//! Tracks the authenticated locally-issued QUIC connection-ID set for one
//! policy-owned downstream association.

use crate::{
    http3::{BoxError, ConnectionIdOwner, boxed_owned, varint},
    policy::FlowClaim,
};

use h3::error::Code;
use std::{collections::HashMap, sync::Arc};
use tracing::info;

/// Tracks the authenticated locally-issued CID set for one policy-owned
/// downstream association. Quinn itself rejects unknown CIDs before they can
/// reach this layer; this registry binds every accepted CID to the stable
/// Quinn connection handle and the policy connection identity.
pub(super) struct ConnectionIdBindings {
    registry: Arc<crate::http3::ConnectionIdRegistry>,
    owner: ConnectionIdOwner,
    sequences: HashMap<u64, quinn::ConnectionId>,
}

impl ConnectionIdBindings {
    pub(super) fn new(
        connection: &quinn::Connection,
        claim: &FlowClaim,
        registry: Arc<crate::http3::ConnectionIdRegistry>,
    ) -> Self {
        Self {
            registry,
            owner: ConnectionIdOwner {
                stable_id: connection.stable_id(),
                proxy_connection_id: claim.connection_id,
            },
            sequences: HashMap::new(),
        }
    }

    pub(super) fn drain(&mut self, connection: &quinn::Connection) -> Result<(), BoxError> {
        while let Some(event) = connection.poll_connection_id_event() {
            match event {
                quinn::ConnectionIdEvent::Active { sequence, id } => {
                    if let Some(existing) = self.sequences.get(&sequence)
                        && *existing != id
                    {
                        return Err(boxed_owned(format!(
                            "QUIC connection-ID sequence {sequence} changed from {existing} to \
                             {id}"
                        )));
                    }
                    if !id.is_empty() {
                        self.registry.bind(id, self.owner).map_err(boxed_owned)?;
                    }
                    self.sequences.insert(sequence, id);
                    info!(
                        connection_id = %self.owner.proxy_connection_id,
                        stable_id = self.owner.stable_id,
                        sequence,
                        %id,
                        "QUIC connection ID bound to policy association"
                    );
                }

                quinn::ConnectionIdEvent::Retired { sequence, id } => {
                    self.retire(sequence, id)?;
                    info!(
                        connection_id = %self.owner.proxy_connection_id,
                        stable_id = self.owner.stable_id,
                        sequence,
                        %id,
                        "QUIC connection ID released from policy association"
                    );
                }

                quinn::ConnectionIdEvent::Removed { sequence, id } => {
                    self.remove(sequence, id);
                    info!(
                        connection_id = %self.owner.proxy_connection_id,
                        stable_id = self.owner.stable_id,
                        sequence,
                        %id,
                        "QUIC connection ID removed from policy association"
                    );
                }
            }
        }

        Ok(())
    }

    pub(super) fn drain_or_close(
        &mut self,
        connection: &quinn::Connection,
    ) -> Result<(), BoxError> {
        if let Err(error) = self.drain(connection) {
            connection.close(varint(Code::H3_INTERNAL_ERROR), b"QUIC CID registry failed");
            return Err(error);
        }

        Ok(())
    }

    pub(super) fn retire(
        &mut self,
        sequence: u64,
        id: quinn::ConnectionId,
    ) -> Result<(), BoxError> {
        let Some(existing) = self.sequences.remove(&sequence) else {
            return Err(boxed_owned(format!(
                "unknown QUIC connection-ID retirement for sequence {sequence} ({id})"
            )));
        };

        if existing != id {
            return Err(boxed_owned(format!(
                "QUIC connection-ID sequence {sequence} retired as {id}, expected {existing}"
            )));
        }

        if !id.is_empty() {
            self.registry.unbind(id, self.owner).map_err(boxed_owned)?;
        }

        Ok(())
    }

    /// Teardown events are best-effort and idempotent: the owner cleanup also
    /// runs when the association task is dropped.
    pub(super) fn remove(&mut self, sequence: u64, id: quinn::ConnectionId) {
        self.sequences.remove(&sequence);

        if !id.is_empty() {
            let _ = self.registry.unbind(id, self.owner);
        }
    }
}

impl Drop for ConnectionIdBindings {
    fn drop(&mut self) {
        for (&sequence, id) in &self.sequences {
            info!(
                connection_id = %self.owner.proxy_connection_id,
                stable_id = self.owner.stable_id,
                sequence,
                %id,
                "QUIC connection ID removed from policy association"
            );
        }

        self.registry.remove_owner(self.owner);
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionIdBindings;
    use crate::http3::{ConnectionIdOwner, ConnectionIdRegistry};
    use agent_sandbox_core::ProxyConnectionId;
    use std::{collections::HashMap, sync::Arc};

    fn owner() -> ConnectionIdOwner {
        ConnectionIdOwner {
            stable_id: 7,
            proxy_connection_id: ProxyConnectionId::new(),
        }
    }

    fn id(byte: u8) -> quinn::ConnectionId {
        quinn::ConnectionId::new(&[byte; 8])
    }

    fn bindings(
        registry: Arc<ConnectionIdRegistry>,
        sequences: HashMap<u64, quinn::ConnectionId>,
    ) -> ConnectionIdBindings {
        ConnectionIdBindings {
            registry,
            owner: owner(),
            sequences,
        }
    }

    #[test]
    fn retire_rejects_unknown_sequences() {
        let registry = Arc::new(ConnectionIdRegistry::default());
        let mut bindings = bindings(registry, HashMap::new());

        let error = bindings
            .retire(1, id(0x42))
            .expect_err("unknown retirement is rejected");

        assert!(
            error
                .to_string()
                .starts_with("unknown QUIC connection-ID retirement for sequence 1")
        );
    }

    #[test]
    fn retire_rejects_a_changed_sequence_id() {
        let registry = Arc::new(ConnectionIdRegistry::default());
        let mut bindings = bindings(registry, HashMap::from([(1, id(0x42))]));

        let error = bindings
            .retire(1, id(0x43))
            .expect_err("changed id is rejected");

        assert!(
            error
                .to_string()
                .starts_with("QUIC connection-ID sequence 1 retired as")
        );
    }

    #[test]
    fn retire_unbinds_the_registered_id() {
        let registry = Arc::new(ConnectionIdRegistry::default());
        let binding_owner = owner();
        let cid = id(0x42);
        registry.bind(cid, binding_owner).expect("id binds");

        let mut bindings = ConnectionIdBindings {
            registry: registry.clone(),
            owner: binding_owner,
            sequences: HashMap::from([(1, cid)]),
        };

        bindings.retire(1, cid).expect("retirement succeeds");

        assert!(
            registry.unbind(cid, binding_owner).is_err(),
            "retired id is no longer registered"
        );
    }

    #[test]
    fn remove_is_idempotent_and_ignores_unknown_sequences() {
        let registry = Arc::new(ConnectionIdRegistry::default());
        let mut bindings = bindings(registry, HashMap::from([(1, id(0x42))]));
        bindings.remove(1, id(0x42));
        bindings.remove(1, id(0x42));
        bindings.remove(9, id(0x42));
    }

    #[test]
    fn drop_releases_every_bound_id() {
        let registry = Arc::new(ConnectionIdRegistry::default());
        let first = owner();
        let cid = id(0x42);

        {
            let mut bindings = ConnectionIdBindings {
                registry: registry.clone(),
                owner: first,
                sequences: HashMap::new(),
            };
            bindings.sequences.insert(1, cid);
            registry.bind(cid, first).expect("id binds");
        }

        let second = owner();

        registry
            .bind(cid, second)
            .expect("drop released the bound id");
    }
}
