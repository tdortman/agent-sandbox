//! Trusted, role-bound evidence sent by gate producers.
//!
//! These values describe facts captured at the interception point. The
//! authenticated connection and policyd-owned registries bind them to a
//! sandbox; the values in this module do not grant attribution by themselves.

use std::{
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use super::proxy::{
    AttributionToken, NetworkFlowKey, ProcessIdentity, ProxyConnectionId, ProxyRequestId,
    ProxySessionToken, SocketIdentity,
};
use crate::policy::{DbusBus, DbusMessageKind, FileAccess, ResourceAccess, ResourceKind};

macro_rules! nonzero_wire_id {
    ($name:ident, $inner:ty, $raw:ty, $message:literal) => {
        #[doc = "Non-zero identifier captured by a trusted gate producer."]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name($inner);

        impl $name {
            /// Construct an identifier, rejecting zero.
            pub fn new(value: $raw) -> Result<Self, String> {
                <$inner>::new(value)
                    .map(Self)
                    .ok_or_else(|| $message.to_owned())
            }

            /// Return the numeric identifier.
            #[must_use]
            pub const fn get(self) -> $raw {
                self.0.get()
            }
        }

        impl TryFrom<$raw> for $name {
            type Error = String;

            fn try_from(value: $raw) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

// Connection-scoped identity minted by a trusted gate producer.
//
// Policyd combines this value with the authenticated producer connection
// generation. A caller-chosen number therefore has no authority by itself.
nonzero_wire_id!(
    OperationIdentity,
    NonZeroU64,
    u64,
    "operation identity must be non-zero"
);

// Identity of one capability subcheck within an operation.
nonzero_wire_id!(
    SubcheckIdentity,
    NonZeroU64,
    u64,
    "subcheck identity must be non-zero"
);

// Identity of the controlled cgroup captured with an operation.
nonzero_wire_id!(
    CgroupIdentity,
    NonZeroU64,
    u64,
    "cgroup identity must be non-zero"
);

// Fanotify event identity.
nonzero_wire_id!(
    FanotifyEventId,
    NonZeroU64,
    u64,
    "fanotify event ID must be non-zero"
);

// Seccomp listener generation.
nonzero_wire_id!(
    SeccompListenerGeneration,
    NonZeroU64,
    u64,
    "seccomp listener generation must be non-zero"
);

// Seccomp notification identity.
nonzero_wire_id!(
    SeccompNotificationId,
    NonZeroU64,
    u64,
    "seccomp notification ID must be non-zero"
);

// Non-zero downstream D-Bus serial number.
nonzero_wire_id!(DbusSerial, NonZeroU32, u32, "D-Bus serial must be non-zero");

/// A typed thread ID and its process thread-group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadIdentity {
    /// Thread ID reported by the kernel.
    pub tid: NonZeroU32,
    /// Thread-group ID associated with the thread.
    pub tgid: NonZeroU32,
}

/// Filesystem evidence captured before answering a fanotify event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FanotifyEvidence {
    /// Producer-local operation identity.
    pub operation_id: OperationIdentity,
    /// Identity of this filesystem capability check.
    pub subcheck_id: SubcheckIdentity,
    /// Fanotify event identity.
    pub event_id: FanotifyEventId,
    /// Process generation that opened or changed the path.
    pub process: ProcessIdentity,
    /// TID and TGID reported for the event.
    pub opener: ThreadIdentity,
    /// Controlled cgroup captured with the process.
    pub cgroup: CgroupIdentity,
    /// Path resolved while the fanotify event was live.
    pub path: PathBuf,
    /// Filesystem access observed for the event.
    pub access: FileAccess,
}

/// A capability subcheck produced by one seccomp notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SeccompSubcheck {
    /// Filesystem path access.
    Filesystem {
        /// Identity of this target within the notification.
        subcheck_id: SubcheckIdentity,
        /// Path resolved from the trapped operation.
        path: PathBuf,
        /// Access requested by the trapped operation.
        access: FileAccess,
    },
    /// AF_UNIX or device resource access.
    Resource {
        /// Identity of this target within the notification.
        subcheck_id: SubcheckIdentity,
        /// Resource class being accessed.
        resource_kind: ResourceKind,
        /// Resource path resolved from the trapped operation.
        path: PathBuf,
        /// Access requested by the trapped operation.
        access: ResourceAccess,
    },
    /// Direct network destination captured from the notification.
    Network {
        /// Identity of this target within the notification.
        subcheck_id: SubcheckIdentity,
        /// Raw destination bytes captured before the notification is answered.
        destination: Vec<u8>,
        /// Exact socket generation, when the descriptor permits capture.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socket: Option<SocketIdentity>,
    },
}

/// Filesystem, resource, or direct-network evidence from seccomp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompEvidence {
    /// Producer-local operation identity shared by all subchecks.
    pub operation_id: OperationIdentity,
    /// Generation of the listener that produced the notification.
    pub listener_generation: SeccompListenerGeneration,
    /// Notification identity within that listener.
    pub notification_id: SeccompNotificationId,
    /// Process generation that caused the notification.
    pub process: ProcessIdentity,
    /// TID and TGID reported for the notification.
    pub thread: ThreadIdentity,
    /// Controlled cgroup captured with the process.
    pub cgroup: CgroupIdentity,
    /// All capability targets affected by this notification.
    pub subchecks: Vec<SeccompSubcheck>,
}

/// NFQ flow evidence captured at the packet boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NfqEvidence {
    /// Producer-local operation identity.
    pub operation_id: OperationIdentity,
    /// Identity of this packet capability check.
    pub subcheck_id: SubcheckIdentity,
    /// Exact flow tuple observed by NFQ.
    pub flow: NetworkFlowKey,
    /// Unique process and socket generation owning the flow.
    pub owner: SocketIdentity,
    /// Controlled cgroup captured with the owner.
    pub cgroup: CgroupIdentity,
}

/// HTTP operation evidence carried over a bound proxy bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpBridgeEvidence {
    /// Fresh semantic identity for this HTTP request or stream.
    pub operation_id: ProxyRequestId,
    /// Identity of this policy subcheck.
    pub subcheck_id: SubcheckIdentity,
    /// Authenticated proxy session carrying the bridge.
    pub proxy_session: ProxySessionToken,
    /// Downstream connection generation bound to the flow.
    pub connection_id: ProxyConnectionId,
    /// Opaque flow attribution minted by policyd.
    pub attribution_token: AttributionToken,
}

/// Elevation evidence captured from the direct helper peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationEvidence {
    /// Producer-local operation identity.
    pub operation_id: OperationIdentity,
    /// Identity of the elevation capability check.
    pub subcheck_id: SubcheckIdentity,
    /// Exact helper connection owning the pending request.
    pub helper_connection: ProxyConnectionId,
    /// Process generation from the accepted Unix peer.
    pub peer: ProcessIdentity,
    /// Controlled cgroup captured from the accepted peer.
    pub cgroup: CgroupIdentity,
    /// Command and arguments requested for elevation.
    pub argv: Vec<String>,
}

/// Compound identity for one message on one D-Bus relay connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbusOperationIdentity {
    /// Relay connection generation.
    pub relay_connection: ProxyConnectionId,
    /// Downstream serial on that connection.
    pub serial: DbusSerial,
}

/// Strict D-Bus descriptor metadata captured from a message.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbusFdEvidence {
    /// Descriptor kind supplied by the D-Bus message.
    pub kind: String,
    /// Whether the descriptor is read-only.
    pub read_only: bool,
}

/// Strict D-Bus target facts captured for one message.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbusTargetEvidence {
    /// Bus carrying the message.
    pub bus: DbusBus,
    /// Destination service name.
    pub destination: String,
    /// Object path addressed by the message.
    pub object_path: String,
    /// Target interface.
    pub interface: String,
    /// Method or signal member.
    pub member: String,
    /// Message kind.
    pub message_kind: DbusMessageKind,
    /// D-Bus signature of the body.
    pub signature: String,
    /// Metadata for descriptors carried by the message.
    #[serde(default)]
    pub fd_metadata: Vec<DbusFdEvidence>,
}

/// D-Bus relay evidence captured before forwarding a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbusEvidence {
    /// Message operation identity. Replies retain their matching call identity.
    pub operation_id: DbusOperationIdentity,
    /// Identity of this policy subcheck.
    pub subcheck_id: SubcheckIdentity,
    /// Process generation from the downstream Unix peer.
    pub peer: ProcessIdentity,
    /// Controlled cgroup captured from the downstream peer.
    pub cgroup: CgroupIdentity,
    /// Bound bridge reference, when this relay was opened through a bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_token: Option<AttributionToken>,
    /// Call serial retained by a reply, when this message is a reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<DbusSerial>,
    /// Resource facts extracted from the message.
    pub target: DbusTargetEvidence,
}

/// Trusted gate evidence request. Role-bound variants arrive on authenticated
/// producer connections; elevation binds the direct helper peer instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum RoleEvidenceRequest {
    /// Fanotify filesystem permission event.
    Fanotify {
        /// Request correlation ID chosen by the producer.
        request_id: u64,
        /// Captured fanotify facts.
        evidence: FanotifyEvidence,
    },
    /// Seccomp filesystem, resource, or direct-network notification.
    Seccomp {
        /// Request correlation ID chosen by the producer.
        request_id: u64,
        /// Captured seccomp facts.
        evidence: SeccompEvidence,
    },
    /// NFQ packet-boundary flow event.
    Nfq {
        /// Request correlation ID chosen by the producer.
        request_id: u64,
        /// Captured NFQ facts.
        evidence: NfqEvidence,
    },
    /// Operation on an authenticated HTTP bridge.
    HttpBridge {
        /// Request correlation ID chosen by the producer.
        request_id: u64,
        /// Captured HTTP bridge facts.
        evidence: HttpBridgeEvidence,
    },
    /// Elevation request from a direct Unix helper peer.
    Elevation {
        /// Exact helper request correlation ID.
        request_id: u64,
        /// Captured elevation facts.
        evidence: ElevationEvidence,
    },
    /// D-Bus relay message.
    Dbus {
        /// Request correlation ID chosen by the relay.
        request_id: u64,
        /// Captured D-Bus facts.
        evidence: DbusEvidence,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DeviceAccess, FileAccess, ResourceAccess, ResourceKind};

    #[test]
    fn seccomp_schema_round_trips_strict_distinct_subchecks() {
        let request = RoleEvidenceRequest::Seccomp {
            request_id: 7,
            evidence: SeccompEvidence {
                operation_id: OperationIdentity::new(11).unwrap(),
                listener_generation: SeccompListenerGeneration::new(13).unwrap(),
                notification_id: SeccompNotificationId::new(17).unwrap(),
                process: ProcessIdentity::new(41, 1000, 19).unwrap(),
                thread: ThreadIdentity {
                    tid: NonZeroU32::new(43).unwrap(),
                    tgid: NonZeroU32::new(41).unwrap(),
                },
                cgroup: CgroupIdentity::new(23).unwrap(),
                subchecks: vec![
                    SeccompSubcheck::Filesystem {
                        subcheck_id: SubcheckIdentity::new(29).unwrap(),
                        path: "/workspace/a".into(),
                        access: FileAccess::Read,
                    },
                    SeccompSubcheck::Resource {
                        subcheck_id: SubcheckIdentity::new(31).unwrap(),
                        resource_kind: ResourceKind::Device,
                        path: "/dev/null".into(),
                        access: ResourceAccess::Device(DeviceAccess::Read),
                    },
                ],
            },
        };

        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["role"], "seccomp");
        assert_eq!(wire["evidence"]["operation_id"], 11);
        assert_eq!(wire["evidence"]["subchecks"][0]["subcheck_id"], 29);
        assert_eq!(wire["evidence"]["subchecks"][1]["subcheck_id"], 31);
        assert_eq!(
            serde_json::from_value::<RoleEvidenceRequest>(wire.clone()).unwrap(),
            request
        );

        let mut unknown = wire.as_object().unwrap().clone();
        unknown.insert("unexpected".into(), true.into());
        assert!(serde_json::from_value::<RoleEvidenceRequest>(unknown.into()).is_err());

        let mut nested_unknown = wire;
        nested_unknown["evidence"]["subchecks"][0]["unexpected"] = true.into();
        assert!(serde_json::from_value::<RoleEvidenceRequest>(nested_unknown).is_err());
    }
}
