//! Registry of policy-approved HTTP/3 session identities, with the leases
//! that pin one identity to each downstream stream.

use crate::{
    http3::{
        BoxError,
        session::{self, SessionKey, SessionProtocol},
    },
    semantic::SemanticRequest,
};

use agent_sandbox_core::HttpRequest;
use h3::quic::StreamId;
use std::collections::HashMap;
use tokio::sync::Mutex;

#[derive(Clone)]
pub(super) struct SessionBinding {
    pub(super) key: SessionKey,
    pub(super) downstream_stream_id: StreamId,
    pub(super) upstream_stream_id: StreamId,
}

struct ApprovedSession {
    normalized: HttpRequest,
}

#[derive(Default)]
pub(super) struct SessionRegistry {
    leases: Mutex<HashMap<StreamId, SessionKey>>,
    approvals: Mutex<HashMap<SessionKey, ApprovedSession>>,
}

impl SessionRegistry {
    pub(super) async fn reserve(
        &self,
        downstream_stream_id: StreamId,
        key: &SessionKey,
    ) -> Result<(), BoxError> {
        let mut leases = self.leases.lock().await;

        if let Some(existing) = leases.get(&downstream_stream_id)
            && existing != key
        {
            return Err("HTTP/3 session identity changed during reconnect".into());
        }

        leases.insert(downstream_stream_id, key.clone());
        drop(leases);
        Ok(())
    }

    pub(super) async fn validate(
        &self,
        downstream_stream_id: StreamId,
        key: &SessionKey,
    ) -> Result<(), BoxError> {
        let leases = self.leases.lock().await;

        if leases.get(&downstream_stream_id) == Some(key) {
            drop(leases);
            return Ok(());
        }

        drop(leases);
        Err("HTTP/3 session identity changed during reconnect".into())
    }

    pub(super) async fn approved(
        &self,
        semantic: &SemanticRequest,
        protocol: SessionProtocol,
        attribution: agent_sandbox_core::AttributionToken,
    ) -> Option<HttpRequest> {
        let target = semantic.policy_request().ok()?.url.to_string();

        let key = SessionKey {
            origin: semantic.authority().to_owned(),
            target,
            protocol,
            attribution,
        };

        let approvals = self.approvals.lock().await;
        let normalized = approvals.get(&key)?.normalized.clone();
        drop(approvals);
        Some(normalized)
    }

    pub(super) async fn set(
        &self,
        binding: &SessionBinding,
        normalized: &HttpRequest,
    ) -> Result<(), BoxError> {
        let downstream_datagram = session::encode_http_datagram(binding.downstream_stream_id, &[])?;
        session::decode_http_datagram(&downstream_datagram, binding.downstream_stream_id)?;
        let upstream_datagram = session::encode_http_datagram(binding.upstream_stream_id, &[])?;
        session::decode_http_datagram(&upstream_datagram, binding.upstream_stream_id)?;

        self.reserve(binding.downstream_stream_id, &binding.key)
            .await?;

        self.approvals
            .lock()
            .await
            .insert(binding.key.clone(), ApprovedSession {
                normalized: normalized.clone(),
            });

        Ok(())
    }

    pub(super) async fn remove(&self, downstream_stream_id: StreamId) {
        let (key, remove_approval) = {
            let mut leases = self.leases.lock().await;
            let key = leases.remove(&downstream_stream_id);
            let remove_approval = key
                .as_ref()
                .is_some_and(|key| !leases.values().any(|lease| lease == key));
            drop(leases);
            (key, remove_approval)
        };

        if remove_approval && let Some(key) = key {
            self.approvals.lock().await.remove(&key);
        }
    }
}

pub(super) fn session_key(
    semantic: &SemanticRequest,
    normalized: &agent_sandbox_core::HttpRequest,
    protocol: SessionProtocol,
    attribution: agent_sandbox_core::AttributionToken,
) -> SessionKey {
    SessionKey {
        origin: semantic.authority().to_owned(),
        target: normalized.url.to_string(),
        protocol,
        attribution,
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionBinding, SessionRegistry, session_key};

    use crate::http3::{
        relay::semantic_request,
        session::{SessionKey, SessionProtocol},
    };

    use agent_sandbox_core::{AttributionToken, HttpRequest};
    use h3::quic::StreamId;

    fn semantic() -> crate::semantic::SemanticRequest {
        let request = http::Request::builder()
            .uri("https://example.test/path")
            .body(())
            .expect("valid request");

        semantic_request(&request, None, 8443).expect("valid semantic request")
    }

    fn normalized() -> HttpRequest {
        semantic()
            .policy_request()
            .expect("semantic request normalizes to a policy request")
    }

    fn attribution() -> AttributionToken {
        AttributionToken::from_bytes([7; 32])
    }

    fn key(protocol: SessionProtocol) -> SessionKey {
        session_key(&semantic(), &normalized(), protocol, attribution())
    }

    fn stream(value: u64) -> StreamId {
        StreamId::try_from(value).expect("stream id")
    }

    #[test]
    fn session_key_carries_the_semantic_identity() {
        let key = key(SessionProtocol::WebSocket);
        assert_eq!(key.origin, "example.test:8443");
        assert_eq!(key.target, "https://example.test:8443/path");
        assert_eq!(key.protocol, SessionProtocol::WebSocket);
        assert_eq!(key.attribution, attribution());
    }

    #[tokio::test]
    async fn reserve_rejects_an_identity_change() {
        let registry = SessionRegistry::default();
        let first = key(SessionProtocol::WebSocket);

        registry
            .reserve(stream(0), &first)
            .await
            .expect("reserves the first identity");

        let second = key(SessionProtocol::ConnectUdp);

        let error = registry
            .reserve(stream(0), &second)
            .await
            .expect_err("identity change is rejected");

        assert_eq!(
            error.to_string(),
            "HTTP/3 session identity changed during reconnect"
        );
    }

    #[tokio::test]
    async fn validate_accepts_only_the_current_lease() {
        let registry = SessionRegistry::default();
        let first = key(SessionProtocol::WebSocket);
        let second = key(SessionProtocol::ConnectUdp);

        let error = registry
            .validate(stream(0), &first)
            .await
            .expect_err("unleased identity is rejected");

        assert_eq!(
            error.to_string(),
            "HTTP/3 session identity changed during reconnect"
        );

        registry.reserve(stream(0), &first).await.expect("reserves");

        registry
            .validate(stream(0), &first)
            .await
            .expect("leased identity validates");

        let error = registry
            .validate(stream(0), &second)
            .await
            .expect_err("different identity is rejected");

        assert_eq!(
            error.to_string(),
            "HTTP/3 session identity changed during reconnect"
        );
    }

    #[tokio::test]
    async fn set_registers_the_binding_and_approval() {
        let registry = SessionRegistry::default();

        let binding = SessionBinding {
            key: key(SessionProtocol::WebSocket),
            downstream_stream_id: stream(0),
            upstream_stream_id: stream(4),
        };

        let normalized = normalized();

        registry
            .set(&binding, &normalized)
            .await
            .expect("binding registers");

        assert_eq!(
            registry
                .approved(&semantic(), SessionProtocol::WebSocket, attribution())
                .await,
            Some(normalized)
        );
    }

    #[tokio::test]
    async fn remove_keeps_the_approval_until_the_last_lease_releases() {
        let registry = SessionRegistry::default();

        let binding = SessionBinding {
            key: key(SessionProtocol::WebSocket),
            downstream_stream_id: stream(0),
            upstream_stream_id: stream(4),
        };

        let second = SessionBinding {
            key: binding.key.clone(),
            downstream_stream_id: stream(8),
            upstream_stream_id: stream(12),
        };

        let normalized = normalized();

        registry
            .set(&binding, &normalized)
            .await
            .expect("first binding registers");

        registry
            .set(&second, &normalized)
            .await
            .expect("second binding registers");

        registry.remove(stream(0)).await;

        assert_eq!(
            registry
                .approved(&semantic(), SessionProtocol::WebSocket, attribution())
                .await,
            Some(normalized.clone()),
            "the remaining lease still holds the approval"
        );

        registry.remove(stream(8)).await;

        assert_eq!(
            registry
                .approved(&semantic(), SessionProtocol::WebSocket, attribution())
                .await,
            None,
            "the last lease release drops the approval"
        );
    }
}
