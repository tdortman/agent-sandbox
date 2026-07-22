//! Trusted transparent-proxy session and flow registry.

use std::time::{Duration, Instant};

use agent_sandbox_core::{
    AttributionToken, CheckReply, FlowProtocol, FlowRegistration, HttpCheckReply, HttpRequest,
    NetworkFlowKey, ProcessIds, ProxyConnectionId, ProxyRequestId, ProxySessionReply,
    ProxySessionToken, ResolvedRequestContext, socket_owner::validate_socket_identity,
};
use tokio::sync::oneshot;

use super::types::{
    MAX_PROXY_FLOWS, PolicyStore, ProxyCancellation, ProxyFlowState, ProxySessionState,
};
use crate::{error::PolicydError, wire::NetworkCheckRequest};

const UNCLAIMED_TTL: Duration = Duration::from_secs(30);
const CLAIMED_IDLE_TTL: Duration = Duration::from_hours(1);
const MAX_PROXY_CANCEL_TOMBSTONES: usize = 4096;

fn proxy_error(message: impl Into<String>) -> PolicydError {
    PolicydError::Proxy(message.into())
}

const fn transport_scheme(protocol: FlowProtocol, port: u16) -> &'static str {
    match (protocol, port) {
        (FlowProtocol::Tcp, 80 | 8008 | 8080) => "http",
        (FlowProtocol::Udp, 443) => "http3",
        (FlowProtocol::Tcp, _) => "tcp",
        (FlowProtocol::Udp, _) => "udp",
    }
}

impl PolicyStore {
    /// Open the one persistent trusted proxy session for a client connection.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when another proxy session is active or token
    /// generation fails.
    pub async fn open_proxy_session(
        &self,
        connection_id: u64,
    ) -> Result<ProxySessionReply, PolicydError> {
        let mut inner = self.inner.lock().await;
        if inner.proxy_session.is_some() {
            return Err(proxy_error("a proxy session is already active"));
        }
        let token = ProxySessionToken::try_new().map_err(proxy_error)?;
        inner.proxy_session = Some(ProxySessionState {
            token: token.clone(),
            connection_id,
            opened_at: Instant::now(),
        });
        drop(inner);
        Ok(ProxySessionReply {
            ok: true,
            proxy_session: token,
        })
    }

    /// Register or refresh one owner-identified flow before proxy use.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] for conflicting registrations or a full flow
    /// registry.
    pub async fn register_network_flow(
        &self,
        registration: FlowRegistration,
    ) -> Result<(), PolicydError> {
        let now = Instant::now();
        let owner = registration.owner();
        let (paths, sandbox_session_id) = registration.context().clone().into_parts();
        let raw_context = ResolvedRequestContext::new(
            paths,
            ProcessIds::new(owner.pid().get(), owner.uid()),
            sandbox_session_id,
        );
        // nfq registers flows with empty paths; enrich home/cwd/project_root
        // from the verified owner uid and pid so HTTP pendings carry enough
        // context for global/project scope resolution.
        let context = Self::resolve_trusted_context(&raw_context);
        let key = registration.flow().clone();
        let mut inner = self.inner.lock().await;
        prune_flows(&mut inner.proxy_flows, now);
        if let Some(existing) = inner.proxy_flows.get_mut(&key) {
            if existing.registration != registration {
                return Err(proxy_error(
                    "flow registration conflicts with an existing owner",
                ));
            }
            if existing.attribution_token.is_none() {
                existing.registration = registration;
                existing.context = context;
            }
            existing.last_check = now;
            drop(inner);
            return Ok(());
        }
        if inner.proxy_flows.len() >= MAX_PROXY_FLOWS {
            return Err(proxy_error("proxy flow registry is full"));
        }
        inner.proxy_flows.insert(key, ProxyFlowState {
            owner,
            registration,
            context,
            attribution_token: None,
            connection_id: None,
            claimed_at: None,
            last_check: now,
        });
        drop(inner);
        Ok(())
    }

    /// Pin a registered flow to one proxy connection and issue an attribution
    /// token.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the session or flow is invalid or claimed.
    pub async fn claim_network_flow(
        &self,
        proxy_session: ProxySessionToken,
        flow: NetworkFlowKey,
        connection_id: ProxyConnectionId,
    ) -> Result<agent_sandbox_core::FlowClaimReply, PolicydError> {
        let mut inner = self.inner.lock().await;
        prune_flows(&mut inner.proxy_flows, Instant::now());
        validate_session(&inner, &proxy_session)?;
        let state = inner
            .proxy_flows
            .get_mut(&flow)
            .ok_or_else(|| proxy_error("flow is not registered"))?;
        if state.attribution_token.is_some() {
            return Err(proxy_error("flow is already claimed"));
        }
        let attribution_token = AttributionToken::try_new().map_err(proxy_error)?;
        let now = Instant::now();
        state.attribution_token = Some(attribution_token.clone());
        state.connection_id = Some(connection_id);
        state.claimed_at = Some(now);
        state.last_check = now;
        drop(inner);
        Ok(agent_sandbox_core::FlowClaimReply {
            ok: true,
            attribution_token,
        })
    }

    /// Evaluate a transport fallback for an attributed flow.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the session, claim, or request ID is
    /// invalid.
    pub async fn check_network_flow(
        &self,
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
    ) -> Result<CheckReply, PolicydError> {
        let key = (proxy_session.clone(), request_id);
        let (cancel_tx, cancel_rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            validate_session(&inner, &proxy_session)?;
            match inner.proxy_cancellations.get(&key) {
                Some(ProxyCancellation::Canceled) => {
                    inner.proxy_cancellations.remove(&key);
                    return Ok(CheckReply::blocked(
                        "agent-sandbox: network check cancelled",
                    ));
                }
                Some(ProxyCancellation::Active(_)) => {
                    return Err(proxy_error("duplicate in-flight network request ID"));
                }
                None => {
                    if inner.proxy_cancellations.len() >= MAX_PROXY_CANCEL_TOMBSTONES {
                        return Err(proxy_error("too many in-flight proxy checks"));
                    }
                    inner
                        .proxy_cancellations
                        .insert(key.clone(), ProxyCancellation::Active(cancel_tx));
                }
            }
        }
        let (host, port, ctx, protocol) = match self
            .flow_for_check(&proxy_session, &attribution_token)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                self.inner.lock().await.proxy_cancellations.remove(&key);
                return Err(err);
            }
        };
        let reply = self
            .request_network_approval_with_aliases_cancellable(
                NetworkCheckRequest {
                    host,
                    port,
                    scheme: transport_scheme(protocol, port).into(),
                    url: String::new(),
                    ctx,
                },
                Vec::new(),
                Some((proxy_session.clone(), request_id)),
                Some(cancel_rx),
            )
            .await;
        self.inner.lock().await.proxy_cancellations.remove(&key);
        Ok(reply)
    }

    /// Evaluate one decoded HTTP request for an attributed flow.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the session, claim, or request ID is
    /// invalid.
    pub async fn check_http(
        &self,
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
        request: HttpRequest,
    ) -> Result<HttpCheckReply, PolicydError> {
        let key = (proxy_session.clone(), request_id);
        let (cancel_tx, cancel_rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            validate_session(&inner, &proxy_session)?;
            match inner.proxy_cancellations.get(&key) {
                Some(ProxyCancellation::Canceled) => {
                    inner.proxy_cancellations.remove(&key);
                    return Ok(HttpCheckReply::blocked(
                        "agent-sandbox: HTTP check cancelled",
                    ));
                }
                Some(ProxyCancellation::Active(_)) => {
                    return Err(proxy_error("duplicate in-flight HTTP request ID"));
                }
                None => {
                    if inner.proxy_cancellations.len() >= MAX_PROXY_CANCEL_TOMBSTONES {
                        return Err(proxy_error("too many in-flight proxy checks"));
                    }
                    inner
                        .proxy_cancellations
                        .insert(key.clone(), ProxyCancellation::Active(cancel_tx));
                }
            }
        }
        let (_host, _port, ctx, _protocol) = match self
            .flow_for_check(&proxy_session, &attribution_token)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                self.inner.lock().await.proxy_cancellations.remove(&key);
                return Err(err);
            }
        };
        let approval = self.request_http_approval(
            proxy_session.clone(),
            request_id,
            attribution_token,
            request,
            ctx,
        );
        tokio::pin!(approval);
        let result = tokio::select! {
            reply = &mut approval => reply,
            _ = cancel_rx => {
                let _ = self.cancel_http_check(proxy_session.clone(), request_id).await;
                Ok(HttpCheckReply::blocked("agent-sandbox: HTTP check cancelled"))
            },
        };
        self.inner.lock().await.proxy_cancellations.remove(&key);
        result
    }

    /// Cancel a pending proxy check.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the session is invalid.
    pub async fn cancel_check(
        &self,
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
    ) -> Result<(), PolicydError> {
        let cancel = {
            let mut inner = self.inner.lock().await;
            validate_session(&inner, &proxy_session)?;
            match inner
                .proxy_cancellations
                .remove(&(proxy_session.clone(), request_id))
            {
                Some(ProxyCancellation::Active(sender)) => Some(sender),
                Some(ProxyCancellation::Canceled) => None,
                None => {
                    if inner.proxy_cancellations.len() < MAX_PROXY_CANCEL_TOMBSTONES {
                        inner.proxy_cancellations.insert(
                            (proxy_session.clone(), request_id),
                            ProxyCancellation::Canceled,
                        );
                    }
                    None
                }
            }
        };
        if let Some(cancel) = cancel {
            let _ = cancel.send(());
        }
        self.cancel_http_check(proxy_session, request_id).await
    }

    /// Release a previously claimed network flow.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the proxy session is invalid.
    pub async fn release_network_flow(
        &self,
        proxy_session: ProxySessionToken,
        attribution_token: AttributionToken,
    ) -> Result<(), PolicydError> {
        let mut inner = self.inner.lock().await;
        validate_session(&inner, &proxy_session)?;
        if let Some(state) = inner
            .proxy_flows
            .values_mut()
            .find(|state| state.attribution_token.as_ref() == Some(&attribution_token))
        {
            state.attribution_token = None;
            state.connection_id = None;
            state.claimed_at = None;
            state.last_check = Instant::now();
        }
        drop(inner);
        Ok(())
    }

    /// Clear a session and all claims owned by its persistent connection.
    pub async fn close_proxy_session(&self, connection_id: u64) {
        let canceled = {
            let mut inner = self.inner.lock().await;
            let Some(session) = inner.proxy_session.as_ref() else {
                return;
            };
            if session.connection_id != connection_id {
                return;
            }
            let token = session.token.clone();
            inner.proxy_session = None;
            for (_, state) in inner.proxy_cancellations.drain() {
                if let ProxyCancellation::Active(sender) = state {
                    let _ = sender.send(());
                }
            }
            for state in inner.proxy_flows.values_mut() {
                state.attribution_token = None;
                state.connection_id = None;
                state.claimed_at = None;
                state.last_check = Instant::now();
            }

            let pending_ids = inner.http_futures.keys().copied().collect::<Vec<_>>();
            let mut canceled = Vec::new();
            for pending_id in pending_ids {
                let Some(waiters) = inner.http_futures.remove(&pending_id) else {
                    continue;
                };
                let mut retained = Vec::with_capacity(waiters.len());
                for waiter in waiters {
                    if waiter.proxy_session == token {
                        inner
                            .http_waiters
                            .remove(&(waiter.proxy_session.clone(), waiter.request_id));
                        canceled.push(waiter.tx);
                    } else {
                        retained.push(waiter);
                    }
                }
                if retained.is_empty() {
                    inner.take_pending(&pending_id.to_string());
                } else {
                    inner.http_futures.insert(pending_id, retained);
                }
            }
            canceled
        };
        for sender in canceled {
            let _ = sender.send(HttpCheckReply::blocked(
                "agent-sandbox: proxy session closed",
            ));
        }
    }

    async fn flow_for_check(
        &self,
        proxy_session: &ProxySessionToken,
        attribution_token: &AttributionToken,
    ) -> Result<(String, u16, ResolvedRequestContext, FlowProtocol), PolicydError> {
        let (flow, registration, expected_owner, context) = {
            let mut inner = self.inner.lock().await;
            prune_flows(&mut inner.proxy_flows, Instant::now());
            validate_session(&inner, proxy_session)?;
            let (flow, state) = inner
                .proxy_flows
                .iter()
                .find(|(_, state)| state.attribution_token.as_ref() == Some(attribution_token))
                .ok_or_else(|| proxy_error("flow attribution is invalid"))?;
            let snapshot = (
                flow.clone(),
                state.registration.clone(),
                state.owner,
                state.context.clone(),
            );
            drop(inner);
            snapshot
        };

        let identity_valid = tokio::time::timeout(
            self.args.approval_timeout,
            tokio::task::spawn_blocking(move || validate_socket_identity(expected_owner)),
        )
        .await
        .map_err(|_| proxy_error("socket owner revalidation timed out"))?
        .map_err(|_| proxy_error("socket owner revalidation failed"))?;
        if !identity_valid {
            return Err(proxy_error("socket owner changed"));
        }

        let mut inner = self.inner.lock().await;
        validate_session(&inner, proxy_session)?;
        let state = inner
            .proxy_flows
            .get_mut(&flow)
            .ok_or_else(|| proxy_error("flow registration expired"))?;
        if state.registration != registration
            || state.attribution_token.as_ref() != Some(attribution_token)
        {
            return Err(proxy_error("flow claim changed during revalidation"));
        }
        state.last_check = Instant::now();
        let host = registration.policy_host().to_string();
        let port = registration.flow().destination_port().get();
        drop(inner);
        Ok((host, port, context, registration.flow().protocol()))
    }
}

fn validate_session(
    inner: &super::types::PolicyDecisionState,
    token: &ProxySessionToken,
) -> Result<(), PolicydError> {
    if inner
        .proxy_session
        .as_ref()
        .is_some_and(|session| &session.token == token)
    {
        Ok(())
    } else {
        Err(proxy_error("proxy session token is invalid"))
    }
}

fn prune_flows(
    flows: &mut std::collections::HashMap<NetworkFlowKey, ProxyFlowState>,
    now: Instant,
) {
    flows.retain(|_, state| {
        let ttl = if state.attribution_token.is_some() {
            CLAIMED_IDLE_TTL
        } else {
            UNCLAIMED_TTL
        };
        now.saturating_duration_since(state.last_check) <= ttl
    });
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use agent_sandbox_core::{
        FlowContext, FlowProtocol, NormalizedPolicyHost, ProcessIdentity, SandboxPaths,
        SocketIdentity, SocketInode, VerdictSource,
        socket_owner::{OwnerResolution, SocketProtocol, SocketTuple, resolve_owner_snapshot},
    };

    use super::*;
    use crate::store::types::{Pending, PolicyStore, PolicydArgs};

    fn test_store(dir: &tempfile::TempDir) -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: dir.path().join("host.sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        })
    }

    fn test_owner() -> SocketIdentity {
        let uid = nix::unistd::getuid().as_raw();
        let process = ProcessIdentity::new(1, uid, 1).expect("valid process identity");
        SocketIdentity::new(process, SocketInode::new(1).expect("valid inode"))
    }

    /// Regression: nfq registers flows with `SandboxPaths::default()` (empty
    /// paths). The store must enrich the flow context from the attributed
    /// owner uid so HTTP pendings carry a home for global/project scope
    /// resolution.
    #[tokio::test]
    async fn flow_registration_enriches_empty_paths_from_owner_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(&dir);
        store.open_proxy_session(1).await.expect("open session");

        // Mirror nfq's FlowRegistration with empty paths.
        let flow = NetworkFlowKey::try_new(
            FlowProtocol::Tcp,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            1234.try_into().expect("non-zero port"),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            443.try_into().expect("non-zero port"),
        )
        .expect("valid flow key");
        let registration = FlowRegistration::new(
            flow,
            test_owner(),
            NormalizedPolicyHost::parse("example.com").expect("valid host"),
            FlowContext::new(SandboxPaths::default(), Some("test-session".into())),
        );
        store
            .register_network_flow(registration)
            .await
            .expect("register flow");

        let enriched_home = {
            let inner = store.inner.lock().await;
            inner
                .proxy_flows
                .values()
                .next()
                .expect("flow must be registered")
                .context
                .paths
                .home()
                .map(std::path::Path::to_path_buf)
        };
        assert!(
            enriched_home.is_some(),
            "flow context home must be enriched from owner uid"
        );
    }

    #[tokio::test]
    async fn check_network_flow_requests_deferred_transport_approval_and_honors_cancellation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));
        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let source = socket.local_addr().expect("socket address");
        let owner = match resolve_owner_snapshot(
            SocketProtocol::Udp,
            SocketTuple::from_local(source.ip(), source.port()),
        ) {
            OwnerResolution::Unique(snapshot) => snapshot.identity(),
            other => panic!("expected unique UDP owner, got {other:?}"),
        };
        let flow = NetworkFlowKey::try_new(
            FlowProtocol::Udp,
            source.ip(),
            source.port(),
            "1.1.1.1".parse().expect("valid destination"),
            443,
        )
        .expect("valid flow");
        store
            .register_network_flow(FlowRegistration::new(
                flow.clone(),
                owner,
                NormalizedPolicyHost::parse("1.1.1.1").expect("valid host"),
                FlowContext::default(),
            ))
            .await
            .expect("register flow");
        let claim = store
            .claim_network_flow(session.clone(), flow, ProxyConnectionId::new())
            .await
            .expect("claim flow");

        let request_id = ProxyRequestId::new();
        let task_store = store.clone();
        let task_session = session.clone();
        let attribution_token = claim.attribution_token.clone();
        let task = tokio::spawn(async move {
            task_store
                .check_network_flow(task_session, request_id, attribution_token)
                .await
        });
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some((id, Pending::Network(pending))) =
                    inner.pending_entries().find(|(id, pending)| {
                        id.starts_with("net:") && matches!(pending, Pending::Network(_))
                    })
                {
                    assert_eq!(pending.scheme, "http3");
                    break id.clone();
                }
                assert!(
                    Instant::now() < deadline,
                    "raw transport check never created pending approval"
                );
                drop(inner);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        store
            .finish_network(
                &pending_id,
                true,
                VerdictSource::policy_with_comment("test"),
                None,
            )
            .await;
        let reply = task
            .await
            .expect("check task should not panic")
            .expect("check should succeed");
        assert!(reply.allowed, "expected allowed reply, got {reply:?}");
        assert_eq!(
            reply.source,
            VerdictSource::policy_with_comment("test"),
            "raw fallback must use the transport policy verdict"
        );
        assert!(
            store.inner.lock().await.network_futures.is_empty(),
            "finished transport approval must release its waiter"
        );
        let canceled_request_id = ProxyRequestId::new();
        store
            .cancel_check(session.clone(), canceled_request_id)
            .await
            .expect("cancel check");
        let canceled = store
            .check_network_flow(session, canceled_request_id, claim.attribution_token)
            .await
            .expect("canceled check should return a verdict");
        assert!(!canceled.allowed, "canceled check must be blocked");
    }
}
