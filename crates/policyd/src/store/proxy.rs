//! Trusted transparent-proxy session and flow registry.

use super::types::{
    MAX_PROXY_FLOWS, PolicyStore, ProxyCancellation, ProxyFlowState, ProxySessionState,
};

use crate::{error::PolicydError, wire::NetworkCheckRequest};

use agent_sandbox_core::{
    AttributionToken, CheckReply, FlowProtocol, FlowRegistration, HttpCheckReply, HttpRequest,
    NetworkFlowKey, NetworkFlowSelector, ProcessIds, ProxyConnectionId, ProxyRequestId,
    ProxySessionReply, ProxySessionToken, ResolvedRequestContext, SocketIdentity, scheme_for,
    socket_owner::validate_socket_identity,
};

use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const UNCLAIMED_TTL: Duration = Duration::from_secs(30);
const MAX_PROXY_CANCEL_TOMBSTONES: usize = 4096;

fn proxy_error(message: impl Into<String>) -> PolicydError {
    PolicydError::Proxy(message.into())
}

/// Validate the owner identity attached to an NFQ flow registration.
///
/// The check uses process identity only. It does not resolve the UDP tuple,
/// because policyd runs outside the sandbox network namespace.
///
/// # Errors
///
/// Returns [`PolicydError`] when owner validation times out or fails.
async fn validate_registered_owner(
    owner: SocketIdentity,
    approval_timeout: Duration,
) -> Result<SocketIdentity, PolicydError> {
    let identity_valid = tokio::time::timeout(
        approval_timeout,
        tokio::task::spawn_blocking(move || validate_socket_identity(owner)),
    )
    .await
    .map_err(|_| proxy_error("socket owner validation timed out"))?
    .map_err(|_| proxy_error("socket owner validation failed"))?;

    if !identity_valid {
        return Err(proxy_error("socket owner changed"));
    }

    Ok(owner)
}

fn same_socket_owner(first: SocketIdentity, second: SocketIdentity) -> bool {
    first.pid() == second.pid()
        && first.uid() == second.uid()
        && first.process_start_time_ticks() == second.process_start_time_ticks()
}

fn validate_rebind_candidate(
    claimed: &ProxyFlowState,
    pending: &ProxyFlowState,
) -> Result<(), PolicydError> {
    if pending.attribution_token.is_some() {
        return Err(proxy_error("rebind conflicts with an existing flow"));
    }

    if !same_socket_owner(claimed.registration.owner(), pending.registration.owner()) {
        return Err(proxy_error("socket owner changed"));
    }

    if pending.registration.policy_host() != claimed.registration.policy_host()
        || pending.registration.context() != claimed.registration.context()
    {
        return Err(proxy_error("rebind conflicts with an existing flow"));
    }

    Ok(())
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
        let policy_host = state.registration.policy_host().clone();
        drop(inner);

        Ok(agent_sandbox_core::FlowClaimReply {
            ok: true,
            attribution_token,
            flow,
            policy_host,
        })
    }

    /// Claim one registered UDP flow after OUTPUT NAT hid its destination.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the selector is invalid, ambiguous, or
    /// does not identify exactly one registered flow.
    pub async fn claim_network_flow_by_source(
        &self,
        proxy_session: ProxySessionToken,
        selector: NetworkFlowSelector,
        connection_id: ProxyConnectionId,
    ) -> Result<agent_sandbox_core::FlowClaimReply, PolicydError> {
        if selector.protocol() != FlowProtocol::Udp {
            return Err(proxy_error("redirected flow selector requires UDP"));
        }

        let (candidate, expected_registration) = {
            let mut inner = self.inner.lock().await;
            prune_flows(&mut inner.proxy_flows, Instant::now());
            validate_session(&inner, &proxy_session)?;

            let mut matches = inner
                .proxy_flows
                .iter()
                .filter(|(flow, _state)| {
                    flow.protocol() == selector.protocol()
                        && flow.source_ip() == selector.source_ip()
                        && flow.source_port() == selector.source_port()
                        && flow.destination_port() == selector.destination_port()
                })
                .map(|(flow, state)| {
                    (
                        flow.clone(),
                        state.attribution_token.is_some(),
                        state.registration.clone(),
                    )
                });

            let (candidate, claimed, registration) = matches
                .next()
                .ok_or_else(|| proxy_error("redirected flow is not registered"))?;

            if matches.next().is_some() {
                return Err(proxy_error("redirected flow selector is ambiguous"));
            }

            if claimed {
                return Err(proxy_error("redirected flow is already claimed"));
            }

            drop(matches);
            drop(inner);
            (candidate, registration)
        };

        validate_registered_owner(expected_registration.owner(), self.args.approval_timeout)
            .await?;

        let mut inner = self.inner.lock().await;
        prune_flows(&mut inner.proxy_flows, Instant::now());
        validate_session(&inner, &proxy_session)?;

        let state = inner
            .proxy_flows
            .get_mut(&candidate)
            .ok_or_else(|| proxy_error("redirected flow is no longer registered"))?;

        if state.registration != expected_registration {
            return Err(proxy_error("redirected flow changed during claim"));
        }

        if state.attribution_token.is_some() {
            return Err(proxy_error("redirected flow is already claimed"));
        }

        let attribution_token = AttributionToken::try_new().map_err(proxy_error)?;
        let now = Instant::now();
        state.attribution_token = Some(attribution_token.clone());
        state.connection_id = Some(connection_id);
        state.claimed_at = Some(now);
        state.last_check = now;
        let policy_host = state.registration.policy_host().clone();
        drop(inner);

        Ok(agent_sandbox_core::FlowClaimReply {
            ok: true,
            attribution_token,
            flow: candidate,
            policy_host,
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
                    scheme: scheme_for(protocol, port).into(),
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

    /// Rebind a claimed flow to a new tuple after atomic ownership, tuple,
    /// original-destination, session, and attribution validation.
    ///
    /// A QUIC migration changes the client UDP path without changing the
    /// association. The new tuple must have an unclaimed NFQ registration
    /// with a live owner identity, keep the original destination, and belong
    /// to the same claimed association.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the session, attribution, connection
    /// identifier, tuple, owner, or destination is invalid.
    ///
    /// # Panics
    ///
    /// Panics only when the claimed flow disappears while the store lock is
    /// held; every earlier validation step prevents that state.
    pub async fn rebind_network_flow(
        &self,
        proxy_session: ProxySessionToken,
        attribution_token: AttributionToken,
        connection_id: ProxyConnectionId,
        flow: NetworkFlowKey,
    ) -> Result<(), PolicydError> {
        let (old_key, registration, pending_registration) = {
            let mut inner = self.inner.lock().await;
            prune_flows(&mut inner.proxy_flows, Instant::now());
            validate_session(&inner, &proxy_session)?;

            let (old_key, state) = inner
                .proxy_flows
                .iter()
                .find(|(_, state)| state.attribution_token.as_ref() == Some(&attribution_token))
                .ok_or_else(|| proxy_error("flow attribution is invalid"))?;

            if state.connection_id != Some(connection_id) {
                return Err(proxy_error("unknown connection identifier"));
            }

            if state.registration.flow().protocol() != FlowProtocol::Udp
                || flow.protocol() != FlowProtocol::Udp
            {
                return Err(proxy_error("rebind requires a UDP flow"));
            }

            if flow.destination_ip() != old_key.destination_ip()
                || flow.destination_port() != old_key.destination_port()
            {
                return Err(proxy_error("rebind cannot change the flow destination"));
            }

            if &flow == old_key {
                return Err(proxy_error("rebind requires a new flow tuple"));
            }

            let pending = inner
                .proxy_flows
                .get(&flow)
                .ok_or_else(|| proxy_error("rebind flow is not registered"))?;

            validate_rebind_candidate(state, pending)?;

            let old_key = old_key.clone();
            let registrations = (state.registration.clone(), pending.registration.clone());
            drop(inner);
            (old_key, registrations.0, registrations.1)
        };

        let new_owner =
            validate_registered_owner(pending_registration.owner(), self.args.approval_timeout)
                .await?;

        let mut inner = self.inner.lock().await;
        validate_session(&inner, &proxy_session)?;

        let state = inner
            .proxy_flows
            .get(&old_key)
            .ok_or_else(|| proxy_error("flow registration expired"))?;

        if state.registration != registration
            || state.connection_id != Some(connection_id)
            || state.attribution_token.as_ref() != Some(&attribution_token)
        {
            return Err(proxy_error("flow claim changed during rebind"));
        }

        let pending = inner
            .proxy_flows
            .get(&flow)
            .ok_or_else(|| proxy_error("rebind flow is no longer registered"))?;

        let old_owner = registration.owner();
        let pending_owner = pending.registration.owner();

        if !same_socket_owner(old_owner, pending_owner) {
            return Err(proxy_error("socket owner changed"));
        }

        if pending.attribution_token.is_some() || pending.registration != pending_registration {
            return Err(proxy_error("rebind flow changed during validation"));
        }

        inner.proxy_flows.remove(&flow);
        let now = Instant::now();

        let state = inner
            .proxy_flows
            .remove(&old_key)
            .expect("claimed flow exists");

        let rebind = ProxyFlowState {
            registration: FlowRegistration::new(
                flow.clone(),
                new_owner,
                registration.policy_host().clone(),
                registration.context().clone(),
            ),
            owner: new_owner,
            context: state.context,
            attribution_token: state.attribution_token,
            connection_id: state.connection_id,
            claimed_at: state.claimed_at,
            last_check: now,
        };

        inner.proxy_flows.insert(flow, rebind);
        drop(inner);
        Ok(())
    }

    /// Release a previously claimed network flow.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the proxy session is invalid or the
    /// presented connection identifier does not own the claim.
    pub async fn release_network_flow(
        &self,
        proxy_session: ProxySessionToken,
        attribution_token: AttributionToken,
        connection_id: ProxyConnectionId,
    ) -> Result<(), PolicydError> {
        let mut inner = self.inner.lock().await;
        validate_session(&inner, &proxy_session)?;

        if let Some(state) = inner
            .proxy_flows
            .values_mut()
            .find(|state| state.attribution_token.as_ref() == Some(&attribution_token))
        {
            if state.connection_id != Some(connection_id) {
                return Err(proxy_error("unknown connection identifier"));
            }

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
        // Claimed flows live until release or proxy-session close. Intercepted
        // associations can stay idle for arbitrarily long periods, so an idle
        // TTL would kill live claims; the registry is bounded by
        // `MAX_PROXY_FLOWS` and session close clears every claim.
        if state.attribution_token.is_some() {
            return true;
        }

        now.saturating_duration_since(state.last_check) <= UNCLAIMED_TTL
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::types::{Pending, PolicyStore};

    use agent_sandbox_core::{
        FlowContext, FlowProtocol, NormalizedPolicyHost, ProcessIdentity, SandboxPaths,
        SocketIdentity, SocketInode, VerdictSource,
        socket_owner::{OwnerResolution, SocketProtocol, SocketTuple, resolve_owner_snapshot},
    };

    use std::{sync::Arc, time::Duration};

    fn test_store(dir: &tempfile::TempDir) -> PolicyStore {
        PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ))
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
    async fn redirected_flow_claim_returns_registered_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(&dir);

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let source = socket.local_addr().expect("socket address");
        let owner = test_udp_owner(source).await;

        let flow = NetworkFlowKey::try_new(
            FlowProtocol::Udp,
            source.ip(),
            source.port(),
            "1.1.1.1".parse().expect("valid destination"),
            443,
        )
        .expect("valid flow");

        let registration = FlowRegistration::new(
            flow.clone(),
            owner,
            NormalizedPolicyHost::parse("1.1.1.1").expect("valid host"),
            FlowContext::default(),
        );

        store
            .register_network_flow(registration)
            .await
            .expect("register flow");

        let claim = store
            .claim_network_flow_by_source(
                session,
                NetworkFlowSelector::new(
                    FlowProtocol::Udp,
                    source.ip(),
                    source.port().try_into().expect("non-zero source port"),
                    443.try_into().expect("non-zero destination port"),
                ),
                ProxyConnectionId::new(),
            )
            .await
            .expect("claim redirected flow");

        assert_eq!(claim.flow, flow);
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
        let owner = test_udp_owner(source).await;

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

    async fn test_udp_owner(source: std::net::SocketAddr) -> SocketIdentity {
        for _ in 0..100 {
            match resolve_owner_snapshot(
                SocketProtocol::Udp,
                SocketTuple::from_local(source.ip(), source.port()),
            ) {
                OwnerResolution::Unique(snapshot) => return snapshot.identity(),

                OwnerResolution::Missing => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }

                OwnerResolution::Ambiguous => panic!("expected unique UDP owner"),
            }
        }

        panic!("UDP owner did not become visible in procfs");
    }

    /// Register and claim one real UDP association owned by this test process.
    async fn test_udp_association(
        store: &Arc<PolicyStore>,
        session: &ProxySessionToken,
    ) -> (
        std::net::UdpSocket,
        NetworkFlowKey,
        ProxyConnectionId,
        AttributionToken,
    ) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let source = socket.local_addr().expect("socket address");
        let owner = test_udp_owner(source).await;

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

        let connection_id = ProxyConnectionId::new();

        let claim = store
            .claim_network_flow(session.clone(), flow.clone(), connection_id)
            .await
            .expect("claim flow");

        (socket, flow, connection_id, claim.attribution_token)
    }

    fn test_http_request(authority: &str, path: &str) -> HttpRequest {
        HttpRequest::parse_absolute("GET", &format!("https://{authority}{path}"))
            .expect("valid request")
    }

    #[tokio::test]
    async fn denied_stream_does_not_close_association() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("declarative.json"),
            r#"{
                "network": {
                    "http": {
                        "deny": [{"methods": ["GET"], "url": "https://example.com/deny"}],
                        "allow": [{"methods": ["GET"], "url": "https://example.com/allow"}]
                    }
                }
            }"#,
        )
        .expect("declarative policy");

        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, _flow, connection_id, token) = test_udp_association(&store, &session).await;

        let denied = store
            .check_http(
                session.clone(),
                ProxyRequestId::new(),
                token.clone(),
                test_http_request("example.com", "/deny"),
            )
            .await
            .expect("denied check should reply");

        assert!(!denied.allowed, "deny rule must apply");

        let allowed = store
            .check_http(
                session.clone(),
                ProxyRequestId::new(),
                token.clone(),
                test_http_request("example.com", "/allow"),
            )
            .await
            .expect("allowed check should reply");

        assert!(
            allowed.allowed,
            "allow rule must still apply on the same claim"
        );

        store
            .release_network_flow(session, token, connection_id)
            .await
            .expect("denied stream must not close the association");
    }

    #[tokio::test]
    async fn canceled_check_blocks_without_releasing_claim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, _flow, connection_id, token) = test_udp_association(&store, &session).await;
        let request_id = ProxyRequestId::new();

        store
            .cancel_check(session.clone(), request_id)
            .await
            .expect("cancel check");

        let reply = store
            .check_http(
                session.clone(),
                request_id,
                token.clone(),
                test_http_request("example.com", "/canceled"),
            )
            .await
            .expect("canceled check should reply");

        assert!(!reply.allowed, "canceled check must be blocked");

        assert_eq!(
            reply.error.as_deref(),
            Some("agent-sandbox: HTTP check cancelled")
        );

        store
            .release_network_flow(session, token, connection_id)
            .await
            .expect("cancellation must not release the claim");
    }

    #[tokio::test]
    async fn rebind_preserves_ownership_after_valid_migration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_old_socket, old_flow, connection_id, token) =
            test_udp_association(&store, &session).await;

        let migrated = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let migrated_source = migrated.local_addr().expect("socket address");

        let migrated_flow = NetworkFlowKey::try_new(
            FlowProtocol::Udp,
            migrated_source.ip(),
            migrated_source.port(),
            old_flow.destination_ip(),
            old_flow.destination_port().get(),
        )
        .expect("valid migrated flow");

        let migrated_owner = test_udp_owner(migrated_source).await;

        store
            .register_network_flow(FlowRegistration::new(
                migrated_flow.clone(),
                migrated_owner,
                NormalizedPolicyHost::parse("1.1.1.1").expect("valid host"),
                FlowContext::default(),
            ))
            .await
            .expect("register migrated flow");

        store
            .rebind_network_flow(
                session.clone(),
                token.clone(),
                connection_id,
                migrated_flow.clone(),
            )
            .await
            .expect("valid migration must rebind");

        {
            let inner = store.inner.lock().await;
            assert!(
                !inner.proxy_flows.contains_key(&old_flow),
                "old tuple must be released"
            );
            let state = inner
                .proxy_flows
                .get(&migrated_flow)
                .expect("migrated tuple must own the claim");
            assert_eq!(state.attribution_token.as_ref(), Some(&token));
            assert_eq!(state.connection_id, Some(connection_id));
            assert_eq!(state.registration.flow(), &migrated_flow);
            assert_eq!(state.registration.policy_host().to_string(), "1.1.1.1");
            drop(inner);
        }

        store
            .release_network_flow(session, token, connection_id)
            .await
            .expect("rebound claim must release with its stable identity");
    }

    #[tokio::test]
    async fn rebind_rejects_unknown_connection_identifier() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, _flow, connection_id, token) = test_udp_association(&store, &session).await;
        let migrated = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let migrated_source = migrated.local_addr().expect("socket address");

        let migrated_flow = NetworkFlowKey::try_new(
            FlowProtocol::Udp,
            migrated_source.ip(),
            migrated_source.port(),
            "1.1.1.1".parse().expect("valid destination"),
            443,
        )
        .expect("valid migrated flow");

        let error = store
            .rebind_network_flow(
                session.clone(),
                token.clone(),
                ProxyConnectionId::new(),
                migrated_flow,
            )
            .await
            .expect_err("unknown identifier must be rejected");

        assert!(error.to_string().contains("unknown connection identifier"));

        store
            .release_network_flow(session, token, connection_id)
            .await
            .expect("rejected rebind must not disturb the claim");
    }

    #[tokio::test]
    async fn rebind_rejects_changed_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, old_flow, connection_id, token) =
            test_udp_association(&store, &session).await;

        let migrated = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let migrated_source = migrated.local_addr().expect("socket address");

        let migrated_flow = NetworkFlowKey::try_new(
            FlowProtocol::Udp,
            migrated_source.ip(),
            migrated_source.port(),
            "1.1.1.1".parse().expect("valid destination"),
            8443,
        )
        .expect("valid migrated flow");

        let error = store
            .rebind_network_flow(session.clone(), token, connection_id, migrated_flow)
            .await
            .expect_err("changed destination must be rejected");

        assert!(
            error
                .to_string()
                .contains("rebind cannot change the flow destination")
        );

        assert!(store.inner.lock().await.proxy_flows.contains_key(&old_flow));
    }

    #[tokio::test]
    async fn rebind_rejects_unowned_path_and_non_udp_flows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, _old_flow, connection_id, token) =
            test_udp_association(&store, &session).await;

        let vanished = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let vanished_source = vanished.local_addr().expect("socket address");
        drop(vanished);

        let vanished_flow = NetworkFlowKey::try_new(
            FlowProtocol::Udp,
            vanished_source.ip(),
            vanished_source.port(),
            "1.1.1.1".parse().expect("valid destination"),
            443,
        )
        .expect("valid flow");

        store
            .register_network_flow(FlowRegistration::new(
                vanished_flow.clone(),
                test_owner(),
                NormalizedPolicyHost::parse("1.1.1.1").expect("valid host"),
                FlowContext::default(),
            ))
            .await
            .expect("register vanished flow");

        let error = store
            .rebind_network_flow(session.clone(), token.clone(), connection_id, vanished_flow)
            .await
            .expect_err("unowned path must be rejected");

        assert!(error.to_string().contains("socket owner changed"));

        let tcp_flow = NetworkFlowKey::try_new(
            FlowProtocol::Tcp,
            "127.0.0.1".parse().expect("valid source"),
            12345,
            "1.1.1.1".parse().expect("valid destination"),
            443,
        )
        .expect("valid flow");

        let error = store
            .rebind_network_flow(session.clone(), token.clone(), connection_id, tcp_flow)
            .await
            .expect_err("non-UDP rebind must be rejected");

        assert!(error.to_string().contains("rebind requires a UDP flow"));

        store
            .release_network_flow(session, token, connection_id)
            .await
            .expect("rejected rebinds must not disturb the claim");
    }

    #[tokio::test]
    async fn release_rejects_unknown_connection_identifier() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, _flow, connection_id, token) = test_udp_association(&store, &session).await;

        let error = store
            .release_network_flow(session.clone(), token.clone(), ProxyConnectionId::new())
            .await
            .expect_err("release with an unknown identifier must be rejected");

        assert!(error.to_string().contains("unknown connection identifier"));

        store
            .release_network_flow(session, token, connection_id)
            .await
            .expect("correct identifier must release the claim");
    }

    #[tokio::test]
    async fn ownership_loss_fails_checks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (socket, _flow, _connection_id, token) = test_udp_association(&store, &session).await;
        drop(socket);

        let error = store
            .check_http(
                session.clone(),
                ProxyRequestId::new(),
                token.clone(),
                test_http_request("example.com", "/lost"),
            )
            .await
            .expect_err("ownership loss must fail closed");

        assert!(error.to_string().contains("socket owner changed"));
    }

    #[tokio::test]
    async fn close_proxy_session_releases_all_claims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, _flow, connection_id, token) = test_udp_association(&store, &session).await;
        store.close_proxy_session(1).await;

        let error = store
            .check_http(
                session.clone(),
                ProxyRequestId::new(),
                token.clone(),
                test_http_request("example.com", "/after-close"),
            )
            .await
            .expect_err("session close must invalidate claims");

        assert!(
            error.to_string().contains("proxy session token is invalid"),
            "unexpected error: {error}"
        );

        let error = store
            .release_network_flow(session, token, connection_id)
            .await
            .expect_err("release after session close must reject the stale session");

        assert!(error.to_string().contains("proxy session token is invalid"));
    }

    #[tokio::test]
    async fn claimed_flows_survive_long_idle_periods() {
        // Intercepted associations can stay idle for arbitrarily long periods,
        // so a claimed flow must never be pruned by an idle TTL.
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("declarative.json"),
            r#"{"network":{"http":{"allow":[{"methods":["GET"],"url":"https://example.com/ok"}]}}}"#,
        )
        .expect("declarative policy");

        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let (_socket, flow, connection_id, token) = test_udp_association(&store, &session).await;

        {
            let mut inner = store.inner.lock().await;
            let state = inner.proxy_flows.get_mut(&flow).expect("claim exists");
            state.last_check = Instant::now()
                .checked_sub(Duration::from_hours(48))
                .expect("instant predates test");
            drop(inner);
        }

        let reply = store
            .check_http(
                session.clone(),
                ProxyRequestId::new(),
                token.clone(),
                test_http_request("example.com", "/ok"),
            )
            .await
            .expect("claim must survive long idle");

        assert!(reply.allowed, "long-idle claim must still reach policy");

        store
            .release_network_flow(session, token, connection_id)
            .await
            .expect("long-idle claim must release");
    }

    #[tokio::test]
    async fn unclaimed_registrations_still_prune_after_ttl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(test_store(&dir));

        let session = store
            .open_proxy_session(1)
            .await
            .expect("open session")
            .proxy_session;

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let source = socket.local_addr().expect("socket address");
        let owner = test_udp_owner(source).await;

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

        {
            let mut inner = store.inner.lock().await;
            let state = inner
                .proxy_flows
                .get_mut(&flow)
                .expect("registration exists");
            state.last_check = Instant::now()
                .checked_sub(Duration::from_secs(60))
                .expect("instant predates test");
            drop(inner);
        }

        let error = store
            .claim_network_flow(session, flow, ProxyConnectionId::new())
            .await
            .expect_err("unclaimed registration must prune after its TTL");

        assert!(error.to_string().contains("flow is not registered"));
    }
}
