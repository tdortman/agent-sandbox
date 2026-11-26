//! Policy store, network.

use std::{path::Path, time::Duration};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, CheckReply, NetworkRuleKey, ResolvedRequestContext, RpcReply,
    ScopeActionReply, Verdict, VerdictSource, host_pattern_matches, normalize_host,
};
use tokio::sync::oneshot;

use super::{
    decisions::DecisionAction,
    pending::{
        ApprovalKind, CapHit, Decision, TOO_MANY_PENDING, VerdictExit, cached_verdict,
        record_verdict,
    },
    state::ProxyCheckId,
    types::{NetworkWaiter, Pending, PendingNetwork, PolicyStore},
};
use crate::{error::PolicydError, wire::NetworkScopeOp};

/// How long a network verdict is cached after the first policy check for the
/// same hostname plus port. This deduplicates prompts when curl tries multiple
/// IPs for the same domain (each IP is a separate SYN, but they share the
/// same hostname from the DNS cache).
const NETWORK_VERDICT_CACHE_TTL: Duration = Duration::from_secs(1);

struct NetworkRequestIdentity<'a> {
    host: &'a str,
    port: u16,
    cwd: Option<&'a Path>,
    home: Option<&'a Path>,
    project_root: Option<&'a Path>,
    sandbox_session_id: Option<&'a str>,
    package: Option<&'a str>,
}

impl NetworkRequestIdentity<'_> {
    fn matches(&self, pending: &PendingNetwork) -> bool {
        pending.host == self.host
            && pending.port == self.port
            && pending.ctx.paths.cwd() == self.cwd
            && pending.ctx.paths.home() == self.home
            && pending.ctx.paths.project_root() == self.project_root
            && pending.ctx.sandbox_session_id.as_deref() == self.sandbox_session_id
            && pending.ctx.package.as_deref() == self.package
    }
}

struct NetworkWaitTarget<'a> {
    ctx: &'a ResolvedRequestContext,
    pending_id: &'a str,
    policy_host: String,
    port: u16,
    scheme: &'a str,
}

/// Waiters displaced when a network wait expires: the cancelled senders and
/// whether the expiring waiter was the last one (which seals a blocked
/// verdict into the cache).
struct ExpiredNetworkWait {
    canceled: Vec<oneshot::Sender<CheckReply>>,
    last: bool,
}
impl PolicyStore {
    pub(crate) async fn finish_network(
        &self,
        pending_id: &str,
        allowed: bool,
        source: VerdictSource,
        verdict_cache_key: Option<NetworkRuleKey>,
    ) {
        let verdict = Verdict { allowed, source };
        let mut inner = self.inner.lock().await;

        if let Some(waiters) = inner.pending.network_futures.remove(pending_id) {
            let reply = CheckReply::from_verdict(verdict.clone());

            for waiter in waiters {
                let _ = waiter.tx.send(reply.clone());
            }
        }

        // Cache the verdict for deduplication of multiple IPs from the same
        // DNS response (e.g. curl trying 6 IPv4 + 4 IPv6 for google.com).
        if let Some(key) = verdict_cache_key {
            record_verdict(&mut inner.network_verdict_cache, key, verdict);
        }
    }

    /// Request interactive approval for a network connection, prompting the
    /// policy UI when needed. Returns the cached or policy-derived verdict
    /// immediately when one already exists.
    pub async fn request_network_approval(
        &self,
        host: String,
        port: u16,
        scheme: String,
        url: String,
        ctx: ResolvedRequestContext,
    ) -> CheckReply {
        self.request_network_approval_with_aliases(host, port, scheme, url, ctx, Vec::new())
            .await
    }

    pub(crate) async fn request_network_approval_with_aliases(
        &self,
        host: String,
        port: u16,
        scheme: String,
        url: String,
        ctx: ResolvedRequestContext,
        aliases: Vec<String>,
    ) -> CheckReply {
        self.request_network_approval_with_aliases_cancellable(
            host, port, scheme, url, ctx, aliases, None, None,
        )
        .await
    }

    pub(crate) async fn request_network_approval_with_aliases_cancellable(
        &self,
        host: String,
        port: u16,
        scheme: String,
        url: String,
        ctx: ResolvedRequestContext,
        aliases: Vec<String>,
        waiter: Option<ProxyCheckId>,
        cancel: Option<oneshot::Receiver<()>>,
    ) -> CheckReply {
        let policy_host = normalize_host(&host);

        if self.policy_denied(&policy_host, port, &ctx) {
            tracing::info!(%policy_host, port, "check deny (project policy)");
            return CheckReply::denied(VerdictSource::policy());
        }

        if let Some(verdict) = self.network_verdict(&policy_host, port, &ctx, true).await {
            return CheckReply::from_verdict(verdict);
        }

        if !self.args.interactive_approval {
            return CheckReply::denied(VerdictSource::Blocked);
        }

        // Check the short-lived verdict cache before creating a new prompt.
        // This deduplicates prompts when curl tries multiple IPs for the
        // same domain (each IP is a separate SYN, but they share the
        // same hostname from the DNS cache).
        let cached = {
            let inner = self.inner.lock().await;

            cached_verdict(
                &inner.network_verdict_cache,
                &NetworkRuleKey {
                    host: policy_host.clone(),
                    port,
                },
                NETWORK_VERDICT_CACHE_TTL,
            )
        };

        if let Some(verdict) = cached {
            return CheckReply::from_verdict(verdict);
        }

        // Freeze the owner while the approval pends so its own timers stop:
        // a slow verdict must never time the connection out from under the
        // prompt. This covers every network approval (direct transport
        // checks and proxy flows alike). Unattributed flows have nobody to
        // freeze and keep today's prompt behavior; a failed freeze fails
        // closed without creating an approval.
        let _freeze_hold = match ctx.ids.pid() {
            None => None,
            Some(pid) => match self.cgroup_freeze.acquire(Some(pid), ctx.ids.uid()).await {
                Ok(hold) => hold,
                Err(error) => {
                    return CheckReply::blocked(format!(
                        "agent-sandbox: cannot freeze sandbox for network approval: {error}",
                    ));
                }
            },
        };

        let identity = NetworkRequestIdentity {
            host: &policy_host,
            port,
            cwd: ctx.paths.cwd(),
            home: ctx.paths.home(),
            project_root: ctx.paths.project_root(),
            sandbox_session_id: ctx.sandbox_session_id.as_deref(),
            package: ctx.package.as_deref(),
        };

        let (tx, rx) = oneshot::channel();

        let joined = {
            let mut inner = self.inner.lock().await;

            if let Some(proxy) = &waiter
                && inner
                    .pending
                    .network_futures
                    .values()
                    .flatten()
                    .any(|entry| entry.proxy.as_ref() == Some(proxy))
            {
                return CheckReply::blocked(
                    "agent-sandbox: duplicate in-flight network request ID",
                );
            }

            inner.pending.join_or_create(
                |board| &mut board.network_futures,
                NetworkWaiter {
                    proxy: waiter.clone(),
                    tx,
                },
                "net",
                |pending| matches!(pending, Pending::Network(net) if identity.matches(net)),
                |id, created_at| {
                    Pending::Network(PendingNetwork {
                        id,
                        created_at,
                        host: policy_host.clone(),
                        port,
                        scheme: scheme.clone(),
                        url,
                        aliases: agent_sandbox_core::hosts::sanitize_aliases(aliases),
                        ctx: ctx.clone(),
                    })
                },
            )
        };

        let joined = match joined {
            Ok(joined) => joined,
            Err(CapHit::Waiters) => {
                return CheckReply::blocked(
                    "agent-sandbox: too many waiters for one network approval",
                );
            }
            Err(CapHit::Pendings) => return CheckReply::blocked(TOO_MANY_PENDING),
        };

        if let Some(pending) = &joined.queued {
            Self::audit("pending", Some(policy_host.as_str()), Some(port), &scheme);

            // Late UI registration is flushed by `RegisterUi` in
            // `server::client` (see `flush_pending_to_ui`).
            self.announce(pending, &ctx).await;
        }

        self.await_network_verdict(
            NetworkWaitTarget {
                ctx: &ctx,
                pending_id: &joined.id,
                policy_host,
                port,
                scheme: &scheme,
            },
            rx,
            cancel,
            waiter,
        )
        .await
    }

    fn remove_network_waiter_locked(
        inner: &mut super::types::PolicyDecisionState,
        pending_id: &str,
        proxy: Option<&ProxyCheckId>,
    ) -> Vec<oneshot::Sender<CheckReply>> {
        let Some(mut waiters) = inner.pending.network_futures.remove(pending_id) else {
            return Vec::new();
        };

        let mut canceled = Vec::new();

        if let Some(proxy) = proxy {
            if let Some(index) = waiters
                .iter()
                .position(|waiter| waiter.proxy.as_ref() == Some(proxy))
            {
                canceled.push(waiters.remove(index).tx);
            }

            if waiters.is_empty() {
                inner.pending.pending.remove(pending_id);
            } else {
                inner
                    .pending
                    .network_futures
                    .insert(pending_id.to_owned(), waiters);
            }
        } else {
            canceled.extend(waiters.into_iter().map(|waiter| waiter.tx));
            inner.pending.pending.remove(pending_id);
        }

        canceled
    }

    async fn cancel_network_wait(
        &self,
        pending_id: &str,
        proxy: Option<&ProxyCheckId>,
    ) -> Vec<oneshot::Sender<CheckReply>> {
        let mut inner = self.inner.lock().await;
        let canceled = Self::remove_network_waiter_locked(&mut inner, pending_id, proxy);
        drop(inner);
        canceled
    }

    async fn expire_network_wait(
        &self,
        target: &NetworkWaitTarget<'_>,
        proxy: Option<&ProxyCheckId>,
    ) -> ExpiredNetworkWait {
        let mut inner = self.inner.lock().await;
        let canceled = Self::remove_network_waiter_locked(&mut inner, target.pending_id, proxy);

        let last = !inner
            .pending
            .network_futures
            .contains_key(target.pending_id);

        if last {
            record_verdict(
                &mut inner.network_verdict_cache,
                NetworkRuleKey {
                    host: target.policy_host.clone(),
                    port: target.port,
                },
                Verdict::denied(VerdictSource::Blocked),
            );
        }

        drop(inner);
        ExpiredNetworkWait { canceled, last }
    }

    async fn await_network_verdict(
        &self,
        target: NetworkWaitTarget<'_>,
        rx: oneshot::Receiver<CheckReply>,
        cancel: Option<oneshot::Receiver<()>>,
        proxy: Option<ProxyCheckId>,
    ) -> CheckReply {
        // A request without a cancel channel is never cancelled.
        let cancelled = async {
            match cancel {
                Some(cancel) => {
                    let _ = cancel.await;
                }
                None => std::future::pending().await,
            }
        };

        let waited = self
            .wait_for_verdict_or(target.ctx, target.pending_id, rx, cancelled, |_| {})
            .await;

        match waited {
            Ok(reply) => reply,
            Err(VerdictExit::NoUi) => {
                let expired = self.expire_network_wait(&target, proxy.as_ref()).await;

                for tx in expired.canceled {
                    let _ = tx.send(CheckReply::blocked(
                        "agent-sandbox: no policy UI registered",
                    ));
                }

                tracing::warn!(
                    host = %target.policy_host,
                    port = target.port,
                    last = expired.last,
                    "network approval blocked (no policy UI)"
                );

                CheckReply::blocked(
                    "agent-sandbox: no policy UI registered (agent-sandbox-ui or auto-spawn)",
                )
            }
            Err(VerdictExit::ChannelClosed) => CheckReply::denied(VerdictSource::Blocked),
            Err(VerdictExit::Timeout) => {
                let expired = self.expire_network_wait(&target, proxy.as_ref()).await;

                for tx in expired.canceled {
                    let _ = tx.send(CheckReply::blocked(
                        "agent-sandbox: network approval timed out",
                    ));
                }

                Self::audit(
                    "timeout",
                    Some(&target.policy_host),
                    Some(target.port),
                    target.scheme,
                );

                tracing::warn!(
                    host = %target.policy_host,
                    port = target.port,
                    last = expired.last,
                    "network approval timed out"
                );

                CheckReply::blocked(
                    "agent-sandbox: network approval timed out (no response from policy UI)",
                )
            }
            Err(VerdictExit::Cancelled(())) => {
                let canceled = self
                    .cancel_network_wait(target.pending_id, proxy.as_ref())
                    .await;

                for tx in canceled {
                    let _ = tx.send(CheckReply::blocked(
                        "agent-sandbox: network check cancelled",
                    ));
                }

                CheckReply::blocked("agent-sandbox: network check cancelled")
            }
        }
    }
}

/// The network kind of pending approval. Its waiters live in
/// [`PolicyStore::request_network_approval`]'s own flow: one proxy check can
/// leave a prompt without ending it.
pub(super) struct NetworkApproval;

impl ApprovalKind for NetworkApproval {
    type Key = NetworkRuleKey;
    type Pending = PendingNetwork;
    type Target = NetworkRuleKey;

    const FAILED_APPROVAL_BLOCKS: bool = true;

    fn into_pending(pending: PendingNetwork) -> Pending {
        Pending::Network(pending)
    }

    fn id(pending: &PendingNetwork) -> &str {
        &pending.id
    }

    fn key(pending: &PendingNetwork) -> NetworkRuleKey {
        NetworkRuleKey {
            host: pending.host.clone(),
            port: pending.port,
        }
    }

    async fn decided_verdict(store: &PolicyStore, pending: &PendingNetwork) -> Option<Verdict> {
        if pending.port == 0 {
            return None;
        }

        // A once grant is left for the next fresh check to consume.
        store
            .allow_verdict(&pending.host, pending.port, &pending.ctx)
            .await
            .filter(|verdict| !verdict.is_once())
    }

    async fn finish(store: &PolicyStore, pending_id: &str, key: NetworkRuleKey, verdict: Verdict) {
        store
            .finish_network(pending_id, verdict.allowed, verdict.source, Some(key))
            .await;
    }

    fn approval_target(
        pending: &PendingNetwork,
        decision: &Decision,
    ) -> Result<NetworkRuleKey, PolicydError> {
        let host = match &decision.target {
            None => pending.host.clone(),
            Some(ApprovalTarget::NetworkHost { host }) => host.clone(),
            Some(_) => return Err(PolicydError::InvalidDecisionTarget),
        };

        if !host_pattern_matches(&host, &pending.host) {
            return Err(PolicydError::InvalidDecisionTarget);
        }

        if decision.scope == ApprovalScope::Once && host != pending.host {
            return Err(PolicydError::InvalidDecisionTarget);
        }

        Ok(NetworkRuleKey::new(host, pending.port))
    }

    // A once denial is recorded through scope application.
    fn once_skips_scope(action: DecisionAction) -> bool {
        action == DecisionAction::Approve
    }

    fn audit_once(_pending: &PendingNetwork, target: &NetworkRuleKey, action: DecisionAction) {
        PolicyStore::audit(
            action.audit_verb(),
            Some(&target.host),
            Some(target.port),
            ApprovalScope::Once.as_str(),
        );
    }

    fn decided_key(_pending: &PendingNetwork, target: &NetworkRuleKey) -> NetworkRuleKey {
        target.clone()
    }

    fn once_reply(_pending: &PendingNetwork, target: NetworkRuleKey) -> ScopeActionReply {
        ScopeActionReply::ok_network(target.host, target.port, ApprovalScope::Once, None)
    }

    async fn apply_scope(
        store: &PolicyStore,
        pending: &PendingNetwork,
        target: NetworkRuleKey,
        decision: Decision,
    ) -> RpcReply {
        store
            .apply_network_scope(
                NetworkScopeOp {
                    host: target.host,
                    port: target.port,
                    scope: decision.scope,
                    wire: PolicyStore::scope_wire_for_context(decision.wire, &pending.ctx),
                },
                decision.action,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use agent_sandbox_core::{ApprovalScope, NetworkRuleKey, VerdictSource};

    use super::{NetworkRequestIdentity, PendingNetwork, PolicyStore};

    fn pending_network(host: &str, sandbox_session_id: Option<&str>) -> PendingNetwork {
        PendingNetwork {
            id: "net:1".into(),
            created_at: 0.0,
            host: host.into(),
            port: 443,
            scheme: "tcp".into(),
            url: format!("tcp://{host}:443"),
            aliases: Vec::new(),
            ctx: ResolvedRequestContext {
                paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                ids: ProcessIds::default(),
                sandbox_session_id: sandbox_session_id.map(str::to_string),
                package: None,
            },
        }
    }

    #[test]
    fn network_identity_matches_same_host_and_context() {
        let cwd = Some("/repo".to_string());
        let home = Some("/home/user".to_string());
        let project_root = Some("/repo".to_string());
        let sandbox_session_id = Some("sandbox-a".to_string());

        let identity = NetworkRequestIdentity {
            host: "example.com",
            port: 443,
            cwd: cwd.as_deref().map(Path::new),
            home: home.as_deref().map(Path::new),
            project_root: project_root.as_deref().map(Path::new),
            sandbox_session_id: sandbox_session_id.as_deref(),
            package: None,
        };

        assert!(identity.matches(&pending_network("example.com", Some("sandbox-a"))));
        assert!(!identity.matches(&pending_network("example.com", Some("sandbox-b"))));
        assert!(!identity.matches(&pending_network("other.example", Some("sandbox-a"))));
    }

    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use agent_sandbox_core::{
        FileAccess, ProcessIds, ResolvedRequestContext, SandboxPaths, UiPush,
    };
    use tokio::{io::AsyncReadExt, net::UnixStream, sync::Mutex};

    use crate::store::{
        test_store,
        types::{Pending, UiClient, UiSessionContext},
    };

    fn request_context() -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
            ),
            // pid 0 short-circuits resolve_context, so the explicit
            // paths are preserved verbatim.
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-cap".into()),
            package: None,
        }
    }

    async fn request_network(
        store: &PolicyStore,
        host: &str,
        port: u16,
    ) -> agent_sandbox_core::CheckReply {
        store
            .request_network_approval(
                host.into(),
                port,
                "tcp".into(),
                format!("tcp://{host}:{port}"),
                request_context(),
            )
            .await
    }

    #[tokio::test]
    async fn session_allow_is_reused_without_creating_second_prompt() {
        let store = test_store();
        let (a, _b) = UnixStream::pair().expect("UI stream pair");
        let (_, ui_write) = a.into_split();

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "ui1".into(),
                writer: Arc::new(Mutex::new(ui_write)),
            });
            inner
                .ui_context_by_session
                .insert("ui1".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-cap".into()),
                    ..Default::default()
                });
            inner
                .session
                .session_allow
                .entry("ui1".into())
                .or_default()
                .insert(NetworkRuleKey::new("example.com", 443));
        }

        let first = request_network(&store, "example.com", 443).await;

        assert!(
            first.verdict.allowed,
            "session approval should allow first request"
        );

        assert_eq!(
            first.verdict.source,
            VerdictSource::Scope(ApprovalScope::Session)
        );

        assert!(
            store.pending_summaries().await.is_empty(),
            "session approval must not create a pending prompt"
        );

        let second = request_network(&store, "example.com", 443).await;

        assert!(
            second.verdict.allowed,
            "session approval should allow second request"
        );

        assert_eq!(
            second.verdict.source,
            VerdictSource::Scope(ApprovalScope::Session)
        );

        assert!(
            store.pending_summaries().await.is_empty(),
            "second session-approved request must not create a pending prompt"
        );
    }

    #[tokio::test]
    async fn once_allow_is_consumed_before_second_network_prompt() {
        let store = Arc::new(test_store());

        {
            let mut inner = store.inner.lock().await;
            inner
                .session
                .once_allow
                .insert(NetworkRuleKey::new("example.com", 443));
        }

        let first = request_network(&store, "example.com", 443).await;

        assert!(
            first.verdict.allowed,
            "Once grant should allow the first request"
        );

        assert_eq!(
            first.verdict.source,
            VerdictSource::Scope(ApprovalScope::Once)
        );

        assert!(
            store.inner.lock().await.session.once_allow.is_empty(),
            "Once grant must be consumed by the pre-prompt check"
        );

        let task_store = store.clone();

        let task =
            tokio::spawn(async move { request_network(&task_store, "example.com", 443).await });

        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending
                    .pending
                    .keys()
                    .find(|id| id.starts_with("net:"))
                    .cloned()
                {
                    break id;
                }
                assert!(
                    Instant::now() < deadline,
                    "second request did not create pending"
                );
                drop(inner);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        store
            .finish_network(&pending_id, false, VerdictSource::User, None)
            .await;

        let second = task.await.expect("second request should not panic");

        assert!(
            !second.verdict.allowed,
            "second request must not reuse Once grant"
        );
    }

    fn pending_network_owned(host: String) -> PendingNetwork {
        PendingNetwork {
            id: format!("net:{host}"),
            created_at: 0.0,
            host,
            port: 443,
            scheme: "tcp".into(),
            url: "tcp://seed".into(),
            aliases: Vec::new(),
            ctx: ResolvedRequestContext {
                paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                ids: ProcessIds::default(),
                sandbox_session_id: Some("sandbox-cap".into()),
                package: None,
            },
        }
    }

    #[tokio::test]
    async fn network_pending_cap_blocks_new_prompts() {
        let store = test_store();

        {
            let mut inner = store.inner.lock().await;
            for i in 0..crate::store::types::MAX_PENDING_APPROVALS {
                let id = format!("net:seed{i}");
                let mut pending = pending_network_owned(format!("host{i}.example"));
                pending.id = id;
                let pending = Pending::Network(pending);
                inner
                    .pending
                    .pending
                    .insert(pending.id().to_owned(), pending);
            }
            drop(inner);
        }

        let reply = request_network(&store, "overflow.example", 443).await;
        assert!(!reply.verdict.allowed);
        assert_eq!(reply.verdict.source, VerdictSource::Blocked);
        let err = reply.error.unwrap_or_default();
        assert!(err.contains("too many pending"), "got: {err}");
        let pending_count = store.inner.lock().await.pending.pending.len();

        assert_eq!(
            pending_count,
            crate::store::types::MAX_PENDING_APPROVALS,
            "pending cap must not grow on block"
        );
    }

    #[tokio::test]
    async fn network_waiter_cap_blocks_extra_waiter() {
        let store = test_store();

        {
            let mut inner = store.inner.lock().await;
            let mut net = pending_network("example.com", Some("sandbox-cap"));
            net.id = "net:open".into();
            let pending = Pending::Network(net);
            inner
                .pending
                .pending
                .insert(pending.id().to_owned(), pending);
            for _ in 0..crate::store::types::MAX_WAITERS_PER_PENDING {
                let (tx, _rx) = tokio::sync::oneshot::channel();
                inner
                    .pending
                    .network_futures
                    .entry("net:open".into())
                    .or_default()
                    .push(super::NetworkWaiter { proxy: None, tx });
            }
        }

        let reply = request_network(&store, "example.com", 443).await;
        assert!(!reply.verdict.allowed);
        assert_eq!(reply.verdict.source, VerdictSource::Blocked);
        let err = reply.error.unwrap_or_default();
        assert!(err.contains("too many waiters"), "got: {err}");
    }

    #[tokio::test]
    async fn connected_ui_receives_network_prompt_by_path_without_session() {
        let store = test_store();
        let (a, b) = UnixStream::pair().expect("unix stream pair");
        let (_, ui_write) = a.into_split();
        let (mut ui_read, _) = b.into_split();

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "ui1".into(),
                writer: Arc::new(Mutex::new(ui_write)),
            });
            inner
                .ui_context_by_session
                .insert("ui1".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    ..Default::default()
                });
        }

        let payload = UiPush::NetworkRequest {
            id: "net:ui".into(),
            host: Some("example.com".into()),
            port: Some(443),
            scheme: Some("tcp".into()),
            url: Some("tcp://example.com:443".into()),
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            package: None,
        };

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        store.notify_general_ui(&ctx, &payload).await;
        let mut buf = [0u8; 1024];

        let n = tokio::time::timeout(Duration::from_secs(1), ui_read.read(&mut buf))
            .await
            .expect("UI should receive notification")
            .expect("read should succeed");

        let received = String::from_utf8_lossy(&buf[..n]);
        assert!(received.contains("net:ui"), "got: {received}");
    }

    #[tokio::test]
    async fn notify_network_ui_sends_to_standalone() {
        let store = test_store();
        let (a, b) = UnixStream::pair().expect("unix stream pair");
        let (_, standalone_write) = a.into_split();
        let (mut standalone_read, _) = b.into_split();

        // Register standalone UI client
        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(2, UiClient {
                session_id: "ui1".into(),
                writer: Arc::new(Mutex::new(standalone_write)),
            });
            inner
                .ui_context_by_session
                .insert("ui1".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    ..Default::default()
                });
        }

        let payload = UiPush::NetworkRequest {
            id: "net:2".into(),
            host: Some("example.com".into()),
            port: Some(443),
            scheme: Some("tcp".into()),
            url: Some("tcp://example.com:443".into()),
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            package: None,
        };

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        store.notify_general_ui(&ctx, &payload).await;

        // Standalone should have received it
        let mut buf = [0u8; 1024];

        let n = tokio::time::timeout(Duration::from_secs(1), standalone_read.read(&mut buf))
            .await
            .expect("standalone should receive notification")
            .expect("read should succeed");

        assert!(n > 0, "standalone should receive data");
        let received = String::from_utf8_lossy(&buf[..n]);

        assert!(
            received.contains("net:2"),
            "standalone should receive network request for net:2, got: {received}"
        );
    }

    #[tokio::test]
    async fn request_network_approval_prompts_already_registered_standalone_immediately() {
        // A registered standalone UI must receive the network prompt without
        // delay. Late UI registration is flushed by `RegisterUi` in
        // `server::client` (see `flush_pending_to_ui`).
        let store = Arc::new(test_store());

        let (a, b) = UnixStream::pair().expect("unix stream pair");
        let (_, standalone_write) = a.into_split();
        let (mut standalone_read, _) = b.into_split();

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "ui1".into(),
                writer: Arc::new(Mutex::new(standalone_write)),
            });
            inner
                .ui_context_by_session
                .insert("ui1".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-cap".into()),
                    ..Default::default()
                });
        }

        let store_for_task = store.clone();

        let task =
            tokio::spawn(async move { request_network(&store_for_task, "fast.example", 53).await });

        let mut buf = [0u8; 4096];

        let n = tokio::time::timeout(Duration::from_millis(200), standalone_read.read(&mut buf))
            .await
            .expect("standalone UI should receive network prompt within 200ms")
            .expect("read should succeed");

        let received = String::from_utf8_lossy(&buf[..n]);

        assert!(
            received.contains("net:") && received.contains("fast.example"),
            "expected net: and fast.example in prompt, got: {received}"
        );

        // Approve the pending so the spawned task does not hang on the rx
        // channel.
        let pending_id = {
            let inner = store.inner.lock().await;
            inner
                .pending
                .pending
                .keys()
                .find(|k| k.starts_with("net:"))
                .cloned()
                .expect("pending network request should be tracked")
        };

        store
            .finish_network(
                &pending_id,
                true,
                VerdictSource::policy_with_comment("test"),
                None,
            )
            .await;

        let _reply = task.await.expect("task should not panic");
    }

    #[tokio::test]
    async fn cli_approval_during_ui_wait_unblocks_request_promptly() {
        // Regression: a CLI approval that arrives during the pre-verdict
        // UI-registration wait used to be ignored. The request would only
        // return after the (multi-minute) UI wait timed out with `blocked`.
        let store = Arc::new(test_store());

        let store_for_task = store.clone();

        let task =
            tokio::spawn(
                async move { request_network(&store_for_task, "slow.example", 443).await },
            );

        // Wait for the request to register a pending. The task is now
        // inside the UI-registration wait loop.
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending
                    .pending
                    .keys()
                    .find(|k| k.starts_with("net:"))
                    .cloned()
                {
                    break id;
                }
                assert!(
                    Instant::now() < deadline,
                    "request never registered a pending"
                );
                drop(inner);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        // No UI is registered; a CLI once approval finishes the pending the
        // same way.
        store
            .finish_network(
                &pending_id,
                true,
                VerdictSource::policy_with_comment("cli"),
                None,
            )
            .await;

        let reply = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");

        assert!(
            reply.verdict.allowed,
            "expected allowed reply, got: {reply:?}"
        );

        assert_eq!(
            reply.verdict.source,
            VerdictSource::policy_with_comment("cli")
        );
    }

    #[tokio::test]
    async fn filesystem_standalone_matching_works() {
        let store = test_store();
        let (a, b) = UnixStream::pair().expect("unix stream pair");
        let (_, fs_write) = a.into_split();
        let (mut fs_read, _) = b.into_split();

        // Register standalone UI client
        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(3, UiClient {
                session_id: "ui2".into(),
                writer: Arc::new(Mutex::new(fs_write)),
            });
            inner
                .ui_context_by_session
                .insert("ui2".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    ..Default::default()
                });
        }

        // Insert a filesystem pending and flush
        let pending = Pending::Filesystem(crate::store::types::PendingFilesystem {
            id: "fs:1".into(),
            created_at: 0.0,
            path: "/repo/file.txt".into(),
            access: FileAccess::Read,
            ctx: ResolvedRequestContext {
                paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                ids: ProcessIds::default(),
                sandbox_session_id: None,
                package: None,
            },
        });

        {
            let mut inner = store.inner.lock().await;
            inner
                .pending
                .pending
                .insert(pending.id().to_owned(), pending);
        }

        store.flush_pending_to_ui().await;

        // Standalone should have received the filesystem request
        let mut buf = [0u8; 1024];

        let n = tokio::time::timeout(Duration::from_secs(1), fs_read.read(&mut buf))
            .await
            .expect("standalone should receive filesystem notification")
            .expect("read should succeed");

        assert!(n > 0, "standalone should receive data");
        let received = String::from_utf8_lossy(&buf[..n]);

        assert!(
            received.contains("fs:1"),
            "standalone should receive filesystem request for fs:1, got: {received}"
        );
    }
}
