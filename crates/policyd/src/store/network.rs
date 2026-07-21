//! Policy store, network.
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    CheckReply, NetworkRuleKey, ProcessIds, ResolvedRequestContext, SandboxPaths, UiPush,
    VerdictSource, attach_ui_aliases, normalize_host,
};
use tokio::{sync::oneshot, time};
use uuid::Uuid;

use super::types::{
    MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, NetworkWaiter, Pending, PendingKind,
    PendingNetwork, PolicyStore, VerdictEntry, enforce_verdict_cache_limit,
};
use crate::wire::{NetworkCheckRequest, UiSpawnContext, UiSpawnGate};

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
}

impl NetworkRequestIdentity<'_> {
    fn matches(&self, pending: &PendingNetwork) -> bool {
        pending.host == self.host
            && pending.port == self.port
            && pending.cwd.as_deref() == self.cwd
            && pending.home.as_deref() == self.home
            && pending.project_root.as_deref() == self.project_root
            && pending.sandbox_session_id.as_deref() == self.sandbox_session_id
    }
}

struct PendingNetResult {
    id: String,
    is_new: bool,
    rx: oneshot::Receiver<CheckReply>,
}

struct NetworkWaitTarget<'a> {
    ctx: &'a ResolvedRequestContext,
    pending_id: &'a str,
    policy_host: String,
    port: u16,
    scheme: &'a str,
}

impl PolicyStore {
    /// Finish pending network checks that declarative/session policy already
    /// allows (e.g. after a UI client registers).
    pub async fn resolve_pending_declarative_allow(&self) {
        let pending: Vec<Pending> = self
            .inner
            .lock()
            .await
            .pending_values()
            .filter(|p| p.kind() == PendingKind::Network)
            .cloned()
            .collect();
        for p in pending {
            let Pending::Network(net) = &p else {
                continue;
            };
            let host = net.host.clone();
            let port = if net.port > 0 {
                net.port
            } else {
                continue;
            };
            let merge = ResolvedRequestContext {
                paths: SandboxPaths::from_wire(
                    net.cwd.clone(),
                    net.home.clone(),
                    net.project_root.clone(),
                ),
                ids: ProcessIds::default(),
                sandbox_session_id: net.sandbox_session_id.clone(),
            };
            let Some(verdict) = self.allow_verdict(&host, port, &merge).await else {
                continue;
            };
            if verdict.is_policy_denied() || verdict.is_once() {
                continue;
            }
            tracing::info!(
                %host,
                port,
                source = %verdict.source,
                pending_id = %p.id(),
            );
            self.finish_network(
                p.id(),
                true,
                verdict.source,
                Some(NetworkRuleKey {
                    host: host.clone(),
                    port,
                }),
            )
            .await;
            self.inner.lock().await.take_pending(p.id());
        }
    }

    pub(crate) async fn finish_network(
        &self,
        pending_id: &str,
        allowed: bool,
        source: VerdictSource,
        verdict_cache_key: Option<NetworkRuleKey>,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.network_futures.remove(pending_id) {
            let reply = if allowed {
                CheckReply::allowed(source.clone())
            } else {
                CheckReply::denied(source.clone())
            };
            for waiter in waiters {
                let _ = waiter.tx.send(reply.clone());
            }
        }
        // Cache the verdict for deduplication of multiple IPs from the same
        // DNS response (e.g. curl trying 6 IPv4 + 4 IPv6 for google.com).
        if let Some(key) = verdict_cache_key {
            inner.network_verdict_cache.insert(key, VerdictEntry {
                allowed,
                source,
                time: Instant::now(),
            });
            enforce_verdict_cache_limit(&mut inner.network_verdict_cache);
        }
    }

    pub async fn request_network_approval(&self, req: NetworkCheckRequest) -> CheckReply {
        self.request_network_approval_with_aliases(req, Vec::new())
            .await
    }

    pub(crate) async fn request_network_approval_with_aliases(
        &self,
        req: NetworkCheckRequest,
        aliases: Vec<String>,
    ) -> CheckReply {
        self.request_network_approval_with_aliases_cancellable(req, aliases, None, None)
            .await
    }

    pub(crate) async fn request_network_approval_with_aliases_cancellable(
        &self,
        req: NetworkCheckRequest,
        aliases: Vec<String>,
        waiter: Option<(
            agent_sandbox_core::ProxySessionToken,
            agent_sandbox_core::ProxyRequestId,
        )>,
        cancel: Option<oneshot::Receiver<()>>,
    ) -> CheckReply {
        let NetworkCheckRequest {
            host,
            port,
            scheme,
            url,
            ctx,
        } = req;
        let policy_host = normalize_host(&host);
        let wire_ids = ctx.ids;
        let cwd = ctx.paths.cwd_path();
        let home = ctx.paths.home_path();
        let project_root = ctx.paths.project_root_path();
        let sandbox_session_id = ctx.sandbox_session_id.clone();
        if self.policy_denied(&policy_host, port, &ctx) {
            tracing::info!(%policy_host, port, "check deny (project policy)");
            return CheckReply::denied(VerdictSource::policy());
        }
        if let Some(verdict) = self
            .policy_evaluation(&ctx)
            .network_verdict(&policy_host, port, true)
            .await
        {
            return CheckReply::from_verdict(verdict);
        }
        if !self.args.interactive_approval {
            return CheckReply::denied(VerdictSource::Blocked);
        }

        // Check the short-lived verdict cache before creating a new prompt.
        // This deduplicates prompts when curl tries multiple IPs for the
        // same domain (each IP is a separate SYN, but they share the
        // same hostname from the DNS cache).
        if let Some(reply) = self.check_network_verdict_cache(&policy_host, port).await {
            return reply;
        }

        let identity = NetworkRequestIdentity {
            host: &policy_host,
            port,
            cwd: cwd.as_deref(),
            home: home.as_deref(),
            project_root: project_root.as_deref(),
            sandbox_session_id: sandbox_session_id.as_deref(),
        };
        let result = match self
            .dedup_or_create_pending_network(&identity, &scheme, &url, &aliases, waiter.as_ref())
            .await
        {
            Ok(r) => r,
            Err(reply) => return reply,
        };
        if result.is_new {
            Self::audit("pending", Some(policy_host.as_str()), Some(port), &scheme);
            // Notify immediately. Late UI registration is flushed by
            // `RegisterUi` in `server::client` (see `flush_pending_to_ui`).
            self.notify_general_ui(&ctx, &UiPush::NetworkRequest {
                id: result.id.clone(),
                host: Some(policy_host.clone()),
                port: Some(port),
                scheme: Some(scheme.clone()),
                url: attach_ui_aliases(Some(url.clone()), &aliases),
                cwd: cwd.clone(),
                home: home.clone(),
                project_root: project_root.clone(),
            })
            .await;
            if !self.has_ui_for_context(&ctx).await {
                let mut spawn_uid = wire_ids.uid();
                if spawn_uid.is_none_or(|u| u == 0)
                    && let Some(h) = &home
                {
                    spawn_uid =
                        nix::unistd::User::from_name(&Self::user_for_home(Some(h.as_path())))
                            .ok()
                            .flatten()
                            .map(|u| u.uid.as_raw());
                }
                let spawn = UiSpawnContext {
                    gate: UiSpawnGate {
                        has_matching_ui: false,
                    },
                    uid: spawn_uid,
                    home: home.as_deref(),
                    cwd: cwd.as_deref(),
                    project_root: project_root.as_deref(),
                    sandbox_session_id: sandbox_session_id.as_deref(),
                };
                self.spawn_policy_ui(spawn).await;
            }
        }

        self.await_network_verdict(
            NetworkWaitTarget {
                ctx: &ctx,
                pending_id: &result.id,
                policy_host,
                port,
                scheme: &scheme,
            },
            result.rx,
            cancel,
            waiter,
        )
        .await
    }

    async fn check_network_verdict_cache(
        &self,
        policy_host: &str,
        port: u16,
    ) -> Option<CheckReply> {
        let inner = self.inner.lock().await;
        if let Some(entry) = inner.network_verdict_cache.get(&NetworkRuleKey {
            host: policy_host.to_string(),
            port,
        }) && entry.time.elapsed() < NETWORK_VERDICT_CACHE_TTL
        {
            return Some(if entry.allowed {
                CheckReply::allowed(entry.source.clone())
            } else {
                CheckReply::denied(entry.source.clone())
            });
        }
        drop(inner);
        None
    }

    async fn dedup_or_create_pending_network(
        &self,
        identity: &NetworkRequestIdentity<'_>,
        scheme: &str,
        url: &str,
        aliases: &[String],
        waiter: Option<&(
            agent_sandbox_core::ProxySessionToken,
            agent_sandbox_core::ProxyRequestId,
        )>,
    ) -> Result<PendingNetResult, CheckReply> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;
        if let Some(proxy) = waiter
            && inner
                .network_futures
                .values()
                .flatten()
                .any(|entry| entry.proxy.as_ref() == Some(proxy))
        {
            return Err(CheckReply::blocked(
                "agent-sandbox: duplicate in-flight network request ID",
            ));
        }
        let proxy = waiter.cloned();
        let existing_id = inner.pending_values().find_map(|pending| {
            let Pending::Network(net) = pending else {
                return None;
            };
            identity.matches(net).then(|| net.id.clone())
        });
        if let Some(existing_id) = existing_id {
            let waiter_count = inner.network_futures.get(&existing_id).map_or(0, Vec::len);
            if waiter_count >= MAX_WAITERS_PER_PENDING {
                return Err(CheckReply::blocked(
                    "agent-sandbox: too many waiters for one network approval",
                ));
            }
            inner
                .network_futures
                .entry(existing_id.clone())
                .or_default()
                .push(NetworkWaiter { proxy, tx });
            drop(inner);
            return Ok(PendingNetResult {
                id: existing_id,
                is_new: false,
                rx,
            });
        }
        if inner.pending_len() >= MAX_PENDING_APPROVALS {
            return Err(CheckReply::blocked(
                "agent-sandbox: too many pending approvals",
            ));
        }
        let pending_id = format!("net:{}", Uuid::now_v7().simple());
        inner
            .network_futures
            .insert(pending_id.clone(), vec![NetworkWaiter { proxy, tx }]);
        inner.insert_pending(Pending::Network(PendingNetwork {
            id: pending_id.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64()),
            host: identity.host.to_string(),
            port: identity.port,
            scheme: scheme.to_string(),
            url: url.to_string(),
            aliases: aliases.to_vec(),
            cwd: identity.cwd.map(PathBuf::from),
            home: identity.home.map(PathBuf::from),
            project_root: identity.project_root.map(PathBuf::from),
            sandbox_session_id: identity.sandbox_session_id.map(String::from),
        }));
        drop(inner);
        Ok(PendingNetResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    fn remove_network_waiter_locked(
        inner: &mut super::types::PolicyDecisionState,
        pending_id: &str,
        proxy: Option<&(
            agent_sandbox_core::ProxySessionToken,
            agent_sandbox_core::ProxyRequestId,
        )>,
    ) -> Vec<oneshot::Sender<CheckReply>> {
        let Some(mut waiters) = inner.network_futures.remove(pending_id) else {
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
                inner.take_pending(pending_id);
            } else {
                inner.network_futures.insert(pending_id.to_owned(), waiters);
            }
        } else {
            canceled.extend(waiters.into_iter().map(|waiter| waiter.tx));
            inner.take_pending(pending_id);
        }
        canceled
    }

    async fn cancel_network_wait(
        &self,
        pending_id: &str,
        proxy: Option<&(
            agent_sandbox_core::ProxySessionToken,
            agent_sandbox_core::ProxyRequestId,
        )>,
    ) -> Vec<oneshot::Sender<CheckReply>> {
        let mut inner = self.inner.lock().await;
        let canceled = Self::remove_network_waiter_locked(&mut inner, pending_id, proxy);
        drop(inner);
        canceled
    }

    async fn expire_network_wait(
        &self,
        target: &NetworkWaitTarget<'_>,
        proxy: Option<&(
            agent_sandbox_core::ProxySessionToken,
            agent_sandbox_core::ProxyRequestId,
        )>,
    ) -> (Vec<oneshot::Sender<CheckReply>>, bool) {
        let mut inner = self.inner.lock().await;
        let canceled = Self::remove_network_waiter_locked(&mut inner, target.pending_id, proxy);
        let last = !inner.network_futures.contains_key(target.pending_id);
        if last {
            inner.network_verdict_cache.insert(
                NetworkRuleKey {
                    host: target.policy_host.clone(),
                    port: target.port,
                },
                VerdictEntry {
                    allowed: false,
                    source: VerdictSource::Blocked,
                    time: Instant::now(),
                },
            );
            enforce_verdict_cache_limit(&mut inner.network_verdict_cache);
        }
        drop(inner);
        (canceled, last)
    }

    async fn await_network_verdict(
        &self,
        target: NetworkWaitTarget<'_>,
        rx: oneshot::Receiver<CheckReply>,
        cancel: Option<oneshot::Receiver<()>>,
        proxy: Option<(
            agent_sandbox_core::ProxySessionToken,
            agent_sandbox_core::ProxyRequestId,
        )>,
    ) -> CheckReply {
        let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
        let ui_deadline = Instant::now() + ui_wait;
        tokio::pin!(rx);
        let (_fallback_cancel_tx, fallback_cancel_rx) = oneshot::channel();
        let cancel_rx = cancel.unwrap_or(fallback_cancel_rx);
        tokio::pin!(cancel_rx);
        loop {
            if self.has_ui_for_context(target.ctx).await {
                break;
            }
            let now = Instant::now();
            if now >= ui_deadline {
                let (canceled, last) = self.expire_network_wait(&target, proxy.as_ref()).await;
                for tx in canceled {
                    let _ = tx.send(CheckReply::blocked(
                        "agent-sandbox: no policy UI registered",
                    ));
                }
                tracing::warn!(
                    host = %target.policy_host,
                    port = target.port,
                    last,
                    "network approval blocked (no policy UI)"
                );
                return CheckReply::blocked(
                    "agent-sandbox: no policy UI registered (agent-sandbox-ui or auto-spawn)",
                );
            }
            let sleep_dur = (ui_deadline - now).min(Duration::from_millis(50));
            tokio::select! {
                biased;
                () = time::sleep(sleep_dur) => {}
                result = &mut rx => {
                    return result.unwrap_or_else(|_| CheckReply::denied(VerdictSource::Blocked));
                }
                _ = &mut cancel_rx => {
                    let canceled = self
                        .cancel_network_wait(target.pending_id, proxy.as_ref())
                        .await;
                    for tx in canceled {
                        let _ = tx.send(CheckReply::blocked("agent-sandbox: network check cancelled"));
                    }
                    return CheckReply::blocked("agent-sandbox: network check cancelled");
                }
            }
        }

        let verdict = time::timeout(self.args.approval_timeout, &mut rx);
        tokio::pin!(verdict);
        tokio::select! {
            result = &mut verdict => match result {
                Ok(Ok(reply)) => reply,
                Ok(Err(_)) => CheckReply::denied(VerdictSource::Blocked),
                Err(_) => {
                    let (canceled, last) =
                        self.expire_network_wait(&target, proxy.as_ref()).await;
                    for tx in canceled {
                        let _ = tx.send(CheckReply::blocked("agent-sandbox: network approval timed out"));
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
                        last,
                        "network approval timed out"
                    );
                    CheckReply::blocked(
                        "agent-sandbox: network approval timed out (no response from policy UI)",
                    )
                }
            },
            _ = &mut cancel_rx => {
                let canceled = self
                    .cancel_network_wait(target.pending_id, proxy.as_ref())
                    .await;
                for tx in canceled {
                    let _ = tx.send(CheckReply::blocked("agent-sandbox: network check cancelled"));
                }
                CheckReply::blocked("agent-sandbox: network check cancelled")
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use std::path::Path;

    use agent_sandbox_core::VerdictSource;

    use super::{NetworkRequestIdentity, PendingNetwork};

    fn pending_network(host: &str, sandbox_session_id: Option<&str>) -> PendingNetwork {
        PendingNetwork {
            id: "net:1".into(),
            created_at: 0.0,
            host: host.into(),
            port: 443,
            scheme: "tcp".into(),
            url: format!("tcp://{host}:443"),
            aliases: Vec::new(),
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: sandbox_session_id.map(str::to_string),
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

    use crate::{
        store::types::{Pending, PolicyStore, PolicydArgs, UiClient, UiSessionContext},
        wire::NetworkCheckRequest,
    };

    fn test_store() -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: "/tmp/test.sock".into(),
            sandbox_socket: "/tmp/test-sandbox.sock".into(),
            declarative: "/tmp/declarative.json".into(),
            export_json: "/tmp/export.json".into(),
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

    fn unique_request(host: &str, port: u16) -> NetworkCheckRequest {
        NetworkCheckRequest {
            host: host.into(),
            port,
            scheme: "tcp".into(),
            url: format!("tcp://{host}:{port}"),
            ctx: ResolvedRequestContext {
                paths: SandboxPaths::from_wire(
                    Some("/repo".into()),
                    Some("/home/user".into()),
                    Some("/repo".into()),
                ),
                // pid 0 short-circuits resolve_context, so the explicit
                // paths are preserved verbatim.
                ids: ProcessIds::from_options(Some(0), Some(1000)),
                sandbox_session_id: Some("sandbox-cap".into()),
            },
        }
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
                .session_allow
                .entry("ui1".into())
                .or_default()
                .insert(agent_sandbox_core::NetworkRuleKey::new("example.com", 443));
        }

        let first = store
            .request_network_approval(unique_request("example.com", 443))
            .await;
        assert!(first.allowed, "session approval should allow first request");
        assert_eq!(
            first.source,
            VerdictSource::Scope(agent_sandbox_core::ApprovalScope::Session)
        );
        assert!(
            store.pending_summaries().await.is_empty(),
            "session approval must not create a pending prompt"
        );

        let second = store
            .request_network_approval(unique_request("example.com", 443))
            .await;
        assert!(
            second.allowed,
            "session approval should allow second request"
        );
        assert_eq!(
            second.source,
            VerdictSource::Scope(agent_sandbox_core::ApprovalScope::Session)
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
                .once_allow
                .insert(agent_sandbox_core::NetworkRuleKey::new("example.com", 443));
        }

        let first = store
            .request_network_approval(unique_request("example.com", 443))
            .await;
        assert!(first.allowed, "Once grant should allow the first request");
        assert_eq!(
            first.source,
            VerdictSource::Scope(agent_sandbox_core::ApprovalScope::Once)
        );
        assert!(
            store.inner.lock().await.once_allow.is_empty(),
            "Once grant must be consumed by the pre-prompt check"
        );

        let task_store = store.clone();
        let task = tokio::spawn(async move {
            task_store
                .request_network_approval(unique_request("example.com", 443))
                .await
        });
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending_keys()
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
        assert!(!second.allowed, "second request must not reuse Once grant");
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
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: Some("sandbox-cap".into()),
        }
    }

    #[tokio::test]
    async fn network_pending_cap_blocks_new_prompts() {
        let store = test_store();
        {
            let mut inner = store.inner.lock().await;
            for i in 0..super::MAX_PENDING_APPROVALS {
                let id = format!("net:seed{i}");
                let mut pending = pending_network_owned(format!("host{i}.example"));
                pending.id = id;
                inner.insert_pending(Pending::Network(pending));
            }
            drop(inner);
        }

        let reply = store
            .request_network_approval(unique_request("overflow.example", 443))
            .await;
        assert!(!reply.allowed);
        assert_eq!(reply.source, VerdictSource::Blocked);
        let err = reply.error.unwrap_or_default();
        assert!(err.contains("too many pending"), "got: {err}");

        let pending_count = store.inner.lock().await.pending_len();
        assert_eq!(
            pending_count,
            super::MAX_PENDING_APPROVALS,
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
            inner.insert_pending(Pending::Network(net));
            for _ in 0..super::MAX_WAITERS_PER_PENDING {
                let (tx, _rx) = tokio::sync::oneshot::channel();
                inner
                    .network_futures
                    .entry("net:open".into())
                    .or_default()
                    .push(super::super::types::NetworkWaiter { proxy: None, tx });
            }
        }
        let reply = store
            .request_network_approval(unique_request("example.com", 443))
            .await;
        assert!(!reply.allowed);
        assert_eq!(reply.source, VerdictSource::Blocked);
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
        };

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
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
        };

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
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
        // A registered standalone UI must receive the network prompt without delay.
        // Late UI registration is flushed by `RegisterUi` in `server::client`
        // (see `flush_pending_to_ui`).
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
        let task = tokio::spawn(async move {
            store_for_task
                .request_network_approval(unique_request("fast.example", 53))
                .await
        });

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

        // Approve the pending so the spawned task does not hang on the rx channel.
        let pending_id = {
            let inner = store.inner.lock().await;
            inner
                .pending_keys()
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
        let task = tokio::spawn(async move {
            store_for_task
                .request_network_approval(unique_request("slow.example", 443))
                .await
        });
        // Wait for the request to register a pending. The task is now
        // inside the UI-registration wait loop.
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending_keys()
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
        // No UI is registered; CLI approves via the same path
        // `apply_pending_network_decision` would use for the Once scope.
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
        assert!(reply.allowed, "expected allowed reply, got: {reply:?}");
        assert_eq!(reply.source, VerdictSource::policy_with_comment("cli"));
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
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: None,
        });
        store.inner.lock().await.insert_pending(pending);
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
