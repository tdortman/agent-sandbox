//! Policy store, network.

use std::time::{Duration, Instant};

use agent_sandbox_core::{
    CheckReply, ProcessIds, SandboxPaths, UiPush, attach_ui_aliases, normalize_host,
};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use crate::spawn::maybe_spawn_ui;
use crate::wire::{MergeContext, NetworkCheckRequest, UiSpawnContext, UiSpawnGate};

use super::types::{
    MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, NetworkVerdictKey, Pending, PendingKind,
    PendingNetwork, PolicyStore, VerdictEntry, enforce_verdict_cache_limit,
};
use super::ui_route::UiRoute;

/// How long a network verdict is cached after the first policy check for the
/// same hostname plus port. This deduplicates prompts when curl tries multiple
/// IPs for the same domain (each IP is a separate SYN, but they share the
/// same hostname from the DNS cache).
const NETWORK_VERDICT_CACHE_TTL: Duration = Duration::from_secs(1);

struct NetworkRequestIdentity<'a> {
    host: &'a str,
    port: u16,
    cwd: &'a Option<String>,
    home: &'a Option<String>,
    project_root: &'a Option<String>,
    sandbox_session_id: &'a Option<String>,
}

impl NetworkRequestIdentity<'_> {
    fn matches(&self, pending: &PendingNetwork) -> bool {
        pending.host == self.host
            && pending.port == self.port
            && &pending.cwd == self.cwd
            && &pending.home == self.home
            && &pending.project_root == self.project_root
            && &pending.sandbox_session_id == self.sandbox_session_id
    }
}

impl PolicyStore {
    /// Finish pending network checks that declarative/session policy already allows (e.g. after a UI client registers).
    pub async fn resolve_pending_declarative_allow(&self) {
        let pending: Vec<Pending> = self
            .inner
            .lock()
            .await
            .pending
            .values()
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
            let merge = MergeContext {
                paths: SandboxPaths::from_wire(
                    net.cwd.clone(),
                    net.home.clone(),
                    net.project_root.clone(),
                ),
                ids: ProcessIds::default(),
                sandbox_session_id: net.sandbox_session_id.clone(),
            };
            let Some(source) = self.allow_source(&host, port, merge).await else {
                continue;
            };
            if source == "deny" || source == "once" {
                continue;
            }
            tracing::info!(
                %host,
                port,
                %source,
                pending_id = %p.id(),
            );
            self.finish_network(
                p.id(),
                true,
                &source,
                Some(NetworkVerdictKey {
                    host: host.clone(),
                    port,
                }),
            )
            .await;
            self.inner.lock().await.pending.remove(p.id());
        }
    }

    pub(crate) async fn finish_network(
        &self,
        pending_id: &str,
        allowed: bool,
        source: &str,
        verdict_cache_key: Option<NetworkVerdictKey>,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.network_futures.remove(pending_id) {
            let reply = if allowed {
                CheckReply::allowed(source)
            } else {
                CheckReply::denied(source)
            };
            for tx in waiters {
                let _ = tx.send(reply.clone());
            }
        }
        // Cache the verdict for deduplication of multiple IPs from the same
        // DNS response (e.g. curl trying 6 IPv4 + 4 IPv6 for google.com).
        if let Some(key) = verdict_cache_key {
            inner.network_verdict_cache.insert(
                key,
                VerdictEntry {
                    allowed,
                    source: source.to_string(),
                    time: Instant::now(),
                },
            );
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
        let NetworkCheckRequest {
            host,
            port,
            scheme,
            url,
            ctx,
        } = req;
        let policy_host = normalize_host(&host);
        let resolved = self.resolve_context(ctx).await;
        let wire_ids = resolved.ids;
        let cwd = resolved.paths.cwd_string();
        let home = resolved.paths.home_string();
        let project_root = resolved.paths.project_root_string();
        let sandbox_session_id = resolved.sandbox_session_id.clone();
        if self.policy_denied(&policy_host, port, resolved).await {
            tracing::info!(%policy_host, port, "check deny (project policy)");
            return CheckReply::denied("deny");
        }
        if !self.args.interactive_approval {
            return CheckReply::denied("blocked");
        }

        // Check the short-lived verdict cache before creating a new prompt.
        // This deduplicates prompts when curl tries multiple IPs for the
        // same domain (each IP is a separate SYN, but they share the
        // same hostname from the DNS cache).
        {
            let inner = self.inner.lock().await;
            if let Some(entry) = inner.network_verdict_cache.get(&NetworkVerdictKey {
                host: policy_host.clone(),
                port,
            }) && entry.time.elapsed() < NETWORK_VERDICT_CACHE_TTL
            {
                return if entry.allowed {
                    CheckReply::allowed(entry.source.clone())
                } else {
                    CheckReply::denied(entry.source.clone())
                };
            }
        }

        let (tx, rx) = oneshot::channel();
        let identity = NetworkRequestIdentity {
            host: &policy_host,
            port,
            cwd: &cwd,
            home: &home,
            project_root: &project_root,
            sandbox_session_id: &sandbox_session_id,
        };

        let (pending_id, created_prompt) = {
            let mut inner = self.inner.lock().await;
            if let Some(existing_id) = inner.pending.values().find_map(|pending| {
                let Pending::Network(net) = pending else {
                    return None;
                };
                identity.matches(net).then(|| net.id.clone())
            }) {
                let waiter_count = inner.network_futures.get(&existing_id).map_or(0, Vec::len);
                tracing::error!(waiter_count, MAX_WAITERS_PER_PENDING, host = %identity.host, "dedup found existing pending, waiter count");
                if waiter_count >= MAX_WAITERS_PER_PENDING {
                    return CheckReply::blocked(
                        "agent-sandbox: too many waiters for one network approval",
                    );
                }
                tracing::error!(
                    waiter_count,
                    MAX_WAITERS_PER_PENDING,
                    "waiter count check failed"
                );
                inner
                    .network_futures
                    .entry(existing_id.clone())
                    .or_default()
                    .push(tx);
                (existing_id, false)
            } else {
                if inner.pending.len() >= MAX_PENDING_APPROVALS {
                    tracing::warn!(
                        pending_count = inner.pending.len(),
                        "network approval blocked (too many pending approvals)"
                    );
                    return CheckReply::blocked("agent-sandbox: too many pending approvals");
                }
                let pending_id = format!("net:{}", Uuid::now_v7().simple());
                inner.network_futures.insert(pending_id.clone(), vec![tx]);
                inner.pending.insert(
                    pending_id.clone(),
                    Pending::Network(PendingNetwork {
                        id: pending_id.clone(),
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0.0, |d| d.as_secs_f64()),
                        host: policy_host.clone(),
                        port,
                        scheme: scheme.clone(),
                        url: url.clone(),
                        aliases: aliases.clone(),
                        cwd: cwd.clone(),
                        home: home.clone(),
                        project_root: project_root.clone(),
                        sandbox_session_id: sandbox_session_id.clone(),
                    }),
                );
                (pending_id, true)
            }
        };
        let route = UiRoute::new(cwd.clone(), project_root.clone())
            .with_sandbox_session(sandbox_session_id.clone());
        if created_prompt {
            Self::audit("pending", Some(&policy_host), Some(port), &scheme);
            // Notify immediately. Late UI registration is flushed by
            // `RegisterUi` in `server::client` (see `flush_pending_to_ui`).
            self.notify_network_ui(
                &route,
                &UiPush::NetworkRequest {
                    id: pending_id.clone(),
                    host: Some(policy_host.clone()),
                    port: Some(port),
                    scheme: Some(scheme.clone()),
                    url: attach_ui_aliases(Some(url.clone()), &aliases),
                    cwd: cwd.clone(),
                    home: home.clone(),
                    project_root: project_root.clone(),
                },
            )
            .await;
            if !self.has_ui_for_route(&route).await {
                let mut spawn_uid = wire_ids.uid();
                if spawn_uid.is_none_or(|u| u == 0)
                    && let Some(h) = &home
                {
                    spawn_uid = nix::unistd::User::from_name(&Self::user_for_home(Some(h)))
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
                maybe_spawn_ui(
                    &self.args,
                    &mut self.inner.lock().await.ui_spawn_last,
                    &spawn,
                );
            }
        }

        if !self.has_ui_for_route(&route).await {
            let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
            if !self.wait_for_matching_ui_client(&route, ui_wait).await {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.network_futures.remove(&pending_id);
                inner.network_verdict_cache.insert(
                    NetworkVerdictKey {
                        host: policy_host.clone(),
                        port,
                    },
                    VerdictEntry {
                        allowed: false,
                        source: "blocked".to_string(),
                        time: Instant::now(),
                    },
                );
                enforce_verdict_cache_limit(&mut inner.network_verdict_cache);
                tracing::warn!(%policy_host, port, "network approval blocked (no policy UI)");
                return CheckReply::blocked(
                    "agent-sandbox: no policy UI registered (agent-sandbox-ui or auto-spawn)",
                );
            }
        }

        match time::timeout(self.args.approval_timeout, rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => CheckReply::denied("blocked"),
            Err(_) => {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.network_futures.remove(&pending_id);
                inner.network_verdict_cache.insert(
                    NetworkVerdictKey {
                        host: policy_host.clone(),
                        port,
                    },
                    VerdictEntry {
                        allowed: false,
                        source: "blocked".to_string(),
                        time: Instant::now(),
                    },
                );
                enforce_verdict_cache_limit(&mut inner.network_verdict_cache);
                Self::audit("timeout", Some(&policy_host), Some(port), &scheme);
                tracing::warn!(%policy_host, port, "network approval timed out");
                CheckReply::blocked(
                    "agent-sandbox: network approval timed out (no response from policy UI)",
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
            cwd: &cwd,
            home: &home,
            project_root: &project_root,
            sandbox_session_id: &sandbox_session_id,
        };

        assert!(identity.matches(&pending_network("example.com", Some("sandbox-a"))));
        assert!(!identity.matches(&pending_network("example.com", Some("sandbox-b"))));
        assert!(!identity.matches(&pending_network("other.example", Some("sandbox-a"))));
    }

    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    use crate::store::types::{Pending, PolicyStore, PolicydArgs, UiClient, UiSessionContext};
    use crate::store::ui_route::UiRoute;
    use crate::wire::{MergeContext, NetworkCheckRequest};
    use agent_sandbox_core::{FileAccess, ProcessIds, SandboxPaths, UiPush};

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
        })
    }

    fn unique_request(host: &str, port: u16) -> NetworkCheckRequest {
        NetworkCheckRequest {
            host: host.into(),
            port,
            scheme: "tcp".into(),
            url: format!("tcp://{host}:{port}"),
            ctx: MergeContext {
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
                inner.pending.insert(
                    id.clone(),
                    Pending::Network(pending_network_owned(format!("host{i}.example"))),
                );
            }
        }

        let reply = store
            .request_network_approval(unique_request("overflow.example", 443))
            .await;
        assert!(!reply.allowed);
        assert_eq!(reply.source, "blocked");
        let err = reply.error.unwrap_or_default();
        assert!(err.contains("too many pending"), "got: {err}");

        let pending_count = store.inner.lock().await.pending.len();
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
            let open_id = "net:open".to_string();
            net.id = open_id.clone();
            inner.pending.insert(open_id, Pending::Network(net));
            for _ in 0..super::MAX_WAITERS_PER_PENDING {
                let (tx, _rx) = tokio::sync::oneshot::channel();
                inner
                    .network_futures
                    .entry("net:open".into())
                    .or_default()
                    .push(tx);
            }
        }
        let reply = store
            .request_network_approval(unique_request("example.com", 443))
            .await;
        assert!(!reply.allowed);
        assert_eq!(reply.source, "blocked");
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
            inner.ui_clients.insert(
                1,
                UiClient {
                    session_id: "ui1".into(),
                    writer: Arc::new(Mutex::new(ui_write)),
                },
            );
            inner.ui_context_by_session.insert(
                "ui1".into(),
                UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: None,
                },
            );
        }
        let route = UiRoute::new(Some("/repo".into()), Some("/repo".into()));
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

        store.notify_network_ui(&route, &payload).await;

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
            inner.ui_clients.insert(
                2,
                UiClient {
                    session_id: "ui1".into(),
                    writer: Arc::new(Mutex::new(standalone_write)),
                },
            );
            inner.ui_context_by_session.insert(
                "ui1".into(),
                UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: None,
                },
            );
        }

        let route = UiRoute::new(Some("/repo".into()), Some("/repo".into()));
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

        store.notify_network_ui(&route, &payload).await;

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
            inner.ui_clients.insert(
                1,
                UiClient {
                    session_id: "ui1".into(),
                    writer: Arc::new(Mutex::new(standalone_write)),
                },
            );
            inner.ui_context_by_session.insert(
                "ui1".into(),
                UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-cap".into()),
                },
            );
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
                .pending
                .keys()
                .find(|k| k.starts_with("net:"))
                .cloned()
                .expect("pending network request should be tracked")
        };
        store.finish_network(&pending_id, true, "test", None).await;

        let reply = task.await.expect("task should not panic");
        assert!(reply.allowed);
        assert_eq!(reply.source, "test");
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
            inner.ui_clients.insert(
                3,
                UiClient {
                    session_id: "ui2".into(),
                    writer: Arc::new(Mutex::new(fs_write)),
                },
            );
            inner.ui_context_by_session.insert(
                "ui2".into(),
                UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: None,
                },
            );
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
        store
            .inner
            .lock()
            .await
            .pending
            .insert("fs:1".into(), pending);
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
