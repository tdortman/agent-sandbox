//! Policy store: resource gate (declarative approval flow).
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_sandbox_core::{
    DbusTarget, ResourceAccess, ResourceCheckReply, ResourceKind, UiPush, VerdictSource,
};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use super::types::{
    MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, Pending, PendingResource, PolicyStore,
    ResourceVerdictKey, VerdictEntry, enforce_verdict_cache_limit,
};
use crate::wire::{ResourceCheckRequest, UiSpawnContext, UiSpawnGate};

struct PendingResResult {
    id: String,
    is_new: bool,
    rx: oneshot::Receiver<ResourceCheckReply>,
}

/// Context fields threaded into [`PolicyStore::dedup_or_create_pending_resource`],
/// grouped to keep the function signature under clippy's argument-count threshold.
struct PendingCtx<'a> {
    cwd: Option<&'a Path>,
    home: Option<&'a Path>,
    project_root: Option<&'a Path>,
    sandbox_session_id: Option<&'a str>,
}

impl PolicyStore {
    pub async fn check_resource(&self, req: ResourceCheckRequest) -> ResourceCheckReply {
        let ResourceCheckRequest {
            kind,
            path,
            access,
            ctx,
        } = req;
        if let Some(verdict) = self.resource_allow_source(kind, &path, access, &ctx).await {
            return ResourceCheckReply::from_verdict(verdict, kind, path.clone(), access);
        }
        self.request_resource_approval(ResourceCheckRequest {
            kind,
            path,
            access,
            ctx,
        })
        .await
    }

    pub async fn request_resource_approval(&self, req: ResourceCheckRequest) -> ResourceCheckReply {
        self.request_resource_approval_with_target(req, None).await
    }

    pub(crate) async fn request_resource_approval_with_target(
        &self,
        req: ResourceCheckRequest,
        dbus_target: Option<DbusTarget>,
    ) -> ResourceCheckReply {
        let ResourceCheckRequest {
            kind,
            path,
            access,
            ctx,
        } = req;
        let wire_ids = ctx.ids;
        let cwd = ctx.paths.cwd_path();
        let home = ctx.paths.home_path();
        let project_root = ctx.paths.project_root_path();
        let sandbox_session_id = ctx.sandbox_session_id.clone();
        if dbus_target.is_none() && self.resource_policy_denied(kind, &path, access, &ctx).await {
            return ResourceCheckReply::denied(VerdictSource::policy(), kind, path.clone(), access);
        }
        if !self.args.interactive_approval {
            return ResourceCheckReply::denied(VerdictSource::Blocked, kind, path.clone(), access);
        }

        if let Some(reply) = self.check_resource_verdict_cache(kind, &path, access).await {
            return reply;
        }

        let result = match self
            .dedup_or_create_pending_resource(
                kind,
                &path,
                access,
                dbus_target.as_ref(),
                &PendingCtx {
                    cwd: cwd.as_deref(),
                    home: home.as_deref(),
                    project_root: project_root.as_deref(),
                    sandbox_session_id: sandbox_session_id.as_deref(),
                },
            )
            .await
        {
            Ok(r) => r,
            Err(reply) => return reply,
        };

        if result.is_new {
            let push = match dbus_target.as_ref() {
                Some(target) => UiPush::DbusRequest {
                    id: result.id.clone(),
                    target: target.clone(),
                    cwd: cwd.clone(),
                    home: home.clone(),
                    project_root: project_root.clone(),
                    sandbox_session_id: sandbox_session_id.clone(),
                },
                None => UiPush::ResourceRequest {
                    id: result.id.clone(),
                    kind,
                    path: path.clone(),
                    access,
                    cwd: cwd.clone(),
                    home: home.clone(),
                    project_root: project_root.clone(),
                },
            };
            self.notify_standalone_ui(&ctx, &push).await;

            if !self.has_standalone_ui_for_context(&ctx).await {
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

        self.await_resource_verdict(&ctx, &result.id, kind, path, access, result.rx)
            .await
    }

    async fn check_resource_verdict_cache(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
    ) -> Option<ResourceCheckReply> {
        let inner = self.inner.lock().await;
        if let Some(entry) = inner.resource_verdict_cache.get(&ResourceVerdictKey {
            kind,
            path: path.to_path_buf(),
            access,
        }) && entry.time.elapsed() < Duration::from_secs(2)
        {
            return Some(if entry.allowed {
                ResourceCheckReply::allowed(entry.source.clone(), kind, path.to_path_buf(), access)
            } else {
                ResourceCheckReply::denied(entry.source.clone(), kind, path.to_path_buf(), access)
            });
        }
        drop(inner);
        None
    }

    async fn dedup_or_create_pending_resource(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        dbus_target: Option<&DbusTarget>,
        ctx: &PendingCtx<'_>,
    ) -> Result<PendingResResult, ResourceCheckReply> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;
        // Deduplicate: if a pending already exists for the same resource
        // kind, path, and access type, join its waiters instead of creating
        // a new prompt.
        if let Some(existing_id) = inner.pending.values().find_map(|p| match p {
            Pending::Resource(res)
                if dbus_target.is_none()
                    && res.kind == kind
                    && res.path == path
                    && res.access == access =>
            {
                Some(res.id.clone())
            }
            Pending::Dbus(res)
                if dbus_target == Some(&res.target)
                    && res.sandbox_session_id.as_deref() == ctx.sandbox_session_id =>
            {
                Some(res.id.clone())
            }
            _ => None,
        }) {
            let waiter_count = inner.resource_futures.get(&existing_id).map_or(0, Vec::len);
            if waiter_count >= MAX_WAITERS_PER_PENDING {
                return Err(ResourceCheckReply::blocked(
                    "agent-sandbox: too many waiters for one resource approval",
                    kind,
                    path.to_path_buf(),
                    access,
                ));
            }
            inner
                .resource_futures
                .entry(existing_id.clone())
                .or_default()
                .push(tx);
            drop(inner);
            return Ok(PendingResResult {
                id: existing_id,
                is_new: false,
                rx,
            });
        }
        if inner.pending.len() >= MAX_PENDING_APPROVALS {
            return Err(ResourceCheckReply::blocked(
                "agent-sandbox: too many pending approvals",
                kind,
                path.to_path_buf(),
                access,
            ));
        }
        let pending_id = format!("res:{}", Uuid::now_v7().simple());
        inner.resource_futures.insert(pending_id.clone(), vec![tx]);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let pending = dbus_target.map_or_else(
            || {
                Pending::Resource(PendingResource {
                    id: pending_id.clone(),
                    created_at,
                    kind,
                    path: path.to_path_buf(),
                    access,
                    cwd: ctx.cwd.map(PathBuf::from),
                    home: ctx.home.map(PathBuf::from),
                    project_root: ctx.project_root.map(PathBuf::from),
                    sandbox_session_id: ctx.sandbox_session_id.map(String::from),
                })
            },
            |target| {
                Pending::Dbus(crate::store::types::PendingDbus {
                    id: pending_id.clone(),
                    created_at,
                    target: target.clone(),
                    path: path.to_path_buf(),
                    cwd: ctx.cwd.map(PathBuf::from),
                    home: ctx.home.map(PathBuf::from),
                    project_root: ctx.project_root.map(PathBuf::from),
                    sandbox_session_id: ctx.sandbox_session_id.map(String::from),
                })
            },
        );
        inner.pending.insert(pending_id.clone(), pending);
        drop(inner);
        Ok(PendingResResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    async fn await_resource_verdict(
        &self,
        ctx: &agent_sandbox_core::ResolvedRequestContext,
        pending_id: &str,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        rx: oneshot::Receiver<ResourceCheckReply>,
    ) -> ResourceCheckReply {
        // Race UI registration against the verdict channel so a CLI approval
        // can unblock the request even if no policy UI ever appears.
        let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
        let ui_deadline = Instant::now() + ui_wait;
        tokio::pin!(rx);
        loop {
            if self.has_standalone_ui_for_context(ctx).await {
                break;
            }
            let now = Instant::now();
            if now >= ui_deadline {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(pending_id);
                inner.resource_futures.remove(pending_id);
                drop(inner);
                return ResourceCheckReply::blocked(
                    "agent-sandbox: no standalone resource policy UI registered (agent-sandbox-ui or auto-spawn)",
                    kind,
                    path.clone(),
                    access,
                );
            }
            let sleep_dur = (ui_deadline - now).min(Duration::from_millis(50));
            tokio::select! {
                biased;
                () = time::sleep(sleep_dur) => {}
                result = &mut rx => {
                    return result.unwrap_or_else(|_| ResourceCheckReply::denied(VerdictSource::Blocked, kind, path.clone(), access));
                }
            }
        }

        match time::timeout(self.args.approval_timeout, &mut rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => {
                ResourceCheckReply::denied(VerdictSource::Blocked, kind, path.clone(), access)
            }
            Err(_) => {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(pending_id);
                inner.resource_futures.remove(pending_id);
                drop(inner);
                ResourceCheckReply::blocked(
                    "agent-sandbox: resource approval timed out (no response from policy UI)",
                    kind,
                    path,
                    access,
                )
            }
        }
    }

    pub(crate) async fn finish_resource(
        &self,
        pending_id: &str,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        allowed: bool,
        source: VerdictSource,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.resource_futures.remove(pending_id) {
            let reply = if allowed {
                ResourceCheckReply::allowed(source.clone(), kind, path.clone(), access)
            } else {
                ResourceCheckReply::denied(source.clone(), kind, path.clone(), access)
            };
            for tx in waiters {
                let _ = tx.send(reply.clone());
            }
        }
        // Cache the verdict for deduplication.
        inner.resource_verdict_cache.insert(
            ResourceVerdictKey { kind, path, access },
            VerdictEntry {
                allowed,
                source,
                time: Instant::now(),
            },
        );
        enforce_verdict_cache_limit(&mut inner.resource_verdict_cache);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use agent_sandbox_core::{
        ProcessIds, ResolvedRequestContext, ResourceAccess, ResourceKind, SandboxPaths,
        VerdictSource,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    use super::PolicyStore;
    use crate::store::types::UiClient;
    use crate::store::{PolicydArgs, UiSessionContext};
    use crate::wire::ResourceCheckRequest;

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

    fn unique_request(path: &str) -> ResourceCheckRequest {
        ResourceCheckRequest {
            kind: ResourceKind::UnixSocket,
            path: PathBuf::from(path),
            access: ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
            ctx: ResolvedRequestContext {
                paths: SandboxPaths::from_wire(
                    Some("/repo".into()),
                    Some("/home/user".into()),
                    Some("/repo".into()),
                ),
                ids: ProcessIds::from_options(Some(0), Some(1000)),
                sandbox_session_id: Some("sandbox-cap".into()),
            },
        }
    }

    #[tokio::test]
    async fn request_resource_approval_prompts_already_registered_standalone_immediately() {
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
                    ..Default::default()
                },
            );
        }

        let store_for_task = store.clone();
        let task = tokio::spawn(async move {
            store_for_task
                .request_resource_approval(unique_request("/repo/fast.sock"))
                .await
        });

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_millis(200), standalone_read.read(&mut buf))
            .await
            .expect("standalone UI should receive resource prompt within 200ms")
            .expect("read should succeed");
        let received = String::from_utf8_lossy(&buf[..n]);
        assert!(
            received.contains("res:") && received.contains("/repo/fast.sock"),
            "expected pending id and resource path in prompt, got: {received}"
        );

        let pending_id = {
            let inner = store.inner.lock().await;
            inner
                .pending
                .keys()
                .find(|k| k.starts_with("res:"))
                .cloned()
                .expect("pending resource request should be tracked")
        };
        store
            .finish_resource(
                &pending_id,
                ResourceKind::UnixSocket,
                PathBuf::from("/repo/fast.sock"),
                ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
                true,
                VerdictSource::policy_with_comment("test"),
            )
            .await;

        let reply = task.await.expect("task should not panic");
        assert!(reply.allowed, "expected allowed reply, got: {reply:?}");
        assert_eq!(reply.source, VerdictSource::policy_with_comment("test"));
    }

    #[tokio::test]
    async fn cli_approval_during_ui_wait_unblocks_resource_promptly() {
        let store = Arc::new(test_store());
        let store_for_task = store.clone();
        let task = tokio::spawn(async move {
            store_for_task
                .request_resource_approval(unique_request("/repo/slow.sock"))
                .await
        });

        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending
                    .keys()
                    .find(|k| k.starts_with("res:"))
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

        store
            .finish_resource(
                &pending_id,
                ResourceKind::UnixSocket,
                PathBuf::from("/repo/slow.sock"),
                ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
                true,
                VerdictSource::policy_with_comment("cli"),
            )
            .await;

        let reply = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");
        assert!(reply.allowed, "expected allowed reply, got: {reply:?}");
        assert_eq!(reply.source, VerdictSource::policy_with_comment("cli"));
    }
}
