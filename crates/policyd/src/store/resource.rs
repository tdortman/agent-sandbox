//! Policy store: resource gate (declarative approval flow).

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    DbusCheckReply, DbusTarget, ResolvedRequestContext, ResourceAccess, ResourceCheckReply,
    ResourceKind, ResourceRuleKey, UiPush, VerdictSource,
};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::{
    types::{
        MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, Pending, PendingResource, PendingResult,
        PolicyStore, VerdictEntry, enforce_verdict_cache_limit,
    },
    ui::VerdictExit,
};

impl PolicyStore {
    /// Evaluate a resource access request, returning an immediate verdict
    /// when declarative rules or the verdict cache decide it, otherwise
    /// routing it through interactive approval.
    pub async fn check_resource(
        &self,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        ctx: ResolvedRequestContext,
    ) -> ResourceCheckReply {
        if let Some(verdict) = self.resource_allow_source(kind, &path, access, &ctx).await {
            return ResourceCheckReply::from_verdict(verdict, kind, path.clone(), access);
        }

        self.request_resource_approval(kind, path, access, ctx)
            .await
    }

    /// Request interactive approval for a resource access, prompting the
    /// policy UI if needed and waiting for the verdict.
    pub async fn request_resource_approval(
        &self,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        ctx: ResolvedRequestContext,
    ) -> ResourceCheckReply {
        let wire_ids = ctx.ids;
        let cwd = ctx.paths.cwd_path();
        let home = ctx.paths.home_path();
        let project_root = ctx.paths.project_root_path();
        let sandbox_session_id = ctx.sandbox_session_id.clone();

        if self.resource_policy_denied(kind, &path, access, &ctx).await {
            return ResourceCheckReply::denied(VerdictSource::policy(), kind, path.clone(), access);
        }

        if !self.args.interactive_approval {
            return ResourceCheckReply::denied(VerdictSource::Blocked, kind, path.clone(), access);
        }

        if let Some(reply) = self.check_resource_verdict_cache(kind, &path, access).await {
            return reply;
        }

        let result = match self
            .dedup_or_create_pending_resource(kind, &path, access, &ctx)
            .await
        {
            Ok(r) => r,
            Err(reply) => return reply,
        };

        if result.is_new {
            let push = UiPush::ResourceRequest {
                id: result.id.clone(),
                kind,
                path: path.clone(),
                access,
                cwd: cwd.clone(),
                home: home.clone(),
                project_root: project_root.clone(),
                package: ctx.package.clone(),
            };

            self.notify_general_ui(&ctx, &push).await;

            self.maybe_spawn_ui(
                || self.has_ui_for_context(&ctx),
                wire_ids.uid(),
                home.as_deref(),
                cwd.as_deref(),
                project_root.as_deref(),
                sandbox_session_id.as_deref(),
            )
            .await;
        }

        self.await_resource_verdict(&ctx, &result.id, kind, path, access, result.rx)
            .await
    }

    /// Route a D-Bus capability through the interactive approval pipeline.
    /// Callers apply declarative rules first. `target` is the typed
    /// capability, so no path encoding is involved.
    pub async fn request_dbus_approval(
        &self,
        target: DbusTarget,
        ctx: ResolvedRequestContext,
    ) -> DbusCheckReply {
        if !self.args.interactive_approval {
            return DbusCheckReply::denied(VerdictSource::Blocked, target);
        }

        if let Some(reply) = self.check_dbus_verdict_cache(&target).await {
            return reply;
        }

        let cwd = ctx.paths.cwd_path();
        let home = ctx.paths.home_path();
        let project_root = ctx.paths.project_root_path();
        let sandbox_session_id = ctx.sandbox_session_id.clone();

        let result = match self.dedup_or_create_pending_dbus(&target, &ctx).await {
            Ok(r) => r,
            Err(reply) => return *reply,
        };

        if result.is_new {
            let push = UiPush::DbusRequest {
                id: result.id.clone(),
                target: target.clone(),
                cwd: cwd.clone(),
                home: home.clone(),
                project_root: project_root.clone(),
                sandbox_session_id: sandbox_session_id.clone(),
                package: ctx.package.clone(),
            };

            self.notify_general_ui(&ctx, &push).await;

            self.maybe_spawn_ui(
                || self.has_ui_for_context(&ctx),
                ctx.ids.uid(),
                home.as_deref(),
                cwd.as_deref(),
                project_root.as_deref(),
                sandbox_session_id.as_deref(),
            )
            .await;
        }

        self.await_dbus_verdict(&ctx, &result.id, target, result.rx)
            .await
    }

    async fn check_dbus_verdict_cache(&self, target: &DbusTarget) -> Option<DbusCheckReply> {
        let inner = self.inner.lock().await;

        if let Some(entry) = inner.dbus_verdict_cache.get(target)
            && entry.time.elapsed() < Duration::from_secs(2)
        {
            return Some(if entry.allowed {
                DbusCheckReply::allowed(entry.source.clone(), target.clone())
            } else {
                DbusCheckReply::denied(entry.source.clone(), target.clone())
            });
        }

        drop(inner);
        None
    }

    async fn check_resource_verdict_cache(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
    ) -> Option<ResourceCheckReply> {
        let inner = self.inner.lock().await;

        if let Some(entry) = inner.resource_verdict_cache.get(&ResourceRuleKey {
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
        ctx: &ResolvedRequestContext,
    ) -> Result<PendingResult<String, ResourceCheckReply>, ResourceCheckReply> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;

        // Deduplicate: if a pending already exists for the same resource
        // kind, path, access type, and sandbox session, join its waiters
        // instead of creating a new prompt. The session is part of the key
        // so one sandbox's stale pending is not reused for another's
        // requests to the same socket.
        let existing_id = inner.pending.pending.values().find_map(|p| match p {
            Pending::Resource(res)
                if res.kind == kind
                    && res.path == path
                    && res.access == access
                    && res.ctx.sandbox_session_id == ctx.sandbox_session_id =>
            {
                Some(res.id.clone())
            }
            _ => None,
        });

        if let Some(existing_id) = existing_id {
            let waiter_count = inner
                .pending
                .resource_futures
                .get(&existing_id)
                .map_or(0, Vec::len);

            if waiter_count >= MAX_WAITERS_PER_PENDING {
                return Err(ResourceCheckReply::blocked(
                    "agent-sandbox: too many waiters for one resource approval",
                    kind,
                    path.to_path_buf(),
                    access,
                ));
            }

            inner
                .pending
                .resource_futures
                .entry(existing_id.clone())
                .or_default()
                .push(tx);

            drop(inner);

            return Ok(PendingResult {
                id: existing_id,
                is_new: false,
                rx,
            });
        }

        if inner.pending.pending.len() >= MAX_PENDING_APPROVALS {
            return Err(ResourceCheckReply::blocked(
                "agent-sandbox: too many pending approvals",
                kind,
                path.to_path_buf(),
                access,
            ));
        }

        let pending_id = format!("res:{}", Uuid::now_v7().simple());
        inner
            .pending
            .resource_futures
            .insert(pending_id.clone(), vec![tx]);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());

        let pending = Pending::Resource(PendingResource {
            id: pending_id.clone(),
            created_at,
            kind,
            path: path.to_path_buf(),
            access,
            ctx: ctx.clone(),
        });

        let id = pending.id().to_owned();
        inner.pending.pending.insert(id, pending);
        drop(inner);

        Ok(PendingResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    async fn dedup_or_create_pending_dbus(
        &self,
        target: &DbusTarget,
        ctx: &ResolvedRequestContext,
    ) -> Result<PendingResult<String, DbusCheckReply>, Box<DbusCheckReply>> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;

        // Deduplicate: if a pending already exists for the same target and
        // sandbox session, join its waiters instead of creating a new prompt.
        let existing_id = inner.pending.pending.values().find_map(|p| match p {
            Pending::Dbus(res)
                if &res.target == target
                    && res.ctx.sandbox_session_id == ctx.sandbox_session_id =>
            {
                Some(res.id.clone())
            }
            _ => None,
        });

        if let Some(existing_id) = existing_id {
            let waiter_count = inner
                .pending
                .dbus_futures
                .get(&existing_id)
                .map_or(0, Vec::len);

            if waiter_count >= MAX_WAITERS_PER_PENDING {
                return Err(Box::new(DbusCheckReply::blocked(
                    "agent-sandbox: too many waiters for one D-Bus approval",
                    target.clone(),
                )));
            }

            inner
                .pending
                .dbus_futures
                .entry(existing_id.clone())
                .or_default()
                .push(tx);

            drop(inner);

            return Ok(PendingResult {
                id: existing_id,
                is_new: false,
                rx,
            });
        }

        if inner.pending.pending.len() >= MAX_PENDING_APPROVALS {
            return Err(Box::new(DbusCheckReply::blocked(
                "agent-sandbox: too many pending approvals",
                target.clone(),
            )));
        }

        let pending_id = format!("dbus:{}", Uuid::now_v7().simple());
        inner
            .pending
            .dbus_futures
            .insert(pending_id.clone(), vec![tx]);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());

        let pending = Pending::Dbus(crate::store::types::PendingDbus {
            id: pending_id.clone(),
            created_at,
            target: target.clone(),
            ctx: ctx.clone(),
        });

        let id = pending.id().to_owned();
        inner.pending.pending.insert(id, pending);
        drop(inner);

        Ok(PendingResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    async fn await_resource_verdict(
        &self,
        ctx: &ResolvedRequestContext,
        pending_id: &str,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        rx: oneshot::Receiver<ResourceCheckReply>,
    ) -> ResourceCheckReply {
        self.wait_for_ui_or_verdict(
            || self.has_ui_for_context(ctx),
            rx,
            None,
            |reason| async move {
                match reason {
                    VerdictExit::NoUi => {
                        let mut inner = self.inner.lock().await;
                        inner.pending.pending.remove(pending_id);
                        inner.pending.resource_futures.remove(pending_id);
                        drop(inner);

                        ResourceCheckReply::blocked(
                            "agent-sandbox: no standalone resource policy UI registered \
                             (agent-sandbox-ui or auto-spawn)",
                            kind,
                            path.clone(),
                            access,
                        )
                    }
                    VerdictExit::ChannelClosed => ResourceCheckReply::denied(
                        VerdictSource::Blocked,
                        kind,
                        path.clone(),
                        access,
                    ),
                    VerdictExit::Timeout => {
                        let mut inner = self.inner.lock().await;
                        inner.pending.pending.remove(pending_id);
                        inner.pending.resource_futures.remove(pending_id);
                        drop(inner);

                        ResourceCheckReply::blocked(
                            "agent-sandbox: resource approval timed out (no response from policy \
                             UI)",
                            kind,
                            path.clone(),
                            access,
                        )
                    }
                    VerdictExit::Cancelled => {
                        unreachable!("no cancel channel wired for resource waits")
                    }
                }
            },
        )
        .await
    }

    async fn await_dbus_verdict(
        &self,
        ctx: &ResolvedRequestContext,
        pending_id: &str,
        target: DbusTarget,
        rx: oneshot::Receiver<DbusCheckReply>,
    ) -> DbusCheckReply {
        self.wait_for_ui_or_verdict(
            || self.has_ui_for_context(ctx),
            rx,
            None,
            |reason| async move {
                match reason {
                    VerdictExit::NoUi => {
                        let mut inner = self.inner.lock().await;
                        inner.pending.pending.remove(pending_id);
                        inner.pending.dbus_futures.remove(pending_id);
                        drop(inner);

                        DbusCheckReply::blocked(
                            "agent-sandbox: no standalone policy UI registered (agent-sandbox-ui \
                             or auto-spawn)",
                            target,
                        )
                    }
                    VerdictExit::ChannelClosed => {
                        DbusCheckReply::denied(VerdictSource::Blocked, target)
                    }
                    VerdictExit::Timeout => {
                        let mut inner = self.inner.lock().await;
                        inner.pending.pending.remove(pending_id);
                        inner.pending.dbus_futures.remove(pending_id);
                        drop(inner);

                        DbusCheckReply::blocked(
                            "agent-sandbox: D-Bus approval timed out (no response from policy UI)",
                            target,
                        )
                    }
                    VerdictExit::Cancelled => {
                        unreachable!("no cancel channel wired for D-Bus waits")
                    }
                }
            },
        )
        .await
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

        if let Some(waiters) = inner.pending.resource_futures.remove(pending_id) {
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
        inner
            .resource_verdict_cache
            .insert(ResourceRuleKey { kind, path, access }, VerdictEntry {
                allowed,
                source,
                time: Instant::now(),
            });

        enforce_verdict_cache_limit(&mut inner.resource_verdict_cache);
    }

    pub(crate) async fn finish_dbus(
        &self,
        pending_id: &str,
        target: DbusTarget,
        allowed: bool,
        source: VerdictSource,
    ) {
        let mut inner = self.inner.lock().await;

        if let Some(waiters) = inner.pending.dbus_futures.remove(pending_id) {
            let reply = if allowed {
                DbusCheckReply::allowed(source.clone(), target.clone())
            } else {
                DbusCheckReply::denied(source.clone(), target.clone())
            };

            for tx in waiters {
                let _ = tx.send(reply.clone());
            }
        }

        // Cache the verdict for deduplication.
        inner.dbus_verdict_cache.insert(target, VerdictEntry {
            allowed,
            source,
            time: Instant::now(),
        });

        enforce_verdict_cache_limit(&mut inner.dbus_verdict_cache);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };

    use agent_sandbox_core::{
        DbusMessageKind, DbusTarget, ProcessIds, ResolvedRequestContext, ResourceAccess,
        ResourceKind, SandboxPaths, SocketAccess, VerdictSource,
    };
    use tokio::{io::AsyncReadExt, net::UnixStream, sync::Mutex};

    use crate::store::{UiSessionContext, test_store, types::UiClient};

    fn resource_ctx() -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
            ),
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-cap".into()),
            package: None,
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
                .request_resource_approval(
                    ResourceKind::UnixSocket,
                    PathBuf::from("/repo/fast.sock"),
                    ResourceAccess::Socket(SocketAccess::Connect),
                    resource_ctx(),
                )
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
                ResourceAccess::Socket(SocketAccess::Connect),
                true,
                VerdictSource::policy_with_comment("test"),
            )
            .await;

        let reply = task.await.expect("task should not panic");
        assert!(
            reply.verdict.allowed,
            "expected allowed reply, got: {reply:?}"
        );
        assert_eq!(
            reply.verdict.source,
            VerdictSource::policy_with_comment("test")
        );
    }

    #[tokio::test]
    async fn request_dbus_approval_prompts_standalone_ui_with_typed_target() {
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

        let target = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );

        let store_for_task = store.clone();
        let target_for_task = target.clone();

        let task = tokio::spawn(async move {
            store_for_task
                .request_dbus_approval(target_for_task, ResolvedRequestContext {
                    paths: SandboxPaths::from_wire(
                        Some("/repo".into()),
                        Some("/home/user".into()),
                        Some("/repo".into()),
                    ),
                    ids: ProcessIds::from_options(None, Some(1000)),
                    sandbox_session_id: Some("sandbox-cap".into()),
                    package: None,
                })
                .await
        });

        let mut buf = [0u8; 4096];

        let n = tokio::time::timeout(Duration::from_millis(200), standalone_read.read(&mut buf))
            .await
            .expect("standalone UI should receive D-Bus prompt within 200ms")
            .expect("read should succeed");

        let received = String::from_utf8_lossy(&buf[..n]);

        assert!(
            received.contains("dbus:") && received.contains("org.example.Service"),
            "expected pending id and typed D-Bus target in prompt, got: {received}"
        );

        assert!(
            !received.contains("@dbus:"),
            "no fake resource path may appear in the D-Bus prompt, got: {received}"
        );

        let pending_id = {
            let inner = store.inner.lock().await;
            inner
                .pending
                .pending
                .keys()
                .find(|k| k.starts_with("dbus:"))
                .cloned()
                .expect("pending D-Bus request should be tracked")
        };

        store
            .finish_dbus(
                &pending_id,
                target.clone(),
                true,
                VerdictSource::policy_with_comment("test"),
            )
            .await;

        let reply = task.await.expect("task should not panic");
        assert!(
            reply.verdict.allowed,
            "expected allowed reply, got: {reply:?}"
        );
        assert_eq!(
            reply.verdict.source,
            VerdictSource::policy_with_comment("test")
        );
        assert_eq!(reply.target, target);
        let inner = store.inner.lock().await;

        assert!(
            inner.dbus_verdict_cache.contains_key(&target),
            "approved D-Bus target should be cached under the typed key"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn cli_approval_during_ui_wait_unblocks_resource_promptly() {
        let store = Arc::new(test_store());
        let store_for_task = store.clone();

        let task = tokio::spawn(async move {
            store_for_task
                .request_resource_approval(
                    ResourceKind::UnixSocket,
                    PathBuf::from("/repo/slow.sock"),
                    ResourceAccess::Socket(SocketAccess::Connect),
                    resource_ctx(),
                )
                .await
        });

        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending
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
                ResourceAccess::Socket(SocketAccess::Connect),
                true,
                VerdictSource::policy_with_comment("cli"),
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
    async fn resource_pending_dedup_is_scoped_to_the_sandbox_session() {
        fn pending_ctx(session: &str) -> ResolvedRequestContext {
            ResolvedRequestContext {
                paths: SandboxPaths::from_wire(
                    Some("/repo".into()),
                    Some("/home/user".into()),
                    Some("/repo".into()),
                ),
                ids: ProcessIds::default(),
                sandbox_session_id: Some(session.into()),
                package: None,
            }
        }

        let store = test_store();
        let kind = ResourceKind::UnixSocket;
        let path = PathBuf::from("/repo/shared.sock");
        let access = ResourceAccess::Socket(SocketAccess::Connect);

        let a = store
            .dedup_or_create_pending_resource(kind, &path, access, &pending_ctx("sandbox-a"))
            .await
            .expect("first session pending");
        assert!(a.is_new, "first session must create its own pending");

        let b = store
            .dedup_or_create_pending_resource(kind, &path, access, &pending_ctx("sandbox-b"))
            .await
            .expect("second session pending");
        assert!(
            b.is_new,
            "a different sandbox session must not reuse the first pending"
        );

        let c = store
            .dedup_or_create_pending_resource(kind, &path, access, &pending_ctx("sandbox-a"))
            .await
            .expect("same session pending");
        assert!(
            !c.is_new,
            "the same session must deduplicate to its own pending"
        );
    }
}
