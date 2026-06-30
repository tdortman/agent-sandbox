//! Policy store: resource gate (declarative approval flow).
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_sandbox_core::{ResourceAccess, ResourceCheckReply, ResourceKind, UiPush};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use super::types::{
    MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, Pending, PendingResource, PolicyStore,
    ResourceVerdictKey, VerdictEntry, enforce_verdict_cache_limit,
};
use crate::spawn::maybe_spawn_ui;
use crate::store::ui_route::UiRoute;
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
        let resolved = self.resolve_context(&req.ctx);
        if let Some(source) = self
            .resource_allow_source(req.kind, &req.path, req.access, &resolved)
            .await
        {
            if source == "deny" {
                return ResourceCheckReply::denied("deny", req.kind, req.path.clone(), req.access);
            }
            return ResourceCheckReply::allowed(source, req.kind, req.path.clone(), req.access);
        }
        self.request_resource_approval(ResourceCheckRequest {
            kind: req.kind,
            path: req.path,
            access: req.access,
            ctx: resolved,
        })
        .await
    }

    pub async fn request_resource_approval(&self, req: ResourceCheckRequest) -> ResourceCheckReply {
        let ResourceCheckRequest {
            kind,
            path,
            access,
            ctx,
        } = req;
        let resolved = self.resolve_context(&ctx);
        let wire_ids = resolved.ids;
        let cwd = resolved.paths.cwd_path();
        let home = resolved.paths.home_path();
        let project_root = resolved.paths.project_root_path();
        let sandbox_session_id = resolved.sandbox_session_id.clone();
        if self
            .resource_policy_denied(kind, &path, access, &resolved)
            .await
        {
            return ResourceCheckReply::denied("deny", kind, path.clone(), access);
        }
        if !self.args.interactive_approval {
            return ResourceCheckReply::denied("blocked", kind, path.clone(), access);
        }

        if let Some(reply) = self.check_resource_verdict_cache(kind, &path, access).await {
            return reply;
        }

        let result = match self
            .dedup_or_create_pending_resource(
                kind,
                &path,
                access,
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

        let route = UiRoute::new(cwd.clone(), project_root.clone())
            .with_sandbox_session(sandbox_session_id.clone());

        if result.is_new {
            let push = UiPush::ResourceRequest {
                id: result.id.clone(),
                kind,
                path: path.clone(),
                access,
                cwd: cwd.clone(),
                home: home.clone(),
                project_root: project_root.clone(),
            };
            self.notify_standalone_ui(&route, &push).await;

            if !self.has_standalone_ui_for_route(&route).await {
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
                maybe_spawn_ui(
                    &self.args,
                    &mut self.inner.lock().await.ui_spawn_last,
                    &spawn,
                );
            }
        }

        self.await_resource_verdict(&route, &result.id, kind, path, access, result.rx)
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
        ctx: &PendingCtx<'_>,
    ) -> Result<PendingResResult, ResourceCheckReply> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;
        // Deduplicate: if a pending already exists for the same resource
        // kind, path, and access type, join its waiters instead of creating
        // a new prompt.
        if let Some(existing_id) = inner.pending.values().find_map(|p| {
            let Pending::Resource(res) = p else {
                return None;
            };
            (res.kind == kind && res.path == path && res.access == access).then(|| res.id.clone())
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
        inner.pending.insert(
            pending_id.clone(),
            Pending::Resource(PendingResource {
                id: pending_id.clone(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |d| d.as_secs_f64()),
                kind,
                path: path.to_path_buf(),
                access,
                cwd: ctx.cwd.map(PathBuf::from),
                home: ctx.home.map(PathBuf::from),
                project_root: ctx.project_root.map(PathBuf::from),
                sandbox_session_id: ctx.sandbox_session_id.map(String::from),
            }),
        );
        drop(inner);
        Ok(PendingResResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    async fn await_resource_verdict(
        &self,
        route: &UiRoute,
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
            if self.has_standalone_ui_for_route(route).await {
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
                    return result.unwrap_or_else(|_| ResourceCheckReply::denied("blocked", kind, path.clone(), access));
                }
            }
        }

        match time::timeout(self.args.approval_timeout, &mut rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => ResourceCheckReply::denied("blocked", kind, path.clone(), access),
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
        source: &str,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.resource_futures.remove(pending_id) {
            let reply = if allowed {
                ResourceCheckReply::allowed(source, kind, path.clone(), access)
            } else {
                ResourceCheckReply::denied(source, kind, path.clone(), access)
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
                source: source.to_string(),
                time: Instant::now(),
            },
        );
        enforce_verdict_cache_limit(&mut inner.resource_verdict_cache);
    }
}
