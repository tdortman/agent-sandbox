//! Policy store: filesystem (fanotify monitor spawn and declarative checks).
use std::path::Path;

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_sandbox_core::{FileAccess, FilesystemCheckReply, FilesystemMonitorReply, UiPush};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use super::types::{
    FilesystemVerdictKey, MAX_PENDING_APPROVALS, MAX_STATIC_ALLOW_RULES, MAX_WAITERS_PER_PENDING,
    Pending, PendingFilesystem, PolicyStore, VerdictEntry, enforce_verdict_cache_limit,
};
use crate::spawn::maybe_spawn_ui;
use crate::store::ui_route::UiRoute;
use crate::wire::{FilesystemCheckRequest, FilesystemMonitorRequest, UiSpawnContext, UiSpawnGate};

/// Timeout for waiting for the fsmon `ready` line.
const FSMON_READY_TIMEOUT: Duration = Duration::from_secs(10);

struct PendingFsResult {
    id: String,
    is_new: bool,
    rx: oneshot::Receiver<FilesystemCheckReply>,
}

impl PolicyStore {
    /// Spawn the filesystem monitor for a sandbox, wait for it to signal
    /// readiness, and return a reply.
    pub async fn start_filesystem_monitor(
        &self,
        req: FilesystemMonitorRequest,
    ) -> FilesystemMonitorReply {
        let cmd = match &self.args.fs_monitor_cmd {
            Some(c) => c.clone(),
            None => {
                return FilesystemMonitorReply::failed("fs_monitor_cmd not configured");
            }
        };

        if req.static_allow.len() > MAX_STATIC_ALLOW_RULES {
            return FilesystemMonitorReply::failed("too many filesystem static allow rules");
        }

        let ctx = self.resolve_context(&req.ctx);
        let cwd = ctx.paths.cwd_string();
        let home = ctx.paths.home_string();
        let project_root = ctx.paths.project_root_string();

        let sandbox_session_id = ctx.sandbox_session_id.clone();
        let socket_str = self.args.sandbox_socket.to_string_lossy().to_string();

        let mut command = Command::new(&cmd);
        command
            .arg("--pid")
            .arg(req.peer_pid.to_string())
            .arg("--socket")
            .arg(&socket_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        if let Some(c) = &cwd {
            command.arg("--cwd").arg(c);
        }
        if let Some(h) = &home {
            command.arg("--home").arg(h);
        }
        if let Some(p) = &project_root {
            command.arg("--project-root").arg(p);
        }

        // Pass static allow rules to fsmon via environment.
        if !req.static_allow.is_empty()
            && let Ok(json) = serde_json::to_string(&req.static_allow)
        {
            command.env("AGENT_SANDBOX_FS_STATIC_ALLOW", &json);
        }
        if let Some(sandbox_session_id) = &sandbox_session_id {
            command.env("AGENT_SANDBOX_SESSION_ID", sandbox_session_id);
        }

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(error = %err, "failed to spawn fsmon");
                return FilesystemMonitorReply::failed(format!("spawn failed: {err}"));
            }
        };

        let Some(stdout) = child.stdout.take() else {
            tracing::error!("fsmon stdout not captured");
            return FilesystemMonitorReply::failed("stdout not captured");
        };

        // Wait for the "ready" line.
        let result = tokio::time::timeout(FSMON_READY_TIMEOUT, async {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("fsmon closed stdout before ready".to_string());
                }
                if line.trim() == "ready" {
                    return Ok::<_, String>(());
                }
            }
        })
        .await;

        match result {
            Ok(Ok(())) => FilesystemMonitorReply::active(),
            Ok(Err(err)) => FilesystemMonitorReply::failed(format!("ready wait failed: {err}")),
            Err(_) => FilesystemMonitorReply::failed("fsmon ready timeout"),
        }
    }

    pub async fn check_filesystem(&self, req: FilesystemCheckRequest) -> FilesystemCheckReply {
        let resolved = self.resolve_context(&req.ctx);
        if let Some(source) = self
            .filesystem_allow_source(&req.path, req.access, &resolved)
            .await
        {
            if source == "deny" {
                return FilesystemCheckReply::denied("deny", req.path, req.access);
            }
            return FilesystemCheckReply::allowed(source, req.path, req.access);
        }
        self.request_filesystem_approval(FilesystemCheckRequest {
            path: req.path,
            access: req.access,
            ctx: resolved,
        })
        .await
    }

    pub async fn request_filesystem_approval(
        &self,
        req: FilesystemCheckRequest,
    ) -> FilesystemCheckReply {
        let FilesystemCheckRequest { path, access, ctx } = req;
        let resolved = self.resolve_context(&ctx);
        let wire_ids = resolved.ids;
        let cwd = resolved.paths.cwd_string();
        let home = resolved.paths.home_string();
        let project_root = resolved.paths.project_root_string();
        let sandbox_session_id = resolved.sandbox_session_id.clone();
        if self.filesystem_policy_denied(&path, access, &resolved) {
            return FilesystemCheckReply::denied("deny", path, access);
        }
        if !self.args.interactive_approval {
            return FilesystemCheckReply::denied("blocked", path, access);
        }

        if let Some(reply) = self.check_filesystem_verdict_cache(&path, access).await {
            return reply;
        }

        let result = match self
            .dedup_or_create_pending_filesystem(
                &path,
                access,
                cwd.as_deref(),
                home.as_deref(),
                project_root.as_deref(),
                sandbox_session_id.as_deref(),
            )
            .await
        {
            Ok(r) => r,
            Err(reply) => return reply,
        };

        let route = UiRoute::new(cwd.clone(), project_root.clone())
            .with_sandbox_session(sandbox_session_id.clone());

        if result.is_new {
            let push = UiPush::FilesystemRequest {
                id: result.id.clone(),
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
                        nix::unistd::User::from_name(&Self::user_for_home(Some(Path::new(h))))
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

        self.await_filesystem_verdict(&route, &result.id, path, access, result.rx)
            .await
    }
    async fn check_filesystem_verdict_cache(
        &self,
        path: &str,
        access: FileAccess,
    ) -> Option<FilesystemCheckReply> {
        let inner = self.inner.lock().await;
        if let Some(entry) = inner.filesystem_verdict_cache.get(&FilesystemVerdictKey {
            path: path.to_string(),
            access,
        }) && entry.time.elapsed() < Duration::from_secs(2)
        {
            return Some(if entry.allowed {
                FilesystemCheckReply::allowed(entry.source.clone(), path.to_string(), access)
            } else {
                FilesystemCheckReply::denied(entry.source.clone(), path.to_string(), access)
            });
        }
        drop(inner);
        None
    }

    async fn dedup_or_create_pending_filesystem(
        &self,
        path: &str,
        access: FileAccess,
        cwd: Option<&str>,
        home: Option<&str>,
        project_root: Option<&str>,
        sandbox_session_id: Option<&str>,
    ) -> Result<PendingFsResult, FilesystemCheckReply> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;
        // Deduplicate: if a pending already exists for the same file and
        // access type, join its waiters instead of creating a new prompt.
        if let Some(existing_id) = inner.pending.values().find_map(|p| {
            let Pending::Filesystem(fs) = p else {
                return None;
            };
            (fs.path == path && fs.access == access).then(|| fs.id.clone())
        }) {
            let waiter_count = inner
                .filesystem_futures
                .get(&existing_id)
                .map_or(0, Vec::len);
            if waiter_count >= MAX_WAITERS_PER_PENDING {
                return Err(FilesystemCheckReply::blocked(
                    "agent-sandbox: too many waiters for one filesystem approval",
                    path.to_string(),
                    access,
                ));
            }
            inner
                .filesystem_futures
                .entry(existing_id.clone())
                .or_default()
                .push(tx);
            drop(inner);
            return Ok(PendingFsResult {
                id: existing_id,
                is_new: false,
                rx,
            });
        }
        if inner.pending.len() >= MAX_PENDING_APPROVALS {
            return Err(FilesystemCheckReply::blocked(
                "agent-sandbox: too many pending approvals",
                path.to_string(),
                access,
            ));
        }
        let pending_id = format!("fs:{}", Uuid::now_v7().simple());
        inner
            .filesystem_futures
            .insert(pending_id.clone(), vec![tx]);
        inner.pending.insert(
            pending_id.clone(),
            Pending::Filesystem(PendingFilesystem {
                id: pending_id.clone(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |d| d.as_secs_f64()),
                path: path.to_string(),
                access,
                cwd: cwd.map(String::from),
                home: home.map(String::from),
                project_root: project_root.map(String::from),
                sandbox_session_id: sandbox_session_id.map(String::from),
            }),
        );
        drop(inner);
        Ok(PendingFsResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    async fn await_filesystem_verdict(
        &self,
        route: &UiRoute,
        pending_id: &str,
        path: String,
        access: FileAccess,
        rx: oneshot::Receiver<FilesystemCheckReply>,
    ) -> FilesystemCheckReply {
        // Race UI registration against the verdict channel so a CLI approval
        // can unblock the request even if no policy UI ever appears.
        // Preserve the existing two-timeout contract: a short wait for the
        // UI to register, then a full approval_timeout for the verdict.
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
                inner.filesystem_futures.remove(pending_id);
                drop(inner);
                return FilesystemCheckReply::blocked(
                    "agent-sandbox: no standalone filesystem policy UI registered (agent-sandbox-ui or auto-spawn)",
                    path,
                    access,
                );
            }
            let sleep_dur = (ui_deadline - now).min(Duration::from_millis(50));
            tokio::select! {
                biased;
                () = time::sleep(sleep_dur) => {}
                result = &mut rx => {
                    return result.unwrap_or_else(|_| FilesystemCheckReply::denied("blocked", path, access));
                }
            }
        }

        match time::timeout(self.args.approval_timeout, &mut rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => FilesystemCheckReply::denied("blocked", path, access),
            Err(_) => {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(pending_id);
                inner.filesystem_futures.remove(pending_id);
                drop(inner);
                FilesystemCheckReply::blocked(
                    "agent-sandbox: filesystem approval timed out (no response from policy UI)",
                    path,
                    access,
                )
            }
        }
    }

    pub(crate) async fn finish_filesystem(
        &self,
        pending_id: &str,
        path: String,
        access: FileAccess,
        allowed: bool,
        source: &str,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.filesystem_futures.remove(pending_id) {
            let reply = if allowed {
                FilesystemCheckReply::allowed(source, path.clone(), access)
            } else {
                FilesystemCheckReply::denied(source, path.clone(), access)
            };
            for tx in waiters {
                let _ = tx.send(reply.clone());
            }
        }
        // Cache the verdict for deduplication.
        inner.filesystem_verdict_cache.insert(
            FilesystemVerdictKey { path, access },
            VerdictEntry {
                allowed,
                source: source.to_string(),
                time: Instant::now(),
            },
        );
        enforce_verdict_cache_limit(&mut inner.filesystem_verdict_cache);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use agent_sandbox_core::{FileAccess, ProcessIds, SandboxPaths};

    use crate::store::types::{PolicyStore, PolicydArgs};
    use crate::wire::{FilesystemCheckRequest, MergeContext};

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

    fn filesystem_request(path: &str, access: FileAccess) -> FilesystemCheckRequest {
        FilesystemCheckRequest {
            path: path.into(),
            access,
            ctx: MergeContext {
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
    async fn cli_approval_during_ui_wait_unblocks_filesystem_promptly() {
        // Regression: a CLI approval that arrives during the pre-verdict
        // UI-registration wait used to be ignored. The request would only
        // return after the (multi-minute) UI wait timed out.
        let store = Arc::new(test_store());
        let store_for_task = store.clone();
        let task = tokio::spawn(async move {
            store_for_task
                .request_filesystem_approval(filesystem_request("/repo/file.txt", FileAccess::Read))
                .await
        });
        // Wait for the request to register a pending. The task is now
        // inside the UI-registration wait loop.
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner.pending.keys().find(|k| k.starts_with("fs:")).cloned() {
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
        // `apply_pending_filesystem_decision` would use.
        store
            .finish_filesystem(
                &pending_id,
                "/repo/file.txt".into(),
                FileAccess::Read,
                true,
                "cli",
            )
            .await;
        let reply = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");
        assert!(reply.allowed, "expected allowed reply, got: {reply:?}");
    }
}
