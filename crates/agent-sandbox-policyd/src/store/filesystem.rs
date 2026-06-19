//! Policy store: filesystem (fanotify monitor spawn and declarative checks).

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

use agent_sandbox_core::{FileAccess, FilesystemCheckReply, FilesystemMonitorReply, UiPush};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use super::types::PolicyStore;
use crate::spawn::maybe_spawn_ui;
use crate::store::ui_route::UiRoute;
use crate::wire::{FilesystemCheckRequest, FilesystemMonitorRequest, UiSpawnContext, UiSpawnGate};

/// Timeout for waiting for the fsmon `ready` line.
const FSMON_READY_TIMEOUT: Duration = Duration::from_secs(10);

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

        let ctx = self.resolve_context(req.ctx).await;
        let cwd = ctx.paths.cwd_string();
        let home = ctx.paths.home_string();
        let project_root = ctx.paths.project_root_string();

        let sandbox_session_id = ctx.sandbox_session_id.clone();
        let socket_str = self.args.socket.to_string_lossy().to_string();

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
            Err(e) => {
                tracing::error!(error = %e, "failed to spawn fsmon");
                return FilesystemMonitorReply::failed(format!("spawn failed: {e}"));
            }
        };

        let Some(stdout) = child.stdout.take() else {
            tracing::error!("fsmon stdout not captured");
            let _ = child.kill();
            return FilesystemMonitorReply::failed("stdout not captured");
        };

        // Wait for the "ready" line.
        let result = tokio::time::timeout(FSMON_READY_TIMEOUT, async {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) if l.trim() == "ready" => return Ok(()),
                    Ok(l) if l.trim().is_empty() => {}
                    Ok(l) => {
                        tracing::debug!(line = %l, "fsmon stdout");
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fsmon stdout closed before ready",
            ))
        })
        .await;

        match result {
            Ok(Ok(())) => {
                // Detach the child - it continues running as the monitor.
                let _ = child.id();
                FilesystemMonitorReply::active()
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "fsmon ready wait failed");
                let _ = child.kill();
                FilesystemMonitorReply::failed(format!("ready wait failed: {e}"))
            }
            Err(_) => {
                tracing::error!("fsmon ready timed out");
                let _ = child.kill();
                FilesystemMonitorReply::failed("fsmon ready timeout")
            }
        }
    }

    pub async fn check_filesystem(&self, req: FilesystemCheckRequest) -> FilesystemCheckReply {
        let resolved = self.resolve_context(req.ctx.clone()).await;
        if let Some(source) = self
            .filesystem_allow_source(&req.path, req.access, resolved.clone())
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
        let resolved = self.resolve_context(ctx).await;
        let wire_ids = resolved.ids;
        let cwd = resolved.paths.cwd_string();
        let home = resolved.paths.home_string();
        let project_root = resolved.paths.project_root_string();
        let sandbox_session_id = resolved.sandbox_session_id.clone();
        if self
            .filesystem_policy_denied(&path, access, resolved.clone())
            .await
        {
            return FilesystemCheckReply::denied("deny", path, access);
        }
        if !self.args.interactive_approval {
            return FilesystemCheckReply::denied("blocked", path, access);
        }

        let pending_id = format!("fs:{}", Uuid::new_v4().simple());
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            inner.filesystem_futures.insert(pending_id.clone(), tx);
            inner.pending.insert(
                pending_id.clone(),
                super::types::Pending::Filesystem(super::types::PendingFilesystem {
                    id: pending_id.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0.0, |d| d.as_secs_f64()),
                    path: path.clone(),
                    access,
                    cwd: cwd.clone(),
                    home: home.clone(),
                    project_root: project_root.clone(),
                    request_pid: wire_ids.pid().filter(|&p| p != 0),
                    sandbox_session_id: sandbox_session_id.clone(),
                }),
            );
        }

        let route = UiRoute::new(
            wire_ids.pid().filter(|&p| p != 0),
            cwd.clone(),
            home.clone(),
            project_root.clone(),
        )
        .with_sandbox_session(sandbox_session_id.clone());
        let push = UiPush::FilesystemRequest {
            id: pending_id.clone(),
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

        if !self.has_standalone_ui_for_route(&route).await {
            let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
            if !self.wait_for_standalone_ui_client(&route, ui_wait).await {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.filesystem_futures.remove(&pending_id);
                return FilesystemCheckReply::blocked(
                    "agent-sandbox: no standalone filesystem policy UI registered (agent-sandbox-ui or auto-spawn)",
                    path,
                    access,
                );
            }
        }

        match time::timeout(self.args.approval_timeout, rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => FilesystemCheckReply::denied("blocked", path, access),
            Err(_) => {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.filesystem_futures.remove(&pending_id);
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
        if let Some(tx) = inner.filesystem_futures.remove(pending_id) {
            let reply = if allowed {
                FilesystemCheckReply::allowed(source, path, access)
            } else {
                FilesystemCheckReply::denied(source, path, access)
            };
            let _ = tx.send(reply);
        }
    }
}
