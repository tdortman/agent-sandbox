//! Policy store: elevation.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use agent_sandbox_core::{ElevateReply, UiPush};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use crate::spawn::maybe_spawn_ui;
use crate::wire::{ElevationRequest, UiSpawnContext, UiSpawnGate};

use super::types::{MAX_PENDING_APPROVALS, Pending, PendingElevation, PolicyStore};
use super::ui_route::UiRoute;

impl PolicyStore {
    pub(crate) fn user_for_home(home: Option<&Path>) -> String {
        let Some(home) = home else {
            return "root".into();
        };
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            let home_str = home.to_string_lossy();
            for line in passwd.lines() {
                let mut parts = line.splitn(7, ':');
                let _ = parts.next();
                let _ = parts.next();
                let _ = parts.next();
                let _ = parts.next();
                let _ = parts.next();
                let dir = parts.next().unwrap_or("");
                if dir == home_str.as_ref()
                    && let Some(user) = line.split(':').next()
                    && !user.is_empty()
                {
                    return user.to_string();
                }
            }
        }
        home.file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("nobody")
            .to_string()
    }

    pub(crate) fn elevation_env(home: Option<&Path>) -> HashMap<String, String> {
        let user = Self::user_for_home(home);
        HashMap::from([("AGENT_SANDBOX_ELEVATE_USER".into(), user)])
    }

    pub(crate) async fn exec_elevation(
        &self,
        argv: &[String],
        cwd: Option<&Path>,
        home: Option<&Path>,
    ) -> ElevateReply {
        let work_dir = cwd.unwrap_or(Path::new("/"));
        let mut cmd = tokio::process::Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir(work_dir)
            .envs(Self::elevation_env(home))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let output = cmd.output().await;
        match output {
            Ok(out) => {
                let exit_code = out.status.code().unwrap_or(1);
                let detail = format!("argv={argv:?} exit_code={exit_code}");
                Self::audit("exec", None, None, &detail);
                ElevateReply::executed(
                    exit_code,
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                )
            }
            Err(err) => ElevateReply::exec_failed(err),
        }
    }

    pub(crate) async fn finish_elevation(&self, pending_id: &str, result: ElevateReply) {
        let mut inner = self.inner.lock().await;
        if let Some(tx) = inner.elevation_futures.remove(pending_id) {
            let _ = tx.send(result);
        }
    }

    pub async fn request_elevation(&self, req: ElevationRequest) -> ElevateReply {
        let ElevationRequest { argv, ctx } = req;
        let argv: Vec<String> = argv.into_iter().collect();
        let resolved = self.resolve_context(ctx).await;
        let wire_ids = resolved.ids;
        let cwd = resolved.paths.cwd_string();
        let home = resolved.paths.home_string();
        let project_root = resolved.paths.project_root_string();
        let sandbox_session_id = resolved.sandbox_session_id.clone();
        if self.sudo_policy_denied(&argv, resolved.clone()).await
            || self.session_sudo_denied(&argv, resolved.clone()).await
        {
            tracing::info!(argv = %argv.join(" "), "sudo deny (policy)");
            return ElevateReply::denied();
        }
        if self.sudo_policy_allowed(&argv, resolved.clone()).await
            || self.session_sudo_allowed(&argv, resolved).await
        {
            return self
                .exec_elevation(
                    &argv,
                    cwd.as_deref().map(Path::new),
                    home.as_deref().map(Path::new),
                )
                .await;
        }

        let pending_id = format!("elev:{}", Uuid::now_v7().simple());
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            if inner.pending.len() >= MAX_PENDING_APPROVALS {
                tracing::warn!(
                    pending_count = inner.pending.len(),
                    "elevation approval blocked (too many pending approvals)"
                );
                return ElevateReply {
                    ok: true,
                    allowed: false,
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "agent-sandbox: too many pending approvals".into(),
                };
            }
            inner.elevation_futures.insert(pending_id.clone(), tx);
            inner.pending.insert(
                pending_id.clone(),
                Pending::Elevation(PendingElevation {
                    id: pending_id.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0.0, |d| d.as_secs_f64()),
                    argv: argv.clone(),
                    cwd: cwd.clone(),
                    home: home.clone(),
                    project_root: project_root.clone(),
                    sandbox_session_id: sandbox_session_id.clone(),
                }),
            );
        }
        let detail = format!("id={pending_id} argv={argv:?}");
        Self::audit("pending", None, None, &detail);

        let route = UiRoute::new(cwd.clone(), project_root.clone())
            .with_sandbox_session(sandbox_session_id.clone());
        self.notify_ui(
            &route,
            &UiPush::ElevationRequest {
                id: pending_id.clone(),
                argv: Some(argv.clone()),
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
                spawn_uid = nix::unistd::User::from_name(&Self::user_for_home(Some(Path::new(h))))
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

        // Race UI registration against the verdict channel so a CLI approval
        // can unblock the request even if no policy UI ever appears.
        // Preserve the existing two-timeout contract: a short wait for the
        // UI to register, then a full approval_timeout for the verdict.
        let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
        let ui_deadline = Instant::now() + ui_wait;
        tokio::pin!(rx);
        loop {
            if self.has_ui_for_route(&route).await {
                break;
            }
            let now = Instant::now();
            if now >= ui_deadline {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.elevation_futures.remove(&pending_id);
                drop(inner);
                return ElevateReply {
                    ok: true,
                    allowed: false,
                    exit_code: 1,
                    stdout: String::new(),
                    stderr:
                        "agent-sandbox: no policy UI registered (agent-sandbox-ui or auto-spawn)"
                            .into(),
                };
            }
            let sleep_dur = (ui_deadline - now).min(Duration::from_millis(50));
            tokio::select! {
                biased;
                _ = time::sleep(sleep_dur) => {}
                result = &mut rx => {
                    return match result {
                        Ok(v) => v,
                        Err(_) => ElevateReply::denied(),
                    };
                }
            }
        }

        match time::timeout(self.args.approval_timeout, &mut rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => ElevateReply::denied(),
            Err(_) => {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.elevation_futures.remove(&pending_id);
                drop(inner);
                Self::audit("timeout", None, None, &pending_id);
                ElevateReply {
                    ok: true,
                    allowed: false,
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "agent-sandbox: elevation timed out (no response from policy UI)"
                        .into(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::store::types::{PolicyStore, PolicydArgs};
    use crate::wire::{ElevationRequest, MergeContext};
    use agent_sandbox_core::{ElevateReply, ProcessIds, SandboxPaths};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
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

    fn elevation_request(argv: Vec<String>) -> ElevationRequest {
        ElevationRequest {
            argv,
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
    async fn cli_approval_during_ui_wait_unblocks_elevation_promptly() {
        // Regression: a CLI approval that arrives during the pre-verdict
        // UI-registration wait used to be ignored. The request would only
        // return after the (multi-minute) UI wait timed out.
        let store = Arc::new(test_store());
        let store_for_task = store.clone();
        let task = tokio::spawn(async move {
            store_for_task
                .request_elevation(elevation_request(vec![
                    "systemctl".into(),
                    "restart".into(),
                ]))
                .await
        });
        // Wait for the request to register a pending. The task is now
        // inside the UI-registration wait loop.
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending
                    .keys()
                    .find(|k| k.starts_with("elev:"))
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
        // `apply_pending_sudo_decision` would use.
        let reply = ElevateReply::executed(0, String::new(), String::new());
        store.finish_elevation(&pending_id, reply).await;
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");
        assert!(result.allowed, "expected allowed reply, got: {result:?}");
    }
}
