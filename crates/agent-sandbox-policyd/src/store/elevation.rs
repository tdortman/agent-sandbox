//! Policy store — elevation.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use agent_sandbox_core::{ElevateReply, SandboxPaths, UiPush};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use crate::spawn::maybe_spawn_ui;
use crate::wire::{ElevationRequest, MergeContext, UiSpawnContext, UiSpawnGate};

use super::types::{Pending, PendingKind, PolicyStore};

impl PolicyStore {
    pub(crate) fn user_for_home(home: Option<&str>) -> String {
        let Some(home) = home else {
            return "root".into();
        };
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let parts: Vec<_> = line.split(':').collect();
                if parts.len() >= 7 && parts[5] == home {
                    return parts[0].to_string();
                }
            }
        }
        Path::new(home)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("nobody")
            .to_string()
    }

    pub(crate) fn elevation_env(home: Option<&str>) -> HashMap<String, String> {
        let user = Self::user_for_home(home);
        HashMap::from([
            ("HOME".into(), home.unwrap_or("/root").to_string()),
            ("USER".into(), user.clone()),
            ("LOGNAME".into(), user),
            (
                "PATH".into(),
                "/run/wrappers:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin:/usr/bin:/bin".into(),
            ),
        ])
    }

    pub(crate) async fn exec_elevation(
        &self,
        argv: &[String],
        cwd: Option<&str>,
        home: Option<&str>,
    ) -> ElevateReply {
        let work_dir = cwd.unwrap_or("/");
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
        let (cwd, home, project_root) = self
            .resolve_context(
                ctx.paths.cwd_string(),
                ctx.paths.home_string(),
                ctx.paths.project_root_string(),
                ctx.ids.pid(),
                ctx.ids.uid(),
            )
            .await;
        let wire_ids = ctx.ids;
        let resolved = MergeContext {
            paths: SandboxPaths::from_wire(cwd.clone(), home.clone(), project_root.clone()),
            ids: wire_ids,
        };
        if self.sudo_policy_denied(&argv, resolved.clone()).await
            || self.session_sudo_denied(&argv).await
        {
            tracing::info!(argv = %argv.join(" "), "sudo deny (policy)");
            return ElevateReply::denied();
        }
        if self.sudo_policy_allowed(&argv, resolved).await || self.session_sudo_allowed(&argv).await
        {
            return self
                .exec_elevation(&argv, cwd.as_deref(), home.as_deref())
                .await;
        }

        let pending_id = format!("elev:{}", Uuid::new_v4().simple());
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            inner.elevation_futures.insert(pending_id.clone(), tx);
            inner.pending.insert(
                pending_id.clone(),
                Pending {
                    id: pending_id.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0.0, |d| d.as_secs_f64()),
                    kind: PendingKind::Elevation,
                    argv: Some(argv.clone()),
                    host: None,
                    port: None,
                    scheme: None,
                    url: None,
                    cwd: cwd.clone(),
                    home: home.clone(),
                    project_root: project_root.clone(),
                },
            );
        }
        let detail = format!("id={pending_id} argv={argv:?}");
        Self::audit("pending", None, None, &detail);

        self.notify_ui(&UiPush::ElevationRequest {
            id: pending_id.clone(),
            argv: Some(argv.clone()),
            cwd: cwd.clone(),
            home: home.clone(),
            project_root: project_root.clone(),
        })
        .await;

        if self.inner.lock().await.ui_clients.is_empty() {
            let mut spawn_uid = wire_ids.uid();
            if spawn_uid.is_none_or(|u| u == 0)
                && let Some(ref h) = home
            {
                spawn_uid = nix::unistd::User::from_name(&Self::user_for_home(Some(h)))
                    .ok()
                    .flatten()
                    .map(|u| u.uid.as_raw());
            }
            let has_omp = self.has_omp_ui().await;
            let spawn = UiSpawnContext {
                gate: UiSpawnGate {
                    has_ui_clients: false,
                    has_omp_ui: has_omp,
                },
                uid: spawn_uid,
                home: home.as_deref(),
                cwd: cwd.as_deref(),
                project_root: project_root.as_deref(),
            };
            maybe_spawn_ui(
                &self.args,
                &mut self.inner.lock().await.ui_spawn_last_by_uid,
                &spawn,
            );
        }

        let ui_clients_empty = {
            let inner = self.inner.lock().await;
            inner.ui_clients.is_empty()
        };
        if ui_clients_empty {
            let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
            if !self.wait_for_ui_client(ui_wait).await {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.elevation_futures.remove(&pending_id);
                drop(inner);
                return ElevateReply {
                    ok: true,
                    allowed: false,
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "agent-sandbox: no policy UI registered (OMP extension, agent-sandbox-ui, or auto-spawn)".into(),
                };
            }
        }

        match time::timeout(self.args.approval_timeout, rx).await {
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
