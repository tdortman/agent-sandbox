//! Policy store — network.

use std::time::Duration;

use agent_sandbox_core::{CheckReply, ProcessIds, SandboxPaths, UiPush, normalize_host};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use crate::spawn::maybe_spawn_ui;
use crate::wire::{MergeContext, NetworkCheckRequest, UiSpawnContext, UiSpawnGate};

use super::types::{Pending, PendingKind, PolicyStore};

impl PolicyStore {
    /// Finish pending network checks that declarative/session policy already allows (e.g. after OMP registers).
    pub async fn resolve_pending_declarative_allow(&self) {
        let pending: Vec<Pending> = self
            .inner
            .lock()
            .await
            .pending
            .values()
            .filter(|p| p.kind == PendingKind::Network)
            .cloned()
            .collect();
        for p in pending {
            let Some(host) = p.host.clone() else {
                continue;
            };
            let Some(port) = p.port.filter(|&p| p > 0) else {
                continue;
            };
            let merge = MergeContext {
                paths: SandboxPaths::from_wire(
                    p.cwd.clone(),
                    p.home.clone(),
                    p.project_root.clone(),
                ),
                ids: ProcessIds::default(),
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
                pending_id = %p.id,
                "auto-allow pending (policy already allows)"
            );
            self.finish_network(&p.id, true, &source).await;
            self.inner.lock().await.pending.remove(&p.id);
        }
    }

    pub(crate) async fn finish_network(&self, pending_id: &str, allowed: bool, source: &str) {
        let mut inner = self.inner.lock().await;
        if let Some(tx) = inner.network_futures.remove(pending_id) {
            let reply = if allowed {
                CheckReply::allowed(source)
            } else {
                CheckReply::denied(source)
            };
            let _ = tx.send(reply);
        }
    }

    pub async fn request_network_approval(&self, req: NetworkCheckRequest) -> CheckReply {
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
        if self.policy_denied(&policy_host, port, resolved).await {
            tracing::info!(%policy_host, port, "check deny (project policy)");
            return CheckReply::denied("deny");
        }
        if !self.args.interactive_approval {
            return CheckReply::denied("blocked");
        }

        let pending_id = format!("net:{}", Uuid::new_v4().simple());
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().await;
            inner.network_futures.insert(pending_id.clone(), tx);
            inner.pending.insert(
                pending_id.clone(),
                Pending {
                    id: pending_id.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0.0, |d| d.as_secs_f64()),
                    kind: PendingKind::Network,
                    argv: None,
                    host: Some(policy_host.clone()),
                    port: Some(port),
                    scheme: Some(scheme.clone()),
                    url: Some(url.clone()),
                    cwd: cwd.clone(),
                    home: home.clone(),
                    project_root: project_root.clone(),
                },
            );
        }
        Self::audit("pending", Some(&policy_host), Some(port), &scheme);

        self.notify_ui(&UiPush::NetworkRequest {
            id: pending_id.clone(),
            host: Some(policy_host.clone()),
            port: Some(port),
            scheme: Some(scheme.clone()),
            url: Some(url.clone()),
            cwd: cwd.clone(),
            home: home.clone(),
            project_root: project_root.clone(),
        })
        .await;

        let uid = wire_ids.uid();
        let has_ui = !self.inner.lock().await.ui_clients.is_empty();
        if !has_ui {
            let has_omp = self.has_omp_ui().await;
            let spawn = UiSpawnContext {
                gate: UiSpawnGate {
                    has_ui_clients: false,
                    has_omp_ui: has_omp,
                },
                uid,
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

        if self.inner.lock().await.ui_clients.is_empty() {
            let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
            if !self.wait_for_ui_client(ui_wait).await {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(&pending_id);
                inner.network_futures.remove(&pending_id);
                drop(inner);
                tracing::warn!(%policy_host, port, "network approval blocked (no policy UI)");
                return CheckReply::blocked(
                    "agent-sandbox: no policy UI registered (OMP extension, agent-sandbox-ui, or auto-spawn)",
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
                drop(inner);
                Self::audit("timeout", Some(&policy_host), Some(port), &scheme);
                tracing::warn!(%policy_host, port, "network approval timed out");
                CheckReply::blocked(
                    "agent-sandbox: network approval timed out (no response from policy UI)",
                )
            }
        }
    }
}
