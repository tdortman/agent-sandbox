//! Policy store — ui.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use agent_sandbox_core::{SessionContext, UiPush};
use tokio::io::AsyncWriteExt;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::time;
use uuid::Uuid;

use super::types::{
    CLIENT_ID, Pending, PendingKind, PolicyStore, UiClient, UiClientHandle, UiSessionContext,
};

impl PolicyStore {
    pub async fn has_omp_ui(&self) -> bool {
        self.inner
            .lock()
            .await
            .ui_clients
            .values()
            .any(|c| c.ui_client == "omp")
    }

    async fn ui_notification_targets(&self) -> Vec<std::sync::Arc<Mutex<OwnedWriteHalf>>> {
        let inner = self.inner.lock().await;
        let omp: Vec<_> = inner
            .ui_clients
            .values()
            .filter(|c| c.ui_client == "omp")
            .map(|c| c.writer.clone())
            .collect();
        if !omp.is_empty() {
            return omp;
        }
        inner
            .ui_clients
            .values()
            .filter(|c| c.ui_client != "omp")
            .map(|c| c.writer.clone())
            .collect()
    }

    async fn disconnect_standalone_clients(&self) {
        let to_disconnect: Vec<u64> = {
            let inner = self.inner.lock().await;
            inner
                .ui_clients
                .iter()
                .filter(|(_, c)| c.ui_client != "omp")
                .map(|(id, _)| *id)
                .collect()
        };
        for id in to_disconnect {
            self.end_ui_session_by_id(id).await;
        }
    }

    pub async fn start_ui_session(
        &self,
        handle: &UiClientHandle,
        ui_client: &str,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    ) -> String {
        if ui_client == "omp" {
            self.disconnect_standalone_clients().await;
        }
        let session_id = Uuid::new_v4().simple().to_string();
        let mut inner = self.inner.lock().await;
        inner.ui_clients.insert(
            handle.id,
            UiClient {
                session_id: session_id.clone(),
                ui_client: ui_client.to_string(),
                writer: handle.writer.clone(),
            },
        );
        inner.ui_context_by_session.insert(
            session_id.clone(),
            UiSessionContext {
                cwd,
                home,
                project_root,
            },
        );
        session_id
    }

    pub async fn end_ui_session(&self, client_id: u64) {
        self.end_ui_session_by_id(client_id).await;
    }

    async fn end_ui_session_by_id(&self, client_id: u64) {
        let mut inner = self.inner.lock().await;
        if let Some(client) = inner.ui_clients.remove(&client_id) {
            inner.session_allow.remove(&client.session_id);
            inner.session_deny.remove(&client.session_id);
            inner.session_sudo_allow.remove(&client.session_id);
            inner.session_sudo_deny.remove(&client.session_id);
            inner.ui_context_by_session.remove(&client.session_id);
        }
    }

    pub fn new_client_handle(writer: std::sync::Arc<Mutex<OwnedWriteHalf>>) -> UiClientHandle {
        UiClientHandle {
            id: CLIENT_ID.fetch_add(1, Ordering::Relaxed),
            writer,
        }
    }

    pub async fn ui_context_for_session(&self, session_id: &str) -> Option<SessionContext> {
        self.inner
            .lock()
            .await
            .ui_context_by_session
            .get(session_id)
            .map(|ctx| SessionContext {
                cwd: ctx.cwd.clone(),
                home: ctx.home.clone(),
                project_root: ctx.project_root.clone(),
            })
    }

    pub(crate) async fn wait_for_ui_client(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !self.inner.lock().await.ui_clients.is_empty() {
                return true;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    pub async fn notify_ui(&self, payload: &UiPush) {
        let targets = self.ui_notification_targets().await;
        if targets.is_empty() {
            return;
        }
        let line = agent_sandbox_core::RpcMessage::UiPush(payload.clone()).to_string();
        let mut dead = Vec::new();
        for (id, writer) in self
            .inner
            .lock()
            .await
            .ui_clients
            .iter()
            .map(|(id, c)| (*id, c.writer.clone()))
        {
            if !targets.iter().any(|t| std::sync::Arc::ptr_eq(t, &writer)) {
                continue;
            }
            let mut w = writer.lock().await;
            if w.write_all(line.as_bytes()).await.is_err() {
                dead.push(id);
            }
        }
        for id in dead {
            self.end_ui_session(id).await;
        }
    }

    pub async fn flush_pending_to_ui(&self) {
        let pending: Vec<Pending> = self.inner.lock().await.pending.values().cloned().collect();
        for p in pending {
            if p.kind == PendingKind::Network {
                self.notify_ui(&UiPush::NetworkRequest {
                    id: p.id.clone(),
                    host: p.host.clone(),
                    port: p.port,
                    scheme: p.scheme.clone(),
                    url: p.url.clone(),
                    cwd: p.cwd.clone(),
                    home: p.home.clone(),
                    project_root: p.project_root.clone(),
                })
                .await;
            } else {
                self.notify_ui(&UiPush::ElevationRequest {
                    id: p.id.clone(),
                    argv: p.argv.clone(),
                    cwd: p.cwd.clone(),
                    home: p.home.clone(),
                    project_root: p.project_root.clone(),
                })
                .await;
            }
        }
    }
}
