//! Policy store: status.

use std::sync::Arc;

use agent_sandbox_core::{PendingSummary, ResolvedRequestContext, StatusReply};

use super::types::{Pending, PolicyStore};

impl PolicyStore {
    pub async fn status(self: &Arc<Self>, ctx: ResolvedRequestContext) -> StatusReply {
        let pending = self.pending_summaries().await;
        let merged = self.merged_for_async(&ctx).await;
        StatusReply {
            ok: true,
            merged,
            pending,
        }
    }

    pub(crate) async fn merged_for_async(
        self: &Arc<Self>,
        ctx: &ResolvedRequestContext,
    ) -> agent_sandbox_core::Policy {
        let store = Arc::clone(self);
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || store.merged_for(&ctx))
            .await
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "merged_for worker panicked");
                agent_sandbox_core::Policy::default()
            })
    }

    async fn pending_summaries(&self) -> Vec<PendingSummary> {
        let inner = self.inner.lock().await;
        inner
            .pending
            .values()
            .map(|p| match p {
                Pending::Network(net) => PendingSummary::Network {
                    id: net.id.clone(),
                    host: Some(net.host.clone()),
                    port: Some(net.port),
                    scheme: Some(net.scheme.clone()),
                    url: Some(net.url.clone()),
                    cwd: net.cwd.clone(),
                    home: net.home.clone(),
                },
                Pending::Http(http) => PendingSummary::Http {
                    id: http.pending_id,
                    request: http.request.clone(),
                    cwd: http.context.cwd.clone(),
                    home: http.context.home.clone(),
                    project_root: http.context.project_root.clone(),
                    sandbox_session_id: http.context.sandbox_session_id.clone(),
                },
                Pending::Elevation(elev) => PendingSummary::Elevation {
                    id: elev.id.clone(),
                    argv: Some(elev.argv.clone()),
                    cwd: elev.cwd.clone(),
                    home: elev.home.clone(),
                },
                Pending::Filesystem(fs) => PendingSummary::Filesystem {
                    id: fs.id.clone(),
                    path: Some(fs.path.clone()),
                    access: Some(fs.access),
                    cwd: fs.cwd.clone(),
                    home: fs.home.clone(),
                },
                Pending::Resource(res) => PendingSummary::Resource {
                    id: res.id.clone(),
                    resource_kind: res.kind,
                    path: Some(res.path.clone()),
                    access: Some(res.access),
                    cwd: res.cwd.clone(),
                    home: res.home.clone(),
                },
                Pending::Dbus(dbus) => PendingSummary::Dbus {
                    id: dbus.id.clone(),
                    target: dbus.target.clone(),
                    cwd: dbus.cwd.clone(),
                    home: dbus.home.clone(),
                    project_root: dbus.project_root.clone(),
                    sandbox_session_id: dbus.sandbox_session_id.clone(),
                },
            })
            .collect()
    }
}
