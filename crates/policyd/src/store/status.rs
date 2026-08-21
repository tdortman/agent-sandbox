//! Policy store: status.

use std::sync::Arc;

use agent_sandbox_core::{PendingSummary, Policy, ResolvedRequestContext, StatusReply};

use super::types::{Pending, PolicyStore};

impl PolicyStore {
    /// Produce a [`StatusReply`] summarizing pending approvals and the merged
    /// policy.
    pub async fn status(self: &Arc<Self>, ctx: ResolvedRequestContext) -> StatusReply {
        let pending = self.pending_summaries_for_uid(ctx.ids.uid()).await;
        let merged = self.merged_for_async(&ctx).await;

        StatusReply {
            ok: true,
            merged,
            pending,
        }
    }

    pub(crate) async fn pending_summaries_for_uid(&self, uid: Option<u32>) -> Vec<PendingSummary> {
        let Some(uid) = uid.filter(|&u| u > 0) else {
            return Vec::new();
        };
        let inner = self.inner.lock().await;
        let sessions = self.sandbox_sessions.read().ok();

        inner
            .pending
            .pending_values()
            .filter(|p| {
                p.sandbox_session_id().is_none_or(|session_id| {
                    sessions
                        .as_ref()
                        .and_then(|map| map.get(session_id))
                        .is_some_and(|reg| reg.owner_uid == uid)
                })
            })
            .map(|p| match p {
                Pending::Network(net) => PendingSummary::Network {
                    id: net.id.clone(),
                    host: Some(net.host.clone()),
                    port: Some(net.port),
                    scheme: Some(net.scheme.clone()),
                    url: Some(net.url.clone()),
                    cwd: net.cwd.clone(),
                    home: net.home.clone(),
                    package: net.package.clone(),
                },
                Pending::Http(http) => PendingSummary::Http {
                    id: http.pending_id,
                    request: http.request.clone(),
                    cwd: http.context.cwd.clone(),
                    home: http.context.home.clone(),
                    project_root: http.context.project_root.clone(),
                    sandbox_session_id: http.context.sandbox_session_id.clone(),
                    package: http.package.clone(),
                },
                Pending::Elevation(elev) => PendingSummary::Elevation {
                    id: elev.id.clone(),
                    argv: Some(elev.argv.clone()),
                    cwd: elev.cwd.clone(),
                    home: elev.home.clone(),
                    package: elev.package.clone(),
                },
                Pending::Filesystem(fs) => PendingSummary::Filesystem {
                    id: fs.id.clone(),
                    path: Some(fs.path.clone()),
                    access: Some(fs.access),
                    cwd: fs.cwd.clone(),
                    home: fs.home.clone(),
                    package: fs.package.clone(),
                },
                Pending::Resource(res) => PendingSummary::Resource {
                    id: res.id.clone(),
                    resource_kind: res.kind,
                    path: Some(res.path.clone()),
                    access: Some(res.access),
                    cwd: res.cwd.clone(),
                    home: res.home.clone(),
                    package: res.package.clone(),
                },
                Pending::Dbus(dbus) => PendingSummary::Dbus {
                    id: dbus.id.clone(),
                    target: dbus.target.clone(),
                    cwd: dbus.cwd.clone(),
                    home: dbus.home.clone(),
                    project_root: dbus.project_root.clone(),
                    sandbox_session_id: dbus.sandbox_session_id.clone(),
                    package: dbus.package.clone(),
                },
            })
            .collect()
    }

    pub(crate) async fn merged_for_async(self: &Arc<Self>, ctx: &ResolvedRequestContext) -> Policy {
        let store = Arc::clone(self);
        let ctx = ctx.clone();

        tokio::task::spawn_blocking(move || store.merged_for(&ctx))
            .await
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "merged_for worker panicked");
                Policy::default()
            })
    }

    #[cfg(test)]
    pub(crate) async fn pending_summaries(&self) -> Vec<PendingSummary> {
        let inner = self.inner.lock().await;
        inner
            .pending
            .pending_values()
            .map(|p| match p {
                Pending::Network(net) => PendingSummary::Network {
                    id: net.id.clone(),
                    host: Some(net.host.clone()),
                    port: Some(net.port),
                    scheme: Some(net.scheme.clone()),
                    url: Some(net.url.clone()),
                    cwd: net.cwd.clone(),
                    home: net.home.clone(),
                    package: net.package.clone(),
                },
                Pending::Http(http) => PendingSummary::Http {
                    id: http.pending_id,
                    request: http.request.clone(),
                    cwd: http.context.cwd.clone(),
                    home: http.context.home.clone(),
                    project_root: http.context.project_root.clone(),
                    sandbox_session_id: http.context.sandbox_session_id.clone(),
                    package: http.package.clone(),
                },
                Pending::Elevation(elev) => PendingSummary::Elevation {
                    id: elev.id.clone(),
                    argv: Some(elev.argv.clone()),
                    cwd: elev.cwd.clone(),
                    home: elev.home.clone(),
                    package: elev.package.clone(),
                },
                Pending::Filesystem(fs) => PendingSummary::Filesystem {
                    id: fs.id.clone(),
                    path: Some(fs.path.clone()),
                    access: Some(fs.access),
                    cwd: fs.cwd.clone(),
                    home: fs.home.clone(),
                    package: fs.package.clone(),
                },
                Pending::Resource(res) => PendingSummary::Resource {
                    id: res.id.clone(),
                    resource_kind: res.kind,
                    path: Some(res.path.clone()),
                    access: Some(res.access),
                    cwd: res.cwd.clone(),
                    home: res.home.clone(),
                    package: res.package.clone(),
                },
                Pending::Dbus(dbus) => PendingSummary::Dbus {
                    id: dbus.id.clone(),
                    target: dbus.target.clone(),
                    cwd: dbus.cwd.clone(),
                    home: dbus.home.clone(),
                    project_root: dbus.project_root.clone(),
                    sandbox_session_id: dbus.sandbox_session_id.clone(),
                    package: dbus.package.clone(),
                },
            })
            .collect()
    }
}
