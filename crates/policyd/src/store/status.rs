//! Policy store: status.

use agent_sandbox_core::{PendingSummary, ProcessIds, SandboxPaths, StatusReply};

use crate::wire::MergeContext;

use super::types::{Pending, PolicyStore};

impl PolicyStore {
    pub async fn status(&self, paths: SandboxPaths) -> StatusReply {
        let ctx = MergeContext {
            paths,
            ids: ProcessIds::default(),
            sandbox_session_id: None,
        };
        let merged = self.merged_for(&ctx);
        let pending: Vec<PendingSummary> = self
            .inner
            .lock()
            .await
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
            })
            .collect();
        StatusReply {
            ok: true,
            merged,
            pending,
        }
    }
}
