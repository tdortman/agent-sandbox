//! Policy store — status.

use agent_sandbox_core::{PendingSummary, ProcessIds, SandboxPaths, StatusReply};

use crate::wire::MergeContext;

use super::types::{PendingKind, PolicyStore};

impl PolicyStore {
    pub async fn status(&self, paths: SandboxPaths) -> StatusReply {
        let merged = self
            .merged_for(MergeContext {
                paths,
                ids: ProcessIds::default(),
            })
            .await;
        let pending: Vec<PendingSummary> = self
            .inner
            .lock()
            .await
            .pending
            .values()
            .map(|p| {
                if p.kind == PendingKind::Network {
                    PendingSummary::Network {
                        id: p.id.clone(),
                        host: p.host.clone(),
                        port: p.port,
                        scheme: p.scheme.clone(),
                        url: p.url.clone(),
                        cwd: p.cwd.clone(),
                        home: p.home.clone(),
                    }
                } else {
                    PendingSummary::Elevation {
                        id: p.id.clone(),
                        argv: p.argv.clone(),
                        cwd: p.cwd.clone(),
                        home: p.home.clone(),
                    }
                }
            })
            .collect();
        StatusReply {
            ok: true,
            merged,
            pending,
        }
    }
}
