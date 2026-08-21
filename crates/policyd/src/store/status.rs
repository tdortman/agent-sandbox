//! Policy store: status.

use std::sync::Arc;

use agent_sandbox_core::{PendingSummary, Policy, ResolvedRequestContext, StatusReply};

use super::types::PolicyStore;

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
            .map(PendingSummary::from)
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
            .map(PendingSummary::from)
            .collect()
    }
}
