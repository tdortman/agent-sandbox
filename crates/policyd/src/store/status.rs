//! Policy store: status.

use std::{collections::HashSet, sync::Arc};

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

        // Collect before locking the state: a request must never wait on a
        // blocking lock while holding the lock every other request needs.
        let owned: HashSet<String> = self
            .sandbox_sessions
            .snapshot()
            .iter()
            .filter(|(_, registration)| registration.owner_uid == uid)
            .map(|(session_id, _)| session_id.clone())
            .collect();

        let inner = self.inner.lock().await;

        inner
            .pending
            .pending
            .values()
            .filter(|pending| {
                pending
                    .sandbox_session_id()
                    .is_none_or(|session_id| owned.contains(session_id))
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
            .pending
            .values()
            .map(PendingSummary::from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::PathBuf};

    use agent_sandbox_core::{PendingSummary, ProcessIds, ResolvedRequestContext, SandboxPaths};

    use crate::store::{
        test_store,
        types::{
            LauncherBinding, Pending, PendingNetwork, RootAdoption, SandboxSessionRegistration,
        },
    };

    fn registration(owner_uid: u32) -> SandboxSessionRegistration {
        SandboxSessionRegistration {
            root: RootAdoption::Unadopted,
            owner_uid,
            project_root: PathBuf::from("/repo"),
            package: None,
            launcher: LauncherBinding::Unbound,
            cgroup: None,
            export_reader: None,
        }
    }

    fn pending_network(id: &str, sandbox_session_id: Option<&str>) -> Pending {
        Pending::Network(PendingNetwork {
            id: id.to_owned(),
            created_at: 0.0,
            host: "example.com".into(),
            port: 443,
            scheme: "tcp".into(),
            url: "tcp://example.com:443".into(),
            aliases: Vec::new(),
            ctx: ResolvedRequestContext::new(
                SandboxPaths::default(),
                ProcessIds::default(),
                sandbox_session_id.map(str::to_owned),
            ),
        })
    }

    #[tokio::test]
    async fn pending_summaries_for_uid_lists_only_that_uid_s_sessions() {
        let store = test_store();
        store.update_registry(|sessions| {
            sessions.insert("mine".into(), registration(1000));
            sessions.insert("theirs".into(), registration(1001));
        });

        for (id, session) in [
            ("own", Some("mine")),
            ("foreign", Some("theirs")),
            ("loose", None),
        ] {
            let pending = pending_network(id, session);
            store
                .inner
                .lock()
                .await
                .pending
                .pending
                .insert(pending.id().to_owned(), pending);
        }

        let ids: BTreeSet<String> = store
            .pending_summaries_for_uid(Some(1000))
            .await
            .into_iter()
            .map(|summary| match summary {
                PendingSummary::Network { id, .. } => id,
                other => panic!("unexpected summary kind: {other:?}"),
            })
            .collect();

        assert_eq!(ids, BTreeSet::from(["loose".to_owned(), "own".to_owned()]));
    }
}
