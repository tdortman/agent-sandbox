//! Policy store: network scope application.

use std::path::Path;

use agent_sandbox_core::{NetworkRuleKey, RpcReply, ScopeActionReply, ScopeTarget};

use super::{
    decisions::DecisionAction,
    scope_apply::{ScopeLadder, ScopePersistFlags},
    state::apply_bucket,
    types::PolicyStore,
};
use crate::wire::{NetworkScopeOp, ScopeWire};

impl PolicyStore {
    pub(crate) async fn apply_network_scope(
        &self,
        op: NetworkScopeOp,
        action: DecisionAction,
    ) -> RpcReply {
        let NetworkScopeOp {
            host,
            port,
            scope,
            wire,
        } = op;

        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id: _,
            comment,
            package,
        } = wire;

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        let key = NetworkRuleKey::new(&host, port);

        let mut persist = |policy_path: &Path, home: Option<&Path>| -> std::io::Result<()> {
            Self::persist_network_rule(
                policy_path,
                &host,
                port,
                scope_label,
                action == DecisionAction::Approve,
                home,
                owner_uid,
            )
        };

        if let Err(err) = self
            .apply_scope_ladder(
                ScopeLadder {
                    scope,
                    session_id: session_id.as_deref(),
                    package: package.as_deref(),
                    paths: &paths,
                    flags: ScopePersistFlags::new(false, true),
                    project_log: Some("project policy saved"),
                    project_package_log: Some("project package policy saved"),
                },
                |inner, target| {
                    match target {
                        ScopeTarget::Ephemeral => {
                            if action == DecisionAction::Approve {
                                inner.session.once_allow.insert(key.clone());
                            }
                        }

                        ScopeTarget::Session { session_id } => {
                            apply_bucket(
                                &mut inner.session.session_allow,
                                &mut inner.session.session_deny,
                                action,
                                session_id,
                                &key,
                            );
                        }

                        ScopeTarget::Global { .. }
                        | ScopeTarget::GlobalPackage { .. }
                        | ScopeTarget::Project { .. }
                        | ScopeTarget::ProjectPackage { .. } => {}
                    }

                    Ok(())
                },
                &mut persist,
            )
            .await
        {
            return err.into();
        }

        self.finalize_scope_reply(
            &paths,
            scope,
            action,
            (Some(host.as_str()), Some(port), scope.as_str()),
            |scope, policy_path| {
                RpcReply::ScopeAction(ScopeActionReply::ok_network(
                    host.clone(),
                    port,
                    scope,
                    policy_path,
                ))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use agent_sandbox_core::{
        ApprovalScope, NetworkRuleKey, Policy, ProcessIds, ResolvedRequestContext, RpcReply,
        SandboxPaths, load_policy,
    };

    use super::*;
    use crate::wire::ScopeWire;

    fn store(dir: &tempfile::TempDir) -> PolicyStore {
        PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ))
    }

    fn ctx(home: &PathBuf, session: Option<&str>, package: Option<&str>) -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::new(home, home, home.join("project")),
            ids: ProcessIds::default(),
            sandbox_session_id: session.map(str::to_string),
            package: package.map(str::to_string),
        }
    }

    fn op(
        host: &str,
        port: u16,
        scope: ApprovalScope,
        context: &ResolvedRequestContext,
    ) -> NetworkScopeOp {
        NetworkScopeOp {
            host: host.to_string(),
            port,
            scope,
            wire: ScopeWire::from_resolved(context, context.sandbox_session_id.clone()),
        }
    }

    fn ui_writer() -> std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>> {
        std::sync::Arc::new(tokio::sync::Mutex::new(
            tokio::net::UnixStream::pair()
                .expect("unix stream pair")
                .0
                .into_split()
                .1,
        ))
    }

    /// Session-scope approvals validate the session against the registered
    /// UI clients, so a test session exists only once a UI client carries it.
    fn register_ui_session(store: &PolicyStore, id: &str) {
        store
            .inner
            .try_lock()
            .expect("the decision state lock is only held by this test")
            .ui_clients
            .insert(1, crate::store::types::UiClient {
                session_id: id.to_string(),
                writer: ui_writer(),
            });
    }

    #[tokio::test]
    async fn once_approval_tracks_once_allow_and_deny_is_ignored() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let store = store(&dir);

        let reply = store
            .apply_network_scope(
                op(
                    "example.com",
                    443,
                    ApprovalScope::Once,
                    &ctx(&home, Some("sandbox-a"), None),
                ),
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let deny = store
            .apply_network_scope(
                op(
                    "denied.example.com",
                    443,
                    ApprovalScope::Once,
                    &ctx(&home, Some("sandbox-a"), None),
                ),
                DecisionAction::Deny,
            )
            .await;

        assert!(matches!(deny, RpcReply::ScopeAction(_)));

        let inner = store.inner.lock().await;

        assert!(
            inner
                .session
                .once_allow
                .contains(&NetworkRuleKey::new("example.com", 443)),
            "once approval must land in the once-allow set"
        );

        assert!(
            !inner
                .session
                .once_allow
                .contains(&NetworkRuleKey::new("denied.example.com", 443)),
            "a once deny must not create a once-allow entry"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn session_deny_wins_over_approve() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let store = store(&dir);
        register_ui_session(&store, "sandbox-a");

        let approve = store
            .apply_network_scope(
                op(
                    "example.com",
                    443,
                    ApprovalScope::Session,
                    &ctx(&home, Some("sandbox-a"), None),
                ),
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(approve, RpcReply::ScopeAction(_)));

        let deny = store
            .apply_network_scope(
                op(
                    "example.com",
                    443,
                    ApprovalScope::Session,
                    &ctx(&home, Some("sandbox-a"), None),
                ),
                DecisionAction::Deny,
            )
            .await;

        assert!(matches!(deny, RpcReply::ScopeAction(_)));

        let inner = store.inner.lock().await;
        let key = NetworkRuleKey::new("example.com", 443);

        assert!(
            !inner
                .session
                .session_allow
                .get("sandbox-a")
                .is_some_and(|bucket| bucket.contains(&key)),
            "the later deny must remove the earlier session allow"
        );

        assert!(
            inner
                .session
                .session_deny
                .get("sandbox-a")
                .is_some_and(|bucket| bucket.contains(&key)),
            "the session deny must land in the deny bucket"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn global_approval_persists_direct_rule_to_user_policy() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).expect("create home");
        let store = store(&dir);

        let reply = store
            .apply_network_scope(
                op(
                    "example.com",
                    443,
                    ApprovalScope::Global,
                    &ctx(&home, None, None),
                ),
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let policy: Policy = load_policy(
            &home.join(".config/agent-sandbox/policy.json"),
            Some(&home),
            None,
        );

        assert_eq!(
            policy.network.direct.allow.len(),
            1,
            "the global approval must persist one direct allow rule"
        );
    }

    #[tokio::test]
    async fn global_package_requires_attribution() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).expect("create home");
        let store = store(&dir);

        let reply = store
            .apply_network_scope(
                op(
                    "example.com",
                    443,
                    ApprovalScope::GlobalPackage,
                    &ctx(&home, Some("sandbox-a"), None),
                ),
                DecisionAction::Approve,
            )
            .await;

        assert!(
            !matches!(reply, RpcReply::ScopeAction(_)),
            "a package scope without an attributed package must be rejected"
        );

        assert!(
            !home.join(".config/agent-sandbox/packages").exists(),
            "no package extension file may be written without attribution"
        );
    }
}
