//! Policy store: sudo scope application.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget};

use super::{
    decisions::DecisionAction,
    scope_apply::{ScopeLadder, ScopePersistFlags},
    state::apply_bucket,
    types::PolicyStore,
};
use crate::wire::{ScopeWire, SudoScopeOp};

impl PolicyStore {
    pub(crate) async fn apply_sudo_scope(
        &self,
        op: SudoScopeOp,
        action: DecisionAction,
    ) -> RpcReply {
        let SudoScopeOp { argv, scope, wire } = op;

        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id: _,
            comment,
            package,
        } = wire;

        let cwd = paths.cwd_path();
        let home = paths.home();
        let project_root = paths.project_root();

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());

        let mut persist = |policy_path: &Path, home: Option<&Path>| -> std::io::Result<()> {
            Self::persist_sudo_rule(
                policy_path,
                &argv,
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
                    project_log: Some("project sudo policy saved"),
                    project_package_log: Some("project package sudo policy saved"),
                },
                |inner, target| {
                    match target {
                        ScopeTarget::Ephemeral => {}

                        ScopeTarget::Session { session_id } => {
                            apply_bucket(
                                &mut inner.session.session_sudo_allow,
                                &mut inner.session.session_sudo_deny,
                                action,
                                session_id,
                                &argv,
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

        let scope_label = scope.as_str();
        let audit_detail = format!("argv={argv:?} scope={scope_label}");

        self.finalize_scope_reply(
            &SandboxPaths::from_wire(
                cwd,
                home.map(PathBuf::from),
                project_root.map(PathBuf::from),
            ),
            scope,
            action,
            (None, None, &audit_detail),
            |scope, policy_path| {
                RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope, policy_path))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use agent_sandbox_core::{
        ApprovalScope, Policy, ProcessIds, ResolvedRequestContext, RpcReply, SandboxPaths,
        load_policy,
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

    fn ctx(home: &PathBuf, session: Option<&str>) -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::new(home, home, home.join("project")),
            ids: ProcessIds::default(),
            sandbox_session_id: session.map(str::to_string),
            package: None,
        }
    }

    fn op(scope: ApprovalScope, context: &ResolvedRequestContext) -> SudoScopeOp {
        SudoScopeOp {
            argv: vec!["cargo".into(), "publish".into()],
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
    async fn session_approval_applies_to_the_sudo_bucket() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let store = store(&dir);
        register_ui_session(&store, "sandbox-a");

        let reply = store
            .apply_sudo_scope(
                op(ApprovalScope::Session, &ctx(&home, Some("sandbox-a"))),
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let inner = store.inner.lock().await;

        assert!(
            inner
                .session
                .session_sudo_allow
                .get("sandbox-a")
                .is_some_and(
                    |bucket| bucket.contains(&vec!["cargo".to_string(), "publish".to_string()])
                ),
            "the session approval must land in the sudo allow bucket"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn project_approval_persists_to_the_project_policy() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = store(&dir);

        let reply = store
            .apply_sudo_scope(
                op(ApprovalScope::Project, &ctx(&home, None)),
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let policy: Policy = load_policy(
            &project.join(".agent-sandbox/policy.json"),
            Some(&home),
            None,
        );

        assert_eq!(
            policy.sudo.allow.len(),
            1,
            "the project approval must persist one sudo allow rule"
        );
    }
}
