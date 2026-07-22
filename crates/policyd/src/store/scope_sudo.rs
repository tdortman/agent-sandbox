//! Policy store: sudo scope application.
use std::path::PathBuf;

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget};

use super::{
    apply_session_rule,
    decisions::DecisionAction,
    types::{PolicyDecisionState, PolicyStore},
};
use crate::{
    error::PolicydError,
    wire::{ScopeWire, SudoScopeOp},
};

impl PolicyStore {
    fn finalize_sudo_scope(
        &self,
        paths: &SandboxPaths,
        argv: Vec<String>,
        scope: ApprovalScope,
        action: DecisionAction,
    ) -> RpcReply {
        let _ = self.export_policy_files(paths.clone());
        let scope_label = scope.as_str();
        let detail = format!("argv={argv:?} scope={scope_label}");
        Self::audit(action.audit_verb(), None, None, &detail);
        let path = match (paths.home(), paths.project_root()) {
            (_, Some(p)) if scope == ApprovalScope::Project => Self::project_policy_path_display(p),
            _ => None,
        };
        RpcReply::ScopeAction(ScopeActionReply::ok_sudo(
            argv,
            scope,
            path.map(PathBuf::from),
        ))
    }

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
        } = wire;
        let cwd = paths.cwd_path();
        let home = paths.home();
        let project_root = paths.project_root();
        let key = argv.clone();
        let target = match self
            .resolve_scope_target(scope, session_id.as_deref(), home, project_root)
            .await
        {
            Ok(target) => target,
            Err(reply) => return *reply,
        };
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                let PolicyDecisionState {
                    session_sudo_allow: allow,
                    session_sudo_deny: deny,
                    ..
                } = &mut *inner;
                apply_session_rule(action, &session_id, &key, allow, deny);
                drop(inner);
            }
            ScopeTarget::Global { policy_path, home } => {
                let persist = Self::persist_sudo_rule(
                    &policy_path,
                    &argv,
                    scope_label,
                    action == DecisionAction::Approve,
                    Some(home.as_path()),
                    owner_uid,
                );
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
            }
            ScopeTarget::Project {
                policy_path,
                project_root: _,
            } => {
                let persist = Self::persist_sudo_rule(
                    &policy_path,
                    &argv,
                    scope_label,
                    action == DecisionAction::Approve,
                    home,
                    owner_uid,
                );
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project sudo policy saved");
            }
        }
        self.finalize_sudo_scope(
            &SandboxPaths::from_wire(
                cwd,
                home.map(PathBuf::from),
                project_root.map(PathBuf::from),
            ),
            argv,
            scope,
            action,
        )
    }
}
