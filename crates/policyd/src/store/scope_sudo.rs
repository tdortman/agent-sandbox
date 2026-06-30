//! Policy store: sudo scope application.
use std::path::PathBuf;

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget};

use crate::error::PolicydError;
use crate::wire::{ScopeWire, SudoScopeOp};

use super::decisions::DecisionAction;
use super::types::PolicyStore;

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
            Err(reply) => return reply,
        };
        let scope_label = scope.as_str();
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                self.apply_sudo_scope_session(action, session_id.clone(), key)
                    .await;
            }
            ScopeTarget::Global { policy_path, home } => {
                let persist = match action {
                    DecisionAction::Approve => Self::persist_sudo_allow(
                        &policy_path,
                        &argv,
                        scope_label,
                        Some(home.as_path()),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_sudo_deny(
                        &policy_path,
                        &argv,
                        scope_label,
                        Some(home.as_path()),
                        owner_uid,
                    ),
                };
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
            }
            ScopeTarget::Project {
                policy_path,
                project_root: _,
            } => {
                let persist = match action {
                    DecisionAction::Approve => {
                        Self::persist_sudo_allow(&policy_path, &argv, scope_label, home, owner_uid)
                    }
                    DecisionAction::Deny => {
                        Self::persist_sudo_deny(&policy_path, &argv, scope_label, home, owner_uid)
                    }
                };
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
    pub(crate) async fn apply_sudo_scope_session(
        &self,
        action: DecisionAction,
        session_id: String,
        key: Vec<String>,
    ) {
        let mut inner = self.inner.lock().await;
        match action {
            DecisionAction::Approve => {
                let bucket = inner
                    .session_sudo_allow
                    .entry(session_id.clone())
                    .or_default();
                bucket.insert(key.clone());
                if let Some(deny_bucket) = inner.session_sudo_deny.get_mut(&session_id) {
                    deny_bucket.remove(&key);
                }
            }
            DecisionAction::Deny => {
                let bucket = inner
                    .session_sudo_deny
                    .entry(session_id.clone())
                    .or_default();
                bucket.insert(key.clone());
                if let Some(allow_bucket) = inner.session_sudo_allow.get_mut(&session_id) {
                    allow_bucket.remove(&key);
                }
            }
        }
    }
}
