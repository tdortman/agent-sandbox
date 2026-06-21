//! Policy store: sudo scope application.

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget};

use crate::error::PolicydError;
use crate::wire::{ScopeWire, SudoScopeOp};

use super::decisions::DecisionAction;
use super::types::PolicyStore;

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
        } = wire;
        let cwd = paths.cwd_string();
        let home = paths.home_string();
        let project_root = paths.project_root_string();
        let key = argv.clone();
        let target = match self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                home.as_deref(),
                project_root.as_deref(),
            )
            .await
        {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let scope_label = scope.as_str();
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                match action {
                    DecisionAction::Approve => {
                        inner
                            .session_sudo_allow
                            .entry(session_id.clone())
                            .or_default()
                            .insert(key.clone());
                        if let Some(deny_bucket) = inner.session_sudo_deny.get_mut(&session_id) {
                            deny_bucket.remove(&key);
                        }
                    }
                    DecisionAction::Deny => {
                        inner
                            .session_sudo_deny
                            .entry(session_id.clone())
                            .or_default()
                            .insert(key.clone());
                        if let Some(allow_bucket) = inner.session_sudo_allow.get_mut(&session_id) {
                            allow_bucket.remove(&key);
                        }
                    }
                }
            }
            ScopeTarget::Global { policy_path, home } => {
                let persist = match action {
                    DecisionAction::Approve => Self::persist_sudo_allow(
                        &policy_path,
                        &argv,
                        scope_label,
                        Some(&home),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_sudo_deny(
                        &policy_path,
                        &argv,
                        scope_label,
                        Some(&home),
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
                    DecisionAction::Approve => Self::persist_sudo_allow(
                        &policy_path,
                        &argv,
                        scope_label,
                        home.as_deref(),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_sudo_deny(
                        &policy_path,
                        &argv,
                        scope_label,
                        home.as_deref(),
                        owner_uid,
                    ),
                };
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project policy saved");
            }
        }
        let _ = self
            .export_policy_files(SandboxPaths::from_wire(
                cwd,
                home.clone(),
                project_root.clone(),
            ))
            .await;
        let detail = format!("argv={argv:?} scope={scope_label}");
        Self::audit(action.audit_verb(), None, None, &detail);
        let path = project_root
            .as_deref()
            .filter(|_| scope == ApprovalScope::Project)
            .and_then(Self::project_policy_path_display);
        RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope, path))
    }
}
