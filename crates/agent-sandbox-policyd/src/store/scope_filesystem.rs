//! Policy store — filesystem scope application.

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget};

use crate::error::PolicydError;
use crate::wire::{FilesystemScopeOp, ScopeWire};

use super::decisions::DecisionAction;
use super::types::PolicyStore;

impl PolicyStore {
    pub(crate) async fn apply_filesystem_scope(
        &self,
        op: FilesystemScopeOp,
        action: DecisionAction,
    ) -> RpcReply {
        let FilesystemScopeOp {
            path,
            access,
            scope,
            wire,
        } = op;
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
        } = wire;
        let cwd = paths.cwd_string();
        let home = paths.home_string();
        let project_root = paths.project_root_string();
        let target = match self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                home.as_deref(),
                project_root.as_deref(),
            )
            .await
        {
            Ok(t) => t,
            Err(err) => return err,
        };
        let scope_label = scope.as_str();
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                let entry = (path.clone(), access);
                match action {
                    DecisionAction::Approve => {
                        inner
                            .session_filesystem_allow
                            .entry(session_id.clone())
                            .or_default()
                            .insert(entry.clone());
                        if let Some(deny) = inner.session_filesystem_deny.get_mut(&session_id) {
                            deny.remove(&entry);
                        }
                    }
                    DecisionAction::Deny => {
                        inner
                            .session_filesystem_deny
                            .entry(session_id.clone())
                            .or_default()
                            .insert(entry.clone());
                        if let Some(allow) = inner.session_filesystem_allow.get_mut(&session_id) {
                            allow.remove(&entry);
                        }
                    }
                }
            }
            ScopeTarget::Global {
                policy_path,
                home: target_home,
            } => {
                if let Err(err) = Self::persist_filesystem_rule(
                    &policy_path,
                    &path,
                    access,
                    scope_label,
                    action == DecisionAction::Approve,
                    Some(&target_home),
                    owner_uid,
                ) {
                    return PolicydError::from(err).into();
                }
            }
            ScopeTarget::Project {
                policy_path,
                project_root: _,
            } => {
                if let Err(err) = Self::persist_filesystem_rule(
                    &policy_path,
                    &path,
                    access,
                    scope_label,
                    action == DecisionAction::Approve,
                    home.as_deref(),
                    owner_uid,
                ) {
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
        let detail = format!("path={path} access={access:?} scope={scope_label}");
        Self::audit(action.audit_verb(), None, None, &detail);
        let policy_path = project_root
            .as_deref()
            .filter(|_| scope == ApprovalScope::Project)
            .and_then(Self::project_policy_path_display);
        RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
            path,
            access,
            scope,
            policy_path,
        ))
    }
}
