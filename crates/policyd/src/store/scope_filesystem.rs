//! Policy store: filesystem scope application.
use std::path::Path;

use agent_sandbox_core::{
    ApprovalScope, FileAccess, FilesystemRuleKey, RpcReply, SandboxPaths, ScopeActionReply,
    ScopeTarget,
};

use crate::error::PolicydError;
use crate::wire::{FilesystemScopeOp, ScopeWire};

use super::decisions::DecisionAction;
use super::types::PolicyStore;

impl PolicyStore {
    fn finalize_filesystem_scope(
        &self,
        paths: &SandboxPaths,
        path: String,
        access: FileAccess,
        scope: ApprovalScope,
        action: DecisionAction,
    ) -> RpcReply {
        let _ = self.export_policy_files(paths.clone());
        let scope_label = scope.as_str();
        let detail = format!("path={path} access={access:?} scope={scope_label}");
        Self::audit(action.audit_verb(), None, None, &detail);
        let policy_path = match (paths.home(), paths.project_root()) {
            (_, Some(p)) if scope == ApprovalScope::Project => {
                Self::project_policy_path_display(Path::new(p))
            }
            _ => None,
        };
        RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
            path,
            access,
            scope,
            policy_path,
        ))
    }

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
            sandbox_session_id: _,
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
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let scope_label = scope.as_str();
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let key = FilesystemRuleKey::new(&path, access);
                self.apply_filesystem_scope_session(action, session_id.clone(), key)
                    .await;
            }
            ScopeTarget::Global { policy_path, home } => {
                let persist = match action {
                    DecisionAction::Approve => Self::persist_filesystem_rule(
                        &policy_path,
                        &path,
                        access,
                        scope_label,
                        true,
                        Some(Path::new(&home)),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_filesystem_rule(
                        &policy_path,
                        &path,
                        access,
                        scope_label,
                        false,
                        Some(Path::new(&home)),
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
                    DecisionAction::Approve => Self::persist_filesystem_rule(
                        &policy_path,
                        &path,
                        access,
                        scope_label,
                        true,
                        home.as_deref().map(Path::new),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_filesystem_rule(
                        &policy_path,
                        &path,
                        access,
                        scope_label,
                        false,
                        home.as_deref().map(Path::new),
                        owner_uid,
                    ),
                };
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project filesystem policy saved");
            }
        }
        self.finalize_filesystem_scope(
            &SandboxPaths::from_wire(cwd, home, project_root),
            path,
            access,
            scope,
            action,
        )
    }
    pub(crate) async fn apply_filesystem_scope_session(
        &self,
        action: DecisionAction,
        session_id: String,
        key: FilesystemRuleKey,
    ) {
        let mut inner = self.inner.lock().await;
        match action {
            DecisionAction::Approve => {
                let bucket = inner
                    .session_filesystem_allow
                    .entry(session_id.clone())
                    .or_default();
                bucket.insert(key.clone());
                if let Some(deny_bucket) = inner.session_filesystem_deny.get_mut(&session_id) {
                    deny_bucket.remove(&key);
                }
            }
            DecisionAction::Deny => {
                let bucket = inner
                    .session_filesystem_deny
                    .entry(session_id.clone())
                    .or_default();
                bucket.insert(key.clone());
                if let Some(allow_bucket) = inner.session_filesystem_allow.get_mut(&session_id) {
                    allow_bucket.remove(&key);
                }
            }
        }
    }
}
