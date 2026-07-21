//! Policy store: filesystem scope application.
use std::path::PathBuf;

use agent_sandbox_core::{
    ApprovalScope, DbusTarget, FileAccess, FilesystemRuleKey, ResourceAccess, ResourceKind,
    ResourceRuleKey, RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget, expand_policy_path,
};

use super::{decisions::DecisionAction, persist::PersistResourceRuleArgs, types::PolicyStore};
use crate::{
    error::PolicydError,
    wire::{FilesystemScopeOp, ResourceScopeOp, ScopeWire},
};

impl PolicyStore {
    fn finalize_filesystem_scope(
        &self,
        paths: &SandboxPaths,
        path: PathBuf,
        access: FileAccess,
        scope: ApprovalScope,
        action: DecisionAction,
    ) -> RpcReply {
        let _ = self.export_policy_files(paths.clone());
        let scope_label = scope.as_str();
        let detail = format!(
            "path={} access={access:?} scope={scope_label}",
            path.display()
        );
        Self::audit(action.audit_verb(), None, None, &detail);
        let policy_path = match (paths.home(), paths.project_root()) {
            (_, Some(p)) if scope == ApprovalScope::Project => Self::project_policy_path_display(p),
            _ => None,
        };
        RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
            path,
            access,
            scope,
            policy_path.map(PathBuf::from),
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
            comment,
        } = wire;
        let home = paths.home();
        let project_root = paths.project_root();
        let target = match self
            .resolve_scope_target(scope, session_id.as_deref(), home, project_root)
            .await
        {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let resolved_path = expand_policy_path(&path, home, project_root);
                let key = FilesystemRuleKey::new(resolved_path, access);
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
                        Some(home.as_path()),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_filesystem_rule(
                        &policy_path,
                        &path,
                        access,
                        scope_label,
                        false,
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
                    DecisionAction::Approve => Self::persist_filesystem_rule(
                        &policy_path,
                        &path,
                        access,
                        scope_label,
                        true,
                        home,
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_filesystem_rule(
                        &policy_path,
                        &path,
                        access,
                        scope_label,
                        false,
                        home,
                        owner_uid,
                    ),
                };
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project filesystem policy saved");
            }
        }
        self.finalize_filesystem_scope(&paths, path, access, scope, action)
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

    fn finalize_resource_scope(
        &self,
        paths: &SandboxPaths,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        scope: ApprovalScope,
        action: DecisionAction,
    ) -> RpcReply {
        let _ = self.export_policy_files(paths.clone());
        let scope_label = scope.as_str();
        let detail = format!(
            "kind={kind:?} path={} access={access:?} scope={scope_label}",
            path.display()
        );
        Self::audit(action.audit_verb(), None, None, &detail);
        let policy_path = match (paths.home(), paths.project_root()) {
            (_, Some(p)) if scope == ApprovalScope::Project => Self::project_policy_path_display(p),
            _ => None,
        };
        RpcReply::ScopeAction(ScopeActionReply::ok_resource(
            kind,
            path,
            access,
            scope,
            policy_path.map(PathBuf::from),
        ))
    }

    pub(crate) async fn apply_dbus_scope(
        &self,
        target: DbusTarget,
        scope: ApprovalScope,
        wire: ScopeWire,
        action: DecisionAction,
    ) -> RpcReply {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id: _,
            comment,
        } = wire;
        let home = paths.home();
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        let project_root = paths.project_root();
        let scope_target = match self
            .resolve_scope_target(scope, session_id.as_deref(), home, project_root)
            .await
        {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let policy_path = match scope_target {
            ScopeTarget::Ephemeral => None,
            ScopeTarget::Session { session_id } => {
                self.apply_dbus_scope_session(action, session_id, target.clone())
                    .await;
                None
            }
            ScopeTarget::Global { policy_path, home } => {
                if let Err(err) = Self::persist_dbus_rule(
                    &policy_path,
                    &target,
                    scope_label,
                    action == DecisionAction::Approve,
                    Some(home.as_path()),
                    owner_uid,
                ) {
                    return PolicydError::from(err).into();
                }
                Some(policy_path)
            }
            ScopeTarget::Project { policy_path, .. } => {
                if let Err(err) = Self::persist_dbus_rule(
                    &policy_path,
                    &target,
                    scope_label,
                    action == DecisionAction::Approve,
                    home,
                    owner_uid,
                ) {
                    return PolicydError::from(err).into();
                }
                Some(policy_path)
            }
        };
        let _ = self.export_policy_files(paths);
        Self::audit(
            action.audit_verb(),
            None,
            None,
            &format!("D-Bus target={target:?} scope={scope_label}"),
        );
        RpcReply::ScopeAction(ScopeActionReply::ok_dbus(target, scope, policy_path))
    }

    pub(crate) async fn apply_dbus_scope_session(
        &self,
        action: DecisionAction,
        session_id: String,
        target: DbusTarget,
    ) {
        let mut inner = self.inner.lock().await;
        match action {
            DecisionAction::Approve => {
                inner
                    .session_dbus_allow
                    .entry(session_id.clone())
                    .or_default()
                    .insert(target.clone());
                if let Some(deny) = inner.session_dbus_deny.get_mut(&session_id) {
                    deny.remove(&target);
                }
            }
            DecisionAction::Deny => {
                inner
                    .session_dbus_deny
                    .entry(session_id.clone())
                    .or_default()
                    .insert(target.clone());
                if let Some(allow) = inner.session_dbus_allow.get_mut(&session_id) {
                    allow.remove(&target);
                }
            }
        }
    }

    pub(crate) async fn apply_resource_scope(
        &self,
        op: ResourceScopeOp,
        action: DecisionAction,
    ) -> RpcReply {
        let ResourceScopeOp {
            kind,
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
            comment,
        } = wire;
        let home = paths.home();
        let project_root = paths.project_root();
        let target = match self
            .resolve_scope_target(scope, session_id.as_deref(), home, project_root)
            .await
        {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let key = ResourceRuleKey::new(kind, &path, access);
                self.apply_resource_scope_session(action, session_id.clone(), key)
                    .await;
            }
            ScopeTarget::Global { policy_path, home } => {
                if let Err(err) = Self::persist_resource_rule(&PersistResourceRuleArgs {
                    path: &policy_path,
                    kind,
                    rule_path: &path,
                    access,
                    label: scope_label,
                    allow_rule: matches!(action, DecisionAction::Approve),
                    home: Some(home.as_path()),
                    owner_uid,
                }) {
                    return PolicydError::from(err).into();
                }
            }
            ScopeTarget::Project {
                policy_path,
                project_root: _,
            } => {
                if let Err(err) = Self::persist_resource_rule(&PersistResourceRuleArgs {
                    path: &policy_path,
                    kind,
                    rule_path: &path,
                    access,
                    label: scope_label,
                    allow_rule: matches!(action, DecisionAction::Approve),
                    home,
                    owner_uid,
                }) {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project resource policy saved");
            }
        }
        self.finalize_resource_scope(&paths, kind, path, access, scope, action)
    }

    pub(crate) async fn apply_resource_scope_session(
        &self,
        action: DecisionAction,
        session_id: String,
        key: ResourceRuleKey,
    ) {
        let mut inner = self.inner.lock().await;
        match action {
            DecisionAction::Approve => {
                let bucket = inner
                    .session_resource_allow
                    .entry(session_id.clone())
                    .or_default();
                bucket.insert(key.clone());
                if let Some(deny_bucket) = inner.session_resource_deny.get_mut(&session_id) {
                    deny_bucket.remove(&key);
                }
            }
            DecisionAction::Deny => {
                let bucket = inner
                    .session_resource_deny
                    .entry(session_id.clone())
                    .or_default();
                bucket.insert(key.clone());
                if let Some(allow_bucket) = inner.session_resource_allow.get_mut(&session_id) {
                    allow_bucket.remove(&key);
                }
            }
        }
    }
}
