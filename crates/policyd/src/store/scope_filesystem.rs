//! Policy store: filesystem scope application.
use std::path::PathBuf;

use agent_sandbox_core::{
    ApprovalScope, DbusTarget, FileAccess, FilesystemRuleKey, ResourceAccess, ResourceKind,
    ResourceRuleKey, RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget, expand_policy_path,
};

use super::{
    apply_session_rule,
    decisions::DecisionAction,
    persist::PersistResourceRuleArgs,
    types::{PolicyDecisionState, PolicyStore},
};
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
            Err(reply) => return *reply,
        };
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let resolved_path = expand_policy_path(&path, home, project_root);
                let key = FilesystemRuleKey::new(resolved_path, access);
                let mut inner = self.inner.lock().await;
                let PolicyDecisionState {
                    session_filesystem_allow: allow,
                    session_filesystem_deny: deny,
                    ..
                } = &mut *inner;
                apply_session_rule(action, &session_id, &key, allow, deny);
                drop(inner);
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
                self.invalidate_merged_policy_cache();
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
                self.invalidate_merged_policy_cache();
                tracing::info!(path = ?policy_path, "project filesystem policy saved");
            }
        }
        self.finalize_filesystem_scope(&paths, path, access, scope, action)
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
            Err(reply) => return *reply,
        };
        let policy_path = match scope_target {
            ScopeTarget::Ephemeral => None,
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                let PolicyDecisionState {
                    session_dbus_allow: allow,
                    session_dbus_deny: deny,
                    ..
                } = &mut *inner;
                apply_session_rule(action, &session_id, &target, allow, deny);
                drop(inner);
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
            Err(reply) => return *reply,
        };
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        let key = ResourceRuleKey::new(kind, &path, access);
        match target {
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                let PolicyDecisionState {
                    session_resource_allow: allow,
                    session_resource_deny: deny,
                    ..
                } = &mut *inner;
                apply_session_rule(action, &session_id, &key, allow, deny);
                drop(inner);
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
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use agent_sandbox_core::{
        ApprovalScope, FileAccess, Policy, ProcessIds, ResolvedRequestContext, RpcReply,
        SandboxPaths, Verdict, VerdictSource,
    };

    use super::*;
    use crate::{
        store::decisions::DecisionAction,
        wire::{FilesystemScopeOp, ScopeWire},
    };

    #[tokio::test]
    async fn project_filesystem_persistence_invalidates_merged_cache() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        let scripts = project.join("scripts");
        std::fs::create_dir_all(&scripts).expect("create project scripts");
        let declarative = dir.path().join("declarative.json");
        let export_json = dir.path().join("export.json");
        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            declarative,
            export_json,
            Duration::from_secs(30),
            true,
        ));
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project, &home, &project),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
        };
        let requested = scripts.join("plot_utils.py");

        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &ctx)
                .await,
            None
        );

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("./scripts"),
                    access: FileAccess::ReadWrite,
                    scope: ApprovalScope::Project,
                    wire: ScopeWire::from_resolved(&ctx, None),
                },
                DecisionAction::Approve,
            )
            .await;
        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::allowed(VerdictSource::policy()))
        );
        let policy: Policy = agent_sandbox_core::load_policy(
            &project.join(".agent-sandbox/policy.json"),
            Some(&home),
            None,
        );
        assert_eq!(policy.filesystem.allow[0].path, PathBuf::from("./scripts"));
    }
}
