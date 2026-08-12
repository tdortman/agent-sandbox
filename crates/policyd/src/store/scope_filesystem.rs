//! Policy store: filesystem scope application.

use super::{
    ScopePersistFlags, apply_persistent_scope, decisions::DecisionAction,
    persist::PersistResourceRuleArgs, types::PolicyStore,
};
use crate::wire::{FilesystemScopeOp, ResourceScopeOp, ScopeWire};
use agent_sandbox_core::{
    ApprovalScope, DbusTarget, FilesystemRuleKey, ResourceRuleKey, RpcReply, ScopeActionReply,
    ScopeTarget, expand_policy_path,
};
use std::path::Path;

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
            sandbox_session_id: _,
            comment,
            package,
        } = wire;

        let home = paths.home();
        let project_root = paths.project_root();

        let target = match self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                home,
                project_root,
                package.as_deref(),
            )
            .await
        {
            Ok(target) => target,
            Err(reply) => return *reply,
        };

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());

        let persist =
            |policy_path: &Path, home: Option<&Path>, invalidate: bool| -> std::io::Result<()> {
                Self::persist_filesystem_rule(
                    policy_path,
                    &path,
                    access,
                    scope_label,
                    matches!(action, DecisionAction::Approve),
                    home,
                    owner_uid,
                )?;

                if invalidate {
                    self.invalidate_merged_policy_cache();
                }

                Ok(())
            };

        match target {
            ScopeTarget::Ephemeral => {}

            ScopeTarget::Session { session_id } => {
                let resolved_path = expand_policy_path(&path, home, project_root);
                let key = FilesystemRuleKey::new(resolved_path, access);
                let mut inner = self.inner.lock().await;
                inner.session.filesystem().apply(action, &session_id, &key);
                drop(inner);
            }

            ScopeTarget::Global { .. }
            | ScopeTarget::GlobalPackage { .. }
            | ScopeTarget::Project { .. }
            | ScopeTarget::ProjectPackage { .. } => {
                if let Err(err) = apply_persistent_scope(
                    target,
                    home,
                    ScopePersistFlags::new(true, true),
                    Some("project filesystem policy saved"),
                    Some("project package filesystem policy saved"),
                    persist,
                ) {
                    return err.into();
                }
            }
        }

        let scope_label = scope.as_str();
        let audit_detail = format!(
            "path={} access={access:?} scope={scope_label}",
            path.display()
        );

        self.finalize_scope_reply(
            &paths,
            scope,
            action,
            (None, None, &audit_detail),
            |scope, policy_path| {
                RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
                    path,
                    access,
                    scope,
                    policy_path,
                ))
            },
        )
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
            package,
        } = wire;

        let home = paths.home();
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        let project_root = paths.project_root();

        let scope_target = match self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                home,
                project_root,
                package.as_deref(),
            )
            .await
        {
            Ok(target) => target,
            Err(reply) => return *reply,
        };

        let persist =
            |policy_path: &Path, home: Option<&Path>, invalidate: bool| -> std::io::Result<()> {
                Self::persist_dbus_rule(
                    policy_path,
                    &target,
                    scope_label,
                    action == DecisionAction::Approve,
                    home,
                    owner_uid,
                )?;

                if invalidate {
                    self.invalidate_merged_policy_cache();
                }

                Ok(())
            };

        let policy_path = match scope_target {
            ScopeTarget::Ephemeral => None,

            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                inner.session.dbus().apply(action, &session_id, &target);
                drop(inner);
                None
            }

            ScopeTarget::Global { .. }
            | ScopeTarget::GlobalPackage { .. }
            | ScopeTarget::Project { .. }
            | ScopeTarget::ProjectPackage { .. } => {
                match apply_persistent_scope(
                    scope_target,
                    home,
                    ScopePersistFlags::new(false, true),
                    None,
                    None,
                    persist,
                ) {
                    Ok(path) => path,
                    Err(err) => return err.into(),
                }
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
            package,
        } = wire;

        let home = paths.home();
        let project_root = paths.project_root();

        let target = match self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                home,
                project_root,
                package.as_deref(),
            )
            .await
        {
            Ok(target) => target,
            Err(reply) => return *reply,
        };

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
        let key = ResourceRuleKey::new(kind, &path, access);

        let persist =
            |policy_path: &Path, home: Option<&Path>, invalidate: bool| -> std::io::Result<()> {
                Self::persist_resource_rule(&PersistResourceRuleArgs {
                    path: policy_path,
                    kind,
                    rule_path: &path,
                    access,
                    label: scope_label,
                    allow_rule: matches!(action, DecisionAction::Approve),
                    home,
                    owner_uid,
                })?;

                if invalidate {
                    self.invalidate_merged_policy_cache();
                }

                Ok(())
            };

        match target {
            ScopeTarget::Ephemeral => {}

            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                inner.session.resource().apply(action, &session_id, &key);
                drop(inner);
            }

            ScopeTarget::Global { .. }
            | ScopeTarget::GlobalPackage { .. }
            | ScopeTarget::Project { .. }
            | ScopeTarget::ProjectPackage { .. } => {
                if let Err(err) = apply_persistent_scope(
                    target,
                    home,
                    ScopePersistFlags::new(false, true),
                    Some("project resource policy saved"),
                    Some("project package resource policy saved"),
                    persist,
                ) {
                    return err.into();
                }
            }
        }

        let scope_label = scope.as_str();
        let audit_detail = format!(
            "kind={kind:?} path={} access={access:?} scope={scope_label}",
            path.display()
        );

        self.finalize_scope_reply(
            &paths,
            scope,
            action,
            (None, None, &audit_detail),
            |scope, policy_path| {
                RpcReply::ScopeAction(ScopeActionReply::ok_resource(
                    kind,
                    path,
                    access,
                    scope,
                    policy_path,
                ))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        store::decisions::DecisionAction,
        wire::{FilesystemScopeOp, ScopeWire},
    };
    use agent_sandbox_core::{
        ApprovalScope, FileAccess, Policy, ProcessIds, ResolvedRequestContext, RpcReply,
        SandboxPaths, Verdict, VerdictSource,
    };
    use std::{path::PathBuf, time::Duration};

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
            package: None,
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

    fn package_store(dir: &tempfile::TempDir) -> PolicyStore {
        PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ))
    }

    fn package_ctx(
        home: &PathBuf,
        project: &PathBuf,
        package: Option<&str>,
    ) -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::new(project, home, project),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-pkg".into()),
            package: package.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn global_package_approval_persists_to_home_extension_and_applies() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        let scripts = project.join("scripts");
        std::fs::create_dir_all(&scripts).expect("create project scripts");
        let store = package_store(&dir);
        let omp = package_ctx(&home, &project, Some("omp"));
        let requested = scripts.join("plot_utils.py");

        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &omp)
                .await,
            None
        );

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("./scripts"),
                    access: FileAccess::ReadWrite,
                    scope: ApprovalScope::GlobalPackage,
                    wire: ScopeWire::from_resolved(&omp, None),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        // The rule lands in the flat home extension file, not the global
        // user policy file.
        let ext = home.join(".config/agent-sandbox/packages/omp.json");

        let policy: Policy = agent_sandbox_core::load_policy(&ext, Some(&home), None);

        assert_eq!(
            policy.filesystem.allow[0].path,
            PathBuf::from("./scripts"),
            "global_package approval must persist to the package home extension file"
        );

        assert!(
            !home.join(".config/agent-sandbox/policy.json").exists(),
            "global_package approval must not touch the shared user policy file"
        );

        // A later request from the same package sees the persisted rule via
        // the merged policy.
        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &omp)
                .await,
            Some(Verdict::allowed(VerdictSource::policy()))
        );

        // A different package in the same home does not see the rule.
        let codex = package_ctx(&home, &project, Some("codex"));

        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &codex)
                .await,
            None,
            "the omp rule must not leak to another package's session"
        );
    }

    #[tokio::test]
    async fn global_package_deny_persists_to_home_extension() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        let omp = package_ctx(&home, &project, Some("omp"));

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("/denied/file"),
                    access: FileAccess::ReadWrite,
                    scope: ApprovalScope::GlobalPackage,
                    wire: ScopeWire::from_resolved(&omp, None),
                },
                DecisionAction::Deny,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));
        let ext = home.join(".config/agent-sandbox/packages/omp.json");
        let policy: Policy = agent_sandbox_core::load_policy(&ext, Some(&home), None);

        assert_eq!(
            policy.filesystem.deny[0].path,
            PathBuf::from("/denied/file"),
            "global_package deny must persist to the package home extension file"
        );

        assert!(
            policy.filesystem.allow.is_empty(),
            "the deny must not also create an allow rule"
        );
    }

    #[tokio::test]
    async fn global_package_scope_requires_attributed_session() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        let unattributed = package_ctx(&home, &project, None);

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("./scripts"),
                    access: FileAccess::Read,
                    scope: ApprovalScope::GlobalPackage,
                    wire: ScopeWire::from_resolved(&unattributed, None),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            matches!(
                &reply,
                RpcReply::Error(e) if e.error == "package required for global_package scope"
            ),
            "an unattributed session must not resolve the global_package scope, got: {reply:?}"
        );

        assert!(
            !home
                .join(".config/agent-sandbox/packages/omp.json")
                .exists(),
            "no package file may be written without attribution"
        );
    }

    #[tokio::test]
    async fn project_package_approval_persists_to_project_package_file_and_stays_scoped() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        let other_project = home.join("other-project");
        let scripts = project.join("scripts");
        std::fs::create_dir_all(&scripts).expect("create project scripts");
        std::fs::create_dir_all(&other_project).expect("create other project dir");
        let store = package_store(&dir);
        let omp = package_ctx(&home, &project, Some("omp"));
        let requested = scripts.join("plot_utils.py");

        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &omp)
                .await,
            None
        );

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("./scripts"),
                    access: FileAccess::ReadWrite,
                    scope: ApprovalScope::ProjectPackage,
                    wire: ScopeWire::from_resolved(&omp, None),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        // The rule lands in the flat package project file, not the shared
        // project policy file and not the home extension file.
        let pkg_project = project.join(".agent-sandbox/packages/omp.json");

        let policy: Policy = agent_sandbox_core::load_policy(&pkg_project, Some(&home), None);

        assert_eq!(
            policy.filesystem.allow[0].path,
            PathBuf::from("./scripts"),
            "project_package approval must persist to the package-specific project file"
        );

        assert!(
            !project.join(".agent-sandbox/policy.json").exists(),
            "project_package approval must not touch the shared project policy file"
        );

        assert!(
            !home
                .join(".config/agent-sandbox/packages/omp.json")
                .exists(),
            "project_package approval must not touch the home extension file"
        );

        // A later request from the same package in the same project sees
        // the persisted rule via the merged policy.
        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &omp)
                .await,
            Some(Verdict::allowed(VerdictSource::policy()))
        );

        // A different package in the same project does not see the rule.
        let codex = package_ctx(&home, &project, Some("codex"));

        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &codex)
                .await,
            None,
            "the omp rule must not leak to another package in the same project"
        );

        // The same package in a different project does not see the rule.
        let omp_other = package_ctx(&home, &other_project, Some("omp"));

        assert_eq!(
            store
                .filesystem_allow_source(&requested, FileAccess::Read, &omp_other)
                .await,
            None,
            "the omp rule must not leak to the same package in another project"
        );

        assert!(
            !other_project
                .join(".agent-sandbox/packages/omp.json")
                .exists(),
            "no package project file may be written for the other project"
        );
    }

    #[tokio::test]
    async fn project_package_deny_persists_to_project_package_file() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        let omp = package_ctx(&home, &project, Some("omp"));

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("/denied/file"),
                    access: FileAccess::ReadWrite,
                    scope: ApprovalScope::ProjectPackage,
                    wire: ScopeWire::from_resolved(&omp, None),
                },
                DecisionAction::Deny,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));
        let pkg_project = project.join(".agent-sandbox/packages/omp.json");
        let policy: Policy = agent_sandbox_core::load_policy(&pkg_project, Some(&home), None);

        assert_eq!(
            policy.filesystem.deny[0].path,
            PathBuf::from("/denied/file"),
            "project_package deny must persist to the package-specific project file"
        );

        assert!(
            policy.filesystem.allow.is_empty(),
            "the deny must not also create an allow rule"
        );
    }

    #[tokio::test]
    async fn project_package_scope_requires_attributed_session() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        let unattributed = package_ctx(&home, &project, None);

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("./scripts"),
                    access: FileAccess::Read,
                    scope: ApprovalScope::ProjectPackage,
                    wire: ScopeWire::from_resolved(&unattributed, None),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            matches!(
                &reply,
                RpcReply::Error(e) if e.error == "package required for global_package scope"
            ),
            "an unattributed session must not resolve the project_package scope, got: {reply:?}"
        );

        assert!(
            !project.join(".agent-sandbox/packages/omp.json").exists(),
            "no package project file may be written without attribution"
        );
    }
}
