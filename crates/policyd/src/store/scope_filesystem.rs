//! Policy store: filesystem scope application.

use std::path::Path;

use agent_sandbox_core::{
    ApprovalScope, DbusTarget, FilesystemRuleKey, ResourceRuleKey, RpcReply, ScopeActionReply,
    ScopeTarget, expand_policy_path,
};

use super::{
    decisions::DecisionAction,
    persist::PersistResourceRuleArgs,
    scope_apply::{ScopeLadder, ScopePersistFlags},
    types::PolicyStore,
};
use crate::wire::{FilesystemScopeOp, ResourceScopeOp, ScopeWire};

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

        let key = FilesystemRuleKey::new(expand_policy_path(&path, home, project_root), access);

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());

        let mut persist = |policy_path: &Path, home: Option<&Path>| -> std::io::Result<()> {
            Self::persist_filesystem_rule(
                policy_path,
                &path,
                access,
                scope_label,
                matches!(action, DecisionAction::Approve),
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
                    flags: ScopePersistFlags::new(true, true),
                    project_log: Some("project filesystem policy saved"),
                    project_package_log: Some("project package filesystem policy saved"),
                },
                |inner, target| {
                    match target {
                        ScopeTarget::Ephemeral => {}

                        ScopeTarget::Session { session_id } => {
                            inner.session.filesystem().apply(action, session_id, &key);
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

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());

        let mut persist = |policy_path: &Path, home: Option<&Path>| -> std::io::Result<()> {
            Self::persist_dbus_rule(
                policy_path,
                &target,
                scope_label,
                action == DecisionAction::Approve,
                home,
                owner_uid,
            )
        };

        let applied = self
            .apply_scope_ladder(
                ScopeLadder {
                    scope,
                    session_id: session_id.as_deref(),
                    package: package.as_deref(),
                    paths: &paths,
                    flags: ScopePersistFlags::new(false, true),
                    project_log: None,
                    project_package_log: None,
                },
                |inner, scope_target| {
                    match scope_target {
                        ScopeTarget::Ephemeral => {}

                        ScopeTarget::Session { session_id } => {
                            inner.session.dbus().apply(action, session_id, &target);
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
            .await;

        let policy_path = match applied {
            Ok(applied) => applied.policy_path,
            Err(err) => return err.into(),
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

        let key = ResourceRuleKey::new(kind, &path, access);

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());

        let mut persist = |policy_path: &Path, home: Option<&Path>| -> std::io::Result<()> {
            Self::persist_resource_rule(&PersistResourceRuleArgs {
                path: policy_path,
                kind,
                rule_path: &path,
                access,
                label: scope_label,
                allow_rule: matches!(action, DecisionAction::Approve),
                home,
                owner_uid,
            })
        };

        if let Err(err) = self
            .apply_scope_ladder(
                ScopeLadder {
                    scope,
                    session_id: session_id.as_deref(),
                    package: package.as_deref(),
                    paths: &paths,
                    flags: ScopePersistFlags::new(false, true),
                    project_log: Some("project resource policy saved"),
                    project_package_log: Some("project package resource policy saved"),
                },
                |inner, target| {
                    match target {
                        ScopeTarget::Ephemeral => {}

                        ScopeTarget::Session { session_id } => {
                            inner.session.resource().apply(action, session_id, &key);
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
    use std::{path::PathBuf, time::Duration};

    use agent_sandbox_core::{
        ApprovalScope, DbusTarget, FileAccess, Policy, ProcessIds, ResolvedRequestContext,
        ResourceAccess, ResourceKind, RpcReply, SandboxPaths, Verdict, VerdictSource, load_policy,
    };

    use super::*;
    use crate::{
        store::decisions::DecisionAction,
        wire::{FilesystemScopeOp, ResourceScopeOp, ScopeWire},
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
    async fn once_filesystem_scope_applies_nothing() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        let omp = package_ctx(&home, &project, Some("omp"));

        let reply = store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: PathBuf::from("/once/file"),
                    access: FileAccess::Read,
                    scope: ApprovalScope::Once,
                    wire: ScopeWire::from_resolved(&omp, None),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let inner = store.inner.lock().await;

        assert!(
            inner.session.session_filesystem_allow.is_empty(),
            "the filesystem ephemeral arm is a deliberate no-op"
        );

        assert!(
            !project.join(".agent-sandbox/policy.json").exists()
                && !home.join(".config/agent-sandbox/policy.json").exists(),
            "a once filesystem approval must not persist anything"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn session_filesystem_deny_wins_over_approve() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        register_ui_session(&store, "sandbox-a");
        let omp = package_ctx(&home, &project, None);
        let omp_with_session = ResolvedRequestContext {
            sandbox_session_id: Some("sandbox-a".into()),
            ..omp
        };

        for action in [DecisionAction::Approve, DecisionAction::Deny] {
            let reply = store
                .apply_filesystem_scope(
                    FilesystemScopeOp {
                        path: PathBuf::from("/guarded/file"),
                        access: FileAccess::ReadWrite,
                        scope: ApprovalScope::Session,
                        wire: ScopeWire::from_resolved(
                            &omp_with_session,
                            omp_with_session.sandbox_session_id.clone(),
                        ),
                    },
                    action,
                )
                .await;

            assert!(matches!(reply, RpcReply::ScopeAction(_)));
        }

        let inner = store.inner.lock().await;
        let key = FilesystemRuleKey::new(PathBuf::from("/guarded/file"), FileAccess::ReadWrite);

        assert!(
            !inner
                .session
                .session_filesystem_allow
                .get("sandbox-a")
                .is_some_and(|bucket| bucket.contains(&key)),
            "the later deny must remove the earlier session allow"
        );

        assert!(
            inner
                .session
                .session_filesystem_deny
                .get("sandbox-a")
                .is_some_and(|bucket| bucket.contains(&key)),
            "the deny must land in the filesystem deny bucket"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn dbus_session_scope_applies_to_the_dbus_bucket() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        register_ui_session(&store, "sandbox-a");
        let omp = package_ctx(&home, &project, None);
        let omp_with_session = ResolvedRequestContext {
            sandbox_session_id: Some("sandbox-a".into()),
            ..omp
        };
        let target = DbusTarget::default();

        let reply = store
            .apply_dbus_scope(
                target.clone(),
                ApprovalScope::Session,
                ScopeWire::from_resolved(
                    &omp_with_session,
                    omp_with_session.sandbox_session_id.clone(),
                ),
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let inner = store.inner.lock().await;

        assert!(
            inner
                .session
                .session_dbus_allow
                .get("sandbox-a")
                .is_some_and(|bucket| bucket.contains(&target)),
            "the session approval must land in the dbus allow bucket"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn dbus_global_package_persists_home_extension() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        let omp = package_ctx(&home, &project, Some("omp"));
        let target = DbusTarget::default();

        let reply = store
            .apply_dbus_scope(
                target,
                ApprovalScope::GlobalPackage,
                ScopeWire::from_resolved(&omp, None),
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let ext = home.join(".config/agent-sandbox/packages/omp.json");
        let policy: Policy = load_policy(&ext, Some(&home), None);

        assert_eq!(
            policy.dbus.allow.len(),
            1,
            "the global package approval must persist one dbus rule to the home extension"
        );
    }

    #[tokio::test]
    async fn resource_session_scope_applies_to_the_resource_bucket() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        register_ui_session(&store, "sandbox-a");
        let omp = package_ctx(&home, &project, None);
        let omp_with_session = ResolvedRequestContext {
            sandbox_session_id: Some("sandbox-a".into()),
            ..omp
        };

        let reply = store
            .apply_resource_scope(
                ResourceScopeOp {
                    kind: ResourceKind::UnixSocket,
                    path: PathBuf::from("/run/user/1000/bus"),
                    access: ResourceAccess::default(),
                    scope: ApprovalScope::Session,
                    wire: ScopeWire::from_resolved(
                        &omp_with_session,
                        omp_with_session.sandbox_session_id.clone(),
                    ),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(reply, RpcReply::ScopeAction(_)));

        let inner = store.inner.lock().await;
        let key = ResourceRuleKey::new(
            ResourceKind::UnixSocket,
            "/run/user/1000/bus",
            ResourceAccess::default(),
        );

        assert!(
            inner
                .session
                .session_resource_allow
                .get("sandbox-a")
                .is_some_and(|bucket| bucket.contains(&key)),
            "the session approval must land in the resource allow bucket"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn resource_global_persists_user_policy() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let store = package_store(&dir);
        let omp = package_ctx(&home, &project, None);

        let reply = store
            .apply_resource_scope(
                ResourceScopeOp {
                    kind: ResourceKind::UnixSocket,
                    path: PathBuf::from("/run/user/1000/bus"),
                    access: ResourceAccess::default(),
                    scope: ApprovalScope::Global,
                    wire: ScopeWire::from_resolved(&omp, None),
                },
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
            policy.resources.allow.len(),
            1,
            "the global approval must persist one resource rule to the user policy"
        );
    }
}
