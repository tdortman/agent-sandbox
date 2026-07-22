use std::path::Path;

use agent_sandbox_core::{
    ApprovalScope, DbusTarget, FileAccess, ResolvedRequestContext, ResourceAccess, ResourceKind,
    Verdict, VerdictSource, normalize_directory_traverse_access, normalize_host,
};

use super::{
    PolicyStore,
    access::{filesystem_rules_match_allow, is_sandbox_infrastructure_path},
};

impl PolicyStore {
    pub(crate) async fn network_verdict(
        &self,
        host: &str,
        port: u16,
        ctx: &ResolvedRequestContext,
        consume_once: bool,
    ) -> Option<Verdict> {
        let host = normalize_host(host);
        if self.policy_denied(&host, port, ctx) {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.session_denied(&host, port, ctx).await {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.once_allowed(&host, port, consume_once).await {
            return Some(Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once)));
        }
        if self.session_allowed(&host, port, ctx).await {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        let merged = self.merged_for(ctx);
        for rule in &merged.network.direct.allow {
            if Self::host_matches(&rule.host, &host) && rule.port == port {
                if let Some(comment) = &rule.comment
                    && !comment.is_empty()
                {
                    return Some(Verdict::allowed(VerdictSource::policy_with_comment(
                        comment,
                    )));
                }
                return Some(Verdict::allowed(VerdictSource::policy()));
            }
        }
        None
    }

    pub(crate) async fn network_allowed(
        &self,
        host: &str,
        port: u16,
        ctx: &ResolvedRequestContext,
        consume_once: bool,
    ) -> bool {
        self.network_verdict(host, port, ctx, consume_once)
            .await
            .is_some_and(|verdict| verdict.allowed)
    }

    pub(crate) async fn filesystem_allow_source(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let access = normalize_directory_traverse_access(path, access);
        if is_sandbox_infrastructure_path(path) {
            return Some(Verdict::allowed(VerdictSource::Infrastructure));
        }
        let merged = self.merged_for_worker(ctx);
        let project_root = ctx.paths.project_root();
        let home = ctx.paths.home();
        let path_denied = merged
            .filesystem
            .deny
            .iter()
            .any(|rule| rule.matches(path, access, project_root));
        if path_denied {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        let fingerprint = Self::deny_fingerprint(&merged, home, project_root);
        if self.deny_inode_denied(path, access, &fingerprint).await {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.session_filesystem_denied(path, access, ctx).await {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.session_filesystem_allowed(path, access, ctx).await {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        if self
            .session_filesystem_allowed_by_inode(path, access, ctx)
            .await
        {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        if self.static_filesystem_allowed(path, access, ctx).await {
            return Some(Verdict::allowed(VerdictSource::Static));
        }
        if filesystem_rules_match_allow(&merged.filesystem.allow, path, access, project_root) {
            return Some(Verdict::allowed(VerdictSource::policy()));
        }
        None
    }

    pub(crate) async fn resource_allow_source(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        if self.resource_policy_denied(kind, path, access, ctx).await {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.session_resource_denied(kind, path, access, ctx).await {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.session_resource_allowed(kind, path, access, ctx).await {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        if self.resource_policy_allowed(kind, path, access, ctx) {
            return Some(Verdict::allowed(VerdictSource::policy()));
        }
        None
    }

    pub(crate) fn dbus_verdict(
        &self,
        target: &DbusTarget,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let merged = self.merged_for(ctx);
        if merged.dbus.deny.iter().any(|rule| rule.matches(target)) {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        merged
            .dbus
            .allow
            .iter()
            .find(|rule| rule.matches(target))
            .map(|rule| {
                rule.comment.as_deref().map_or_else(
                    || Verdict::allowed(VerdictSource::policy()),
                    |comment| Verdict::allowed(VerdictSource::policy_with_comment(comment)),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

    use agent_sandbox_core::{
        DbusMessageKind, DbusRule, DbusTarget, DeviceAccess, NetworkRule, NetworkRuleKey, Policy,
        ProcessIds, ResourceRule, ResourceRuleKey, SandboxPaths, atomic_write_policy,
    };
    use tokio::{net::UnixStream, sync::Mutex};

    use super::{
        super::types::{UiClient, UiSessionContext},
        *,
    };

    fn test_store(dir: &tempfile::TempDir) -> PolicyStore {
        PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            false,
        ))
    }

    async fn register_ui_session(
        store: &PolicyStore,
        session_id: &str,
        cwd: PathBuf,
        home: PathBuf,
        project_root: PathBuf,
    ) {
        let (a, _b) = UnixStream::pair().expect("unix stream pair");
        let (_, writer) = a.into_split();
        let mut inner = store.inner.lock().await;
        inner.ui_clients.insert(7, UiClient {
            session_id: session_id.into(),
            writer: Arc::new(Mutex::new(writer)),
        });
        inner
            .ui_context_by_session
            .insert(session_id.into(), UiSessionContext {
                cwd: Some(cwd),
                home: Some(home),
                project_root: Some(project_root),
                ..Default::default()
            });
    }

    #[tokio::test]
    async fn network_deny_source_beats_once_and_session_allow() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home-user");
        let project_root = dir.path().join("repo");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&project_root).expect("create project root");
        let store = test_store(&dir);
        register_ui_session(
            &store,
            "ui-session",
            project_root.clone(),
            home.clone(),
            project_root.clone(),
        )
        .await;
        {
            let mut inner = store.inner.lock().await;
            inner
                .once_allow
                .insert(NetworkRuleKey::new("example.com", 443));
            inner.session_allow.insert(
                "ui-session".into(),
                HashSet::from([NetworkRuleKey::new("example.com", 443)]),
            );
            inner.session_deny.insert(
                "ui-session".into(),
                HashSet::from([NetworkRuleKey::new("example.com", 443)]),
            );
        }

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
        };

        assert_eq!(
            store.network_verdict("example.com", 443, &ctx, false).await,
            Some(Verdict::denied(VerdictSource::policy()))
        );
        assert!(!store.network_allowed("example.com", 443, &ctx, true).await);
    }

    #[tokio::test]
    async fn network_policy_comment_survives_as_allow_comment_source() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home-user");
        let project_root = dir.path().join("repo");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        std::fs::create_dir_all(&project_root).expect("create project root");

        let mut policy = Policy::default();
        policy.network.direct.allow.push(NetworkRule::new(
            "example.com",
            443,
            "trusted policy file",
        ));
        atomic_write_policy(&policy_dir.join("policy.json"), &policy, None, None, None)
            .expect("write policy");

        let store = test_store(&dir);
        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
        };

        assert_eq!(
            store.network_verdict("example.com", 443, &ctx, false).await,
            Some(Verdict::allowed(VerdictSource::policy_with_comment(
                "trusted policy file"
            )))
        );
    }

    #[tokio::test]
    async fn resource_session_source_beats_policy_allow() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home-user");
        let project_root = dir.path().join("repo");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        std::fs::create_dir_all(&project_root).expect("create project root");
        let device_path = dir.path().join("dev/fd/3");
        std::fs::create_dir_all(device_path.parent().expect("device parent")).expect("create dev");
        std::fs::write(&device_path, "fd").expect("write device");

        let mut policy = Policy::default();
        policy.resources.allow.push(ResourceRule::new(
            ResourceKind::Device,
            device_path.clone(),
            ResourceAccess::Device(DeviceAccess::Read),
            "policy allow",
        ));
        atomic_write_policy(&policy_dir.join("policy.json"), &policy, None, None, None)
            .expect("write policy");

        let store = test_store(&dir);
        register_ui_session(
            &store,
            "ui-session",
            project_root.clone(),
            home.clone(),
            project_root.clone(),
        )
        .await;
        {
            let mut inner = store.inner.lock().await;
            inner.session_resource_allow.insert(
                "ui-session".into(),
                HashSet::from([ResourceRuleKey::new(
                    ResourceKind::Device,
                    device_path.clone(),
                    ResourceAccess::Device(DeviceAccess::Read),
                )]),
            );
        }

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
        };

        assert_eq!(
            store
                .resource_allow_source(
                    ResourceKind::Device,
                    &device_path,
                    ResourceAccess::Device(DeviceAccess::Read),
                    &ctx,
                )
                .await,
            Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session
            )))
        );
    }
    #[tokio::test]
    async fn dbus_policy_matches_structured_target() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home-user");
        let project_root = dir.path().join("repo");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        std::fs::create_dir_all(&project_root).expect("create project root");
        let mut policy = Policy::default();
        policy.dbus.allow.push(DbusRule::new(
            DbusTarget::session(
                "org.example.Service",
                "/org/example/Object",
                "org.example.Interface",
                "Read",
                DbusMessageKind::MethodCall,
                "s",
                Vec::new(),
            ),
            "trusted D-Bus method",
        ));
        atomic_write_policy(&policy_dir.join("policy.json"), &policy, None, None, None)
            .expect("write policy");
        let store = test_store(&dir);
        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
        };
        let target = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );
        assert_eq!(
            store.dbus_verdict(&target, &ctx),
            Some(Verdict::allowed(VerdictSource::policy_with_comment(
                "trusted D-Bus method"
            )))
        );
    }
}
