use std::path::Path;

use agent_sandbox_core::{
    ApprovalScope, FileAccess, ResourceAccess, ResourceKind, Verdict, VerdictSource, normalize_host,
};

use agent_sandbox_core::ResolvedRequestContext;

use super::PolicyStore;
use super::access::{filesystem_rules_match_allow, is_sandbox_infrastructure_path};
pub struct PolicyEvaluation<'a> {
    store: &'a PolicyStore,
    ctx: ResolvedRequestContext,
}

impl PolicyStore {
    pub(crate) fn policy_evaluation(&self, ctx: &ResolvedRequestContext) -> PolicyEvaluation<'_> {
        PolicyEvaluation {
            store: self,
            ctx: ctx.clone(),
        }
    }
}

impl PolicyEvaluation<'_> {
    pub(crate) async fn network_verdict(
        &self,
        host: &str,
        port: u16,
        consume_once: bool,
    ) -> Option<Verdict> {
        let host = normalize_host(host);
        if self.store.policy_denied(&host, port, &self.ctx) {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.store.session_denied(&host, port, &self.ctx).await {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self.store.once_allowed(&host, port, consume_once).await {
            return Some(Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once)));
        }
        if self.store.session_allowed(&host, port, &self.ctx).await {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        let merged = self.store.merged_for(&self.ctx);
        for rule in &merged.network.direct.allow {
            if PolicyStore::host_matches(&rule.host, &host) && rule.port == port {
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

    pub(crate) async fn network_allowed(&self, host: &str, port: u16, consume_once: bool) -> bool {
        self.network_verdict(host, port, consume_once)
            .await
            .is_some_and(|verdict| verdict.allowed)
    }

    pub(crate) async fn filesystem_allow_source(
        &self,
        path: &Path,
        access: FileAccess,
    ) -> Option<Verdict> {
        let access = agent_sandbox_core::normalize_directory_traverse_access(path, access);
        if is_sandbox_infrastructure_path(path) {
            return Some(Verdict::allowed(VerdictSource::Infrastructure));
        }
        let merged = self.store.merged_for_worker(&self.ctx);
        let project_root = self.ctx.paths.project_root();
        let home = self.ctx.paths.home();
        let path_denied = merged
            .filesystem
            .deny
            .iter()
            .any(|rule| rule.matches(path, access, project_root));
        if path_denied {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        let fingerprint = PolicyStore::deny_fingerprint(&merged, home, project_root);
        if self
            .store
            .deny_inode_denied(path, access, &fingerprint)
            .await
        {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self
            .store
            .session_filesystem_denied(path, access, &self.ctx)
            .await
        {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self
            .store
            .session_filesystem_allowed(path, access, &self.ctx)
            .await
        {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        if self
            .store
            .session_filesystem_allowed_by_inode(path, access, &self.ctx)
            .await
        {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        if self
            .store
            .static_filesystem_allowed(path, access, &self.ctx)
            .await
        {
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
    ) -> Option<Verdict> {
        if self
            .store
            .resource_policy_denied(kind, path, access, &self.ctx)
            .await
        {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self
            .store
            .session_resource_denied(kind, path, access, &self.ctx)
            .await
        {
            return Some(Verdict::denied(VerdictSource::policy()));
        }
        if self
            .store
            .session_resource_allowed(kind, path, access, &self.ctx)
            .await
        {
            return Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session,
            )));
        }
        if self
            .store
            .resource_policy_allowed(kind, path, access, &self.ctx)
        {
            return Some(Verdict::allowed(VerdictSource::policy()));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use agent_sandbox_core::{
        NetworkRuleKey, Policy, ProcessIds, ResourceRule, ResourceRuleKey, SandboxPaths,
        atomic_write_policy,
    };
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    use super::super::types::{PolicydArgs, UiClient, UiSessionContext};
    use super::*;

    fn test_store(dir: &tempfile::TempDir) -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: dir.path().join("sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: false,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        })
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
        inner.ui_clients.insert(
            7,
            UiClient {
                session_id: session_id.into(),
                writer: Arc::new(Mutex::new(writer)),
            },
        );
        inner.ui_context_by_session.insert(
            session_id.into(),
            UiSessionContext {
                cwd: Some(cwd),
                home: Some(home),
                project_root: Some(project_root),
                ..Default::default()
            },
        );
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
            store
                .policy_evaluation(&ctx)
                .network_verdict("example.com", 443, false)
                .await,
            Some(Verdict::denied(VerdictSource::policy()))
        );
        assert!(
            !store
                .policy_evaluation(&ctx)
                .network_allowed("example.com", 443, true)
                .await
        );
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
        policy
            .network
            .direct
            .allow
            .push(agent_sandbox_core::NetworkRule::new(
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
            store
                .policy_evaluation(&ctx)
                .network_verdict("example.com", 443, false)
                .await,
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
            ResourceAccess::OpenRead,
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
                    ResourceAccess::OpenRead,
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
                .policy_evaluation(&ctx)
                .resource_allow_source(
                    ResourceKind::Device,
                    &device_path,
                    ResourceAccess::OpenRead,
                )
                .await,
            Some(Verdict::allowed(VerdictSource::Scope(ApprovalScope::Session)))
        );
    }
}
