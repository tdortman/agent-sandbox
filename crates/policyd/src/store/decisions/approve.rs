//! Apply pending network or elevation decisions.

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, ElevateReply, FileAccess, FilesystemRule, NetworkRuleKey,
    RpcReply, ScopeActionReply, SudoRule, approval_host_patterns,
};

use crate::error::PolicydError;
use crate::store::ui_route::UiRoute;
use crate::wire::{NetworkScopeOp, PendingDecision, SudoScopeOp};

use super::super::types::{
    NetworkVerdictKey, Pending, PendingElevation, PendingFilesystem, PendingNetwork, PolicyStore,
};
use super::DecisionAction;

impl PolicyStore {
    pub async fn approve(&self, decision: PendingDecision) -> RpcReply {
        self.apply_pending_decision(decision, DecisionAction::Approve)
            .await
    }

    pub(crate) async fn apply_pending_decision(
        &self,
        decision: PendingDecision,
        action: DecisionAction,
    ) -> RpcReply {
        let decision = match self.take_pending_decision(decision).await {
            Ok(value) => value,
            Err(err) => return err,
        };
        match decision.pending {
            Pending::Network(net) => {
                self.apply_pending_network_decision(
                    net,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
            Pending::Elevation(elev) => {
                self.apply_pending_sudo_decision(
                    elev,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
            Pending::Filesystem(fs) => {
                self.apply_pending_filesystem_decision(
                    fs,
                    decision.wire,
                    decision.scope,
                    decision.target.as_ref(),
                    action,
                )
                .await
            }
        }
    }

    async fn apply_pending_network_decision(
        &self,
        net: PendingNetwork,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = net.id.clone();
        let resolved = match Self::resolve_pending_network_target(&net, scope, target) {
            Ok(value) => value,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .pending
                    .insert(pending_id.clone(), Pending::Network(net));
                return err.into();
            }
        };

        if action == DecisionAction::Approve && scope == ApprovalScope::Once {
            Self::audit(
                action.audit_verb(),
                Some(&resolved.host),
                Some(resolved.port),
                scope.as_str(),
            );
            self.finish_network(
                &pending_id,
                true,
                "once",
                Some(NetworkVerdictKey {
                    host: resolved.host.clone(),
                    port: resolved.port,
                }),
            )
            .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_network(
                resolved.host,
                resolved.port,
                scope,
                None,
            ));
        }

        let result = self
            .apply_network_scope(
                NetworkScopeOp {
                    host: resolved.host.clone(),
                    port: resolved.port,
                    scope,
                    wire: Self::scope_wire_for_pending_network(wire, &net),
                },
                action,
            )
            .await;

        if result.scope_succeeded() {
            match action {
                DecisionAction::Approve => {
                    let source = result.scope_label().unwrap_or(scope.as_str());
                    self.finish_network(
                        &pending_id,
                        true,
                        source,
                        Some(NetworkVerdictKey {
                            host: resolved.host.clone(),
                            port: resolved.port,
                        }),
                    )
                    .await;
                }
                DecisionAction::Deny => {
                    self.finish_network(
                        &pending_id,
                        false,
                        "denied",
                        Some(NetworkVerdictKey {
                            host: resolved.host.clone(),
                            port: resolved.port,
                        }),
                    )
                    .await;
                }
            }
        } else if action == DecisionAction::Approve {
            self.finish_network(
                &pending_id,
                false,
                "blocked",
                Some(NetworkVerdictKey {
                    host: resolved.host.clone(),
                    port: resolved.port,
                }),
            )
            .await;
        } else {
            self.inner
                .lock()
                .await
                .pending
                .insert(pending_id, Pending::Network(net));
        }
        result
    }

    async fn apply_pending_sudo_decision(
        &self,
        elev: PendingElevation,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = elev.id.clone();
        let argv = match Self::resolve_pending_sudo_target(&elev, scope, target) {
            Ok(value) => value,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .pending
                    .insert(pending_id.clone(), Pending::Elevation(elev));
                return err.into();
            }
        };
        let scope_wire = Self::scope_wire_for_pending_elevation(wire, &elev);

        if action == DecisionAction::Deny {
            if scope == ApprovalScope::Once {
                let detail = format!("id={pending_id} argv={argv:?}");
                Self::audit(action.audit_verb(), None, None, &detail);
                self.finish_elevation(&pending_id, ElevateReply::denied())
                    .await;
                return RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope, None));
            }
            let result = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv: argv.clone(),
                        scope,
                        wire: scope_wire,
                    },
                    action,
                )
                .await;
            if result.scope_succeeded() {
                self.finish_elevation(&pending_id, ElevateReply::denied())
                    .await;
            } else {
                self.inner
                    .lock()
                    .await
                    .pending
                    .insert(pending_id, Pending::Elevation(elev));
            }
            return result;
        }

        let saved_path = if scope == ApprovalScope::Once {
            None
        } else {
            let scope_result = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv: argv.clone(),
                        scope,
                        wire: scope_wire.clone(),
                    },
                    action,
                )
                .await;
            if !scope_result.scope_succeeded() {
                self.inner
                    .lock()
                    .await
                    .pending
                    .insert(pending_id, Pending::Elevation(elev));
                return scope_result;
            }
            scope_result.scope_path()
        };

        let detail = format!("id={pending_id} argv={argv:?}");
        Self::audit(action.audit_verb(), None, None, &detail);
        let elevation = self
            .exec_elevation(
                &argv,
                elev.cwd.as_deref().or(scope_wire.paths.cwd()),
                elev.home.as_deref().or(scope_wire.paths.home()),
            )
            .await;
        self.finish_elevation(&pending_id, elevation).await;
        RpcReply::ScopeAction(ScopeActionReply::ok_elevation_approve(scope, saved_path))
    }

    async fn apply_pending_filesystem_decision(
        &self,
        fs: PendingFilesystem,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = fs.id.clone();
        let path = match Self::resolve_pending_filesystem_target(&fs, scope, target) {
            Ok(value) => value,
            Err(err) => {
                self.inner
                    .lock()
                    .await
                    .pending
                    .insert(pending_id.clone(), Pending::Filesystem(fs));
                return err.into();
            }
        };

        if action == DecisionAction::Approve && scope == ApprovalScope::Once {
            let detail = format!("id={pending_id} path={path} access={:?}", fs.access);
            Self::audit(action.audit_verb(), None, None, &detail);
            self.finish_filesystem(&pending_id, path.clone(), fs.access, true, "once")
                .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
                path, fs.access, scope, None,
            ));
        }

        let scope_wire = self
            .filesystem_scope_wire_for_pending(wire, &fs, scope)
            .await;

        if action == DecisionAction::Deny && scope == ApprovalScope::Once {
            let detail = format!("id={pending_id} path={path}");
            Self::audit(action.audit_verb(), None, None, &detail);
            self.finish_filesystem(&pending_id, path.clone(), fs.access, false, "denied")
                .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_filesystem(
                path, fs.access, scope, None,
            ));
        }

        let result = self
            .apply_filesystem_scope(
                crate::wire::FilesystemScopeOp {
                    path: path.clone(),
                    access: fs.access,
                    scope,
                    wire: scope_wire,
                },
                action,
            )
            .await;

        if result.scope_succeeded() {
            let source = result.scope_label().unwrap_or(scope.as_str());
            self.finish_filesystem(
                &pending_id,
                path.clone(),
                fs.access,
                action == DecisionAction::Approve,
                source,
            )
            .await;
        } else if action == DecisionAction::Approve {
            self.finish_filesystem(&pending_id, path, fs.access, false, "blocked")
                .await;
        } else {
            self.inner
                .lock()
                .await
                .pending
                .insert(pending_id, Pending::Filesystem(fs));
        }
        result
    }

    async fn filesystem_scope_wire_for_pending(
        &self,
        wire: crate::wire::ScopeWire,
        fs: &PendingFilesystem,
        scope: ApprovalScope,
    ) -> crate::wire::ScopeWire {
        let mut scope_wire = Self::scope_wire_for_pending_filesystem(wire, fs);
        if scope != ApprovalScope::Session {
            return scope_wire;
        }

        let route = UiRoute::new(fs.cwd.clone(), fs.project_root.clone())
            .with_sandbox_session(fs.sandbox_session_id.clone());
        let session_ids = self.filesystem_session_ids_for_route(&route).await;
        if scope_wire
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_ids.contains(session_id))
        {
            return scope_wire;
        }
        if let Some(session_id) = session_ids.into_iter().min() {
            scope_wire.session_id = Some(session_id);
        }
        scope_wire
    }

    fn resolve_pending_filesystem_target(
        pending: &PendingFilesystem,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
    ) -> Result<String, PolicydError> {
        let pending_path = &pending.path;
        let path = match target {
            None => pending_path.clone(),
            Some(ApprovalTarget::FilesystemPath { path }) => path.clone(),
            Some(_) => return Err(PolicydError::InvalidDecisionTarget),
        };

        // For Once scope, only exact match is allowed.
        if scope == ApprovalScope::Once {
            if path != *pending_path {
                return Err(PolicydError::InvalidDecisionTarget);
            }
            return Ok(path);
        }

        // For broader scopes, accept exact match or ancestor path (with boundary).
        if path == *pending_path {
            return Ok(path);
        }

        if FilesystemRule::new(path.clone(), FileAccess::Read, "").path_matches(pending_path) {
            return Ok(path);
        }

        Err(PolicydError::InvalidDecisionTarget)
    }

    fn resolve_pending_network_target(
        pending: &PendingNetwork,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
    ) -> Result<NetworkRuleKey, PolicydError> {
        let pending_host = &pending.host;
        let pending_port = pending.port;
        let host = match target {
            None => pending_host.clone(),
            Some(ApprovalTarget::NetworkHost { host }) => host.clone(),
            Some(_) => {
                return Err(PolicydError::InvalidDecisionTarget);
            }
        };
        let valid_host = approval_host_patterns(pending_host)
            .into_iter()
            .any(|candidate| candidate == host);
        if !valid_host {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        if scope == ApprovalScope::Once && host != *pending_host {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        Ok(NetworkRuleKey::new(host, pending_port))
    }

    fn resolve_pending_sudo_target(
        pending: &PendingElevation,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
    ) -> Result<Vec<String>, PolicydError> {
        let pending_argv = &pending.argv;
        let argv = match target {
            None => pending_argv.clone(),
            Some(ApprovalTarget::SudoCommand { argv }) => argv.clone(),
            Some(_) => {
                return Err(PolicydError::InvalidDecisionTarget);
            }
        };
        let valid_argv = SudoRule::approval_prefixes(pending_argv)
            .into_iter()
            .any(|candidate| candidate == argv);
        if !valid_argv {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        if scope == ApprovalScope::Once && argv != *pending_argv {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        Ok(argv)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use agent_sandbox_core::{
        ApprovalScope, ApprovalTarget, FileAccess, NetworkRuleKey, ProcessIds, SandboxPaths,
    };
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    use crate::store::types::{UiClient, UiSessionContext};
    use crate::store::{
        Pending, PendingElevation, PendingFilesystem, PendingNetwork, PolicyStore, PolicydArgs,
    };
    use crate::wire::{MergeContext, PendingDecision, ScopeWire};

    #[test]
    fn network_target_accepts_parent_domain_patterns() {
        let pending = Pending::Network(PendingNetwork {
            id: "p1".into(),
            created_at: 0.0,
            host: "foo.bar.baz.com".into(),
            port: 443,
            scheme: "https".into(),
            url: "https://foo.bar.baz.com".into(),
            aliases: Vec::new(),
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::NetworkHost {
            host: "*.baz.com".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_network_target(
                match &pending {
                    Pending::Network(net) => net,
                    _ => panic!("expected Network"),
                },
                ApprovalScope::Project,
                Some(&target),
            )
            .expect("resolve pending network target"),
            NetworkRuleKey::new("*.baz.com", 443)
        );
    }

    #[test]
    fn sudo_target_accepts_command_prefixes() {
        let pending = Pending::Elevation(PendingElevation {
            id: "p1".into(),
            created_at: 0.0,
            argv: vec!["foo".into(), "bar".into(), "baz".into()],
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::SudoCommand {
            argv: vec!["foo".into(), "bar".into()],
        };
        assert_eq!(
            PolicyStore::resolve_pending_sudo_target(
                match &pending {
                    Pending::Elevation(elev) => elev,
                    _ => panic!("expected Elevation"),
                },
                ApprovalScope::Session,
                Some(&target),
            )
            .expect("resolve pending sudo target"),
            vec!["foo".to_string(), "bar".to_string()]
        );
    }

    #[test]
    fn filesystem_target_rejects_mismatch() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/projects/foo/src/main.rs".into(),
            access: FileAccess::Read,
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::FilesystemPath {
            path: "/other/path".into(),
        };
        assert!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Session,
                Some(&target),
            )
            .is_err(),
            "unrelated path should be rejected"
        );
    }

    #[test]
    fn filesystem_target_accepts_ancestor_path() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/projects/foo/src/main.rs".into(),
            access: FileAccess::Read,
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        let target = ApprovalTarget::FilesystemPath {
            path: "/home/user/projects/foo".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Session,
                Some(&target),
            )
            .expect("resolve pending filesystem target"),
            "/home/user/projects/foo"
        );
    }

    #[test]
    fn filesystem_target_exact_once_scope() {
        let pending = Pending::Filesystem(PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/file.txt".into(),
            access: FileAccess::Read,
            cwd: None,
            home: None,
            project_root: None,
            sandbox_session_id: None,
        });
        // Once scope: exact match is valid
        assert!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Once,
                None,
            )
            .is_ok()
        );

        // Ancestor path with Once scope should be rejected
        let ancestor_target = ApprovalTarget::FilesystemPath {
            path: "/home/user".into(),
        };
        assert!(
            PolicyStore::resolve_pending_filesystem_target(
                match &pending {
                    Pending::Filesystem(fs) => fs,
                    _ => panic!("expected Filesystem"),
                },
                ApprovalScope::Once,
                Some(&ancestor_target),
            )
            .is_err(),
            "ancestor target should be rejected for Once scope"
        );
    }

    fn test_store(name: &str) -> PolicyStore {
        let dir = std::env::temp_dir().join(format!(
            "agent-sandbox-fs-session-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test store dir");
        PolicyStore::new(PolicydArgs {
            host_socket: dir.join("policy.sock"),
            sandbox_socket: dir.join("sandbox-policy.sock"),
            declarative: dir.join("declarative.json"),
            export_json: dir.join("exported-policy.json"),
            export_nix: None,
            approval_timeout: Duration::from_mins(1),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        })
    }

    fn writer() -> Arc<Mutex<tokio::net::unix::OwnedWriteHalf>> {
        Arc::new(Mutex::new(
            UnixStream::pair()
                .expect("unix stream pair")
                .0
                .into_split()
                .1,
        ))
    }

    fn ui_session_context() -> UiSessionContext {
        UiSessionContext {
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: None,
        }
    }

    async fn add_ui_sessions(store: &PolicyStore) {
        let mut inner = store.inner.lock().await;
        inner.ui_clients.insert(
            1,
            UiClient {
                session_id: "ui-session".into(),
                writer: writer(),
            },
        );
        inner
            .ui_context_by_session
            .insert("ui-session".into(), ui_session_context());
    }

    fn pending_filesystem() -> PendingFilesystem {
        PendingFilesystem {
            id: "fs1".into(),
            created_at: 0.0,
            path: "/home/user/projects/foo/src/main.rs".into(),
            access: FileAccess::Read,
            cwd: Some("/repo".into()),
            home: Some("/home/user".into()),
            project_root: Some("/repo".into()),
            sandbox_session_id: None,
        }
    }

    fn scope_wire(session_id: &str) -> ScopeWire {
        ScopeWire {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            session_id: Some(session_id.into()),
            owner_uid: Some(1000),
            sandbox_session_id: None,
        }
    }

    async fn approve_filesystem_session(
        store: &PolicyStore,
        pending: PendingFilesystem,
        submitting_session_id: &str,
    ) {
        let pending_id = pending.id.clone();
        store
            .inner
            .lock()
            .await
            .pending
            .insert(pending_id.clone(), Pending::Filesystem(pending));
        let reply = store
            .approve(PendingDecision {
                pending_id,
                scope: ApprovalScope::Session,
                target: Some(ApprovalTarget::FilesystemPath {
                    path: "/home/user/projects/foo".into(),
                }),
                wire: scope_wire(submitting_session_id),
            })
            .await;
        assert!(reply.scope_succeeded());
    }

    fn merge_context(pid: Option<u32>) -> MergeContext {
        MergeContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::from_options(pid, None),
            sandbox_session_id: None,
        }
    }

    #[tokio::test]
    async fn filesystem_session_approval_binds_to_submitting_session() {
        let store = test_store("ui-session");
        add_ui_sessions(&store).await;
        approve_filesystem_session(&store, pending_filesystem(), "ui-session").await;

        {
            let inner = store.inner.lock().await;
            assert!(inner.session_filesystem_allow.contains_key("ui-session"));
        }

        assert!(
            store
                .session_filesystem_allowed(
                    "/home/user/projects/foo/src/lib.rs",
                    FileAccess::Read,
                    merge_context(None),
                )
                .await
        );
    }

    #[tokio::test]
    async fn filesystem_session_approval_keeps_standalone_session() {
        let store = test_store("standalone");
        add_ui_sessions(&store).await;
        approve_filesystem_session(&store, pending_filesystem(), "ui-session").await;

        {
            let inner = store.inner.lock().await;
            assert!(inner.session_filesystem_allow.contains_key("ui-session"));
        }

        assert!(
            store
                .session_filesystem_allowed(
                    "/home/user/projects/foo/src/lib.rs",
                    FileAccess::Read,
                    merge_context(None),
                )
                .await
        );
    }

    #[tokio::test]
    async fn session_network_rules_do_not_cross_sandbox_sessions_in_same_project() {
        let store = test_store("sandbox-session-isolation");
        {
            let mut inner = store.inner.lock().await;
            for (client_id, ui_session_id, sandbox_session_id) in
                [(10_u64, "ui-a", "sandbox-a"), (11_u64, "ui-b", "sandbox-b")]
            {
                inner.ui_clients.insert(
                    client_id,
                    UiClient {
                        session_id: ui_session_id.into(),
                        writer: writer(),
                    },
                );
                inner.ui_context_by_session.insert(
                    ui_session_id.into(),
                    UiSessionContext {
                        cwd: Some("/repo".into()),
                        home: Some("/home/user".into()),
                        project_root: Some("/repo".into()),
                        sandbox_session_id: Some(sandbox_session_id.into()),
                    },
                );
            }
            inner
                .session_allow
                .entry("ui-a".into())
                .or_default()
                .insert(NetworkRuleKey::new("api.example.com", 443));
        }

        assert!(
            store
                .session_allowed(
                    "api.example.com",
                    443,
                    MergeContext {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        ids: ProcessIds::default(),
                        sandbox_session_id: Some("sandbox-a".into()),
                    },
                )
                .await
        );
        assert!(
            !store
                .session_allowed(
                    "api.example.com",
                    443,
                    MergeContext {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        ids: ProcessIds::default(),
                        sandbox_session_id: Some("sandbox-b".into()),
                    },
                )
                .await
        );
    }
}
