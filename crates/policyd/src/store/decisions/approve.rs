//! Tests of decisions on pending approvals, applied through the store.

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use agent_sandbox_core::{
        ApprovalScope, ApprovalTarget, DbusMessageKind, DbusTarget, FileAccess, NetworkRuleKey,
        PendingSummary, ProcessIds, ResolvedRequestContext, ResourceAccess, ResourceKind, RpcReply,
        SandboxPaths, ScopeActionReply, SocketAccess, Verdict, VerdictSource, load_policy,
    };
    use tokio::{net::UnixStream, sync::Mutex};

    use crate::{
        store::{
            DecisionAction, Pending, PendingElevation, PendingFilesystem, PendingResource,
            PolicyStore,
            types::{PendingDbus, UiClient, UiSessionContext},
        },
        wire::{PendingDecision, ScopeWire},
    };

    fn pending_context(
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        sandbox_session_id: Option<&str>,
    ) -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(cwd, home, project_root),
            ids: ProcessIds::default(),
            sandbox_session_id: sandbox_session_id.map(str::to_owned),
            package: None,
        }
    }

    #[tokio::test]
    async fn decision_target_must_cover_the_pending_request() {
        let store = test_store("target-must-cover").await;
        add_ui_sessions(&store).await;

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert("fs1".into(), Pending::Filesystem(pending_filesystem()));

        let decide = |scope, path: &str| {
            store.apply_pending_decision(
                PendingDecision {
                    pending_id: "fs1".into(),
                    scope,
                    target: Some(ApprovalTarget::FilesystemPath { path: path.into() }),
                    wire: scope_wire("ui-session"),
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
        };

        let unrelated = decide(ApprovalScope::Session, "/other/path").await;

        assert!(
            !unrelated.scope_succeeded(),
            "a path that does not cover the request must be rejected"
        );

        let broad_once = decide(ApprovalScope::Once, "/home/user/projects/foo").await;

        assert!(
            !broad_once.scope_succeeded(),
            "a once decision must name the requested path itself"
        );

        assert!(
            store.inner.lock().await.pending.pending.contains_key("fs1"),
            "a rejected decision leaves the pending queued"
        );

        let ancestor = decide(ApprovalScope::Session, "/home/user/projects/foo").await;

        assert!(
            ancestor.scope_succeeded(),
            "an ancestor of the requested path covers the request"
        );

        assert!(store.inner.lock().await.pending.pending.is_empty());
    }

    #[tokio::test]
    async fn global_git_approval_works_when_pending_lacks_project_root() {
        let store = test_store("global-git-wire-root").await;

        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-global-git-wire-{}",
            std::process::id()
        ));

        let project_root = home.join("dotfiles");
        std::fs::create_dir_all(&home).expect("create test home");
        std::fs::create_dir_all(project_root.join(".git")).expect("create git dir");

        let pending = PendingFilesystem {
            id: "fs-git-config-wire".into(),
            created_at: 0.0,
            path: project_root.join(".git/config"),
            access: FileAccess::ReadWrite,
            ctx: pending_context(Some(project_root.clone()), Some(home.clone()), None, None),
        };

        let pending_id = pending.id.clone();

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert(pending.id.clone(), Pending::Filesystem(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Global,
                    target: Some(ApprovalTarget::FilesystemPath {
                        path: PathBuf::from("./.git"),
                    }),
                    wire: ScopeWire {
                        paths: SandboxPaths::new(
                            project_root.clone(),
                            home.clone(),
                            project_root.clone(),
                        ),
                        session_id: None,
                        owner_uid: Some(1000),
                        sandbox_session_id: None,
                        comment: None,
                        package: None,
                    },
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "global ./.git approval should succeed via wire project_root, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn scoped_filesystem_deny_completes_pending_with_serializable_reply() {
        // Regression: a scoped deny used to finish the pending waiter with
        // `VerdictSource::Scope(scope)` on a denied verdict. That source has
        // no wire encoding for `allowed = false`, so the policyd server
        // dropped the reply and the sandboxed open hung until fsmon timed
        // out. The deny verdict must reach the waiter and stay serializable.
        let store = test_store("scoped-fs-deny").await;

        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        std::fs::create_dir_all(&project).expect("create project dir");
        let pending_id = "fs-scoped-deny".to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();

        {
            let mut inner = store.inner.lock().await;

            let pending = Pending::Filesystem(PendingFilesystem {
                id: pending_id.clone(),
                created_at: 0.0,
                path: PathBuf::from("/etc/nextdns.conf"),
                access: FileAccess::Read,
                ctx: pending_context(
                    Some(project.clone()),
                    Some(home.clone()),
                    Some(project.clone()),
                    None,
                ),
            });
            inner
                .pending
                .pending
                .insert(pending.id().to_owned(), pending);

            inner
                .pending
                .filesystem_futures
                .insert(pending_id.clone(), vec![tx]);
        }

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id: pending_id.clone(),
                    scope: ApprovalScope::Project,
                    target: None,
                    wire: ScopeWire {
                        paths: SandboxPaths::new(&project, &home, &project),
                        session_id: None,
                        owner_uid: Some(1000),
                        sandbox_session_id: None,
                        comment: None,
                        package: None,
                    },
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Deny,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "scoped filesystem deny should succeed, got: {reply:?}"
        );

        let check = rx.await.expect("pending waiter must receive the verdict");

        assert!(
            !check.verdict.allowed,
            "scoped deny must deny the pending open"
        );

        let line = serde_json::to_string(&RpcReply::FilesystemCheck(check))
            .expect("deny verdict must be wire-serializable");

        let decoded: RpcReply = serde_json::from_str(&line).expect("deny verdict must round-trip");

        assert!(
            matches!(decoded, RpcReply::FilesystemCheck(decoded) if !decoded.verdict.allowed),
            "round-tripped deny verdict must stay denied"
        );
    }

    #[tokio::test]
    async fn global_filesystem_git_dir_persists_project_relative_path() {
        let store = test_store("global-git-dir").await;

        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-global-git-{}",
            std::process::id()
        ));

        let project_root = home.join("dotfiles");
        std::fs::create_dir_all(&home).expect("create test home");
        std::fs::create_dir_all(project_root.join(".git")).expect("create git dir");

        let pending = PendingFilesystem {
            id: "fs-git-config".into(),
            created_at: 0.0,
            path: project_root.join(".git/config"),
            access: FileAccess::ReadWrite,
            ctx: pending_context(
                Some(project_root.clone()),
                Some(home.clone()),
                Some(project_root.clone()),
                None,
            ),
        };

        let pending_id = pending.id.clone();

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert(pending.id.clone(), Pending::Filesystem(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Global,
                    target: Some(ApprovalTarget::FilesystemPath {
                        path: PathBuf::from("./.git"),
                    }),
                    wire: ScopeWire {
                        paths: SandboxPaths::new(
                            project_root.clone(),
                            home.clone(),
                            project_root.clone(),
                        ),
                        session_id: None,
                        owner_uid: Some(1000),
                        sandbox_session_id: None,
                        comment: None,
                        package: None,
                    },
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "global filesystem approval should succeed, got {reply:?}"
        );

        let policy_path = home.join(".config/agent-sandbox/policy.json");
        let raw = std::fs::read_to_string(&policy_path).expect("read policy.json");

        assert!(
            raw.contains("./.git"),
            "global project-relative paths should persist literally, got: {raw}"
        );

        let policy = agent_sandbox_core::load_policy(&policy_path, Some(home.as_path()), None);

        let found = policy.filesystem.allow.iter().any(|rule| {
            rule.path == Path::new("./.git") && rule.access.covers(FileAccess::ReadWrite)
        });

        assert!(
            found,
            "global ./.git approval should persist as ./.git in {:?}, allow={:?}",
            policy_path, policy.filesystem.allow
        );
    }

    #[tokio::test]
    async fn global_resource_dev_fd_glob_persists_to_policy_json() {
        // A non-once approval for a resource prompt whose target is the glob
        // /dev/fd/* under Global scope must persist an allow rule to the
        // global policy.json rather than silently doing nothing.
        let store = test_store("global-devfd").await;

        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-global-devfd-{}",
            std::process::id()
        ));

        std::fs::create_dir_all(&home).expect("create test home");

        let pending = PendingResource {
            id: "rs-devfd".into(),
            created_at: 0.0,
            kind: ResourceKind::UnixSocket,
            path: "/dev/fd/3".into(),
            access: ResourceAccess::Socket(SocketAccess::Connect),
            ctx: pending_context(None, Some(home.clone()), None, None),
        };

        let pending_id = pending.id.clone();

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert(pending.id.clone(), Pending::Resource(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Global,
                    target: Some(ApprovalTarget::ResourcePath {
                        resource_kind: ResourceKind::UnixSocket,
                        path: "/dev/fd/*".into(),
                    }),
                    wire: ScopeWire {
                        paths: SandboxPaths::new("/repo", home.clone(), "/repo"),
                        session_id: None,
                        owner_uid: Some(1000),
                        sandbox_session_id: None,
                        comment: None,
                        package: None,
                    },
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "global resource approval should succeed, got {reply:?}"
        );

        let policy_path = home.join(".config/agent-sandbox/policy.json");
        let policy = load_policy(&policy_path, Some(home.as_path()), None);

        let found = policy.resources.allow.iter().any(|rule| {
            rule.kind == ResourceKind::UnixSocket
                && rule.path == Path::new("/dev/fd/*")
                && rule
                    .access
                    .covers(ResourceAccess::Socket(SocketAccess::Connect))
        });

        assert!(
            found,
            "global /dev/fd/* resource rule should be persisted to {:?}, allow={:?}",
            policy_path, policy.resources.allow
        );
    }

    async fn test_store(name: &str) -> PolicyStore {
        let dir = std::env::temp_dir().join(format!(
            "agent-sandbox-fs-session-{name}-{}",
            std::process::id()
        ));

        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test store dir");

        let store = PolicyStore::new(crate::store::test_args(
            dir.join("policy.sock"),
            dir.join("sandbox-policy.sock"),
            dir.join("declarative.json"),
            dir.join("exported-policy.json"),
            Duration::from_mins(1),
            true,
        ));

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "test-ui".into(),
                writer: writer(),
            });
            inner
                .ui_context_by_session
                .insert("test-ui".into(), UiSessionContext {
                    owner_uid: Some(1000),
                    client_id: 1,
                    ..UiSessionContext::default()
                });
        }

        store
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
            owner_uid: Some(1000),
            client_id: 1,
        }
    }

    #[tokio::test]
    async fn dbus_once_approval_caches_typed_target() {
        let store = test_store("dbus-once").await;

        let target = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );

        let pending_id = "dbus:once".to_owned();

        {
            let mut inner = store.inner.lock().await;
            let pending = Pending::Dbus(PendingDbus {
                id: pending_id.clone(),
                created_at: 0.0,
                target: target.clone(),
                ctx: pending_context(
                    Some("/repo".into()),
                    Some("/home/user".into()),
                    Some("/repo".into()),
                    None,
                ),
            });
            inner
                .pending
                .pending
                .insert(pending.id().to_owned(), pending);
        }

        let ctx = agent_sandbox_core::ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::from_options(Some(123), Some(1000)),
            sandbox_session_id: None,
            package: None,
        };

        add_ui_sessions(&store).await;

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Once,
                    target: Some(ApprovalTarget::Dbus {
                        target: target.clone(),
                    }),
                    wire: ScopeWire::from_resolved(&ctx, None),
                    client_id: 1,
                    approver_uid: Some(1000),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(matches!(
            reply,
            RpcReply::ScopeAction(ScopeActionReply::Dbus { .. })
        ));

        let inner = store.inner.lock().await;

        assert!(
            inner.dbus_verdict_cache.contains_key(&target),
            "once-approved D-Bus target should be cached under the typed key"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn dbus_global_approval_with_comment_persists_edited_target() {
        let store = test_store("dbus-global-comment").await;

        let home = std::env::temp_dir().join(format!(
            "agent-sandbox-home-dbus-comment-{}",
            std::process::id()
        ));

        std::fs::create_dir_all(&home).expect("create test home");

        let requested = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "",
            Vec::new(),
        );

        let edited = DbusTarget {
            destination: "org.example.Service".into(),
            object_path: "**".into(),
            interface: "*".into(),
            member: "*".into(),
            ..requested.clone()
        };

        let pending_id = "dbus-global-comment".to_owned();

        {
            let mut inner = store.inner.lock().await;
            let pending = Pending::Dbus(PendingDbus {
                id: pending_id.clone(),
                created_at: 0.0,
                target: requested.clone(),
                ctx: pending_context(Some("/repo".into()), Some(home.clone()), None, None),
            });
            inner
                .pending
                .pending
                .insert(pending.id().to_owned(), pending);
        }

        add_ui_sessions(&store).await;

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Global,
                    target: Some(ApprovalTarget::Dbus {
                        target: edited.clone(),
                    }),
                    wire: ScopeWire {
                        paths: SandboxPaths::new("/repo", home.clone(), "/repo"),
                        session_id: None,
                        owner_uid: Some(1000),
                        sandbox_session_id: None,
                        comment: Some("allow introspect".into()),
                        package: None,
                    },
                    client_id: 1,
                    approver_uid: Some(1000),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "global D-Bus wildcard approval should succeed, got {reply:?}"
        );

        let policy_path = home.join(".config/agent-sandbox/policy.json");
        let policy = load_policy(&policy_path, Some(&home), None);

        let found = policy.dbus.allow.iter().find(|rule| {
            rule.target.destination == "org.example.Service" && rule.target.object_path == "**"
        });

        let found = found.expect("wildcard D-Bus rule persisted");

        assert_eq!(
            found.comment.as_deref(),
            Some("allow introspect"),
            "persisted rule should carry the user-supplied comment"
        );
    }

    async fn add_ui_sessions(store: &PolicyStore) {
        let mut inner = store.inner.lock().await;

        inner.ui_clients.insert(1, UiClient {
            session_id: "ui-session".into(),
            writer: writer(),
        });

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
            ctx: pending_context(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
                None,
            ),
        }
    }

    fn scope_wire(session_id: &str) -> ScopeWire {
        ScopeWire {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            session_id: Some(session_id.into()),
            owner_uid: Some(1000),
            sandbox_session_id: None,
            comment: None,
            package: None,
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
            .pending
            .insert(pending.id.clone(), Pending::Filesystem(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Session,
                    target: Some(ApprovalTarget::FilesystemPath {
                        path: "/home/user/projects/foo".into(),
                    }),
                    wire: scope_wire(submitting_session_id),
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(reply.scope_succeeded());
    }

    fn merge_context(pid: Option<u32>) -> agent_sandbox_core::ResolvedRequestContext {
        agent_sandbox_core::ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::from_options(pid, None),
            sandbox_session_id: None,
            package: None,
        }
    }

    #[tokio::test]
    async fn filesystem_session_approval_binds_to_submitting_session() {
        let store = test_store("ui-session").await;
        add_ui_sessions(&store).await;
        approve_filesystem_session(&store, pending_filesystem(), "ui-session").await;

        let has_allow = {
            let inner = store.inner.lock().await;
            inner
                .session
                .session_filesystem_allow
                .contains_key("ui-session")
        };

        assert!(has_allow);

        assert_eq!(
            store
                .filesystem_allow_source(
                    Path::new("/home/user/projects/foo/src/lib.rs"),
                    FileAccess::Read,
                    &merge_context(None),
                )
                .await,
            Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session
            )))
        );
    }

    #[tokio::test]
    async fn filesystem_session_approval_keeps_standalone_session() {
        let store = test_store("standalone").await;
        add_ui_sessions(&store).await;
        approve_filesystem_session(&store, pending_filesystem(), "ui-session").await;

        let has_allow = {
            let inner = store.inner.lock().await;
            inner
                .session
                .session_filesystem_allow
                .contains_key("ui-session")
        };

        assert!(has_allow);

        assert_eq!(
            store
                .filesystem_allow_source(
                    Path::new("/home/user/projects/foo/src/lib.rs"),
                    FileAccess::Read,
                    &merge_context(None),
                )
                .await,
            Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session
            )))
        );
    }

    #[tokio::test]
    async fn sandbox_session_pending_rejects_foreign_host_uid() {
        let store = test_store("sandbox-session-direct-approval").await;

        store.sandbox_sessions.update(|sessions| {
            sessions.insert(
                "sandbox-a".into(),
                crate::store::types::SandboxSessionRegistration {
                    root: crate::store::types::RootAdoption::Adopted { pid: 42 },
                    owner_uid: 1000,
                    project_root: "/repo".into(),
                    package: None,
                    launcher: crate::store::types::LauncherBinding::Unbound,
                    cgroup: None,
                    export_reader: None,
                },
            );
        });

        let mut pending = pending_filesystem();
        pending.ctx.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert(pending.id.clone(), Pending::Filesystem(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id: pending_id.clone(),
                    scope: ApprovalScope::Once,
                    target: None,
                    wire: ScopeWire {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        session_id: None,
                        owner_uid: Some(1001),
                        sandbox_session_id: Some("sandbox-a".into()),
                        comment: None,
                        package: None,
                    },
                    client_id: 99,
                    approver_uid: Some(1001),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "approval not authorized for this connection"),
            "foreign uid host approval must be rejected, got: {reply:?}"
        );

        let summaries = store.pending_summaries().await;
        assert_eq!(summaries.len(), 1);

        assert!(
            matches!(&summaries[0], PendingSummary::Filesystem { id, .. } if id == &pending_id),
            "rejected approval must leave pending request intact"
        );
    }

    #[tokio::test]
    async fn cross_connection_approve_rejects_foreign_sandbox_ui() {
        let store = test_store("cross-connection-approve").await;

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "ui-b".into(),
                writer: writer(),
            });
            inner
                .ui_context_by_session
                .insert("ui-b".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-b".into()),
                    owner_uid: Some(1000),
                    client_id: 1,
                });
        }

        let mut pending = pending_filesystem();
        pending.ctx.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert(pending.id.clone(), Pending::Filesystem(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id: pending_id.clone(),
                    scope: ApprovalScope::Once,
                    target: None,
                    wire: scope_wire("ui-b"),
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "approval not authorized for this connection"),
            "cross-sandbox Approve must be rejected, got: {reply:?}"
        );

        let summaries = store.pending_summaries().await;
        assert_eq!(summaries.len(), 1);

        assert!(
            matches!(&summaries[0], PendingSummary::Filesystem { id, .. } if id == &pending_id),
            "rejected approval must leave pending request intact"
        );
    }

    #[tokio::test]
    async fn sandbox_session_pending_allows_matching_uifd_approval() {
        let store = test_store("sandbox-session-uifd-approval").await;

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "ui-a".into(),
                writer: writer(),
            });
            inner
                .ui_context_by_session
                .insert("ui-a".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-a".into()),
                    owner_uid: Some(1000),
                    client_id: 1,
                });
        }

        let mut pending = pending_filesystem();
        pending.ctx.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert(pending.id.clone(), Pending::Filesystem(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Once,
                    target: None,
                    wire: scope_wire("ui-a"),
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "matching UiFd approval failed: {reply:?}"
        );
    }

    #[tokio::test]
    async fn sandbox_session_pending_allows_host_owner_cli_approval() {
        let store = test_store("sandbox-session-host-cli-approval").await;

        store.sandbox_sessions.update(|sessions| {
            sessions.insert(
                "sandbox-a".into(),
                crate::store::types::SandboxSessionRegistration {
                    root: crate::store::types::RootAdoption::Adopted { pid: 42 },
                    owner_uid: 1000,
                    project_root: "/repo".into(),
                    package: None,
                    launcher: crate::store::types::LauncherBinding::Unbound,
                    cgroup: None,
                    export_reader: None,
                },
            );
        });

        let mut pending = pending_filesystem();
        pending.ctx.sandbox_session_id = Some("sandbox-a".into());
        let pending_id = pending.id.clone();

        store
            .inner
            .lock()
            .await
            .pending
            .pending
            .insert(pending.id.clone(), Pending::Filesystem(pending));

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Once,
                    target: None,
                    wire: ScopeWire {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        session_id: None,
                        owner_uid: Some(1000),
                        sandbox_session_id: Some("sandbox-a".into()),
                        comment: None,
                        package: None,
                    },
                    client_id: 99,
                    approver_uid: Some(1000),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "host owner CLI approval failed: {reply:?}"
        );
    }

    #[tokio::test]
    async fn approving_unrunnable_elevation_resolves_the_request() {
        let store = test_store("unrunnable-elevation-approval").await;

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "ui-a".into(),
                writer: writer(),
            });
            inner
                .ui_context_by_session
                .insert("ui-a".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-a".into()),
                    owner_uid: Some(1000),
                    client_id: 1,
                });
        }

        let pending = PendingElevation {
            id: "elev:unrunnable".into(),
            created_at: 0.0,
            argv: vec!["-n".into(), "true".into()],
            ctx: pending_context(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
                Some("sandbox-a"),
            ),
        };
        let pending_id = pending.id.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();

        {
            let mut inner = store.inner.lock().await;
            inner
                .pending
                .elevation_futures
                .insert(pending_id.clone(), tx);
            inner
                .pending
                .pending
                .insert(pending_id.clone(), Pending::Elevation(pending));
        }

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id,
                    scope: ApprovalScope::Once,
                    target: None,
                    wire: scope_wire("ui-a"),
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            matches!(reply, RpcReply::Error(_)),
            "approver must learn the command cannot run, got: {reply:?}"
        );
        assert!(
            store.pending_summaries().await.is_empty(),
            "approved request must leave the pending queue"
        );

        let verdict = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("requester must get a verdict")
            .expect("verdict channel must not be dropped");
        assert_ne!(
            verdict.exit_code, 0,
            "unrunnable command must fail: {verdict:?}"
        );
        assert!(
            verdict.stderr.contains("elevation argv[0]"),
            "requester must see why: {verdict:?}"
        );
    }

    #[tokio::test]
    async fn session_network_rules_do_not_cross_sandbox_sessions_in_same_project() {
        let store = test_store("sandbox-session-isolation").await;

        {
            let mut inner = store.inner.lock().await;
            for (client_id, ui_session_id, sandbox_session_id) in
                [(10_u64, "ui-a", "sandbox-a"), (11_u64, "ui-b", "sandbox-b")]
            {
                inner.ui_clients.insert(client_id, UiClient {
                    session_id: ui_session_id.into(),
                    writer: writer(),
                });
                inner
                    .ui_context_by_session
                    .insert(ui_session_id.into(), UiSessionContext {
                        cwd: Some("/repo".into()),
                        home: Some("/home/user".into()),
                        project_root: Some("/repo".into()),
                        sandbox_session_id: Some(sandbox_session_id.into()),
                        owner_uid: Some(1000),
                        client_id,
                    });
            }
            inner
                .session
                .session_allow
                .entry("ui-a".into())
                .or_default()
                .insert(NetworkRuleKey::new("api.example.com", 443));
        }

        assert_eq!(
            store
                .allow_verdict(
                    "api.example.com",
                    443,
                    &agent_sandbox_core::ResolvedRequestContext {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        ids: ProcessIds::default(),
                        sandbox_session_id: Some("sandbox-a".into()),
                        package: None,
                    },
                )
                .await,
            Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session
            )))
        );

        assert_eq!(
            store
                .allow_verdict(
                    "api.example.com",
                    443,
                    &agent_sandbox_core::ResolvedRequestContext {
                        paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
                        ids: ProcessIds::default(),
                        sandbox_session_id: Some("sandbox-b".into()),
                        package: None,
                    },
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn scoped_filesystem_approval_settles_other_covered_pendings() {
        // Regression: a directory rule approved on one prompt left sibling
        // prompts it covers pending, so the UI asked about each of them again.
        let store = Arc::new(test_store("settle-covered").await);
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project = home.join("project");
        let slides = project.join("slides");
        std::fs::create_dir_all(&slides).expect("create slides dir");

        let names = ["talk.pptx", "poster.png"];
        for name in names {
            std::fs::write(slides.join(name), b"").expect("write slide file");
        }

        let ctx = pending_context(
            Some(project.clone()),
            Some(home.clone()),
            Some(project.clone()),
            None,
        );

        let requests = names.map(|name| {
            let store = Arc::clone(&store);
            let path = slides.join(name);
            let ctx = ctx.clone();
            tokio::spawn(async move {
                store
                    .request_filesystem_approval(path, FileAccess::Read, ctx)
                    .await
            })
        });

        let talk = slides.join("talk.pptx");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let talk_id = loop {
            let inner = store.inner.lock().await;
            let pending = &inner.pending.pending;
            let talk_id = (pending.len() == 2)
                .then(|| {
                    pending.values().find_map(|p| match p {
                        Pending::Filesystem(fs) if fs.path == talk => Some(fs.id.clone()),
                        _ => None,
                    })
                })
                .flatten();
            drop(inner);
            if let Some(id) = talk_id {
                break id;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "both requests must register a pending"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let reply = store
            .apply_pending_decision(
                PendingDecision {
                    pending_id: talk_id,
                    scope: ApprovalScope::Project,
                    target: Some(ApprovalTarget::FilesystemPath {
                        path: slides.clone(),
                    }),
                    wire: ScopeWire {
                        paths: SandboxPaths::new(&project, &home, &project),
                        session_id: None,
                        owner_uid: Some(1000),
                        sandbox_session_id: None,
                        comment: None,
                        package: None,
                    },
                    client_id: 1,
                    approver_uid: None,
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            reply.scope_succeeded(),
            "project directory approval should succeed, got: {reply:?}"
        );

        for request in requests {
            let check = tokio::time::timeout(Duration::from_secs(5), request)
                .await
                .expect("a request covered by the new rule must not wait for its own prompt")
                .expect("request task");
            assert!(
                check.verdict.allowed,
                "covered request must be allowed, got {check:?}"
            );
        }

        assert!(
            store.pending_summaries().await.is_empty(),
            "covered requests must leave the pending queue"
        );
    }
}
