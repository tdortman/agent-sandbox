//! Policy store: the decided verdict of every capability kind.
//!
//! A request is decided by the verdict ladder: merged policy deny, Session
//! runtime decision deny, Session runtime decision allow, merged policy
//! allow. Resource, D-Bus, secret and sudo requests run exactly that ladder.
//! Network and filesystem requests have steps of their own between the
//! rungs, so they share the session step and spell out the rest.

use std::{cell::LazyCell, collections::HashSet, path::Path};

use agent_sandbox_core::{
    ApprovalScope, DbusRule, DbusTarget, FileAccess, FilesystemRule, FilesystemRuleKey,
    InodeIdentity, NetworkRuleKey, ResolvedRequestContext, ResourceAccess, ResourceKind,
    ResourceRule, ResourceRuleKey, SecretRequest, SecretTarget, SudoRule, Verdict, VerdictSource,
    host_pattern_matches, normalize_directory_traverse_access, normalize_host, with_canonical_memo,
};

use super::{
    PolicyStore,
    access::{
        filesystem_rules_match_allow, is_sandbox_infrastructure_path, project_roots_for_allow,
    },
    decisions::DecisionAction,
    state::{SessionBuckets, SessionState},
    types::DenyFingerprint,
};

/// A capability kind's share of the session step: which buckets hold its
/// Session runtime decisions and whether one bucket entry covers the request.
struct SessionRules<K, D, A> {
    bucket: fn(&mut SessionState) -> SessionBuckets<'_, K>,
    denies: D,
    allows: A,
}

/// Verdict of a Session runtime decision. A session deny reports as policy.
const fn session_verdict(action: DecisionAction) -> Verdict {
    match action {
        DecisionAction::Deny => Verdict::denied(VerdictSource::policy()),
        DecisionAction::Approve => Verdict::allowed(VerdictSource::Scope(ApprovalScope::Session)),
    }
}

impl PolicyStore {
    /// Run `read` on a kind's session buckets and the ids of the sessions a
    /// request routes to. One state lock spans the routing and the read.
    async fn read_session<K, T>(
        &self,
        ctx: &ResolvedRequestContext,
        bucket: fn(&mut SessionState) -> SessionBuckets<'_, K>,
        read: impl FnOnce(&SessionBuckets<'_, K>, &HashSet<String>) -> T + Send,
    ) -> T {
        let mut inner = self.inner.lock().await;
        let session_ids = Self::deciding_ui_session_ids(&inner, ctx);

        read(&bucket(&mut inner.session), &session_ids)
    }

    /// The Session runtime decision covering a request.
    async fn session_decision<K>(
        &self,
        ctx: &ResolvedRequestContext,
        rules: SessionRules<K, impl Fn(&K) -> bool + Send, impl Fn(&K) -> bool + Send>,
    ) -> Option<DecisionAction> {
        self.read_session(ctx, rules.bucket, move |buckets, session_ids| {
            buckets.decision(session_ids, rules.denies, rules.allows)
        })
        .await
    }

    /// The verdict ladder: policy deny, session deny, session allow, policy
    /// allow. `policy` is the kind's verdict from one merged-policy snapshot.
    async fn decided_verdict<K>(
        &self,
        ctx: &ResolvedRequestContext,
        policy: Option<Verdict>,
        rules: SessionRules<K, impl Fn(&K) -> bool + Send, impl Fn(&K) -> bool + Send>,
    ) -> Option<Verdict> {
        if policy.as_ref().is_some_and(|verdict| !verdict.allowed) {
            return policy;
        }

        self.session_decision(ctx, rules)
            .await
            .map(session_verdict)
            .or(policy)
    }

    pub(crate) async fn network_verdict(
        &self,
        host: &str,
        port: u16,
        ctx: &ResolvedRequestContext,
        consume_once: bool,
    ) -> Option<Verdict> {
        let host = normalize_host(host);

        // One fresh policy snapshot keeps deny and allow on the same revision.
        let merged = self.merged_for(ctx);

        if merged
            .network
            .direct
            .deny
            .iter()
            .any(|rule| rule.port == port && host_pattern_matches(&rule.host, &host))
        {
            return Some(Verdict::denied(VerdictSource::policy()));
        }

        let covers =
            |rule: &NetworkRuleKey| rule.port == port && host_pattern_matches(&rule.host, &host);

        let session = self
            .session_decision(ctx, SessionRules {
                bucket: SessionState::network_buckets,
                denies: covers,
                allows: covers,
            })
            .await;

        if session == Some(DecisionAction::Deny) {
            return Some(session_verdict(DecisionAction::Deny));
        }

        if self.once_allowed(&host, port, ctx, consume_once).await {
            return Some(Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once)));
        }

        if let Some(action) = session {
            return Some(session_verdict(action));
        }

        for rule in &merged.network.direct.allow {
            if host_pattern_matches(&rule.host, &host) && rule.port == port {
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

    pub(crate) async fn filesystem_allow_source(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let access = normalize_directory_traverse_access(path, access);

        if let Some(verdict) = self.session_export_verdict(path, access, ctx) {
            return Some(verdict);
        }

        if is_sandbox_infrastructure_path(path) {
            return Some(Verdict::allowed(VerdictSource::Infrastructure));
        }

        let project_root = ctx.paths.project_root();
        let home = ctx.paths.home();

        /// What the path rules of the merged policy layers decide.
        enum RuleMatch {
            Denied,
            NotDenied {
                fingerprint: Vec<DenyFingerprint>,
                grant: RuleGrant,
            },
        }

        enum RuleGrant {
            Allowed,
            Unmatched,
        }

        // One memo spans the load and every match, so rule paths resolved while
        // expanding the layers are not resolved again while matching them.
        let rules = Self::blocking(|| {
            with_canonical_memo(|| {
                let merged = self.merged_for(ctx);

                if merged
                    .filesystem
                    .deny
                    .iter()
                    .any(|rule| rule.matches(path, access, project_root))
                {
                    return RuleMatch::Denied;
                }

                let grant = if filesystem_rules_match_allow(
                    &merged.filesystem.allow,
                    path,
                    access,
                    project_root,
                ) {
                    RuleGrant::Allowed
                } else {
                    RuleGrant::Unmatched
                };

                RuleMatch::NotDenied {
                    fingerprint: Self::deny_fingerprint(&merged, home, project_root),
                    grant,
                }
            })
        });

        let RuleMatch::NotDenied { fingerprint, grant } = rules else {
            return Some(Verdict::denied(VerdictSource::policy()));
        };

        if self.deny_inode_denied(path, access, &fingerprint).await {
            return Some(Verdict::denied(VerdictSource::policy()));
        }

        let session = self
            .read_session(
                ctx,
                SessionState::filesystem_buckets,
                |buckets, session_ids| {
                    let rule = |entry: &FilesystemRuleKey| {
                        FilesystemRule::new(entry.path.clone(), entry.access, "")
                    };

                    let roots = LazyCell::new(|| project_roots_for_allow(project_root, path));

                    let by_path = buckets.decision(
                        session_ids,
                        |entry| rule(entry).matches(path, access, project_root),
                        |entry| {
                            let rule = rule(entry);

                            if roots.is_empty() {
                                rule.matches(path, access, None)
                            } else {
                                roots
                                    .iter()
                                    .any(|root| rule.matches(path, access, Some(root)))
                            }
                        },
                    );

                    // A hard link to an approved path is the same inode, so
                    // the approval covers it. Inodes are compared only once
                    // no entry matched by path; denies are already read.
                    by_path.or_else(|| {
                        let identity = InodeIdentity::from_path(path)?;

                        buckets.decision(
                            session_ids,
                            |_| false,
                            |entry| {
                                entry.access.covers(access)
                                    && InodeIdentity::from_path(&entry.path) == Some(identity)
                            },
                        )
                    })
                },
            )
            .await;

        if let Some(action) = session {
            return Some(session_verdict(action));
        }

        if self.static_filesystem_allowed(path, access, ctx).await {
            return Some(Verdict::allowed(VerdictSource::Static));
        }

        if matches!(grant, RuleGrant::Allowed) {
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
        let merged = self.merged_for(ctx);

        let policy = if self
            .resource_denied_by(&merged, kind, path, access, ctx)
            .await
        {
            Some(Verdict::denied(VerdictSource::policy()))
        } else {
            merged
                .resources
                .allow
                .iter()
                .any(|rule| rule.matches(kind, path, access, ctx.paths.project_root()))
                .then_some(Verdict::allowed(VerdictSource::policy()))
        };

        let covers = |entry: &ResourceRuleKey| {
            ResourceRule::new(entry.kind, entry.path.clone(), entry.access, "")
                .matches(kind, path, access, None)
        };

        self.decided_verdict(ctx, policy, SessionRules {
            bucket: SessionState::resource_buckets,
            denies: covers,
            allows: covers,
        })
        .await
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

    /// Verdict the declarative and session rules give a D-Bus target, or
    /// `None` when the target needs a prompt. Denies win over allows.
    pub(crate) async fn dbus_decided_verdict(
        &self,
        target: &DbusTarget,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let covers = |entry: &DbusTarget| DbusRule::new(entry.clone(), "").matches(target);

        self.decided_verdict(ctx, self.dbus_verdict(target, ctx), SessionRules {
            bucket: SessionState::dbus_buckets,
            denies: covers,
            allows: covers,
        })
        .await
    }

    /// Verdict the merged file policy layers and session buckets give a
    /// runtime secret request, or `None` when undecided. Denies win over
    /// allows.
    pub(crate) async fn secret_decided_verdict(
        &self,
        request: &SecretRequest,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let attributed_package = ctx.package.is_some();
        let policy = Self::blocking(|| self.secret_verdict(request, ctx));

        self.decided_verdict(ctx, policy, SessionRules {
            bucket: SessionState::secret_buckets,
            denies: |target: &SecretTarget| {
                target.validate().is_ok() && target.matches(request, attributed_package)
            },
            allows: |target: &SecretTarget| {
                target.validate_for_allow().is_ok() && target.matches(request, attributed_package)
            },
        })
        .await
    }

    /// Verdict the merged policy layers and session buckets give an
    /// elevation argv, or `None` when it needs a prompt. Denies win over
    /// allows.
    pub(crate) async fn sudo_decided_verdict(
        &self,
        argv: &[String],
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let policy = {
            let merged = self.merged_for(ctx);

            if merged.sudo.deny.iter().any(|rule| rule.matches(argv)) {
                Some(Verdict::denied(VerdictSource::policy()))
            } else {
                merged
                    .sudo
                    .allow
                    .iter()
                    .any(|rule| rule.matches(argv))
                    .then_some(Verdict::allowed(VerdictSource::policy()))
            }
        };

        let covers = |entry: &Vec<String>| SudoRule::new(entry.clone(), "").matches(argv);

        self.decided_verdict(ctx, policy, SessionRules {
            bucket: SessionState::sudo_buckets,
            denies: covers,
            allows: covers,
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashSet},
        path::PathBuf,
        sync::Arc,
        time::Duration,
    };

    use agent_sandbox_core::{
        DbusMessageKind, DbusRule, DbusTarget, DeviceAccess, NetworkRule, NetworkRuleKey, Policy,
        ProcessIds, ResourceRule, ResourceRuleKey, RpcReply, SandboxPaths, SecretAccess,
        SecretOperation, SecretPartition, SecretRule, atomic_write_policy,
    };
    use tokio::{net::UnixStream, sync::Mutex};

    use super::{
        super::types::{UiClient, UiSessionContext},
        *,
    };
    use crate::{
        store::decision_context::ContextKey,
        wire::{FilesystemScopeOp, NetworkScopeOp, ScopeWire},
    };

    const UI_SESSION: &str = "ui-session";

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

    /// Store whose home policy is `policy`, plus a request context routed to
    /// the one registered UI session.
    struct Ladder {
        _dir: tempfile::TempDir,
        store: PolicyStore,
        ctx: ResolvedRequestContext,
    }

    async fn ladder(policy: &Policy) -> Ladder {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home-user");
        let project_root = dir.path().join("repo");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        std::fs::create_dir_all(&project_root).expect("create project root");

        atomic_write_policy(&policy_dir.join("policy.json"), policy, None, None, None)
            .expect("write policy");

        let store = test_store(&dir);

        register_ui_session(
            &store,
            UI_SESSION,
            project_root.clone(),
            home.clone(),
            project_root.clone(),
        )
        .await;

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root, &home, &project_root),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        Ladder {
            _dir: dir,
            store,
            ctx,
        }
    }

    fn secret_request() -> SecretRequest {
        SecretRequest {
            partition: SecretPartition::Host,
            collection: "login".into(),
            is_default_collection: false,
            attributes: BTreeMap::from([("service".to_owned(), "gh".to_owned())]),
            label: "GitHub CLI".into(),
            access: SecretAccess::Read,
            operation: SecretOperation::GetSecret,
            replace: false,
            batch: None,
        }
    }

    /// Record a Session runtime decision for `target` the way a UI verdict
    /// does.
    async fn decide_secret_for_session(
        ladder: &Ladder,
        target: SecretTarget,
        action: DecisionAction,
    ) {
        let reply = ladder
            .store
            .apply_secret_scope(
                target,
                ApprovalScope::Session,
                ScopeWire::from_resolved(&ladder.ctx, Some(UI_SESSION.into())),
                action,
            )
            .await;

        assert!(
            matches!(reply, RpcReply::ScopeAction(_)),
            "session decision must apply, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn secret_policy_deny_beats_session_allow() {
        let request = secret_request();
        let target = SecretTarget::exact_for_request(&request);
        let mut policy = Policy::default();

        policy
            .secrets
            .deny
            .push(SecretRule::new(target.clone(), "never"));

        let ladder = ladder(&policy).await;
        decide_secret_for_session(&ladder, target, DecisionAction::Approve).await;
        let reply = ladder.store.check_secret(request, ladder.ctx.clone()).await;

        assert_eq!(reply.verdict, Verdict::denied(VerdictSource::policy()));
    }

    #[tokio::test]
    async fn secret_session_deny_beats_policy_allow() {
        let request = secret_request();
        let target = SecretTarget::exact_for_request(&request);
        let mut policy = Policy::default();

        policy
            .secrets
            .allow
            .push(SecretRule::new(target.clone(), "trusted"));

        let ladder = ladder(&policy).await;
        decide_secret_for_session(&ladder, target, DecisionAction::Deny).await;
        let reply = ladder.store.check_secret(request, ladder.ctx.clone()).await;

        assert_eq!(reply.verdict, Verdict::denied(VerdictSource::policy()));
    }

    #[tokio::test]
    async fn secret_session_allow_decides_when_policy_is_silent() {
        let request = secret_request();
        let ladder = ladder(&Policy::default()).await;

        decide_secret_for_session(
            &ladder,
            SecretTarget::exact_for_request(&request),
            DecisionAction::Approve,
        )
        .await;

        let reply = ladder.store.check_secret(request, ladder.ctx.clone()).await;

        assert_eq!(
            reply.verdict,
            Verdict::allowed(VerdictSource::Scope(ApprovalScope::Session))
        );
    }

    #[tokio::test]
    async fn secret_session_allow_too_broad_to_allow_does_not_allow() {
        let request = secret_request();

        // A host target with neither attributes nor a label covers the
        // request but fails the allow guardrail.
        let broad = SecretTarget {
            partition: SecretPartition::Host,
            collection: request.collection.clone(),
            attributes: BTreeMap::new(),
            label: None,
            access: SecretAccess::Read,
        };

        let ladder = ladder(&Policy::default()).await;
        decide_secret_for_session(&ladder, broad, DecisionAction::Approve).await;
        let reply = ladder.store.check_secret(request, ladder.ctx.clone()).await;

        assert!(
            !reply.verdict.allowed,
            "a session allow entry that is invalid as an allow must not allow, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn network_session_allow_covers_wildcard_host_on_its_port() {
        let ladder = ladder(&Policy::default()).await;

        let reply = ladder
            .store
            .apply_network_scope(
                NetworkScopeOp {
                    host: "2001:db8:*".into(),
                    port: 443,
                    scope: ApprovalScope::Session,
                    wire: ScopeWire::from_resolved(&ladder.ctx, Some(UI_SESSION.into())),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            matches!(reply, RpcReply::ScopeAction(_)),
            "session decision must apply, got {reply:?}"
        );

        // The request spells the address in its long form.
        assert_eq!(
            ladder
                .store
                .allow_verdict("2001:db8:0:0:0:0:0:1", 443, &ladder.ctx)
                .await,
            Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session
            )))
        );

        assert_eq!(
            ladder
                .store
                .allow_verdict("2001:db8:0:0:0:0:0:1", 80, &ladder.ctx)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn filesystem_session_allow_resolves_project_relative_path() {
        let ladder = ladder(&Policy::default()).await;
        let project_root = ladder.ctx.paths.project_root().expect("project root");
        let in_project = project_root.join(".git/config");
        let elsewhere = ladder
            .ctx
            .paths
            .home()
            .expect("home")
            .join("other/.git/config");

        assert_eq!(
            ladder
                .store
                .filesystem_allow_source(&in_project, FileAccess::ReadWrite, &ladder.ctx)
                .await,
            None,
            "nothing decides the path before the session decision"
        );

        let reply = ladder
            .store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: "./.git".into(),
                    access: FileAccess::ReadWrite,
                    scope: ApprovalScope::Session,
                    wire: ScopeWire::from_resolved(&ladder.ctx, Some(UI_SESSION.into())),
                },
                DecisionAction::Approve,
            )
            .await;

        assert!(
            matches!(reply, RpcReply::ScopeAction(_)),
            "session decision must apply, got {reply:?}"
        );

        assert_eq!(
            ladder
                .store
                .filesystem_allow_source(&in_project, FileAccess::ReadWrite, &ladder.ctx)
                .await,
            Some(Verdict::allowed(VerdictSource::Scope(
                ApprovalScope::Session
            )))
        );

        assert_eq!(
            ladder
                .store
                .filesystem_allow_source(&elsewhere, FileAccess::ReadWrite, &ladder.ctx)
                .await,
            None,
            "a project-relative allow must not reach outside the project root"
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

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner.session.once_allow.insert(ContextKey::new(
                &ctx,
                NetworkRuleKey::new("example.com", 443),
            ));
            inner.session.session_allow.insert(
                "ui-session".into(),
                HashSet::from([NetworkRuleKey::new("example.com", 443)]),
            );
            inner.session.session_deny.insert(
                "ui-session".into(),
                HashSet::from([NetworkRuleKey::new("example.com", 443)]),
            );
        }

        assert_eq!(
            store.network_verdict("example.com", 443, &ctx, false).await,
            Some(Verdict::denied(VerdictSource::policy()))
        );

        assert!(
            !store
                .network_verdict("example.com", 443, &ctx, true)
                .await
                .is_some_and(|v| v.allowed)
        );
    }

    #[tokio::test]
    async fn network_policy_snapshot_preserves_comments_and_refreshes_denies() {
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
            package: None,
        };

        assert_eq!(
            store.network_verdict("example.com", 443, &ctx, false).await,
            Some(Verdict::allowed(VerdictSource::policy_with_comment(
                "trusted policy file"
            )))
        );

        policy
            .network
            .direct
            .deny
            .push(NetworkRule::new("example.com", 443, "new deny"));

        let path = policy_dir.join("policy.json");
        let original_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        atomic_write_policy(&path, &policy, None, None, None).expect("update policy");

        std::fs::File::open(&path)
            .expect("open policy")
            .set_modified(original_mtime)
            .expect("preserve original policy mtime");

        assert_eq!(
            store.network_verdict("example.com", 443, &ctx, false).await,
            Some(Verdict::denied(VerdictSource::policy()))
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
            inner.session.session_resource_allow.insert(
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
            package: None,
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
            package: None,
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
