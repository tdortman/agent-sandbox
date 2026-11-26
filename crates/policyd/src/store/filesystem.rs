//! Policy store: filesystem (fanotify monitor spawn and declarative checks).

use std::{
    collections::HashMap,
    io::BufRead,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, FilesystemCheckReply, FilesystemMonitorReply,
    FilesystemRule, FilesystemRuleKey, InodeIdentity, ResolvedRequestContext, RpcReply,
    ScopeActionReply, Verdict, VerdictSource, expand_policy_path,
    normalize_directory_traverse_access,
};
use tokio::sync::oneshot;

use super::{
    decisions::DecisionAction,
    pending::{ApprovalKind, Decision, PromptKind, PromptStage},
    state::{PendingBoard, PolicyDecisionState},
    types::{MAX_STATIC_ALLOW_RULES, Pending, PendingFilesystem, PolicyStore, VerdictEntry},
};
use crate::{error::PolicydError, wire::FilesystemScopeOp};

/// Timeout for waiting for the fsmon `ready` line.
const FSMON_READY_TIMEOUT: Duration = Duration::from_secs(10);

fn canonicalize_static_allow_path(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

fn wait_fsmon_ready(stdout: std::process::ChildStdout) -> Result<(), String> {
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;

        if n == 0 {
            return Err("fsmon closed stdout before ready".to_string());
        }

        if line.trim() == "ready" {
            return Ok(());
        }
    }
}

/// Wait for `child` on its own thread so an exited monitor never lingers as a
/// zombie. A monitor that never became ready is killed first.
fn reap_in_background(mut child: Child, kill: bool) {
    std::thread::spawn(move || {
        if kill && let Err(error) = child.kill() {
            tracing::debug!(%error, "fsmon already exited before kill");
        }

        if let Err(error) = child.wait() {
            tracing::warn!(%error, "failed to reap fsmon");
        }
    });
}

fn expand_static_allow_rules(
    rules: &[FilesystemRule],
    home: Option<&Path>,
    project_root: Option<&Path>,
) -> Vec<FilesystemRule> {
    rules
        .iter()
        .map(|rule| {
            let path = expand_policy_path(&rule.path, home, project_root);

            FilesystemRule {
                path: canonicalize_static_allow_path(path),
                access: rule.access,
                comment: rule.comment.clone(),
            }
        })
        .collect()
}

impl PolicyStore {
    /// Spawn the filesystem monitor for a sandbox, wait for it to signal
    /// readiness, and return a reply.
    pub async fn start_filesystem_monitor(
        &self,
        peer_pid: u32,
        ctx: ResolvedRequestContext,
        static_allow: Vec<FilesystemRule>,
    ) -> FilesystemMonitorReply {
        let cmd = match &self.args.fs_monitor_cmd {
            Some(c) => c.clone(),
            None => {
                return FilesystemMonitorReply::failed("fs_monitor_cmd not configured");
            }
        };

        if peer_pid == 0 {
            return FilesystemMonitorReply::failed("cannot determine monitor target pid");
        }

        if static_allow.len() > MAX_STATIC_ALLOW_RULES {
            return FilesystemMonitorReply::failed("too many filesystem static allow rules");
        }

        let cwd = ctx.paths.cwd_path();
        let home = ctx.paths.home_path();
        let project_root = ctx.paths.project_root_path();
        let sandbox_session_id = ctx.sandbox_session_id.clone();
        let socket_str = self.args.sandbox_socket.to_string_lossy().to_string();
        let mut command = Command::new(&cmd);

        command
            .arg("--pid")
            .arg(peer_pid.to_string())
            .arg("--socket")
            .arg(&socket_str)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        for (flag, path) in [
            ("--cwd", cwd.as_ref()),
            ("--home", home.as_ref()),
            ("--project-root", project_root.as_ref()),
        ] {
            if let Some(path) = path {
                command.arg(flag).arg(path);
            }
        }

        // Ignore marks are grants the monitor can only revoke by stopping the
        // sandbox, which it does by killing the launcher; that stops every
        // process only when policyd kills the launcher's scope in turn.
        let ignore_static_allows = self.args.fs_ignore_static_allows
            && self.launcher_scope_stops_sandbox(sandbox_session_id.as_deref(), peer_pid);

        command
            .arg("--fs-ignore-static-allows")
            .arg(if ignore_static_allows {
                "true"
            } else {
                "false"
            });
        let static_allow_input = static_allow.clone();
        let home_for_expand = home.clone();
        let project_root_for_expand = project_root.clone();

        let static_allow = match tokio::task::spawn_blocking(move || {
            expand_static_allow_rules(
                &static_allow_input,
                home_for_expand.as_deref(),
                project_root_for_expand.as_deref(),
            )
        })
        .await
        {
            Ok(rules) => rules,
            Err(err) => {
                tracing::error!(error = %err, "expand static allow panicked");
                return FilesystemMonitorReply::failed("internal error expanding static allow");
            }
        };

        self.store_sandbox_static_allow(&ctx, static_allow).await;

        if let Some(sandbox_session_id) = &sandbox_session_id {
            command.env("AGENT_SANDBOX_SESSION_ID", sandbox_session_id);
        }

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(error = %err, "failed to spawn fsmon");
                return FilesystemMonitorReply::failed(format!("spawn failed: {err}"));
            }
        };

        let Some(stdout) = child.stdout.take() else {
            tracing::error!("fsmon stdout not captured");
            reap_in_background(child, true);
            return FilesystemMonitorReply::failed("stdout not captured");
        };

        tracing::info!(peer_pid, "spawning fsmon");

        let result = tokio::time::timeout(
            FSMON_READY_TIMEOUT,
            tokio::task::spawn_blocking(move || wait_fsmon_ready(stdout)),
        )
        .await;

        match result {
            Ok(Ok(Ok(()))) => {
                tracing::info!(peer_pid, "fsmon ready");
                reap_in_background(child, false);

                if let Some(session_id) = &sandbox_session_id {
                    self.record_export_reader(session_id, peer_pid);
                }

                FilesystemMonitorReply::active()
            }

            Ok(Ok(Err(err))) => {
                reap_in_background(child, true);
                FilesystemMonitorReply::failed(format!("ready wait failed: {err}"))
            }

            Ok(Err(err)) => {
                tracing::error!(error = %err, "fsmon ready wait panicked");
                reap_in_background(child, true);
                FilesystemMonitorReply::failed("internal error waiting for fsmon")
            }

            Err(_) => {
                reap_in_background(child, true);
                FilesystemMonitorReply::failed("fsmon ready timeout")
            }
        }
    }

    /// Check a filesystem access request against static allow sources and,
    /// if not already allowed, route it to an interactive approval.
    pub async fn check_filesystem(
        &self,
        path: PathBuf,
        access: FileAccess,
        ctx: ResolvedRequestContext,
    ) -> FilesystemCheckReply {
        let access = normalize_directory_traverse_access(&path, access);

        if let Some(verdict) = self.filesystem_allow_source(&path, access, &ctx).await {
            return FilesystemCheckReply::from_verdict(verdict, path, access);
        }

        self.request_filesystem_approval(path, access, ctx).await
    }

    /// Request interactive approval for a filesystem access, deduplicating
    /// concurrent requests for the same path and awaiting the user verdict.
    pub async fn request_filesystem_approval(
        &self,
        path: PathBuf,
        access: FileAccess,
        ctx: ResolvedRequestContext,
    ) -> FilesystemCheckReply {
        if self.filesystem_policy_denied(&path, access, &ctx).await {
            return FilesystemCheckReply::denied(VerdictSource::policy(), path, access);
        }

        if !self.args.interactive_approval {
            return FilesystemCheckReply::denied(VerdictSource::Blocked, path, access);
        }

        let key = FilesystemRuleKey { path, access };

        if let Some(reply) = self.cached_reply::<FilesystemApproval>(&key).await {
            return reply;
        }

        self.prompt::<FilesystemApproval>(key, &ctx).await
    }
}

/// The filesystem kind of pending approval.
pub(super) struct FilesystemApproval;

impl ApprovalKind for FilesystemApproval {
    type Key = FilesystemRuleKey;
    type Pending = PendingFilesystem;
    type Target = PathBuf;

    const FAILED_APPROVAL_BLOCKS: bool = true;

    fn into_pending(pending: PendingFilesystem) -> Pending {
        Pending::Filesystem(pending)
    }

    fn id(pending: &PendingFilesystem) -> &str {
        &pending.id
    }

    fn key(pending: &PendingFilesystem) -> FilesystemRuleKey {
        FilesystemRuleKey {
            path: pending.path.clone(),
            access: pending.access,
        }
    }

    async fn decided_verdict(store: &PolicyStore, pending: &PendingFilesystem) -> Option<Verdict> {
        store
            .filesystem_allow_source(&pending.path, pending.access, &pending.ctx)
            .await
    }

    async fn finish(
        store: &PolicyStore,
        pending_id: &str,
        key: FilesystemRuleKey,
        verdict: Verdict,
    ) {
        store.finish_prompt::<Self>(pending_id, key, verdict).await;
    }

    fn approval_target(
        pending: &PendingFilesystem,
        decision: &Decision,
    ) -> Result<PathBuf, PolicydError> {
        let path = match &decision.target {
            None => pending.path.clone(),
            Some(ApprovalTarget::FilesystemPath { path }) => path.clone(),
            Some(_) => return Err(PolicydError::InvalidDecisionTarget),
        };

        if path == pending.path {
            return Ok(path);
        }

        // A once decision covers exactly the requested path.
        if decision.scope == ApprovalScope::Once {
            return Err(PolicydError::InvalidDecisionTarget);
        }

        // Broader scopes also accept an ancestor of the requested path.
        let project_root = decision
            .wire
            .paths
            .project_root()
            .or_else(|| pending.ctx.paths.project_root());

        let rule = FilesystemRule::new(path, FileAccess::Read, "");

        if rule.path_matches(&pending.path, project_root) {
            return Ok(rule.path);
        }

        Err(PolicydError::InvalidDecisionTarget)
    }

    fn audit_once(pending: &PendingFilesystem, target: &PathBuf, action: DecisionAction) {
        let detail = if action == DecisionAction::Approve {
            format!(
                "id={} path={} access={:?}",
                pending.id,
                target.display(),
                pending.access
            )
        } else {
            format!("id={} path={}", pending.id, target.display())
        };

        PolicyStore::audit(action.audit_verb(), None, None, &detail);
    }

    fn decided_key(pending: &PendingFilesystem, target: &PathBuf) -> FilesystemRuleKey {
        FilesystemRuleKey {
            path: target.clone(),
            access: pending.access,
        }
    }

    fn once_reply(pending: &PendingFilesystem, target: PathBuf) -> ScopeActionReply {
        ScopeActionReply::ok_filesystem(target, pending.access, ApprovalScope::Once, None)
    }

    async fn apply_scope(
        store: &PolicyStore,
        pending: &PendingFilesystem,
        target: PathBuf,
        decision: Decision,
    ) -> RpcReply {
        let wire = store
            .session_scope_wire(decision.wire, &pending.ctx, decision.scope)
            .await;

        store
            .apply_filesystem_scope(
                FilesystemScopeOp {
                    path: target,
                    access: pending.access,
                    scope: decision.scope,
                    wire,
                },
                decision.action,
            )
            .await
    }
}

impl PromptKind for FilesystemApproval {
    type Reply = FilesystemCheckReply;

    const APPROVAL_NAME: &'static str = "filesystem";
    const ID_PREFIX: &'static str = "fs";
    const NO_UI: &'static str = "agent-sandbox: no standalone filesystem policy UI registered \
                                 (agent-sandbox-ui or auto-spawn)";
    const TIMED_OUT: &'static str =
        "agent-sandbox: filesystem approval timed out (no response from policy UI)";
    const TOO_MANY_WAITERS: &'static str =
        "agent-sandbox: too many waiters for one filesystem approval";
    /// How long a deny verdict is cached. Concurrent opens of one path join
    /// the prompt in flight; this only covers rapid re-denials (or hard-link
    /// aliases) without prompting again.
    const VERDICT_TTL: Duration = Duration::from_secs(2);

    fn waiters(
        board: &mut PendingBoard,
    ) -> &mut HashMap<String, Vec<oneshot::Sender<FilesystemCheckReply>>> {
        &mut board.filesystem_futures
    }

    fn verdict_cache(
        state: &mut PolicyDecisionState,
    ) -> &mut HashMap<FilesystemRuleKey, VerdictEntry> {
        &mut state.filesystem_verdict_cache
    }

    // Opens of one path with one access share a prompt whatever their context.
    fn same_prompt(
        pending: &Pending,
        key: &FilesystemRuleKey,
        _ctx: &ResolvedRequestContext,
    ) -> bool {
        matches!(pending, Pending::Filesystem(fs) if fs.path == key.path && fs.access == key.access)
    }

    fn new_pending(
        id: String,
        created_at: f64,
        key: &FilesystemRuleKey,
        ctx: &ResolvedRequestContext,
    ) -> Pending {
        Pending::Filesystem(PendingFilesystem {
            id,
            created_at,
            path: key.path.clone(),
            access: key.access,
            ctx: ctx.clone(),
        })
    }

    fn reply(key: &FilesystemRuleKey, verdict: Verdict) -> FilesystemCheckReply {
        FilesystemCheckReply::from_verdict(verdict, key.path.clone(), key.access)
    }

    fn blocked(key: &FilesystemRuleKey, message: &str) -> FilesystemCheckReply {
        FilesystemCheckReply::blocked(message, key.path.clone(), key.access)
    }

    // An allow is not cached: a one-shot approval must not cover later opens
    // unless the user chose a scope that installs a real rule.
    fn caches(verdict: &Verdict) -> bool {
        !verdict.allowed
    }

    // Hard links share an inode, so a deny verdict for one path covers every
    // other path of that inode.
    fn aliased_verdict(
        cache: &HashMap<FilesystemRuleKey, VerdictEntry>,
        key: &FilesystemRuleKey,
    ) -> Option<Verdict> {
        let identity = InodeIdentity::from_path(&key.path)?;

        cache
            .iter()
            .find(|(cached, entry)| {
                entry.time.elapsed() < Self::VERDICT_TTL
                    && cached.access.covers(key.access)
                    && InodeIdentity::from_path(&cached.path) == Some(identity)
            })
            .map(|(_, entry)| Verdict {
                allowed: entry.allowed,
                source: entry.source.clone(),
            })
    }

    fn trace(stage: PromptStage, id: &str, key: &FilesystemRuleKey, ctx: &ResolvedRequestContext) {
        let path = key.path.display();
        let access = key.access;

        match stage {
            PromptStage::Queued => tracing::info!(
                pending_id = %id,
                path = %path,
                access = ?access,
                sandbox_session_id = ?ctx.sandbox_session_id,
                "filesystem approval pending; run agent-sandbox-approve pending or respond in the policy UI"
            ),
            PromptStage::AwaitingUi => tracing::info!(
                pending_id = id,
                path = %path,
                access = ?access,
                "filesystem approval waiting for policy UI to register"
            ),
            PromptStage::AwaitingDecision => tracing::info!(
                pending_id = id,
                path = %path,
                access = ?access,
                "filesystem approval waiting for user decision"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };

    use agent_sandbox_core::{
        ApprovalScope, FileAccess, FilesystemRule, FilesystemRuleKey, Policy, ProcessIds,
        ResolvedRequestContext, SandboxPaths, Verdict, VerdictSource, atomic_write_policy,
        trusted_project_policy_path,
    };

    use super::FilesystemApproval;
    use crate::store::{test_store, types::PolicyStore};

    fn filesystem_ctx() -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
            ),
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-cap".into()),
            package: None,
        }
    }

    #[tokio::test]
    async fn cli_approval_during_ui_wait_unblocks_filesystem_promptly() {
        // Regression: a CLI approval that arrives during the pre-verdict
        // UI-registration wait used to be ignored. The request would only
        // return after the (multi-minute) UI wait timed out.
        let store = Arc::new(test_store());

        let store_for_task = store.clone();

        let task = tokio::spawn(async move {
            store_for_task
                .request_filesystem_approval(
                    PathBuf::from("/repo/file.txt"),
                    FileAccess::Read,
                    filesystem_ctx(),
                )
                .await
        });

        // Wait for the request to register a pending. The task is now
        // inside the UI-registration wait loop.
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending
                    .pending
                    .keys()
                    .find(|k| k.starts_with("fs:"))
                    .cloned()
                {
                    break id;
                }
                assert!(
                    Instant::now() < deadline,
                    "request never registered a pending"
                );
                drop(inner);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        // No UI is registered; a CLI approval finishes the pending the same
        // way.
        store
            .finish_prompt::<FilesystemApproval>(
                &pending_id,
                FilesystemRuleKey {
                    path: "/repo/file.txt".into(),
                    access: FileAccess::Read,
                },
                Verdict::allowed(VerdictSource::policy_with_comment("cli")),
            )
            .await;

        let reply = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");

        assert!(
            reply.verdict.allowed,
            "expected allowed reply, got: {reply:?}"
        );
    }

    #[tokio::test]
    async fn filesystem_approval_blocks_when_sandbox_cannot_freeze() {
        // A real requester pid outside any agent-sandbox scope cannot be
        // frozen, so the prompt fails closed instead of letting it run on.
        let store = test_store();
        let ctx = ResolvedRequestContext {
            ids: ProcessIds::from_options(Some(std::process::id()), None),
            ..filesystem_ctx()
        };

        let reply = store
            .request_filesystem_approval(PathBuf::from("/repo/file.txt"), FileAccess::Read, ctx)
            .await;

        assert!(
            !reply.verdict.allowed,
            "expected blocked reply, got {reply:?}"
        );
        assert!(
            reply
                .error
                .as_deref()
                .is_some_and(|error| error.contains("freeze")),
            "block reason must name the freeze, got {reply:?}"
        );
        assert!(
            store.inner.lock().await.pending.pending.is_empty(),
            "failed freeze must not create an approval"
        );
    }

    #[tokio::test]
    async fn filesystem_allow_verdict_is_not_cached() {
        let store = test_store();

        let key = FilesystemRuleKey {
            path: PathBuf::from("/tmp/agent-sandbox-allow-not-cached"),
            access: FileAccess::Read,
        };

        store
            .finish_prompt::<FilesystemApproval>(
                "fs:test",
                key.clone(),
                Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once)),
            )
            .await;

        assert!(
            store
                .cached_reply::<FilesystemApproval>(&key)
                .await
                .is_none(),
            "allow verdicts must not be replayed from the cache"
        );
    }

    #[tokio::test]
    async fn filesystem_deny_verdict_is_cached_briefly() {
        let store = test_store();

        let key = FilesystemRuleKey {
            path: PathBuf::from("/tmp/agent-sandbox-deny-cached"),
            access: FileAccess::Read,
        };

        store
            .finish_prompt::<FilesystemApproval>(
                "fs:test",
                key.clone(),
                Verdict::denied(VerdictSource::User),
            )
            .await;

        let reply = store
            .cached_reply::<FilesystemApproval>(&key)
            .await
            .expect("deny verdict should be cached");

        assert!(!reply.verdict.allowed);
    }

    #[tokio::test]
    async fn check_filesystem_mutation_denies_when_any_endpoint_denied() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox")).expect("policy dir");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let allowed_path = project_root.join("allowed.txt");
        let denied_path = project_root.join("denied.txt");
        std::fs::write(&allowed_path, "ok").expect("write allowed");
        std::fs::write(&denied_path, "no").expect("write denied");

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            allowed_path.clone(),
            FileAccess::ReadWrite,
            "allow rename/link source",
        ));

        policy.filesystem.deny.push(FilesystemRule::new(
            denied_path.clone(),
            FileAccess::All,
            "deny destination",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-mutation".into()),
            package: None,
        };

        let source_reply = store
            .check_filesystem(allowed_path.clone(), FileAccess::ReadWrite, ctx.clone())
            .await;

        let dest_reply = store
            .check_filesystem(denied_path.clone(), FileAccess::ReadWrite, ctx)
            .await;

        assert!(
            source_reply.verdict.allowed,
            "rename/link source must pass read_write CheckFilesystem, got: {source_reply:?}"
        );

        assert!(
            !dest_reply.verdict.allowed,
            "rename/link destination must be denied on read_write, got: {dest_reply:?}"
        );
    }

    #[tokio::test]
    async fn check_filesystem_symlink_checks_target_read_and_linkpath_write() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox")).expect("policy dir");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let target_path = project_root.join("target.txt");
        let link_path = project_root.join("link.txt");
        std::fs::write(&target_path, "target").expect("write target");

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            target_path.clone(),
            FileAccess::Read,
            "allow symlink target read",
        ));

        policy.filesystem.deny.push(FilesystemRule::new(
            link_path.clone(),
            FileAccess::All,
            "deny symlink linkpath",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-symlink".into()),
            package: None,
        };

        let target_reply = store
            .check_filesystem(target_path.clone(), FileAccess::Read, ctx.clone())
            .await;

        let link_reply = store
            .check_filesystem(link_path.clone(), FileAccess::Write, ctx)
            .await;

        assert!(
            target_reply.verdict.allowed,
            "symlink target must pass read CheckFilesystem, got: {target_reply:?}"
        );

        assert!(
            !link_reply.verdict.allowed,
            "symlink linkpath must be denied on write, got: {link_reply:?}"
        );
    }

    #[tokio::test]
    async fn check_filesystem_allows_broad_static_glob_when_not_denied() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join("vendor/pkg")).expect("vendor dir");
        std::fs::create_dir_all(&home).expect("home");
        let nested_path = project_root.join("vendor/pkg/LICENSE");
        std::fs::write(&nested_path, "license").expect("write license");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-glob-check".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner.sandbox_filesystem_static_allow.insert(
                "sandbox:sandbox-glob-check".into(),
                vec![FilesystemRule::new(
                    project_root.join("vendor/**"),
                    FileAccess::Read,
                    "static allow vendor tree",
                )],
            );
        }

        let reply = store
            .check_filesystem(nested_path, FileAccess::Read, ctx)
            .await;

        assert!(
            reply.verdict.allowed,
            "broad static-allow globs must remain functional when not denied, got: {reply:?}"
        );

        assert_eq!(
            reply.verdict.source,
            VerdictSource::Static,
            "static allow should be evaluated through policyd after deny/inode checks"
        );
    }

    #[tokio::test]
    async fn check_filesystem_denies_policy_copies_despite_store_static_allow() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let export = dir.path().join("export.json");
        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            export.clone(),
            Duration::from_secs(30),
            false,
        ));
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-store-copy".into()),
            package: None,
        };
        store
            .inner
            .lock()
            .await
            .sandbox_filesystem_static_allow
            .insert("sandbox:sandbox-store-copy".into(), vec![
                FilesystemRule::new("/nix/store", FileAccess::All, "static store"),
            ]);

        let source = "/nix/store/0aji9km36ijxgsr0b5sjfjzvivgzdjir-source";
        for denied in [
            format!("{source}/.agent-sandbox/policy.json"),
            format!("{source}/.agent-sandbox/packages/omp.json"),
            format!("{source}/home/dot_config/agent-sandbox/policy.json"),
            format!("{source}/home/dot_config/agent-sandbox/packages/omp.json"),
            format!("{source}/.git/objects/ab/cdef"),
            export.to_string_lossy().into_owned(),
        ] {
            let reply = store
                .check_filesystem(PathBuf::from(&denied), FileAccess::Read, ctx.clone())
                .await;
            assert!(
                !reply.verdict.allowed,
                "{denied} must be denied, got {reply:?}"
            );
        }

        let reply = store
            .check_filesystem(
                PathBuf::from(format!("{source}/flake.nix")),
                FileAccess::Read,
                ctx,
            )
            .await;
        assert!(
            reply.verdict.allowed,
            "other store files stay allowed, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn check_filesystem_denies_when_broad_static_glob_matches_but_policy_denies() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox")).expect("policy dir");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let license_path = project_root.join("LICENSE");
        std::fs::write(&license_path, "license").expect("write license");

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy.filesystem.deny.push(FilesystemRule::new(
            license_path.clone(),
            FileAccess::All,
            "deny license",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-broad-glob-check-deny".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner.sandbox_filesystem_static_allow.insert(
                "sandbox:sandbox-broad-glob-check-deny".into(),
                vec![FilesystemRule::new(
                    project_root.join("**"),
                    FileAccess::All,
                    "broad static allow repo tree",
                )],
            );
        }

        let reply = store
            .check_filesystem(license_path, FileAccess::Read, ctx)
            .await;

        assert!(
            !reply.verdict.allowed,
            "policyd must deny before broad static-allow globs can allow, got: {reply:?}"
        );

        assert_eq!(reply.verdict.source, VerdictSource::policy());
    }

    #[test]
    fn expand_static_allow_rules_canonicalizes_home_symlinks() {
        use std::os::unix::fs::symlink;

        use super::expand_static_allow_rules;

        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let target = home.join("dotfiles/home/dot_omp");
        std::fs::create_dir_all(&target).expect("target dir");
        symlink(&target, home.join(".omp")).expect("symlink .omp");

        let rules = expand_static_allow_rules(
            &[FilesystemRule::new("~/.omp", FileAccess::ReadWrite, "")],
            Some(home),
            None,
        );

        assert_eq!(rules[0].path, target);

        assert!(
            rules[0].matches(
                &target.join("private_agent/config.yml"),
                FileAccess::ReadWrite,
                None,
            ),
            "static allow must match paths under the symlink target"
        );
    }
}
