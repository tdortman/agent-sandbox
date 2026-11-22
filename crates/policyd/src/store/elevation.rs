//! Policy store: elevation.

use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, ElevateReply, ResolvedRequestContext, RpcReply,
    ScopeActionReply, SudoRule,
};
use tokio::sync::oneshot;

use super::{
    decisions::DecisionAction,
    pending::{Decided, Decision, TOO_MANY_PENDING, VerdictExit},
    types::{Pending, PendingElevation, PolicyStore},
};
use crate::{error::PolicydError, wire::SudoScopeOp};

/// Trusted elevation binary resolved from an approval's argv: the
/// canonicalized store path to execute and the `argv[0]` name multi-call
/// binaries dispatch on.
struct ResolvedElevationArgv {
    prog: PathBuf,
    arg0_name: String,
}

const ELEVATION_PATH: &str = "/run/current-system/sw/bin";

impl PolicyStore {
    pub(crate) fn user_for_home(home: Option<&Path>) -> String {
        let Some(home) = home else {
            return "root".into();
        };

        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            let home_str = home.to_string_lossy();

            for line in passwd.lines() {
                let mut parts = line.splitn(7, ':');
                let _ = parts.next();
                let _ = parts.next();
                let _ = parts.next();
                let _ = parts.next();
                let _ = parts.next();
                let dir = parts.next().unwrap_or("");

                if dir == home_str.as_ref()
                    && let Some(user) = line.split(':').next()
                    && !user.is_empty()
                {
                    return user.to_string();
                }
            }
        }

        home.file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("nobody")
            .to_string()
    }

    pub(crate) fn elevation_env(home: Option<&Path>) -> HashMap<String, String> {
        let user = Self::user_for_home(home);

        HashMap::from([
            ("AGENT_SANDBOX_ELEVATE_USER".into(), user),
            ("PATH".into(), ELEVATION_PATH.into()),
        ])
    }

    fn resolve_elevation_argv(argv: &[String]) -> Result<ResolvedElevationArgv, PolicydError> {
        let Some(program) = argv.first() else {
            return Err(PolicydError::ArgvRequired);
        };

        let path = Path::new(program);

        let candidate = if path.is_absolute() {
            // Reject absolute paths outside the trusted system profile before
            // following links. The suffix must contain only normal
            // components, so traversal and dot aliases cannot escape it.
            let Some(relative) = program.strip_prefix("/run/current-system/") else {
                return Err(PolicydError::ElevationArgvNotAbsolute);
            };
            if relative
                .split('/')
                .any(|component| matches!(component, "." | ".."))
                || relative.is_empty()
                || !Path::new(relative)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(PolicydError::ElevationArgvNotAbsolute);
            }
            path.to_path_buf()
        } else {
            let mut components = path.components();
            if !matches!(
                (components.next(), components.next()),
                (Some(Component::Normal(_)), None)
            ) {
                return Err(PolicydError::ElevationArgvNotAbsolute);
            }
            Path::new(ELEVATION_PATH).join(program)
        };

        // Preserve the trusted candidate's name for multi-call binaries
        // (e.g. coreutils), which dispatch on argv[0], rather than the
        // canonical store path's name.
        let arg0_name = candidate.to_string_lossy().into_owned();

        // Canonicalize and require a regular file in the immutable Nix store.
        let canonical = candidate
            .canonicalize()
            .map_err(|_| PolicydError::ElevationArgvNotAbsolute)?;

        if !canonical.is_file() || !canonical.starts_with("/nix/store/") {
            return Err(PolicydError::ElevationArgvNotAbsolute);
        }

        Ok(ResolvedElevationArgv {
            prog: canonical,
            arg0_name,
        })
    }

    pub(crate) async fn exec_elevation(
        &self,
        argv: &[String],
        cwd: Option<&Path>,
        home: Option<&Path>,
    ) -> Result<ElevateReply, PolicydError> {
        let ResolvedElevationArgv { prog, arg0_name } = Self::resolve_elevation_argv(argv)?;

        let work_dir = cwd
            .and_then(|dir| dir.canonicalize().ok())
            .filter(|dir| dir.is_dir())
            .unwrap_or_else(|| PathBuf::from("/"));

        let mut cmd = tokio::process::Command::new(&prog);

        // Preserve the original argv[0] for multi-call binaries (e.g.
        // coreutils) that dispatch on the program name.
        cmd.arg0(&arg0_name)
            .args(&argv[1..])
            .current_dir(work_dir)
            .env_clear()
            .envs(Self::elevation_env(home))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd.output().await;

        match output {
            Ok(out) => {
                let exit_code = out.status.code().unwrap_or(1);
                let detail = format!(
                    "argv={argv:?} resolved={} exit_code={exit_code}",
                    prog.display()
                );
                Self::audit("exec", None, None, &detail);
                Ok(ElevateReply::executed(
                    exit_code,
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                ))
            }

            Err(err) => Ok(ElevateReply::exec_failed(err)),
        }
    }

    /// Reply for an argv policyd refuses to execute.
    pub(crate) fn unrunnable_elevation(err: &PolicydError) -> ElevateReply {
        let stderr = match err {
            PolicydError::ElevationArgvNotAbsolute => {
                "agent-sandbox: elevation argv[0] must be a bare command resolved via \
                 /run/current-system/sw/bin or an absolute path under /run/current-system, with a \
                 regular canonical target under /nix/store"
                    .into()
            }
            other => format!("agent-sandbox: {other}"),
        };

        ElevateReply {
            ok: true,
            allowed: false,
            exit_code: 1,
            stdout: String::new(),
            stderr,
        }
    }

    pub(crate) async fn finish_elevation(&self, pending_id: &str, result: ElevateReply) {
        let mut inner = self.inner.lock().await;

        if let Some(tx) = inner.pending.elevation_futures.remove(pending_id) {
            let _ = tx.send(result);
        }
    }

    /// Handles an elevation request: applies the sudo policy (allowing or
    /// denying outright), otherwise registers it as pending and awaits the
    /// UI verdict.
    pub async fn request_elevation(
        &self,
        argv: Vec<String>,
        ctx: ResolvedRequestContext,
    ) -> ElevateReply {
        match self.sudo_decided_verdict(&argv, &ctx).await {
            Some(verdict) if verdict.allowed => {
                return self
                    .exec_elevation(&argv, ctx.paths.cwd(), ctx.paths.home())
                    .await
                    .unwrap_or_else(|err| Self::unrunnable_elevation(&err));
            }

            Some(_) => {
                tracing::info!(argv = %argv.join(" "), "sudo deny (policy)");
                return ElevateReply::denied();
            }

            None => {}
        }

        // Approving a command that cannot run would leave nothing to execute.
        if let Err(err) = Self::resolve_elevation_argv(&argv) {
            return Self::unrunnable_elevation(&err);
        }

        let (tx, rx) = oneshot::channel();

        let mut inner = self.inner.lock().await;

        let queued = inner.pending.create("elev", |id, created_at| {
            Pending::Elevation(PendingElevation {
                id,
                created_at,
                argv: argv.clone(),
                ctx: ctx.clone(),
            })
        });

        let Some(pending) = queued else {
            tracing::warn!(
                pending_count = inner.pending.pending.len(),
                "elevation approval blocked (too many pending approvals)"
            );

            return blocked_elevation(TOO_MANY_PENDING);
        };

        inner
            .pending
            .elevation_futures
            .insert(pending.id().to_owned(), tx);

        drop(inner);

        let pending_id = pending.id();
        let detail = format!("id={pending_id} argv={argv:?}");
        Self::audit("pending", None, None, &detail);
        self.announce(&pending, &ctx).await;

        match self.wait_for_verdict(&ctx, rx).await {
            Ok(reply) => reply,
            Err(VerdictExit::ChannelClosed) => ElevateReply::denied(),
            Err(VerdictExit::NoUi) => {
                self.abandon_pending(|board| &mut board.elevation_futures, pending_id)
                    .await;

                blocked_elevation(
                    "agent-sandbox: no policy UI registered (agent-sandbox-ui or auto-spawn)",
                )
            }
            Err(VerdictExit::Timeout) => {
                self.abandon_pending(|board| &mut board.elevation_futures, pending_id)
                    .await;

                Self::audit("timeout", None, None, pending_id);

                blocked_elevation("agent-sandbox: elevation timed out (no response from policy UI)")
            }
        }
    }

    /// Apply a decision to a taken elevation pending. An approval runs the
    /// command and answers the waiter with its outcome.
    pub(super) async fn decide_elevation(
        &self,
        elev: PendingElevation,
        decision: Decision,
    ) -> Decided {
        let Decision {
            wire,
            scope,
            target,
            action,
        } = decision;

        let argv = match elevation_target(&elev, scope, target.as_ref()) {
            Ok(argv) => argv,
            Err(err) => return Decided::put_back(Pending::Elevation(elev), err.into()),
        };

        let scope_wire = Self::scope_wire_for_context(wire, &elev.ctx);

        if action == DecisionAction::Deny {
            if scope == ApprovalScope::Once {
                let detail = format!("id={} argv={argv:?}", elev.id);
                Self::audit(action.audit_verb(), None, None, &detail);

                self.finish_elevation(&elev.id, ElevateReply::denied())
                    .await;

                return Decided::done(RpcReply::ScopeAction(ScopeActionReply::ok_sudo(
                    argv, scope, None,
                )));
            }

            let reply = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv,
                        scope,
                        wire: scope_wire,
                    },
                    action,
                )
                .await;

            if !reply.scope_succeeded() {
                return Decided::put_back(Pending::Elevation(elev), reply);
            }

            self.finish_elevation(&elev.id, ElevateReply::denied())
                .await;

            return Decided::done(reply);
        }

        let saved_path = if scope == ApprovalScope::Once {
            None
        } else {
            let reply = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv: argv.clone(),
                        scope,
                        wire: scope_wire.clone(),
                    },
                    action,
                )
                .await;

            if !reply.scope_succeeded() {
                return Decided::put_back(Pending::Elevation(elev), reply);
            }

            reply.scope_path()
        };

        let detail = format!("id={} argv={:?} rule_argv={argv:?}", elev.id, elev.argv);
        Self::audit(action.audit_verb(), None, None, &detail);

        let executed = self
            .exec_elevation(
                &elev.argv,
                elev.ctx.paths.cwd().or_else(|| scope_wire.paths.cwd()),
                elev.ctx.paths.home().or_else(|| scope_wire.paths.home()),
            )
            .await;

        let elevation = match executed {
            Ok(reply) => reply,
            Err(err) => {
                self.finish_elevation(&elev.id, Self::unrunnable_elevation(&err))
                    .await;

                return Decided::done(err.into());
            }
        };

        self.finish_elevation(&elev.id, elevation).await;

        Decided::done(RpcReply::ScopeAction(
            ScopeActionReply::ok_elevation_approve(scope, saved_path.map(PathBuf::from)),
        ))
    }
}

/// Reply to an elevation request that was neither run nor denied by a
/// decision.
fn blocked_elevation(stderr: &str) -> ElevateReply {
    ElevateReply {
        ok: true,
        allowed: false,
        exit_code: 1,
        stdout: String::new(),
        stderr: stderr.into(),
    }
}

/// Validate a decision's approval target against the pending command.
fn elevation_target(
    pending: &PendingElevation,
    scope: ApprovalScope,
    target: Option<&ApprovalTarget>,
) -> Result<Vec<String>, PolicydError> {
    let argv = match target {
        None => pending.argv.clone(),
        Some(ApprovalTarget::SudoCommand { argv }) => argv.clone(),
        Some(_) => return Err(PolicydError::InvalidDecisionTarget),
    };

    let rule = SudoRule::new(argv, "");

    if !rule.matches(&pending.argv) {
        return Err(PolicydError::InvalidDecisionTarget);
    }

    if scope == ApprovalScope::Once && rule.argv != pending.argv {
        return Err(PolicydError::InvalidDecisionTarget);
    }

    Ok(rule.argv)
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, Instant},
    };

    use agent_sandbox_core::{
        ApprovalScope, ElevateReply, Policy, ProcessIds, ResolvedRequestContext, RpcReply,
        SandboxPaths, SudoRule, SudoSection, atomic_write_policy,
    };
    use tokio::{net::UnixStream, sync::Mutex};

    use super::ELEVATION_PATH;
    use crate::{
        store::{
            DecisionAction, PolicyStore, UiSessionContext, test_args, test_store, types::UiClient,
        },
        wire::{ScopeWire, SudoScopeOp},
    };

    const UI_SESSION: &str = "ui-session";
    const SANDBOX_SESSION: &str = "sandbox-sudo";

    /// Store whose home policy carries `sudo`, plus a request context routed
    /// to the one registered UI session.
    struct SudoLadder {
        _dir: tempfile::TempDir,
        store: PolicyStore,
        ctx: ResolvedRequestContext,
    }

    async fn sudo_ladder(sudo: SudoSection) -> SudoLadder {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");

        let policy = Policy {
            sudo,
            ..Policy::default()
        };

        atomic_write_policy(&policy_dir.join("policy.json"), &policy, None, None, None)
            .expect("write policy");

        let store = PolicyStore::new(test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ));

        let (stream, _peer) = UnixStream::pair().expect("unix stream pair");

        {
            let mut inner = store.inner.lock().await;

            inner.ui_clients.insert(1, UiClient {
                session_id: UI_SESSION.into(),
                writer: Arc::new(Mutex::new(stream.into_split().1)),
            });

            inner
                .ui_context_by_session
                .insert(UI_SESSION.into(), UiSessionContext {
                    sandbox_session_id: Some(SANDBOX_SESSION.into()),
                    ..Default::default()
                });
        }

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&home, &home, home.join("project")),
            ids: ProcessIds::default(),
            sandbox_session_id: Some(SANDBOX_SESSION.into()),
            package: None,
        };

        SudoLadder {
            _dir: dir,
            store,
            ctx,
        }
    }

    /// Record a Session runtime decision for `argv` the way a UI verdict does.
    async fn decide_for_session(ladder: &SudoLadder, argv: &[&str], action: DecisionAction) {
        let reply = ladder
            .store
            .apply_sudo_scope(
                SudoScopeOp {
                    argv: argv.iter().map(ToString::to_string).collect(),
                    scope: ApprovalScope::Session,
                    wire: ScopeWire::from_resolved(&ladder.ctx, Some(UI_SESSION.into())),
                },
                action,
            )
            .await;

        assert!(
            matches!(reply, RpcReply::ScopeAction(_)),
            "session decision must apply, got {reply:?}"
        );
    }

    fn system_profile_true() -> Option<PathBuf> {
        let path = Path::new(ELEVATION_PATH).join("true");
        path.is_file().then_some(path)
    }

    fn elevation_ctx() -> ResolvedRequestContext {
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
    async fn cli_approval_during_ui_wait_unblocks_elevation_promptly() {
        // Regression: a CLI approval that arrives during the pre-verdict
        // UI-registration wait used to be ignored. The request would only
        // return after the (multi-minute) UI wait timed out.
        if system_profile_true().is_none() {
            return;
        }
        let store = Arc::new(test_store());

        let store_for_task = store.clone();

        let task = tokio::spawn(async move {
            store_for_task
                .request_elevation(vec!["true".into()], elevation_ctx())
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
                    .find(|k| k.starts_with("elev:"))
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
        let reply = ElevateReply::executed(0, String::new(), String::new());

        store.finish_elevation(&pending_id, reply).await;

        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");

        assert!(result.allowed, "expected allowed reply, got: {result:?}");
    }

    #[tokio::test]
    async fn unrunnable_elevation_fails_without_prompting() {
        let store = test_store();

        let reply = tokio::time::timeout(
            Duration::from_secs(2),
            store.request_elevation(vec!["-n".into(), "true".into()], elevation_ctx()),
        )
        .await
        .expect("request must fail immediately");

        assert!(!reply.allowed, "got: {reply:?}");
        assert!(
            reply.stderr.contains("elevation argv[0]"),
            "unrunnable command must be rejected before it is queued: {reply:?}"
        );
    }

    #[tokio::test]
    async fn forged_home_does_not_auto_elevate_via_attacker_policy() {
        use crate::store::types::TrustedPeer;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_home = tmp.path().join("home/user");
        let evil = tmp.path().join("evil");
        std::fs::create_dir_all(real_home.join(".config/agent-sandbox")).expect("real config");
        std::fs::create_dir_all(evil.join(".config/agent-sandbox")).expect("evil config");

        std::fs::write(
            real_home.join(".config/agent-sandbox/policy.json"),
            r#"{"network":{"direct":{"allow":[],"deny":[]},"http":{"allow":[],"deny":[]}},"sudo":{"allow":[],"deny":[]},"filesystem":{"allow":[],"deny":[]},"resources":{"allow":[],"deny":[]}}"#,
        )
        .expect("real policy");

        std::fs::write(
            evil.join(".config/agent-sandbox/policy.json"),
            serde_json::to_string(&Policy {
                sudo: agent_sandbox_core::SudoSection {
                    allow: vec![SudoRule::new(vec!["id".into()], "evil")],
                    deny: vec![],
                },
                ..Policy::default()
            })
            .expect("serialize"),
        )
        .expect("evil policy");

        let store = test_store();
        let uid = nix::unistd::getuid().as_raw();

        let forged = ResolvedRequestContext {
            paths: SandboxPaths::from_wire(Some(evil.clone()), Some(evil.clone()), Some(evil)),
            ids: ProcessIds::from_options(Some(0), Some(uid)),
            sandbox_session_id: None,
            package: None,
        };

        let resolved = store.resolve_context_with_peer(&forged, Some(TrustedPeer { pid: 0, uid }));

        assert!(
            !store
                .sudo_decided_verdict(&["id".into()], &resolved)
                .await
                .is_some_and(|verdict| verdict.allowed),
            "forged home must not auto-approve elevation via attacker sudo policy"
        );
    }

    #[tokio::test]
    async fn sudo_policy_deny_beats_session_allow() {
        let ladder = sudo_ladder(SudoSection {
            allow: vec![],
            deny: vec![SudoRule::new(vec!["frobnicate".into()], "never")],
        })
        .await;

        decide_for_session(&ladder, &["frobnicate"], DecisionAction::Approve).await;

        let reply = ladder
            .store
            .request_elevation(vec!["frobnicate".into()], ladder.ctx.clone())
            .await;

        assert_eq!(
            reply.stderr,
            ElevateReply::denied().stderr,
            "a policy deny must win over a session allow, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn sudo_session_deny_beats_policy_allow() {
        let ladder = sudo_ladder(SudoSection {
            allow: vec![SudoRule::new(vec!["frobnicate".into()], "trusted")],
            deny: vec![],
        })
        .await;

        // The session entry is an argv prefix with a glob.
        decide_for_session(&ladder, &["frob*"], DecisionAction::Deny).await;

        let reply = ladder
            .store
            .request_elevation(
                vec!["frobnicate".into(), "--now".into()],
                ladder.ctx.clone(),
            )
            .await;

        assert_eq!(
            reply.stderr,
            ElevateReply::denied().stderr,
            "a session deny must win over a policy allow, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn sudo_session_allow_runs_when_policy_is_silent() {
        if system_profile_true().is_none() {
            return;
        }

        let ladder = sudo_ladder(SudoSection::default()).await;
        decide_for_session(&ladder, &["true"], DecisionAction::Approve).await;

        let reply = tokio::time::timeout(
            Duration::from_secs(2),
            ladder
                .store
                .request_elevation(vec!["true".into()], ladder.ctx.clone()),
        )
        .await
        .expect("a session allow must run without waiting for a prompt");

        assert!(
            reply.allowed && reply.exit_code == 0,
            "a session allow must run the command, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn elevation_rejects_executable_outside_nix_store() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fake_bin = tmp.path().join("evil");
        std::fs::write(&fake_bin, b"#!/bin/sh\necho pwned\n").expect("write fake binary");
        let store = test_store();

        let err = store
            .exec_elevation(&[fake_bin.to_string_lossy().into_owned()], None, None)
            .await
            .expect_err("must reject");

        assert!(
            matches!(err, crate::error::PolicydError::ElevationArgvNotAbsolute),
            "expected ElevationArgvNotAbsolute, got {err:?}"
        );
    }

    #[tokio::test]
    async fn elevation_rejects_direct_nix_store_path() {
        let Some(profile_true) = system_profile_true() else {
            return;
        };

        let store_path = profile_true
            .canonicalize()
            .expect("system-profile true must resolve");

        assert!(store_path.starts_with("/nix/store/"));
        let store = test_store();

        let err = store
            .exec_elevation(&[store_path.to_string_lossy().into_owned()], None, None)
            .await
            .expect_err("direct Nix store paths must be rejected");

        assert!(
            matches!(err, crate::error::PolicydError::ElevationArgvNotAbsolute),
            "expected ElevationArgvNotAbsolute, got {err:?}"
        );
    }

    #[tokio::test]
    async fn elevation_resolves_bare_system_profile_binary() {
        let Some(profile_true) = system_profile_true() else {
            return;
        };

        let canonical = profile_true
            .canonicalize()
            .expect("system-profile true must resolve");

        assert!(
            canonical.is_file() && canonical.starts_with("/nix/store/"),
            "system-profile true must be a regular Nix-store file: {canonical:?}"
        );

        let store = test_store();

        let reply = store
            .exec_elevation(&["true".into()], None, None)
            .await
            .expect("true must resolve and execute");

        assert_eq!(reply.exit_code, 0, "true must exit 0, got {reply:?}");
    }

    #[tokio::test]
    async fn elevation_accepts_absolute_system_profile_binary() {
        let Some(profile_true) = system_profile_true() else {
            return;
        };

        let store = test_store();

        let reply = store
            .exec_elevation(&[profile_true.to_string_lossy().into_owned()], None, None)
            .await
            .expect("absolute system-profile true must resolve and execute");

        assert_eq!(
            reply.exit_code, 0,
            "absolute system-profile true must exit 0, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn elevation_rejects_traversal_symlink_alias() {
        let tmp = tempfile::tempdir_in("/tmp").expect("tempdir");
        let alias = tmp.path().join("rm");

        std::os::unix::fs::symlink("/nix/store/fake-coreutils/bin/true", &alias)
            .expect("create symlink alias");

        let name = tmp
            .path()
            .file_name()
            .expect("tempdir name")
            .to_string_lossy();

        let traversal = format!("../../../../tmp/{name}/rm");
        let store = test_store();

        let err = store
            .exec_elevation(&[traversal], None, None)
            .await
            .expect_err("relative symlink alias must be rejected");

        assert!(
            matches!(err, crate::error::PolicydError::ElevationArgvNotAbsolute),
            "expected ElevationArgvNotAbsolute for traversal alias, got {err:?}"
        );
    }

    #[tokio::test]
    async fn elevation_rejects_absolute_traversal_symlink_alias() {
        let tmp = tempfile::tempdir_in("/tmp").expect("tempdir");
        let alias = tmp.path().join("rm");

        std::os::unix::fs::symlink("/nix/store/fake-coreutils/bin/true", &alias)
            .expect("create symlink alias");

        let name = tmp
            .path()
            .file_name()
            .expect("tempdir name")
            .to_string_lossy();

        let traversal = format!("/run/current-system/../../../../tmp/{name}/rm");
        let store = test_store();

        let err = store
            .exec_elevation(&[traversal], None, None)
            .await
            .expect_err("absolute traversal alias must be rejected");

        assert!(
            matches!(err, crate::error::PolicydError::ElevationArgvNotAbsolute),
            "expected ElevationArgvNotAbsolute for absolute traversal alias, got {err:?}"
        );
    }

    #[tokio::test]
    async fn elevation_rejects_symlink_alias_outside_trusted_root() {
        // A symlink outside the trusted root must be rejected before links
        // are followed. Otherwise an attacker could create /tmp/rm pointing
        // at a multi-call binary and spoof its applet dispatch via argv[0].
        let tmp = tempfile::tempdir().expect("tempdir");

        let alias = tmp.path().join("rm");

        std::os::unix::fs::symlink("/nix/store/fake-coreutils/bin/true", &alias)
            .expect("create symlink alias");

        let store = test_store();

        let err = store
            .exec_elevation(&[alias.to_string_lossy().into_owned()], None, None)
            .await
            .expect_err("symlink alias must be rejected");

        assert!(
            matches!(err, crate::error::PolicydError::ElevationArgvNotAbsolute),
            "expected ElevationArgvNotAbsolute for symlink alias, got {err:?}"
        );
    }
}
