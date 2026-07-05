//! Policy store: filesystem (fanotify monitor spawn and declarative checks).
use std::path::{Path, PathBuf};

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_sandbox_core::{
    FileAccess, FilesystemCheckReply, FilesystemMonitorReply, FilesystemRule, InodeIdentity,
    UiPush, expand_policy_path,
};
use tokio::sync::oneshot;
use tokio::time;
use uuid::Uuid;

use super::types::{
    FilesystemVerdictKey, MAX_PENDING_APPROVALS, MAX_STATIC_ALLOW_RULES, MAX_WAITERS_PER_PENDING,
    Pending, PendingFilesystem, PolicyStore, VerdictEntry, enforce_verdict_cache_limit,
};
use crate::store::ui_route::UiRoute;
use crate::wire::{FilesystemCheckRequest, FilesystemMonitorRequest, UiSpawnContext, UiSpawnGate};

/// Timeout for waiting for the fsmon `ready` line.
const FSMON_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a **deny** filesystem verdict is cached after a decision.
///
/// Concurrent opens of the same path while a prompt is in flight are joined
/// via [`dedup_or_create_pending_filesystem`]; this TTL only covers rapid
/// re-denials (or hardlink aliases) without re-prompting. Allow verdicts are
/// not cached: a one-shot approval must not silently cover later opens unless
/// the user chose session/global/project scope (which installs a real rule).
const FILESYSTEM_VERDICT_DENY_CACHE_TTL: Duration = Duration::from_secs(2);

struct PendingFsResult {
    id: String,
    is_new: bool,
    rx: oneshot::Receiver<FilesystemCheckReply>,
}

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
        req: FilesystemMonitorRequest,
    ) -> FilesystemMonitorReply {
        let cmd = match &self.args.fs_monitor_cmd {
            Some(c) => c.clone(),
            None => {
                return FilesystemMonitorReply::failed("fs_monitor_cmd not configured");
            }
        };

        if req.peer_pid == 0 {
            return FilesystemMonitorReply::failed("cannot determine monitor target pid");
        }

        if req.static_allow.len() > MAX_STATIC_ALLOW_RULES {
            return FilesystemMonitorReply::failed("too many filesystem static allow rules");
        }

        let ctx = self.resolve_context(&req.ctx);
        let cwd = ctx.paths.cwd_path();
        let home = ctx.paths.home_path();
        let project_root = ctx.paths.project_root_path();

        let sandbox_session_id = ctx.sandbox_session_id.clone();
        let socket_str = self.args.sandbox_socket.to_string_lossy().to_string();

        let mut command = Command::new(&cmd);
        command
            .arg("--pid")
            .arg(req.peer_pid.to_string())
            .arg("--socket")
            .arg(&socket_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        if let Some(c) = &cwd {
            command.arg("--cwd").arg(c);
        }
        if let Some(h) = &home {
            command.arg("--home").arg(h);
        }
        if let Some(p) = &project_root {
            command.arg("--project-root").arg(p);
        }

        let static_allow_input = req.static_allow.clone();
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
            return FilesystemMonitorReply::failed("stdout not captured");
        };

        tracing::info!(peer_pid = req.peer_pid, "spawning fsmon");
        let peer_pid = req.peer_pid;
        let result = tokio::time::timeout(
            FSMON_READY_TIMEOUT,
            tokio::task::spawn_blocking(move || wait_fsmon_ready(stdout)),
        )
        .await;

        match result {
            Ok(Ok(Ok(()))) => {
                tracing::info!(peer_pid, "fsmon ready");
                FilesystemMonitorReply::active()
            }
            Ok(Ok(Err(err))) => FilesystemMonitorReply::failed(format!("ready wait failed: {err}")),
            Ok(Err(err)) => {
                tracing::error!(error = %err, "fsmon ready wait panicked");
                FilesystemMonitorReply::failed("internal error waiting for fsmon")
            }
            Err(_) => FilesystemMonitorReply::failed("fsmon ready timeout"),
        }
    }

    pub async fn check_filesystem(&self, req: FilesystemCheckRequest) -> FilesystemCheckReply {
        let path = req.path;
        let access =
            agent_sandbox_core::normalize_directory_traverse_access(&path, req.access);
        let resolved = self.resolve_context(&req.ctx);
        if let Some(source) = self
            .filesystem_allow_source(&path, access, &resolved)
            .await
        {
            if source == "deny" {
                return FilesystemCheckReply::denied("deny", path, access);
            }
            return FilesystemCheckReply::allowed(source, path, access);
        }
        self.request_filesystem_approval(FilesystemCheckRequest {
            path,
            access,
            ctx: resolved,
        })
        .await
    }

    pub async fn request_filesystem_approval(
        &self,
        req: FilesystemCheckRequest,
    ) -> FilesystemCheckReply {
        let FilesystemCheckRequest { path, access, ctx } = req;
        let resolved = self.resolve_context(&ctx);
        let wire_ids = resolved.ids;
        let cwd = resolved.paths.cwd_path();
        let home = resolved.paths.home_path();
        let project_root = resolved.paths.project_root_path();
        let sandbox_session_id = resolved.sandbox_session_id.clone();
        if self
            .filesystem_policy_denied(&path, access, &resolved)
            .await
        {
            return FilesystemCheckReply::denied("deny", path.clone(), access);
        }
        if !self.args.interactive_approval {
            return FilesystemCheckReply::denied("blocked", path.clone(), access);
        }

        if let Some(reply) = self.check_filesystem_verdict_cache(&path, access).await {
            return reply;
        }

        let result = match self
            .dedup_or_create_pending_filesystem(
                &path,
                access,
                cwd.as_deref(),
                home.as_deref(),
                project_root.as_deref(),
                sandbox_session_id.as_deref(),
            )
            .await
        {
            Ok(r) => r,
            Err(reply) => return reply,
        };

        let route = UiRoute::new(cwd.clone(), project_root.clone())
            .with_sandbox_session(sandbox_session_id.clone());

        if result.is_new {
            tracing::info!(
                pending_id = %result.id,
                path = %path.display(),
                access = ?access,
                sandbox_session_id = ?sandbox_session_id,
                "filesystem approval pending; run agent-sandbox-approve pending or respond in the policy UI"
            );
            let push = UiPush::FilesystemRequest {
                id: result.id.clone(),
                path: path.clone(),
                access,
                cwd: cwd.clone(),
                home: home.clone(),
                project_root: project_root.clone(),
            };
            self.notify_standalone_ui(&route, &push).await;

            if !self.has_standalone_ui_for_route(&route).await {
                let mut spawn_uid = wire_ids.uid();
                if spawn_uid.is_none_or(|u| u == 0)
                    && let Some(h) = &home
                {
                    spawn_uid =
                        nix::unistd::User::from_name(&Self::user_for_home(Some(h.as_path())))
                            .ok()
                            .flatten()
                            .map(|u| u.uid.as_raw());
                }
                if spawn_uid.is_none_or(|u| u == 0)
                    && let Some(session_id) = sandbox_session_id.as_deref()
                {
                    spawn_uid = self
                        .sandbox_sessions
                        .read()
                        .ok()
                        .and_then(|sessions| sessions.get(session_id).map(|reg| reg.owner_uid))
                        .filter(|uid| *uid > 0);
                }
                let spawn = UiSpawnContext {
                    gate: UiSpawnGate {
                        has_matching_ui: false,
                    },
                    uid: spawn_uid,
                    home: home.as_deref(),
                    cwd: cwd.as_deref(),
                    project_root: project_root.as_deref(),
                    sandbox_session_id: sandbox_session_id.as_deref(),
                };
                self.spawn_policy_ui(spawn).await;
            }
        }

        self.await_filesystem_verdict(&route, &result.id, path, access, result.rx)
            .await
    }
    async fn check_filesystem_verdict_cache(
        &self,
        path: &Path,
        access: FileAccess,
    ) -> Option<FilesystemCheckReply> {
        let inner = self.inner.lock().await;
        if let Some(entry) = inner.filesystem_verdict_cache.get(&FilesystemVerdictKey {
            path: path.to_path_buf(),
            access,
        }) && !entry.allowed
            && entry.time.elapsed() < FILESYSTEM_VERDICT_DENY_CACHE_TTL
        {
            return Some(FilesystemCheckReply::denied(
                entry.source.clone(),
                path.to_path_buf(),
                access,
            ));
        }
        // Inode-based cache lookup: hardlinks share the same inode, so a
        // deny verdict for one path covers all hardlinks at any path.
        if let Some(identity) = InodeIdentity::from_path(path) {
            for (key, entry) in &inner.filesystem_verdict_cache {
                if entry.allowed || entry.time.elapsed() >= FILESYSTEM_VERDICT_DENY_CACHE_TTL {
                    continue;
                }
                if !key.access.covers(access) {
                    continue;
                }
                if InodeIdentity::from_path(&key.path).is_some_and(|id| id == identity) {
                    return Some(FilesystemCheckReply::denied(
                        entry.source.clone(),
                        path.to_path_buf(),
                        access,
                    ));
                }
            }
        }
        drop(inner);
        None
    }

    async fn dedup_or_create_pending_filesystem(
        &self,
        path: &Path,
        access: FileAccess,
        cwd: Option<&Path>,
        home: Option<&Path>,
        project_root: Option<&Path>,
        sandbox_session_id: Option<&str>,
    ) -> Result<PendingFsResult, FilesystemCheckReply> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;
        // Deduplicate: if a pending already exists for the same file and
        // access type, join its waiters instead of creating a new prompt.
        if let Some(existing_id) = inner.pending.values().find_map(|p| {
            let Pending::Filesystem(fs) = p else {
                return None;
            };
            (fs.path == path && fs.access == access).then(|| fs.id.clone())
        }) {
            let waiter_count = inner
                .filesystem_futures
                .get(&existing_id)
                .map_or(0, Vec::len);
            if waiter_count >= MAX_WAITERS_PER_PENDING {
                return Err(FilesystemCheckReply::blocked(
                    "agent-sandbox: too many waiters for one filesystem approval",
                    path.to_path_buf(),
                    access,
                ));
            }
            inner
                .filesystem_futures
                .entry(existing_id.clone())
                .or_default()
                .push(tx);
            drop(inner);
            return Ok(PendingFsResult {
                id: existing_id,
                is_new: false,
                rx,
            });
        }
        if inner.pending.len() >= MAX_PENDING_APPROVALS {
            return Err(FilesystemCheckReply::blocked(
                "agent-sandbox: too many pending approvals",
                path.to_path_buf(),
                access,
            ));
        }
        let pending_id = format!("fs:{}", Uuid::now_v7().simple());
        inner
            .filesystem_futures
            .insert(pending_id.clone(), vec![tx]);
        inner.pending.insert(
            pending_id.clone(),
            Pending::Filesystem(PendingFilesystem {
                id: pending_id.clone(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |d| d.as_secs_f64()),
                path: path.to_path_buf(),
                access,
                cwd: cwd.map(PathBuf::from),
                home: home.map(PathBuf::from),
                project_root: project_root.map(PathBuf::from),
                sandbox_session_id: sandbox_session_id.map(String::from),
            }),
        );
        drop(inner);
        Ok(PendingFsResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    async fn await_filesystem_verdict(
        &self,
        route: &UiRoute,
        pending_id: &str,
        path: PathBuf,
        access: FileAccess,
        rx: oneshot::Receiver<FilesystemCheckReply>,
    ) -> FilesystemCheckReply {
        // Race UI registration against the verdict channel so a CLI approval
        // can unblock the request even if no policy UI ever appears.
        // Preserve the existing two-timeout contract: a short wait for the
        // UI to register, then a full approval_timeout for the verdict.
        let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
        let ui_deadline = Instant::now() + ui_wait;
        tokio::pin!(rx);
        let mut logged_ui_wait = false;
        loop {
            if self.has_standalone_ui_for_route(route).await {
                tracing::info!(
                    pending_id,
                    path = %path.display(),
                    access = ?access,
                    "filesystem approval waiting for user decision"
                );
                break;
            }
            if !logged_ui_wait {
                tracing::info!(
                    pending_id,
                    path = %path.display(),
                    access = ?access,
                    "filesystem approval waiting for policy UI to register"
                );
                logged_ui_wait = true;
            }
            let now = Instant::now();
            if now >= ui_deadline {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(pending_id);
                inner.filesystem_futures.remove(pending_id);
                drop(inner);
                return FilesystemCheckReply::blocked(
                    "agent-sandbox: no standalone filesystem policy UI registered (agent-sandbox-ui or auto-spawn)",
                    path.clone(),
                    access,
                );
            }
            let sleep_dur = (ui_deadline - now).min(Duration::from_millis(50));
            tokio::select! {
                biased;
                () = time::sleep(sleep_dur) => {}
                result = &mut rx => {
                    return result.unwrap_or_else(|_| FilesystemCheckReply::denied("blocked", path.clone(), access));
                }
            }
        }

        match time::timeout(self.args.approval_timeout, &mut rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => FilesystemCheckReply::denied("blocked", path.clone(), access),
            Err(_) => {
                let mut inner = self.inner.lock().await;
                inner.pending.remove(pending_id);
                inner.filesystem_futures.remove(pending_id);
                drop(inner);
                FilesystemCheckReply::blocked(
                    "agent-sandbox: filesystem approval timed out (no response from policy UI)",
                    path,
                    access,
                )
            }
        }
    }

    pub(crate) async fn finish_filesystem(
        &self,
        pending_id: &str,
        path: PathBuf,
        access: FileAccess,
        allowed: bool,
        source: &str,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.filesystem_futures.remove(pending_id) {
            let reply = if allowed {
                FilesystemCheckReply::allowed(source, path.clone(), access)
            } else {
                FilesystemCheckReply::denied(source, path.clone(), access)
            };
            for tx in waiters {
                let _ = tx.send(reply.clone());
            }
        }
        // Cache deny verdicts briefly so rapid re-opens of a denied path (or
        // its hardlinks) fail closed without spamming prompts.
        if !allowed {
            inner.filesystem_verdict_cache.insert(
                FilesystemVerdictKey { path, access },
                VerdictEntry {
                    allowed: false,
                    source: source.to_string(),
                    time: Instant::now(),
                },
            );
            enforce_verdict_cache_limit(&mut inner.filesystem_verdict_cache);
        }
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{FileAccess, ProcessIds, SandboxPaths};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::store::types::{PolicyStore, PolicydArgs};
    use crate::wire::{FilesystemCheckRequest, MergeContext};

    fn test_store() -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: "/tmp/test.sock".into(),
            sandbox_socket: "/tmp/test-sandbox.sock".into(),
            declarative: "/tmp/declarative.json".into(),
            export_json: "/tmp/export.json".into(),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        })
    }

    fn filesystem_request(path: &Path, access: FileAccess) -> FilesystemCheckRequest {
        FilesystemCheckRequest {
            path: path.into(),
            access,
            ctx: MergeContext {
                paths: SandboxPaths::from_wire(
                    Some("/repo".into()),
                    Some("/home/user".into()),
                    Some("/repo".into()),
                ),
                ids: ProcessIds::from_options(Some(0), Some(1000)),
                sandbox_session_id: Some("sandbox-cap".into()),
            },
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
                .request_filesystem_approval(filesystem_request(
                    Path::new("/repo/file.txt"),
                    FileAccess::Read,
                ))
                .await
        });
        // Wait for the request to register a pending. The task is now
        // inside the UI-registration wait loop.
        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner.pending.keys().find(|k| k.starts_with("fs:")).cloned() {
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
        // No UI is registered; CLI approves via the same path
        // `apply_pending_filesystem_decision` would use.
        store
            .finish_filesystem(
                &pending_id,
                "/repo/file.txt".into(),
                FileAccess::Read,
                true,
                "cli",
            )
            .await;
        let reply = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");
        assert!(reply.allowed, "expected allowed reply, got: {reply:?}");
    }

    #[tokio::test]
    async fn filesystem_allow_verdict_is_not_cached() {
        let store = test_store();
        let path = PathBuf::from("/tmp/agent-sandbox-allow-not-cached");
        store
            .finish_filesystem("fs:test", path.clone(), FileAccess::Read, true, "once")
            .await;
        assert!(
            store
                .check_filesystem_verdict_cache(&path, FileAccess::Read)
                .await
                .is_none(),
            "allow verdicts must not be replayed from the cache"
        );
    }

    #[tokio::test]
    async fn filesystem_deny_verdict_is_cached_briefly() {
        let store = test_store();
        let path = PathBuf::from("/tmp/agent-sandbox-deny-cached");
        store
            .finish_filesystem("fs:test", path.clone(), FileAccess::Read, false, "denied")
            .await;
        let reply = store
            .check_filesystem_verdict_cache(&path, FileAccess::Read)
            .await
            .expect("deny verdict should be cached");
        assert!(!reply.allowed);
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

        let policy_path = agent_sandbox_core::trusted_project_policy_path(&project_root)
            .expect("trusted project policy path");
        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .filesystem
            .allow
            .push(agent_sandbox_core::FilesystemRule::new(
                allowed_path.clone(),
                agent_sandbox_core::FileAccess::ReadWrite,
                "allow rename/link source",
            ));
        policy
            .filesystem
            .deny
            .push(agent_sandbox_core::FilesystemRule::new(
                denied_path.clone(),
                agent_sandbox_core::FileAccess::All,
                "deny destination",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = PolicyStore::new(PolicydArgs {
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
        });

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = MergeContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-mutation".into()),
        };

        let source_reply = store
            .check_filesystem(FilesystemCheckRequest {
                path: allowed_path.clone(),
                access: FileAccess::ReadWrite,
                ctx: ctx.clone(),
            })
            .await;
        let dest_reply = store
            .check_filesystem(FilesystemCheckRequest {
                path: denied_path.clone(),
                access: FileAccess::ReadWrite,
                ctx,
            })
            .await;

        assert!(
            source_reply.allowed,
            "rename/link source must pass read_write CheckFilesystem, got: {source_reply:?}"
        );
        assert!(
            !dest_reply.allowed,
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

        let policy_path = agent_sandbox_core::trusted_project_policy_path(&project_root)
            .expect("trusted project policy path");
        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .filesystem
            .allow
            .push(agent_sandbox_core::FilesystemRule::new(
                target_path.clone(),
                FileAccess::Read,
                "allow symlink target read",
            ));
        policy
            .filesystem
            .deny
            .push(agent_sandbox_core::FilesystemRule::new(
                link_path.clone(),
                FileAccess::All,
                "deny symlink linkpath",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = PolicyStore::new(PolicydArgs {
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
        });

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = MergeContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-symlink".into()),
        };

        let target_reply = store
            .check_filesystem(FilesystemCheckRequest {
                path: target_path.clone(),
                access: FileAccess::Read,
                ctx: ctx.clone(),
            })
            .await;
        let link_reply = store
            .check_filesystem(FilesystemCheckRequest {
                path: link_path.clone(),
                access: FileAccess::Write,
                ctx,
            })
            .await;

        assert!(
            target_reply.allowed,
            "symlink target must pass read CheckFilesystem, got: {target_reply:?}"
        );
        assert!(
            !link_reply.allowed,
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

        let store = PolicyStore::new(PolicydArgs {
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
        });

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = MergeContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-glob-check".into()),
        };
        {
            let mut inner = store.inner.lock().await;
            inner.sandbox_filesystem_static_allow.insert(
                "sandbox:sandbox-glob-check".into(),
                vec![agent_sandbox_core::FilesystemRule::new(
                    project_root.join("vendor/**"),
                    FileAccess::Read,
                    "static allow vendor tree",
                )],
            );
        }

        let reply = store
            .check_filesystem(FilesystemCheckRequest {
                path: nested_path,
                access: FileAccess::Read,
                ctx,
            })
            .await;

        assert!(
            reply.allowed,
            "broad static-allow globs must remain functional when not denied, got: {reply:?}"
        );
        assert_eq!(
            reply.source, "static",
            "static allow should be evaluated through policyd after deny/inode checks"
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

        let policy_path = agent_sandbox_core::trusted_project_policy_path(&project_root)
            .expect("trusted project policy path");
        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .filesystem
            .deny
            .push(agent_sandbox_core::FilesystemRule::new(
                license_path.clone(),
                FileAccess::All,
                "deny license",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = PolicyStore::new(PolicydArgs {
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
        });

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();
        let ctx = MergeContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-broad-glob-check-deny".into()),
        };
        {
            let mut inner = store.inner.lock().await;
            inner.sandbox_filesystem_static_allow.insert(
                "sandbox:sandbox-broad-glob-check-deny".into(),
                vec![agent_sandbox_core::FilesystemRule::new(
                    project_root.join("**"),
                    FileAccess::All,
                    "broad static allow repo tree",
                )],
            );
        }

        let reply = store
            .check_filesystem(FilesystemCheckRequest {
                path: license_path,
                access: FileAccess::Read,
                ctx,
            })
            .await;

        assert!(
            !reply.allowed,
            "policyd must deny before broad static-allow globs can allow, got: {reply:?}"
        );
        assert_eq!(reply.source, "deny");
    }

    #[test]
    fn expand_static_allow_rules_canonicalizes_home_symlinks() {
        use super::expand_static_allow_rules;
        use agent_sandbox_core::FilesystemRule;
        use std::os::unix::fs::symlink;

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
