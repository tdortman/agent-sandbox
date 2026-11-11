//! Host-side lifecycle of a sandbox instance's agent scope.
//!
//! The launcher runs inside a transient user scope named
//! `agent-sandbox-<launcher pid>_<nonce>.scope` and registers the same pid
//! with policyd. This module is the only place that parses that name. It
//! finds the scope of a process, freezes and thaws it around interactive
//! approvals, and kills it when the registered launcher exits, so a sandbox
//! never outlives its launcher whether or not any other gate is running. Once
//! the kill succeeds the registration is dropped as well.

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError, RwLock},
};

use agent_sandbox_core::socket_owner::process_start_time_ticks;
use tokio::{
    io::{Interest, unix::AsyncFd},
    task::AbortHandle,
};
use tracing::{info, warn};

use super::{
    access::sandbox_session_static_allow_key,
    types::{PolicyStore, SandboxSessionRegistration},
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const USER_RUNTIME_ROOT: &str = "/run/user";
const DEFAULT_REGISTRY: &str = "/run/agent-sandbox/cgroup-freeze";

#[derive(Debug, thiserror::Error)]
pub enum CgroupFreezeError {
    #[error("cannot read cgroup for pid {pid}: {source}")]
    ProcessCgroup { pid: u32, source: io::Error },

    #[error("pid {pid} is not in a cgroup v2 hierarchy")]
    NotCgroupV2 { pid: u32 },

    #[error("pid {pid} is not owned by uid {expected_uid} (actual uid {actual_uid})")]
    WrongOwner {
        pid: u32,
        expected_uid: u32,
        actual_uid: u32,
    },

    #[error("pid {pid} is not in an agent-sandbox systemd scope: {path}")]
    UnmanagedScope { pid: u32, path: PathBuf },

    #[error("cgroup freezer path is invalid: {0}")]
    InvalidPath(PathBuf),

    #[error("cannot freeze cgroup {path}: {source}")]
    Freeze { path: PathBuf, source: io::Error },

    #[error("cannot persist cgroup freeze state: {0}")]
    Registry(#[source] io::Error),
}

#[derive(Clone)]
pub struct CgroupFreezeManager {
    state: Arc<Mutex<FreezeState>>,
}

struct FreezeState {
    holds: HashMap<PathBuf, usize>,
    registry: PathBuf,
}

pub struct CgroupFreezeHold {
    manager: CgroupFreezeManager,
    path: Option<PathBuf>,
}

impl CgroupFreezeManager {
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_recovery(true)
    }

    #[must_use]
    pub fn new_without_recovery() -> Self {
        Self::new_with_recovery(false)
    }

    fn new_with_recovery(recover: bool) -> Self {
        let registry = std::env::var_os("AGENT_SANDBOX_CGROUP_FREEZE_STATE")
            .map_or_else(|| PathBuf::from(DEFAULT_REGISTRY), PathBuf::from);

        if recover && let Err(error) = thaw_stale_registry(&registry) {
            warn!(%error, "failed to recover stale cgroup freeze registry");
        }

        Self {
            state: Arc::new(Mutex::new(FreezeState {
                holds: HashMap::new(),
                registry,
            })),
        }
    }

    /// Freeze the agent-sandbox scope containing `pid` and share a hold with
    /// other approvals for the same scope.
    pub fn acquire(
        &self,
        pid: Option<u32>,
        expected_uid: Option<u32>,
    ) -> Result<Option<CgroupFreezeHold>, CgroupFreezeError> {
        let Some(pid) = pid else {
            return Ok(None);
        };

        let path = cgroup_for_pid(pid, expected_uid)?;

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if state.holds.contains_key(&path) {
            *state
                .holds
                .get_mut(&path)
                .expect("cgroup hold exists after contains_key") += 1;

            if let Err(error) = persist_registry(&state.registry, state.holds.keys()) {
                *state
                    .holds
                    .get_mut(&path)
                    .expect("cgroup hold exists after failed persistence") -= 1;

                return Err(error);
            }
        } else {
            state.holds.insert(path.clone(), 1);

            if let Err(error) = persist_registry(&state.registry, state.holds.keys()) {
                state.holds.remove(&path);
                return Err(error);
            }

            if let Err(error) = set_frozen(&path, true) {
                state.holds.remove(&path);
                let _ = persist_registry(&state.registry, state.holds.keys());
                return Err(error);
            }
        }

        drop(state);

        Ok(Some(CgroupFreezeHold {
            manager: self.clone(),
            path: Some(path),
        }))
    }

    fn release(&self, path: &Path) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match state.holds.get(path).copied() {
            Some(count) if count > 1 => {
                state.holds.insert(path.to_path_buf(), count - 1);
            }

            Some(1) => match set_frozen(path, false) {
                Ok(()) => {
                    state.holds.remove(path);
                }
                Err(error) => {
                    warn!(
                        %error,
                        path = %path.display(),
                        "failed to thaw cgroup after approval; retaining recovery state"
                    );
                }
            },

            _ => {}
        }

        if let Err(error) = persist_registry(&state.registry, state.holds.keys()) {
            warn!(%error, "failed to persist cgroup freeze state after release");
        }
    }
}

impl Default for CgroupFreezeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Thaw the stale cgroup freeze registry, if any.
///
/// The registry path honours `AGENT_SANDBOX_CGROUP_FREEZE_STATE`.
///
/// # Errors
///
/// Returns an error when the registry cannot be read or thawed.
pub fn cleanup_cgroup_freeze() -> Result<(), CgroupFreezeError> {
    let registry = std::env::var_os("AGENT_SANDBOX_CGROUP_FREEZE_STATE")
        .map_or_else(|| PathBuf::from(DEFAULT_REGISTRY), PathBuf::from);

    thaw_stale_registry(&registry)
}

impl Drop for CgroupFreezeHold {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            self.manager.release(&path);
        }
    }
}

fn cgroup_for_pid(pid: u32, expected_uid: Option<u32>) -> Result<PathBuf, CgroupFreezeError> {
    if let Some(expected_uid) = expected_uid {
        let actual_uid = process_uid(pid)?;

        if actual_uid != expected_uid {
            return Err(CgroupFreezeError::WrongOwner {
                pid,
                expected_uid,
                actual_uid,
            });
        }
    }

    let path = process_cgroup(pid)?;

    if !is_agent_scope(&path) {
        return Err(CgroupFreezeError::UnmanagedScope { pid, path });
    }

    if !path.join("cgroup.freeze").is_file() {
        return Err(CgroupFreezeError::InvalidPath(path));
    }

    Ok(path)
}

/// The cgroup v2 directory `pid` belongs to.
pub(super) fn process_cgroup(pid: u32) -> Result<PathBuf, CgroupFreezeError> {
    let contents = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|source| CgroupFreezeError::ProcessCgroup { pid, source })?;

    let Some(relative) = contents.lines().find_map(|line| {
        let (hierarchy, path) = line.split_once("::")?;
        (hierarchy == "0").then_some(path)
    }) else {
        return Err(CgroupFreezeError::NotCgroupV2 { pid });
    };

    Ok(Path::new(CGROUP_ROOT).join(relative.trim_start_matches('/')))
}

/// The cgroup of `pid` when it is an agent sandbox scope.
pub(super) fn agent_scope_cgroup(pid: u32) -> Option<PathBuf> {
    process_cgroup(pid).ok().filter(|path| is_agent_scope(path))
}

fn process_uid(pid: u32) -> Result<u32, CgroupFreezeError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|source| CgroupFreezeError::ProcessCgroup { pid, source })?;

    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| CgroupFreezeError::ProcessCgroup {
            pid,
            source: io::Error::new(io::ErrorKind::InvalidData, "missing process uid"),
        })?;

    Ok(uid)
}

/// The launcher pid in an `agent-sandbox-<pid>_<nonce>.scope` unit name.
fn scope_name_owner_pid(name: &str) -> Option<u32> {
    let (pid, nonce) = name
        .strip_prefix("agent-sandbox-")?
        .strip_suffix(".scope")?
        .split_once('_')?;

    if nonce.is_empty() || !nonce.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    pid.parse().ok()
}

/// Whether `path` is an agent scope or lies inside one.
fn is_agent_scope(path: &Path) -> bool {
    path.components()
        .any(|component| scope_name_owner_pid(&component.as_os_str().to_string_lossy()).is_some())
}

/// The launcher pid of the agent scope `path` names, when its leaf is one.
fn scope_owner_pid(path: &Path) -> Option<u32> {
    scope_name_owner_pid(&path.file_name()?.to_string_lossy())
}

fn set_frozen(path: &Path, frozen: bool) -> Result<(), CgroupFreezeError> {
    let freeze_path = path.join("cgroup.freeze");

    fs::write(&freeze_path, if frozen { "1" } else { "0" }).map_err(|source| {
        CgroupFreezeError::Freeze {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn persist_registry<'a>(
    registry: &Path,
    paths: impl Iterator<Item = &'a PathBuf>,
) -> Result<(), CgroupFreezeError> {
    let Some(parent) = registry.parent() else {
        return Err(CgroupFreezeError::Registry(io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry has no parent",
        )));
    };

    fs::create_dir_all(parent).map_err(CgroupFreezeError::Registry)?;
    let mut contents = String::new();

    for path in paths {
        writeln!(&mut contents, "{}", path.display()).expect("writing to String cannot fail");
    }

    let tmp = registry.with_extension("tmp");
    fs::write(&tmp, contents).map_err(CgroupFreezeError::Registry)?;
    fs::rename(tmp, registry).map_err(CgroupFreezeError::Registry)
}

fn thaw_stale_registry(registry: &Path) -> Result<(), CgroupFreezeError> {
    let contents = match fs::read_to_string(registry) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CgroupFreezeError::Registry(error)),
    };

    let mut first_error = None;

    for path in contents.lines().map(Path::new) {
        if !path.starts_with(CGROUP_ROOT) {
            continue;
        }

        if let Err(error) = set_frozen(path, false)
            && !matches!(error, CgroupFreezeError::Freeze { ref source, .. } if source.kind() == io::ErrorKind::NotFound)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }

    if let Some(error) = first_error {
        return Err(error);
    }

    match fs::remove_file(registry) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CgroupFreezeError::Registry(error)),
    }
}

/// A registered launcher: its pid and the kernel start time that tells it
/// apart from a later process that reuses the pid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Launcher {
    pid: u32,
    start_ticks: u64,
}

impl Launcher {
    /// The launcher a registration is bound to, if it has one.
    pub(super) const fn of(registration: &SandboxSessionRegistration) -> Option<Self> {
        if registration.launcher_pid == 0 {
            return None;
        }

        Some(Self {
            pid: registration.launcher_pid,
            start_ticks: registration.launcher_start_ticks,
        })
    }

    /// Whether the registered process is still running.
    pub(super) fn is_running(self) -> bool {
        process_start_time_ticks(self.pid)
            .is_some_and(|ticks| ticks > 0 && ticks == self.start_ticks)
    }
}

/// Whether `scope` is the agent scope launcher `launcher_pid` created for
/// `owner_uid` under the cgroup tree at `root`: the leaf is named for the
/// launcher and the scope sits under the owner's user manager. This is what
/// keeps a kill away from the user's session scope and from other users'
/// sandboxes.
fn is_launcher_scope(root: &Path, scope: &Path, launcher_pid: u32, owner_uid: u32) -> bool {
    let user_manager = format!("user@{owner_uid}.service");

    scope.starts_with(root)
        && scope_owner_pid(scope) == Some(launcher_pid)
        && scope
            .components()
            .any(|component| component.as_os_str() == user_manager.as_str())
}

/// Kills a sandbox's scope once its registered launcher exits.
///
/// One pidfd watch per registered launcher runs on the tokio runtime. The
/// watches are reconciled against the registry by [`Self::sync`], so a
/// registration armed before a restart is armed again after it.
pub(super) struct ScopeLifecycle {
    sessions: Arc<RwLock<HashMap<String, SandboxSessionRegistration>>>,
    cgroup_root: PathBuf,
    /// Where per-user runtime directories live; a sandbox is scoped only when
    /// its owner's user manager answers there.
    runtime_root: PathBuf,
    watches: Mutex<HashMap<String, LauncherWatch>>,
    /// Sandboxes whose scope was killed, waiting for the store to drop their
    /// registrations; see [`Self::take_ended`].
    ended: Arc<Mutex<Vec<EndedSession>>>,
}

struct LauncherWatch {
    launcher: Launcher,
    task: AbortHandle,
}

/// A registration whose launcher exited and whose scope was killed.
struct EndedSession {
    id: String,
    launcher: Launcher,
}

impl ScopeLifecycle {
    pub(super) fn new(
        sessions: Arc<RwLock<HashMap<String, SandboxSessionRegistration>>>,
        cgroup_root: PathBuf,
        runtime_root: PathBuf,
    ) -> Self {
        Self {
            sessions,
            cgroup_root,
            runtime_root,
            watches: Mutex::new(HashMap::new()),
            ended: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The sandboxes that ended since the last call.
    fn take_ended(&self) -> Vec<EndedSession> {
        std::mem::take(&mut *self.ended.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether the watch of `session_id` has handled its launcher's exit.
    #[cfg(test)]
    pub(super) fn watch_finished(&self, session_id: &str) -> bool {
        self.watches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(session_id)
            .is_some_and(|watch| watch.task.is_finished())
    }

    pub(super) fn host(sessions: Arc<RwLock<HashMap<String, SandboxSessionRegistration>>>) -> Self {
        Self::new(
            sessions,
            PathBuf::from(CGROUP_ROOT),
            PathBuf::from(USER_RUNTIME_ROOT),
        )
    }

    /// Make the watches match `registrations`: one per launcher-bound
    /// registration, none for removed or re-bound ones.
    pub(super) fn sync(&self, registrations: &HashMap<String, SandboxSessionRegistration>) {
        let mut watches = self.watches.lock().unwrap_or_else(PoisonError::into_inner);

        watches.retain(|id, watch| {
            let current = registrations.get(id).and_then(Launcher::of);

            if current != Some(watch.launcher) {
                watch.task.abort();
            }

            current == Some(watch.launcher)
        });

        for (id, registration) in registrations {
            let Some(launcher) = Launcher::of(registration) else {
                continue;
            };

            if watches.contains_key(id) {
                continue;
            }

            let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                warn!(session = %id, "no async runtime; sandbox scope is not watched");
                continue;
            };

            if !self
                .runtime_root
                .join(format!("{}/systemd/private", registration.owner_uid))
                .exists()
            {
                warn!(
                    session = %id,
                    uid = registration.owner_uid,
                    "no user manager for the sandbox owner; the sandbox runs unscoped and cannot \
                     be killed when its launcher exits"
                );
            }

            let task = runtime
                .spawn(kill_scope_after_exit(
                    Arc::clone(&self.sessions),
                    Arc::clone(&self.ended),
                    self.cgroup_root.clone(),
                    id.clone(),
                    launcher,
                ))
                .abort_handle();

            watches.insert(id.clone(), LauncherWatch { launcher, task });
        }
    }

    /// Whether the scope `pid` runs in is the launcher scope of
    /// `registration`, and therefore dies with its launcher.
    pub(super) fn dies_with_launcher(
        &self,
        registration: &SandboxSessionRegistration,
        pid: u32,
    ) -> bool {
        process_cgroup(pid).is_ok_and(|scope| {
            is_launcher_scope(
                &self.cgroup_root,
                &scope,
                registration.launcher_pid,
                registration.owner_uid,
            )
        })
    }

    /// Kill the scope of `registration`'s launcher; see [`kill_scope`].
    pub(super) fn kill_scope(&self, registration: &SandboxSessionRegistration) -> io::Result<bool> {
        kill_scope(&self.cgroup_root, registration)
    }
}

/// How deep below the user manager the launcher's scope is searched for.
const SCOPE_SEARCH_DEPTH: usize = 3;

/// The scope launcher `launcher_pid` created for `owner_uid`, found by name
/// in the owner's user manager.
fn find_launcher_scope(root: &Path, owner_uid: u32, launcher_pid: u32) -> Option<PathBuf> {
    let mut level = vec![root.join(format!(
        "user.slice/user-{owner_uid}.slice/user@{owner_uid}.service"
    ))];

    for _ in 0..SCOPE_SEARCH_DEPTH {
        let mut next = Vec::new();

        for entries in level.iter().filter_map(|dir| fs::read_dir(dir).ok()) {
            for entry in entries.flatten() {
                let path = entry.path();

                if scope_owner_pid(&path) == Some(launcher_pid) {
                    return Some(path);
                }

                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    next.push(path);
                }
            }
        }

        level = next;
    }

    None
}

/// Kill the agent scope the registration's launcher created: the scope
/// recorded in the registration when it is the launcher's own, else the one
/// found by the launcher's name. `Ok(false)` means there is no such scope and
/// nothing was touched; a scope that is already gone counts as killed.
fn kill_scope(root: &Path, registration: &SandboxSessionRegistration) -> io::Result<bool> {
    let recorded = registration.cgroup.as_deref().filter(|scope| {
        is_launcher_scope(
            root,
            scope,
            registration.launcher_pid,
            registration.owner_uid,
        )
    });

    let Some(scope) = recorded
        .map(Path::to_path_buf)
        .or_else(|| find_launcher_scope(root, registration.owner_uid, registration.launcher_pid))
    else {
        return Ok(false);
    };

    match OpenOptions::new()
        .write(true)
        .open(scope.join("cgroup.kill"))
        .and_then(|mut kill| kill.write_all(b"1"))
    {
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(nix::libc::ENODEV) =>
        {
            Ok(true)
        }
        result => result.map(|()| true),
    }
}

impl Drop for ScopeLifecycle {
    fn drop(&mut self) {
        for watch in self
            .watches
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            watch.task.abort();
        }
    }
}

/// Wait for `launcher` to exit, then kill the scope its registration still
/// names. The registration is read after the exit, so a scope recorded after
/// arming is covered; a registration re-bound to another launcher is left to
/// that launcher's own watch. A session whose scope was killed is queued as
/// ended; one with no scope, or whose kill failed, stays registered so its
/// surviving processes keep their attribution.
async fn kill_scope_after_exit(
    sessions: Arc<RwLock<HashMap<String, SandboxSessionRegistration>>>,
    ended: Arc<Mutex<Vec<EndedSession>>>,
    cgroup_root: PathBuf,
    session_id: String,
    launcher: Launcher,
) {
    if let Err(error) = wait_for_exit(launcher).await {
        warn!(%error, session = %session_id, "cannot watch the sandbox launcher");
        return;
    }

    let registration = sessions
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&session_id)
        .filter(|registration| Launcher::of(registration) == Some(launcher))
        .cloned();

    if let Some(registration) = registration {
        let outcome = kill_scope(&cgroup_root, &registration);
        let killed = matches!(outcome, Ok(true));

        report_kill(&session_id, outcome);

        if killed {
            ended
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(EndedSession {
                    id: session_id,
                    launcher,
                });
        }
    }
}

/// Log the outcome of killing the scope of an exited launcher.
pub(super) fn report_kill(session_id: &str, outcome: io::Result<bool>) {
    match outcome {
        Ok(true) => info!(session = %session_id, "sandbox launcher exited; killed its scope"),
        Ok(false) => {
            info!(session = %session_id, "sandbox launcher exited; it has no scope to kill");
        }
        Err(error) => {
            warn!(%error, session = %session_id, "cannot kill the scope of an exited launcher");
        }
    }
}

/// Resolve once `launcher` has exited. A launcher that is already gone, or
/// whose pid now belongs to another process, counts as exited.
async fn wait_for_exit(launcher: Launcher) -> io::Result<()> {
    let pidfd = match agent_sandbox_sysutil::pidfd_open(launcher.pid) {
        Ok(pidfd) => pidfd,
        Err(error) if error.raw_os_error() == Some(nix::libc::ESRCH) => return Ok(()),
        Err(error) => return Err(error),
    };

    // The pidfd pins the pid only from the open on, so the process must
    // still be the registered one afterwards.
    if !launcher.is_running() {
        return Ok(());
    }

    AsyncFd::with_interest(pidfd, Interest::READABLE)?
        .readable()
        .await
        .map(drop)
}

impl PolicyStore {
    /// Whether the sandbox of `session_id`, whose process is `pid`, stops
    /// entirely when its launcher exits: the registration is bound to a
    /// launcher whose own scope `pid` runs in.
    pub(super) fn launcher_scope_stops_sandbox(&self, session_id: Option<&str>, pid: u32) -> bool {
        let sessions = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(PoisonError::into_inner);

        session_id
            .and_then(|id| sessions.get(id))
            .is_some_and(|registration| {
                Launcher::of(registration).is_some()
                    && self.lifecycle.dies_with_launcher(registration, pid)
            })
    }

    /// Drop the registrations of sandboxes whose scope was killed after their
    /// launcher exited, with their filesystem exports and static allows. A
    /// registration that a new launcher has re-bound since is kept.
    pub(crate) async fn reap_ended_sessions(&self) {
        let ended = self.lifecycle.take_ended();

        if ended.is_empty() {
            return;
        }

        let removed = self.update_registry(|sessions| {
            let mut removed = Vec::new();

            for session in ended {
                if sessions.get(&session.id).and_then(Launcher::of) == Some(session.launcher) {
                    sessions.remove(&session.id);
                    removed.push(session.id);
                }
            }

            removed
        });

        Self::blocking(|| {
            for session_id in &removed {
                self.remove_session_filesystem_export(session_id);
            }
        });
        self.forget_static_allow(&removed);

        let mut inner = self.inner.lock().await;

        for session_id in &removed {
            inner
                .sandbox_filesystem_static_allow
                .remove(&sandbox_session_static_allow_key(session_id));
        }
    }
}

/// A launcher process with one child standing in for the sandbox's peer,
/// and a fake cgroup tree holding the launcher's agent scope.
#[cfg(test)]
pub(super) mod fixture {
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        time::Duration,
    };

    use tempfile::TempDir;

    use super::{PolicyStore, ScopeLifecycle, fs};
    use crate::store::test_args;

    pub(in crate::store) struct FakeSandbox {
        launcher: Child,
        pub(in crate::store) peer: u32,
        root: TempDir,
        scope: std::path::PathBuf,
    }

    impl FakeSandbox {
        pub(in crate::store) fn start() -> Self {
            let uid = nix::unistd::getuid().as_raw();
            let mut launcher = Command::new("sh")
                .args(["-c", "sleep 60 & echo $!; wait"])
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn launcher");
            let mut line = String::new();

            BufReader::new(launcher.stdout.take().expect("launcher stdout"))
                .read_line(&mut line)
                .expect("peer pid line");

            let peer = line.trim().parse().expect("peer pid");
            let root = tempfile::tempdir().expect("cgroup root");
            let scope = root.path().join(format!(
                "user.slice/user-{uid}.slice/user@{uid}.service/app.slice/agent-sandbox-{}_7.scope",
                launcher.id()
            ));

            fs::create_dir_all(&scope).expect("scope directory");
            fs::write(scope.join("cgroup.kill"), "").expect("kill file");

            Self {
                launcher,
                peer,
                root,
                scope,
            }
        }

        pub(in crate::store) fn launcher_pid(&self) -> u32 {
            self.launcher.id()
        }

        pub(in crate::store) fn root(&self) -> &std::path::Path {
            self.root.path()
        }

        /// Record the fake scope as the cgroup of `session_id`'s registration.
        pub(in crate::store) fn record_scope(&self, store: &PolicyStore, session_id: &str) {
            store.update_registry(|sessions| {
                sessions
                    .get_mut(session_id)
                    .expect("registered session")
                    .cgroup = Some(self.scope.clone());
            });
        }

        /// What the scope's `cgroup.kill` file received.
        pub(in crate::store) fn kill_file(&self) -> String {
            fs::read_to_string(self.scope.join("cgroup.kill")).expect("read kill file")
        }

        pub(in crate::store) fn end_launcher(&mut self) {
            self.launcher.kill().expect("kill launcher");
            self.launcher.wait().expect("reap launcher");
        }
    }

    impl Drop for FakeSandbox {
        fn drop(&mut self) {
            let _ = self.launcher.kill();
            let _ = self.launcher.wait();
            let _ = Command::new("kill").arg(self.peer.to_string()).status();
        }
    }

    /// A store whose scopes live under the fake cgroup tree at `root`, with
    /// its sockets and export directory there too.
    pub(in crate::store) fn store_over(root: &std::path::Path) -> PolicyStore {
        let mut store = PolicyStore::new(test_args(
            root.join("host.sock"),
            root.join("shared/sandbox.sock"),
            root.join("declarative.json"),
            root.join("export.json"),
            Duration::from_secs(30),
            true,
        ));

        store.lifecycle = ScopeLifecycle::new(
            store.sandbox_sessions.clone(),
            root.to_path_buf(),
            root.join("run-user"),
        );
        store
    }

    /// Poll `condition` for up to five seconds.
    pub(in crate::store) async fn eventually(condition: impl Fn() -> bool) {
        for _ in 0..100 {
            if condition() {
                return;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        panic!("condition not reached within five seconds");
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{
        FileAccess, FilesystemRule, ProcessIds, ResolvedRequestContext, SandboxPaths,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::store::{restart::RestartPaths, types::ExportReader};

    fn manager_for(path: &Path, registry: &Path, count: usize) -> CgroupFreezeManager {
        CgroupFreezeManager {
            state: Arc::new(Mutex::new(FreezeState {
                holds: HashMap::from([(path.to_path_buf(), count)]),
                registry: registry.to_path_buf(),
            })),
        }
    }

    #[test]
    fn last_release_thaws_after_shared_holds() {
        let dir = tempdir().expect("temporary directory");
        let cgroup = dir.path().join("sandbox");
        fs::create_dir(&cgroup).expect("cgroup directory");
        fs::write(cgroup.join("cgroup.freeze"), "1").expect("freeze file");
        let manager = manager_for(&cgroup, &dir.path().join("state"), 2);
        manager.release(&cgroup);

        assert_eq!(
            fs::read_to_string(cgroup.join("cgroup.freeze")).unwrap(),
            "1"
        );

        manager.release(&cgroup);

        assert_eq!(
            fs::read_to_string(cgroup.join("cgroup.freeze")).unwrap(),
            "0"
        );
    }

    #[test]
    fn failed_thaw_retains_recovery_registry() {
        let dir = tempdir().expect("temporary directory");
        let cgroup = dir.path().join("missing");
        let registry = dir.path().join("state");
        let manager = manager_for(&cgroup, &registry, 1);
        manager.release(&cgroup);
        assert!(registry.exists());

        assert_eq!(
            fs::read_to_string(registry).unwrap().trim(),
            cgroup.display().to_string()
        );
    }

    #[test]
    fn stale_registry_cleanup_removes_missing_cgroup_entries() {
        let dir = tempdir().expect("temporary directory");
        let registry = dir.path().join("state");

        fs::write(
            &registry,
            "/sys/fs/cgroup/agent-sandbox-freeze-test-missing.scope\n",
        )
        .expect("registry");

        thaw_stale_registry(&registry).expect("missing cgroup is already thawed");
        assert!(!registry.exists());
    }

    #[tokio::test]
    async fn registered_launcher_exit_kills_its_scope() {
        use fixture::{FakeSandbox, eventually, store_over};

        let mut sandbox = FakeSandbox::start();
        let store = store_over(sandbox.root());
        let uid = nix::unistd::getuid().as_raw();

        store
            .register_sandbox("s", "omp", uid, sandbox.launcher_pid(), sandbox.peer)
            .expect("register sandbox");
        sandbox.record_scope(&store, "s");
        assert_eq!(sandbox.kill_file(), "");

        sandbox.end_launcher();
        eventually(|| sandbox.kill_file() == "1").await;
    }

    /// The dynamic filesystem launcher registers before it enters its scope,
    /// so the registration records none.
    #[tokio::test]
    async fn launcher_exit_finds_an_unrecorded_scope_by_name() {
        use fixture::{FakeSandbox, eventually, store_over};

        let mut sandbox = FakeSandbox::start();
        let store = store_over(sandbox.root());
        let uid = nix::unistd::getuid().as_raw();

        store
            .register_sandbox("s", "omp", uid, sandbox.launcher_pid(), sandbox.peer)
            .expect("register sandbox");

        sandbox.end_launcher();
        eventually(|| sandbox.kill_file() == "1").await;
    }

    fn is_registered(store: &PolicyStore, id: &str) -> bool {
        store
            .sandbox_sessions
            .read()
            .expect("sessions lock")
            .contains_key(id)
    }

    /// Reap until `id` is no longer registered, for up to five seconds.
    async fn reap_until_gone(store: &PolicyStore, id: &str) {
        for _ in 0..100 {
            store.reap_ended_sessions().await;

            if !is_registered(store, id) {
                return;
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        panic!("{id} was not reaped within five seconds");
    }

    #[tokio::test]
    async fn killed_sandbox_loses_its_registration_export_and_static_allow() {
        use fixture::{FakeSandbox, store_over};

        let mut sandbox = FakeSandbox::start();
        let mut store = store_over(sandbox.root());
        let uid = nix::unistd::getuid().as_raw();

        store.restore_from(RestartPaths {
            state: sandbox.root().join("sandbox-state.json"),
            handoff: sandbox.root().join("policyd-handoff.json"),
        });
        store
            .register_sandbox("s", "omp", uid, sandbox.launcher_pid(), sandbox.peer)
            .expect("register sandbox");
        store.set_export_reader("s", ExportReader::of(sandbox.launcher_pid()));
        store
            .store_sandbox_static_allow(
                &ResolvedRequestContext::new(
                    SandboxPaths::default(),
                    ProcessIds::default(),
                    Some("s".into()),
                ),
                vec![FilesystemRule::new("/allowed/**", FileAccess::All, "test")],
            )
            .await;

        let export = store
            .session_export_dir()
            .expect("export directory")
            .join("s");

        assert!(export.exists(), "a monitored session is exported");
        assert!(store.tracks_static_allow("s"));
        assert!(
            store
                .inner
                .lock()
                .await
                .sandbox_filesystem_static_allow
                .contains_key("sandbox:s")
        );

        sandbox.end_launcher();
        reap_until_gone(&store, "s").await;

        assert!(!export.exists(), "the export goes with the registration");
        assert!(!store.tracks_static_allow("s"));
        assert!(
            !store
                .inner
                .lock()
                .await
                .sandbox_filesystem_static_allow
                .contains_key("sandbox:s")
        );
    }

    #[tokio::test]
    async fn sandbox_whose_scope_was_not_killed_keeps_its_registration() {
        use fixture::{FakeSandbox, eventually, store_over};

        let mut killed = FakeSandbox::start();
        let mut unscoped = FakeSandbox::start();
        let store = store_over(killed.root());
        let uid = nix::unistd::getuid().as_raw();

        // The second sandbox's scope is not under the store's cgroup tree, so
        // the kill finds no scope to act on.
        store
            .register_sandbox("killed", "omp", uid, killed.launcher_pid(), killed.peer)
            .expect("register sandbox");
        store
            .register_sandbox(
                "unscoped",
                "omp",
                uid,
                unscoped.launcher_pid(),
                unscoped.peer,
            )
            .expect("register sandbox");

        unscoped.end_launcher();
        killed.end_launcher();
        reap_until_gone(&store, "killed").await;
        eventually(|| store.lifecycle.watch_finished("unscoped")).await;
        store.reap_ended_sessions().await;

        assert!(is_registered(&store, "unscoped"));
        assert_eq!(unscoped.kill_file(), "");
    }

    #[tokio::test]
    async fn rebound_registration_is_not_reaped() {
        use fixture::{FakeSandbox, eventually, store_over};

        let mut sandbox = FakeSandbox::start();
        let store = store_over(sandbox.root());
        let uid = nix::unistd::getuid().as_raw();

        store
            .register_sandbox("s", "omp", uid, sandbox.launcher_pid(), sandbox.peer)
            .expect("register sandbox");
        sandbox.end_launcher();
        eventually(|| sandbox.kill_file() == "1").await;

        // A new launcher took the id over before the store reaped the old one.
        store.update_registry(|sessions| {
            sessions
                .get_mut("s")
                .expect("registered session")
                .launcher_start_ticks += 1;
        });
        store.reap_ended_sessions().await;

        assert!(is_registered(&store, "s"));
    }

    #[test]
    fn only_the_launchers_own_scope_is_killed() {
        let root = tempdir().expect("cgroup root");
        let uid = nix::unistd::getuid().as_raw();
        let launcher = 4242;
        let manager = format!("user.slice/user-{uid}.slice/user@{uid}.service/app.slice");
        let other_manager = format!(
            "user.slice/user-{0}.slice/user@{0}.service/app.slice",
            uid + 1
        );

        let scopes = [
            format!("{manager}/session-3.scope"),
            format!("{manager}/agent-sandbox-{}_7.scope", launcher + 1),
            format!("{manager}/agent-sandbox-{launcher}.scope"),
            format!("{other_manager}/agent-sandbox-{launcher}_7.scope"),
            format!("system.slice/agent-sandbox-{launcher}_7.scope"),
        ];

        let lifecycle = ScopeLifecycle::new(
            Arc::new(RwLock::new(HashMap::new())),
            root.path().join("user.slice"),
            root.path().join("run-user"),
        );

        for scope in scopes {
            let dir = root.path().join(&scope);

            fs::create_dir_all(&dir).expect("scope directory");
            fs::write(dir.join("cgroup.kill"), "").expect("kill file");

            let registration = SandboxSessionRegistration {
                root_pid: 0,
                owner_uid: uid,
                project_root: PathBuf::new(),
                package: None,
                launcher_pid: launcher,
                launcher_start_ticks: 1,
                cgroup: Some(dir.clone()),
                export_reader: None,
            };

            assert!(
                !lifecycle
                    .kill_scope(&registration)
                    .expect("refusal is not an error"),
                "{scope} must not be killed"
            );
            assert_eq!(
                fs::read_to_string(dir.join("cgroup.kill")).expect("read kill file"),
                "",
                "{scope} received a kill"
            );
        }
    }
}
