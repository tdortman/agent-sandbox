//! What a policyd restart keeps of the running sandboxes.
//!
//! Two files carry state across a restart, split by one rule:
//!
//! - The *state file* holds what must survive a crash: [`survives_crash`]
//!   registrations (those bound to a launcher) and their static filesystem
//!   allows. [`PolicyStore::update_registry`] and
//!   [`PolicyStore::persist_static_allow`] rewrite it after every change.
//! - The *handoff* (see `handoff.rs`) holds what only an orderly stop can save:
//!   the proxy's session and flows, and the UI sessions' decisions. It is
//!   written on `SIGTERM`; a daemon that crashes writes none and its successor
//!   starts without them. Verdict caches and network grants are persisted in
//!   neither.
//!
//! [`PolicyStore::restore`] is the one restore entry point. It reads the state
//! file, then the handoff (flows derive their context from the restored
//! registrations), then arms the lifecycle watches. A sandbox whose launcher
//! exited while the daemon was down loses its registration and has its scope
//! killed.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::PoisonError,
};

use agent_sandbox_core::{FilesystemRule, is_descendant_of};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    access::sandbox_session_static_allow_key,
    lifecycle::{Launcher, report_kill},
    types::{PolicyStore, SandboxSessionRegistration},
};

const DEFAULT_STATE_PATH: &str = "/run/agent-sandbox/sandbox-state.json";
const STATE_PATH_ENV: &str = "AGENT_SANDBOX_SANDBOX_STATE";
const DEFAULT_HANDOFF_PATH: &str = "/run/agent-sandbox/policyd-handoff.json";
const HANDOFF_PATH_ENV: &str = "AGENT_SANDBOX_POLICYD_HANDOFF";

/// Whether a registration is kept in the state file, and so survives a crash.
///
/// A registration bound to a launcher can be checked against that process
/// after a restart. One without a launcher has nothing to be checked against
/// and is rebuilt from the next descendant that claims the session.
pub(super) const fn survives_crash(registration: &SandboxSessionRegistration) -> bool {
    Launcher::of(registration).is_some()
}

/// Where the restart files live.
#[derive(Clone, Debug)]
pub struct RestartPaths {
    pub state: PathBuf,
    pub handoff: PathBuf,
}

impl RestartPaths {
    /// The paths named by `AGENT_SANDBOX_SANDBOX_STATE` and
    /// `AGENT_SANDBOX_POLICYD_HANDOFF`, else the defaults under
    /// `/run/agent-sandbox`.
    fn from_env() -> Self {
        let path = |variable, default: &str| {
            std::env::var_os(variable).map_or_else(|| PathBuf::from(default), PathBuf::from)
        };

        Self {
            state: path(STATE_PATH_ENV, DEFAULT_STATE_PATH),
            handoff: path(HANDOFF_PATH_ENV, DEFAULT_HANDOFF_PATH),
        }
    }
}

/// The restart files in use, and the static allows to write into the state
/// file.
///
/// The static allows mirror `sandbox_filesystem_static_allow` entries of
/// sandbox sessions, keyed by session id, because the decision state sits
/// behind an async lock that the synchronous registration paths cannot take.
pub(super) struct RestartState {
    paths: RestartPaths,
    static_allow: HashMap<String, Vec<FilesystemRule>>,
    /// The state file content last written, so an unchanged state is not
    /// written again.
    written: Vec<u8>,
}

/// State file contents as written.
#[derive(Serialize)]
struct StateView<'a> {
    sessions: BTreeMap<&'a str, &'a SandboxSessionRegistration>,
    static_allow: BTreeMap<&'a str, &'a [FilesystemRule]>,
}

/// State file contents as read.
#[derive(Deserialize)]
struct LoadedState {
    sessions: BTreeMap<String, SandboxSessionRegistration>,
    static_allow: BTreeMap<String, Vec<FilesystemRule>>,
}

impl RestartState {
    /// Write the state file for `sessions`. A failure is logged and
    /// otherwise ignored: the request that changed the state must still
    /// succeed.
    fn persist(&mut self, sessions: &HashMap<String, SandboxSessionRegistration>) {
        let mut view = StateView {
            sessions: BTreeMap::new(),
            static_allow: BTreeMap::new(),
        };

        for (id, registration) in sessions {
            if survives_crash(registration) {
                view.sessions.insert(id, registration);

                if let Some(rules) = self.static_allow.get(id) {
                    view.static_allow.insert(id, rules);
                }
            }
        }

        let bytes = match serde_json::to_vec(&view) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(%error, "cannot serialize sandbox state");
                return;
            }
        };

        if bytes == self.written {
            return;
        }

        match write_atomic(&self.paths.state, &bytes) {
            Ok(()) => self.written = bytes,
            Err(error) => {
                warn!(%error, path = %self.paths.state.display(), "failed to persist sandbox state");
            }
        }
    }
}

impl PolicyStore {
    /// Restore what the previous daemon left, from the paths named by
    /// `AGENT_SANDBOX_SANDBOX_STATE` and `AGENT_SANDBOX_POLICYD_HANDOFF`,
    /// and keep the state file current from here on.
    pub fn restore(&mut self) {
        self.restore_from(RestartPaths::from_env());
    }

    pub(crate) fn restore_from(&mut self, paths: RestartPaths) {
        let mut state = RestartState {
            paths,
            static_allow: HashMap::new(),
            written: Vec::new(),
        };

        if let Some(loaded) = read_state(&state.paths.state) {
            self.restore_registry(loaded, &mut state);
        }

        let handoff = state.paths.handoff.clone();
        *self
            .restart
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner) = Some(state);
        self.restore_handoff_from(&handoff);
        self.commit_registry();
    }

    /// The path the handoff is written to.
    pub(super) fn handoff_path(&self) -> io::Result<PathBuf> {
        self.restart
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|state| state.paths.handoff.clone())
            .ok_or_else(|| io::Error::other("restart state is not configured"))
    }

    /// The one write path for registry changes: apply `change` to the
    /// registrations, then write the state file and bring the lifecycle
    /// watches in line with the result.
    pub(super) fn update_registry<T>(
        &self,
        change: impl FnOnce(&mut HashMap<String, SandboxSessionRegistration>) -> T,
    ) -> T {
        let result = change(
            &mut self
                .sandbox_sessions
                .write()
                .unwrap_or_else(PoisonError::into_inner),
        );

        self.commit_registry();
        result
    }

    /// Record the static allows of a sandbox session and write the state file.
    pub(super) fn persist_static_allow(&self, session_id: Option<&str>, rules: &[FilesystemRule]) {
        let mut restart = self.restart.lock().unwrap_or_else(PoisonError::into_inner);

        if let Some(state) = restart.as_mut()
            && let Some(session_id) = session_id
        {
            state
                .static_allow
                .insert(session_id.to_string(), rules.to_vec());
            state.persist(
                &self
                    .sandbox_sessions
                    .read()
                    .unwrap_or_else(PoisonError::into_inner),
            );
        }
    }

    /// Forget the static allows recorded for sandbox sessions that ended.
    pub(super) fn forget_static_allow(&self, session_ids: &[String]) {
        if let Some(state) = self
            .restart
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            for session_id in session_ids {
                state.static_allow.remove(session_id);
            }
        }
    }

    /// Whether the restart state still records static allows for `session_id`.
    #[cfg(test)]
    pub(super) fn tracks_static_allow(&self, session_id: &str) -> bool {
        self.restart
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|state| state.static_allow.contains_key(session_id))
    }

    /// Persist the registrations and arm a lifecycle watch for each launcher.
    // The restart lock is taken before the registrations are read, as in
    // `persist_static_allow`, so the two paths cannot deadlock.
    fn commit_registry(&self) {
        let mut restart = self.restart.lock().unwrap_or_else(PoisonError::into_inner);
        let sessions = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(PoisonError::into_inner);

        self.lifecycle.sync(&sessions);

        if let Some(state) = restart.as_mut() {
            state.persist(&sessions);
        }
    }

    /// Reinstate the registrations whose launcher is still the process that
    /// registered them, with their static allows. The scope of a launcher
    /// that exited while the daemon was down is killed.
    fn restore_registry(&mut self, loaded: LoadedState, state: &mut RestartState) {
        let mut sessions = self
            .sandbox_sessions
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let inner = self.inner.get_mut();

        for (id, registration) in loaded.sessions {
            if !survives_crash(&registration) {
                continue;
            }

            if Launcher::of(&registration).is_some_and(Launcher::is_running) {
                sessions.insert(id, adopt_orphaned_root(registration));
            } else {
                report_kill(&id, self.lifecycle.kill_scope(&registration));
            }
        }

        for (id, rules) in loaded.static_allow {
            if sessions.contains_key(&id) {
                inner
                    .sandbox_filesystem_static_allow
                    .insert(sandbox_session_static_allow_key(&id), rules.clone());
                state.static_allow.insert(id, rules);
            }
        }
    }
}

/// The registration with a root pid that is no longer inside the launcher's
/// tree cleared, so the next descendant adopts the session.
fn adopt_orphaned_root(mut registration: SandboxSessionRegistration) -> SandboxSessionRegistration {
    if let (
        crate::store::types::LauncherBinding::Bound {
            pid: launcher_pid, ..
        },
        crate::store::types::RootAdoption::Adopted { pid: root_pid },
    ) = (registration.launcher, registration.root)
        && !is_descendant_of(launcher_pid, root_pid)
    {
        registration.root = crate::store::types::RootAdoption::Unadopted;
    }

    registration
}

// The file is trusted because it lives in a root-owned directory and is
// written only by root; sandboxes cannot modify it.
fn read_state(path: &Path) -> Option<LoadedState> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            warn!(%error, path = %path.display(), "ignoring unreadable sandbox state");
            return None;
        }
    };

    match serde_json::from_str(&content) {
        Ok(state) => Some(state),
        Err(error) => {
            warn!(%error, path = %path.display(), "ignoring corrupt sandbox state");
            None
        }
    }
}

/// Replace `path` with `content`, readable by root only.
pub(super) fn write_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file: File = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;

    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(content)?;
    drop(file);
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{
        FileAccess, ProcessIds, ResolvedRequestContext, SandboxPaths,
        socket_owner::process_start_time_ticks,
    };

    use super::*;
    use crate::store::{
        TrustedPeer,
        context::read_proc_ppid,
        lifecycle::fixture::{FakeSandbox, eventually, store_over},
        test_store,
        types::ExportReader,
    };

    const SESSION: &str = "sandbox-restart";

    struct Dirs {
        _dir: tempfile::TempDir,
        paths: RestartPaths,
    }

    fn dirs() -> Dirs {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = RestartPaths {
            state: dir.path().join("sandbox-state.json"),
            handoff: dir.path().join("policyd-handoff.json"),
        };

        Dirs { _dir: dir, paths }
    }

    fn restored_store(paths: &RestartPaths) -> PolicyStore {
        let mut store = test_store();

        store.restore_from(paths.clone());
        store
    }

    fn session_context() -> ResolvedRequestContext {
        ResolvedRequestContext::new(
            SandboxPaths::default(),
            ProcessIds::default(),
            Some(SESSION.into()),
        )
    }

    fn peer_context(peer: u32, uid: u32) -> ResolvedRequestContext {
        ResolvedRequestContext::new(
            SandboxPaths::default(),
            ProcessIds::new(peer, uid),
            Some(SESSION.into()),
        )
    }

    fn registration(launcher_pid: u32, launcher_start_ticks: u64) -> SandboxSessionRegistration {
        let launcher = if launcher_pid == 0 {
            crate::store::types::LauncherBinding::Unbound
        } else {
            crate::store::types::LauncherBinding::Bound {
                pid: launcher_pid,
                start_ticks: launcher_start_ticks,
            }
        };
        SandboxSessionRegistration {
            root: crate::store::types::RootAdoption::Unadopted,
            owner_uid: nix::unistd::getuid().as_raw(),
            project_root: PathBuf::new(),
            package: Some("omp".into()),
            launcher,
            cgroup: None,
            export_reader: None,
        }
    }

    struct SeededSession {
        id: &'static str,
        registration: SandboxSessionRegistration,
    }

    fn seeded(id: &'static str, registration: SandboxSessionRegistration) -> SeededSession {
        SeededSession { id, registration }
    }

    fn write_sessions(path: &Path, seeded_sessions: &[SeededSession]) {
        let rules = [FilesystemRule::new("/allowed/**", FileAccess::All, "test")];
        let mut view = StateView {
            sessions: BTreeMap::new(),
            static_allow: BTreeMap::new(),
        };

        for session in seeded_sessions {
            view.sessions.insert(session.id, &session.registration);
            view.static_allow.insert(session.id, &rules);
        }

        write_atomic(path, &serde_json::to_vec(&view).expect("state json")).expect("write state");
    }

    #[tokio::test]
    async fn restarted_policyd_restores_live_sandbox_state() {
        let dirs = dirs();
        let uid = nix::unistd::getuid().as_raw();
        let peer = std::process::id();
        let launcher = read_proc_ppid(peer).expect("parent of the test process");

        let first = restored_store(&dirs.paths);

        first
            .register_sandbox(SESSION, "omp", uid, launcher, peer)
            .expect("register sandbox");
        first
            .note_sandbox_peer(TrustedPeer { pid: peer, uid }, SESSION)
            .expect("adopt session root");
        first
            .store_sandbox_static_allow(&session_context(), vec![FilesystemRule::new(
                "/allowed/**",
                FileAccess::All,
                "test",
            )])
            .await;

        let mode = fs::metadata(&dirs.paths.state)
            .expect("state file")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o600);

        drop(first);
        let second = restored_store(&dirs.paths);
        let resolved = second.resolve_context_with_peer(
            &peer_context(peer, uid),
            Some(TrustedPeer { pid: peer, uid }),
        );

        assert_eq!(resolved.sandbox_session_id.as_deref(), Some(SESSION));
        assert_eq!(resolved.package.as_deref(), Some("omp"));
        assert!(
            second
                .static_filesystem_allowed(
                    Path::new("/allowed/file"),
                    FileAccess::Read,
                    &session_context(),
                )
                .await
        );
        assert!(
            !second
                .static_filesystem_allowed(
                    Path::new("/elsewhere/file"),
                    FileAccess::Read,
                    &session_context(),
                )
                .await
        );
    }

    #[tokio::test]
    async fn restart_keeps_the_filesystem_monitor_record() {
        let dirs = dirs();
        let uid = nix::unistd::getuid().as_raw();
        let peer = std::process::id();
        let launcher = read_proc_ppid(peer).expect("parent of the test process");

        let first = restored_store(&dirs.paths);

        first
            .register_sandbox(SESSION, "omp", uid, launcher, peer)
            .expect("register sandbox");
        first.update_registry(|sessions| {
            sessions
                .get_mut(SESSION)
                .expect("registered session")
                .export_reader = ExportReader::of(peer);
        });
        drop(first);

        let second = restored_store(&dirs.paths);

        assert_eq!(
            second
                .sandbox_sessions
                .read()
                .expect("sessions lock")
                .get(SESSION)
                .expect("restored session")
                .export_reader,
            ExportReader::of(peer),
            "a restarted policyd keeps exporting for a monitored sandbox"
        );
    }

    #[tokio::test]
    async fn restart_drops_sandboxes_whose_launcher_is_gone() {
        let dirs = dirs();
        let launcher = read_proc_ppid(std::process::id()).expect("parent of the test process");
        let launcher_ticks = process_start_time_ticks(launcher).expect("launcher start time");
        let mut exited = std::process::Command::new("true")
            .spawn()
            .expect("spawn child");
        let exited_pid = exited.id();
        let exited_ticks = process_start_time_ticks(exited_pid).expect("child start time");

        exited.wait().expect("reap child");
        write_sessions(&dirs.paths.state, &[
            seeded("live", registration(launcher, launcher_ticks)),
            seeded("reused-pid", registration(launcher, launcher_ticks + 1)),
            seeded("dead", registration(exited_pid, exited_ticks)),
            seeded("unbound", registration(0, 0)),
        ]);

        let store = restored_store(&dirs.paths);
        let mut ids: Vec<String> = store
            .sandbox_sessions
            .read()
            .expect("sessions lock")
            .keys()
            .cloned()
            .collect();

        ids.sort();

        assert_eq!(ids, ["live"]);

        let rewritten: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&dirs.paths.state).expect("state file"))
                .expect("valid state");

        assert_eq!(
            rewritten["sessions"]
                .as_object()
                .expect("sessions")
                .keys()
                .collect::<Vec<_>>(),
            ["live"]
        );
        assert_eq!(
            rewritten["static_allow"]
                .as_object()
                .expect("static_allow")
                .keys()
                .collect::<Vec<_>>(),
            ["live"]
        );

        let static_allow_keys: Vec<String> = store
            .inner
            .lock()
            .await
            .sandbox_filesystem_static_allow
            .keys()
            .cloned()
            .collect();

        assert_eq!(static_allow_keys, ["sandbox:live"]);
    }

    #[test]
    fn corrupt_state_file_is_ignored() {
        let dirs = dirs();

        fs::write(&dirs.paths.state, "{not json").expect("write corrupt state");

        let store = restored_store(&dirs.paths);

        assert!(
            store
                .sandbox_sessions
                .read()
                .expect("sessions lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn restored_sandbox_is_killed_when_its_launcher_exits() {
        let dirs = dirs();
        let mut sandbox = FakeSandbox::start();
        let uid = nix::unistd::getuid().as_raw();

        let mut first = store_over(sandbox.root());
        first.restore_from(dirs.paths.clone());
        first
            .register_sandbox(SESSION, "omp", uid, sandbox.launcher_pid(), sandbox.peer)
            .expect("register sandbox");
        sandbox.record_scope(&first, SESSION);
        drop(first);

        let mut second = store_over(sandbox.root());
        second.restore_from(dirs.paths.clone());

        assert!(
            second
                .sandbox_sessions
                .read()
                .expect("sessions lock")
                .contains_key(SESSION),
            "a sandbox with a live launcher survives the restart"
        );
        assert_eq!(sandbox.kill_file(), "");

        sandbox.end_launcher();
        eventually(|| sandbox.kill_file() == "1").await;
    }

    #[tokio::test]
    async fn restart_kills_the_scope_of_a_launcher_that_exited_while_down() {
        let dirs = dirs();
        let mut sandbox = FakeSandbox::start();
        let uid = nix::unistd::getuid().as_raw();

        let mut first = store_over(sandbox.root());
        first.restore_from(dirs.paths.clone());
        first
            .register_sandbox(SESSION, "omp", uid, sandbox.launcher_pid(), sandbox.peer)
            .expect("register sandbox");
        sandbox.record_scope(&first, SESSION);
        drop(first);
        sandbox.end_launcher();

        let mut second = store_over(sandbox.root());
        second.restore_from(dirs.paths);

        assert_eq!(sandbox.kill_file(), "1");
        assert!(
            second
                .sandbox_sessions
                .read()
                .expect("sessions lock")
                .is_empty(),
            "a dead launcher's registration is dropped"
        );
    }
}
