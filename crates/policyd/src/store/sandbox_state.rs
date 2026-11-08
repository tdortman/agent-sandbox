//! Per-sandbox state that survives a policyd restart.
//!
//! Launcher-bound session registrations and their static filesystem allows
//! are written to a state file after each mutation and reloaded by the next
//! daemon, so a running sandbox keeps its package attribution and static
//! allows. Session approvals, verdict caches and network grants are not
//! persisted: losing them re-prompts.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::PoisonError,
};

use agent_sandbox_core::{
    FilesystemRule, is_descendant_of, socket_owner::process_start_time_ticks,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    access::sandbox_session_static_allow_key,
    types::{PolicyStore, SandboxSessionRegistration},
};

const DEFAULT_STATE_PATH: &str = "/run/agent-sandbox/sandbox-state.json";
const STATE_PATH_ENV: &str = "AGENT_SANDBOX_SANDBOX_STATE";

/// Where the sandbox state is written, and the static allows to write.
///
/// The static allows mirror `sandbox_filesystem_static_allow` entries of
/// sandbox sessions, keyed by session id, because the decision state sits
/// behind an async lock that the synchronous registration paths cannot take.
pub(super) struct SandboxStateFile {
    path: PathBuf,
    static_allow: HashMap<String, Vec<FilesystemRule>>,
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

impl PolicyStore {
    /// Persist launcher-bound sandbox state across restarts, and restore the
    /// state of sandboxes that are still running.
    ///
    /// The state file honours `AGENT_SANDBOX_SANDBOX_STATE`.
    pub fn enable_sandbox_state(&mut self) {
        let path = std::env::var_os(STATE_PATH_ENV)
            .map_or_else(|| PathBuf::from(DEFAULT_STATE_PATH), PathBuf::from);

        self.enable_sandbox_state_at(path);
    }

    pub(crate) fn enable_sandbox_state_at(&mut self, path: PathBuf) {
        let mut file = SandboxStateFile {
            path,
            static_allow: HashMap::new(),
        };
        let loaded = read_state(&file.path);

        if let Some(loaded) = &loaded {
            let mut sessions = self
                .sandbox_sessions
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let inner = self.inner.get_mut();

            for (id, registration) in &loaded.sessions {
                if let Some(registration) = live_registration(registration) {
                    sessions.insert(id.clone(), registration);
                }
            }

            for (id, rules) in &loaded.static_allow {
                if sessions.contains_key(id) {
                    inner
                        .sandbox_filesystem_static_allow
                        .insert(sandbox_session_static_allow_key(id), rules.clone());
                    file.static_allow.insert(id.clone(), rules.clone());
                }
            }
        }

        *self
            .sandbox_state
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner) = Some(file);

        if loaded.is_some() {
            self.persist_sandbox_state();
        }
    }

    /// Write the sandbox state file. A failure is logged and otherwise
    /// ignored: the request that changed the state must still succeed.
    pub(super) fn persist_sandbox_state(&self) {
        let state = self
            .sandbox_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        if let Some(file) = state.as_ref() {
            self.write_sandbox_state(file);
        }
    }

    /// Record the static allows of a sandbox session and write the state file.
    pub(super) fn persist_static_allow(&self, session_id: Option<&str>, rules: &[FilesystemRule]) {
        let mut state = self
            .sandbox_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        if let Some(file) = state.as_mut()
            && let Some(session_id) = session_id
        {
            file.static_allow
                .insert(session_id.to_string(), rules.to_vec());
            self.write_sandbox_state(file);
        }
    }

    fn write_sandbox_state(&self, file: &SandboxStateFile) {
        let sessions = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let mut view = StateView {
            sessions: BTreeMap::new(),
            static_allow: BTreeMap::new(),
        };

        for (id, registration) in sessions.iter() {
            if registration.launcher_pid > 0 {
                view.sessions.insert(id, registration);

                if let Some(rules) = file.static_allow.get(id) {
                    view.static_allow.insert(id, rules);
                }
            }
        }

        if let Err(error) = write_atomic(&file.path, &view) {
            warn!(%error, path = %file.path.display(), "failed to persist sandbox state");
        }

        drop(sessions);
    }
}

/// The registration when its launcher is still the process that registered
/// it, with a root pid that is no longer inside the launcher's tree cleared
/// so the next descendant adopts the session.
fn live_registration(
    registration: &SandboxSessionRegistration,
) -> Option<SandboxSessionRegistration> {
    if registration.launcher_pid == 0
        || process_start_time_ticks(registration.launcher_pid)
            .filter(|ticks| *ticks > 0)
            .is_none_or(|ticks| ticks != registration.launcher_start_ticks)
    {
        return None;
    }

    let mut registration = registration.clone();

    if !is_descendant_of(registration.launcher_pid, registration.root_pid) {
        registration.root_pid = 0;
    }

    Some(registration)
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

fn write_atomic(path: &Path, view: &StateView<'_>) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file: File = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;

    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(&serde_json::to_vec(view).map_err(io::Error::other)?)?;
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
    use crate::store::{TrustedPeer, context::read_proc_ppid, test_store};

    const SESSION: &str = "sandbox-restart";

    fn store_with_state(path: &Path) -> PolicyStore {
        let mut store = test_store();

        store.enable_sandbox_state_at(path.to_path_buf());
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
        SandboxSessionRegistration {
            root_pid: 0,
            owner_uid: nix::unistd::getuid().as_raw(),
            project_root: PathBuf::new(),
            package: Some("omp".into()),
            launcher_pid,
            launcher_start_ticks,
            cgroup: None,
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

        write_atomic(path, &view).expect("write state");
    }

    #[tokio::test]
    async fn restarted_policyd_restores_live_sandbox_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sandbox-state.json");
        let uid = nix::unistd::getuid().as_raw();
        let peer = std::process::id();
        let launcher = read_proc_ppid(peer).expect("parent of the test process");

        let first = store_with_state(&path);

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

        let mode = fs::metadata(&path)
            .expect("state file")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o600);

        let second = store_with_state(&path);
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
    async fn restart_drops_sandboxes_whose_launcher_is_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sandbox-state.json");
        let launcher = read_proc_ppid(std::process::id()).expect("parent of the test process");
        let launcher_ticks = process_start_time_ticks(launcher).expect("launcher start time");
        let mut exited = std::process::Command::new("true")
            .spawn()
            .expect("spawn child");
        let exited_pid = exited.id();
        let exited_ticks = process_start_time_ticks(exited_pid).expect("child start time");

        exited.wait().expect("reap child");
        write_sessions(&path, &[
            seeded("live", registration(launcher, launcher_ticks)),
            seeded("reused-pid", registration(launcher, launcher_ticks + 1)),
            seeded("dead", registration(exited_pid, exited_ticks)),
            seeded("unbound", registration(0, 0)),
        ]);

        let store = store_with_state(&path);
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
            serde_json::from_str(&fs::read_to_string(&path).expect("state file"))
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
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sandbox-state.json");

        fs::write(&path, "{not json").expect("write corrupt state");

        let store = store_with_state(&path);

        assert!(
            store
                .sandbox_sessions
                .read()
                .expect("sessions lock")
                .is_empty()
        );
    }
}
