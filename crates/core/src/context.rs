//! Sandbox context resolution with three trust levels.
//!
//! One module, three entry points. Each entry point encodes its trust level
//! internally:
//!
//! - [`wire_context`]: peer env. Assembles the `RequestContext` a client sends
//!   to policyd from the caller's own paths, falling back to the persisted
//!   session file and the process environment.
//! - [`peer_context`]: `/proc`. Resolves paths by inspecting the peer process
//!   itself. The environment comes from `/proc/<pid>/environ` and the home
//!   directory is verified against the uid's passwd entry.
//! - [`daemon_context`]: `/proc`, persisted session file, and daemon env. Full
//!   daemon-side resolution for requests that name a process.
//!
//! The session-context JSON file at `/run/agent-sandbox/session-context.json`
//! is read and written here. [`persist_session_paths`] exposes the write side
//! to daemons.

use std::{
    env,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{merge_policy::ProjectPolicyContext, rpc::RequestContext};

/// Shared session context for policyd and enforcement daemons.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionContext {
    /// Process working directory, if known.
    pub cwd: Option<PathBuf>,
    /// User home directory, if known.
    pub home: Option<PathBuf>,
    /// Git project root, if known.
    pub project_root: Option<PathBuf>,
}

fn session_context_path() -> PathBuf {
    env::var("AGENT_SANDBOX_SESSION_CONTEXT_PATH").map_or_else(
        |_| PathBuf::from("/run/agent-sandbox/session-context.json"),
        PathBuf::from,
    )
}

#[must_use]
fn read_session_context() -> SessionContext {
    let path = session_context_path();

    let Ok(data) = std::fs::read_to_string(&path) else {
        return SessionContext::default();
    };

    serde_json::from_str(&data).unwrap_or_default()
}

fn write_session_context(ctx: &SessionContext) {
    let path = session_context_path();

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp = path.with_extension("tmp");

    if let Ok(json) = serde_json::to_string_pretty(ctx)
        && std::fs::write(&tmp, format!("{json}\n")).is_ok()
    {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn non_empty_path(path: &Path) -> Option<&Path> {
    if path.as_os_str().is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Cwd / home / `project_root` after merging peer, file, and env sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPaths {
    cwd: PathBuf,
    home: PathBuf,
    project_root: PathBuf,
}

impl SandboxPaths {
    /// Construct [`SandboxPaths`] from all three paths directly.
    #[must_use]
    pub fn new(
        cwd: impl Into<PathBuf>,
        home: impl Into<PathBuf>,
        project_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            cwd: cwd.into(),
            home: home.into(),
            project_root: project_root.into(),
        }
    }

    /// Construct [`SandboxPaths`] from optional values, defaulting to empty
    /// paths where a value is absent.
    #[must_use]
    pub fn from_wire(
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
    ) -> Self {
        Self {
            cwd: cwd.unwrap_or_default(),
            home: home.unwrap_or_default(),
            project_root: project_root.unwrap_or_default(),
        }
    }

    /// Merge in optional values, keeping this instance's values where an input
    /// is `None`. Used to layer peer, file, and env sources.
    #[must_use]
    pub fn merged_with(
        &self,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
    ) -> Self {
        Self::from_wire(
            cwd.or_else(|| self.cwd_path()),
            home.or_else(|| self.home_path()),
            project_root.or_else(|| self.project_root_path()),
        )
    }

    /// Cwd, or `None` if the stored path is empty.
    #[must_use]
    pub fn cwd(&self) -> Option<&Path> {
        non_empty_path(&self.cwd)
    }

    /// Home directory, or `None` if the stored path is empty.
    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        non_empty_path(&self.home)
    }

    /// `project_root`, or `None` if the stored path is empty.
    #[must_use]
    pub fn project_root(&self) -> Option<&Path> {
        non_empty_path(&self.project_root)
    }

    /// Owned copy of the cwd, or `None` if empty.
    #[must_use]
    pub fn cwd_path(&self) -> Option<PathBuf> {
        self.cwd().map(Path::to_path_buf)
    }

    /// Owned copy of the home directory, or `None` if empty.
    #[must_use]
    pub fn home_path(&self) -> Option<PathBuf> {
        self.home().map(Path::to_path_buf)
    }

    /// Owned copy of the `project_root`, or `None` if empty.
    #[must_use]
    pub fn project_root_path(&self) -> Option<PathBuf> {
        self.project_root().map(Path::to_path_buf)
    }
}

impl From<&SandboxPaths> for SessionContext {
    fn from(paths: &SandboxPaths) -> Self {
        Self {
            cwd: paths.cwd_path(),
            home: paths.home_path(),
            project_root: paths.project_root_path(),
        }
    }
}

/// `pid` / `uid` from the wire or peer cred. `0` means unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessIds {
    /// Process id, or `0` when unknown.
    pub pid: u32,
    /// User id, or `0` when unknown.
    pub uid: u32,
}

impl ProcessIds {
    /// Construct from a pid and uid directly.
    #[must_use]
    pub const fn new(pid: u32, uid: u32) -> Self {
        Self { pid, uid }
    }

    /// Construct from optional pid and uid, treating `None` as `0`.
    #[must_use]
    pub const fn from_options(pid: Option<u32>, uid: Option<u32>) -> Self {
        Self {
            pid: match pid {
                Some(pid) => pid,
                None => 0,
            },
            uid: match uid {
                Some(uid) => uid,
                None => 0,
            },
        }
    }

    /// Pid as `Some` when known (`> 0`), else `None`.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        (self.pid > 0).then_some(self.pid)
    }

    /// Uid as `Some` when known (`> 0`), else `None`.
    #[must_use]
    pub fn uid(&self) -> Option<u32> {
        (self.uid > 0).then_some(self.uid)
    }
}

/// Canonical daemon-side sandbox context after applying trust and enrichment.
///
/// `package` is server-derived attribution from a validated sandbox
/// registration. It is never read from wire input: policyd fills it from the
/// session registration only after verifying the requesting peer owns the
/// session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedRequestContext {
    /// Resolved cwd, home, and project root.
    pub paths: SandboxPaths,
    /// Process id and user id from wire or peer cred.
    pub ids: ProcessIds,
    /// Sandbox session this request belongs to, if any.
    pub sandbox_session_id: Option<String>,
    /// Server-derived package attribution, if validated against the session.
    pub package: Option<String>,
}

impl ResolvedRequestContext {
    /// Build a resolved context without package attribution.
    #[must_use]
    pub const fn new(
        paths: SandboxPaths,
        ids: ProcessIds,
        sandbox_session_id: Option<String>,
    ) -> Self {
        Self {
            paths,
            ids,
            sandbox_session_id,
            package: None,
        }
    }
}

/// Read the environment of a process from `/proc/<pid>/environ` as a map.
///
/// Returns an empty map if the file cannot be read. Malformed (non-null
/// separated) entries and entries without `=` are skipped.
/// Values and keys are decoded lossily as UTF-8.
#[must_use]
pub fn read_proc_environ(pid: u32) -> std::collections::HashMap<String, String> {
    let path = format!("/proc/{pid}/environ");

    let Ok(raw) = std::fs::read(&path) else {
        return std::collections::HashMap::new();
    };

    let mut env = std::collections::HashMap::new();

    for item in raw.split(|&b| b == 0) {
        if let Some(eq) = item.iter().position(|&b| b == b'=') {
            let (key, value) = item.split_at(eq);
            let value = &value[1..];

            env.insert(
                String::from_utf8_lossy(key).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            );
        }
    }

    env
}

fn read_proc_cwd(pid: u32) -> Option<PathBuf> {
    let link = format!("/proc/{pid}/cwd");
    std::fs::read_link(&link).ok()
}

/// Read the UID of a process from `/proc/<pid>/status`.
fn proc_uid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut parts = rest.split_whitespace();
            return parts.next().and_then(|s| s.parse().ok());
        }
    }

    None
}

/// Look up the home directory for a user id from the system passwd database.
///
/// Returns `None` when `uid` is `None` or no matching user is found.
#[must_use]
pub fn home_from_uid(uid: Option<u32>) -> Option<String> {
    let uid = uid?;

    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir.to_string_lossy().into_owned())
}

/// Process credentials for an RPC peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Process id of the peer, when the platform reports one.
    pub pid: u32,
    /// Real user id of the peer.
    pub uid: u32,
    /// Real group id of the peer, or `-1` when it does not fit in an `i32`.
    pub gid: i32,
}

/// Cwd / home / `project_root` resolved from a process's environment and
/// `/proc`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcContext {
    /// Current working directory claim from the process environment.
    pub cwd: Option<PathBuf>,
    /// Home directory claim.
    pub home: Option<PathBuf>,
    /// Discovered repository root, when inside a git work tree.
    pub project_root: Option<PathBuf>,
}

/// Assemble the `RequestContext` a client sends to policyd.
///
/// Trust level: peer env. The caller's own `cwd`, `home`, and `project_root`
/// claims are primary. Missing values fall back to the persisted session file
/// and then the process environment.
#[must_use]
pub fn wire_context(
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
    ids: ProcessIds,
    sandbox_session_id: Option<String>,
) -> RequestContext {
    let paths = resolve_sandbox_paths(cwd, home, project_root, ids);
    let mut ctx = RequestContext::from_paths_and_ids(&paths, ids);
    ctx.sandbox_session_id = sandbox_session_id;
    ctx
}

/// Cwd and home facts read from a verified peer process.
///
/// A process environment and cwd are display facts. They never establish a
/// project root; project attribution requires a separate authority binding.
#[must_use]
pub fn peer_context(pid: u32, uid: Option<u32>) -> ProcContext {
    if pid == 0 {
        return ProcContext::default();
    }

    let env = read_proc_environ(pid);
    let cwd = env
        .get("AGENT_SANDBOX_CWD")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| read_proc_cwd(pid));
    let home = env
        .get("AGENT_SANDBOX_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| uid.and_then(|u| home_from_uid(Some(u))).map(PathBuf::from));

    ProcContext {
        cwd,
        home,
        project_root: None,
    }
}

/// Full daemon-side resolution for a request that names a process.
///
/// Trust level: `/proc`, persisted session file, and daemon env. The uid and
/// sandbox session id are derived from the process itself, and the paths are
/// resolved peer-first with file and env fallbacks.
#[must_use]
pub fn daemon_context(pid: Option<u32>) -> ResolvedRequestContext {
    let pid = pid.unwrap_or(0);
    let ids = ProcessIds::new(pid, proc_uid(pid).unwrap_or(0));

    ResolvedRequestContext::new(
        resolve_daemon_paths(ids),
        ids,
        sandbox_session_id_from_pid(pid),
    )
}

/// Peer process paths from `SO_PEERCRED` + `/proc`.
fn peer_sandbox_paths(ids: ProcessIds) -> SandboxPaths {
    let ctx = ids
        .pid()
        .map_or_else(ProcContext::default, context_from_pid);

    let home = ctx.home.clone().or_else(|| {
        ids.uid()
            .and_then(|u| home_from_uid(Some(u)))
            .map(PathBuf::from)
    });

    SandboxPaths::from_wire(ctx.cwd, home, ctx.project_root)
}

/// Resolve sandbox paths from peer env, session file, and `/proc` (never the
/// process cwd).
fn resolve_sandbox_paths(
    peer_cwd: Option<PathBuf>,
    peer_home: Option<PathBuf>,
    peer_project: Option<PathBuf>,
    ids: ProcessIds,
) -> SandboxPaths {
    let file = read_session_context();

    let cwd: Option<PathBuf> = peer_cwd
        .or(file.cwd)
        .or_else(|| std::env::var("AGENT_SANDBOX_CWD").ok().map(PathBuf::from));

    let mut home: Option<PathBuf> = peer_home
        .or(file.home)
        .or_else(|| {
            ids.uid()
                .and_then(|u| home_from_uid(Some(u)))
                .map(PathBuf::from)
        })
        .or_else(|| std::env::var("AGENT_SANDBOX_HOME").ok().map(PathBuf::from))
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from));

    let mut project_root: Option<PathBuf> = peer_project.or(file.project_root).or_else(|| {
        std::env::var("AGENT_SANDBOX_PROJECT_ROOT")
            .ok()
            .map(PathBuf::from)
    });

    if project_root.is_none() || home.is_none() {
        let project =
            ProjectPolicyContext::new(home.as_deref(), cwd.as_deref(), project_root.as_deref());

        if project_root.is_none() {
            project_root = project.project_root().map(PathBuf::from);
        }

        if home.is_none() {
            home = project.home_hint().map(PathBuf::from);
        }
    }

    SandboxPaths::new(
        cwd.unwrap_or_default(),
        home.unwrap_or_default(),
        project_root.unwrap_or_default(),
    )
}

/// Full daemon-side resolution (peer + file + env).
fn resolve_daemon_paths(ids: ProcessIds) -> SandboxPaths {
    let peer = peer_sandbox_paths(ids);

    resolve_sandbox_paths(
        peer.cwd_path(),
        peer.home_path(),
        peer.project_root_path(),
        ids,
    )
}

/// Persist merged paths for later RPCs in this session.
pub fn persist_session_paths(paths: &SandboxPaths) {
    if paths.home().is_some() {
        let ctx = SessionContext::from(paths);
        write_session_context(&ctx);
    }
}

/// Cwd / home / `project_root` from a process's environment and `/proc`.
fn context_from_pid(pid: u32) -> ProcContext {
    if pid == 0 {
        return ProcContext {
            cwd: None,
            home: None,
            project_root: None,
        };
    }

    let env = read_proc_environ(pid);

    let cwd = env
        .get("AGENT_SANDBOX_CWD")
        .cloned()
        .map(PathBuf::from)
        .or_else(|| read_proc_cwd(pid));

    let home = env
        .get("AGENT_SANDBOX_HOME")
        .cloned()
        .or_else(|| env.get("HOME").cloned())
        .map(PathBuf::from);

    let project_root = env
        .get("AGENT_SANDBOX_PROJECT_ROOT")
        .cloned()
        .map(PathBuf::from);

    ProcContext {
        cwd,
        home,
        project_root,
    }
}

/// If `path` lies inside a Git work tree, return that tree's root directory.
///
/// Walks upward from `path` looking for a `.git` directory or gitfile. Used
/// when matching project-relative allow rules (e.g. `./.git`) so Git metadata
/// under `.git/objects` is allowed even if the sandbox launcher froze a stale
/// `AGENT_SANDBOX_PROJECT_ROOT` or the tracee changed directory into another
/// repository.
#[must_use]
pub fn discover_git_project_root(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();

    loop {
        let git_meta = current.join(".git");

        if git_meta.is_dir() || git_meta.is_file() {
            return Some(current);
        }

        if !current.pop() {
            return None;
        }
    }
}

/// Whether `child` is the same as or under `ancestor` after canonicalization.
#[must_use]
pub fn is_path_descendant(child: &Path, ancestor: &Path) -> bool {
    let Ok(child) = child.canonicalize() else {
        return false;
    };

    let Ok(ancestor) = ancestor.canonicalize() else {
        return false;
    };

    child == ancestor || child.starts_with(&ancestor)
}

/// Read the `AGENT_SANDBOX_SESSION_ID` from a process's `/proc/<pid>/environ`.
///
/// Returns `None` when the pid is `0`, the variable is absent, or its value
/// is empty.
#[must_use]
pub fn sandbox_session_id_from_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }

    read_proc_environ(pid)
        .get("AGENT_SANDBOX_SESSION_ID")
        .filter(|value| !value.is_empty())
        .cloned()
}

/// Return process credentials for the peer of a connected Unix domain socket.
pub fn peer_cred_unix(stream: &tokio::net::UnixStream) -> Option<PeerCredentials> {
    let cred = stream.peer_cred().ok()?;
    let pid = u32::try_from(cred.pid()?).ok()?;
    let uid = cred.uid();
    let gid = i32::try_from(cred.gid()).unwrap_or(-1);
    Some(PeerCredentials { pid, uid, gid })
}

/// Parent pid from `/proc/<pid>/status` (`PPid` field).
#[must_use]
fn read_proc_ppid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }

    None
}

/// Whether `pid` is `ancestor` or one of its descendants in the host pid
/// namespace.
#[must_use]
pub fn is_descendant_of(ancestor: u32, pid: u32) -> bool {
    if ancestor == 0 || pid == 0 {
        return false;
    }

    if ancestor == pid {
        return true;
    }

    let mut current = pid;

    for _ in 0..256 {
        let Some(parent_pid) = read_proc_ppid(current) else {
            break;
        };

        if parent_pid == ancestor {
            return true;
        }

        if parent_pid <= 1 {
            break;
        }

        current = parent_pid;
    }

    false
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        ProcessIds, SandboxPaths, daemon_context, discover_git_project_root, wire_context,
    };
    use crate::SessionContext;

    #[test]
    fn sandbox_paths_merged_with_prefers_explicit_values() {
        let base = SandboxPaths::new("/cwd", "/home", "/project");
        let merged = base.merged_with(None, Some("/alt-home".into()), None);
        assert_eq!(merged.cwd(), Some(Path::new("/cwd")));
        assert_eq!(merged.home(), Some(Path::new("/alt-home")));
        assert_eq!(merged.project_root(), Some(Path::new("/project")));
    }

    #[test]
    fn process_ids_from_options_uses_zero_for_unknowns() {
        let ids = ProcessIds::from_options(Some(42), None);
        assert_eq!(ids.pid(), Some(42));
        assert_eq!(ids.uid(), None);
    }

    #[test]
    fn sandbox_paths_convert_to_session_context() {
        let paths = SandboxPaths::new("/cwd", "", "/project");
        let ctx = SessionContext::from(&paths);
        assert_eq!(ctx.cwd.as_deref(), Some(Path::new("/cwd")));
        assert_eq!(ctx.home, None);
        assert_eq!(ctx.project_root.as_deref(), Some(Path::new("/project")));
    }

    #[test]
    fn wire_context_preserves_paths_ids_and_session_id() {
        let ctx = wire_context(
            Some("/cwd".into()),
            Some("/home/user".into()),
            Some("/cwd/repo".into()),
            ProcessIds::new(42, 1000),
            Some("session-a".into()),
        );

        assert_eq!(ctx.sandbox_paths().cwd(), Some(Path::new("/cwd")));
        assert_eq!(ctx.sandbox_paths().home(), Some(Path::new("/home/user")));

        assert_eq!(
            ctx.sandbox_paths().project_root(),
            Some(Path::new("/cwd/repo"))
        );

        assert_eq!(ctx.ids(), ProcessIds::new(42, 1000));
        assert_eq!(ctx.sandbox_session_id.as_deref(), Some("session-a"));
    }

    #[test]
    fn daemon_context_resolves_the_calling_process() {
        let ctx = daemon_context(Some(std::process::id()));
        assert_eq!(ctx.ids.pid(), Some(std::process::id()));

        assert!(
            ctx.paths.cwd().is_some(),
            "cwd must resolve from /proc/self/cwd"
        );
    }

    #[test]
    fn discover_git_root_from_objects_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git/objects/pack")).expect("git tree");
        let objects = repo.join(".git/objects/pack");

        assert_eq!(
            discover_git_project_root(&objects),
            Some(repo.canonicalize().expect("canonicalize"))
        );
    }

    #[test]
    fn discover_git_root_from_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).expect("git dir");
        std::fs::write(repo.join(".git/config"), "[core]\n").expect("config");

        assert_eq!(
            discover_git_project_root(&repo.join(".git/config")),
            Some(repo.canonicalize().expect("canonicalize"))
        );
    }

    #[test]
    fn discover_git_root_returns_none_outside_repo() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-a-repo/file");
        std::fs::create_dir_all(&path).expect("mkdir");
        assert_eq!(discover_git_project_root(&path), None);
    }
}
