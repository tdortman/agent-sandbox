//! Resolved sandbox paths and process identity (fewer `Option`s in daemon/proxy hot paths).

use std::path::PathBuf;

use crate::merge_policy::{discover_project_policy, infer_home_from_paths};
use crate::proc_context::{context_from_pid, home_from_uid};
use crate::session_context::{SessionContext, read_session_context, write_session_context};

const fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

/// Cwd / home / project_root after merging peer, file, and env sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPaths {
    cwd: String,
    home: String,
    project_root: String,
}

impl SandboxPaths {
    #[must_use]
    pub fn new(
        cwd: impl Into<String>,
        home: impl Into<String>,
        project_root: impl Into<String>,
    ) -> Self {
        Self {
            cwd: cwd.into(),
            home: home.into(),
            project_root: project_root.into(),
        }
    }

    #[must_use]
    pub fn from_wire(
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    ) -> Self {
        Self {
            cwd: cwd.unwrap_or_default(),
            home: home.unwrap_or_default(),
            project_root: project_root.unwrap_or_default(),
        }
    }

    pub fn cwd(&self) -> Option<&str> {
        non_empty(&self.cwd)
    }

    pub fn home(&self) -> Option<&str> {
        non_empty(&self.home)
    }

    pub fn project_root(&self) -> Option<&str> {
        non_empty(&self.project_root)
    }

    pub fn cwd_string(&self) -> Option<String> {
        self.cwd().map(str::to_owned)
    }

    pub fn home_string(&self) -> Option<String> {
        self.home().map(str::to_owned)
    }

    pub fn project_root_string(&self) -> Option<String> {
        self.project_root().map(str::to_owned)
    }

    #[must_use]
    pub fn to_session_context(&self) -> SessionContext {
        SessionContext {
            cwd: self.cwd_string(),
            home: self.home_string(),
            project_root: self.project_root_string(),
        }
    }
}

/// `pid` / `uid` from the wire or peer cred; `0` means unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessIds {
    pub pid: u32,
    pub uid: u32,
}

impl ProcessIds {
    #[must_use]
    pub const fn new(pid: u32, uid: u32) -> Self {
        Self { pid, uid }
    }

    pub fn pid(&self) -> Option<u32> {
        (self.pid > 0).then_some(self.pid)
    }

    pub fn uid(&self) -> Option<u32> {
        (self.uid > 0).then_some(self.uid)
    }

    #[must_use]
    pub fn from_wire(pid: Option<u32>, uid: Option<u32>) -> Self {
        Self {
            pid: pid.unwrap_or(0),
            uid: uid.unwrap_or(0),
        }
    }
}

/// Resolve sandbox paths from peer env, session file, and `/proc` (never the process cwd).
#[must_use]
pub fn resolve_sandbox_paths(
    peer_cwd: Option<String>,
    peer_home: Option<String>,
    peer_project: Option<String>,
    ids: ProcessIds,
) -> SandboxPaths {
    let file = read_session_context();
    let cwd = peer_cwd
        .or(file.cwd)
        .or_else(|| std::env::var("AGENT_SANDBOX_CWD").ok());
    let mut home = peer_home
        .or(file.home)
        .or_else(|| ids.uid().and_then(|u| home_from_uid(Some(u))))
        .or_else(|| std::env::var("AGENT_SANDBOX_HOME").ok())
        .or_else(|| std::env::var("HOME").ok());
    let mut project_root = peer_project
        .or(file.project_root)
        .or_else(|| std::env::var("AGENT_SANDBOX_PROJECT_ROOT").ok());

    if let Some(ref c) = cwd
        && project_root.is_none()
        && let Ok(cwd_path) = PathBuf::from(c).canonicalize()
        && let Some(existing) = discover_project_policy(&cwd_path)
        && let Some(parent) = existing.parent().and_then(|p| p.parent())
    {
        project_root = Some(parent.to_string_lossy().into_owned());
    }

    if home.is_none() {
        let path_refs: Vec<&std::path::Path> = [project_root.as_deref(), cwd.as_deref()]
            .into_iter()
            .flatten()
            .map(std::path::Path::new)
            .collect();
        home = infer_home_from_paths(path_refs);
    }

    SandboxPaths::new(
        cwd.unwrap_or_default(),
        home.unwrap_or_default(),
        project_root.unwrap_or_default(),
    )
}

/// Peer process paths from `SO_PEERCRED` + `/proc`.
#[must_use]
pub fn peer_sandbox_paths(ids: ProcessIds) -> SandboxPaths {
    let (cwd, home, project_root) = ids.pid().map_or((None, None, None), context_from_pid);
    let home = home.or_else(|| ids.uid().and_then(|u| home_from_uid(Some(u))));
    SandboxPaths::from_wire(cwd, home, project_root)
}

/// Full proxy-side resolution (peer + file + env).
#[must_use]
pub fn resolve_proxy_paths(ids: ProcessIds) -> SandboxPaths {
    let peer = peer_sandbox_paths(ids);
    resolve_sandbox_paths(
        peer.cwd_string(),
        peer.home_string(),
        peer.project_root_string(),
        ids,
    )
}

/// Persist merged paths for later RPCs in this session.
pub fn persist_session_paths(paths: &SandboxPaths) {
    if paths.home().is_some() {
        write_session_context(&paths.to_session_context());
    }
}
