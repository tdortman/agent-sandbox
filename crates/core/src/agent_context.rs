//! Resolved sandbox paths and process identity (fewer `Option`s in daemon hot paths).

use std::path::Path;

use crate::merge_policy::ProjectPolicyContext;
use crate::proc_context::{ProcContext, context_from_pid, home_from_uid};
use crate::session_context::{SessionContext, read_session_context, write_session_context};

const fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

/// Cwd / home / `project_root` after merging peer, file, and env sources.
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

    #[must_use]
    pub fn merged_with(
        &self,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    ) -> Self {
        Self::from_wire(
            cwd.or_else(|| self.cwd_string()),
            home.or_else(|| self.home_string()),
            project_root.or_else(|| self.project_root_string()),
        )
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
}

impl From<&SandboxPaths> for SessionContext {
    fn from(paths: &SandboxPaths) -> Self {
        Self {
            cwd: paths.cwd_string(),
            home: paths.home_string(),
            project_root: paths.project_root_string(),
        }
    }
}

/// `pid` / `uid` from the wire or peer cred. `0` means unknown.
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

    pub fn pid(&self) -> Option<u32> {
        (self.pid > 0).then_some(self.pid)
    }

    pub fn uid(&self) -> Option<u32> {
        (self.uid > 0).then_some(self.uid)
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

    if project_root.is_none() || home.is_none() {
        let project = ProjectPolicyContext::new(
            home.as_deref().map(Path::new),
            cwd.as_deref().map(Path::new),
            project_root.as_deref().map(Path::new),
        );
        if project_root.is_none() {
            project_root = project
                .project_root()
                .map(|path| path.to_string_lossy().into_owned());
        }
        if home.is_none() {
            home = project.home_hint();
        }
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
    let ctx = ids.pid().map_or(ProcContext::default(), context_from_pid);
    let home = ctx
        .home
        .clone()
        .or_else(|| ids.uid().and_then(|u| home_from_uid(Some(u))));
    SandboxPaths::from_wire(ctx.cwd, home, ctx.project_root)
}

/// Full daemon-side resolution (peer + file + env).
#[must_use]
pub fn resolve_daemon_paths(ids: ProcessIds) -> SandboxPaths {
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
        let ctx = SessionContext::from(paths);
        write_session_context(&ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessIds, SandboxPaths};
    use crate::session_context::SessionContext;

    #[test]
    fn sandbox_paths_merged_with_prefers_explicit_values() {
        let base = SandboxPaths::new("/cwd", "/home", "/project");
        let merged = base.merged_with(None, Some("/alt-home".into()), None);
        assert_eq!(merged.cwd(), Some("/cwd"));
        assert_eq!(merged.home(), Some("/alt-home"));
        assert_eq!(merged.project_root(), Some("/project"));
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
        assert_eq!(ctx.cwd.as_deref(), Some("/cwd"));
        assert_eq!(ctx.home, None);
        assert_eq!(ctx.project_root.as_deref(), Some("/project"));
    }
}
