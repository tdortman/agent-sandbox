//! Resolved sandbox paths and process identity (fewer `Option`s in daemon hot paths).

use std::path::{Path, PathBuf};

use crate::merge_policy::ProjectPolicyContext;
use crate::proc_context::{ProcContext, context_from_pid, home_from_uid};
use crate::session_context::{SessionContext, read_session_context, write_session_context};

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

    #[must_use]
    pub fn cwd(&self) -> Option<&Path> {
        non_empty_path(&self.cwd)
    }

    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        non_empty_path(&self.home)
    }

    #[must_use]
    pub fn project_root(&self) -> Option<&Path> {
        non_empty_path(&self.project_root)
    }

    pub fn cwd_path(&self) -> Option<PathBuf> {
        self.cwd().map(Path::to_path_buf)
    }

    pub fn home_path(&self) -> Option<PathBuf> {
        self.home().map(Path::to_path_buf)
    }

    pub fn project_root_path(&self) -> Option<PathBuf> {
        self.project_root().map(Path::to_path_buf)
    }

    #[must_use]
    pub fn cwd_string(&self) -> Option<String> {
        self.cwd().map(|p| p.to_string_lossy().into_owned())
    }

    #[must_use]
    pub fn home_string(&self) -> Option<String> {
        self.home().map(|p| p.to_string_lossy().into_owned())
    }

    #[must_use]
    pub fn project_root_string(&self) -> Option<String> {
        self.project_root()
            .map(|p| p.to_string_lossy().into_owned())
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

    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        (self.pid > 0).then_some(self.pid)
    }

    #[must_use]
    pub fn uid(&self) -> Option<u32> {
        (self.uid > 0).then_some(self.uid)
    }
}

/// Resolve sandbox paths from peer env, session file, and `/proc` (never the process cwd).
#[must_use]
pub fn resolve_sandbox_paths(
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

/// Peer process paths from `SO_PEERCRED` + `/proc`.
#[must_use]
pub fn peer_sandbox_paths(ids: ProcessIds) -> SandboxPaths {
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

/// Full daemon-side resolution (peer + file + env).
#[must_use]
pub fn resolve_daemon_paths(ids: ProcessIds) -> SandboxPaths {
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

#[cfg(test)]
mod tests {
    use super::{ProcessIds, SandboxPaths};
    use crate::SessionContext;
    use std::path::Path;

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
}
