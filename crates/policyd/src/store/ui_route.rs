//! Match pending requests to the UI client that owns the agent.

use std::path::PathBuf;

use super::types::UiSessionContext;

#[derive(Debug, Clone)]
pub struct UiRoute {
    pub cwd: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub sandbox_session_id: Option<String>,
}

impl UiRoute {
    #[must_use]
    pub const fn new(cwd: Option<PathBuf>, project_root: Option<PathBuf>) -> Self {
        Self {
            cwd,
            project_root,
            sandbox_session_id: None,
        }
    }

    #[must_use]
    pub fn with_sandbox_session(mut self, sandbox_session_id: Option<String>) -> Self {
        self.sandbox_session_id = sandbox_session_id;
        self
    }
}

fn project_or_cwd_matches(ui: &UiSessionContext, route: &UiRoute) -> bool {
    if let (Some(a), Some(b)) = (&ui.project_root, &route.project_root)
        && a == b
    {
        return true;
    }
    if let (Some(a), Some(b)) = (&ui.cwd, &route.cwd)
        && a == b
    {
        return true;
    }
    false
}

pub fn paths_match(ui: &UiSessionContext, route: &UiRoute) -> bool {
    if let Some(route_session) = &route.sandbox_session_id {
        return ui
            .sandbox_session_id
            .as_ref()
            .is_some_and(|ui_session| ui_session == route_session);
    }
    project_or_cwd_matches(ui, route)
}
#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{UiRoute, paths_match};
    use crate::store::types::{UiClient, UiSessionContext};
    fn ctx(cwd: &Path, project_root: &Path) -> UiSessionContext {
        UiSessionContext {
            cwd: Some(cwd.to_path_buf()),
            home: Some(PathBuf::from("/home/user")),
            project_root: Some(project_root.to_path_buf()),
            sandbox_session_id: None,
        }
    }

    fn make_client(session_id: &str) -> UiClient {
        let (a, b) = tokio::net::UnixStream::pair().expect("unix stream pair");
        let _ = a;
        UiClient {
            session_id: session_id.into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(b.into_split().1)),
        }
    }

    #[tokio::test]
    async fn standalone_matches_same_project_paths() {
        let client = make_client("ui1");
        let client_ctx = ctx(Path::new("/repo"), Path::new("/repo"));
        let route = UiRoute::new(Some(PathBuf::from("/repo")), Some(PathBuf::from("/repo")));
        assert!(paths_match(&client_ctx, &route));
        let _ = client;
    }

    #[tokio::test]
    async fn standalone_does_not_match_unrelated_project_paths() {
        let client = make_client("ui1");
        let client_ctx = ctx(Path::new("/dotfiles"), Path::new("/home/user/dotfiles"));
        let route = UiRoute::new(Some("/other".into()), Some("/other".into()));
        assert!(!paths_match(&client_ctx, &route));
        let _ = client;
    }

    #[tokio::test]
    async fn standalone_requires_matching_sandbox_session_when_present() {
        let client = make_client("ui1");
        let mut client_ctx = ctx(Path::new("/repo"), Path::new("/repo"));
        client_ctx.sandbox_session_id = Some("sandbox-a".into());
        let route = UiRoute::new(Some("/repo".into()), Some("/repo".into()))
            .with_sandbox_session(Some("sandbox-b".into()));
        assert!(!paths_match(&client_ctx, &route));
        let route = UiRoute::new(Some("/repo".into()), Some("/repo".into()))
            .with_sandbox_session(Some("sandbox-a".into()));
        assert!(paths_match(&client_ctx, &route));
        let _ = client;
    }
}
