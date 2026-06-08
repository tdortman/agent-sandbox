//! Match pending requests to the UI client that owns the agent.

use agent_sandbox_core::{is_descendant_of, omp_ui_owner_for_pid};

use super::types::{UiClient, UiSessionContext};

#[derive(Debug, Clone)]
pub(crate) struct UiRoute {
    pub request_pid: Option<u32>,
    pub cwd: Option<String>,
    #[allow(dead_code)]
    pub home: Option<String>,
    pub project_root: Option<String>,
}

impl UiRoute {
    #[must_use]
    pub fn new(
        request_pid: Option<u32>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    ) -> Self {
        Self {
            request_pid,
            cwd,
            home,
            project_root,
        }
    }
}

fn paths_match(ui: &UiSessionContext, route: &UiRoute) -> bool {
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

fn omp_pid_owns_request(client: &UiClient, route: &UiRoute) -> bool {
    client.ui_client == "omp"
        && client.owner_pid != 0
        && route.request_pid.is_some_and(|pid| {
            is_descendant_of(client.owner_pid, pid)
                || omp_ui_owner_for_pid(pid) == Some(client.owner_pid)
        })
}

fn request_owned_by_omp_pid(route: &UiRoute, omp_clients: &[&UiClient]) -> bool {
    route.request_pid.is_some_and(|pid| {
        let owner = omp_ui_owner_for_pid(pid);
        omp_clients.iter().any(|omp| {
            omp.owner_pid != 0
                && (is_descendant_of(omp.owner_pid, pid) || owner == Some(omp.owner_pid))
        })
    })
}

/// Whether a pending request should be handled by a registered OMP UI (skip kdialog spawn).
#[must_use]
pub(crate) fn request_owned_by_omp(route: &UiRoute, omp_clients: &[&UiClient]) -> bool {
    request_owned_by_omp_pid(route, omp_clients)
}

fn omp_owns_request(client: &UiClient, route: &UiRoute) -> bool {
    client.ui_client == "omp" && omp_pid_owns_request(client, route)
}

#[must_use]
pub(crate) fn ui_client_matches(
    client: &UiClient,
    ctx: &UiSessionContext,
    route: &UiRoute,
    omp_clients: &[&UiClient],
) -> bool {
    if client.ui_client == "omp" {
        return omp_owns_request(client, route);
    }
    if request_owned_by_omp_pid(route, omp_clients) {
        return false;
    }
    paths_match(ctx, route)
}

#[cfg(test)]
mod tests {
    use super::{UiRoute, ui_client_matches};
    use crate::store::types::{UiClient, UiSessionContext};

    fn ctx(cwd: &str, project_root: &str) -> UiSessionContext {
        UiSessionContext {
            cwd: Some(cwd.into()),
            home: Some("/home/tim".into()),
            project_root: Some(project_root.into()),
        }
    }

    fn omp_client(owner_pid: u32) -> UiClient {
        UiClient {
            session_id: "omp1".into(),
            ui_client: "omp".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().unwrap().0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid,
        }
    }

    #[tokio::test]
    async fn omp_ui_matches_own_process() {
        let pid = std::process::id();
        let omp = omp_client(pid);
        let omp_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(Some(pid), Some("/repo".into()), None, Some("/repo".into()));
        assert!(ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn omp_does_not_match_unrelated_project_paths() {
        let pid = std::process::id();
        let omp = omp_client(pid);
        let omp_ctx = ctx("/dotfiles", "/home/tim/dotfiles");
        let route = UiRoute::new(None, Some("/other".into()), None, Some("/other".into()));
        assert!(!ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn omp_matches_child_of_owner() {
        let owner_pid = std::process::id();
        let omp = omp_client(owner_pid);
        let omp_ctx = ctx("/repo", "/repo");
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 0")
            .spawn()
            .expect("spawn sh");
        let child_pid = child.id();
        let route = UiRoute::new(
            Some(child_pid),
            Some("/repo".into()),
            None,
            Some("/repo".into()),
        );
        let matches = ui_client_matches(&omp, &omp_ctx, &route, &[&omp]);
        let _ = child.wait();
        if agent_sandbox_core::looks_like_omp_ui_process(owner_pid) {
            assert!(matches);
        }
    }

    #[tokio::test]
    async fn omp_does_not_match_same_project_without_pid() {
        let pid = std::process::id();
        let omp = omp_client(pid);
        let omp_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()));
        assert!(!ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn standalone_matches_when_omp_on_same_project() {
        let pid = std::process::id();
        let omp = omp_client(pid);
        let omp_ctx = ctx("/repo", "/repo");
        let standalone = UiClient {
            session_id: "ui1".into(),
            ui_client: "standalone".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().unwrap().0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid: 0,
        };
        let standalone_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()));
        assert!(!ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
        assert!(ui_client_matches(
            &standalone,
            &standalone_ctx,
            &route,
            &[&omp],
        ));
    }

    #[tokio::test]
    async fn standalone_matches_same_project_paths() {
        let standalone = UiClient {
            session_id: "ui1".into(),
            ui_client: "standalone".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().unwrap().0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid: 0,
        };
        let standalone_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()));
        assert!(ui_client_matches(&standalone, &standalone_ctx, &route, &[],));
    }
}
