//! Match pending requests to the UI client that owns the agent.

use std::collections::HashMap;

use agent_sandbox_core::is_descendant_of;

use super::types::{UiClient, UiSessionContext};

#[derive(Debug, Clone)]
pub(crate) struct UiRoute {
    pub request_pid: Option<u32>,
    pub cwd: Option<String>,
    #[allow(dead_code)]
    pub home: Option<String>,
    pub project_root: Option<String>,
    pub sandbox_session_id: Option<String>,
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

fn paths_match(ui: &UiSessionContext, route: &UiRoute) -> bool {
    if let Some(route_session) = &route.sandbox_session_id {
        return ui
            .sandbox_session_id
            .as_ref()
            .is_some_and(|ui_session| ui_session == route_session);
    }
    project_or_cwd_matches(ui, route)
}

fn omp_session_owns_request(client: &UiClient, ctx: &UiSessionContext, route: &UiRoute) -> bool {
    client.ui_client == "omp"
        && route.sandbox_session_id.is_some()
        && route.sandbox_session_id == ctx.sandbox_session_id
}

fn omp_pid_owns_request(client: &UiClient, route: &UiRoute) -> bool {
    client.ui_client == "omp"
        && client.owner_pid != 0
        && route
            .request_pid
            .is_some_and(|pid| is_descendant_of(client.owner_pid, pid))
}

pub(crate) fn omp_ui_client_owns_by_pid(client: &UiClient, route: &UiRoute) -> bool {
    omp_pid_owns_request(client, route)
}

fn omp_path_matches_client(ctx: &UiSessionContext, route: &UiRoute) -> bool {
    if let (Some(route_session), Some(ctx_session)) =
        (&route.sandbox_session_id, &ctx.sandbox_session_id)
        && route_session != ctx_session
    {
        return false;
    }
    project_or_cwd_matches(ctx, route)
}

fn request_owned_by_omp_pid(route: &UiRoute, omp_clients: &[&UiClient]) -> bool {
    route.request_pid.is_some_and(|pid| {
        omp_clients
            .iter()
            .any(|omp| omp.owner_pid != 0 && is_descendant_of(omp.owner_pid, pid))
    })
}

/// Whether a pending request should be handled by a registered OMP UI (skip standalone UI spawn).
#[must_use]
pub(crate) fn request_owned_by_omp(
    route: &UiRoute,
    omp_clients: &[&UiClient],
    ctx_by_session: &HashMap<String, UiSessionContext>,
) -> bool {
    request_owned_by_omp_pid(route, omp_clients)
        || request_owned_by_omp_session(route, omp_clients, ctx_by_session)
        || request_owned_by_omp_path(route, omp_clients, ctx_by_session)
}

fn request_owned_by_omp_session(
    route: &UiRoute,
    omp_clients: &[&UiClient],
    ctx_by_session: &HashMap<String, UiSessionContext>,
) -> bool {
    route
        .sandbox_session_id
        .as_ref()
        .is_some_and(|route_session| {
            omp_clients.iter().any(|omp| {
                ctx_by_session
                    .get(&omp.session_id)
                    .and_then(|ctx| ctx.sandbox_session_id.as_ref())
                    .is_some_and(|ctx_session| ctx_session == route_session)
            })
        })
}

fn request_owned_by_omp_path(
    route: &UiRoute,
    omp_clients: &[&UiClient],
    ctx_by_session: &HashMap<String, UiSessionContext>,
) -> bool {
    omp_clients.iter().any(|omp| {
        ctx_by_session
            .get(&omp.session_id)
            .is_some_and(|ctx| omp_path_matches_client(ctx, route))
    })
}

fn omp_owns_request(client: &UiClient, ctx: &UiSessionContext, route: &UiRoute) -> bool {
    client.ui_client == "omp"
        && (omp_pid_owns_request(client, route)
            || omp_session_owns_request(client, ctx, route)
            || omp_path_matches_client(ctx, route))
}

pub(crate) fn ui_client_matches_with_contexts(
    client: &UiClient,
    ctx: &UiSessionContext,
    route: &UiRoute,
    omp_clients: &[&UiClient],
    ctx_by_session: &HashMap<String, UiSessionContext>,
) -> bool {
    if client.ui_client == "omp" {
        return omp_owns_request(client, ctx, route);
    }
    if request_owned_by_omp(route, omp_clients, ctx_by_session) {
        return false;
    }
    paths_match(ctx, route)
}

#[cfg(test)]
#[must_use]
pub(crate) fn ui_client_matches(
    client: &UiClient,
    ctx: &UiSessionContext,
    route: &UiRoute,
    omp_clients: &[&UiClient],
) -> bool {
    ui_client_matches_with_contexts(client, ctx, route, omp_clients, &HashMap::new())
}

#[must_use]
pub(crate) fn standalone_ui_client_matches(
    client: &UiClient,
    ctx: &UiSessionContext,
    route: &UiRoute,
) -> bool {
    client.ui_client != "omp" && paths_match(ctx, route)
}

#[cfg(test)]
mod tests {
    use super::{
        UiRoute, standalone_ui_client_matches, ui_client_matches, ui_client_matches_with_contexts,
    };
    use crate::store::types::{UiClient, UiSessionContext};
    use std::collections::HashMap;

    fn ctx(cwd: &str, project_root: &str) -> UiSessionContext {
        UiSessionContext {
            cwd: Some(cwd.into()),
            home: Some("/home/user".into()),
            project_root: Some(project_root.into()),
            sandbox_session_id: None,
        }
    }

    fn omp_client(owner_pid: u32) -> UiClient {
        UiClient {
            session_id: "omp1".into(),
            ui_client: "omp".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().expect("unix stream pair").0.into_split().1,
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
        let omp_ctx = ctx("/dotfiles", "/home/userdotfiles");
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
        assert!(matches);
    }

    #[tokio::test]
    async fn omp_matches_same_project_without_pid() {
        let pid = std::process::id();
        let omp = omp_client(pid);
        let omp_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()));
        assert!(ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn omp_matches_by_sandbox_session_without_pid() {
        let omp = omp_client(1000);
        let mut omp_ctx = ctx("/repo", "/repo");
        omp_ctx.sandbox_session_id = Some("sandbox-session-1".into());
        let route = UiRoute::new(None, Some("/other".into()), None, Some("/other".into()))
            .with_sandbox_session(Some("sandbox-session-1".into()));
        assert!(ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn omp_does_not_match_different_sandbox_session() {
        let omp = omp_client(1000);
        let mut omp_ctx = ctx("/repo", "/repo");
        omp_ctx.sandbox_session_id = Some("sandbox-session-1".into());
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()))
            .with_sandbox_session(Some("sandbox-session-2".into()));
        assert!(!ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn omp_matches_same_project_without_pid_nor_session() {
        let pid = std::process::id();
        let omp = omp_client(pid);
        let omp_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()));
        assert!(ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn omp_matches_same_project_when_route_has_session_but_omp_has_none() {
        let omp = omp_client(1000);
        let omp_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()))
            .with_sandbox_session(Some("sandbox-session-1".into()));
        assert!(ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
    }

    #[tokio::test]
    async fn standalone_network_match_is_suppressed_by_omp_path() {
        let pid = std::process::id();
        let omp = omp_client(pid);
        let omp_ctx = ctx("/repo", "/repo");
        let standalone = UiClient {
            session_id: "ui1".into(),
            ui_client: "standalone".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().expect("unix stream pair").0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid: 0,
        };
        let standalone_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()));
        let mut contexts = HashMap::new();
        contexts.insert(omp.session_id.clone(), omp_ctx.clone());
        assert!(ui_client_matches(&omp, &omp_ctx, &route, &[&omp]));
        assert!(!ui_client_matches_with_contexts(
            &standalone,
            &standalone_ctx,
            &route,
            &[&omp],
            &contexts,
        ));
    }

    #[tokio::test]
    async fn standalone_network_match_is_suppressed_by_omp_session() {
        let omp = omp_client(1000);
        let mut omp_ctx = ctx("/repo", "/repo");
        omp_ctx.sandbox_session_id = Some("sandbox-session-1".into());
        let standalone = UiClient {
            session_id: "ui1".into(),
            ui_client: "standalone".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().expect("unix stream pair").0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid: 0,
        };
        let standalone_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()))
            .with_sandbox_session(Some("sandbox-session-1".into()));
        let mut contexts = HashMap::new();
        contexts.insert(omp.session_id.clone(), omp_ctx);

        assert!(!ui_client_matches_with_contexts(
            &standalone,
            &standalone_ctx,
            &route,
            &[&omp],
            &contexts,
        ));
    }

    #[tokio::test]
    async fn standalone_filesystem_route_can_match_omp_owned_request_by_path() {
        let pid = std::process::id();
        let standalone = UiClient {
            session_id: "ui1".into(),
            ui_client: "standalone".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().expect("unix stream pair").0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid: 0,
        };
        let standalone_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(Some(pid), Some("/repo".into()), None, Some("/repo".into()));
        assert!(standalone_ui_client_matches(
            &standalone,
            &standalone_ctx,
            &route,
        ));
    }

    #[tokio::test]
    async fn standalone_requires_matching_sandbox_session_when_present() {
        let standalone = UiClient {
            session_id: "ui1".into(),
            ui_client: "standalone".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().expect("unix stream pair").0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid: 0,
        };
        let mut standalone_ctx = ctx("/repo", "/repo");
        standalone_ctx.sandbox_session_id = Some("sandbox-a".into());
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()))
            .with_sandbox_session(Some("sandbox-b".into()));
        assert!(!ui_client_matches(
            &standalone,
            &standalone_ctx,
            &route,
            &[]
        ));
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()))
            .with_sandbox_session(Some("sandbox-a".into()));
        assert!(ui_client_matches(&standalone, &standalone_ctx, &route, &[]));
    }

    #[tokio::test]
    async fn standalone_matches_same_project_paths() {
        let standalone = UiClient {
            session_id: "ui1".into(),
            ui_client: "standalone".into(),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::pair().expect("unix stream pair").0.into_split().1,
            )),
            owner_uid: 1000,
            owner_pid: 0,
        };
        let standalone_ctx = ctx("/repo", "/repo");
        let route = UiRoute::new(None, Some("/repo".into()), None, Some("/repo".into()));
        assert!(ui_client_matches(&standalone, &standalone_ctx, &route, &[],));
    }
}
