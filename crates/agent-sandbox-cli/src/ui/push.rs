use std::path::PathBuf;

use agent_sandbox_core::{SandboxPaths, UiPush};

use super::choice::{format_elevation_title, resolve_choice};
use super::dialog::pick_option;
use super::error::UiCliError;
use super::options::{NETWORK_OPTIONS, SUDO_OPTIONS};

pub(crate) async fn handle_push(
    socket: &PathBuf,
    paths: &SandboxPaths,
    session_id: Option<&str>,
    push: UiPush,
) -> Result<(), UiCliError> {
    match push {
        UiPush::NetworkRequest {
            id,
            host,
            port,
            scheme,
            url,
            cwd,
            home,
            project_root,
        } => {
            let host = host.unwrap_or_default();
            let port = port.unwrap_or(0);
            let scheme = scheme.unwrap_or_else(|| "https".into());
            let url = url.unwrap_or_else(|| format!("{scheme}://{host}:{port}"));
            let title = format!("agent-sandbox: allow {url}?");
            let paths = merge_push_paths(paths, cwd, home, project_root);
            let choice = tokio::task::spawn_blocking(move || pick_option(&title, NETWORK_OPTIONS))
                .await
                .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
            resolve_choice(socket, &paths, session_id, &id, choice.as_deref()).await?;
        }
        UiPush::ElevationRequest {
            id,
            argv,
            cwd,
            home,
            project_root,
        } => {
            let argv = argv.unwrap_or_default();
            let cwd = cwd
                .or_else(|| paths.cwd_string())
                .unwrap_or_else(|| "?".to_string());
            let title = format_elevation_title(&argv, &cwd);
            let paths = merge_push_paths(paths, Some(cwd), home, project_root);
            let choice = tokio::task::spawn_blocking(move || pick_option(&title, SUDO_OPTIONS))
                .await
                .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
            resolve_choice(socket, &paths, session_id, &id, choice.as_deref()).await?;
        }
    }
    Ok(())
}

fn merge_push_paths(
    base: &SandboxPaths,
    cwd: Option<String>,
    home: Option<String>,
    project_root: Option<String>,
) -> SandboxPaths {
    SandboxPaths::from_wire(
        cwd.or_else(|| base.cwd_string()),
        home.or_else(|| base.home_string()),
        project_root.or_else(|| base.project_root_string()),
    )
}
