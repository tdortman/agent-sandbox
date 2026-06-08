use std::path::PathBuf;

use agent_sandbox_core::UiPush;

use super::choice::{format_elevation_title, resolve_choice};
use super::dialog::pick_option;
use super::error::UiCliError;
use super::options::{
    ACTION_OPTIONS, PromptAction, ScopeOption, network_scope_options, sudo_scope_options,
};

pub(crate) async fn handle_push(
    socket: &PathBuf,
    paths: &agent_sandbox_core::SandboxPaths,
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
            let paths = paths.merged_with(cwd, home, project_root);
            let Some(action) = choose_action(&format!("agent-sandbox: {url}")).await? else {
                return Ok(());
            };
            let choice = choose_scope(
                &format!("agent-sandbox: {} {url}?", action.verb()),
                network_scope_options(&host, session_id.is_some()),
            )
            .await?;
            resolve_choice(socket, &paths, session_id, &id, action, choice).await?;
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
            let paths = paths.merged_with(Some(cwd), home, project_root);
            let Some(action) = choose_action(&title).await? else {
                return Ok(());
            };
            let choice = choose_scope(
                &format!("agent-sandbox: {} sudo scope?", action.verb()),
                sudo_scope_options(&argv, session_id.is_some()),
            )
            .await?;
            resolve_choice(socket, &paths, session_id, &id, action, choice).await?;
        }
    }
    Ok(())
}

async fn choose_action(title: &str) -> Result<Option<PromptAction>, UiCliError> {
    let title = title.to_string();
    let choice = tokio::task::spawn_blocking(move || pick_option(&title, ACTION_OPTIONS))
        .await
        .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
    Ok(choice.as_deref().and_then(PromptAction::from_label))
}

async fn choose_scope(
    title: &str,
    options: Vec<ScopeOption>,
) -> Result<Option<ScopeOption>, UiCliError> {
    let title = title.to_string();
    let choice = tokio::task::spawn_blocking({
        let option_labels: Vec<String> =
            options.iter().map(|option| option.label.clone()).collect();
        move || {
            let refs: Vec<&str> = option_labels.iter().map(String::as_str).collect();
            pick_option(&title, &refs)
        }
    })
    .await
    .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
    Ok(choice.and_then(|label| options.into_iter().find(|option| option.label == label)))
}
