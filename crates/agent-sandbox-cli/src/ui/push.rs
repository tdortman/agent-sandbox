use std::path::PathBuf;

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, UiPush, approval_host_patterns,
    filesystem_approval_paths,
};

use super::choice::{format_elevation_title, resolve_choice};
use super::dialog::pick_option;
use super::error::UiCliError;
use super::options::{
    ACTION_OPTIONS, PromptAction, ScopeOption, scope_only_options, sudo_scope_options,
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

            // Step 1: choose action
            let Some(action) = choose_action(&format!("agent-sandbox: {url}")).await? else {
                return Ok(());
            };

            // Step 2: choose scope
            let Some(scope) = choose_scope_only(
                &format!("agent-sandbox: {} {url} scope?", action.verb()),
                session_id.is_some(),
            )
            .await?
            else {
                return Ok(());
            };

            // Step 3: for non-Once scopes, choose target level
            let target = if scope == ApprovalScope::Once {
                None
            } else {
                choose_target_level(
                    &format!("agent-sandbox: {} {url} target?", action.verb()),
                    network_target_options(&host, scope),
                )
                .await?
            };

            let choice = ScopeOption {
                label: String::new(),
                scope,
                target,
            };
            resolve_choice(socket, &paths, session_id, &id, action, Some(choice)).await?;
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
        UiPush::FilesystemRequest {
            id,
            path,
            access,
            cwd,
            home,
            project_root,
        } => {
            let paths = paths.merged_with(cwd, home, project_root);
            let title = format!("agent-sandbox: filesystem {access} {path}");

            // Step 1: choose action
            let Some(action) = choose_action(&title).await? else {
                return Ok(());
            };

            // Step 2: choose scope
            let Some(scope) = choose_scope_only(
                &format!("agent-sandbox: {} filesystem scope?", action.verb()),
                session_id.is_some(),
            )
            .await?
            else {
                return Ok(());
            };

            // Step 3: for non-Once scopes, choose target level
            let home_str = paths.home_string();
            let target = if scope == ApprovalScope::Once {
                None
            } else {
                choose_target_level(
                    &format!("agent-sandbox: {} filesystem target?", action.verb()),
                    filesystem_target_options(&path, access, home_str.as_deref(), scope),
                )
                .await?
            };

            let choice = ScopeOption {
                label: String::new(),
                scope,
                target,
            };
            resolve_choice(socket, &paths, session_id, &id, action, Some(choice)).await?;
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

async fn choose_scope_only(
    title: &str,
    session_available: bool,
) -> Result<Option<ApprovalScope>, UiCliError> {
    let options = scope_only_options(session_available);
    let choice = choose_scope(title, options).await?;
    Ok(choice.map(|opt| opt.scope))
}

async fn choose_target_level(
    title: &str,
    options: Vec<ScopeOption>,
) -> Result<Option<ApprovalTarget>, UiCliError> {
    let choice = choose_scope(title, options).await?;
    Ok(choice.and_then(|opt| opt.target))
}

fn network_target_options(host: &str, scope: ApprovalScope) -> Vec<ScopeOption> {
    let hosts = approval_host_patterns(host);
    let mut options = Vec::with_capacity(hosts.len());
    for host_pattern in hosts {
        options.push(ScopeOption {
            label: host_pattern.clone(),
            scope,
            target: Some(ApprovalTarget::NetworkHost { host: host_pattern }),
        });
    }
    options
}

fn filesystem_target_options(
    path: &str,
    access: FileAccess,
    home: Option<&str>,
    scope: ApprovalScope,
) -> Vec<ScopeOption> {
    let levels = filesystem_approval_paths(path, home);
    let mut options = Vec::with_capacity(levels.len());
    for level in levels {
        options.push(ScopeOption {
            label: format!("{level} ({access})"),
            scope,
            target: Some(ApprovalTarget::FilesystemPath { path: level }),
        });
    }
    options
}
