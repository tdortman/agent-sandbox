use std::path::PathBuf;

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, UiPush, approval_host_patterns,
    filesystem_approval_paths,
};

use super::choice::{deny_cancellation, format_elevation_title, resolve_choice};
use super::dialog::pick_option;
use super::error::UiCliError;
use super::options::{
    ACTION_OPTIONS, PromptAction, ScopeOption, scope_only_options, sudo_target_options,
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
            let url = network_prompt_url(&host, port, &scheme, url);
            let paths = paths.merged_with(cwd, home, project_root);

            // Step 1: choose action
            let Some(action) = choose_action(&format!("agent-sandbox: {url}")).await? else {
                return deny_cancellation(socket, &paths, session_id, &id).await;
            };

            // Step 2: choose scope
            let Some(scope) = choose_scope_only(
                &format!("agent-sandbox: {} {url} scope?", action.verb()),
                session_id.is_some(),
            )
            .await?
            else {
                return deny_cancellation(socket, &paths, session_id, &id).await;
            };

            // Step 3: for non-Once scopes, choose target level
            let target = if scope == ApprovalScope::Once {
                None
            } else {
                match choose_target_level(
                    &format!("agent-sandbox: {} {url} target?", action.verb()),
                    network_target_options(&host, scope),
                )
                .await?
                {
                    Some(t) => Some(t),
                    None => return deny_cancellation(socket, &paths, session_id, &id).await,
                }
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
            let paths = paths.merged_with(cwd, home, project_root);

            // Step 1: choose action
            let title = format_elevation_title(&argv, paths.cwd().unwrap_or("?"));
            let Some(action) = choose_action(&title).await? else {
                return deny_cancellation(socket, &paths, session_id, &id).await;
            };

            // Step 2: choose scope
            let Some(scope) = choose_scope_only(
                &format!("agent-sandbox: {} sudo scope?", action.verb()),
                session_id.is_some(),
            )
            .await?
            else {
                return deny_cancellation(socket, &paths, session_id, &id).await;
            };

            // Step 3: for non-Once scopes, choose command prefix
            let target = if scope == ApprovalScope::Once {
                None
            } else {
                match choose_target_level(
                    &format!("agent-sandbox: {} sudo target?", action.verb()),
                    sudo_target_options(&argv, scope),
                )
                .await?
                {
                    Some(t) => Some(t),
                    None => return deny_cancellation(socket, &paths, session_id, &id).await,
                }
            };
            let choice = ScopeOption {
                label: String::new(),
                scope,
                target,
            };
            resolve_choice(socket, &paths, session_id, &id, action, Some(choice)).await?;
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
                return deny_cancellation(socket, &paths, session_id, &id).await;
            };

            // Step 2: choose scope
            let Some(scope) = choose_scope_only(
                &format!("agent-sandbox: {} filesystem scope?", action.verb()),
                session_id.is_some(),
            )
            .await?
            else {
                return deny_cancellation(socket, &paths, session_id, &id).await;
            };

            // Step 3: for non-Once scopes, choose target level
            let home_str = paths.home_string();
            let target = if scope == ApprovalScope::Once {
                None
            } else {
                match choose_target_level(
                    &format!("agent-sandbox: {} filesystem target?", action.verb()),
                    filesystem_target_options(&path, access, home_str.as_deref(), scope),
                )
                .await?
                {
                    Some(t) => Some(t),
                    None => return deny_cancellation(socket, &paths, session_id, &id).await,
                }
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

fn network_prompt_url(host: &str, port: u16, scheme: &str, fallback_url: Option<String>) -> String {
    if host.trim().is_empty() {
        fallback_url.unwrap_or_else(|| format!("{scheme}://{host}:{port}"))
    } else {
        format!("{scheme}://{host}:{port}")
    }
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

#[cfg(test)]
mod tests {
    use super::{network_prompt_url, network_target_options};
    use agent_sandbox_core::{ApprovalScope, ApprovalTarget};

    #[test]
    fn network_prompt_url_prefers_policy_host_over_raw_ip_url() {
        let url = network_prompt_url(
            "example.com",
            443,
            "tcp",
            Some("tcp://104.18.32.47:443".to_string()),
        );
        assert_eq!(url, "tcp://example.com:443");
    }

    #[test]
    fn network_prompt_url_falls_back_when_host_missing() {
        let url = network_prompt_url("", 443, "tcp", Some("tcp://104.18.32.47:443".to_string()));
        assert_eq!(url, "tcp://104.18.32.47:443");
    }

    #[test]
    fn network_target_options_use_ipv4_prefix_wildcards() {
        let options = network_target_options("34.230.40.69", ApprovalScope::Session);
        let labels: Vec<_> = options.iter().map(|option| option.label.as_str()).collect();
        assert_eq!(labels, ["34.230.40.69", "34.230.40.*", "34.230.*", "34.*"]);
        assert!(matches!(
            options.get(1).and_then(|option| option.target.as_ref()),
            Some(ApprovalTarget::NetworkHost { host }) if host == "34.230.40.*"
        ));
    }
    #[test]
    fn network_target_options_use_ipv6_prefix_wildcards() {
        let options = network_target_options("2001:db8::1", ApprovalScope::Session);
        let labels: Vec<_> = options.iter().map(|option| option.label.as_str()).collect();
        assert_eq!(labels[0], "2001:db8::1");
        assert!(labels.contains(&"2001:db8:0:0:0:0:0:*"));
        assert!(labels.contains(&"2001:db8:*"));
        assert!(labels.contains(&"2001:*"));
        assert_eq!(labels.len(), 8);
        assert!(matches!(
            options.iter().find(|o| o.label == "2001:db8:*").and_then(|option| option.target.as_ref()),
            Some(ApprovalTarget::NetworkHost { host }) if host == "2001:db8:*"
        ));
    }
}
