use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, UiPush, approval_host_patterns,
    filesystem_approval_paths, is_ip_literal, split_check_aliases,
};

use super::choice::{deny_cancellation, format_elevation_title, resolve_choice};
use super::dialog::pick_option;
use super::error::UiCliError;
use super::options::{
    ACTION_OPTIONS, PromptAction, ScopeOption, scope_only_options, sudo_target_options,
};

/// Extracted fields from [`UiPush::NetworkRequest`].
struct NetworkPush {
    id: String,
    host: Option<String>,
    port: Option<u16>,
    scheme: Option<String>,
    url: Option<String>,
    cwd: Option<String>,
    home: Option<String>,
    project_root: Option<String>,
}

/// Extracted fields from [`UiPush::ElevationRequest`].
struct ElevationPush {
    id: String,
    argv: Option<Vec<String>>,
    cwd: Option<String>,
    home: Option<String>,
    project_root: Option<String>,
}

/// Prompt the user for a network request approval.
async fn handle_network_push(
    socket: &PathBuf,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    net: NetworkPush,
) -> Result<(), UiCliError> {
    let host = net.host.unwrap_or_default();
    let port = net.port.unwrap_or(0);
    let scheme = net.scheme.unwrap_or_else(|| "https".into());
    let (url, aliases) = split_check_aliases(net.url);
    let url = network_prompt_with_aliases(
        &host,
        port,
        &scheme,
        url,
        if aliases.is_empty() {
            None
        } else {
            Some(aliases)
        },
    );
    let paths = paths.merged_with(net.cwd, net.home, net.project_root);

    // Step 1: choose action
    let Some(action) = choose_action(&format!("agent-sandbox: {url}")).await? else {
        return deny_cancellation(socket, &paths, session_id, &net.id).await;
    };

    // Step 2: choose scope
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} {url} scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, session_id, &net.id).await;
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
            None => return deny_cancellation(socket, &paths, session_id, &net.id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(socket, &paths, session_id, &net.id, action, Some(choice)).await
}

/// Prompt the user for an elevation (sudo) request approval.
async fn handle_elevation_push(
    socket: &PathBuf,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    elev: ElevationPush,
) -> Result<(), UiCliError> {
    let argv = elev.argv.unwrap_or_default();
    let paths = paths.merged_with(elev.cwd, elev.home, elev.project_root);

    // Step 1: choose action
    let title = format_elevation_title(&argv, paths.cwd().unwrap_or("?"));
    let Some(action) = choose_action(&title).await? else {
        return deny_cancellation(socket, &paths, session_id, &elev.id).await;
    };

    // Step 2: choose scope
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} sudo scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, session_id, &elev.id).await;
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
            None => return deny_cancellation(socket, &paths, session_id, &elev.id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(socket, &paths, session_id, &elev.id, action, Some(choice)).await
}
/// Handle an incoming UI push: parse the variant, prompt the user, and resolve the choice.
///
/// # Errors
/// Returns [`UiCliError`] when RPC communication with policyd fails.
pub async fn handle_push(
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
            let net = NetworkPush {
                id,
                host,
                port,
                scheme,
                url,
                cwd,
                home,
                project_root,
            };
            handle_network_push(socket, paths, session_id, net).await?;
        }
        UiPush::ElevationRequest {
            id,
            argv,
            cwd,
            home,
            project_root,
        } => {
            let elev = ElevationPush {
                id,
                argv,
                cwd,
                home,
                project_root,
            };
            handle_elevation_push(socket, paths, session_id, elev).await?;
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

fn network_prompt_with_aliases(
    host: &str,
    port: u16,
    scheme: &str,
    fallback_url: Option<String>,
    aliases: Option<Vec<String>>, // parsed from URL fragment when present
) -> String {
    let base = network_prompt_url(host, port, scheme, fallback_url);
    if !is_ip_literal(host) {
        return base;
    }
    let Some(aliases) = aliases else {
        return base;
    };
    let hints: Vec<&str> = aliases
        .iter()
        .map(String::as_str)
        .filter(|alias| !alias.is_empty() && !is_ip_literal(alias))
        .collect();
    if hints.is_empty() {
        return base;
    }
    format!("{base} (previously seen as: {})", hints.join(", "))
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
    let levels = filesystem_approval_paths(Path::new(path), home.map(Path::new));
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
    use super::{network_prompt_url, network_prompt_with_aliases, network_target_options};
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
    fn network_prompt_with_aliases_appends_hint_for_ip_literal() {
        let url = network_prompt_with_aliases(
            "104.18.32.47",
            443,
            "tcp",
            Some("tcp://104.18.32.47:443".to_string()),
            Some(vec!["chatgpt.com".to_string()]),
        );
        assert_eq!(
            url,
            "tcp://104.18.32.47:443 (previously seen as: chatgpt.com)"
        );
    }

    #[test]
    fn network_prompt_with_aliases_skips_hint_for_hostname() {
        let url = network_prompt_with_aliases(
            "chatgpt.com",
            443,
            "tcp",
            None,
            Some(vec!["example.com".to_string()]),
        );
        assert_eq!(url, "tcp://chatgpt.com:443");
    }

    #[test]
    fn network_prompt_with_aliases_joins_multiple_hints() {
        let url = network_prompt_with_aliases(
            "104.18.32.47",
            443,
            "tcp",
            None,
            Some(vec![
                "chatgpt.com".to_string(),
                "www.chatgpt.com".to_string(),
            ]),
        );
        assert_eq!(
            url,
            "tcp://104.18.32.47:443 (previously seen as: chatgpt.com, www.chatgpt.com)"
        );
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
