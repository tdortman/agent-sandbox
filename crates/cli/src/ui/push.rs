use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, HttpMethodMatcher, HttpRuleTarget, HttpUrl,
    ResourceAccess, ResourceKind, UiPush, is_ip_literal, split_check_aliases,
};

use super::choice::{deny_cancellation, format_elevation_title, resolve_choice};
use super::dialog::{pick_option, pick_text};
use super::error::UiCliError;
use super::options::{
    ACTION_OPTIONS, PromptAction, ScopeOption, scope_only_options, sudo_target_options,
};
use tracing::warn;

/// Default rule path shown in the filesystem approval text field.
fn suggest_filesystem_rule_path(path: &Path, project_root: Option<&Path>) -> String {
    if let Some(root) = project_root.filter(|r| !r.as_os_str().is_empty()) {
        let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        if canonical_path.starts_with(&canonical_root) {
            let rel = canonical_path
                .strip_prefix(&canonical_root)
                .map_or(path, |rel| rel);
            let rel = rel.to_string_lossy().trim_start_matches('/').to_string();
            if !rel.is_empty() {
                return format!("./{rel}");
            }
        }
    }
    path.display().to_string()
}

/// Extracted fields from [`UiPush::NetworkRequest`].
struct NetworkPush {
    id: String,
    host: Option<String>,
    port: Option<u16>,
    scheme: Option<String>,
    url: Option<String>,
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

/// Extracted fields from [`UiPush::HttpRequest`].
struct HttpPush {
    id: String,
    request: agent_sandbox_core::HttpRequest,
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

/// Extracted fields from [`UiPush::ElevationRequest`].
struct ElevationPush {
    id: String,
    argv: Option<Vec<String>>,
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

/// Extracted fields from [`UiPush::FilesystemRequest`].
struct FilesystemPush {
    id: String,
    path: PathBuf,
    access: FileAccess,
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

/// Extracted fields from [`UiPush::ResourceRequest`].
struct ResourcePush {
    id: String,
    kind: ResourceKind,
    path: PathBuf,
    access: ResourceAccess,
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

/// Prompt the user for a network request approval.
async fn handle_network_push(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    net: NetworkPush,
) -> Result<(), UiCliError> {
    let host = net.host.unwrap_or_default();
    let port = net.port.unwrap_or(0);
    let transport = net.scheme.unwrap_or_else(|| "https".into());
    let scheme = network_prompt_scheme(&transport, port);
    let result = split_check_aliases(net.url);
    let url = network_prompt_with_transport_hint(
        network_prompt_with_aliases(
            &host,
            port,
            scheme,
            result.url,
            if result.aliases.is_empty() {
                None
            } else {
                Some(result.aliases)
            },
        ),
        &transport,
        port,
    );
    let paths = paths.merged_with(net.cwd, net.home, net.project_root);

    // Step 1: choose action
    let Some(action) = choose_action(&format!("agent-sandbox: {url}")).await? else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &net.id).await;
    };

    // Step 2: choose scope
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} {url} scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &net.id).await;
    };

    let target = if scope == ApprovalScope::Once {
        None
    } else {
        let title = format!("agent-sandbox: {} {url} target?", action.verb());
        let default_host = host.clone();
        let entered = tokio::task::spawn_blocking(move || pick_text(&title, &default_host))
            .await
            .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
        match entered {
            Some(host) => Some(ApprovalTarget::NetworkHost { host }),
            None => return deny_cancellation(socket, &paths, sandbox_session_id, &net.id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &net.id,
        action,
        Some(choice),
    )
    .await
}

/// Prompt the user for a decoded HTTP request approval.
async fn handle_http_push(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    push: HttpPush,
) -> Result<(), UiCliError> {
    let HttpPush {
        id,
        request,
        cwd,
        home,
        project_root,
    } = push;
    let paths = paths.merged_with(cwd, home, project_root);
    let title = format!("agent-sandbox: {} {}", request.method.as_str(), request.url);
    let Some(action) = choose_action(&title).await? else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
    };
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} HTTP scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
    };
    let target = if scope == ApprovalScope::Once {
        None
    } else {
        let exact = HttpRuleTarget::new(
            HttpMethodMatcher::Exact(request.method.clone()),
            request.url.clone(),
        )
        .map_err(|error| UiCliError::Register(format!("invalid HTTP request target: {error}")))?;
        let all_methods = HttpRuleTarget::new(HttpMethodMatcher::All, request.url.clone())
            .map_err(|error| {
                UiCliError::Register(format!("invalid HTTP request target: {error}"))
            })?;
        let Some(ApprovalTarget::Http {
            target: method_target,
        }) = choose_target_level(
            &format!("agent-sandbox: {} HTTP method?", action.verb()),
            vec![
                ScopeOption {
                    label: request.method.as_str().to_owned(),
                    scope,
                    target: Some(ApprovalTarget::Http { target: exact }),
                },
                ScopeOption {
                    label: "All methods".into(),
                    scope,
                    target: Some(ApprovalTarget::Http {
                        target: all_methods,
                    }),
                },
            ],
        )
        .await?
        else {
            return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
        };
        choose_http_target(
            &format!("agent-sandbox: {} HTTP path?", action.verb()),
            &request,
            method_target.method,
        )
        .await?
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &id,
        action,
        Some(choice),
    )
    .await
}

/// Prompt the user for an elevation (sudo) request approval.
async fn handle_elevation_push(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    elev: ElevationPush,
) -> Result<(), UiCliError> {
    let argv = elev.argv.unwrap_or_default();
    let paths = paths.merged_with(elev.cwd, elev.home, elev.project_root);

    // Step 1: choose action
    let title = format_elevation_title(&argv, paths.cwd().unwrap_or_else(|| Path::new("?")));
    let Some(action) = choose_action(&title).await? else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &elev.id).await;
    };

    // Step 2: choose scope
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} sudo scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &elev.id).await;
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
            None => return deny_cancellation(socket, &paths, sandbox_session_id, &elev.id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &elev.id,
        action,
        Some(choice),
    )
    .await
}
async fn handle_network_variant(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    push: UiPush,
) -> Result<(), UiCliError> {
    let UiPush::NetworkRequest {
        id,
        host,
        port,
        scheme,
        url,
        cwd,
        home,
        project_root,
    } = push
    else {
        unreachable!("network variant was validated by the dispatcher")
    };
    handle_network_push(
        socket,
        paths,
        session_id,
        sandbox_session_id,
        NetworkPush {
            id,
            host,
            port,
            scheme,
            url,
            cwd,
            home,
            project_root,
        },
    )
    .await
}

async fn handle_http_variant(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    push: UiPush,
) -> Result<(), UiCliError> {
    let UiPush::HttpRequest {
        id,
        request,
        cwd,
        home,
        project_root,
        sandbox_session_id,
    } = push
    else {
        unreachable!("HTTP variant was validated by the dispatcher")
    };
    handle_http_push(
        socket,
        paths,
        session_id,
        sandbox_session_id.as_deref(),
        HttpPush {
            id: id.to_string(),
            request,
            cwd,
            home,
            project_root,
        },
    )
    .await
}

async fn handle_elevation_variant(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    push: UiPush,
) -> Result<(), UiCliError> {
    let UiPush::ElevationRequest {
        id,
        argv,
        cwd,
        home,
        project_root,
    } = push
    else {
        unreachable!("elevation variant was validated by the dispatcher")
    };
    handle_elevation_push(
        socket,
        paths,
        session_id,
        sandbox_session_id,
        ElevationPush {
            id,
            argv,
            cwd,
            home,
            project_root,
        },
    )
    .await
}

async fn handle_filesystem_variant(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    push: UiPush,
) -> Result<(), UiCliError> {
    let UiPush::FilesystemRequest {
        id,
        path,
        access,
        cwd,
        home,
        project_root,
    } = push
    else {
        unreachable!("filesystem variant was validated by the dispatcher")
    };
    handle_filesystem_push(
        socket,
        paths,
        session_id,
        sandbox_session_id,
        FilesystemPush {
            id,
            path,
            access,
            cwd,
            home,
            project_root,
        },
    )
    .await
}

async fn handle_resource_variant(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    push: UiPush,
) -> Result<(), UiCliError> {
    let UiPush::ResourceRequest {
        id,
        kind,
        path,
        access,
        cwd,
        home,
        project_root,
    } = push
    else {
        unreachable!("resource variant was validated by the dispatcher")
    };
    handle_resource_push(
        socket,
        paths,
        session_id,
        sandbox_session_id,
        ResourcePush {
            id,
            kind,
            path,
            access,
            cwd,
            home,
            project_root,
        },
    )
    .await
}

/// Handle an incoming UI push: parse the variant, prompt the user, and resolve the choice.
///
/// # Errors
/// Returns [`UiCliError`] when RPC communication with policyd fails.
pub async fn handle_push(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    push: UiPush,
) -> Result<(), UiCliError> {
    match push {
        push @ UiPush::NetworkRequest { .. } => {
            handle_network_variant(socket, paths, session_id, sandbox_session_id, push).await?;
        }
        push @ UiPush::HttpRequest { .. } => {
            handle_http_variant(socket, paths, session_id, push).await?;
        }
        push @ UiPush::ElevationRequest { .. } => {
            handle_elevation_variant(socket, paths, session_id, sandbox_session_id, push).await?;
        }
        push @ UiPush::FilesystemRequest { .. } => {
            handle_filesystem_variant(socket, paths, session_id, sandbox_session_id, push).await?;
        }
        push @ UiPush::ResourceRequest { .. } => {
            handle_resource_variant(socket, paths, session_id, sandbox_session_id, push).await?;
        }
    }
    Ok(())
}

/// Prompt the user for a filesystem access approval.
async fn handle_filesystem_push(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    fs: FilesystemPush,
) -> Result<(), UiCliError> {
    let FilesystemPush {
        id,
        path,
        access,
        cwd,
        home,
        project_root,
    } = fs;
    let paths = paths.merged_with(cwd, home, project_root.clone());
    let title = format!("agent-sandbox: filesystem {access} {}", path.display());
    let default_rule_path = suggest_filesystem_rule_path(&path, paths.project_root());

    // Step 1: choose action
    let Some(action) = choose_action(&title).await? else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
    };

    // Step 2: choose scope
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} filesystem scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
    };

    // Step 3: for non-Once scopes, edit the rule path in a text field
    let target = if scope == ApprovalScope::Once {
        None
    } else {
        match choose_path_target(
            &format!("agent-sandbox: allow filesystem {access} path?"),
            &default_rule_path,
            |rule_path| ApprovalTarget::FilesystemPath { path: rule_path },
        )
        .await?
        {
            Some(t) => Some(t),
            None => return deny_cancellation(socket, &paths, sandbox_session_id, &id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &id,
        action,
        Some(choice),
    )
    .await
}

/// Prompt the user for a resource access approval.
async fn handle_resource_push(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    res: ResourcePush,
) -> Result<(), UiCliError> {
    let ResourcePush {
        id,
        kind,
        path,
        access,
        cwd,
        home,
        project_root,
    } = res;
    let paths = paths.merged_with(cwd, home, project_root);
    let title = format!("agent-sandbox: {kind} {access} {}", path.display());

    let Some(action) = choose_action(&title).await? else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
    };

    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} {} scope?", action.verb(), kind),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
    };

    let target = if scope == ApprovalScope::Once {
        None
    } else {
        match choose_path_target(
            &format!("agent-sandbox: allow {kind} {access} path?"),
            &path.display().to_string(),
            move |rule_path| ApprovalTarget::ResourcePath {
                resource_kind: kind,
                path: rule_path,
            },
        )
        .await?
        {
            Some(t) => Some(t),
            None => return deny_cancellation(socket, &paths, sandbox_session_id, &id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &id,
        action,
        Some(choice),
    )
    .await
}

async fn choose_action(title: &str) -> Result<Option<PromptAction>, UiCliError> {
    let title = title.to_string();
    let choice = tokio::task::spawn_blocking(move || pick_option(&title, ACTION_OPTIONS))
        .await
        .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
    Ok(choice.as_deref().and_then(PromptAction::from_label))
}
async fn choose_http_target(
    title: &str,
    request: &agent_sandbox_core::HttpRequest,
    method: HttpMethodMatcher,
) -> Result<Option<ApprovalTarget>, UiCliError> {
    let title = title.to_owned();
    let default_url = request.url.to_string();
    loop {
        let prompt_title = title.clone();
        let default_url = default_url.clone();
        let Some(raw_url) =
            tokio::task::spawn_blocking(move || pick_text(&prompt_title, &default_url))
                .await
                .map_err(|_| UiCliError::Register("prompt join failed".into()))?
        else {
            return Ok(None);
        };
        let url = match HttpUrl::parse(&raw_url) {
            Ok(url) => url,
            Err(error) => {
                warn!(%error, "rejecting invalid HTTP approval target");
                continue;
            }
        };
        let target = match HttpRuleTarget::new(method.clone(), url) {
            Ok(target) => target,
            Err(error) => {
                warn!(%error, "rejecting invalid HTTP approval target");
                continue;
            }
        };
        if !target.matches(request) {
            warn!("rejecting HTTP approval target outside the observed request");
            continue;
        }
        return Ok(Some(ApprovalTarget::Http { target }));
    }
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

async fn choose_path_target(
    title: &str,
    default_path: &str,
    build_target: impl FnOnce(PathBuf) -> ApprovalTarget + Send + 'static,
) -> Result<Option<ApprovalTarget>, UiCliError> {
    let title = title.to_string();
    let default_path = default_path.to_string();
    let choice = tokio::task::spawn_blocking(move || pick_text(&title, &default_path))
        .await
        .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
    Ok(choice.map(|path| build_target(PathBuf::from(path))))
}

async fn choose_target_level(
    title: &str,
    options: Vec<ScopeOption>,
) -> Result<Option<ApprovalTarget>, UiCliError> {
    let choice = choose_scope(title, options).await?;
    Ok(choice.and_then(|opt| opt.target))
}

fn network_prompt_scheme(transport: &str, port: u16) -> &str {
    match (transport, port) {
        ("tcp", 80 | 8008 | 8080) => "http",
        ("tcp", 443 | 8443) | ("udp" | "http3", 443) => "https",
        _ => transport,
    }
}

fn network_prompt_with_transport_hint(base: String, transport: &str, port: u16) -> String {
    if (transport == "udp" || transport == "http3") && port == 443 {
        format!("{base} (HTTP/3 over QUIC)")
    } else {
        base
    }
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

#[cfg(test)]
mod tests {
    use super::{
        network_prompt_scheme, network_prompt_url, network_prompt_with_aliases,
        network_prompt_with_transport_hint, suggest_filesystem_rule_path,
    };
    use std::path::Path;

    #[test]
    fn suggest_filesystem_rule_path_shows_relative_file_path() {
        assert_eq!(
            suggest_filesystem_rule_path(
                Path::new("/home/user/repo/.git/config"),
                Some(Path::new("/home/user/repo")),
            ),
            "./.git/config"
        );
    }

    #[test]
    fn network_prompt_scheme_uses_registered_http_service_ports() {
        assert_eq!(network_prompt_scheme("tcp", 80), "http");
        assert_eq!(network_prompt_scheme("tcp", 8008), "http");
        assert_eq!(network_prompt_scheme("tcp", 8080), "http");
        assert_eq!(network_prompt_scheme("tcp", 443), "https");
        assert_eq!(network_prompt_scheme("tcp", 8443), "https");
        assert_eq!(network_prompt_scheme("udp", 443), "https");
        assert_eq!(network_prompt_scheme("udp", 853), "udp");
    }

    #[test]
    fn network_prompt_marks_udp_443_as_http3_without_inventing_uri_scheme() {
        let base = network_prompt_url(
            "example.com",
            443,
            network_prompt_scheme("http3", 443),
            None,
        );
        assert_eq!(
            network_prompt_with_transport_hint(base, "http3", 443),
            "https://example.com:443 (HTTP/3 over QUIC)"
        );
    }

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
}
