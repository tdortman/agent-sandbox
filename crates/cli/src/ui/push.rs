use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, FilesystemRule, HttpMethodMatcher, HttpRuleTarget,
    HttpUrl, ResourceAccess, ResourceKind, ResourceRule, UiPush, contract_project_path,
    host_pattern_matches, is_ip_literal, normalize_dns_name, split_check_aliases,
};

use super::choice::{deny_cancellation, format_elevation_title, resolve_choice};
use super::dialog::{ApprovalReviewOutcome, pick_option, pick_text, review_approval};
use super::error::UiCliError;
use super::options::{
    ACTION_OPTIONS, ApprovalFormContext, ApprovalFormControl, ApprovalFormField,
    ApprovalFormOption, ApprovalFormPresentation, ApprovalFormRequest, ApprovalFormResult,
    PromptAction, ReviewValidator, ScopeOption, format_command, scope_only_options,
    sudo_target_options,
};
use tracing::warn;

/// Default project-relative rule path shown in approval prompts.
fn suggest_project_rule_path(path: &Path, project_root: Option<&Path>) -> String {
    contract_project_path(path, project_root)
        .display()
        .to_string()
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

fn approval_context(
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
) -> Vec<ApprovalFormContext> {
    let mut context = Vec::new();
    let project_root = paths.project_root();
    if let Some(project) = project_root {
        context.push(ApprovalFormContext {
            label: "Project".into(),
            value: project.display().to_string(),
        });
    }
    if let Some(cwd) = paths.cwd()
        && project_root.is_none_or(|project| project != cwd)
    {
        context.push(ApprovalFormContext {
            label: "Working directory".into(),
            value: cwd.display().to_string(),
        });
    }
    context.push(ApprovalFormContext {
        label: "Session".into(),
        value: session_id.map_or_else(|| "Unavailable".into(), str::to_owned),
    });
    context
}

fn approval_scopes(session_available: bool) -> Vec<ApprovalScope> {
    scope_only_options(session_available)
        .into_iter()
        .map(|option| option.scope)
        .collect()
}

async fn rich_review(
    request: ApprovalFormRequest,
    validate: Option<ReviewValidator>,
) -> Result<ApprovalReviewOutcome, UiCliError> {
    tokio::task::spawn_blocking(move || review_approval(&request, validate.as_ref()))
        .await
        .map_err(|_| UiCliError::Register("prompt join failed".into()))
}

struct ElevationReview {
    request: ApprovalFormRequest,
    prefixes: Vec<Vec<String>>,
}

fn build_elevation_review(
    argv: &[String],
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    title: &str,
) -> ElevationReview {
    let prefixes = agent_sandbox_core::SudoRule::approval_prefixes(argv);
    let prefix_options = prefixes
        .iter()
        .enumerate()
        .map(|(index, prefix)| ApprovalFormOption {
            value: index.to_string(),
            label: format_command(prefix),
        })
        .collect();
    ElevationReview {
        request: ApprovalFormRequest {
            summary: title.to_owned(),
            context: approval_context(paths, session_id),
            presentation: Some(elevation_presentation(argv)),
            scopes: approval_scopes(session_id.is_some()),
            fields: vec![choice_field(
                "target",
                "Command prefix",
                "0",
                prefix_options,
            )],
        },
        prefixes,
    }
}

struct ReviewActionScope {
    action: PromptAction,
    scope: ApprovalScope,
}

struct ReviewedChoice {
    action: PromptAction,
    choice: ScopeOption,
}

fn validated_review_action(
    result: &ApprovalFormResult,
    session_available: bool,
) -> Option<ReviewActionScope> {
    let action = result.action.prompt_action()?;
    let scope = result.scope;
    let allowed = scope == ApprovalScope::Once
        || scope == ApprovalScope::Project
        || scope == ApprovalScope::Global
        || (scope == ApprovalScope::Session && session_available);
    allowed.then_some(ReviewActionScope { action, scope })
}

fn reviewed_choice(
    result: &ApprovalFormResult,
    session_available: bool,
    target: impl FnOnce(&ApprovalFormResult) -> Option<ApprovalTarget>,
) -> Option<ReviewedChoice> {
    let ReviewActionScope { action, scope } = validated_review_action(result, session_available)?;
    let target = if scope == ApprovalScope::Once {
        None
    } else {
        Some(target(result)?)
    };
    Some(ReviewedChoice {
        action,
        choice: ScopeOption {
            label: String::new(),
            scope,
            target,
        },
    })
}

/// Builds a [`ReviewValidator`] that enforces scope availability and
/// runs `parse_target` for persistent scopes, producing a human-readable
/// error so the Qt dialog can keep the form open for correction.
fn make_validator(
    session_available: bool,
    parse_target: impl Fn(&ApprovalFormResult) -> Option<ApprovalTarget> + Send + 'static,
) -> ReviewValidator {
    Box::new(move |result: &ApprovalFormResult| {
        if validated_review_action(result, session_available).is_none() {
            return Err("This scope is not available.".into());
        }
        if result.scope == ApprovalScope::Once {
            return Ok(());
        }
        if parse_target(result).is_some() {
            Ok(())
        } else {
            Err("The rule does not match the request.".into())
        }
    })
}

fn text_field(id: &'static str, label: &str, value: String) -> ApprovalFormField {
    ApprovalFormField {
        id,
        label: label.into(),
        control: ApprovalFormControl::Text { value },
    }
}
fn filesystem_presentation(access: FileAccess, subject: &str) -> ApprovalFormPresentation {
    let heading = match access {
        FileAccess::Read => "Read this file?",
        FileAccess::Write => "Write to this file?",
        FileAccess::ReadWrite => "Read and write this file?",
        FileAccess::Execute => "Execute this file?",
        FileAccess::All => "Allow full access to this file?",
    };
    ApprovalFormPresentation {
        heading: heading.into(),
        subject: subject.into(),
    }
}

fn resource_presentation(
    access: ResourceAccess,
    kind: ResourceKind,
    path: &Path,
) -> ApprovalFormPresentation {
    let kind_label = match kind {
        ResourceKind::UnixSocket => "Unix socket",
        ResourceKind::Device => "device",
    };
    let heading = match access {
        ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect) => {
            format!("Connect to this {kind_label}?")
        }
        ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Send) => {
            format!("Send data to this {kind_label}?")
        }
        ResourceAccess::Socket(agent_sandbox_core::SocketAccess::All) => {
            format!("Connect to and send data to this {kind_label}?")
        }
        ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Read) => {
            format!("Read from this {kind_label}?")
        }
        ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Write) => {
            format!("Write to this {kind_label}?")
        }
        ResourceAccess::Device(agent_sandbox_core::DeviceAccess::ReadWrite) => {
            format!("Read and write this {kind_label}?")
        }
    };
    ApprovalFormPresentation {
        heading,
        subject: path.display().to_string(),
    }
}

fn network_presentation(url: &str) -> ApprovalFormPresentation {
    ApprovalFormPresentation {
        heading: "Allow this network connection?".into(),
        subject: url.into(),
    }
}

fn http_presentation(request: &agent_sandbox_core::HttpRequest) -> ApprovalFormPresentation {
    ApprovalFormPresentation {
        heading: format!("Allow this {} request?", request.method.as_str()),
        subject: request.url.to_string(),
    }
}

fn elevation_presentation(argv: &[String]) -> ApprovalFormPresentation {
    ApprovalFormPresentation {
        heading: "Run this command with elevated privileges?".into(),
        subject: format_command(argv),
    }
}

fn choice_field(
    id: &'static str,
    label: &str,
    value: &str,
    options: Vec<ApprovalFormOption>,
) -> ApprovalFormField {
    ApprovalFormField {
        id,
        label: label.into(),
        control: ApprovalFormControl::Choice {
            value: value.into(),
            options,
        },
    }
}

fn valid_rule_path(value: &str) -> Option<PathBuf> {
    let value = value.trim();
    (!value.is_empty() && !value.contains('\0')).then(|| PathBuf::from(value))
}

fn valid_network_host(value: &str) -> Option<String> {
    let value = value.trim();
    if is_ip_literal(value) {
        return Some(value.to_owned());
    }
    normalize_dns_name(value).ok()
}
/// Parse and validate an editable network host against the request.
fn parse_network_target(
    result: &ApprovalFormResult,
    requested_host: &str,
) -> Option<ApprovalTarget> {
    let host = valid_network_host(result.values.get("target")?)?;
    if !host_pattern_matches(&host, requested_host) {
        return None;
    }
    Some(ApprovalTarget::NetworkHost { host })
}

/// Parse and validate an editable filesystem path against the request.
fn parse_filesystem_target(
    result: &ApprovalFormResult,
    requested_path: &Path,
    project_root: Option<&Path>,
) -> Option<ApprovalTarget> {
    let path = valid_rule_path(result.values.get("target")?)?;
    if !FilesystemRule::new(path.clone(), FileAccess::Read, "")
        .path_matches(requested_path, project_root)
    {
        return None;
    }
    Some(ApprovalTarget::FilesystemPath { path })
}

/// Parse and validate an editable resource path against the request.
fn parse_resource_target(
    result: &ApprovalFormResult,
    kind: ResourceKind,
    requested_path: &Path,
    project_root: Option<&Path>,
) -> Option<ApprovalTarget> {
    let path = valid_rule_path(result.values.get("target")?)?;
    if !ResourceRule::new(
        kind,
        path.clone(),
        ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
        "",
    )
    .path_matches(requested_path, project_root)
    {
        return None;
    }
    Some(ApprovalTarget::ResourcePath {
        resource_kind: kind,
        path,
    })
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
    let url = url.split(['?', '#']).next().unwrap_or_default().to_owned();
    let paths = paths.merged_with(net.cwd, net.home, net.project_root);
    let review = ApprovalFormRequest {
        summary: format!("Network request to {url}"),
        context: approval_context(&paths, session_id),
        presentation: Some(network_presentation(&url)),
        scopes: approval_scopes(session_id.is_some()),
        fields: vec![text_field("target", "Host rule", host.clone())],
    };
    match rich_review(
        review,
        Some(make_validator(session_id.is_some(), {
            let requested = host.clone();
            move |result| parse_network_target(result, &requested)
        })),
    )
    .await?
    {
        ApprovalReviewOutcome::Submitted(result) => {
            let Some(ReviewedChoice { action, choice }) =
                reviewed_choice(&result, session_id.is_some(), |result| {
                    parse_network_target(result, &host)
                })
            else {
                return deny_cancellation(socket, &paths, sandbox_session_id, &net.id).await;
            };
            return resolve_choice(
                socket,
                &paths,
                session_id,
                sandbox_session_id,
                &net.id,
                action,
                Some(choice),
            )
            .await;
        }
        ApprovalReviewOutcome::Cancelled => {
            return deny_cancellation(socket, &paths, sandbox_session_id, &net.id).await;
        }
        ApprovalReviewOutcome::Unavailable => {}
    }
    network_push_cli_fallback(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &net.id,
        &url,
        &host,
    )
    .await
}

async fn network_push_cli_fallback(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    id: &str,
    url: &str,
    host: &str,
) -> Result<(), UiCliError> {
    let Some(action) = choose_action(&format!("agent-sandbox: {url}")).await? else {
        return deny_cancellation(socket, paths, sandbox_session_id, id).await;
    };
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} {url} scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, paths, sandbox_session_id, id).await;
    };
    let target = if scope == ApprovalScope::Once {
        None
    } else {
        let title = format!("agent-sandbox: {} {url} target?", action.verb());
        let default_host = host.to_owned();
        let entered = tokio::task::spawn_blocking(move || pick_text(&title, &default_host))
            .await
            .map_err(|_| UiCliError::Register("prompt join failed".into()))?;
        match entered {
            Some(host) => Some(ApprovalTarget::NetworkHost { host }),
            None => return deny_cancellation(socket, paths, sandbox_session_id, id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(
        socket,
        paths,
        session_id,
        sandbox_session_id,
        id,
        action,
        Some(choice),
    )
    .await
}

async fn handle_http_review(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    id: &str,
    request: &agent_sandbox_core::HttpRequest,
) -> Result<bool, UiCliError> {
    let method_options = vec![
        ApprovalFormOption {
            value: "exact".into(),
            label: format!("{} only", request.method.as_str()),
        },
        ApprovalFormOption {
            value: "all".into(),
            label: "All methods".into(),
        },
    ];
    let review = ApprovalFormRequest {
        summary: format!("HTTP {} {}", request.method.as_str(), request.url),
        context: approval_context(paths, session_id),
        presentation: Some(http_presentation(request)),
        scopes: approval_scopes(session_id.is_some()),
        fields: vec![
            choice_field("method", "Methods", "exact", method_options),
            text_field("url", "URL", request.url.to_string()),
        ],
    };
    let method = request.method.clone();
    let request_url = request.url.clone();
    let session = session_id.is_some();
    match rich_review(
        review,
        Some(make_validator(session, move |result| {
            let matcher = match result.values.get("method")?.as_str() {
                "exact" => HttpMethodMatcher::Exact(method.clone()),
                "all" => HttpMethodMatcher::All,
                _ => return None,
            };
            let url = HttpUrl::parse_pattern(result.values.get("url")?).ok()?;
            let target = HttpRuleTarget::new(matcher, url).ok()?;
            target
                .url
                .covers(&request_url)
                .then_some(ApprovalTarget::Http { target })
        })),
    )
    .await?
    {
        ApprovalReviewOutcome::Submitted(result) => {
            let Some(ReviewedChoice { action, choice }) =
                reviewed_choice(&result, session_id.is_some(), |result| {
                    let matcher = match result.values.get("method")?.as_str() {
                        "exact" => HttpMethodMatcher::Exact(request.method.clone()),
                        "all" => HttpMethodMatcher::All,
                        _ => return None,
                    };
                    let url = HttpUrl::parse_pattern(result.values.get("url")?).ok()?;
                    let target = HttpRuleTarget::new(matcher, url).ok()?;
                    target
                        .url
                        .covers(&request.url)
                        .then_some(ApprovalTarget::Http { target })
                })
            else {
                return deny_cancellation(socket, paths, sandbox_session_id, id)
                    .await
                    .map(|()| true);
            };
            resolve_choice(
                socket,
                paths,
                session_id,
                sandbox_session_id,
                id,
                action,
                Some(choice),
            )
            .await
            .map(|()| true)
        }
        ApprovalReviewOutcome::Cancelled => {
            deny_cancellation(socket, paths, sandbox_session_id, id)
                .await
                .map(|()| true)
        }
        ApprovalReviewOutcome::Unavailable => Ok(false),
    }
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
    if handle_http_review(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &id,
        &request,
    )
    .await?
    {
        return Ok(());
    }
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
    let title = format_elevation_title(&argv, paths.cwd().unwrap_or_else(|| Path::new("?")));
    let elevation_review = build_elevation_review(&argv, &paths, session_id, &title);
    let prefixes = elevation_review.prefixes;
    let prefixes_clone = prefixes.clone();
    match rich_review(
        elevation_review.request,
        Some(make_validator(session_id.is_some(), move |result| {
            let index = result.values.get("target")?.parse::<usize>().ok()?;
            let argv = prefixes_clone.get(index)?.clone();
            Some(ApprovalTarget::SudoCommand { argv })
        })),
    )
    .await?
    {
        ApprovalReviewOutcome::Submitted(result) => {
            let Some(ReviewedChoice { action, choice }) =
                reviewed_choice(&result, session_id.is_some(), |result| {
                    let index = result.values.get("target")?.parse::<usize>().ok()?;
                    let argv = prefixes.get(index)?.clone();
                    Some(ApprovalTarget::SudoCommand { argv })
                })
            else {
                return deny_cancellation(socket, &paths, sandbox_session_id, &elev.id).await;
            };
            return resolve_choice(
                socket,
                &paths,
                session_id,
                sandbox_session_id,
                &elev.id,
                action,
                Some(choice),
            )
            .await;
        }
        ApprovalReviewOutcome::Cancelled => {
            return deny_cancellation(socket, &paths, sandbox_session_id, &elev.id).await;
        }
        ApprovalReviewOutcome::Unavailable => {}
    }
    let Some(action) = choose_action(&title).await? else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &elev.id).await;
    };
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} sudo scope?", action.verb()),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, &paths, sandbox_session_id, &elev.id).await;
    };

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
    let default_rule_path = suggest_project_rule_path(&path, paths.project_root());
    let review = ApprovalFormRequest {
        summary: format!("Filesystem {access} request for {}", path.display()),
        context: approval_context(&paths, session_id),
        presentation: Some(filesystem_presentation(access, &default_rule_path)),
        scopes: approval_scopes(session_id.is_some()),
        fields: vec![text_field(
            "target",
            "Path or pattern",
            default_rule_path.clone(),
        )],
    };
    match rich_review(
        review,
        Some(make_validator(session_id.is_some(), {
            let requested_path = path.clone();
            let project_root = paths.project_root_path();
            move |result| parse_filesystem_target(result, &requested_path, project_root.as_deref())
        })),
    )
    .await?
    {
        ApprovalReviewOutcome::Submitted(result) => {
            let Some(ReviewedChoice { action, choice }) =
                reviewed_choice(&result, session_id.is_some(), |result| {
                    parse_filesystem_target(result, &path, paths.project_root())
                })
            else {
                return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
            };
            return resolve_choice(
                socket,
                &paths,
                session_id,
                sandbox_session_id,
                &id,
                action,
                Some(choice),
            )
            .await;
        }
        ApprovalReviewOutcome::Cancelled => {
            return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
        }
        ApprovalReviewOutcome::Unavailable => {}
    }

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

struct ResourcePrompt<'a> {
    kind: ResourceKind,
    access: ResourceAccess,
    path: &'a Path,
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
    let display_path = suggest_project_rule_path(&path, paths.project_root());
    let review = ApprovalFormRequest {
        summary: format!("{kind} {access} request for {display_path}"),
        context: approval_context(&paths, session_id),
        presentation: Some(resource_presentation(
            access,
            kind,
            Path::new(&display_path),
        )),
        scopes: approval_scopes(session_id.is_some()),
        fields: vec![text_field("target", "Path or pattern", display_path)],
    };
    let validator_kind = kind;
    let validator_path = path.clone();
    let project_root = paths.project_root_path();
    match rich_review(
        review,
        Some(make_validator(session_id.is_some(), move |result| {
            parse_resource_target(
                result,
                validator_kind,
                &validator_path,
                project_root.as_deref(),
            )
        })),
    )
    .await?
    {
        ApprovalReviewOutcome::Submitted(result) => {
            let Some(ReviewedChoice { action, choice }) =
                reviewed_choice(&result, session_id.is_some(), |result| {
                    parse_resource_target(result, kind, &path, paths.project_root())
                })
            else {
                return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
            };
            return resolve_choice(
                socket,
                &paths,
                session_id,
                sandbox_session_id,
                &id,
                action,
                Some(choice),
            )
            .await;
        }
        ApprovalReviewOutcome::Cancelled => {
            return deny_cancellation(socket, &paths, sandbox_session_id, &id).await;
        }
        ApprovalReviewOutcome::Unavailable => {}
    }
    resource_push_cli_fallback(
        socket,
        &paths,
        session_id,
        sandbox_session_id,
        &id,
        ResourcePrompt {
            kind,
            access,
            path: &path,
        },
    )
    .await
}

async fn resource_push_cli_fallback(
    socket: &Path,
    paths: &agent_sandbox_core::SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    id: &str,
    prompt: ResourcePrompt<'_>,
) -> Result<(), UiCliError> {
    let ResourcePrompt { kind, access, path } = prompt;
    let display_path = suggest_project_rule_path(path, paths.project_root());
    let title = format!("agent-sandbox: {kind} {access} {display_path}");
    let Some(action) = choose_action(&title).await? else {
        return deny_cancellation(socket, paths, sandbox_session_id, id).await;
    };
    let Some(scope) = choose_scope_only(
        &format!("agent-sandbox: {} {} scope?", action.verb(), kind),
        session_id.is_some(),
    )
    .await?
    else {
        return deny_cancellation(socket, paths, sandbox_session_id, id).await;
    };
    let target = if scope == ApprovalScope::Once {
        None
    } else {
        match choose_path_target(
            &format!("agent-sandbox: allow {kind} {access} path?"),
            &display_path,
            move |rule_path| ApprovalTarget::ResourcePath {
                resource_kind: kind,
                path: rule_path,
            },
        )
        .await?
        {
            Some(t) => Some(t),
            None => return deny_cancellation(socket, paths, sandbox_session_id, id).await,
        }
    };
    let choice = ScopeOption {
        label: String::new(),
        scope,
        target,
    };
    resolve_choice(
        socket,
        paths,
        session_id,
        sandbox_session_id,
        id,
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
        ApprovalFormResult, ApprovalScope, ApprovalTarget, approval_context,
        elevation_presentation, http_presentation, network_presentation, network_prompt_scheme,
        network_prompt_url, network_prompt_with_aliases, network_prompt_with_transport_hint,
        parse_filesystem_target, parse_network_target, parse_resource_target,
        resource_presentation, reviewed_choice, suggest_project_rule_path, valid_network_host,
        valid_rule_path,
    };
    use crate::ui::options::ApprovalFormAction;
    use agent_sandbox_core::{HttpRequest, ResourceAccess, ResourceKind, SandboxPaths};
    use std::collections::HashMap;
    use std::path::Path;
    #[test]
    fn resource_presentation_uses_human_readable_unix_socket_label() {
        let presentation = resource_presentation(
            ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
            ResourceKind::UnixSocket,
            Path::new("/run/example.sock"),
        );

        assert_eq!(presentation.heading, "Connect to this Unix socket?");
    }

    #[test]
    fn network_presentation_uses_connection_copy_and_destination() {
        let presentation = network_presentation("https://example.com:443");

        assert_eq!(presentation.heading, "Allow this network connection?");
        assert_eq!(presentation.subject, "https://example.com:443");
    }

    #[test]
    fn http_presentation_uses_method_and_destination() {
        let request = HttpRequest::from_parts("GET", "https", "example.com", "/path")
            .expect("valid HTTP request");
        let presentation = http_presentation(&request);

        assert_eq!(presentation.heading, "Allow this GET request?");
        assert_eq!(presentation.subject, "https://example.com/path");
    }

    #[test]
    fn elevation_presentation_uses_full_sudo_command() {
        let argv = vec!["nixos-rebuild".into(), "switch".into()];
        let presentation = elevation_presentation(&argv);

        assert_eq!(
            presentation.heading,
            "Run this command with elevated privileges?"
        );
        assert_eq!(presentation.subject, "sudo nixos-rebuild switch");
    }

    #[test]
    fn suggest_project_rule_path_shows_relative_unix_socket_path() {
        assert_eq!(
            suggest_project_rule_path(
                Path::new("/home/user/repo/.agent.sock"),
                Some(Path::new("/home/user/repo")),
            ),
            "./.agent.sock"
        );
    }
    #[test]
    fn approval_context_omits_cwd_when_it_matches_project() {
        let paths = SandboxPaths::new("/work/project", "/home/user", "/work/project");

        let context = approval_context(&paths, Some("session-id"));

        assert_eq!(context.len(), 2);
        assert_eq!(context[0].label, "Project");
        assert_eq!(context[1].label, "Session");
    }

    #[test]
    fn approval_context_keeps_distinct_cwd() {
        let paths = SandboxPaths::new("/work/project/src", "/home/user", "/work/project");

        let context = approval_context(&paths, Some("session-id"));

        assert_eq!(context.len(), 3);
        assert_eq!(context[1].label, "Working directory");
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

    #[test]
    fn once_review_ignores_untrusted_target_value() {
        let result = ApprovalFormResult {
            action: ApprovalFormAction::Allow,
            scope: ApprovalScope::Once,
            values: HashMap::new(),
        };
        let choice = reviewed_choice(&result, false, |_| {
            panic!("target validator must not run for Once")
        })
        .expect("valid Once choice")
        .choice;

        assert!(choice.target.is_none());
    }

    #[test]
    fn persistent_review_requires_valid_target() {
        let result = ApprovalFormResult {
            action: ApprovalFormAction::Allow,
            scope: ApprovalScope::Project,
            values: HashMap::from([("target".into(), String::new())]),
        };
        let choice = reviewed_choice(&result, false, |result| {
            valid_rule_path(result.values.get("target")?)
                .map(|path| ApprovalTarget::FilesystemPath { path })
        });

        assert!(choice.is_none());
    }

    #[test]
    fn review_rejects_unavailable_session_scope_and_cancel_action() {
        let unavailable = ApprovalFormResult {
            action: ApprovalFormAction::Deny,
            scope: ApprovalScope::Session,
            values: HashMap::new(),
        };
        assert!(reviewed_choice(&unavailable, false, |_| None).is_none());

        let cancelled = ApprovalFormResult {
            action: ApprovalFormAction::Cancel,
            scope: ApprovalScope::Once,
            values: HashMap::new(),
        };
        assert!(reviewed_choice(&cancelled, true, |_| None).is_none());
    }

    #[test]
    fn host_and_path_text_are_revalidated() {
        assert_eq!(
            valid_network_host(" Example.COM. "),
            Some("example.com".into())
        );
        assert!(valid_network_host("bad host").is_none());
        assert!(valid_rule_path("   ").is_none());
        assert_eq!(
            valid_rule_path(" ./src "),
            Some(Path::new("./src").to_path_buf())
        );
    }

    fn form_result(target: &str) -> ApprovalFormResult {
        ApprovalFormResult {
            action: ApprovalFormAction::Allow,
            scope: ApprovalScope::Project,
            values: HashMap::from([("target".into(), target.into())]),
        }
    }

    #[test]
    fn network_target_matches_requested_host() {
        let result = form_result("example.com");
        assert_eq!(
            parse_network_target(&result, "example.com"),
            Some(ApprovalTarget::NetworkHost {
                host: "example.com".into()
            })
        );
    }

    #[test]
    fn network_target_wildcard_matches_requested_host() {
        let result = form_result("*.example.com");
        assert!(parse_network_target(&result, "api.example.com").is_some());
    }

    #[test]
    fn network_target_rejects_nonmatching_host() {
        let result = form_result("other.com");
        assert!(parse_network_target(&result, "example.com").is_none());
    }

    #[test]
    fn filesystem_target_rejects_typo_path() {
        let result = form_result("./some/.conff");
        assert!(
            parse_filesystem_target(
                &result,
                Path::new("/home/user/repo/some/.conf"),
                Some(Path::new("/home/user/repo"))
            )
            .is_none()
        );
    }

    #[test]
    fn filesystem_target_accepts_exact_path() {
        let result = form_result("./config/.conf");
        assert_eq!(
            parse_filesystem_target(
                &result,
                Path::new("/home/user/repo/config/.conf"),
                Some(Path::new("/home/user/repo"))
            ),
            Some(ApprovalTarget::FilesystemPath {
                path: "./config/.conf".into()
            })
        );
    }

    #[test]
    fn filesystem_target_accepts_ancestor_glob() {
        let result = form_result("./config/*");
        assert!(
            parse_filesystem_target(
                &result,
                Path::new("/home/user/repo/config/.conf"),
                Some(Path::new("/home/user/repo"))
            )
            .is_some()
        );
    }

    #[test]
    fn resource_target_rejects_nonmatching_path() {
        let result = form_result("/run/other.sock");
        assert!(
            parse_resource_target(
                &result,
                ResourceKind::UnixSocket,
                Path::new("/run/agent-sandbox/proxy-policy.sock"),
                None
            )
            .is_none()
        );
    }

    #[test]
    fn resource_target_accepts_matching_path() {
        let result = form_result("/run/agent-sandbox/*");
        assert_eq!(
            parse_resource_target(
                &result,
                ResourceKind::UnixSocket,
                Path::new("/run/agent-sandbox/proxy-policy.sock"),
                None
            ),
            Some(ApprovalTarget::ResourcePath {
                resource_kind: ResourceKind::UnixSocket,
                path: "/run/agent-sandbox/*".into()
            })
        );
    }
}
