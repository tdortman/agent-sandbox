//! The sequential action, scope and target questions asked when no review
//! dialog is available.

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, HttpMethodMatcher, HttpRequest, HttpRuleTarget, HttpUrl,
};
use tracing::warn;

use super::{
    dialog::Dialogs,
    error::UiCliError,
    options::{ACTION_OPTIONS, PromptAction, ReviewedChoice, ScopeOption, scope_only_options},
    prompt::{Fallback, FallbackTarget, prompt_tag},
};

/// Ask action, scope and (for non-`Once` scopes) target in turn.
///
/// Returns `Ok(None)` when the user cancels at any step.
pub async fn ask(
    dialogs: &Dialogs,
    session_available: bool,
    package: Option<&str>,
    fallback: &Fallback,
) -> Result<Option<ReviewedChoice>, UiCliError> {
    let Some(action) = dialogs
        .pick_option(&fallback.action_title, ACTION_OPTIONS)
        .await?
        .as_deref()
        .and_then(PromptAction::from_label)
    else {
        return Ok(None);
    };

    let scope_title = format!(
        "{}: {} {} scope?",
        prompt_tag(package),
        action.verb(),
        fallback.scope_phrase
    );

    let Some(scope) = choose_scope(
        dialogs,
        &scope_title,
        scope_only_options(session_available, package.is_some()),
    )
    .await?
    .map(|option| option.scope) else {
        return Ok(None);
    };

    let target = if scope == ApprovalScope::Once {
        None
    } else {
        let Some(target) = ask_target(dialogs, action, scope, package, &fallback.target).await?
        else {
            return Ok(None);
        };

        Some(target)
    };

    Ok(Some(ReviewedChoice {
        action,
        choice: ScopeOption {
            label: String::new(),
            scope,
            target,
            comment: None,
        },
    }))
}

async fn ask_target(
    dialogs: &Dialogs,
    action: PromptAction,
    scope: ApprovalScope,
    package: Option<&str>,
    target: &FallbackTarget,
) -> Result<Option<ApprovalTarget>, UiCliError> {
    match target {
        FallbackTarget::Fixed(target) => Ok(Some(target.clone())),

        FallbackTarget::Text(text) => {
            let entered = dialogs
                .pick_text(&text.title.render(action), &text.default)
                .await?;

            Ok(entered.as_deref().and_then(|entered| (text.parse)(entered)))
        }

        FallbackTarget::Http(request) => {
            choose_http_scope_target(dialogs, action, scope, request, package).await
        }
    }
}

/// Choose the HTTP method and path target for a non-`Once` approval scope.
async fn choose_http_scope_target(
    dialogs: &Dialogs,
    action: PromptAction,
    scope: ApprovalScope,
    request: &HttpRequest,
    package: Option<&str>,
) -> Result<Option<ApprovalTarget>, UiCliError> {
    let exact = HttpRuleTarget::new(
        HttpMethodMatcher::Exact(request.method.clone()),
        request.url.clone(),
    )
    .map_err(|error| UiCliError::Register(format!("invalid HTTP request target: {error}")))?;

    let all_methods = HttpRuleTarget::new(HttpMethodMatcher::All, request.url.clone())
        .map_err(|error| UiCliError::Register(format!("invalid HTTP request target: {error}")))?;

    let methods = choose_scope(
        dialogs,
        &format!("{}: {} HTTP method?", prompt_tag(package), action.verb()),
        vec![
            ScopeOption {
                label: request.method.as_str().to_owned(),
                scope,
                target: Some(ApprovalTarget::Http { target: exact }),
                comment: None,
            },
            ScopeOption {
                label: "All methods".into(),
                scope,
                target: Some(ApprovalTarget::Http {
                    target: all_methods,
                }),
                comment: None,
            },
        ],
    )
    .await?;

    let Some(ApprovalTarget::Http {
        target: method_target,
    }) = methods.and_then(|option| option.target)
    else {
        return Ok(None);
    };

    choose_http_target(
        dialogs,
        &format!("{}: {} HTTP path?", prompt_tag(package), action.verb()),
        request,
        method_target.method,
    )
    .await
}

/// Ask for a URL pattern until it parses and covers the request.
async fn choose_http_target(
    dialogs: &Dialogs,
    title: &str,
    request: &HttpRequest,
    method: HttpMethodMatcher,
) -> Result<Option<ApprovalTarget>, UiCliError> {
    let default_url = request.url.to_string();

    loop {
        let Some(raw_url) = dialogs.pick_text(title, &default_url).await? else {
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
    dialogs: &Dialogs,
    title: &str,
    options: Vec<ScopeOption>,
) -> Result<Option<ScopeOption>, UiCliError> {
    let labels: Vec<&str> = options.iter().map(|option| option.label.as_str()).collect();
    let choice = dialogs.pick_option(title, &labels).await?;

    Ok(choice.and_then(|label| options.into_iter().find(|option| option.label == label)))
}
