//! The settlement driver: take a pending request from prompt to policyd
//! reply.
//!
//! Every request kind follows the same sequence. Skip the prompt if the
//! request was settled while the push queued. Otherwise show the review
//! dialog and, when none is available, the fallback questions. Re-validate
//! what the user chose and tell policyd: the decision, or a one-time deny
//! when the user cancelled or submitted an unusable choice.

use std::time::Duration;

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, RequestContext, RpcReply, RpcRequest, UiPush,
};
use tracing::{info, warn};

use super::{
    choice::{deny_cancellation, resolve_choice},
    dialog::{ApprovalReviewOutcome, Dialogs},
    error::UiCliError,
    fallback, kinds,
    options::{ApprovalFormResult, PromptAction, ReviewValidator, ReviewedChoice, ScopeOption},
    prompt::{ClientContext, Prompt, TargetParser},
};

/// Settle `push` unless policyd no longer waits on it.
///
/// # Errors
/// Returns [`UiCliError`] when a dialog cannot run or RPC communication with
/// policyd fails.
pub async fn handle_push(
    client: &ClientContext<'_>,
    dialogs: &Dialogs,
    push: UiPush,
) -> Result<(), UiCliError> {
    // Pushes queue while a dialog is open; a decision on an earlier
    // prompt can settle the request behind this one in the meantime.
    if !still_pending(client, &push).await {
        info!("skipping prompt already settled by an earlier decision");
        return Ok(());
    }

    settle(client, dialogs, kinds::prompt_for(client, push)).await
}

/// Whether policyd still waits on the request `push` prompts for. A failed
/// status check prompts anyway rather than drop a live request.
async fn still_pending(client: &ClientContext<'_>, push: &UiPush) -> bool {
    let mut ctx = RequestContext::from(client.paths);
    ctx.sandbox_session_id = client.sandbox_session_id.map(str::to_owned);

    match agent_sandbox_core::policy_rpc(
        client.socket,
        RpcRequest::Status { ctx },
        Duration::from_secs(10),
    )
    .await
    {
        Ok(RpcReply::Status(status)) => status.pending.iter().any(|pending| push.is_for(pending)),

        Ok(reply) => {
            warn!(?reply, "unexpected status reply; prompting anyway");
            true
        }

        Err(err) => {
            warn!(error = %err, "pending status check failed; prompting anyway");
            true
        }
    }
}

async fn settle(
    client: &ClientContext<'_>,
    dialogs: &Dialogs,
    prompt: Prompt,
) -> Result<(), UiCliError> {
    let Prompt {
        origin,
        review,
        parse_target,
        fallback,
    } = prompt;

    let session_available = client.session_id.is_some();
    let package_available = origin.package.is_some();

    let validator = make_validator(
        session_available,
        package_available,
        TargetParser::clone(&parse_target),
    );

    let decision = match dialogs.review(review, Some(validator)).await? {
        ApprovalReviewOutcome::Submitted(result) => {
            reviewed_choice(&result, session_available, package_available, |result| {
                parse_target(result)
            })
        }

        ApprovalReviewOutcome::Cancelled => None,

        ApprovalReviewOutcome::Unavailable => {
            fallback::ask(
                dialogs,
                session_available,
                origin.package.as_deref(),
                &fallback,
            )
            .await?
        }
    };

    let sandbox_session_id = origin.sandbox_session_id.as_deref();

    match decision {
        Some(ReviewedChoice { action, choice }) => {
            resolve_choice(
                client.socket,
                &origin.paths,
                client.session_id,
                sandbox_session_id,
                &origin.id,
                action,
                choice,
            )
            .await
        }

        None => {
            deny_cancellation(client.socket, &origin.paths, sandbox_session_id, &origin.id).await
        }
    }
}

struct ReviewActionScope {
    action: PromptAction,
    scope: ApprovalScope,
}

fn validated_review_action(
    result: &ApprovalFormResult,
    session_available: bool,
    package_available: bool,
) -> Option<ReviewActionScope> {
    let action = result.action?;
    let scope = result.scope;

    let allowed = scope == ApprovalScope::Once
        || scope == ApprovalScope::Project
        || scope == ApprovalScope::Global
        || (scope == ApprovalScope::ProjectPackage && package_available)
        || (scope == ApprovalScope::GlobalPackage && package_available)
        || (scope == ApprovalScope::Session && session_available);

    allowed.then_some(ReviewActionScope { action, scope })
}

fn persistent_comment(result: &ApprovalFormResult, scope: ApprovalScope) -> Option<String> {
    if !matches!(
        scope,
        ApprovalScope::Project
            | ApprovalScope::ProjectPackage
            | ApprovalScope::GlobalPackage
            | ApprovalScope::Global
    ) {
        return None;
    }

    result
        .values
        .get("comment")
        .map(String::as_str)
        .map(str::trim)
        .filter(|comment| !comment.is_empty())
        .map(str::to_owned)
}

fn reviewed_choice(
    result: &ApprovalFormResult,
    session_available: bool,
    package_available: bool,
    target: impl FnOnce(&ApprovalFormResult) -> Option<ApprovalTarget>,
) -> Option<ReviewedChoice> {
    let ReviewActionScope { action, scope } =
        validated_review_action(result, session_available, package_available)?;

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
            comment: persistent_comment(result, scope),
        },
    })
}

/// Builds a [`ReviewValidator`] that enforces scope availability and
/// runs `parse_target` for persistent scopes, producing a human-readable
/// error so the Qt dialog can keep the form open for correction.
fn make_validator(
    session_available: bool,
    package_available: bool,
    parse_target: TargetParser,
) -> ReviewValidator {
    Box::new(move |result: &ApprovalFormResult| {
        if validated_review_action(result, session_available, package_available).is_none() {
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

#[cfg(test)]
mod tests;
