use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::{ApprovalScope, RequestContext, RpcReply, RpcRequest, SandboxPaths};
use tracing::info;

use super::error::UiCliError;
use super::options::{PromptAction, ScopeOption};

pub(crate) fn format_elevation_title(argv: &[String], _cwd: &str) -> String {
    let cmd = argv.join(" ");
    let mut title = format!("agent-sandbox: sudo {cmd}");
    if title.len() > 72 {
        title.truncate(69);
        title.push_str("...");
    }
    title
}

pub(crate) async fn resolve_choice(
    socket: &PathBuf,
    paths: &SandboxPaths,
    session_id: Option<&str>,
    id: &str,
    action: PromptAction,
    choice: Option<ScopeOption>,
) -> Result<(), UiCliError> {
    let Some(choice) = choice else {
        return deny_cancellation(socket, paths, session_id, id).await;
    };
    if choice.scope == ApprovalScope::Session && session_id.is_none() {
        let noun = match action {
            PromptAction::Allow => "approval",
            PromptAction::Deny => "deny",
        };
        eprintln!("agent-sandbox: session {noun} unavailable (policy UI not connected).");
        return Ok(());
    }

    let req = match action {
        PromptAction::Allow => RpcRequest::Approve {
            id: id.to_string(),
            scope: choice.scope,
            session_id: session_id.map(str::to_owned),
            target: choice.target,
            ctx: RequestContext::from(paths),
        },
        PromptAction::Deny => RpcRequest::Deny {
            id: id.to_string(),
            scope: choice.scope,
            session_id: session_id.map(str::to_owned),
            target: choice.target,
            ctx: RequestContext::from(paths),
        },
    };
    let resp = agent_sandbox_core::policy_rpc(socket, req, Duration::from_mins(1)).await?;
    match resp {
        RpcReply::Error(e) => {
            let verb = match action {
                PromptAction::Allow => "approval",
                PromptAction::Deny => "deny",
            };
            eprintln!("agent-sandbox: {verb} failed ({})", e.error);
        }
        RpcReply::ScopeAction(s) if s.path().is_some() => {
            eprintln!("Project policy saved to {}.", s.path().unwrap_or_default());
        }
        _ => {}
    }
    Ok(())
}

/// Send a one-time deny to policyd for a prompt the user cancelled so the
/// agent is unblocked with EACCES instead of waiting for the approval
/// timeout. The denial is in-memory only: no rule is saved.
pub(crate) async fn deny_cancellation(
    socket: &PathBuf,
    paths: &SandboxPaths,
    session_id: Option<&str>,
    id: &str,
) -> Result<(), UiCliError> {
    info!(request_id = %id, "prompt cancelled by user; sending one-time deny");
    let req = RpcRequest::Deny {
        id: id.to_string(),
        scope: ApprovalScope::Once,
        session_id: session_id.map(str::to_owned),
        target: None,
        ctx: RequestContext::from(paths),
    };
    if let Err(err) = agent_sandbox_core::policy_rpc(socket, req, Duration::from_mins(1)).await {
        eprintln!("agent-sandbox: cancel-deny failed ({err})");
    }
    Ok(())
}
