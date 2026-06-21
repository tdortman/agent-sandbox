use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::{RequestContext, RpcReply, RpcRequest, SandboxPaths};
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
        info!("no prompt available; request left pending");
        return Ok(());
    };
    if choice.scope == agent_sandbox_core::ApprovalScope::Session && session_id.is_none() {
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
