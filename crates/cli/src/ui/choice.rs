use std::{path::Path, time::Duration};

use agent_sandbox_core::{ApprovalScope, RequestContext, RpcReply, RpcRequest, SandboxPaths};
use tracing::info;

use super::{
    error::UiCliError,
    options::{PromptAction, ScopeOption},
};

pub fn format_elevation_title(argv: &[String]) -> String {
    let cmd = argv.join(" ");
    format!("agent-sandbox: sudo {cmd}")
}

pub async fn resolve_choice(
    socket: &Path,
    paths: &SandboxPaths,
    session_id: Option<&str>,
    sandbox_session_id: Option<&str>,
    id: &str,
    action: PromptAction,
    choice: Option<ScopeOption>,
) -> Result<(), UiCliError> {
    let Some(choice) = choice else {
        return deny_cancellation(socket, paths, sandbox_session_id, id).await;
    };
    if choice.scope == ApprovalScope::Session && session_id.is_none() {
        let noun = match action {
            PromptAction::Allow => "approval",
            PromptAction::Deny => "deny",
        };
        return Err(UiCliError::Register(format!(
            "session {noun} unavailable (policy UI not connected yet)"
        )));
    }

    let mut ctx = RequestContext::from(paths);
    ctx.sandbox_session_id = sandbox_session_id.map(str::to_owned);
    let req = match action {
        PromptAction::Allow => RpcRequest::Approve {
            id: id.to_string(),
            scope: choice.scope,
            session_id: session_id.map(str::to_owned),
            target: choice.target,
            comment: choice.comment,
            ctx,
        },
        PromptAction::Deny => RpcRequest::Deny {
            id: id.to_string(),
            scope: choice.scope,
            session_id: session_id.map(str::to_owned),
            target: choice.target,
            comment: choice.comment,
            ctx,
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
            eprintln!(
                "Project policy saved to {}.",
                s.path()
                    .map_or_else(String::new, |p| p.display().to_string())
            );
        }
        _ => {}
    }
    Ok(())
}

/// Send a one-time deny to policyd for a prompt the user cancelled so the
/// agent is unblocked with EACCES instead of waiting for the approval
/// timeout. The denial is in-memory only: no rule is saved.
pub async fn deny_cancellation(
    socket: &Path,
    paths: &SandboxPaths,
    sandbox_session_id: Option<&str>,
    id: &str,
) -> Result<(), UiCliError> {
    info!(request_id = %id, "prompt cancelled by user; sending one-time deny");
    let mut ctx = RequestContext::from(paths);
    ctx.sandbox_session_id = sandbox_session_id.map(str::to_owned);
    let req = RpcRequest::Deny {
        id: id.to_string(),
        scope: ApprovalScope::Once,
        session_id: None,
        target: None,
        comment: None,
        ctx,
    };
    if let Err(err) = agent_sandbox_core::policy_rpc(socket, req, Duration::from_mins(1)).await {
        eprintln!("agent-sandbox: cancel-deny failed ({err})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::format_elevation_title;
    #[test]
    fn format_elevation_title_keeps_full_long_argv() {
        let argv: Vec<String> = std::iter::once("id".to_string())
            .chain(std::iter::repeat_n(
                "adsfsdafsdafdasadsfsdafsdafsadfasd".to_string(),
                20,
            ))
            .collect();
        let title = format_elevation_title(&argv);
        let expected_cmd = argv.join(" ");
        assert!(
            title.contains(&expected_cmd),
            "title must include the full command; got {title}"
        );
        assert!(!title.ends_with("..."), "title must not end with ellipsis");
        assert!(title.len() > 200, "long argv should produce a long title");
    }

    #[test]
    fn format_elevation_title_does_not_truncate_or_insert_newlines() {
        // Wrapping/reflow is the dialog's job (e.g. QTextEdit with
        // WidgetWidth line wrap on the Qt helper). The CLI must hand off
        // the full command unmodified so the dialog can reflow as the
        // window is resized.
        let argv = vec![
            "id".to_string(),
            "adsfsdafsdafdasadsfsdafsdafsadfasd".repeat(20),
            "BLOB=".to_string() + &"a".repeat(500),
        ];
        let title = format_elevation_title(&argv);
        assert!(
            !title.contains('\n'),
            "CLI must not insert newlines; the dialog reflows. got {title}"
        );
        assert!(!title.ends_with("..."), "title must not end with ellipsis");
        let expected = argv.join(" ");
        assert!(
            title.contains(&expected),
            "title must contain the full command verbatim"
        );
    }
}
