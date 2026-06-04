use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::{ApprovalScope, RpcReply, RpcRequest, SandboxPaths};
use tracing::info;

use super::error::UiCliError;

pub(crate) fn format_elevation_title(argv: &[String], cwd: &str) -> String {
    let cmd = if argv.is_empty() {
        "sudo".to_string()
    } else {
        format!("sudo {}", argv.join(" "))
    };
    let mut title = format!("agent-sandbox — sudo: {cmd}");
    if title.len() > 72 {
        title.truncate(69);
        title.push_str("...");
    }
    let _ = cwd;
    title
}

pub(crate) async fn resolve_choice(
    socket: &PathBuf,
    paths: &SandboxPaths,
    session_id: Option<&str>,
    id: &str,
    choice: Option<&str>,
) -> Result<(), UiCliError> {
    let Some(choice) = choice else {
        info!("no prompt available; request left pending");
        return Ok(());
    };
    let (deny, scope) = scope_for_label(choice);
    let scope_str = scope.as_str().to_string();
    if deny {
        if scope == ApprovalScope::Session && session_id.is_none() {
            eprintln!("agent-sandbox: session deny unavailable (policy UI not connected).");
            return Ok(());
        }
        let req = RpcRequest::Deny {
            id: id.to_string(),
            scope: scope_str,
            session_id: session_id.map(str::to_owned),
            cwd: paths.cwd_string(),
            home: paths.home_string(),
            project_root: paths.project_root_string(),
            uid: None,
        };
        let resp = agent_sandbox_core::policy_rpc(socket, req, Duration::from_mins(1)).await?;
        if let RpcReply::Error(e) = resp {
            eprintln!("agent-sandbox: deny failed ({})", e.error);
        }
    } else {
        if scope == ApprovalScope::Session && session_id.is_none() {
            eprintln!("agent-sandbox: session approval unavailable (policy UI not connected).");
            return Ok(());
        }
        let req = RpcRequest::Approve {
            id: id.to_string(),
            scope: scope_str,
            session_id: session_id.map(str::to_owned),
            cwd: paths.cwd_string(),
            home: paths.home_string(),
            project_root: paths.project_root_string(),
            uid: None,
        };
        let resp = agent_sandbox_core::policy_rpc(socket, req, Duration::from_mins(1)).await?;
        match resp {
            RpcReply::Error(e) => {
                eprintln!("agent-sandbox: approval failed ({})", e.error);
            }
            RpcReply::ScopeAction(s) if s.path.is_some() => {
                eprintln!("Project policy saved to {}.", s.path.unwrap_or_default());
            }
            _ => {}
        }
    }
    Ok(())
}

fn scope_for_label(label: &str) -> (bool, ApprovalScope) {
    let deny = label.starts_with("Deny ");
    let scope = if label.contains("once") {
        ApprovalScope::Once
    } else if label.contains("session") {
        ApprovalScope::Session
    } else if label.contains("project") {
        ApprovalScope::Project
    } else {
        ApprovalScope::Global
    };
    (deny, scope)
}
