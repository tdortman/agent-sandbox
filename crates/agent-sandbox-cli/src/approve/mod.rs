//! Host CLI for pending policy approvals.

use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::{
    ApprovalScope, PendingSummary, RequestContext, RpcReply, RpcRequest, SandboxPaths, policy_rpc,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-approve")]
struct Cli {
    #[arg(long, default_value = "/run/agent-sandbox/policy.sock")]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Pending {
        #[arg(long)]
        home: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        project_root: Option<String>,
    },
    Approve {
        id: String,
        scope: ApprovalScope,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        home: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        project_root: Option<String>,
    },
    ApproveHost {
        host: String,
        port: u16,
        scope: ApprovalScope,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        home: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        project_root: Option<String>,
    },
    Deny {
        id: String,
        #[arg(default_value = "once")]
        scope: ApprovalScope,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        home: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        project_root: Option<String>,
    },
}

pub async fn run() -> Result<(), ApproveCliError> {
    let cli = Cli::parse();
    let paths = |home: Option<String>, cwd: Option<String>, project_root: Option<String>| {
        SandboxPaths::from_wire(cwd, home, project_root)
    };

    match cli.cmd {
        Command::Pending {
            home,
            cwd,
            project_root,
        } => {
            let p = paths(home, cwd, project_root);
            let req = RpcRequest::Status {
                ctx: RequestContext::from(&p),
            };
            let resp = rpc(&cli.socket, req).await?;
            let RpcReply::Status(body) = resp else {
                return Err(approve_error(&resp));
            };
            if body.pending.is_empty() {
                println!("No pending approvals.");
                return Ok(());
            }
            for item in body.pending {
                match item {
                    PendingSummary::Elevation { id, argv, .. } => {
                        let argv = argv.unwrap_or_default();
                        println!("{id}\televation\t{}", argv.join(" "));
                    }
                    PendingSummary::Network { id, host, port, .. } => {
                        let host = host.unwrap_or_default();
                        let port = port.unwrap_or(0);
                        println!("{id}\tnetwork\t{host}:{port}");
                    }
                }
            }
        }
        Command::Approve {
            id,
            scope,
            session_id,
            home,
            cwd,
            project_root,
        } => {
            let p = paths(home, cwd, project_root);
            let req = RpcRequest::Approve {
                id,
                scope,
                session_id,
                ctx: RequestContext::from(&p),
            };
            let resp = rpc(&cli.socket, req).await?;
            print_json(&resp)?;
        }
        Command::ApproveHost {
            host,
            port,
            scope,
            session_id,
            home,
            cwd,
            project_root,
        } => {
            let p = paths(home, cwd, project_root);
            let req = RpcRequest::ApproveHost {
                host,
                port,
                scope,
                session_id,
                ctx: RequestContext::from(&p),
            };
            let resp = rpc(&cli.socket, req).await?;
            print_json(&resp)?;
        }
        Command::Deny {
            id,
            scope,
            session_id,
            home,
            cwd,
            project_root,
        } => {
            let p = paths(home, cwd, project_root);
            let req = RpcRequest::Deny {
                id,
                scope,
                session_id,
                ctx: RequestContext::from(&p),
            };
            let resp = rpc(&cli.socket, req).await?;
            print_json(&resp)?;
        }
    }
    Ok(())
}

async fn rpc(socket: &PathBuf, req: RpcRequest) -> Result<RpcReply, ApproveCliError> {
    policy_rpc(socket, req, Duration::from_secs(30))
        .await
        .map_err(ApproveCliError::Rpc)
}

fn print_json(resp: &RpcReply) -> Result<(), ApproveCliError> {
    println!("{}", serde_json::to_string_pretty(resp)?);
    if resp.is_ok() {
        Ok(())
    } else {
        Err(approve_error(resp))
    }
}

fn approve_error(resp: &RpcReply) -> ApproveCliError {
    match resp {
        RpcReply::Error(e) => ApproveCliError::Policyd(e.error.clone()),
        _ => ApproveCliError::Policyd("request failed".into()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApproveCliError {
    #[error(transparent)]
    Rpc(#[from] agent_sandbox_core::RpcClientError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Policyd(String),
}
