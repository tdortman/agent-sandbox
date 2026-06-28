//! Host CLI for pending policy approvals.

use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::{
    ApprovalScope, PendingSummary, RequestContext, RpcReply, RpcRequest, SandboxPaths, policy_rpc,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-approve",
    version,
    about = "Inspect and resolve pending policy approval requests",
    long_about = "Host-side helper for resolving pending policyd approval requests. Connects \
        to the policyd Unix socket, lists requests waiting on user input, and approves or \
        denies them at the chosen scope. Normally driven by \"agent-sandbox-ui\" (a long-lived UI client), but the same \
        commands are usable from a terminal or from automation scripts.\n\n\
        EXAMPLES:\n\
        # Show every pending approval routed through this host.\n\
        agent-sandbox-approve pending\n\n\
        # Approve a network request for the current session only.\n\
        agent-sandbox-approve approve <request-id> session --session-id session-2024-05-01-abc\n\n\
        # Pre-approve 1.1.1.1 on port 53 globally so all sandboxes can use the Cloudflare DNS.\n\
        agent-sandbox-approve approve-host 1.1.1.1 53 global --home /home/user"
)]
struct Cli {
    /// Path to the policyd Unix domain socket the CLI talks to.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List every pending approval request.
    Pending {
        /// Home directory inside the sandbox. Used to scope "global" rules to the right "policy.json". Defaults to the env var `AGENT_SANDBOX_HOME` or `$HOME`.
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var `AGENT_SANDBOX_CWD`.
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
        #[arg(long, value_name = "DIR")]
        project_root: Option<String>,
    },
    /// Approve a pending request and persist the rule at the requested scope.
    Approve {
        /// Request id printed by "pending". Identifies the queued elevation, network, or filesystem request.
        id: String,
        /// Where to persist the rule: "once" (this request only, default for "deny"), "session", "project", or "global".
        #[arg(value_name = "SCOPE")]
        scope: ApprovalScope,
        /// Session id the request belongs to. Required when the scope is "session" and the policy is keyed by session.
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,
        /// Home directory inside the sandbox. Used to scope "global" rules. Defaults to the env var `AGENT_SANDBOX_HOME` or `$HOME`.
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var `AGENT_SANDBOX_CWD`.
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
        #[arg(long, value_name = "DIR")]
        project_root: Option<String>,
    },
    /// Pre-approve a single (host, port) pair without an outstanding request. Writes the rule directly to policyd.
    ApproveHost {
        /// Destination host. Either a literal IPv4/IPv6 address (e.g. "1.1.1.1") or a hostname (e.g. "example.com").
        host: String,
        /// Destination port. Use the well-known port for the scheme (e.g. 443 for HTTPS, 53 for DNS).
        port: u16,
        /// Where to persist the rule: "once", "session", "project", or "global".
        #[arg(value_name = "SCOPE")]
        scope: ApprovalScope,
        /// Session id the rule applies to. Required when the scope is "session".
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,
        /// Home directory inside the sandbox. Used to scope "global" rules. Defaults to the env var `AGENT_SANDBOX_HOME` or `$HOME`.
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var `AGENT_SANDBOX_CWD`.
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT`.
        #[arg(long, value_name = "DIR")]
        project_root: Option<String>,
    },
    /// Deny a pending request and persist the deny rule at the requested scope.
    Deny {
        /// Request id printed by "pending".
        id: String,
        /// Where to persist the deny rule. Defaults to "once" so a denial only affects this single request.
        #[arg(value_name = "SCOPE", default_value = "once")]
        scope: ApprovalScope,
        /// Session id the request belongs to. Required when the scope is "session".
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,
        /// Home directory inside the sandbox. Used to scope "global" rules. Defaults to the env var "AGENT_SANDBOX_HOME" or "$HOME".
        #[arg(long, value_name = "DIR")]
        home: Option<String>,
        /// Working directory inside the sandbox. Used to scope per-project rules. Defaults to the env var "AGENT_SANDBOX_CWD".
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Project root inside the sandbox. Required for "project" scope. Defaults to the env var "AGENT_SANDBOX_PROJECT_ROOT".
        #[arg(long, value_name = "DIR")]
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
                        println!("{id}\televation\t\t{}", argv.join(" "));
                    }
                    PendingSummary::Network { id, host, port, .. } => {
                        let host = host.unwrap_or_default();
                        let port = port.unwrap_or(0);
                        println!("{id}\tnetwork\t\t{host}:{port}");
                    }
                    PendingSummary::Filesystem {
                        id, path, access, ..
                    } => {
                        let path = path.unwrap_or_default();
                        let access = access.map_or_else(String::new, |value| value.to_string());
                        println!("{id}\tfilesystem\t{access}\t{path}");
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
                target: None,
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
                target: None,
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
