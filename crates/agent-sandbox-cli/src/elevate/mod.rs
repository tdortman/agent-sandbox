//! Request host-side root execution via policyd.

use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::{
    ProcessIds, RequestContext, RpcReply, RpcRequest, SandboxPaths, policy_rpc,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-elevate")]
struct Cli {
    #[arg(
        long,
        env = "AGENT_SANDBOX_POLICY_SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<String>,
}

pub async fn run() -> Result<(), ElevateCliError> {
    let cli = Cli::parse();
    if cli.argv.is_empty() {
        eprintln!("agent-sandbox: usage: sudo <command>");
        return Err(ElevateCliError::Usage);
    }

    let paths = SandboxPaths::new(
        std::env::var("AGENT_SANDBOX_CWD").unwrap_or_default(),
        std::env::var("AGENT_SANDBOX_HOME")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_default(),
        std::env::var("AGENT_SANDBOX_PROJECT_ROOT").unwrap_or_default(),
    );
    let pid = std::process::id();
    let uid = nix::unistd::getuid().as_raw();

    let req = RpcRequest::Elevate {
        argv: cli.argv,
        ctx: RequestContext::from((paths, ProcessIds::new(pid, uid))),
    };

    let resp = policy_rpc(&cli.socket, req, Duration::from_mins(2))
        .await
        .map_err(ElevateCliError::Rpc)?;

    match resp {
        RpcReply::Error(e) => {
            eprintln!("agent-sandbox: {}", e.error);
            Err(ElevateCliError::Policyd)
        }
        RpcReply::Elevate(e) if !e.allowed => {
            let msg = if e.stderr.is_empty() {
                "agent-sandbox: elevation denied".to_string()
            } else {
                e.stderr.trim().to_string()
            };
            eprintln!("{msg}");
            std::process::exit(e.exit_code);
        }
        RpcReply::Elevate(e) => {
            if !e.stdout.is_empty() {
                print!("{}", ensure_nl(&e.stdout));
            }
            if !e.stderr.is_empty() {
                eprint!("{}", ensure_nl(&e.stderr));
            }
            std::process::exit(e.exit_code);
        }
        other => {
            eprintln!("agent-sandbox: unexpected reply: {other:?}");
            Err(ElevateCliError::Policyd)
        }
    }
}

fn ensure_nl(s: &str) -> String {
    if s.ends_with('\n') {
        s.to_string()
    } else {
        format!("{s}\n")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ElevateCliError {
    #[error("usage")]
    Usage,
    #[error("policyd error")]
    Policyd,
    #[error(transparent)]
    Rpc(#[from] agent_sandbox_core::RpcClientError),
}
