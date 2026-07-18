//! Request host-side root execution via policyd.

use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_core::{
    ProcessIds, RequestContext, RpcReply, RpcRequest, SandboxPaths, policy_rpc,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-elevate",
    version,
    about = "Request host-side root execution of a command via policyd",
    long_about = "Wrapper that runs inside the sandbox to ask policyd to perform a one-shot \
        privileged execution of the given command on the host. policyd prompts the user (via \
        the registered UI) and, on approval, runs the command with full root capabilities, \
        capturing stdout and stderr. The exit status of the elevated process is propagated to \
        the caller.\n\n\
        Reads the sandbox paths from the \"AGENT_SANDBOX_CWD\", \"AGENT_SANDBOX_HOME\", and \
        \"AGENT_SANDBOX_PROJECT_ROOT\" env vars (set by the bwrap wrapper) and the session id \
        from \"AGENT_SANDBOX_SESSION_ID\".\n\n\
        EXAMPLES:\n\
        # Run \"apt install\" as root on the host with no sandbox mediation.\n\
        agent-sandbox-elevate -- apt install -y neovim\n\n\
        # Point at a non-default policyd socket for local testing.\n\
        agent-sandbox-elevate --socket /run/agent-sandbox/policy.sock -- apt update"
)]
struct Cli {
    /// Path to the policyd Unix domain socket. The elevate request is sent here. Falls back to the env var "`AGENT_SANDBOX_POLICY_SOCKET`" if unset.
    #[arg(
        long,
        value_name = "SOCKET",
        env = "AGENT_SANDBOX_POLICY_SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,
    /// The full argv of the command to run with elevated privileges on the host. Leading dashes are preserved (e.g. "--list").
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    argv: Vec<String>,
}

/// Run the elevate CLI: parse args, build request, send to policyd, handle reply.
///
/// # Errors
/// Returns [`ElevateCliError::Usage`] when no command is provided,
/// [`ElevateCliError::Rpc`] when the RPC to policyd fails,
/// or [`ElevateCliError::Policyd`] when policyd returns an error or unexpected reply.
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

    let mut ctx = RequestContext::from_paths_and_ids(&paths, ProcessIds::new(pid, uid));
    ctx.sandbox_session_id = std::env::var("AGENT_SANDBOX_SESSION_ID").ok();

    let req = RpcRequest::Elevate {
        argv: cli.argv,
        ctx,
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
