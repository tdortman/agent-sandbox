use std::path::PathBuf;

use agent_sandbox_core::rpc::RequestContext;
use agent_sandbox_dbus_proxy::{RelayConfig, run};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "agent-sandbox-dbus-proxy")]
struct Args {
    /// Unix socket exposed to sandbox clients.
    #[arg(long)]
    listen: PathBuf,

    /// D-Bus address used for each upstream connection.
    #[arg(long)]
    upstream_address: String,

    /// Unix socket for policyd JSON-line RPC.
    #[arg(long)]
    policy_socket: PathBuf,

    /// Policy bus selection.
    #[arg(long, default_value = "session", value_parser = ["session", "system"])]
    bus: String,

    /// Request context current working directory.
    #[arg(long)]
    cwd: Option<PathBuf>,

    /// Request context home directory.
    #[arg(long)]
    home: Option<PathBuf>,

    /// Request context project root.
    #[arg(long)]
    project_root: Option<PathBuf>,

    /// Request context process id.
    #[arg(long)]
    pid: Option<u32>,

    /// Request context user id.
    #[arg(long)]
    uid: Option<u32>,

    /// Request context sandbox session identifier.
    #[arg(long)]
    sandbox_session_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let context = RequestContext {
        cwd: args.cwd,
        home: args.home,
        project_root: args.project_root,
        pid: args.pid,
        uid: args.uid,
        sandbox_session_id: args.sandbox_session_id,
    };
    let mut config = RelayConfig::new(args.listen, args.upstream_address, args.policy_socket);
    config.context = context;
    config.bus = if args.bus == "system" {
        agent_sandbox_core::DbusBus::System
    } else {
        agent_sandbox_core::DbusBus::Session
    };
    run(config).await?;
    Ok(())
}
