//! Entry point for the D-Bus relay daemon.
//!
//! Parses relay configuration from the command line, then runs the
//! `agent-sandbox-dbus-proxy` library relay against the configured listener
//! and policy socket.
use std::{path::PathBuf, process::ExitCode};

use agent_sandbox_core::{DbusBus, rpc::RequestContext};
use agent_sandbox_dbus_proxy::{RelayConfig, open_terminal_oauth, run};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "agent-sandbox-dbus-proxy",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Args {
    #[command(flatten)]
    relay: Option<RelayArgs>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Open a terminal OAuth link through the session relay of the launcher
    /// running under the given foreground process. Exit 3 means the terminal
    /// should handle the link normally.
    Open { foreground: u32, uri: String },
}

#[derive(Debug, clap::Args)]
struct RelayArgs {
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
async fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args = Args::parse();
    if let Some(Command::Open { foreground, uri }) = args.command {
        return Ok(if open_terminal_oauth(foreground, uri).await? {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        });
    }
    let args = args.relay.ok_or("missing relay options")?;

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
        DbusBus::System
    } else {
        DbusBus::Session
    };

    run(config).await?;
    Ok(ExitCode::SUCCESS)
}
