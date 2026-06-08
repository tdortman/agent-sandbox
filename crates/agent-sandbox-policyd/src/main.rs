//! Agent sandbox policy daemon entry point.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_sandbox_policyd::{PolicyServer, PolicyStore, PolicydArgs, PolicydError};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-policyd")]
struct Cli {
    #[arg(long, default_value = "/run/agent-sandbox/policy.sock")]
    socket: PathBuf,

    /// When set, peers in this network namespace may only call `check` / `elevate`.
    #[arg(long, env = "AGENT_SANDBOX_SANDBOX_NETNS")]
    sandbox_netns: Option<PathBuf>,

    #[arg(long, default_value = "/etc/agent-sandbox/declarative.json")]
    declarative: PathBuf,

    #[arg(long, default_value = "/var/lib/agent-sandbox/exported-policy.json")]
    export_json: PathBuf,

    #[arg(long, default_value = "")]
    export_nix: String,

    #[arg(long, default_value = "300")]
    approval_timeout: f64,

    #[arg(long, default_value_t = true)]
    interactive_approval: bool,

    #[arg(long, env = "AGENT_SANDBOX_UI_SPAWN_CMD")]
    ui_spawn_cmd: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), PolicydError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sandbox_policyd=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    let args = PolicydArgs {
        socket: cli.socket,
        sandbox_netns: cli.sandbox_netns,
        declarative: cli.declarative,
        export_json: cli.export_json,
        export_nix: if cli.export_nix.is_empty() {
            None
        } else {
            Some(PathBuf::from(cli.export_nix))
        },
        approval_timeout: Duration::from_secs_f64(cli.approval_timeout.max(1.0)),
        interactive_approval: cli.interactive_approval,
        ui_spawn_cmd: cli.ui_spawn_cmd,
    };

    let store = Arc::new(PolicyStore::new(args));
    store
        .export_policy_files(agent_sandbox_core::SandboxPaths::default())
        .await?;

    let server = PolicyServer::new(store.clone(), store.args().socket.clone());
    server.run().await?;
    Ok(())
}
