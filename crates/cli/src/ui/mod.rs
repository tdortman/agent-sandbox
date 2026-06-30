//! Long-lived policyd UI client (graphical Qt / zenity prompts).

mod choice;
mod dialog;
mod error;
mod options;
mod push;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_sandbox_core::{
    RequestContext, RpcConnection, RpcMessage, RpcReply, RpcRequest, SandboxPaths, UiPush,
};
use clap::Parser;
pub use error::UiCliError;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-ui",
    version,
    about = "Long-lived policyd UI client that surfaces interactive approval prompts",
    long_about = "Long-lived UI client for policyd. Connects to the policyd host socket, \
        registers as a UI client for the current context, then loops on the connection to \
        display incoming approval requests (network/elevation/filesystem) and forward the \
        user's decisions back to policyd. Typically spawned by \"agent-sandbox-open-ui-fd\" or by \
        policyd itself when no other UI is registered for a given request.\n\n\
        EXAMPLES:\n\
        # Start a UI client with the default policyd socket, sourcing context from env vars.\n\
        agent-sandbox-ui\n\n\
        # Pass context explicitly and tag the session for policy routing.\n\
        agent-sandbox-ui \\\n\
            --socket /run/agent-sandbox/policy.sock \\\n\
            --cwd /home/user/project \\\n\
            --home /home/user \\\n\
            --project-root /home/user/project \\\n\
            --sandbox-session-id session-2024-05-01-abc"
)]
struct Cli {
    /// Path to the policyd Unix domain socket the UI registers on. Falls back to the env var "`AGENT_SANDBOX_POLICY_SOCKET`" if unset.
    #[arg(
        long,
        value_name = "SOCKET",
        env = "AGENT_SANDBOX_POLICY_SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,
    /// Working directory inside the sandbox. Forwarded to policyd so per-project rules resolve correctly. Defaults to the env var "`AGENT_SANDBOX_CWD`".
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
    cwd: Option<PathBuf>,
    /// Home directory inside the sandbox. Used to scope "global" rules. Defaults to the env var "`AGENT_SANDBOX_HOME`".
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
    home: Option<PathBuf>,
    /// Project root inside the sandbox. Used to scope "project" rules. Defaults to the env var "`AGENT_SANDBOX_PROJECT_ROOT`".
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
    project_root: Option<PathBuf>,
    /// Sandbox session id. Routes this UI client to a specific sandbox session's pending requests. Defaults to the env var "`AGENT_SANDBOX_SESSION_ID`".
    #[arg(long, value_name = "ID", env = "AGENT_SANDBOX_SESSION_ID")]
    sandbox_session_id: Option<String>,
}

/// Run the UI client: parse CLI args, build context, connect to policyd, and process pushes.
///
/// # Errors
/// Returns [`UiCliError`] when the RPC connection or push processing fails.
pub async fn run() -> Result<(), UiCliError> {
    let cli = Cli::parse();
    let mut ctx = RequestContext::from(&SandboxPaths::from_wire(
        cli.cwd,
        cli.home,
        cli.project_root,
    ));
    ctx.sandbox_session_id = cli.sandbox_session_id;
    let paths = ctx.sandbox_paths();
    UiClient::new(cli.socket, paths, ctx.sandbox_session_id)
        .run()
        .await
}

struct UiClient {
    socket: PathBuf,
    paths: SandboxPaths,
    sandbox_session_id: Option<String>,
    session_id: Arc<Mutex<Option<String>>>,
}

impl UiClient {
    fn new(socket: PathBuf, paths: SandboxPaths, sandbox_session_id: Option<String>) -> Self {
        Self {
            socket,
            paths,
            sandbox_session_id,
            session_id: Arc::new(Mutex::new(None)),
        }
    }

    async fn run(self) -> Result<(), UiCliError> {
        loop {
            if let Err(err) = self.session().await {
                warn!(error = %err, "disconnected; retrying");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn session(&self) -> Result<(), UiCliError> {
        let mut conn = RpcConnection::connect(&self.socket).await?;
        let mut ctx = RequestContext::from(&self.paths);
        ctx.sandbox_session_id.clone_from(&self.sandbox_session_id);
        conn.write_request(&RpcRequest::RegisterUi {
            ui_client: Some("standalone".into()),
            ctx,
        })
        .await?;

        *self.session_id.lock().await = None;

        while self.session_id.lock().await.is_none() {
            let msg = conn.read_message().await?;
            match msg {
                RpcMessage::Reply(RpcReply::RegisterUi(r)) if r.ok => {
                    *self.session_id.lock().await = Some(r.session_id);
                    info!("connected to policyd");
                }
                RpcMessage::Reply(RpcReply::Error(e)) => {
                    return Err(UiCliError::Register(e.error));
                }
                RpcMessage::UiPush(push) => {
                    self.spawn_prompt(push);
                }
                RpcMessage::Reply(_) => {}
            }
        }

        loop {
            let msg = conn.read_message().await?;
            if let RpcMessage::UiPush(push) = msg {
                self.spawn_prompt(push);
            }
        }
    }

    fn spawn_prompt(&self, push: UiPush) {
        let socket = self.socket.clone();
        let paths = self.paths.clone();
        let session_id = Arc::clone(&self.session_id);
        tokio::spawn(async move {
            let sid = session_id.lock().await.clone();
            if let Err(err) = push::handle_push(&socket, &paths, sid.as_deref(), push).await {
                warn!(error = %err, "prompt error");
            }
        });
    }
}
