//! Long-lived policyd UI client (Qt / tty prompts).

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
#[command(name = "agent-sandbox-ui")]
struct Cli {
    #[arg(
        long,
        env = "AGENT_SANDBOX_POLICY_SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,
    #[arg(long, env = "AGENT_SANDBOX_CWD")]
    cwd: Option<String>,
    #[arg(long, env = "AGENT_SANDBOX_HOME")]
    home: Option<String>,
    #[arg(long, env = "AGENT_SANDBOX_PROJECT_ROOT")]
    project_root: Option<String>,
    #[arg(long, env = "AGENT_SANDBOX_SESSION_ID")]
    sandbox_session_id: Option<String>,
}

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
