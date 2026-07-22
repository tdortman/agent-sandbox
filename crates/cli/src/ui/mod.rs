//! Long-lived policyd UI client (graphical Qt / zenity prompts).

mod choice;
mod dialog;
mod error;
mod options;
mod push;

use std::{
    fs::{File, OpenOptions},
    future::Future,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::{
    DbusBus, DbusMessageKind, RequestContext, RpcConnection, RpcMessage, RpcReply, RpcRequest,
    SandboxPaths, UiPush,
};
use clap::Parser;
pub use error::UiCliError;
use nix::fcntl::{Flock, FlockArg, OFlag};
use tracing::{info, warn};

#[must_use]
pub const fn bus_name(bus: DbusBus) -> &'static str {
    match bus {
        DbusBus::Session => "session",
        DbusBus::System => "system",
    }
}

#[must_use]
pub const fn message_kind_name(kind: DbusMessageKind) -> &'static str {
    match kind {
        DbusMessageKind::MethodCall => "method_call",
        DbusMessageKind::MethodReturn => "method_return",
        DbusMessageKind::Error => "error",
        DbusMessageKind::Signal => "signal",
    }
}

#[must_use]
pub const fn signature_display(signature: &str) -> &str {
    if signature.is_empty() {
        "<empty>"
    } else {
        signature
    }
}

const PROMPT_LOCK_FILE_NAME: &str = "agent-sandbox-ui.prompt.lock";

fn is_safe_runtime_dir(path: &Path, uid: u32) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_dir() && metadata.uid() == uid && metadata.mode().trailing_zeros() >= 6
}

fn prompt_lock_path() -> Result<PathBuf, UiCliError> {
    let uid = nix::unistd::Uid::current().as_raw();
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && is_safe_runtime_dir(path, uid))
        .or_else(|| {
            let path = PathBuf::from("/run/user").join(uid.to_string());
            is_safe_runtime_dir(&path, uid).then_some(path)
        });
    runtime_dir
        .map(|path| path.join(PROMPT_LOCK_FILE_NAME))
        .ok_or_else(|| {
            UiCliError::Register("no safe per-user runtime directory for the prompt lock".into())
        })
}

pub(super) async fn prompt_blocking<F, T>(operation: F) -> Result<T, UiCliError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| UiCliError::Register("prompt join failed".into()))
}

async fn acquire_prompt_lock(path: PathBuf) -> Result<Flock<File>, UiCliError> {
    prompt_blocking(move || {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(OFlag::O_NOFOLLOW.bits())
            .open(&path)
            .map_err(|err| {
                UiCliError::Register(format!(
                    "failed to open prompt lock {}: {err}",
                    path.display()
                ))
            })?;
        let metadata = file.metadata().map_err(|err| {
            UiCliError::Register(format!(
                "failed to inspect prompt lock {}: {err}",
                path.display()
            ))
        })?;
        if metadata.uid() != nix::unistd::Uid::current().as_raw()
            || (metadata.mode() & 0o7777) != 0o600
        {
            return Err(UiCliError::Register(format!(
                "prompt lock {} has unsafe ownership or permissions",
                path.display()
            )));
        }
        Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, err)| {
            UiCliError::Register(format!(
                "failed to lock prompt lock {}: {err}",
                path.display()
            ))
        })
    })
    .await?
}

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-ui",
    version,
    about = "Long-lived policyd UI client that surfaces interactive approval prompts",
    long_about = r#"Long-lived UI client for policyd. 
Connects to the policyd host socket, registers as a UI client for the current context, then loops on the connection to display incoming approval requests (network/elevation/filesystem) and forward the user's decisions back to policyd.

EXAMPLES:
# Start a UI client from launcher-provided env vars, including AGENT_SANDBOX_SESSION_ID.
agent-sandbox-ui

# Pass context explicitly and tag the session for policy routing.
agent-sandbox-ui \
    --socket /run/agent-sandbox/policy.sock \
    --cwd /home/user/project \
    --home /home/user \
    --project-root /home/user/project \
    --sandbox-session-id session-2024-05-01-abc"#
)]
struct Cli {
    /// Path to the policyd Unix domain socket the UI registers on. Falls back
    /// to the env var "`AGENT_SANDBOX_POLICY_SOCKET`" if unset.
    #[arg(
        long,
        value_name = "SOCKET",
        env = "AGENT_SANDBOX_POLICY_SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,
    /// Working directory inside the sandbox. Forwarded to policyd so
    /// per-project rules resolve correctly. Defaults to the env var
    /// "`AGENT_SANDBOX_CWD`".
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
    cwd: Option<PathBuf>,
    /// Home directory inside the sandbox. Used to scope "global" rules.
    /// Defaults to the env var "`AGENT_SANDBOX_HOME`".
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
    home: Option<PathBuf>,
    /// Project root inside the sandbox. Used to scope "project" rules. Defaults
    /// to the env var "`AGENT_SANDBOX_PROJECT_ROOT`".
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
    project_root: Option<PathBuf>,
    /// Sandbox session id. Routes this UI client to a specific sandbox
    /// session's pending requests. Defaults to the env var
    /// "`AGENT_SANDBOX_SESSION_ID`".
    #[arg(long, value_name = "ID", env = "AGENT_SANDBOX_SESSION_ID")]
    sandbox_session_id: Option<String>,
}

/// Run the UI client: parse CLI args, build context, connect to policyd, and
/// process pushes.
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
}

impl UiClient {
    const fn new(socket: PathBuf, paths: SandboxPaths, sandbox_session_id: Option<String>) -> Self {
        Self {
            socket,
            paths,
            sandbox_session_id,
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

        let mut queued_pushes = Vec::new();
        let session_id = loop {
            let msg = conn.read_message().await?;
            match msg {
                RpcMessage::Reply(RpcReply::RegisterUi(r)) if r.ok => {
                    info!("connected to policyd");
                    break r.session_id;
                }
                RpcMessage::Reply(RpcReply::Error(e)) => {
                    return Err(UiCliError::Register(e.error));
                }
                RpcMessage::UiPush(push) => {
                    queued_pushes.push(push);
                }
                RpcMessage::Reply(_) => {}
            }
        };
        process_prompts(queued_pushes, |push| self.handle_prompt(&session_id, push)).await;

        loop {
            let msg = conn.read_message().await?;
            if let RpcMessage::UiPush(push) = msg {
                process_prompts(std::iter::once(push), |push| {
                    self.handle_prompt(&session_id, push)
                })
                .await;
            }
        }
    }

    async fn handle_prompt(&self, session_id: &str, push: UiPush) {
        let lock_path = match prompt_lock_path() {
            Ok(path) => path,
            Err(err) => {
                warn!(error = %err, "prompt lock error");
                return;
            }
        };
        let _prompt_lock = match acquire_prompt_lock(lock_path).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(error = %err, "prompt lock error");
                return;
            }
        };

        if let Err(err) = push::handle_push(
            &self.socket,
            &self.paths,
            Some(session_id),
            self.sandbox_session_id.as_deref(),
            push,
        )
        .await
        {
            warn!(error = %err, "prompt error");
        }
    }
}

async fn process_prompts<F, Fut>(pushes: impl IntoIterator<Item = UiPush>, mut process: F)
where
    F: FnMut(UiPush) -> Fut,
    Fut: Future<Output = ()>,
{
    for push in pushes {
        process(push).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{
        sync::{Mutex, Notify, oneshot},
        time::timeout,
    };

    use super::*;

    #[tokio::test]
    async fn queued_prompts_are_processed_serially() {
        let pushes = (0..4)
            .map(|id| UiPush::NetworkRequest {
                id: id.to_string(),
                host: Some("example.com".into()),
                port: Some(443),
                scheme: Some("https".into()),
                url: Some("https://example.com/".into()),
                cwd: None,
                home: None,
                project_root: None,
            })
            .collect::<Vec<_>>();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_handler = Arc::clone(&seen);
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));

        process_prompts(pushes, |push| {
            let seen = Arc::clone(&seen_by_handler);
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(current, Ordering::SeqCst);
                if let UiPush::NetworkRequest { id, .. } = push {
                    seen.lock().await.push(id);
                }
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;

        assert_eq!(*seen.lock().await, ["0", "1", "2", "3"].map(str::to_owned));
        assert_eq!(max_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn prompt_lock_serializes_independent_workers() {
        let temp_dir = tempfile::tempdir().expect("create temporary lock directory");
        let lock_path = temp_dir.path().join("prompt.lock");
        let (first_acquired_tx, first_acquired_rx) = oneshot::channel();
        let (first_release_tx, first_release_rx) = oneshot::channel();
        let first_worker = tokio::spawn({
            let lock_path = lock_path.clone();
            async move {
                let lock = acquire_prompt_lock(lock_path)
                    .await
                    .expect("first worker acquires prompt lock");
                first_acquired_tx
                    .send(())
                    .expect("first worker acquisition receiver");
                first_release_rx.await.expect("first worker release signal");
                drop(lock);
            }
        });
        timeout(Duration::from_secs(1), first_acquired_rx)
            .await
            .expect("first worker acquisition timed out")
            .expect("first worker acquisition channel closed");

        let (second_attempted_tx, second_attempted_rx) = oneshot::channel();
        let second_acquired = Arc::new(Notify::new());
        let second_worker = tokio::spawn({
            let lock_path = lock_path.clone();
            let second_acquired = Arc::clone(&second_acquired);
            async move {
                second_attempted_tx
                    .send(())
                    .expect("second worker attempt receiver");
                let lock = acquire_prompt_lock(lock_path)
                    .await
                    .expect("second worker acquires prompt lock");
                second_acquired.notify_one();
                drop(lock);
            }
        });
        second_attempted_rx
            .await
            .expect("second worker attempt channel closed");
        assert!(
            timeout(Duration::from_millis(100), second_acquired.notified())
                .await
                .is_err(),
            "second worker entered while first worker held the prompt lock"
        );

        first_release_tx
            .send(())
            .expect("first worker release receiver");
        first_worker.await.expect("first worker task");
        timeout(Duration::from_secs(1), second_acquired.notified())
            .await
            .expect("second worker acquisition timed out");
        second_worker.await.expect("second worker task");
    }
}
