//! Long-lived policyd UI client (graphical Qt / zenity prompts).

mod choice;
mod dialog;
mod error;
mod fallback;
mod kinds;
mod options;
mod prompt;
mod settle;

use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::{
    DbusBus, DbusMessageKind, DbusTarget, RequestContext, RpcConnection, RpcMessage, RpcReply,
    RpcRequest, SandboxPaths, UiPush,
};
use clap::Parser;
use dialog::{Dialogs, Graphical};
pub use error::UiCliError;
use nix::fcntl::{Flock, FlockArg, OFlag};
use prompt::ClientContext;
use tracing::{info, warn};

/// Return the D-Bus bus name string (`"session"` or `"system"`) for `bus`.
#[must_use]
pub const fn bus_name(bus: DbusBus) -> &'static str {
    match bus {
        DbusBus::Session => "session",
        DbusBus::System => "system",
    }
}

/// Return the D-Bus message type name (`"method_call"`, `"method_return"`,
/// `"error"`, or `"signal"`) for `kind`.
#[must_use]
pub const fn message_kind_name(kind: DbusMessageKind) -> &'static str {
    match kind {
        DbusMessageKind::MethodCall => "method_call",
        DbusMessageKind::MethodReturn => "method_return",
        DbusMessageKind::Error => "error",
        DbusMessageKind::Signal => "signal",
    }
}

/// Return `signature` unchanged, or the placeholder `"<empty>"` when it is
/// empty.
#[must_use]
pub const fn signature_display(signature: &str) -> &str {
    if signature.is_empty() {
        "<empty>"
    } else {
        signature
    }
}

/// Format fd metadata as a semicolon-joined "index: kind=..., `read_only`=..."
/// list.
#[must_use]
pub(crate) fn dbus_fd_display(target: &DbusTarget) -> String {
    target
        .fd_metadata
        .iter()
        .enumerate()
        .map(|(index, metadata)| {
            format!(
                "{index}: kind={}, read_only={}",
                metadata.kind, metadata.read_only
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
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

/// Pushes held between sending the registration and its acknowledgement.
const MAX_QUEUED_PUSHES: usize = 64;

/// Where the client stands with policyd's registration handshake.
enum ClientSessionState {
    /// Registration is in flight; early pushes wait in `queued`.
    Registering {
        /// Session to resume from an earlier connection, if any.
        resume_session: Option<String>,
        queued: VecDeque<UiPush>,
    },

    /// policyd acknowledged the registration.
    Registered { session_id: String },
}

impl ClientSessionState {
    const fn new() -> Self {
        Self::Registering {
            resume_session: None,
            queued: VecDeque::new(),
        }
    }

    fn resume_session(&self) -> Option<&str> {
        match self {
            Self::Registering { resume_session, .. } => resume_session.as_deref(),
            Self::Registered { session_id } => Some(session_id),
        }
    }

    /// Begin registering on a fresh connection, keeping the known session
    /// id to resume.
    fn restart_registration(&mut self) {
        *self = Self::Registering {
            resume_session: self.resume_session().map(str::to_owned),
            queued: VecDeque::new(),
        };
    }

    /// Hold a push that arrived before the registration reply. Pushes past
    /// [`MAX_QUEUED_PUSHES`] are dropped.
    fn queue_push(&mut self, push: UiPush) {
        match self {
            Self::Registering { queued, .. } if queued.len() < MAX_QUEUED_PUSHES => {
                queued.push_back(push);
            }

            Self::Registering { .. } => warn!("push queue full before registration; dropping push"),

            Self::Registered { .. } => warn!("push queued outside registration; dropping push"),
        }
    }

    /// Record the acknowledged session and hand back the pushes that
    /// arrived first.
    fn complete_registration(&mut self, session_id: String) -> VecDeque<UiPush> {
        match std::mem::replace(self, Self::Registered { session_id }) {
            Self::Registering { queued, .. } => queued,
            Self::Registered { .. } => VecDeque::new(),
        }
    }
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
        // Survives reconnects so policyd keeps this UI's session approvals
        // across its own restart.
        let mut state = ClientSessionState::new();

        loop {
            match self.session(&mut state).await {
                Ok(()) => {}

                Err(UiCliError::Register(err)) => {
                    // A rejected registration is permanent: retrying cannot
                    // help and each attempt logs a policyd dispatch error.
                    warn!(error = %err, "registration rejected; exiting");
                    return Ok(());
                }

                Err(err) => warn!(error = %err, "disconnected; retrying"),
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn session(&self, state: &mut ClientSessionState) -> Result<(), UiCliError> {
        let mut conn = RpcConnection::connect(&self.socket).await?;
        let mut ctx = RequestContext::from(&self.paths);
        ctx.sandbox_session_id.clone_from(&self.sandbox_session_id);

        state.restart_registration();

        conn.write_request(&RpcRequest::RegisterUi {
            ui_client: Some("standalone".into()),
            resume_session: state.resume_session().map(str::to_owned),
            ctx,
        })
        .await?;

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
                    state.queue_push(push);
                }
                RpcMessage::Reply(_) => {}
            }
        };

        let queued = state.complete_registration(session_id.clone());

        for push in queued {
            self.handle_prompt(&session_id, push).await;
        }

        loop {
            let msg = conn.read_message().await?;

            if let RpcMessage::UiPush(push) = msg {
                self.handle_prompt(&session_id, push).await;
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

        let client = ClientContext {
            socket: &self.socket,
            paths: &self.paths,
            session_id: Some(session_id),
            sandbox_session_id: self.sandbox_session_id.as_deref(),
        };

        if let Err(err) = settle::handle_push(&client, &Dialogs::new(Graphical), push).await {
            warn!(error = %err, "prompt error");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        sync::{Notify, oneshot},
        time::timeout,
    };

    use super::*;

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

    fn network_push(id: &str) -> UiPush {
        UiPush::NetworkRequest {
            id: id.into(),
            host: None,
            port: None,
            scheme: None,
            url: None,
            cwd: None,
            home: None,
            project_root: None,
            package: None,
        }
    }

    #[test]
    fn registration_queue_is_bounded() {
        let mut state = ClientSessionState::new();

        for index in 0..=MAX_QUEUED_PUSHES {
            state.queue_push(network_push(&index.to_string()));
        }

        assert_eq!(
            state.complete_registration("session".into()).len(),
            MAX_QUEUED_PUSHES
        );
    }

    #[test]
    fn restarted_registration_resumes_previous_session() {
        let mut state = ClientSessionState::new();
        assert_eq!(state.resume_session(), None);

        state.queue_push(network_push("early"));
        state.complete_registration("session".into());
        assert_eq!(state.resume_session(), Some("session"));

        state.restart_registration();

        assert_eq!(state.resume_session(), Some("session"));
        assert!(state.complete_registration("session".into()).is_empty());
    }
}
