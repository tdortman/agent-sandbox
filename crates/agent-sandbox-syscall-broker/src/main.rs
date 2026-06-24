#![allow(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use agent_sandbox_syscall_broker::{
    check_target, recv_notification, send_continue, send_errno, target_from_notification,
};
use clap::Parser;
use tokio::time;
use tracing::{debug, warn};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-syscall-broker",
    version,
    about = "Host-side seccomp user-notification broker for sandboxed agents",
    long_about = "Runs OUTSIDE the sandbox (typically as the child of `agent-sandbox-syscall-arm`) \
        and consumes the seccomp user-notification file descriptor the arm inherited from its \
        parent. For each notification the broker asks policyd whether the target syscall is \
        allowed, then writes a `SECCOMP_IOCTL_NOTIF_SEND` continue response with the chosen \
        errno (or success). Optionally supervises the sandbox child PID and exits when the \
        child does, tearing the listener down with it.\n\n\
        Spawned by policyd, not invoked by hand.\n\n\
        EXAMPLES:\n\
        # Run with a 4 (the inherited listener fd) and the default policyd socket.\n\
        agent-sandbox-syscall-broker --listener-fd 4\n\n\
        # Tag the session for policy routing and watch the child pid for early exit.\n\
        agent-sandbox-syscall-broker \\\n\
            --listener-fd 4 \\\n\
            --sandbox-session-id session-2024-05-01-abc \
            --child-pid 12345"
)]
struct Cli {
    /// Inherited seccomp user-notification file descriptor. The arm uses `SCM_RIGHTS` to pass this fd across exec. The broker sets it non-blocking and loops on `SECCOMP_IOCTL_NOTIF_RECV`.
    #[arg(long, value_name = "FD")]
    listener_fd: i32,
    /// Path to the policyd Unix domain socket. Used to ask policyd for the verdict on each notified syscall.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    policy_socket: PathBuf,
    /// Sandbox session id forwarded to policyd so per-session rules and audit logs are routed correctly. Falls back to the env var `AGENT_SANDBOX_SESSION_ID` if unset.
    #[arg(long, value_name = "ID")]
    sandbox_session_id: Option<String>,
    /// Max seconds to wait for a policyd verdict per notified syscall. Fractional values are accepted. The effective wait is clamped to at least 1 second. Larger values tolerate slow policyd startups but delay the sandboxed syscall.
    #[arg(long, value_name = "SECONDS", default_value_t = 305.0)]
    policy_timeout: f64,
    /// PID of the immediate child the broker is supervising. When the child exits the broker exits too and the seccomp listener is closed. Optional: omit for a broker that runs until its listener fd is revoked.
    #[arg(long, value_name = "PID")]
    child_pid: Option<i32>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sandbox_syscall_broker=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    set_nonblocking(cli.listener_fd)?;
    let timeout = Duration::from_secs_f64(cli.policy_timeout.max(1.0));
    loop {
        if child_exited(cli.child_pid) {
            return Ok(());
        }
        let notif = match recv_notification(cli.listener_fd) {
            Ok(notif) => notif,
            Err(err) => match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {
                    time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Some(libc::ENOENT) => {
                    // The seccomp listener fd is invalid; the task that
                    // installed the filter is gone. Exiting avoids a noisy
                    // log race against waitpid, which may not yet observe
                    // the exit.
                    return Ok(());
                }
                _ => {
                    if child_exited(cli.child_pid) {
                        return Ok(());
                    }
                    warn!(error = %err, "seccomp notification receive failed");
                    time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let allowed = match target_from_notification(&notif) {
            Ok(Some(target)) => {
                check_target(
                    &cli.policy_socket,
                    &target,
                    cli.sandbox_session_id.clone(),
                    notif.pid,
                    timeout,
                )
                .await
            }
            Ok(None) => {
                debug!(syscall = notif.data.nr, "continuing non-network syscall");
                true
            }
            Err(err) => {
                warn!(error = %err, syscall = notif.data.nr, "failed to parse syscall target");
                false
            }
        };

        let result = if allowed {
            send_continue(cli.listener_fd, notif.id)
        } else {
            send_errno(cli.listener_fd, notif.id, libc::EACCES)
        };
        if let Err(err) = result {
            warn!(error = %err, "seccomp notification response failed");
        }
    }
}

fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn child_exited(child_pid: Option<i32>) -> bool {
    let Some(pid) = child_pid else {
        return false;
    };
    let mut status = 0;
    let rc = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
    rc == pid
}
