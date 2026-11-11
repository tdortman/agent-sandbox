//! seccomp user-notification broker daemon.
//!
//! Intercepts syscalls from a sandboxed process via seccomp's user
//! notification mechanism, forwards them to policyd for a policy verdict, and
//! issues the corresponding allow/deny response or `addfd` injection.

pub(crate) mod decision;

pub(crate) mod dispatch;

pub(crate) mod emulate;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use agent_sandbox_core::{
    FilesystemReplica, InodeIdentity, NetworkOwnership, REFRESH_INTERVAL, ResourceKind,
    SessionExport, session_export_path,
};
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    NetworkMode, PersistentPolicyClient, Resolver, ResourceTarget, recv_notification,
};
use agent_sandbox_sysutil::set_raw_fd_nonblocking;
use clap::Parser;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use tokio::time;
use tracing::{debug, warn};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-syscall-broker",
    version,
    about = "Host-side seccomp user-notification broker for sandboxed agents",
    long_about = r"Runs OUTSIDE the sandbox (typically as the child of `agent-sandbox-syscall-arm`) and consumes the seccomp user-notification file descriptor the arm inherited from its parent.
For each notification the broker asks policyd whether the target syscall is allowed, then writes a `SECCOMP_IOCTL_NOTIF_SEND` continue response with the chosen errno (or success).
Optionally supervises the sandbox child PID and exits when the child does, tearing the listener down with it.

Spawned by policyd, not invoked by hand.

EXAMPLES:
# Run with a 4 (the inherited listener fd) and the default policyd socket.
agent-sandbox-syscall-broker --listener-fd 4

# Tag the session for policy routing and watch the child pid for early exit.
agent-sandbox-syscall-broker \
    --listener-fd 4 \
    --sandbox-session-id session-2024-05-01-abc \
    --child-pid 12345"
)]
struct Cli {
    /// Trusted network mediation mode. `direct` keeps transport policy RPC
    /// checks; `proxy` delegates Internet transport to the transparent proxy.
    /// The value is required; `AGENT_SANDBOX_NETWORK_MODE` is consulted as a
    /// fallback, and missing or unknown values fail closed at startup.
    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        env = "AGENT_SANDBOX_NETWORK_MODE"
    )]
    network_mode: NetworkMode,

    /// Trusted DNS forwarder endpoint inside the sandbox network namespace.
    /// Only this exact TCP/UDP endpoint bypasses transport policy. If omitted,
    /// `AGENT_SANDBOX_DNS_ENDPOINT` is consulted.
    #[arg(long, value_name = "IP:PORT", env = "AGENT_SANDBOX_DNS_ENDPOINT")]
    dns_endpoint: Option<SocketAddr>,

    /// Inherited seccomp user-notification file descriptor. The arm writes
    /// the fd number over a `pipe2(O_CLOEXEC)` pair and re-acquires the fd
    /// via `pidfd_getfd`, then passes it on exec. The broker sets it
    /// non-blocking and loops on `SECCOMP_IOCTL_NOTIF_RECV`.
    #[arg(long, value_name = "FD")]
    listener_fd: i32,

    /// Path to the policyd Unix domain socket. Used to ask policyd for the
    /// verdict on each notified syscall.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    policy_socket: PathBuf,

    /// Sandbox session id forwarded to policyd so per-session rules and audit
    /// logs are routed correctly. Falls back to the env var
    /// `AGENT_SANDBOX_SESSION_ID` if unset.
    #[arg(long, value_name = "ID", env = "AGENT_SANDBOX_SESSION_ID")]
    sandbox_session_id: Option<String>,

    /// Max seconds to wait for a policyd verdict per notified syscall.
    /// Fractional values are accepted. The effective wait is clamped to at
    /// least 1 second. Larger values tolerate slow policyd startups but delay
    /// the sandboxed syscall.
    #[arg(long, value_name = "SECONDS", default_value_t = 305.0)]
    policy_timeout: f64,

    /// PID of the immediate child the broker is supervising. The broker becomes
    /// a child subreaper, so daemons the sandbox double-forks stay its
    /// descendants (and readable under Yama `ptrace_scope=1`). When the child
    /// exits, the broker kills every remaining descendant and exits too,
    /// closing the seccomp listener. Optional: omit for a broker that runs
    /// until its listener fd is revoked.
    #[arg(long, value_name = "PID")]
    child_pid: Option<i32>,
}

/// Maximum concurrent notification consumers. Each owns a policy client and
/// blocks in `SECCOMP_IOCTL_NOTIF_RECV`; the kernel hands each notification
/// to exactly one waiter. Two consumers bound listener contention while
/// keeping policy requests concurrent.
const WORKER_LIMIT: usize = 2;

/// State every broker worker shares.
struct Shared {
    policy_socket: PathBuf,
    local_filesystem: FilesystemReplica,
    resolver: Resolver,
    sandbox_session_id: Option<String>,
    listener_fd: i32,
    timeout: Duration,
    network_policy: dispatch::NetworkPolicyBypass,
    child_pid: Option<i32>,
    child_resumed: AtomicBool,
}

fn main() -> std::io::Result<()> {
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
    // The inherited soft limit is 1024 only for `select(2)` compatibility;
    // the broker polls through epoll and dups tracee fds per notification.
    let (_, nofile_hard) = getrlimit(Resource::RLIMIT_NOFILE)?;
    setrlimit(Resource::RLIMIT_NOFILE, nofile_hard, nofile_hard)?;
    let network_mode = cli.network_mode;
    let dns_endpoint = cli.dns_endpoint;
    set_raw_fd_nonblocking(cli.listener_fd)?;
    if let Some(pid) = cli.child_pid {
        nix::sys::prctl::set_child_subreaper(true)?;
        std::thread::spawn(move || supervise_child(pid));
    }
    let timeout = Duration::from_secs_f64(cli.policy_timeout.max(1.0));

    let project_root = std::env::var("AGENT_SANDBOX_PROJECT_ROOT")
        .ok()
        .map(PathBuf::from);

    // The broker runs as the sandbox user, so it cannot ask policyd for the
    // merged policy; it reads the export policyd keeps for its session in
    // the directory shared with sandboxes, next to the policy socket.
    let export_path = cli
        .sandbox_session_id
        .as_deref()
        .zip(cli.policy_socket.parent())
        .and_then(|(session, shared_dir)| session_export_path(shared_dir, session));

    let local_filesystem = match &export_path {
        Some(path) => FilesystemReplica::fetch(&mut SessionExport::new(path.clone()), project_root),
        None => FilesystemReplica::new(None, SystemTime::now(), project_root),
    };

    let shared = Arc::new(Shared {
        policy_socket: cli.policy_socket.clone(),
        local_filesystem,
        resolver: Resolver::default(),
        sandbox_session_id: cli.sandbox_session_id.clone(),
        listener_fd: cli.listener_fd,
        timeout,
        network_policy: dispatch::NetworkPolicyBypass {
            ownership: NetworkOwnership {
                proxy_mode: network_mode == NetworkMode::Proxy,
                udp_proxy_ports: Vec::new(),
            },
            dns_endpoint,
        },
        child_pid: cli.child_pid,
        child_resumed: AtomicBool::new(false),
    });

    let workers = std::thread::available_parallelism()
        .map_or(1, |parallelism| parallelism.get().min(WORKER_LIMIT))
        .max(1);

    if let Some(path) = export_path {
        let follower = Arc::clone(&shared);
        std::thread::spawn(move || {
            follower.local_filesystem.follow(
                &mut SessionExport::new(path),
                REFRESH_INTERVAL,
                || false,
                || {},
            );
        });
    }

    let mut handles = Vec::with_capacity(workers - 1);
    for _ in 1..workers {
        let shared = Arc::clone(&shared);
        handles.push(std::thread::spawn(move || serve(&shared)));
    }

    let result = serve(&shared);
    for handle in handles {
        let _ = handle.join();
    }
    result
}

/// Serve seccomp notifications. `supervise_child` ends the process.
///
/// # Errors
///
/// Returns an error when the worker runtime or policy client cannot be set up.
fn serve(shared: &Shared) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut policy_client = PersistentPolicyClient::new_trusted(shared.policy_socket.clone());

    loop {
        // Don't SIGCONT the child until the broker is inside its notification
        // loop and ready to receive. The child traps from the first openat
        // onward (dynamic linker), and if the kernel finds a USER_NOTIF filter
        // with no listener-fd holder, it returns ENOSYS to the tracee. The
        // first worker to get here resumes the child, once.
        if !shared.child_resumed.swap(true, Ordering::AcqRel)
            && let Some(pid) = shared.child_pid
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGCONT,
            );

            debug!(child_pid = pid, "resumed sandboxed child");
        }

        let notif = match recv_notification(shared.listener_fd) {
            Ok(notif) => notif,
            Err(err) => match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {
                    runtime.block_on(async { time::sleep(Duration::from_millis(50)).await });
                    continue;
                }
                Some(libc::ENOENT) => {
                    // NOTIF_RECV returned ENOENT because a pending notification
                    // was withdrawn (the tracee thread that triggered it was
                    // killed by a signal before the broker could process it).
                    // This is a transient per-notification condition, not a
                    // listener-fd failure. We must NOT exit here: the child
                    // process (omp's main thread) is still alive and will
                    // generate more notifications. Exiting would close the
                    // listener fd, turning every future trap into ENOSYS for
                    // the still-alive child. `supervise_child` owns exit.
                    // Brief backoff so a signal-storm won't spin the loop.
                    debug!("notification withdrawn before processing");
                    runtime.block_on(async { time::sleep(Duration::from_millis(1)).await });
                    continue;
                }
                _ => {
                    warn!(error = %err, "seccomp notification receive failed");
                    runtime.block_on(async { time::sleep(Duration::from_millis(50)).await });
                    continue;
                }
            },
        };

        runtime.block_on(dispatch::dispatch_notification_with_mode(
            &shared.policy_socket,
            &shared.resolver,
            &mut policy_client,
            &shared.local_filesystem,
            shared.sandbox_session_id.as_deref(),
            shared.listener_fd,
            &notif,
            shared.timeout,
            shared.network_policy.clone(),
        ));
    }
}

fn log_notification_response(result: std::io::Result<()>) {
    if let Err(err) = result {
        if err.raw_os_error() == Some(libc::ENOENT) {
            debug!(error = %err, "seccomp notification response failed");
        } else {
            warn!(error = %err, "seccomp notification response failed");
        }
    }
}

fn is_open_family_syscall(nr: i32) -> bool {
    matches!(
        i64::from(nr),
        nr::OPEN | nr::OPENAT | nr::OPENAT2 | nr::CREAT
    )
}

/// Reap every exit among the broker's children (the supervised child plus the
/// orphans it adopts as subreaper). Runs on its own thread so an idle listener
/// cannot delay it. When the supervised child exits, tear the sandbox instance
/// down and exit with the child's status.
fn supervise_child(pid: i32) -> ! {
    use nix::{
        errno::Errno,
        sys::wait::{WaitStatus, waitpid},
    };

    let code = loop {
        match waitpid(None, None) {
            Ok(WaitStatus::Exited(reaped, code)) if reaped.as_raw() == pid => break code,
            Ok(WaitStatus::Signaled(reaped, signal, _)) if reaped.as_raw() == pid => {
                break 128 + signal as i32;
            }
            // An adopted orphan exited: reaping it is all a subreaper owes it.
            Ok(_) | Err(Errno::EINTR) => {}
            Err(err) => {
                warn!(error = %err, "waiting for the sandboxed child failed");
                break 1;
            }
        }
    };
    kill_descendants();
    std::process::exit(code);
}

/// SIGKILL every remaining descendant. Adopted daemons would otherwise outlive
/// the listener and see `ENOSYS` on every trapped syscall. Killing a child
/// reparents its children to this subreaper, so repeat until none are left.
fn kill_descendants() {
    use nix::{
        errno::Errno,
        sys::{
            signal::{Signal, kill},
            wait::waitpid,
        },
        unistd::Pid,
    };

    loop {
        // Orphans are adopted by whichever broker thread the kernel picks, so
        // every task's `children` list counts.
        for pid in std::fs::read_dir("/proc/self/task")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|task| std::fs::read_to_string(task.path().join("children")).ok())
            .flat_map(|children| {
                children
                    .split_whitespace()
                    .filter_map(|pid| pid.parse().ok())
                    .collect::<Vec<i32>>()
            })
        {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }

        if waitpid(None, None) == Err(Errno::ECHILD) {
            return;
        }
    }
}

/// Return true if the target is a connect to the broker's own policyd
/// socket. These connects are infrastructure traffic from fs-arm (which
/// runs under the seccomp filter), not agent actions, and should not
/// prompt. The broker issues `CONTINUE` so policyd observes the tracee pid
/// on `SO_PEERCRED`. The kernel re-reads the sockaddr after `CONTINUE`; the
/// arm's Landlock floor allows resolving only this socket, so a swapped
/// address cannot reach another one.
///
/// Compares by inode and device, not path, to defeat hardlink aliases:
/// `link(policy_sock, ~/evil.sock)` creates a second path to the same
/// socket inode. A path comparison would miss the alias and prompt the
/// user for infrastructure traffic.
fn is_policy_socket_bypass(
    resolver: &Resolver,
    target: &ResourceTarget,
    policy_socket: &Path,
) -> bool {
    if target.kind != ResourceKind::UnixSocket {
        return false;
    }

    match (
        InodeIdentity::from_path(&target.path),
        InodeIdentity::from_path(policy_socket),
    ) {
        (Some(a), Some(b)) => a == b,

        // Fall back to canonical path comparison if either stat fails
        // (e.g. socket deleted between canonicalize and stat).
        _ => resolver.normalize_path(&target.path) == resolver.normalize_path(policy_socket),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use agent_sandbox_core::{DeviceAccess, ResourceAccess, ResourceKind, SocketAccess};
    use agent_sandbox_syscall_broker::{
        DeviceCapture, Resolver, ResourceCapture, ResourceTarget, UnixCapture,
    };

    use super::is_policy_socket_bypass;

    fn make_unix_target(path: &str) -> ResourceTarget {
        ResourceTarget {
            kind: ResourceKind::UnixSocket,
            path: PathBuf::from(path),
            access: ResourceAccess::Socket(SocketAccess::Connect),
            capture: ResourceCapture::Unix(UnixCapture {
                addr: path.as_bytes().to_vec(),
                pinned: None,
                msghdr: None,
            }),
        }
    }

    #[test]
    fn policy_socket_bypass_matches_exact_path() {
        let target = make_unix_target("/run/agent-sandbox/policy.sock");

        assert!(is_policy_socket_bypass(
            &Resolver::default(),
            &target,
            Path::new("/run/agent-sandbox/policy.sock")
        ));
    }

    #[test]
    fn policy_socket_bypass_rejects_other_paths() {
        let target = make_unix_target("/run/user/1000/op-daemon.sock");

        assert!(!is_policy_socket_bypass(
            &Resolver::default(),
            &target,
            Path::new("/run/agent-sandbox/policy.sock")
        ));
    }

    #[test]
    fn policy_socket_bypass_rejects_device_kind() {
        let pinned = nix::fcntl::open(
            "/dev/null",
            nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("pin device");
        let target = ResourceTarget {
            kind: ResourceKind::Device,
            path: PathBuf::from("/run/agent-sandbox/policy.sock"),
            access: ResourceAccess::Device(DeviceAccess::Read),
            capture: ResourceCapture::Device(DeviceCapture {
                pinned,
                flags: 0,
                mode: 0,
            }),
        };

        assert!(!is_policy_socket_bypass(
            &Resolver::default(),
            &target,
            Path::new("/run/agent-sandbox/policy.sock")
        ));
    }

    #[test]
    fn policy_socket_bypass_detects_hardlink() {
        use std::os::unix::net::UnixListener;

        // Create a real Unix socket, hardlink it, and verify the bypass
        // detects the alias via inode comparison.
        let dir = std::env::temp_dir();

        let orig = dir.join("asbx_bypass_orig.sock");
        let alias = dir.join("asbx_bypass_alias.sock");
        let _ = std::fs::remove_file(&orig);
        let _ = std::fs::remove_file(&alias);
        let _listener = UnixListener::bind(&orig).expect("bind failed");

        // Create hardlink: both paths share the same inode.
        std::fs::hard_link(&orig, &alias).expect("hard_link failed");

        let target = make_unix_target(alias.to_string_lossy().as_ref());

        assert!(
            is_policy_socket_bypass(&Resolver::default(), &target, &orig),
            "hardlink to policy socket should be detected via inode comparison"
        );

        let _ = std::fs::remove_file(&orig);
        let _ = std::fs::remove_file(&alias);
    }

    #[test]
    fn environment_defaults_are_declared_on_cli_arguments() {
        use clap::CommandFactory;

        use super::Cli;

        struct EnvDeclaration {
            argument: &'static str,
            environment: &'static str,
        }

        let command = Cli::command();

        for declaration in [
            EnvDeclaration {
                argument: "network_mode",
                environment: "AGENT_SANDBOX_NETWORK_MODE",
            },
            EnvDeclaration {
                argument: "dns_endpoint",
                environment: "AGENT_SANDBOX_DNS_ENDPOINT",
            },
            EnvDeclaration {
                argument: "sandbox_session_id",
                environment: "AGENT_SANDBOX_SESSION_ID",
            },
        ] {
            let argument = command
                .get_arguments()
                .find(|candidate| candidate.get_id().as_str() == declaration.argument)
                .expect("environment-backed argument should exist");

            assert_eq!(
                argument.get_env().and_then(|value| value.to_str()),
                Some(declaration.environment)
            );
        }
    }
}
