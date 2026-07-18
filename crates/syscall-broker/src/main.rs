pub(crate) mod decision;
pub(crate) mod dispatch;

use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_sandbox_core::{InodeIdentity, ResourceKind};
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    PersistentPolicyClient, ResourceTarget, SeccompNotif, parse_network_mode, recv_notification,
    send_addfd, send_continue, send_errno, send_result,
};
use agent_sandbox_sysutil::{connect_raw, sendmsg_raw, sendto_raw, set_raw_fd_nonblocking};
use clap::Parser;
use tokio::time;
use tracing::{debug, info, warn};

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
    /// Trusted network mediation mode. `direct` keeps transport policy RPC
    /// checks; `proxy` delegates Internet transport to the transparent proxy.
    /// If omitted, `AGENT_SANDBOX_NETWORK_MODE` is consulted and missing or
    /// unknown values fail closed at startup.
    #[arg(long, value_name = "MODE")]
    network_mode: Option<String>,

    /// Trusted DNS forwarder endpoint inside the sandbox network namespace.
    /// Only this exact TCP/UDP endpoint bypasses transport policy. If omitted,
    /// `AGENT_SANDBOX_DNS_ENDPOINT` is consulted.
    #[arg(long, value_name = "IP:PORT")]
    dns_endpoint: Option<SocketAddr>,

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
    let network_mode_value = cli
        .network_mode
        .or_else(|| std::env::var("AGENT_SANDBOX_NETWORK_MODE").ok());
    let network_mode =
        parse_network_mode(network_mode_value.as_deref()).map_err(std::io::Error::other)?;
    let dns_endpoint = if let Some(endpoint) = cli.dns_endpoint {
        Some(endpoint)
    } else {
        match std::env::var("AGENT_SANDBOX_DNS_ENDPOINT") {
            Ok(value) => Some(value.parse().map_err(std::io::Error::other)?),
            Err(std::env::VarError::NotPresent) => None,
            Err(err) => return Err(std::io::Error::other(err)),
        }
    };
    set_raw_fd_nonblocking(cli.listener_fd)?;
    let timeout = Duration::from_secs_f64(cli.policy_timeout.max(1.0));

    let policy_client = PersistentPolicyClient::new(cli.policy_socket.clone());

    // Don't SIGCONT the child until the broker is inside its notification
    // loop and ready to receive. The child traps from the first openat onward
    // (dynamic linker), and if the kernel finds a USER_NOTIF filter with no
    // listener-fd holder, it returns ENOSYS to the tracee. We set a flag and
    // SIGCONT on the first loop iteration.
    let mut child_was_resumed = false;

    loop {
        propagate_child_exit(cli.child_pid);
        if !child_was_resumed {
            if let Some(pid) = cli.child_pid {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGCONT,
                );
                debug!(child_pid = pid, "resumed sandboxed child");
            }
            child_was_resumed = true;
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
                    // NOTIF_RECV returned ENOENT because a pending notification
                    // was withdrawn (the tracee thread that triggered it was
                    // killed by a signal before the broker could process it).
                    // This is a transient per-notification condition, not a
                    // listener-fd failure. We must NOT exit here: the child
                    // process (omp's main thread) is still alive and will
                    // generate more notifications. Exiting would close the
                    // listener fd, turning every future trap into ENOSYS for
                    // the still-alive child.
                    //
                    // If the child has truly exited, propagate_child_exit() above
                    // propagates its status. Brief backoff so a signal-storm won't
                    // spin the loop.
                    debug!("notification withdrawn before processing");
                    time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
                _ => {
                    propagate_child_exit(cli.child_pid);
                    warn!(error = %err, "seccomp notification receive failed");
                    time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        dispatch::dispatch_notification_with_mode(
            &cli.policy_socket,
            &policy_client,
            cli.sandbox_session_id.as_deref(),
            cli.listener_fd,
            &notif,
            timeout,
            dispatch::NetworkPolicyBypass {
                mode: network_mode,
                dns_endpoint,
            },
        )
        .await;
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

fn propagate_child_exit(child_pid: Option<i32>) {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::Pid;
    let Some(pid) = child_pid else {
        return;
    };
    match waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::Exited(_, code)) => std::process::exit(code),
        Ok(WaitStatus::Signaled(_, signal, _)) => {
            std::process::exit(128 + signal as i32);
        }
        _ => {}
    }
}

/// Return true if the target is a connect to the broker's own policyd
/// socket. These connects are infrastructure traffic from fs-arm (which
/// runs under the seccomp filter), not agent actions, and should not
/// prompt. The policy socket is `--ro-bind`'d into the sandbox, so the
/// agent cannot impersonate it. The broker issues `CONTINUE` so the tracee
/// completes the paused `connect()` with frozen args (TOCTOU-safe) and
/// policyd observes the tracee pid on `SO_PEERCRED`.
///
/// Compares by inode and device, not path, to defeat hardlink aliases:
/// `link(policy_sock, ~/evil.sock)` creates a second path to the same
/// socket inode. A path comparison would miss the alias and prompt the
/// user for infrastructure traffic.
fn is_policy_socket_bypass(target: &ResourceTarget, policy_socket: &Path) -> bool {
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
        _ => normalize_path(&target.path) == normalize_path(policy_socket),
    }
}

/// Canonicalize a path for comparison, resolving symlinks. Falls back to
/// the original path if canonicalization fails (socket not yet created).
fn normalize_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Emulate a policy-allowed resource syscall on behalf of the tracee. Never
/// calls `send_continue`: the broker completes the syscall itself and injects
/// the result, so the tracee never touches the gated resource directly.
///
/// For Unix-socket `connect`/`sendto`/`sendmsg`/`sendmmsg`: duplicate the
/// tracee's socket fd via `pidfd_getfd`, perform the syscall in the broker's
/// own fd table, and inject the return value with `send_result`. For device
/// `open*`: open the device in the broker and install the fd into the tracee
/// with `send_addfd`.
///
/// # Errors
///
/// Returns an error if any fd duplication, syscall, or ioctls fail.
fn emulate_resource(
    listener_fd: i32,
    notif: &SeccompNotif,
    target: &ResourceTarget,
) -> std::io::Result<()> {
    match target.kind {
        ResourceKind::UnixSocket => emulate_unix_socket(listener_fd, notif, target),
        ResourceKind::Device => emulate_device_open(listener_fd, notif, target),
    }
}

/// Emulate a `connect`/`sendto`/`sendmsg`/`sendmmsg` on a Unix-domain socket
/// the tracee already holds open. The broker duplicates the tracee's socket
/// fd, performs the syscall with the tracee's args, and injects the return
/// value. For `sendmsg` with a null `msg_name` (already-connected socket),
/// the broker continues the syscall because there is no destination to
/// emulate against. For `sendmsg` with control data (e.g. `SCM_RIGHTS`),
/// the broker denies it with `EACCES` because it cannot safely relay
/// ancillary data across the pidfd boundary.
fn emulate_unix_socket(
    listener_fd: i32,
    notif: &SeccompNotif,
    target: &ResourceTarget,
) -> std::io::Result<()> {
    let nr_val = i64::from(notif.data.nr);
    let sockfd = i32::try_from(notif.data.args[0]).unwrap_or(-1);
    if sockfd < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid sockfd in notification",
        ));
    }
    let dup = agent_sandbox_sysutil::dup_tracee_fd(notif.pid, sockfd)?;

    match nr_val {
        nr::CONNECT => {
            // Use the captured raw sockaddr from policy parsing, never
            // re-read the tracee pointer. This prevents a TOCTOU where the
            // tracee swaps the sockaddr between approval and emulation.
            if target.raw.is_empty() {
                return send_continue(listener_fd, notif.id);
            }
            match connect_raw(&dup, &target.raw) {
                Ok(()) => send_result(listener_fd, notif.id, 0),
                Err(err) => {
                    let errno = err.raw_os_error().unwrap_or(libc::EACCES);
                    send_errno(listener_fd, notif.id, errno)
                }
            }
        }
        nr::SENDTO => enhance_sendto_emulation(listener_fd, notif, &dup, target),
        nr::SENDMSG => enhance_sendmsg_emulation(listener_fd, notif, &dup, target),
        nr::SENDMMSG => {
            // For connected SOCK_STREAM / SOCK_SEQPACKET, the kernel ignores
            // per-message msg_name, so the destination is fixed by the prior
            // approved connect. CONTINUE is safe. For datagrams or
            // unconnected sockets, deny: multi-message emulation is not
            // supported and CONTINUE would allow a TOCTOU on the destination.
            if matches!(
                agent_sandbox_sysutil::socket_type(dup.as_fd()),
                Some(libc::SOCK_STREAM | libc::SOCK_SEQPACKET)
            ) && agent_sandbox_sysutil::is_socket_connected(dup.as_fd())
            {
                return send_continue(listener_fd, notif.id);
            }
            info!("sendmmsg on AF_UNIX denied: multi-message emulation not supported");
            send_errno(listener_fd, notif.id, libc::EACCES)
        }
        _ => {
            // Unknown socket syscall, deny to be safe.
            send_errno(listener_fd, notif.id, libc::EACCES)
        }
    }
}

/// Emulate `sendto(sockfd, buf, len, flags, dest_addr, addrlen)` on a
/// duplicated tracee socket. If `dest_addr` is null the socket is already
/// connected and we continue. Otherwise we re-read the sockaddr and call
/// sendto from the broker.
fn enhance_sendto_emulation(
    listener_fd: i32,
    notif: &SeccompNotif,
    dup: &OwnedFd,
    target: &ResourceTarget,
) -> std::io::Result<()> {
    const MAX_PAYLOAD: usize = 1024 * 1024;
    let buf_ptr = notif.data.args[1];
    let len = usize::try_from(notif.data.args[2]).unwrap_or(0);
    let flags = i32::try_from(notif.data.args[3]).unwrap_or(0);
    // For a resource target, the destination was non-null when approved.
    // Use target.raw unconditionally: if it is empty, something is wrong
    // and we deny rather than CONTINUE (which would bypass the resource gate).
    if target.raw.is_empty() {
        return send_errno(listener_fd, notif.id, libc::EACCES);
    }
    // Copy the payload from the tracee's address space into a broker-owned
    // buffer. The user namespace does NOT share the address space, so tracee
    // pointers are invalid in the broker.
    if len > MAX_PAYLOAD {
        return send_errno(listener_fd, notif.id, libc::E2BIG);
    }
    let payload =
        agent_sandbox_syscall_broker::read_tracee_bytes(notif.pid, buf_ptr, len.min(MAX_PAYLOAD))?;
    let sent = match sendto_raw(dup, &payload, flags, &target.raw) {
        Ok(n) => n,
        Err(err) => {
            let errno = err.raw_os_error().unwrap_or(libc::EACCES);
            return send_errno(listener_fd, notif.id, errno);
        }
    };
    send_result(listener_fd, notif.id, i64::try_from(sent).unwrap_or(0))
}
/// Emulate `sendmsg(sockfd, msg, flags)` on a duplicated tracee socket.
/// If `msg` is null or `msg_name` is null the socket is already connected
/// and the broker continues. If the `msghdr` carries control data
/// (`msg_control != NULL && msg_controllen > 0`) the broker denies the
/// syscall with `EACCES` because it cannot safely relay ancillary data
/// (e.g. `SCM_RIGHTS` fd passing) across the pidfd boundary.
fn enhance_sendmsg_emulation(
    listener_fd: i32,
    notif: &SeccompNotif,
    dup: &OwnedFd,
    target: &ResourceTarget,
) -> std::io::Result<()> {
    const MAX_PAYLOAD: usize = 1024 * 1024;
    let msg_ptr = notif.data.args[1];
    let flags = i32::try_from(notif.data.args[2]).unwrap_or(0);
    if msg_ptr == 0 {
        return send_continue(listener_fd, notif.id);
    }
    // Connected SOCK_STREAM / SOCK_SEQPACKET sockets: the kernel ignores
    // msg_name, so the destination is fixed by the prior approved connect.
    // CONTINUE is safe because the tracee cannot redirect the destination.
    // This covers the common case of sendmsg with SCM_RIGHTS on a connected
    // stream socket (D-Bus, Wayland fd passing).
    if matches!(
        agent_sandbox_sysutil::socket_type(dup.as_fd()),
        Some(libc::SOCK_STREAM | libc::SOCK_SEQPACKET)
    ) && agent_sandbox_sysutil::is_socket_connected(dup.as_fd())
    {
        return send_continue(listener_fd, notif.id);
    }
    // Read the msghdr to check for control data and find iovec locations.
    // The destination sockaddr is NOT re-read: use target.raw (captured
    // during policy parsing) to prevent a TOCTOU swap.
    let bytes = agent_sandbox_syscall_broker::read_tracee_bytes(notif.pid, msg_ptr, 56)?;
    if bytes.len() < 56 {
        return send_errno(listener_fd, notif.id, libc::EINVAL);
    }
    // For a resource target, the destination was non-null when approved.
    // Use target.raw unconditionally: if empty, deny rather than CONTINUE.
    if target.raw.is_empty() {
        return send_errno(listener_fd, notif.id, libc::EACCES);
    }
    let msg_control = u64::from_ne_bytes(bytes[32..40].try_into().expect("8 bytes"));
    let msg_controllen = u64::from_ne_bytes(bytes[40..48].try_into().expect("8 bytes"));
    if msg_control != 0 && msg_controllen != 0 {
        // Control data present (SCM_RIGHTS, SCM_CREDENTIALS, etc.). The
        // broker cannot safely relay ancillary data, so deny.
        info!("sendmsg with control data denied");
        return send_errno(listener_fd, notif.id, libc::EACCES);
    }
    let msg_iov = u64::from_ne_bytes(bytes[16..24].try_into().expect("8 bytes"));
    let msg_iovlen = u64::from_ne_bytes(bytes[24..32].try_into().expect("8 bytes"));
    // Copy each iovec's payload from the tracee into broker-owned buffers.
    let iov_count = msg_iovlen.min(1024) as usize;
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(iov_count);
    let mut total: usize = 0;
    for i in 0..iov_count {
        let iov_offset = i * 16;
        let iov_buf = agent_sandbox_syscall_broker::read_tracee_bytes(
            notif.pid,
            msg_iov + iov_offset as u64,
            16,
        )?;
        if iov_buf.len() < 16 {
            return send_errno(listener_fd, notif.id, libc::EINVAL);
        }
        let iov_base = u64::from_ne_bytes(iov_buf[0..8].try_into().expect("8 bytes"));
        let iov_len = u64::from_ne_bytes(iov_buf[8..16].try_into().expect("8 bytes"));
        if iov_len == 0 {
            payloads.push(Vec::new());
            continue;
        }
        let iov_len_usize = usize::try_from(iov_len).unwrap_or(0);
        total = total.saturating_add(iov_len_usize);
        if total > MAX_PAYLOAD {
            return send_errno(listener_fd, notif.id, libc::E2BIG);
        }
        let payload =
            agent_sandbox_syscall_broker::read_tracee_bytes(notif.pid, iov_base, iov_len_usize)?;
        payloads.push(payload);
    }
    // Build broker-owned iovec array pointing into our payloads.
    let mut iovs: Vec<libc::iovec> = payloads
        .iter_mut()
        .map(|buf| libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        })
        .collect();
    // Build a broker-owned msghdr. Use target.raw as the destination
    // sockaddr, never re-read the tracee pointer.
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: iovs.as_mut_ptr(),
        msg_iovlen: iovs.len(),
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    if !target.raw.is_empty() {
        msg.msg_name = target.raw.as_ptr().cast::<libc::c_void>().cast_mut();
        msg.msg_namelen = u32::try_from(target.raw.len()).unwrap_or(u32::MAX);
    }
    // SAFETY: `msg` is a broker-owned msghdr with iovecs and a captured
    // sockaddr. All pointers are valid for the kernel call.
    #[allow(unsafe_code)]
    let rc = match unsafe { sendmsg_raw(dup, &msg, flags) } {
        Ok(n) => n,
        Err(err) => {
            let errno = err.raw_os_error().unwrap_or(libc::EACCES);
            return send_errno(listener_fd, notif.id, errno);
        }
    };
    send_result(listener_fd, notif.id, i64::try_from(rc).unwrap_or(0))
}

/// Emulate `open`/`openat`/`openat2`/`creat` using captured path and flags.
/// Installs the resulting fd into the tracee via `NOTIF_ADDFD` so the tracee
/// never re-runs the syscall with live pointer args.
/// Emulate `open`/`openat`/`openat2`/`creat` of a policy-allowed device by
/// opening the device in the broker's own fd table and installing that fd
/// into the tracee via `SECCOMP_IOCTL_NOTIF_ADDFD` with
/// `SECCOMP_ADDFD_FLAG_SEND`. This atomically delivers the fd and completes
/// the notification, so no follow-up `SECCOMP_IOCTL_NOTIF_SEND` is needed.
/// The `cloexec` flag is propagated from the tracee's requested `O_CLOEXEC`.
fn emulate_device_open(
    listener_fd: i32,
    notif: &SeccompNotif,
    target: &ResourceTarget,
) -> std::io::Result<()> {
    emulate_open_with_path(
        listener_fd,
        notif.id,
        &target.raw,
        target.open_flags,
        target.open_mode,
    )
}

fn emulate_open_with_path(
    listener_fd: i32,
    notif_id: u64,
    raw_path: &[u8],
    flags: i32,
    mode: u32,
) -> std::io::Result<()> {
    let path = std::str::from_utf8(raw_path)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8 path"))?;
    let oflag = nix::fcntl::OFlag::from_bits_truncate(flags);
    let mode = nix::sys::stat::Mode::from_bits_truncate(mode);
    let opened = match nix::fcntl::open(path, oflag, mode) {
        Ok(fd) => fd,
        Err(err) => {
            let errno = err as i32;
            return send_errno(listener_fd, notif_id, errno);
        }
    };
    let cloexec = oflag.contains(nix::fcntl::OFlag::O_CLOEXEC);
    // `opened` (OwnedFd) closes on drop after the fd is installed into the
    // tracee via SECCOMP_IOCTL_NOTIF_ADDFD.
    send_addfd(listener_fd, notif_id, opened.as_raw_fd(), cloexec)
}

#[cfg(test)]
mod tests {
    use super::is_policy_socket_bypass;
    use agent_sandbox_core::{ResourceAccess, ResourceKind};
    use agent_sandbox_syscall_broker::ResourceTarget;
    use std::path::{Path, PathBuf};

    fn make_unix_target(path: &str) -> ResourceTarget {
        ResourceTarget {
            kind: ResourceKind::UnixSocket,
            path: PathBuf::from(path),
            access: ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
            raw: path.as_bytes().to_vec(),
            open_flags: 0,
            open_mode: 0,
        }
    }

    #[test]
    fn is_socket_connected_detects_connected_stream() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        let fds = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair failed");
        assert!(
            agent_sandbox_sysutil::is_socket_connected(&fds.0),
            "socketpair fd should be connected"
        );
        assert!(
            agent_sandbox_sysutil::is_socket_connected(&fds.1),
            "socketpair fd should be connected"
        );
    }

    #[test]
    fn is_socket_connected_rejects_unconnected_dgram() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
        let fd = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .expect("socket creation failed");
        assert!(
            !agent_sandbox_sysutil::is_socket_connected(&fd),
            "unconnected dgram should report not connected"
        );
    }

    #[test]
    fn socket_type_reads_stream() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        let fds = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair failed");
        assert_eq!(
            agent_sandbox_sysutil::socket_type(&fds.0),
            Some(libc::SOCK_STREAM)
        );
    }

    #[test]
    fn socket_type_reads_dgram() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
        let fd = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .expect("socket creation failed");
        assert_eq!(
            agent_sandbox_sysutil::socket_type(&fd),
            Some(libc::SOCK_DGRAM)
        );
    }

    #[test]
    fn policy_socket_bypass_matches_exact_path() {
        let target = make_unix_target("/run/agent-sandbox/policy.sock");
        assert!(is_policy_socket_bypass(
            &target,
            Path::new("/run/agent-sandbox/policy.sock")
        ));
    }

    #[test]
    fn policy_socket_bypass_rejects_other_paths() {
        let target = make_unix_target("/run/user/1000/op-daemon.sock");
        assert!(!is_policy_socket_bypass(
            &target,
            Path::new("/run/agent-sandbox/policy.sock")
        ));
    }

    #[test]
    fn policy_socket_bypass_rejects_device_kind() {
        let target = ResourceTarget {
            kind: ResourceKind::Device,
            path: PathBuf::from("/run/agent-sandbox/policy.sock"),
            access: ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Read),
            raw: b"/run/agent-sandbox/policy.sock".to_vec(),
            open_flags: 0,
            open_mode: 0,
        };
        assert!(!is_policy_socket_bypass(
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
            is_policy_socket_bypass(&target, &orig),
            "hardlink to policy socket should be detected via inode comparison"
        );

        let _ = std::fs::remove_file(&orig);
        let _ = std::fs::remove_file(&alias);
    }
}
