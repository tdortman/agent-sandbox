use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_sandbox_core::{InodeIdentity, ResourceKind};
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    FilesystemTarget, NetworkTarget, ResourceTarget, SeccompNotif, SyscallTarget, check_filesystem,
    check_resource, check_target, is_transient_tracee_io_err, notification_arch_valid,
    recv_notification, revalidate_filesystem_mutation, send_addfd, send_continue, send_errno,
    send_result, target_from_notification,
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
    set_raw_fd_nonblocking(cli.listener_fd)?;
    // The syscall-arm SIGSTOPs the child before exec'ing the command so the
    // broker can acquire the listener fd via pidfd_getfd. Now that the
    // listener is set up and nonblocking, resume the child so it starts
    // executing and generating seccomp notifications.
    if let Some(pid) = cli.child_pid {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGCONT,
        );
    }

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
        dispatch_notification(&cli, &notif, timeout).await;
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

/// Dispatch a single seccomp notification: classify the target, check
/// policy, and emulate/deny/continue as appropriate. Extracted from
/// `main` to keep the loop body readable.
async fn dispatch_notification(cli: &Cli, notif: &SeccompNotif, timeout: Duration) {
    if !notification_arch_valid(notif) {
        warn!(
            arch = notif.data.arch,
            native = agent_sandbox_syscall::policy::AUDIT_ARCH_NATIVE,
            "seccomp notification arch mismatch; denying"
        );
        log_notification_response(send_errno(cli.listener_fd, notif.id, libc::EACCES));
        return;
    }
    match target_from_notification(notif) {
        Ok(Some(SyscallTarget::Network(target))) => {
            dispatch_network_target(cli, notif, &target, timeout).await;
        }
        Ok(Some(SyscallTarget::Resource(target))) => {
            dispatch_resource_target(cli, notif, &target, timeout).await;
        }
        Ok(Some(SyscallTarget::Filesystem(target))) => {
            if let Err(err) = dispatch_filesystem_target(
                &cli.policy_socket,
                cli.sandbox_session_id.clone(),
                cli.listener_fd,
                notif,
                &target,
                timeout,
            )
            .await
            {
                warn!(error = %err, target = ?target, "filesystem dispatch failed");
                let _ = send_errno(cli.listener_fd, notif.id, libc::EACCES);
            }
        }
        Ok(Some(SyscallTarget::Errno(errno))) => {
            if is_open_family_syscall(notif.data.nr) {
                tracing::info!(
                    syscall = notif.data.nr,
                    errno,
                    pid = notif.pid,
                    "denying open-family syscall before fanotify"
                );
            } else {
                debug!(syscall = notif.data.nr, errno, "denying syscall with errno");
            }
            log_notification_response(send_errno(cli.listener_fd, notif.id, errno));
        }
        Ok(Some(SyscallTarget::None) | None) => {
            debug!(syscall = notif.data.nr, "continuing non-gated syscall");
            if let Err(err) = send_continue(cli.listener_fd, notif.id) {
                if err.raw_os_error() == Some(libc::ENOENT) {
                    debug!(error = %err, "seccomp notification response failed");
                } else {
                    warn!(error = %err, "seccomp notification response failed");
                }
            }
        }
        Err(err) => {
            if is_transient_tracee_io_err(&err) {
                debug!(
                    error = %err,
                    syscall = notif.data.nr,
                    pid = notif.pid,
                    "could not read tracee syscall args; continuing"
                );
                log_notification_response(send_continue(cli.listener_fd, notif.id));
            } else if is_open_family_syscall(notif.data.nr) {
                tracing::info!(
                    error = %err,
                    syscall = notif.data.nr,
                    pid = notif.pid,
                    "failed to classify open-family syscall; denying before fanotify"
                );
            } else {
                warn!(error = %err, syscall = notif.data.nr, pid = notif.pid, "failed to parse syscall target");
            }
            if !is_transient_tracee_io_err(&err) {
                let _ = send_errno(cli.listener_fd, notif.id, libc::EACCES);
            }
        }
    }
}

fn is_open_family_syscall(nr: i32) -> bool {
    matches!(
        i64::from(nr),
        nr::OPEN | nr::OPENAT | nr::OPENAT2 | nr::CREAT
    )
}

async fn dispatch_network_target(
    cli: &Cli,
    notif: &SeccompNotif,
    target: &NetworkTarget,
    timeout: Duration,
) {
    let allowed = check_target(
        &cli.policy_socket,
        target,
        cli.sandbox_session_id.clone(),
        notif.pid,
        timeout,
    )
    .await;
    let result = if allowed {
        send_continue(cli.listener_fd, notif.id)
    } else {
        debug!(target = ?target, "network check denied");
        send_errno(cli.listener_fd, notif.id, libc::EACCES)
    };
    if let Err(err) = result {
        if err.raw_os_error() == Some(libc::ENOENT) {
            debug!(error = %err, "seccomp notification response failed");
        } else {
            warn!(error = %err, "seccomp notification response failed");
        }
    }
}

async fn dispatch_resource_target(
    cli: &Cli,
    notif: &SeccompNotif,
    target: &ResourceTarget,
    timeout: Duration,
) {
    if is_policy_socket_bypass(target, &cli.policy_socket) {
        debug!(target = ?target, "bypassing policy socket (infrastructure connect)");
        // Let the tracee complete the paused connect() itself. The sockaddr
        // args are frozen for the duration of the seccomp notification, so
        // this is TOCTOU-safe. Emulating the connect in the broker process
        // would make policyd see the broker's pid on SO_PEERCRED instead of
        // the tracee's, breaking fsmon pid routing and RPC context.
        log_notification_response(send_continue(cli.listener_fd, notif.id));
        return;
    }
    let reply = match check_resource(
        &cli.policy_socket,
        target,
        cli.sandbox_session_id.clone(),
        notif.pid,
        timeout,
    )
    .await
    {
        Ok(reply) => reply,
        Err(err) => {
            warn!(error = %err, target = ?target, "resource check RPC failed");
            let _ = send_errno(cli.listener_fd, notif.id, libc::EACCES);
            return;
        }
    };
    if !reply.allowed {
        if matches!(target.kind, ResourceKind::Device) {
            tracing::info!(
                path = %target.path.display(),
                source = %reply.source,
                pid = notif.pid,
                "device open denied in syscall broker before fanotify"
            );
        } else {
            debug!(target = ?target, source = %reply.source, "resource check denied");
        }
        let _ = send_errno(cli.listener_fd, notif.id, libc::EACCES);
        return;
    }
    if let Err(err) = emulate_resource(cli.listener_fd, notif, target) {
        let errno = err.raw_os_error().unwrap_or(libc::EACCES);
        if matches!(target.kind, ResourceKind::Device) {
            tracing::info!(
                error = %err,
                errno,
                path = %target.path.display(),
                pid = notif.pid,
                "device open emulation failed in syscall broker before fanotify"
            );
        } else {
            debug!(error = %err, errno, target = ?target, "resource emulation failed");
        }
        let _ = send_errno(cli.listener_fd, notif.id, errno);
    }
}

/// Policy-check every filesystem path/access pair, then continue or deny.
async fn dispatch_filesystem_target(
    policy_socket: &Path,
    sandbox_session_id: Option<String>,
    listener_fd: i32,
    notif: &SeccompNotif,
    target: &FilesystemTarget,
    timeout: Duration,
) -> std::io::Result<()> {
    for (path, access) in &target.checks {
        let reply = check_filesystem(
            policy_socket,
            path,
            *access,
            sandbox_session_id.clone(),
            notif.pid,
            timeout,
        )
        .await?;
        if !reply.allowed {
            debug!(path = %path.display(), ?access, source = %reply.source, "filesystem check denied");
            return send_errno(listener_fd, notif.id, libc::EACCES);
        }
    }
    revalidate_filesystem_mutation(notif, target)?;
    send_continue(listener_fd, notif.id)
}

fn child_exited(child_pid: Option<i32>) -> bool {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::Pid;
    let Some(pid) = child_pid else {
        return false;
    };
    // The original checked `rc == pid` (child reaped). With WNOHANG nix
    // returns StillAlive when the child has not changed state. Any other
    // variant (Exited, Signaled, etc.) means the child has terminated and
    // been reaped.
    matches!(
        waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)),
        Ok(status) if !matches!(status, WaitStatus::StillAlive)
    )
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
            access: ResourceAccess::Connect,
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
            access: ResourceAccess::OpenRead,
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
