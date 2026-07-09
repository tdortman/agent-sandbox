use std::path::Path;
use std::time::Duration;

use agent_sandbox_core::ResourceKind;
use agent_sandbox_syscall_broker::{
    FilesystemTarget, NetworkTarget, ResourceTarget, SeccompNotif, SyscallTarget, check_filesystem,
    check_resource, check_target, is_transient_tracee_io_err, notification_arch_valid,
    revalidate_filesystem_mutation, send_continue, send_errno, target_from_notification,
};
use tracing::{debug, info, warn};

pub async fn dispatch_notification(
    policy_socket: &Path,
    sandbox_session_id: Option<&str>,
    listener_fd: i32,
    notif: &SeccompNotif,
    timeout: Duration,
) {
    if !notification_arch_valid(notif) {
        warn!(
            arch = notif.data.arch,
            native = agent_sandbox_syscall::policy::AUDIT_ARCH_NATIVE,
            "seccomp notification arch mismatch; denying"
        );
        super::log_notification_response(send_errno(listener_fd, notif.id, libc::EACCES));
        return;
    }
    match target_from_notification(notif) {
        Ok(Some(SyscallTarget::Network(target))) => {
            dispatch_network_target(
                policy_socket,
                sandbox_session_id,
                listener_fd,
                notif,
                &target,
                timeout,
            )
            .await;
        }
        Ok(Some(SyscallTarget::Resource(target))) => {
            dispatch_resource_target(
                policy_socket,
                sandbox_session_id,
                listener_fd,
                notif,
                &target,
                timeout,
            )
            .await;
        }
        Ok(Some(SyscallTarget::Filesystem(target))) => {
            if let Err(err) = dispatch_filesystem_target(
                policy_socket,
                sandbox_session_id,
                listener_fd,
                notif,
                &target,
                timeout,
            )
            .await
            {
                warn!(error = %err, target = ?target, "filesystem dispatch failed");
                let _ = send_errno(listener_fd, notif.id, libc::EACCES);
            }
        }
        Ok(Some(SyscallTarget::Errno(errno))) => {
            if super::is_open_family_syscall(notif.data.nr) {
                tracing::info!(
                    syscall = notif.data.nr,
                    errno,
                    pid = notif.pid,
                    "denying open-family syscall before fanotify"
                );
            } else {
                debug!(syscall = notif.data.nr, errno, "denying syscall with errno");
            }
            super::log_notification_response(send_errno(listener_fd, notif.id, errno));
        }
        Ok(Some(SyscallTarget::None) | None) => {
            debug!(syscall = notif.data.nr, "continuing non-gated syscall");
            if let Err(err) = send_continue(listener_fd, notif.id) {
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
                super::log_notification_response(send_continue(listener_fd, notif.id));
            } else if super::is_open_family_syscall(notif.data.nr) {
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
                let _ = send_errno(listener_fd, notif.id, libc::EACCES);
            }
        }
    }
}

async fn dispatch_network_target(
    policy_socket: &Path,
    sandbox_session_id: Option<&str>,
    listener_fd: i32,
    notif: &SeccompNotif,
    target: &NetworkTarget,
    timeout: Duration,
) {
    let allowed = check_target(
        policy_socket,
        target,
        sandbox_session_id.map(str::to_owned),
        notif.pid,
        timeout,
    )
    .await;
    let result = if allowed {
        send_continue(listener_fd, notif.id)
    } else {
        debug!(target = ?target, "network check denied");
        send_errno(listener_fd, notif.id, libc::EACCES)
    };
    super::log_notification_response(result);
}

async fn dispatch_resource_target(
    policy_socket: &Path,
    sandbox_session_id: Option<&str>,
    listener_fd: i32,
    notif: &SeccompNotif,
    target: &ResourceTarget,
    timeout: Duration,
) {
    if super::is_policy_socket_bypass(target, policy_socket) {
        debug!(target = ?target, "bypassing policy socket (infrastructure connect)");
        super::log_notification_response(send_continue(listener_fd, notif.id));
        return;
    }
    let reply = match check_resource(
        policy_socket,
        target,
        sandbox_session_id.map(str::to_owned),
        notif.pid,
        timeout,
    )
    .await
    {
        Ok(reply) => reply,
        Err(err) => {
            warn!(error = %err, target = ?target, "resource check RPC failed");
            let _ = send_errno(listener_fd, notif.id, libc::EACCES);
            return;
        }
    };
    if !reply.allowed {
        if matches!(target.kind, ResourceKind::Device) {
            info!(
                path = %target.path.display(),
                source = %reply.source,
                pid = notif.pid,
                "device open denied in syscall broker before fanotify"
            );
        } else {
            debug!(target = ?target, source = %reply.source, "resource check denied");
        }
        let _ = send_errno(listener_fd, notif.id, libc::EACCES);
        return;
    }
    if let Err(err) = super::emulate_resource(listener_fd, notif, target) {
        let errno = err.raw_os_error().unwrap_or(libc::EACCES);
        if matches!(target.kind, ResourceKind::Device) {
            info!(
                error = %err,
                errno,
                path = %target.path.display(),
                pid = notif.pid,
                "device open emulation failed in syscall broker before fanotify"
            );
        } else {
            debug!(error = %err, errno, target = ?target, "resource emulation failed");
        }
        let _ = send_errno(listener_fd, notif.id, errno);
    }
}

async fn dispatch_filesystem_target(
    policy_socket: &Path,
    sandbox_session_id: Option<&str>,
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
            sandbox_session_id.map(str::to_owned),
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
