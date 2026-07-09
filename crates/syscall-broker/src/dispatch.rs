use std::path::Path;
use std::time::Duration;

use super::decision::{
    NormalizedNotification, ResponsePlan, RpcPolicyAdapter, decide, normalize_or_failure,
};
use agent_sandbox_core::ResourceKind;
use agent_sandbox_syscall_broker::{
    SeccompNotif, notification_arch_valid, revalidate_filesystem_mutation, send_continue,
    send_errno,
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

    let facts = normalize_or_failure(notif);
    if let NormalizedNotification::ClassificationFailure { error, transient } = &facts {
        if *transient {
            debug!(error = %error, syscall = notif.data.nr, pid = notif.pid, "could not read tracee syscall args; continuing");
        } else if super::is_open_family_syscall(notif.data.nr) {
            info!(error = %error, syscall = notif.data.nr, pid = notif.pid, "failed to classify open-family syscall; denying before fanotify");
        } else {
            warn!(error = %error, syscall = notif.data.nr, pid = notif.pid, "failed to parse syscall target");
        }
    }
    if let NormalizedNotification::Deny { errno } = &facts {
        if super::is_open_family_syscall(notif.data.nr) {
            info!(
                syscall = notif.data.nr,
                errno,
                pid = notif.pid,
                "denying open-family syscall before fanotify"
            );
        } else {
            debug!(syscall = notif.data.nr, errno, "denying syscall with errno");
        }
    }

    let policy_socket_bypass = matches!(
        &facts,
        NormalizedNotification::Target {
            target: agent_sandbox_syscall_broker::SyscallTarget::Resource(target),
        } if super::is_policy_socket_bypass(target, policy_socket)
    );

    let adapter = RpcPolicyAdapter {
        policy_socket,
        sandbox_session_id,
        pid: notif.pid,
        timeout,
    };
    let plan = decide(&adapter, facts).await;
    execute_response_plan(plan, listener_fd, notif, policy_socket_bypass);
}

fn execute_response_plan(
    plan: ResponsePlan,
    listener_fd: i32,
    notif: &SeccompNotif,
    policy_socket_bypass: bool,
) {
    match plan {
        ResponsePlan::Continue => {
            if policy_socket_bypass {
                debug!("bypassing policy socket (infrastructure connect)");
            } else {
                debug!(syscall = notif.data.nr, "continuing non-gated syscall");
            }
            super::log_notification_response(send_continue(listener_fd, notif.id));
        }
        ResponsePlan::DenyErrno { errno } => {
            super::log_notification_response(send_errno(listener_fd, notif.id, errno));
        }
        ResponsePlan::ResourcePolicyDenied {
            target,
            source,
            error,
        } => {
            info!(target = ?target, source = ?source, error = ?error, "resource syscall denied by policy");
            super::log_notification_response(send_errno(listener_fd, notif.id, libc::EACCES));
        }
        ResponsePlan::ResourceRpcFailure { target, error } => {
            warn!(target = ?target, error = %error, "resource policy RPC failed");
            super::log_notification_response(send_errno(listener_fd, notif.id, libc::EACCES));
        }
        ResponsePlan::FilesystemPolicyDenied {
            errno,
            path,
            access,
            source,
            error,
        } => {
            info!(path = %path.display(), access = ?access, source = ?source, error = ?error, "filesystem syscall denied by policy");
            super::log_notification_response(send_errno(listener_fd, notif.id, errno));
        }
        ResponsePlan::FilesystemRpcFailure {
            errno,
            path,
            access,
            error,
        } => {
            warn!(path = %path.display(), access = ?access, error = %error, "filesystem policy RPC failed");
            super::log_notification_response(send_errno(listener_fd, notif.id, errno));
        }
        ResponsePlan::EmulateResource { target } => {
            if let Err(err) = super::emulate_resource(listener_fd, notif, &target) {
                let errno = err.raw_os_error().unwrap_or(libc::EACCES);
                if matches!(target.kind, ResourceKind::Device) {
                    info!(error = %err, errno, path = %target.path.display(), pid = notif.pid, "device open emulation failed in syscall broker before fanotify");
                } else {
                    debug!(error = %err, errno, target = ?target, "resource emulation failed");
                }
                super::log_notification_response(send_errno(listener_fd, notif.id, errno));
            }
        }
        ResponsePlan::RevalidateFilesystemThenContinue { target } => {
            if let Err(err) = revalidate_filesystem_mutation(notif, &target) {
                warn!(error = %err, target = ?target, "filesystem dispatch failed");
                super::log_notification_response(send_errno(listener_fd, notif.id, libc::EACCES));
            } else {
                super::log_notification_response(send_continue(listener_fd, notif.id));
            }
        }
    }
}
