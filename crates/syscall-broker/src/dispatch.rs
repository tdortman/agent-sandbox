use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use super::decision::{NormalizedNotification, ResponsePlan, decide, normalize_or_failure};
use agent_sandbox_core::ResourceKind;
use agent_sandbox_syscall_broker::{
    NetworkMode, PersistentPolicyClient, SeccompNotif, SyscallTarget, notification_arch_valid,
    revalidate_filesystem_mutation, send_continue, send_errno,
};
use tracing::{debug, info, warn};

fn should_bypass_network_policy(
    network_mode: NetworkMode,
    dns_endpoint: Option<SocketAddr>,
    facts: &NormalizedNotification,
) -> bool {
    let NormalizedNotification::Target {
        target: SyscallTarget::Network(target),
    } = facts
    else {
        return false;
    };

    let is_configured_dns = dns_endpoint.is_some_and(|endpoint| {
        endpoint.port() == target.port && target.connect_host.parse() == Ok(endpoint.ip())
    });

    if is_configured_dns {
        return true;
    }

    if network_mode != NetworkMode::Proxy {
        return false;
    }

    matches!(
        (target.scheme.as_str(), target.port),
        ("tcp", 80 | 443 | 8008 | 8080 | 8443) | ("udp", 443)
    )
}
#[derive(Debug, Clone, Copy)]
pub struct NetworkPolicyBypass {
    pub mode: NetworkMode,
    pub dns_endpoint: Option<SocketAddr>,
}

pub async fn dispatch_notification_with_mode(
    policy_socket: &Path,
    client: &PersistentPolicyClient,
    sandbox_session_id: Option<&str>,
    listener_fd: i32,
    notif: &SeccompNotif,
    timeout: Duration,
    network_policy: NetworkPolicyBypass,
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

    let plan = if policy_socket_bypass {
        // The broker must be able to service the policy RPC that authorizes
        // every other notification; routing this infrastructure connection
        // back through the resource policy would deadlock the gate.
        ResponsePlan::Continue
    } else if should_bypass_network_policy(network_policy.mode, network_policy.dns_endpoint, &facts)
    {
        // The configured DNS forwarder is sandbox infrastructure. Proxy mode
        // also delegates only its transparent service ports.
        ResponsePlan::Continue
    } else {
        decide(client, sandbox_session_id, notif.pid, timeout, facts).await
    };
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{NetworkMode, NormalizedNotification, SyscallTarget, should_bypass_network_policy};
    use agent_sandbox_syscall_broker::NetworkTarget;

    fn target(scheme: &str, host: &str, port: u16) -> NormalizedNotification {
        NormalizedNotification::target(SyscallTarget::Network(NetworkTarget {
            host: host.to_owned(),
            connect_host: host.to_owned(),
            port,
            scheme: scheme.to_owned(),
        }))
    }

    #[test]
    fn configured_dns_endpoint_bypasses_transport_policy() {
        let dns_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 100, 1)), 53);

        assert!(should_bypass_network_policy(
            NetworkMode::Direct,
            Some(dns_endpoint),
            &target("udp", "169.254.100.1", 53)
        ));
        assert!(should_bypass_network_policy(
            NetworkMode::Proxy,
            Some(dns_endpoint),
            &target("tcp", "169.254.100.1", 53)
        ));
    }

    #[test]
    fn dns_bypass_requires_exact_configured_endpoint() {
        let dns_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 100, 1)), 53);

        assert!(!should_bypass_network_policy(
            NetworkMode::Direct,
            Some(dns_endpoint),
            &target("udp", "169.254.100.2", 53)
        ));
        assert!(!should_bypass_network_policy(
            NetworkMode::Direct,
            Some(dns_endpoint),
            &target("udp", "169.254.100.1", 5353)
        ));
        assert!(!should_bypass_network_policy(
            NetworkMode::Direct,
            None,
            &target("udp", "169.254.100.1", 53)
        ));
    }

    #[test]
    fn proxy_mode_bypasses_only_transparent_proxy_ports() {
        assert!(should_bypass_network_policy(
            NetworkMode::Proxy,
            None,
            &target("tcp", "192.0.2.10", 443)
        ));
        assert!(should_bypass_network_policy(
            NetworkMode::Proxy,
            None,
            &target("udp", "192.0.2.10", 443)
        ));
        assert!(!should_bypass_network_policy(
            NetworkMode::Proxy,
            None,
            &target("tcp", "192.0.2.10", 853)
        ));
        assert!(!should_bypass_network_policy(
            NetworkMode::Proxy,
            None,
            &target("udp", "192.0.2.10", 853)
        ));
        assert!(!should_bypass_network_policy(
            NetworkMode::Direct,
            None,
            &target("tcp", "192.0.2.10", 443)
        ));
        assert!(!should_bypass_network_policy(
            NetworkMode::Proxy,
            None,
            &NormalizedNotification::continue_()
        ));
    }
}
