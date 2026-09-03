use std::{net::SocketAddr, path::Path, time::Duration};

use agent_sandbox_core::{NetworkOwnership, ResourceKind, StaticPolicyAllow};
use agent_sandbox_syscall_broker::{
    PersistentPolicyClient, SECCOMP_USER_NOTIF_FLAG_CONTINUE, SeccompNotif, SyscallTarget,
    notification_arch_valid, send_response,
};
use tracing::{debug, info, warn};

use super::decision::{NormalizedNotification, ResponsePlan, decide, normalize_or_failure};

fn should_bypass_network_policy(
    network_policy: &NetworkPolicyBypass,
    facts: &NormalizedNotification,
) -> bool {
    let NormalizedNotification::Target {
        target: SyscallTarget::Network(target),
    } = facts
    else {
        return false;
    };

    network_policy.ownership.syscall_gate_skips(
        &target.scheme,
        &target.host,
        target.port,
        network_policy.dns_endpoint,
    )
}

#[derive(Debug, Clone)]
pub struct NetworkPolicyBypass {
    pub ownership: NetworkOwnership,
    pub dns_endpoint: Option<SocketAddr>,
}
/// Whether a classified filesystem target is covered by the static policy
/// snapshot exported by policyd, so its emulation can proceed without a
/// policyd round trip. Live verdicts (denies, session buckets, approvals)
/// still round-trip: anything the snapshot does not allow is decided by
/// `decide`.
fn static_policy_allows(facts: &NormalizedNotification, static_allow: &StaticPolicyAllow) -> bool {
    let NormalizedNotification::Target {
        target: SyscallTarget::Filesystem(target),
    } = facts
    else {
        return false;
    };

    !static_allow.is_empty() && static_allow.allows_all(&target.checks)
}

pub async fn dispatch_notification_with_mode(
    policy_socket: &Path,
    client: &mut PersistentPolicyClient,
    static_allow: &StaticPolicyAllow,
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

        super::log_notification_response(send_response(listener_fd, notif.id, 0, -libc::EACCES, 0));
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
    } else if should_bypass_network_policy(&network_policy, &facts) {
        // The configured DNS forwarder is sandbox infrastructure. Proxy mode
        // also delegates only its transparent service ports.
        ResponsePlan::Continue
    } else if static_policy_allows(&facts, static_allow) {
        match facts {
            NormalizedNotification::Target {
                target: SyscallTarget::Filesystem(target),
            } => ResponsePlan::emulate_filesystem(target),
            _ => unreachable!("static_policy_allows accepts only filesystem targets"),
        }
    } else {
        decide(client, sandbox_session_id, notif.pid, timeout, facts).await
    };

    execute_response_plan(plan, listener_fd, notif, policy_socket_bypass);
}

/// Reply to the tracee with `EACCES` and log the notification response.
fn respond_denied(listener_fd: i32, notif: &SeccompNotif) {
    super::log_notification_response(send_response(listener_fd, notif.id, 0, -libc::EACCES, 0));
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
            super::log_notification_response(send_response(
                listener_fd,
                notif.id,
                0,
                0,
                SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            ));
        }

        ResponsePlan::DenyErrno { errno } => {
            super::log_notification_response(send_response(listener_fd, notif.id, 0, -errno, 0));
        }

        ResponsePlan::ResourcePolicyDenied {
            target,
            source,
            error,
        } => {
            info!(target = ?target, source = ?source, error = ?error, "resource syscall denied by policy");
            respond_denied(listener_fd, notif);
        }

        ResponsePlan::ResourceRpcFailure { target, error } => {
            warn!(target = ?target, error = %error, "resource policy RPC failed");
            respond_denied(listener_fd, notif);
        }

        ResponsePlan::FilesystemPolicyDenied {
            path,
            access,
            source,
            error,
        } => {
            info!(path = %path.display(), access = ?access, source = ?source, error = ?error, "filesystem syscall denied by policy");
            respond_denied(listener_fd, notif);
        }

        ResponsePlan::FilesystemRpcFailure {
            path,
            access,
            error,
        } => {
            warn!(path = %path.display(), access = ?access, error = %error, "filesystem policy RPC failed");
            respond_denied(listener_fd, notif);
        }

        ResponsePlan::EmulateResource { target } => {
            if let Err(err) = super::emulate_resource(listener_fd, notif, &target) {
                let errno = err.raw_os_error().unwrap_or(libc::EACCES);
                if matches!(target.kind, ResourceKind::Device) {
                    info!(error = %err, errno, path = %target.path.display(), pid = notif.pid, "device open emulation failed in syscall broker before fanotify");
                } else {
                    debug!(error = %err, errno, target = ?target, "resource emulation failed");
                }
                super::log_notification_response(send_response(
                    listener_fd,
                    notif.id,
                    0,
                    -errno,
                    0,
                ));
            }
        }

        ResponsePlan::EmulateFilesystem { target } => {
            if let Err(err) = super::emulate_filesystem_mutation(listener_fd, notif, &target) {
                let errno = err.raw_os_error().unwrap_or(libc::EACCES);
                warn!(error = %err, target = ?target, "filesystem mutation emulation failed");
                super::log_notification_response(send_response(
                    listener_fd,
                    notif.id,
                    0,
                    -errno,
                    0,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use agent_sandbox_core::NetworkOwnership;
    use agent_sandbox_syscall_broker::NetworkTarget;

    use super::{
        NetworkPolicyBypass, NormalizedNotification, SyscallTarget, should_bypass_network_policy,
    };

    fn bypass(proxy_mode: bool, dns_endpoint: Option<SocketAddr>) -> NetworkPolicyBypass {
        NetworkPolicyBypass {
            ownership: NetworkOwnership {
                proxy_mode,
                udp_proxy_ports: Vec::new(),
            },
            dns_endpoint,
        }
    }
    fn target(scheme: &str, host: &str, port: u16) -> NormalizedNotification {
        NormalizedNotification::Target {
            target: SyscallTarget::Network(NetworkTarget {
                host: host.to_owned(),
                port,
                scheme: scheme.to_owned(),
            }),
        }
    }

    #[test]
    fn configured_dns_endpoint_bypasses_transport_policy() {
        let dns_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 100, 1)), 53);

        assert!(should_bypass_network_policy(
            &bypass(false, Some(dns_endpoint)),
            &target("udp", "169.254.100.1", 53)
        ));

        assert!(should_bypass_network_policy(
            &bypass(true, Some(dns_endpoint)),
            &target("tcp", "169.254.100.1", 53)
        ));
    }

    #[test]
    fn dns_bypass_requires_exact_configured_endpoint() {
        let dns_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 100, 1)), 53);

        assert!(!should_bypass_network_policy(
            &bypass(false, Some(dns_endpoint)),
            &target("udp", "169.254.100.2", 53)
        ));

        assert!(!should_bypass_network_policy(
            &bypass(false, Some(dns_endpoint)),
            &target("udp", "169.254.100.1", 5353)
        ));

        assert!(!should_bypass_network_policy(
            &bypass(false, None),
            &target("udp", "169.254.100.1", 53)
        ));
    }

    #[test]
    fn proxy_mode_bypasses_tcp_proxy_ports_and_all_udp() {
        assert!(should_bypass_network_policy(
            &bypass(true, None),
            &target("tcp", "192.0.2.10", 443)
        ));

        assert!(should_bypass_network_policy(
            &bypass(true, None),
            &target("tcp", "192.0.2.10", 80)
        ));

        assert!(!should_bypass_network_policy(
            &bypass(true, None),
            &target("tcp", "192.0.2.10", 853)
        ));

        // The proxy-mode packet filter queues new UDP flows (except DNS to
        // the forwarder) for one deduped transport check per host:port, so
        // the syscall gate must not add a per-sendto prompt on top.
        for port in [53, 80, 443, 853, 4444, 5353] {
            assert!(should_bypass_network_policy(
                &bypass(true, None),
                &target("udp", "192.0.2.10", port)
            ));
        }

        // Direct mode keeps UDP transport checks: there the packet filter
        // queues every UDP datagram for policy.
        assert!(!should_bypass_network_policy(
            &bypass(false, None),
            &target("tcp", "192.0.2.10", 443)
        ));

        assert!(!should_bypass_network_policy(
            &bypass(false, None),
            &target("udp", "192.0.2.10", 4444)
        ));

        assert!(!should_bypass_network_policy(
            &bypass(true, None),
            &NormalizedNotification::continue_()
        ));
    }
}
