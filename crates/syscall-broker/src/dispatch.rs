use std::{net::SocketAddr, os::fd::AsRawFd, path::Path, time::Duration};

use agent_sandbox_core::{FilesystemReplica, NetworkOwnership, ResourceKind};
use agent_sandbox_syscall_broker::{
    PersistentPolicyClient, Resolver, ResourceCapture, SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    SeccompNotif, SyscallTarget, notification_arch_valid, reopen_held_terminal, send_addfd,
    send_response,
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

/// Whether a classified filesystem target is covered by the local copy of
/// policyd's filesystem policy, so its emulation can proceed without a
/// policyd round trip. Live verdicts (denies, session buckets, approvals)
/// still round-trip: anything the copy does not allow is decided by
/// `decide`.
fn static_policy_allows(facts: &NormalizedNotification, local: &FilesystemReplica) -> bool {
    let NormalizedNotification::Target {
        target: SyscallTarget::Filesystem(target),
    } = facts
    else {
        return false;
    };

    local.allows_all(&target.checks)
}

/// The tracee reopening a terminal it already holds needs no policy decision;
/// see [`reopen_held_terminal`].
fn held_terminal_plan(
    resolver: &Resolver,
    facts: &NormalizedNotification,
    pid: u32,
) -> Option<ResponsePlan> {
    let NormalizedNotification::Target {
        target: SyscallTarget::Resource(target),
    } = facts
    else {
        return None;
    };

    let ResourceCapture::Device(device) = &target.capture else {
        return None;
    };

    reopen_held_terminal(resolver, pid, &target.path, device).map(|fd| ResponsePlan::InstallFd {
        fd,
        cloexec: device.flags & libc::O_CLOEXEC != 0,
    })
}

pub async fn dispatch_notification_with_mode(
    policy_socket: &Path,
    resolver: &Resolver,
    client: &mut PersistentPolicyClient,
    local_filesystem: &FilesystemReplica,
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

    let facts = normalize_or_failure(resolver, notif);

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
        } if super::is_policy_socket_bypass(resolver, target, policy_socket)
    );

    let plan = if policy_socket_bypass {
        // The broker must be able to service the policy RPC that authorizes
        // every other notification; routing this infrastructure connection
        // back through the resource policy would deadlock the gate.
        ResponsePlan::Continue
    } else if should_bypass_network_policy(&network_policy, &facts) {
        // The configured DNS forwarder is sandbox infrastructure. Proxy mode
        // delegates every TCP and UDP target to the packet filter and proxy.
        ResponsePlan::Continue
    } else if static_policy_allows(&facts, local_filesystem) {
        match facts {
            NormalizedNotification::Target {
                target: SyscallTarget::Filesystem(target),
            } => ResponsePlan::emulate_filesystem(target),
            _ => unreachable!("static_policy_allows accepts only filesystem targets"),
        }
    } else if let Some(plan) = held_terminal_plan(resolver, &facts, notif.pid) {
        plan
    } else {
        decide(client, sandbox_session_id, notif.pid, timeout, facts).await
    };

    execute_response_plan(plan, resolver, listener_fd, notif, policy_socket_bypass);
}

/// Reply to the tracee with `EACCES` and log the notification response.
fn respond_denied(listener_fd: i32, notif: &SeccompNotif) {
    super::log_notification_response(send_response(listener_fd, notif.id, 0, -libc::EACCES, 0));
}

fn execute_response_plan(
    plan: ResponsePlan,
    resolver: &Resolver,
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

        ResponsePlan::InstallFd { fd, cloexec } => {
            if let Err(err) = send_addfd(listener_fd, notif.id, fd.as_raw_fd(), cloexec) {
                let errno = err.raw_os_error().unwrap_or(libc::EACCES);
                info!(error = %err, errno, pid = notif.pid, "installing reopened terminal failed");
                super::log_notification_response(send_response(
                    listener_fd,
                    notif.id,
                    0,
                    -errno,
                    0,
                ));
            }
        }

        ResponsePlan::EmulateResource { target } => {
            if let Err(err) = super::emulate::resource(resolver, listener_fd, notif, &target) {
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
            if let Err(err) =
                super::emulate::filesystem_mutation(resolver, listener_fd, notif, &target)
            {
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
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::Path,
        time::Duration,
    };

    use agent_sandbox_core::{
        FileAccess, FilesystemReplica, NetworkOwnership, SessionExport, policy::FilesystemCheck,
    };
    use agent_sandbox_syscall_broker::{
        FilesystemMutation, FilesystemTarget, MutationDir, NetworkTarget,
    };

    use super::{
        NetworkPolicyBypass, NormalizedNotification, SyscallTarget, should_bypass_network_policy,
        static_policy_allows,
    };

    fn write_export(path: &Path, allow: &str, deny: Option<&str>) {
        let rule = |path: &str| format!(r#"{{"path": "{path}", "access": "all"}}"#);
        let deny: Vec<_> = deny.map(rule).into_iter().collect();
        let staged = path.with_extension("tmp");
        std::fs::write(
            &staged,
            format!(
                r#"{{"allow": [{}], "deny": [{}]}}"#,
                rule(allow),
                deny.join(",")
            ),
        )
        .expect("write export");
        std::fs::rename(staged, path).expect("replace export");
    }

    fn mkdir(path: &str) -> NormalizedNotification {
        NormalizedNotification::Target {
            target: SyscallTarget::Filesystem(FilesystemTarget {
                checks: vec![FilesystemCheck {
                    path: path.into(),
                    access: FileAccess::Write,
                }],
                operation: FilesystemMutation::Mkdir {
                    dir: MutationDir::Root,
                    path: path.as_bytes().to_vec(),
                    mode: 0o755,
                },
            }),
        }
    }

    #[test]
    fn local_allow_follows_the_session_export() {
        let dir = std::env::temp_dir().join(format!("broker-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("export directory");
        let export = dir.join("filesystem.json");
        write_export(&export, "/srv/project", None);
        let mut source = SessionExport::new(export.clone());
        let replica = FilesystemReplica::fetch(&mut source, None);
        let facts = mkdir("/srv/project/secret/dir");
        assert!(static_policy_allows(&facts, &replica));

        let mut refetch = || {
            let polls = std::cell::Cell::new(0);
            replica.follow(
                &mut source,
                Duration::ZERO,
                || {
                    polls.set(polls.get() + 1);
                    polls.get() > 1
                },
                || {},
            );
        };

        write_export(&export, "/srv/project", Some("/srv/project/secret"));
        refetch();
        assert!(!static_policy_allows(&facts, &replica));
        assert!(static_policy_allows(&mkdir("/srv/project/other"), &replica));

        std::fs::remove_file(&export).expect("remove export");
        refetch();
        assert!(!static_policy_allows(
            &mkdir("/srv/project/other"),
            &replica
        ));
        std::fs::remove_dir_all(dir).expect("remove export directory");
    }

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
    fn proxy_mode_bypasses_all_tcp_and_all_udp() {
        // Every TCP flow registers for the proxy (the proxy sniffs HTTP
        // apart from raw TCP), so the gate skips them all.
        for port in [80, 443, 853, 9443] {
            assert!(should_bypass_network_policy(
                &bypass(true, None),
                &target("tcp", "192.0.2.10", port)
            ));
        }

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
