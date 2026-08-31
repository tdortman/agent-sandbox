//! Resolve request context from an incoming RPC.

use std::{fs, os::unix::fs::MetadataExt, sync::Arc};

use agent_sandbox_core::{
    CgroupIdentity, DbusTarget, FileAccess, ProcessIdentity, ProcessIds, RequestContext,
    ResolvedRequestContext, ResourceAccess, ResourceKind, RoleEvidenceRequest, SeccompSubcheck,
};

use crate::{
    server::{dispatch::SocketRole, peer::ClientPeer},
    store::{PolicyStore, TrustedPeer},
};

pub(super) fn resolve_request_context(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    role: SocketRole,

    ctx: &RequestContext,
) -> ResolvedRequestContext {
    if role == SocketRole::Sandbox
        && let Some(sandbox_session_id) = ctx.sandbox_session_id.clone()
    {
        store.note_sandbox_peer(
            TrustedPeer {
                pid: peer.pid,
                uid: peer.uid,
            },
            &sandbox_session_id,
        );
    }

    let mc = crate::wire::MergeContext::from(ctx);

    store.resolve_context_with_peer(
        &mc,
        Some(TrustedPeer {
            pid: peer.pid,
            uid: peer.uid,
        }),
    )
}

/// Gate kind used to bind evidence to the request handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GateKind {
    Network,
    Filesystem,
    Resource,
    Dbus,
    Elevation,
}

fn evidence_process(evidence: &RoleEvidenceRequest) -> Option<ProcessIdentity> {
    match evidence {
        RoleEvidenceRequest::Fanotify { evidence, .. } => Some(evidence.process),
        RoleEvidenceRequest::Seccomp { evidence, .. } => Some(evidence.process),
        RoleEvidenceRequest::Nfq { evidence, .. } => Some(ProcessIdentity::from_parts(
            evidence.owner.pid(),
            evidence.owner.uid(),
            evidence.owner.process_start_time_ticks(),
        )),
        RoleEvidenceRequest::Elevation { evidence, .. } => Some(evidence.peer),
        RoleEvidenceRequest::Dbus { evidence, .. } => Some(evidence.peer),
        RoleEvidenceRequest::HttpBridge { .. } => None,
    }
}

fn current_cgroup_identity(pid: u32) -> Option<CgroupIdentity> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = content.lines().find_map(|line| {
        let (hierarchy, path) = line.split_once("::")?;
        (hierarchy == "0").then_some(path)
    })?;
    let metadata = fs::metadata(format!("/sys/fs/cgroup{path}")).ok()?;
    CgroupIdentity::new(metadata.ino()).ok()
}

fn live_process(identity: ProcessIdentity) -> bool {
    let pid = identity.pid().get();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok();
    let uid = status.as_deref().and_then(|status| {
        status.lines().find_map(|line| {
            let rest = line.strip_prefix("Uid:")?;
            rest.split_whitespace().next()?.parse().ok()
        })
    });
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok();
    let start_time = stat.as_deref().and_then(|stat| {
        let (_, fields) = stat.rsplit_once(") ")?;
        fields.split_whitespace().nth(19)?.parse().ok()
    });

    uid == Some(identity.uid()) && start_time == Some(identity.process_start_time_ticks().get())
}

fn cgroup_matches_process(identity: ProcessIdentity, cgroup: CgroupIdentity) -> bool {
    current_cgroup_identity(identity.pid().get()).is_some_and(|actual| actual == cgroup)
}

fn evidence_thread_matches_process(
    evidence: &RoleEvidenceRequest,
    process: ProcessIdentity,
) -> bool {
    match evidence {
        RoleEvidenceRequest::Fanotify { evidence, .. } => {
            evidence.opener.tgid.get() == process.pid().get()
        }
        RoleEvidenceRequest::Seccomp { evidence, .. } => {
            evidence.thread.tgid.get() == process.pid().get()
        }
        _ => true,
    }
}

fn evidence_request_id_matches(evidence: &RoleEvidenceRequest) -> bool {
    match evidence {
        RoleEvidenceRequest::Fanotify {
            request_id,
            evidence,
        } => *request_id == evidence.operation_id.get(),
        RoleEvidenceRequest::Seccomp {
            request_id,
            evidence,
        } => *request_id == evidence.operation_id.get(),
        RoleEvidenceRequest::Nfq {
            request_id,
            evidence,
        } => *request_id == evidence.operation_id.get(),
        RoleEvidenceRequest::HttpBridge { .. } => true,
        RoleEvidenceRequest::Elevation {
            request_id,
            evidence,
        } => *request_id == evidence.operation_id.get(),
        RoleEvidenceRequest::Dbus {
            request_id,
            evidence,
        } => *request_id == u64::from(evidence.operation_id.serial.get()),
    }
}

fn evidence_kind_matches(kind: GateKind, evidence: &RoleEvidenceRequest) -> bool {
    match (kind, evidence) {
        (GateKind::Network, RoleEvidenceRequest::Nfq { .. })
        | (GateKind::Network, RoleEvidenceRequest::Seccomp { .. }) => true,
        (GateKind::Filesystem, RoleEvidenceRequest::Fanotify { .. }) => true,
        (GateKind::Filesystem, RoleEvidenceRequest::Seccomp { evidence, .. }) => evidence
            .subchecks
            .iter()
            .any(|subcheck| matches!(subcheck, SeccompSubcheck::Filesystem { .. })),
        (GateKind::Resource, RoleEvidenceRequest::Seccomp { evidence, .. }) => evidence
            .subchecks
            .iter()
            .any(|subcheck| matches!(subcheck, SeccompSubcheck::Resource { .. })),
        (GateKind::Dbus, RoleEvidenceRequest::Dbus { .. })
        | (GateKind::Elevation, RoleEvidenceRequest::Elevation { .. }) => true,
        _ => false,
    }
}

/// Resolve one gate's context after authenticating its producer evidence.
///
/// Legacy callers may omit evidence during the migration. Evidence-bearing
/// callers cannot supply project paths or process ids through `ctx`; those
/// values come from the event-time identity and a policyd-owned cgroup leaf.
/// The leaf is bound to the accepted producer connection before this path runs.
pub(super) fn resolve_gate_context(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    role: SocketRole,
    connection_id: u64,
    kind: GateKind,
    ctx: &RequestContext,
    evidence: Option<&RoleEvidenceRequest>,
) -> Result<ResolvedRequestContext, crate::error::PolicydError> {
    let Some(evidence) = evidence else {
        if kind == GateKind::Dbus && role == SocketRole::Host {
            let mut mc = crate::wire::MergeContext::from(ctx);
            mc.paths = agent_sandbox_core::SandboxPaths::default();
            let pid = ctx
                .pid
                .filter(|_| ctx.uid.is_none_or(|uid| uid == peer.uid));
            mc.ids = ProcessIds::from_options(pid, Some(peer.uid));
            return Ok(store.resolve_gate_context_with_peer(&mc, TrustedPeer {
                pid: peer.pid,
                uid: peer.uid,
            }));
        }
        return Ok(resolve_request_context(store, peer, role, ctx));
    };

    if !matches!(role, SocketRole::Host | SocketRole::Sandbox)
        || !evidence_request_id_matches(evidence)
        || !evidence_kind_matches(kind, evidence)
    {
        return Err(crate::error::PolicydError::InvalidGateEvidence);
    }

    let Some(process) = evidence_process(evidence) else {
        return Err(crate::error::PolicydError::InvalidGateEvidence);
    };

    let cgroup = match evidence {
        RoleEvidenceRequest::Fanotify { evidence, .. } => evidence.cgroup,
        RoleEvidenceRequest::Seccomp { evidence, .. } => evidence.cgroup,
        RoleEvidenceRequest::Nfq { evidence, .. } => evidence.cgroup,
        RoleEvidenceRequest::Elevation { evidence, .. } => evidence.cgroup,
        RoleEvidenceRequest::Dbus { evidence, .. } => evidence.cgroup,
        RoleEvidenceRequest::HttpBridge { .. } => unreachable!(),
    };
    // The registry lookup is the producer authentication boundary. In
    // particular, root credentials do not authorize an arbitrary cgroup.
    let Some(attached_workspace) = store.resolve_attached_process(&process, cgroup, connection_id)
    else {
        return Err(crate::error::PolicydError::InvalidGateEvidence);
    };
    let authenticated_peer = peer.uid == 0
        || (peer.uid == process.uid()
            && (peer.pid == process.pid().get()
                || current_cgroup_identity(peer.pid) == Some(cgroup)));
    if !authenticated_peer
        || !live_process(process)
        || !evidence_thread_matches_process(evidence, process)
    {
        return Err(crate::error::PolicydError::InvalidGateEvidence);
    }

    if !cgroup_matches_process(process, cgroup) {
        return Err(crate::error::PolicydError::InvalidGateEvidence);
    }

    let mut mc = crate::wire::MergeContext::from(ctx);
    mc.paths = agent_sandbox_core::SandboxPaths::default();
    mc.ids = ProcessIds::from_options(Some(process.pid().get()), Some(process.uid()));

    let mut resolved = store.resolve_gate_context_with_peer(&mc, TrustedPeer {
        pid: process.pid().get(),
        uid: process.uid(),
    });
    resolved.paths =
        resolved
            .paths
            .merged_with(None, None, Some(attached_workspace.canonical_path));
    Ok(resolved)
}

/// Check that a network request still describes the captured flow.
pub(super) fn network_evidence_matches(
    host: &Option<String>,
    connect_host: &Option<String>,
    port: Option<u16>,
    evidence: &RoleEvidenceRequest,
) -> bool {
    match evidence {
        RoleEvidenceRequest::Nfq { evidence, .. } => {
            let Some(connect_host) = connect_host.as_deref().and_then(|value| value.parse::<std::net::IpAddr>().ok()) else {
                return false;
            };
            evidence.flow.destination_ip() == connect_host
                && Some(evidence.flow.destination_port().get()) == port
        }
        RoleEvidenceRequest::Seccomp { evidence, .. } => evidence.subchecks.iter().any(|subcheck| {
            matches!(
                subcheck,
                SeccompSubcheck::Network { destination, .. }
                    if host.as_deref().is_some_and(|value| destination == value.as_bytes())
                        || connect_host.as_deref().is_some_and(|value| destination == value.as_bytes())
            )
        }),
        _ => false,
    }
}

/// Check that a D-Bus request still describes the captured message.
pub(super) fn dbus_evidence_matches(target: &DbusTarget, evidence: &RoleEvidenceRequest) -> bool {
    matches!(evidence, RoleEvidenceRequest::Dbus { evidence, .. } if {
        let captured = &evidence.target;
        captured.bus == target.bus
            && captured.destination == target.destination
            && captured.object_path == target.object_path
            && captured.interface == target.interface
            && captured.member == target.member
            && captured.message_kind == target.message_kind
            && captured.signature == target.signature
            && captured
                .fd_metadata
                .iter()
                .map(|fd| (&fd.kind, fd.read_only))
                .eq(target.fd_metadata.iter().map(|fd| (&fd.kind, fd.read_only)))
    })
}

/// Check that an elevation request still describes the captured command.
pub(super) fn elevation_evidence_matches(argv: &[String], evidence: &RoleEvidenceRequest) -> bool {
    matches!(evidence, RoleEvidenceRequest::Elevation { evidence, .. } if evidence.argv == argv)
}

/// Check that a filesystem request still describes the captured event.
pub(super) fn filesystem_evidence_matches(
    path: &std::path::Path,
    access: FileAccess,
    evidence: &RoleEvidenceRequest,
) -> bool {
    match evidence {
        RoleEvidenceRequest::Fanotify { evidence, .. } => {
            evidence.path == path && evidence.access == access
        }
        RoleEvidenceRequest::Seccomp { evidence, .. } => evidence.subchecks.iter().any(|subcheck| {
            matches!(subcheck, SeccompSubcheck::Filesystem { path: captured, access: captured_access, .. } if captured == path && *captured_access == access)
        }),
        _ => false,
    }
}

/// Check that a resource request still describes a captured subcheck.
pub(super) fn resource_evidence_matches(
    kind: ResourceKind,
    path: &std::path::Path,
    access: ResourceAccess,
    evidence: &RoleEvidenceRequest,
) -> bool {
    matches!(
        evidence,
        RoleEvidenceRequest::Seccomp { evidence, .. } if evidence.subchecks.iter().any(|subcheck| matches!(subcheck, SeccompSubcheck::Resource { resource_kind, path: captured, access: captured_access, .. } if *resource_kind == kind && captured == path && *captured_access == access))
    )
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use agent_sandbox_core::{
        FileAccess, ProcessIds, RequestContext, ResolvedRequestContext, RpcRequest, home_from_uid,
    };

    use super::{
        evidence_request_id_matches, filesystem_evidence_matches, resolve_gate_context,
        resolve_request_context,
    };
    use crate::{
        server::{dispatch::SocketRole, peer::ClientPeer},
        store::PolicyStore,
    };

    fn test_store(dir: &tempfile::TempDir) -> Arc<PolicyStore> {
        Arc::new(PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("policy.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        )))
    }

    #[test]
    fn sandbox_dispatch_plans_trusted_context_before_handlers_run() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let store = test_store(&dir);
        let peer_pid = std::process::id();

        let socket_uid = match nix::unistd::getuid().as_raw() {
            0 => 1,
            uid => uid,
        };

        let expected_home = home_from_uid(Some(socket_uid)).map(PathBuf::from);

        let req = RpcRequest::CheckFilesystem {
            path: "/tmp/allowed".into(),
            access: FileAccess::Read,
            ctx: RequestContext {
                cwd: Some("/attacker/cwd".into()),
                home: Some("/attacker/home".into()),
                project_root: Some("/attacker/project".into()),
                pid: Some(peer_pid.saturating_add(10_000)),
                uid: Some(socket_uid.saturating_add(1)),
                sandbox_session_id: Some("sandbox-a".into()),
            },
            evidence: None,
        };

        let RpcRequest::CheckFilesystem { ctx, .. } = req else {
            panic!("expected filesystem request");
        };

        let ctx = resolve_request_context(
            &store,
            ClientPeer {
                pid: peer_pid,
                uid: socket_uid,
                gid: 0,
            },
            SocketRole::Sandbox,
            &ctx,
        );

        assert_eq!(ctx.ids, ProcessIds::new(peer_pid, socket_uid));
        assert_eq!(ctx.paths.home_path(), expected_home);
        assert_ne!(ctx.paths.home(), Some(Path::new("/attacker/home")));

        assert_ne!(
            ctx.paths.project_root(),
            Some(Path::new("/attacker/project"))
        );

        assert_eq!(ctx.sandbox_session_id.as_deref(), Some("sandbox-a"));

        let rehydrated =
            ResolvedRequestContext::new(ctx.paths.clone(), ctx.ids, ctx.sandbox_session_id);

        assert_eq!(rehydrated.ids, ProcessIds::new(peer_pid, socket_uid));
        assert_eq!(rehydrated.paths.home_path(), expected_home);
        assert_ne!(rehydrated.paths.home(), Some(Path::new("/attacker/home")));
        assert_eq!(rehydrated.sandbox_session_id.as_deref(), Some("sandbox-a"));
    }

    #[test]
    fn gate_resolver_rejects_unregistered_cgroup_evidence() {
        use agent_sandbox_core::{
            CgroupIdentity, FanotifyEventId, FanotifyEvidence, OperationIdentity, ProcessIdentity,
            RoleEvidenceRequest, SubcheckIdentity, ThreadIdentity,
        };

        let dir = tempfile::tempdir().expect("create tempdir");
        let store = test_store(&dir);
        let pid = std::process::id();
        let uid = nix::unistd::getuid().as_raw();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read process stat");
        let (_, fields) = stat.rsplit_once(") ").expect("parse process stat");
        let start_time = fields
            .split_whitespace()
            .nth(19)
            .expect("process start time")
            .parse()
            .expect("numeric process start time");
        let process = ProcessIdentity::new(pid, uid, start_time).expect("process identity");
        let cgroup = CgroupIdentity::new(19).expect("cgroup identity");
        let evidence = RoleEvidenceRequest::Fanotify {
            request_id: 31,
            evidence: FanotifyEvidence {
                operation_id: OperationIdentity::new(31).expect("operation id"),
                subcheck_id: SubcheckIdentity::new(32).expect("subcheck id"),
                event_id: FanotifyEventId::new(33).expect("event id"),
                process,
                opener: ThreadIdentity {
                    tid: std::num::NonZeroU32::new(pid).expect("thread id"),
                    tgid: std::num::NonZeroU32::new(pid).expect("thread group id"),
                },
                cgroup,
                path: PathBuf::from("/captured"),
                access: FileAccess::Read,
            },
        };
        let wire_ctx = RequestContext {
            cwd: Some("/attacker/cwd".into()),
            home: Some("/attacker/home".into()),
            project_root: Some("/attacker/project".into()),
            pid: Some(pid.saturating_add(10_000)),
            uid: Some(uid.saturating_add(1)),
            sandbox_session_id: None,
        };

        let result = resolve_gate_context(
            &store,
            ClientPeer { pid, uid, gid: 0 },
            SocketRole::Sandbox,
            17,
            super::GateKind::Filesystem,
            &wire_ctx,
            Some(&evidence),
        );

        assert!(matches!(
            result,
            Err(crate::error::PolicydError::InvalidGateEvidence)
        ));
    }

    #[test]
    fn gate_evidence_binds_request_and_subcheck_targets() {
        use std::num::NonZeroU32;

        use agent_sandbox_core::{
            CgroupIdentity, OperationIdentity, ProcessIdentity, RoleEvidenceRequest,
            SeccompEvidence, SeccompListenerGeneration, SeccompNotificationId, SeccompSubcheck,
            SubcheckIdentity, ThreadIdentity,
        };

        let evidence = RoleEvidenceRequest::Seccomp {
            request_id: 7,
            evidence: SeccompEvidence {
                operation_id: OperationIdentity::new(7).expect("operation id"),
                listener_generation: SeccompListenerGeneration::new(11)
                    .expect("listener generation"),
                notification_id: SeccompNotificationId::new(13).expect("notification id"),
                process: ProcessIdentity::new(1, 1000, 17).expect("process identity"),
                thread: ThreadIdentity {
                    tid: NonZeroU32::new(1).expect("tid"),
                    tgid: NonZeroU32::new(1).expect("tgid"),
                },
                cgroup: CgroupIdentity::new(19).expect("cgroup identity"),
                subchecks: vec![SeccompSubcheck::Filesystem {
                    subcheck_id: SubcheckIdentity::new(23).expect("subcheck id"),
                    path: PathBuf::from("/captured"),
                    access: FileAccess::Read,
                }],
            },
        };

        assert!(evidence_request_id_matches(&evidence));
        assert!(filesystem_evidence_matches(
            Path::new("/captured"),
            FileAccess::Read,
            &evidence
        ));
        assert!(!filesystem_evidence_matches(
            Path::new("/forged"),
            FileAccess::Read,
            &evidence
        ));

        let RoleEvidenceRequest::Seccomp {
            evidence: captured, ..
        } = evidence
        else {
            unreachable!();
        };
        let wrong_request = RoleEvidenceRequest::Seccomp {
            request_id: 8,
            evidence: captured,
        };
        assert!(!evidence_request_id_matches(&wrong_request));
    }
}
