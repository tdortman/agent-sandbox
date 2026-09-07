//! Experimental native publication using this daemon's selected file layers.
use std::{io, path::Path};

use agent_sandbox_core::{
    ProcessIds, ResolvedRequestContext, RpcReply, SandboxPaths,
    network_snapshot::{CapturedNetworkContext, capture_network_context},
};

use super::PolicyStore;

/// System NSS files for files-first passwd resolution. Fixed paths keep a
/// misconfigured publisher from substituting attacker-controlled sources; the
/// observed bytes must still select the captured home below.
const NSSWITCH_CONF: &str = "/etc/nsswitch.conf";
const NSS_PASSWD: &str = "/etc/passwd";
/// Well-known NSS daemon socket. The kernel binds non-root transport grants
/// to a live captured peer, so a missing daemon stays on userspace enforcement.
const NSS_SOCKET: &str = "/run/nscd/socket";

/// A captured observation plus everything needed to install its kernel rules
/// at publication. The rule-map descriptor is resolved at observation so a
/// later pin swap cannot redirect the install.
pub(super) struct PendingNetworkPublication {
    observed: agent_sandbox_core::network_snapshot::ObservedNetworkSources,
    policy: std::os::fd::OwnedFd,
    cgroup: u64,
    controller: [u8; 24],
    grants: Vec<std::net::SocketAddrV4>,
}

impl PolicyStore {
    pub(crate) fn observe_captured_network_grants(
        &self,
        program: &Path,
        pins: &Path,
        pid: u32,
        cgroup: u64,
        endpoints: &[std::net::SocketAddrV4],
        dns: &Path,
    ) -> io::Result<RpcReply> {
        // ponytail: one active snapshot shares the existing global revocation map;
        // use per-scope state when publishing multiple enforcement scopes.
        let mut observation = self
            .network_observation
            .lock()
            .map_err(|_| io::Error::other("network observation lock poisoned"))?;
        if observation.is_some() {
            return Err(io::Error::other("network sources are already observed"));
        }
        if self
            .network_revocation
            .lock()
            .map_err(|_| io::Error::other("network revocation lock poisoned"))?
            .is_none()
        {
            return Err(io::Error::other(
                "bind runtime revocation before observation",
            ));
        }
        let captured = capture_network_context(program, pid)?;
        let ctx = self.captured_network_policy_context(&captured)?;
        // Uniform credentials are established by the context check above.
        let uid = captured.uids[0];
        // Non-root grants additionally bind the resolver view that selected
        // the captured home: the NSS socket is watched, its server is
        // captured and frozen by the kernel, and the observed passwd must
        // select the same home. Any failure keeps userspace enforcement.
        let (observed, grants) = if uid == 0 {
            self.observe_file_network_grants(pins, cgroup, &ctx, endpoints, &[dns], &[])?
        } else {
            let nsswitch = Path::new(NSSWITCH_CONF);
            let passwd = Path::new(NSS_PASSWD);
            let socket = Path::new(NSS_SOCKET);
            let home = ctx
                .paths
                .home()
                .ok_or_else(|| io::Error::other("captured task has no home"))?;
            // NSS documents are the last two additional sources, in order.
            let additional = [dns, nsswitch, passwd];
            let (mut observed, grants) =
                self.observe_file_network_grants(pins, cgroup, &ctx, endpoints, &additional, &[
                    socket,
                ])?;
            let count = observed.documents.len();
            if count < additional.len() {
                return Err(io::Error::other("NSS sources were not observed"));
            }
            observed.capture_nss_peer(
                &program.with_file_name("init_nss"),
                socket,
                [count - 2, count - 1],
                uid,
                home,
            )?;
            (observed, grants)
        };
        let transport = program.with_file_name("transport_policy");
        let policy = agent_sandbox_core::network_snapshot::open_policy_map(&transport)?;
        let mut controller = [0_u8; 24];
        controller[..8].copy_from_slice(&captured.start_ns.to_ne_bytes());
        controller[8..16].copy_from_slice(&captured.exec_id.to_ne_bytes());
        controller[16..20].copy_from_slice(&captured.pid.to_ne_bytes());
        *observation = Some(PendingNetworkPublication {
            observed,
            policy,
            cgroup,
            controller,
            grants: grants.clone(),
        });
        drop(observation);
        Ok(RpcReply::NetworkSnapshot {
            context: Box::new(captured),
            grants,
        })
    }

    pub(crate) fn publish_network_grants(&self) -> io::Result<()> {
        use std::os::fd::AsFd;
        let mut observation = self
            .network_observation
            .lock()
            .map_err(|_| io::Error::other("network observation lock poisoned"))?;
        let pending = observation
            .as_mut()
            .ok_or_else(|| io::Error::other("network sources have not been observed"))?;
        // Finalize the epoch before installing rules: with no outer entry the
        // transport denies, so a failed install below stays fail-closed.
        pending.observed.publish()?;
        let result = agent_sandbox_core::network_snapshot::publish_file_network_grants(
            pending.policy.as_fd(),
            pending.cgroup,
            &pending.controller,
            &pending.grants,
        );
        drop(observation);
        result
    }

    fn captured_network_policy_context(
        &self,
        captured: &CapturedNetworkContext,
    ) -> io::Result<ResolvedRequestContext> {
        // Uniform credentials bind this provisional context to its registration.
        // Source authority must be established before publishing its grants.
        let uid = captured.uids[0];
        if captured.uids.iter().any(|&entry| entry != uid) {
            return Err(io::Error::other("captured credentials are not uniform"));
        }
        let claims = &captured.path_claims;
        let complete = |path: &Option<std::path::PathBuf>| {
            path.as_ref()
                .filter(|path| path.is_absolute())
                .cloned()
                .ok_or_else(|| io::Error::other("missing absolute captured path"))
        };
        let cwd = complete(&claims.cwd)?;
        let home = complete(&claims.home)?;
        let project = complete(&claims.project_root)?;
        let session = captured
            .session_claim
            .as_ref()
            .ok_or_else(|| io::Error::other("captured task has no registration claim"))?;
        let sessions = self
            .sandbox_sessions
            .read()
            .map_err(|_| io::Error::other("sandbox registration lock poisoned"))?;
        let registration = sessions
            .get(session)
            .filter(|reg| reg.owner_uid == uid && reg.launcher_pid != 0)
            .ok_or_else(|| io::Error::other("captured task has no matching registration"))?;
        if registration.launcher_start_ticks == 0
            || captured.parent_start_ticks != registration.launcher_start_ticks
            || captured.parent_pid != registration.launcher_pid
        {
            return Err(io::Error::other(
                "captured task is not the registered launcher's child",
            ));
        }
        let package = registration
            .package
            .clone()
            .ok_or_else(|| io::Error::other("registration has no package"))?;
        drop(sessions);
        Ok(ResolvedRequestContext {
            paths: SandboxPaths::new(cwd, home, project),
            ids: ProcessIds::new(captured.pid, uid),
            sandbox_session_id: Some(session.clone()),
            package: Some(package),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_context_requires_registered_owner_and_complete_paths() {
        let store = super::super::test_store();
        let pid = std::process::id();
        let launcher = super::super::context::read_proc_ppid(pid).expect("parent");
        store
            .register_sandbox("captured", "omp", 0, launcher, pid)
            .expect("registration");
        let captured = CapturedNetworkContext {
            pid,
            parent_pid: launcher,
            parent_start_ticks: agent_sandbox_core::socket_owner::process_start_time_ticks(
                launcher,
            )
            .expect("launcher lifetime"),
            parent_start_ns: 1,
            parent_exec_id: 1,
            start_ns: 1,
            exec_id: 1,
            uids: [0; 4],
            environment: vec![],
            path_claims: agent_sandbox_core::ProcContext {
                cwd: Some("/project".into()),
                home: Some("/home/fixture".into()),
                project_root: Some("/project".into()),
            },
            session_claim: Some("captured".into()),
        };
        let ctx = store
            .captured_network_policy_context(&captured)
            .expect("captured context");
        assert_eq!(ctx.package.as_deref(), Some("omp"));
        assert_eq!(ctx.paths.home(), Some(Path::new("/home/fixture")));
        for mutation in 0..4 {
            let mut invalid = captured.clone();
            match mutation {
                0 => invalid.uids[1] = 1000,
                1 => invalid.path_claims.home = Some("relative".into()),
                2 => invalid.session_claim = Some("forged".into()),
                _ => invalid.parent_pid = u32::MAX,
            }
            assert!(store.captured_network_policy_context(&invalid).is_err());
        }
        store
            .sandbox_sessions
            .write()
            .expect("registrations")
            .get_mut("captured")
            .expect("registration")
            .launcher_start_ticks += 1;
        assert!(
            store.captured_network_policy_context(&captured).is_err(),
            "reused launcher PID must not inherit a registration"
        );
        store
            .register_sandbox("captured", "omp", 0, launcher, pid)
            .expect("fresh registration");
        assert!(store.captured_network_policy_context(&captured).is_ok());
    }
    #[test]
    fn captured_context_matches_uniform_owner_and_rejects_mixed_credentials() {
        let store = super::super::test_store();
        let pid = std::process::id();
        let launcher = super::super::context::read_proc_ppid(pid).expect("parent");
        store
            .register_sandbox("captured-user", "omp", 1000, launcher, pid)
            .expect("registration");
        let captured = CapturedNetworkContext {
            pid,
            parent_pid: launcher,
            parent_start_ticks: agent_sandbox_core::socket_owner::process_start_time_ticks(
                launcher,
            )
            .expect("launcher lifetime"),
            parent_start_ns: 1,
            parent_exec_id: 1,
            start_ns: 1,
            exec_id: 1,
            uids: [1000; 4],
            environment: vec![],
            path_claims: agent_sandbox_core::ProcContext {
                cwd: Some("/project".into()),
                home: Some("/home/tim".into()),
                project_root: Some("/project".into()),
            },
            session_claim: Some("captured-user".into()),
        };
        let ctx = store
            .captured_network_policy_context(&captured)
            .expect("sandbox-user context");
        assert_eq!(ctx.ids.uid(), Some(1000));
        assert_eq!(ctx.paths.home(), Some(Path::new("/home/tim")));
        let mut mixed = captured.clone();
        mixed.uids[2] = 0;
        assert!(store.captured_network_policy_context(&mixed).is_err());
        let mut forged_owner = captured;
        forged_owner.uids = [1001; 4];
        assert!(
            store
                .captured_network_policy_context(&forged_owner)
                .is_err()
        );
    }
}
