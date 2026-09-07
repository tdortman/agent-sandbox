//! Native task capture, source observation, and file-policy compilation.
//! Callers establish source authority, runtime eligibility, and mount isolation
//! before publishing network grants.

mod observation;
mod passwd;
mod source;

use std::{
    io,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};

use aya::{
    maps::{Array, HashMap, Map, MapData, MapType},
    programs::ProgramInfo,
};
pub use observation::ObservedNetworkSources;
pub use passwd::file_passwd_home;

/// Kernel-captured facts used to select a task's policy sources.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapturedNetworkContext {
    /// Target thread-group leader in the initial PID namespace.
    pub pid: u32,
    /// Kernel task start time in boot-time nanoseconds.
    pub start_ns: u64,
    /// Kernel executable incarnation counter.
    pub exec_id: u64,
    /// Kernel-captured parent process whose lifetime the transport checks.
    pub parent_pid: u32,
    /// Parent start time in boot-time nanoseconds.
    pub parent_start_ns: u64,
    /// Parent start time in procfs clock ticks for registration comparison.
    pub parent_start_ticks: u64,
    /// Parent executable incarnation counter.
    pub parent_exec_id: u64,
    /// Real, effective, saved, and filesystem UIDs captured by the kernel.
    pub uids: [u32; 4],
    /// Exact environment bytes, or empty when capture was unavailable.
    pub environment: Vec<u8>,
    /// Explicit path claims parsed from these captured bytes, without live
    /// process, publisher-environment, or persisted-session fallbacks.
    pub path_claims: crate::ProcContext,
    /// Session claim from the captured environment; package attribution still
    /// requires the policy daemon's authenticated registration.
    pub session_claim: Option<String>,
}
/// Require the initial PID namespace.
///
/// Kernel captures resolve numeric PIDs in the caller's namespace, so any
/// other namespace would misattribute the capture. Fail closed when the
/// comparison itself is unavailable.
///
/// # Errors
/// Returns an error outside the initial PID namespace or when either
/// namespace identity cannot be read.
pub fn require_initial_pid_namespace() -> io::Result<()> {
    if std::fs::read_link("/proc/self/ns/pid")? != std::fs::read_link("/proc/1/ns/pid")? {
        return Err(io::Error::other(
            "network snapshot requires the initial PID namespace",
        ));
    }
    Ok(())
}

/// Capture `pid` using a trusted publisher's pinned `init_controller` program.
///
/// The kernel supplies the identity and bytes; callers must derive policy from
/// this snapshot and establish source freshness before publishing any grant.
///
/// # Errors
/// Returns an error for incompatible or used maps, a failed capture, or an
/// invalid kernel response. A failed capture requires a fresh snapshot object.
pub fn capture_network_context(program: &Path, pid: u32) -> io::Result<CapturedNetworkContext> {
    require_initial_pid_namespace()?;
    if pid == 0 || i32::try_from(pid).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid target PID",
        ));
    }
    let info = ProgramInfo::from_pin(program).map_err(io::Error::other)?;
    // Aya 0.14 has no Syscall program wrapper; retain its FD and map APIs.
    if info.program_type() as u32 != 31 || info.name() != b"init_controller" {
        return Err(io::Error::other("invalid network snapshot program"));
    }
    let program_fd = info.fd().map_err(io::Error::other)?;
    let mut controller = None;
    let mut environment = None;
    let mut credentials = None;
    let mut parent = None;
    for id in info
        .map_ids()
        .map_err(io::Error::other)?
        .unwrap_or_default()
    {
        let data = MapData::from_id(id).map_err(io::Error::other)?;
        let map = data.info().map_err(io::Error::other)?;
        let destination = match map.name() {
            b"controller" => (&mut controller, MapType::Hash, 24),
            b"environment" => (&mut environment, MapType::Array, 8208),
            b"credentials" => (&mut credentials, MapType::Array, 16),
            b"parent_identity" => (&mut parent, MapType::Array, 24),
            _ => continue,
        };
        if destination.0.is_some()
            || map.map_type().map_err(io::Error::other)? != destination.1
            || map.key_size() != 4
            || map.value_size() != destination.2
            || map.max_entries() != 1
        {
            return Err(io::Error::other("invalid network snapshot map layout"));
        }
        *destination.0 = Some(data);
    }
    let mut controller =
        Map::HashMap(controller.ok_or_else(|| io::Error::other("missing controller map"))?);
    let environment =
        Map::Array(environment.ok_or_else(|| io::Error::other("missing environment map"))?);
    let credentials =
        Map::Array(credentials.ok_or_else(|| io::Error::other("missing credentials map"))?);
    let credentials = Array::<_, [u8; 16]>::try_from(&credentials).map_err(io::Error::other)?;
    if credentials.get(&0, 0).map_err(io::Error::other)? != [0; 16] {
        return Err(io::Error::other(
            "network snapshot credentials are not fresh",
        ));
    }
    let parent = Map::Array(parent.ok_or_else(|| io::Error::other("missing parent identity map"))?);
    let parent = Array::<_, [u8; 24]>::try_from(&parent).map_err(io::Error::other)?;
    if parent.get(&0, 0).map_err(io::Error::other)? != [0; 24] {
        return Err(io::Error::other("network snapshot parent is not fresh"));
    }
    let mut identities =
        HashMap::<_, u32, [u8; 24]>::try_from(&mut controller).map_err(io::Error::other)?;
    let environments = Array::<_, [u8; 8208]>::try_from(&environment).map_err(io::Error::other)?;
    if environments.get(&0, 0).map_err(io::Error::other)? != [0; 8208] {
        return Err(io::Error::other(
            "network snapshot environment is not fresh",
        ));
    }
    let mut request = [0; 24];
    request[16..20].copy_from_slice(&pid.to_ne_bytes());
    identities.insert(0, request, 1).map_err(io::Error::other)?; // BPF_NOEXIST

    if agent_sandbox_sysutil::bpf_run_syscall_program(program_fd.as_fd())? != 0 {
        return Err(io::Error::other("kernel rejected network context capture"));
    }
    let identity = identities.get(&0, 0).map_err(io::Error::other)?;
    let environment = environments.get(&0, 0).map_err(io::Error::other)?;
    let mut uids = [0; 4];
    for (uid, bytes) in uids.iter_mut().zip(
        credentials
            .get(&0, 0)
            .map_err(io::Error::other)?
            .as_chunks::<4>()
            .0,
    ) {
        *uid = u32::from_ne_bytes(*bytes);
    }
    let start_ns = u64::from_ne_bytes(identity[..8].try_into().map_err(io::Error::other)?);
    let exec_id = u64::from_ne_bytes(identity[8..16].try_into().map_err(io::Error::other)?);
    let captured_pid = u32::from_ne_bytes(identity[16..20].try_into().map_err(io::Error::other)?);
    let length = u64::from_ne_bytes(environment[8..16].try_into().map_err(io::Error::other)?);
    if captured_pid != pid || start_ns == 0 || identity[20..] != [0; 4] || length > 8192 {
        return Err(io::Error::other("invalid captured network context"));
    }
    let parent = parent.get(&0, 0).map_err(io::Error::other)?;
    let parent_start_ns = u64::from_ne_bytes(parent[..8].try_into().map_err(io::Error::other)?);
    let parent_exec_id = u64::from_ne_bytes(parent[8..16].try_into().map_err(io::Error::other)?);
    let parent_pid = u32::from_ne_bytes(parent[16..20].try_into().map_err(io::Error::other)?);
    if parent_start_ns == 0
        || parent_pid == 0
        || i32::try_from(parent_pid).is_err()
        || parent[20..] != [0; 4]
    {
        return Err(io::Error::other("invalid captured parent identity"));
    }
    let ticks = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)?
        .and_then(|ticks| u64::try_from(ticks).ok())
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| io::Error::other("missing clock tick frequency"))?;
    let parent_start_ticks =
        u64::try_from(u128::from(parent_start_ns) * u128::from(ticks) / 1_000_000_000)
            .map_err(io::Error::other)?;
    let environment =
        environment[16..16 + usize::try_from(length).map_err(io::Error::other)?].to_vec();
    let parsed = crate::context::parse_environ_where(&environment, |_| true);
    let path_claims = crate::context::context_path_claims(&parsed);
    let session_claim = parsed
        .get("AGENT_SANDBOX_SESSION_ID")
        .filter(|value| !value.is_empty())
        .cloned();
    Ok(CapturedNetworkContext {
        pid,
        start_ns,
        exec_id,
        parent_pid,
        parent_start_ns,
        parent_start_ticks,
        parent_exec_id,
        uids,
        environment,
        path_claims,
        session_claim,
    })
}

/// Capture the connected NSS peer with a trusted pinned `init_nss` program.
///
/// Start observing the socket path before connecting, and retain that
/// observation through grant publication. This proves process lifetime and
/// namespace only; callers must separately establish the resolver
/// implementation and file sources. The sibling `transport_policy` pin must
/// share this authority map, which capture freezes before returning.
///
/// # Errors
/// Refuses dead peers, incompatible or reused maps, and failed kernel capture.
/// The caller must run in the initial PID namespace, as with target capture.
pub fn capture_nss_peer(program: &Path, peer: &std::os::unix::net::UnixStream) -> io::Result<u32> {
    require_initial_pid_namespace()?;
    use nix::{
        poll::{PollFd, PollFlags, PollTimeout, poll},
        sys::socket::{getsockopt, sockopt},
    };

    // SO_PEERPIDFD names the socket's original peer even after numeric PID reuse.
    let peer_pidfd = getsockopt(peer, sockopt::PeerPidfd)?;
    let credentials = getsockopt(peer, sockopt::PeerCredentials)?;
    let pid = u32::try_from(credentials.pid()).map_err(io::Error::other)?;
    if pid == 0 {
        return Err(io::Error::other("NSS peer is outside the PID namespace"));
    }
    let info = ProgramInfo::from_pin(program).map_err(io::Error::other)?;
    if info.program_type() as u32 != 31 || info.name() != b"init_nss" {
        return Err(io::Error::other("invalid NSS snapshot program"));
    }
    let program_fd = info.fd().map_err(io::Error::other)?;
    let mut authority = None;
    for id in info
        .map_ids()
        .map_err(io::Error::other)?
        .unwrap_or_default()
    {
        let data = MapData::from_id(id).map_err(io::Error::other)?;
        let map = data.info().map_err(io::Error::other)?;
        if map.name() != b"nss_authority" {
            continue;
        }
        if authority.is_some()
            || map.map_type().map_err(io::Error::other)? != MapType::Array
            || map.key_size() != 4
            || map.value_size() != 40
            || map.max_entries() != 1
        {
            return Err(io::Error::other("invalid NSS snapshot map layout"));
        }
        authority = Some(data);
    }
    let authority = authority.ok_or_else(|| io::Error::other("missing NSS authority map"))?;
    let authority_id = authority.info().map_err(io::Error::other)?.id();
    let transport = ProgramInfo::from_pin(program.with_file_name("transport_policy"))
        .map_err(io::Error::other)?;
    if transport.program_type() as u32 != 18
        || transport.name() != b"transport_polic"
        || !transport
            .map_ids()
            .map_err(io::Error::other)?
            .unwrap_or_default()
            .contains(&authority_id)
    {
        return Err(io::Error::other(
            "NSS authority is not bound to the transport",
        ));
    }
    let authority_fd = authority.fd().as_fd().try_clone_to_owned()?;
    let mut authority = Map::Array(authority);
    let mut authority = Array::<_, [u8; 40]>::try_from(&mut authority).map_err(io::Error::other)?;
    if authority.get(&0, 0).map_err(io::Error::other)? != [0; 40] {
        return Err(io::Error::other("NSS snapshot is not fresh"));
    }
    let mut request = [0; 40];
    request[16..20].copy_from_slice(&pid.to_ne_bytes());
    authority.set(0, request, 0).map_err(io::Error::other)?;
    if agent_sandbox_sysutil::bpf_run_syscall_program(program_fd.as_fd())? != 0 {
        return Err(io::Error::other("kernel rejected NSS capture"));
    }
    let saved = authority.get(&0, 0).map_err(io::Error::other)?;
    if saved[..8] == [0; 8]
        || saved[16..20] != pid.to_ne_bytes()
        || saved[20..24] != [0; 4]
        || saved[24..32] == [0; 8]
    {
        return Err(io::Error::other("invalid captured NSS identity"));
    }
    let mut descriptors = [PollFd::new(peer_pidfd.as_fd(), PollFlags::POLLIN)];
    if poll(&mut descriptors, PollTimeout::ZERO)? != 0 {
        return Err(io::Error::other("NSS peer exited during capture"));
    }
    agent_sandbox_sysutil::bpf_freeze_map(authority_fd.as_fd())?;
    Ok(pid)
}

/// Compile eligible literal IPv4 TCP endpoints from six observed policy layers.
///
/// Layer order is global, package base, package home, home, project, package
/// project. Callers must bind the sources to the captured context and exclude
/// runtime approvals and hostname attribution before publishing these grants.
///
/// # Errors
/// Returns an error for more than 1024 endpoints or invalid policy bytes.
pub fn compile_file_network_grants(
    layers: &[Option<String>; 6],
    endpoints: &[std::net::SocketAddrV4],
) -> io::Result<Vec<std::net::SocketAddrV4>> {
    if endpoints.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many endpoints",
        ));
    }
    let layers = layers
        .iter()
        .map(|data| {
            data.as_deref().map_or_else(
                || Ok(crate::Policy::default()),
                crate::merge_policy::parse_policy,
            )
        })
        .collect::<io::Result<Vec<_>>>()?;
    let policy = crate::merge_layers(&layers);
    Ok(endpoints
        .iter()
        .copied()
        .filter(|endpoint| {
            let host = endpoint.ip().to_string();
            let matches = |rule: &crate::NetworkRule| {
                rule.port == endpoint.port() && crate::host_pattern_matches(&rule.host, &host)
            };
            !policy.network.direct.deny.iter().any(matches)
                && policy.network.direct.allow.iter().any(matches)
        })
        .collect())
}

/// Open the transport rule map from a pinned `transport_policy` program.
///
/// The returned descriptor refers to the outer cgroup-keyed hash-of-maps the
/// transport program consults. Callers retain it across the observation so a
/// pin swap before publication cannot redirect the installed rules.
///
/// # Errors
/// Returns an error for an incompatible program or rule-map layout.
pub fn open_policy_map(program: &Path) -> io::Result<std::os::fd::OwnedFd> {
    let info = ProgramInfo::from_pin(program).map_err(io::Error::other)?;
    for id in info
        .map_ids()
        .map_err(io::Error::other)?
        .unwrap_or_default()
    {
        let data = MapData::from_id(id).map_err(io::Error::other)?;
        let map = data.info().map_err(io::Error::other)?;
        if map.name() != b"policy" {
            continue;
        }
        if map.map_type().map_err(io::Error::other)? != MapType::HashOfMaps
            || map.key_size() != 8
            || map.value_size() != 4
            || map.max_entries() != 1024
        {
            return Err(io::Error::other("invalid transport rule map layout"));
        }
        return data
            .fd()
            .as_fd()
            .try_clone_to_owned()
            .map_err(io::Error::other);
    }
    Err(io::Error::other("missing transport rule map"))
}

/// Install compiled grants as kernel rules for one cgroup.
///
/// Builds a frozen inner map of endpoint rules bound to `controller` and
/// inserts it into the outer `policy` map under `cgroup`, mirroring the
/// transport program's lookup. The epoch must already be published: with no
/// outer entry the transport denies, so any error below stays fail-closed.
/// `controller` is the 24-byte kernel identity (`start_ns`, `exec_id`, `pid`,
/// pad) from the capturing observation.
///
/// # Errors
/// Returns an error for more than 1024 grants or any failed map operation.
/// A failure installs nothing reachable: the inner map is dropped uninserted.
pub fn publish_file_network_grants(
    policy: std::os::fd::BorrowedFd<'_>,
    cgroup: u64,
    controller: &[u8; 24],
    grants: &[std::net::SocketAddrV4],
) -> io::Result<()> {
    if grants.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many endpoints",
        ));
    }
    const HASH: u32 = 1;
    let inner = agent_sandbox_sysutil::bpf_create_map(HASH, 8, 32, 1024)?;
    for grant in grants {
        let mut key = [0_u8; 8];
        key[..4].copy_from_slice(&grant.ip().octets());
        // `struct endpoint.port` is __u32 holding the network-order port.
        key[4..6].copy_from_slice(&grant.port().to_be_bytes());
        let mut rule = [0_u8; 32];
        rule[..24].copy_from_slice(controller);
        rule[24..28].copy_from_slice(&1_u32.to_ne_bytes());
        agent_sandbox_sysutil::bpf_map_update(inner.as_fd(), &key, &rule, 0)?;
    }
    agent_sandbox_sysutil::bpf_freeze_map(inner.as_fd())?;
    agent_sandbox_sysutil::bpf_map_update(
        policy,
        &cgroup.to_ne_bytes(),
        &inner.as_raw_fd().to_ne_bytes(),
        0,
    )
}
#[cfg(test)]
mod tests {
    use super::{compile_file_network_grants, require_initial_pid_namespace};

    #[test]
    fn initial_pid_namespace_check_matches_procfs() {
        let same = std::fs::read_link("/proc/self/ns/pid")
            .ok()
            .zip(std::fs::read_link("/proc/1/ns/pid").ok())
            .is_some_and(|(own, init)| own == init);
        assert_eq!(require_initial_pid_namespace().is_ok(), same);
    }

    #[test]
    fn every_layer_obeys_deny_wins_and_input_limits() {
        let endpoint = "127.0.0.1:443".parse().unwrap();
        let allow = r#"{"network":{"direct":{"allow":[{"host":"127.*","port":443}]}}}"#;
        let deny = r#"{"network":{"direct":{"deny":[{"host":"127.0.0.1","port":443}]}}}"#;
        for allow_layer in 0..6 {
            let mut layers = std::array::from_fn(|_| None);
            layers[allow_layer] = Some(allow.to_owned());
            assert_eq!(
                compile_file_network_grants(&layers, &[endpoint]).unwrap(),
                vec![endpoint]
            );
            for deny_layer in 0..6 {
                let mut denied = layers.clone();
                denied[deny_layer] = Some(deny.to_owned());
                assert!(
                    compile_file_network_grants(&denied, &[endpoint])
                        .unwrap()
                        .is_empty()
                );
            }
        }
        let mut layers = std::array::from_fn(|_| None);
        layers[0] = Some("{".to_owned());
        assert!(compile_file_network_grants(&layers, &[endpoint]).is_err());
        layers[0] = Some(" ".repeat((1 << 20) + 1));
        assert!(compile_file_network_grants(&layers, &[endpoint]).is_err());
        assert!(
            compile_file_network_grants(&std::array::from_fn(|_| None), &[endpoint; 1025]).is_err()
        );
    }
}
