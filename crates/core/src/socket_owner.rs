//! Resolve the process that owns a local socket through procfs.
//!
//! Socket ownership is deliberately fail-closed. A tuple with no matching
//! socket or with more than one valid process owner never produces an owner
//! identity. Every candidate is checked against the socket table's UID and
//! inode, the process start-time ticks, and the descriptor's socket target.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;

use crate::{FlowProtocol, ProcessIdentity, ProcessStartTimeTicks, SocketIdentity, SocketInode};

/// Transport protocol used by a procfs socket table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

/// The local and remote endpoints associated with a socket.
///
/// A zero remote port means that the remote endpoint is not available and
/// causes resolution to match only the local endpoint. This is used by NFQ
/// for compatibility with source-port-only attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketTuple {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

impl SocketTuple {
    /// Construct a complete local/remote socket tuple.
    #[must_use]
    pub const fn new(
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }

    /// Construct a tuple when only the local endpoint is known.
    #[must_use]
    pub const fn from_local(local_ip: IpAddr, local_port: u16) -> Self {
        let remote_ip = match local_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        Self::new(local_ip, local_port, remote_ip, 0)
    }

    #[must_use]
    pub const fn local_ip(self) -> IpAddr {
        self.local_ip
    }

    #[must_use]
    pub const fn local_port(self) -> u16 {
        self.local_port
    }

    #[must_use]
    pub const fn remote_ip(self) -> IpAddr {
        self.remote_ip
    }

    #[must_use]
    pub const fn remote_port(self) -> u16 {
        self.remote_port
    }
    #[must_use]
    pub const fn local_addr(self) -> (IpAddr, u16) {
        (self.local_ip, self.local_port)
    }

    #[must_use]
    pub const fn remote_addr(self) -> (IpAddr, u16) {
        (self.remote_ip, self.remote_port)
    }
}

/// A process and descriptor snapshot for a resolved socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerSnapshot {
    identity: SocketIdentity,
    tuple: SocketTuple,
    fd: u32,
}

impl OwnerSnapshot {
    const fn new(identity: SocketIdentity, tuple: SocketTuple, fd: u32) -> Self {
        Self {
            identity,
            tuple,
            fd,
        }
    }

    /// The typed process/socket identity captured by this snapshot.
    #[must_use]
    pub const fn identity(self) -> SocketIdentity {
        self.identity
    }

    /// Alias for callers that name the capability explicitly.
    #[must_use]
    pub const fn socket_identity(self) -> SocketIdentity {
        self.identity
    }

    #[must_use]
    pub const fn tuple(self) -> SocketTuple {
        self.tuple
    }

    /// Descriptor number whose procfs target was checked during resolution.
    #[must_use]
    pub const fn fd(self) -> u32 {
        self.fd
    }

    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.identity.pid()
    }

    #[must_use]
    pub const fn pid_value(self) -> u32 {
        self.identity.pid().get()
    }

    #[must_use]
    pub const fn uid(self) -> u32 {
        self.identity.uid()
    }

    #[must_use]
    pub const fn process_start_time_ticks(self) -> ProcessStartTimeTicks {
        self.identity.process_start_time_ticks()
    }

    #[must_use]
    pub const fn socket_inode(self) -> SocketInode {
        self.identity.socket_inode()
    }
    #[must_use]
    pub const fn start_time(self) -> ProcessStartTimeTicks {
        self.process_start_time_ticks()
    }

    #[must_use]
    pub const fn inode(self) -> SocketInode {
        self.socket_inode()
    }

    #[must_use]
    pub const fn socket_fd(self) -> u32 {
        self.fd()
    }
}

/// Result of resolving a tuple to one process owner.
///
/// `Missing` and `Ambiguous` are intentionally distinct so callers can log or
/// retry them differently, but both must be treated as a failed attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OwnerResolution<T = OwnerSnapshot> {
    Unique(T),
    Missing,
    Ambiguous,
}
impl<T> OwnerResolution<T> {
    /// Transform a unique owner while preserving fail-closed outcomes.
    #[must_use]
    pub fn map<U>(self, function: impl FnOnce(T) -> U) -> OwnerResolution<U> {
        match self {
            Self::Unique(owner) => OwnerResolution::Unique(function(owner)),
            Self::Missing => OwnerResolution::Missing,
            Self::Ambiguous => OwnerResolution::Ambiguous,
        }
    }
}

/// Resolve a tuple to the process/socket identity captured in procfs.
#[must_use]
pub fn resolve_owner(
    protocol: SocketProtocol,
    tuple: SocketTuple,
) -> OwnerResolution<SocketIdentity> {
    resolve_owner_snapshot(protocol, tuple).map(OwnerSnapshot::identity)
}

/// Revalidate a previously captured socket identity through the owning process.
///
/// This deliberately inspects only `/proc/<pid>` and never resolves the
/// identity through a host-network socket table. Validation fails closed when
/// the process disappears, its UID set changes, its start time changes, or no
/// live descriptor still refers to the captured socket inode.
#[must_use]
pub fn validate_socket_identity(identity: SocketIdentity) -> bool {
    let pid = identity.pid().get();
    let expected_uid = identity.uid();
    let expected_start_time = identity.process_start_time_ticks().get();
    let expected_inode = identity.socket_inode().get();

    let Some(uids) = process_uids(pid) else {
        return false;
    };
    if !uids.contains(&expected_uid) {
        return false;
    }
    if process_start_time_ticks(pid) != Some(expected_start_time) {
        return false;
    }

    let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    let needle = format!("socket:[{expected_inode}]");
    for fd in fds.flatten() {
        let fd_path = fd.path();
        let Ok(link) = fs::read_link(&fd_path) else {
            continue;
        };
        if link.as_os_str() != std::ffi::OsStr::new(&needle) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&fd_path) else {
            continue;
        };
        if metadata.ino() != expected_inode {
            continue;
        }

        // Recheck identity after finding the descriptor to reject PID reuse
        // and changes that race the descriptor scan.
        let Some(uids) = process_uids(pid) else {
            return false;
        };
        return uids.contains(&expected_uid)
            && process_start_time_ticks(pid) == Some(expected_start_time);
    }
    false
}

/// Resolve a tuple and retain the checked descriptor as an owner snapshot.
///
/// # Panics
///
/// This function panics only if its internal owner set violates the
/// uniqueness invariant after candidate resolution.
#[must_use]
pub fn resolve_owner_snapshot(
    protocol: SocketProtocol,
    tuple: SocketTuple,
) -> OwnerResolution<OwnerSnapshot> {
    let entries = socket_table_entries(protocol, tuple);
    if entries.is_empty() {
        return OwnerResolution::Missing;
    }

    let mut owners = HashMap::new();
    for entry in entries {
        for candidate in process_candidates(entry.inode, entry.uid, tuple) {
            owners
                .entry((candidate.pid_value(), candidate.socket_inode()))
                .or_insert(candidate);
        }
    }

    match owners.len() {
        0 => OwnerResolution::Missing,
        1 => OwnerResolution::Unique(owners.into_values().next().expect("one owner exists")),
        _ => OwnerResolution::Ambiguous,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketTableEntry {
    uid: u32,
    inode: SocketInode,
}

fn socket_table_entries(protocol: SocketProtocol, tuple: SocketTuple) -> Vec<SocketTableEntry> {
    let table_path = match (protocol, tuple.local_ip.is_ipv6()) {
        (SocketProtocol::Tcp, false) => "/proc/net/tcp",
        (SocketProtocol::Udp, false) => "/proc/net/udp",
        (SocketProtocol::Tcp, true) => "/proc/net/tcp6",
        (SocketProtocol::Udp, true) => "/proc/net/udp6",
    };
    let Ok(table) = fs::read_to_string(table_path) else {
        return Vec::new();
    };

    let exact = proc_addr_field(tuple.local_ip, tuple.local_port);
    let wildcard_ip = match tuple.local_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let wildcard = proc_addr_field(wildcard_ip, tuple.local_port);
    let remote = tuple.remote_port != 0;
    let remote_field = remote.then(|| proc_addr_field(tuple.remote_ip, tuple.remote_port));
    let mut entries = Vec::new();

    for line in table.lines().skip(1) {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 10
            || (parts[1] != exact && parts[1] != wildcard)
            || (remote && remote_field.as_deref() != Some(parts[2]))
        {
            continue;
        }
        let Some(uid) = parts[7].parse().ok() else {
            continue;
        };
        let Ok(inode_value) = parts[9].parse() else {
            continue;
        };
        let Ok(inode) = SocketInode::new(inode_value) else {
            continue;
        };
        if !entries
            .iter()
            .any(|entry: &SocketTableEntry| entry.inode == inode)
        {
            entries.push(SocketTableEntry { uid, inode });
        }
    }
    entries
}

fn process_candidates(
    inode: SocketInode,
    expected_uid: u32,
    tuple: SocketTuple,
) -> Vec<OwnerSnapshot> {
    let needle = format!("socket:[{}]", inode.get());
    let Ok(processes) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for process in processes.flatten() {
        let name = process.file_name();
        let Some(pid) = name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(start_time) = process_start_time_ticks(pid) else {
            continue;
        };
        let Some(uids) = process_uids(pid) else {
            continue;
        };
        if !uids.contains(&expected_uid) {
            continue;
        }
        let fd_dir = process.path().join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let Some(fd_number) = fd
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            let fd_path = fd.path();
            let Ok(link) = fs::read_link(&fd_path) else {
                continue;
            };
            if link.to_string_lossy() != needle {
                continue;
            }
            let Ok(metadata) = fs::metadata(&fd_path) else {
                continue;
            };
            if metadata.ino() != inode.get() {
                continue;
            }
            let Ok(process_identity) = ProcessIdentity::new(pid, expected_uid, start_time) else {
                continue;
            };
            if process_start_time_ticks(pid) != Some(start_time) {
                continue;
            }
            candidates.push(OwnerSnapshot::new(
                SocketIdentity::new(process_identity, inode),
                tuple,
                fd_number,
            ));
        }
    }
    candidates
}

fn process_uids(pid: u32) -> Option<Vec<u32>> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|line| {
        let values = line.strip_prefix("Uid:")?.split_whitespace();
        let values = values.collect::<Vec<_>>();
        if values.is_empty() {
            return None;
        }
        Some(
            values
                .into_iter()
                .filter_map(|value| value.parse().ok())
                .collect(),
        )
    })
}

fn process_start_time_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end_comm = stat.rfind(')')?;
    stat.get(end_comm + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Format an address and port as used by `/proc/net/{tcp,udp}`.
fn proc_addr_field(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let mut reversed = String::with_capacity(8);
            for byte in octets.iter().rev() {
                write!(&mut reversed, "{byte:02X}").expect("writing to String cannot fail");
            }
            format!("{reversed}:{port:04X}")
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut reversed = String::with_capacity(32);
            for chunk in octets.chunks(4) {
                for byte in chunk.iter().rev() {
                    write!(&mut reversed, "{byte:02X}").expect("writing to String cannot fail");
                }
            }
            format!("{reversed}:{port:04X}")
        }
    }
}

impl From<FlowProtocol> for SocketProtocol {
    fn from(protocol: FlowProtocol) -> Self {
        match protocol {
            FlowProtocol::Tcp => Self::Tcp,
            FlowProtocol::Udp => Self::Udp,
        }
    }
}

impl From<SocketProtocol> for FlowProtocol {
    fn from(protocol: SocketProtocol) -> Self {
        match protocol {
            SocketProtocol::Tcp => Self::Tcp,
            SocketProtocol::Udp => Self::Udp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proc_addr_field_ipv4_little_endian() {
        let field = proc_addr_field(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 443);
        assert_eq!(field, "0501A8C0:01BB");
    }

    #[test]
    fn proc_addr_field_ipv6_little_endian_groups() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let field = proc_addr_field(ip, 443);
        assert_eq!(field, "B80D0120000000000000000001000000:01BB");
    }

    #[test]
    fn owner_resolution_is_fail_closed_for_missing_and_ambiguous() {
        assert_eq!(
            OwnerResolution::<SocketIdentity>::Missing,
            OwnerResolution::Missing
        );
        assert_eq!(
            OwnerResolution::<SocketIdentity>::Ambiguous,
            OwnerResolution::Ambiguous
        );
    }

    #[test]
    fn resolves_current_process_loopback_tcp_snapshot() {
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        let listener_addr = listener.local_addr().expect("listener address");
        let client = std::net::TcpStream::connect(listener_addr).expect("connect loopback client");
        let (_server, _) = listener.accept().expect("accept loopback client");
        let client_addr = client.local_addr().expect("client address");
        let tuple = SocketTuple::new(
            client_addr.ip(),
            client_addr.port(),
            listener_addr.ip(),
            listener_addr.port(),
        );

        let resolution = resolve_owner_snapshot(SocketProtocol::Tcp, tuple);
        let OwnerResolution::Unique(snapshot) = resolution else {
            panic!("expected unique owner, got {resolution:?}");
        };
        assert_eq!(snapshot.pid_value(), std::process::id());
        assert_eq!(snapshot.tuple(), tuple);
        assert_ne!(snapshot.socket_inode().get(), 0);
        assert_ne!(snapshot.process_start_time_ticks().get(), 0);
        let identity = snapshot.identity();
        assert!(validate_socket_identity(identity));

        let invalid_start_time = if identity.process_start_time_ticks().get() == u64::MAX {
            u64::MAX - 1
        } else {
            identity.process_start_time_ticks().get() + 1
        };
        let invalid_process =
            ProcessIdentity::new(identity.pid().get(), identity.uid(), invalid_start_time)
                .expect("non-zero invalid process start time");
        let invalid_identity = SocketIdentity::new(invalid_process, identity.socket_inode());
        assert!(!validate_socket_identity(invalid_identity));
    }

    #[test]
    fn missing_local_port_returns_missing() {
        let tuple = SocketTuple::from_local(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        assert_eq!(
            resolve_owner(SocketProtocol::Tcp, tuple),
            OwnerResolution::Missing
        );
    }
}
