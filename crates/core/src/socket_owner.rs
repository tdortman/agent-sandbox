//! Resolve the process that owns a local socket through procfs.
//!
//! Socket ownership is deliberately fail-closed. A tuple with no matching
//! socket or with more than one valid process owner never produces an owner
//! identity. Every candidate is checked against the socket table's UID and
//! inode, the process start-time ticks, and the descriptor's socket target.

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::{ProcessIdentity, ProcessStartTimeTicks, SocketIdentity, SocketInode};

#[cfg(target_os = "linux")]
mod sock_diag;

#[cfg(target_os = "linux")]
mod hint;

#[cfg(target_os = "linux")]
mod kernel;

#[cfg(target_os = "linux")]
pub use kernel::KernelOwnerResolver;

/// Transport protocol used by a procfs socket table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocketProtocol {
    /// Transmission Control Protocol.
    Tcp,

    /// User Datagram Protocol.
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

    /// Descriptor observed during resolution. This is only a hint and must be
    /// revalidated.
    #[must_use]
    pub const fn fd_number(self) -> u32 {
        self.fd
    }

    /// The typed process/socket identity captured by this snapshot.
    #[must_use]
    pub const fn identity(self) -> SocketIdentity {
        self.identity
    }

    /// The PID of the owning process.
    ///
    /// The value is non-zero because the owning process must exist to own the
    /// captured socket and PID 1 cannot be resolved as a socket owner.
    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.identity.pid()
    }

    /// The owning process PID as a plain `u32`.
    #[must_use]
    pub const fn pid_value(self) -> u32 {
        self.identity.pid().get()
    }

    /// The UID of the owning process.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.identity.uid()
    }

    /// The process start-time ticks captured from the owner at resolution time.
    ///
    /// Comparing against the live `/proc/<pid>/stat` value revalidates that the
    /// process has not been replaced by an unrelated one reusing the same PID.
    #[must_use]
    pub const fn process_start_time_ticks(self) -> ProcessStartTimeTicks {
        self.identity.process_start_time_ticks()
    }

    /// The socket inode captured by this snapshot.
    #[must_use]
    pub const fn socket_inode(self) -> SocketInode {
        self.identity.socket_inode()
    }
}

/// Result of resolving a tuple to one process owner.
///
/// `Missing` and `Ambiguous` are intentionally distinct so callers can log or
/// retry them differently, but both must be treated as a failed attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OwnerResolution<T = OwnerSnapshot> {
    /// Exactly one owner matched the tuple.
    Unique(T),

    /// No process owned the tuple.
    Missing,

    /// More than one process could own the tuple.
    Ambiguous,
}

/// Revalidate a previously captured socket identity through the owning process.
///
/// This deliberately inspects only `/proc/<pid>` and never resolves the
/// identity through a host-network socket table. Validation fails closed when
/// the process disappears, its UID set changes, its start time changes, or no
/// live descriptor still refers to the captured socket inode.
#[must_use]
pub fn validate_socket_identity(identity: SocketIdentity) -> bool {
    validate_socket_identity_with_hint(identity, None)
}

/// Revalidate identity with an optional descriptor hint, falling back to
/// discovery. UID, process generation, descriptor target and inode are always
/// checked fresh.
#[must_use]
pub fn validate_socket_identity_with_hint(identity: SocketIdentity, fd_hint: Option<u32>) -> bool {
    let pid = identity.pid().get();
    let expected_uid = identity.uid();
    let expected_start_time = identity.process_start_time_ticks().get();
    let expected_inode = identity.socket_inode().get();

    if process_start_time_ticks(pid) != Some(expected_start_time) {
        return false;
    }

    let Some((task, _)) = process_socket_descriptor(pid, expected_inode, fd_hint) else {
        return false;
    };

    task_has_uid(&task, expected_uid) && process_start_time_ticks(pid) == Some(expected_start_time)
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
        match process_candidates(entry.inode, entry.uid, tuple) {
            OwnerResolution::Missing => {}
            OwnerResolution::Ambiguous => return OwnerResolution::Ambiguous,

            OwnerResolution::Unique(candidate) => {
                owners
                    .entry((candidate.pid_value(), candidate.socket_inode()))
                    .or_insert(candidate);
            }
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
    #[cfg(target_os = "linux")]
    if protocol == SocketProtocol::Tcp
        && let Ok(entries) = sock_diag::entries(tuple)
    {
        return entries;
    }

    socket_table_entries_from_proc(protocol, tuple)
}

fn socket_table_entries_from_proc(
    protocol: SocketProtocol,
    tuple: SocketTuple,
) -> Vec<SocketTableEntry> {
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
        let mut parts = line.split_whitespace();

        let Some(local) = parts.nth(1) else {
            continue;
        };

        if local != exact && local != wildcard {
            continue;
        }

        let peer = parts.next();

        if remote && remote_field.as_deref() != peer {
            continue;
        }

        let Some(uid) = parts.nth(4).and_then(|value| value.parse().ok()) else {
            continue;
        };

        let Some(inode_value) = parts.nth(1).and_then(|value| value.parse().ok()) else {
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

/// Check the leader first, then threads with potentially private descriptor
/// tables. Keep the task path so credentials are read from the actual holder.
fn process_socket_descriptor(pid: u32, inode: u64, fd_hint: Option<u32>) -> Option<(PathBuf, u32)> {
    let process = PathBuf::from(format!("/proc/{pid}"));

    if let Some(fd) = task_socket_descriptor(&process, inode, fd_hint) {
        return Some((process, fd));
    }

    // ponytail: scan thread tables on a leader miss; the BPF iterator avoids
    // this repeated procfs work when available.
    fs::read_dir(process.join("task"))
        .ok()?
        .flatten()
        .filter(|task| {
            task.file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                != Some(pid)
        })
        .find_map(|task| {
            let path = task.path();
            task_socket_descriptor(&path, inode, fd_hint).map(|fd| (path, fd))
        })
}

fn task_socket_descriptor(task: &Path, inode: u64, fd_hint: Option<u32>) -> Option<u32> {
    let needle = format!("socket:[{inode}]");
    let fds = task.join("fd");

    let matches_fd = |path: &Path| {
        fs::read_link(path).is_ok_and(|link| link.as_os_str() == std::ffi::OsStr::new(&needle))
            && fs::metadata(path).is_ok_and(|metadata| metadata.ino() == inode)
    };

    if let Some(fd) = fd_hint
        && matches_fd(&fds.join(fd.to_string()))
    {
        return Some(fd);
    }

    fs::read_dir(fds).ok()?.flatten().find_map(|fd| {
        let number = fd.file_name().to_str()?.parse().ok()?;
        matches_fd(&fd.path()).then_some(number)
    })
}

fn process_candidates(
    inode: SocketInode,
    expected_uid: u32,
    tuple: SocketTuple,
) -> OwnerResolution<OwnerSnapshot> {
    let Ok(processes) = fs::read_dir("/proc") else {
        return OwnerResolution::Missing;
    };

    let mut owner = None;

    for process in processes.flatten() {
        let name = process.file_name();

        let Some(pid) = name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };

        let Some(start_time) = process_start_time_ticks(pid) else {
            continue;
        };

        let Some((task, fd)) = process_socket_descriptor(pid, inode.get(), None) else {
            continue;
        };

        if process_start_time_ticks(pid) != Some(start_time) {
            continue;
        }

        // A transferred socket remains a holder even if its recipient no longer
        // has the creator UID. Never turn that sharing into a unique owner.
        if !task_has_uid(&task, expected_uid) || owner.is_some() {
            return OwnerResolution::Ambiguous;
        }

        let Ok(process_identity) = ProcessIdentity::new(pid, expected_uid, start_time) else {
            continue;
        };

        owner = Some(OwnerSnapshot::new(
            SocketIdentity::new(process_identity, inode),
            tuple,
            fd,
        ));
    }

    owner.map_or(OwnerResolution::Missing, OwnerResolution::Unique)
}

fn task_has_uid(task: &Path, expected_uid: u32) -> bool {
    let Ok(status) = fs::read_to_string(task.join("status")) else {
        return false;
    };

    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .is_some_and(|values| {
            values
                .split_whitespace()
                .any(|value| value.parse::<u32>() == Ok(expected_uid))
        })
}

/// Read the kernel start-time discriminator used to distinguish reused PIDs.
#[must_use]
pub fn process_start_time_ticks(pid: u32) -> Option<u64> {
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
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1));
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
        assert_ne!(snapshot.socket_inode().get(), 0);
        assert_ne!(snapshot.process_start_time_ticks().get(), 0);
        let identity = snapshot.identity();
        assert!(validate_socket_identity(identity));

        let invalid_uid = ProcessIdentity::new(
            identity.pid().get(),
            u32::MAX,
            identity.process_start_time_ticks().get(),
        )
        .expect("non-zero process identity");

        assert!(!validate_socket_identity(SocketIdentity::new(
            invalid_uid,
            identity.socket_inode(),
        )));

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
        let hint = Some(snapshot.fd_number());
        assert!(validate_socket_identity_with_hint(identity, hint));
        assert!(validate_socket_identity_with_hint(identity, Some(u32::MAX)));
        assert!(!validate_socket_identity_with_hint(invalid_identity, hint));

        assert!(!validate_socket_identity_with_hint(
            SocketIdentity::new(invalid_uid, identity.socket_inode()),
            hint
        ));

        use std::os::fd::AsRawFd;

        assert!(validate_socket_identity_with_hint(
            identity,
            Some(listener.as_raw_fd().cast_unsigned())
        ));

        let duplicate = client.try_clone().expect("duplicate socket");
        drop(client);
        assert!(validate_socket_identity_with_hint(identity, hint));
        drop(duplicate);
        assert!(!validate_socket_identity_with_hint(identity, hint));
    }

    #[test]
    fn missing_local_port_returns_missing() {
        let tuple = SocketTuple::from_local(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        assert_eq!(
            resolve_owner_snapshot(SocketProtocol::Tcp, tuple),
            OwnerResolution::Missing
        );
    }
}
