mod policy_client;

pub use policy_client::{PersistentPolicyClient, check_filesystem, check_resource, check_target};

use agent_sandbox_core::{FileAccess, ResourceAccess, ResourceKind};
use agent_sandbox_syscall::policy::nr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
/// `SECCOMP_IOW(2, __u64)` — not `IOWR` like SEND; argument is a single u64 id.
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
pub const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

/// `struct seccomp_notif_addfd` passed to `SECCOMP_IOCTL_NOTIF_ADDFD`.
/// Layout matches the Linux UAPI: a fixed-order tuple of u64/u32 fields
/// with no implicit padding on 64-bit targets.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// Layout of the tracee's `struct msghdr` for the SENDMSG and SENDMMSG
// broker path. The `msg_name` field at offset 0 carries the sockaddr
// pointer and the `msg_namelen` field at offset 8 carries its length.
// `MSGHDR_LEN` is the size of the prefix we read. Values assume 64-bit
// LP64 and are verified at compile time against the libc layout below.
#[cfg(target_pointer_width = "64")]
const MSG_NAME_OFFSET: usize = 0;
#[cfg(target_pointer_width = "64")]
const MSG_NAMELEN_OFFSET: usize = 8;
#[cfg(target_pointer_width = "64")]
const MSGHDR_LEN: usize = 56;

#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::offset_of;
    assert!(offset_of!(libc::msghdr, msg_name) == MSG_NAME_OFFSET);
    assert!(offset_of!(libc::msghdr, msg_namelen) == MSG_NAMELEN_OFFSET);
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Network mediation mode selected by the trusted launcher.
///
/// `Direct` preserves transport policy RPC checks. `Proxy` lets the
/// transparent proxy own only the configured HTTP(S) service-port
/// `AF_INET`/`AF_INET6` connect/send decisions; other network destinations
/// remain gated by seccomp user notification. Unix resources and filesystem
/// mediation remain unchanged in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Direct,
    Proxy,
}

impl std::str::FromStr for NetworkMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct" => Ok(Self::Direct),
            "proxy" => Ok(Self::Proxy),
            _ => Err(format!(
                "invalid network mode {value:?}; expected exactly \"direct\" or \"proxy\""
            )),
        }
    }
}

/// Parse the required launcher mode, failing closed for missing or unknown
/// values instead of silently selecting a transport policy.
///
/// # Errors
///
/// Returns an error when `value` is missing or is not `direct` or `proxy`.
pub fn parse_network_mode(value: Option<&str>) -> Result<NetworkMode, String> {
    value
        .ok_or_else(|| "network mode is required (direct or proxy)".to_owned())?
        .parse()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTarget {
    pub host: String,
    pub connect_host: String,
    pub port: u16,
    pub scheme: String,
}

/// Resource access target from a sandboxed syscall: a Unix-domain socket
/// path or a device node gated independently of network policy.
///
/// The `raw` field carries the captured sockaddr bytes read from the
/// tracee during target parsing, so the broker never re-reads
/// pointer-bearing args after policy approval (which would be
/// TOCTOU-racy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTarget {
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
    /// Captured raw bytes from the tracee's sockaddr (for `AF_UNIX`) or
    /// the resolved path bytes (for device opens). Used during
    /// emulation instead of re-reading tracee memory.
    pub raw: Vec<u8>,
    /// Captured open flags for device opens. Set during target parsing
    /// so the broker never re-reads the tracee's `open_how` after
    /// policy approval. For `AF_UNIX` targets, this is 0.
    pub open_flags: i32,
    /// Captured open mode for device opens. Set during target parsing.
    /// For `AF_UNIX` targets, this is 0.
    pub open_mode: u32,
}

/// Filesystem mutation target from a sandboxed syscall: one or more path
/// and access pairs checked via policyd's `CheckFilesystem` RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemTarget {
    pub checks: Vec<(PathBuf, FileAccess)>,
}

/// Classified target of a notified syscall, driving broker dispatch.
///
/// Network targets go through the `Check` RPC, resource targets through
/// `CheckResource`, filesystem targets through `CheckFilesystem`, `Errno`
/// completes the syscall with that errno, and `None` means continue with no
/// further work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallTarget {
    Network(NetworkTarget),
    Resource(ResourceTarget),
    Filesystem(FilesystemTarget),
    Errno(i32),
    None,
}
/// Parsed `AF_UNIX` address: a filesystem path or a kernel abstract name.
///
/// Abstract names are encoded as either `@abstract:<text>` (when the name
/// is printable UTF-8, so rules like `nv_target_process_*` match) or
/// `@hex:<lower-hex>` (fallback for binary names). Both survive JSON
/// round-trips and match verbatim in policyd's resource rule engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixAddress {
    Path(String),
    AbstractHex(String),
}

/// Parsed sockaddr: either an Internet (`AF_INET`/`AF_INET6`) endpoint or a
/// Unix-domain (`AF_UNIX`) address, paired with the raw bytes so callers can
/// re-derive fields the high-level enum drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockaddrTarget {
    Inet { ip: IpAddr, port: u16 },
    Unix { address: UnixAddress, raw: Vec<u8> },
}

/// Hex-encode a byte slice as lowercase ASCII, no `0x` prefix.
/// ponytail: inlined instead of pulling the `hex` crate for ~20 lines.
fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}
/// Format a kernel abstract socket name for use as a policy key.
///
/// Printable UTF-8 names become `@abstract:<text>` so users can write glob
/// rules (`nv_target_process_*`). Binary names fall back to `@hex:<hex>` to
/// stay byte-stable when the name is not valid text.
fn format_abstract_name(name: &[u8]) -> String {
    if name.is_empty() {
        return "@hex:".to_string();
    }
    if let Ok(s) = std::str::from_utf8(name)
        && s.bytes().all(|b| b >= 0x20 && b != 0x7f)
    {
        return format!("@abstract:{s}");
    }
    format!("@hex:{}", hex_encode_lower(name))
}

/// Return true when `notif.data.arch` matches the broker's native audit arch.
#[must_use]
pub const fn notification_arch_valid(notif: &SeccompNotif) -> bool {
    notif.data.arch == agent_sandbox_syscall::policy::AUDIT_ARCH_NATIVE
}

/// Verify that a notification id is still valid before responding.
///
/// The kernel returns `EINVAL` when the id was recycled or the tracee died.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_ID_VALID` ioctl fails.
pub fn notif_id_valid(listener_fd: i32, id: u64) -> io::Result<()> {
    let mut id = id;
    agent_sandbox_sysutil::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &mut id)
}

/// Receive a seccomp notification from the listener fd.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_RECV` ioctl fails.
pub fn recv_notification(listener_fd: i32) -> io::Result<SeccompNotif> {
    let mut notif = SeccompNotif::default();
    agent_sandbox_sysutil::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif)?;
    Ok(notif)
}

/// Send a `SECCOMP_USER_NOTIF_FLAG_CONTINUE` response, allowing the syscall.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_SEND` ioctl fails.
pub fn send_continue(listener_fd: i32, id: u64) -> io::Result<()> {
    notif_id_valid(listener_fd, id)?;
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    agent_sandbox_sysutil::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp)
}

/// Inject an error return value into the tracee's syscall result.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_SEND` ioctl fails.
pub fn send_errno(listener_fd: i32, id: u64, errno: i32) -> io::Result<()> {
    notif_id_valid(listener_fd, id)?;
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    agent_sandbox_sysutil::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp)
}

/// Inject a success return value into the tracee's syscall result.
///
/// Used to complete emulated syscalls (e.g. `connect`/`sendto` performed
/// by the broker on the tracee's behalf): `val` is the syscall return value.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_SEND` ioctl fails.
pub fn send_result(listener_fd: i32, id: u64, val: i64) -> io::Result<()> {
    notif_id_valid(listener_fd, id)?;
    let mut resp = SeccompNotifResp {
        id,
        val,
        error: 0,
        flags: 0,
    };
    agent_sandbox_sysutil::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp)
}

/// Duplicate a broker-held fd into the tracee as the syscall result.
///
/// `SECCOMP_ADDFD_FLAG_SEND` makes the kernel atomically install the fd
/// into the tracee's fd table AND complete the notification in one step,
/// so no follow-up `SECCOMP_IOCTL_NOTIF_SEND` is required.
///
/// Used to emulate `open`/`openat`/`openat2`/`creat` of policy-allowed
/// resources: the broker opens the device with its own privileges and hands
/// the resulting fd to the tracee, so the tracee never performs the open
/// directly.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_ADDFD` ioctl fails.
pub fn send_addfd(listener_fd: i32, id: u64, srcfd: i32, cloexec: bool) -> io::Result<()> {
    notif_id_valid(listener_fd, id)?;
    let mut addfd = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: u32::try_from(srcfd).unwrap_or(u32::MAX),
        newfd: 0,
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    agent_sandbox_sysutil::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &mut addfd)
}
/// Returns true for tracee memory read failures that are routine races (tracee
/// exited, ptrace scope, another tracer such as `nsys`, notification recycled)
/// rather than broker bugs.
#[must_use]
pub fn is_transient_tracee_io_err(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EPERM | libc::EACCES | libc::ESRCH | libc::ENOENT)
    )
}

/// Read `len` bytes from the tracee's address space at `addr`.
///
/// # Errors
///
/// Returns an error if `process_vm_readv` and the `/proc/<pid>/mem` fallback
/// both fail (e.g. the process is gone or the address is invalid).
pub use agent_sandbox_sysutil::read_tracee_bytes;

/// Look up the actual `SO_TYPE` of a tracee socket via `pidfd_open` +
/// `pidfd_getfd`. Returns `None` on any failure (process gone, fd not a
/// socket, kernel too old for the syscalls, etc.) so the caller can fall
/// back to a per-syscall default.
fn get_socket_type(pid: u32, sockfd: i32) -> Option<i32> {
    let dup = agent_sandbox_sysutil::dup_tracee_fd(pid, sockfd).ok()?;
    agent_sandbox_sysutil::socket_type(&dup)
}

/// Map a `SO_TYPE` value to a URL scheme. DGRAM sockets are UDP; everything
/// else (STREAM, RAW, SEQPACKET, ...) is reported as TCP for policy purposes,
/// because policyd only knows those two schemes today.
const fn scheme_for_socket_type(sock_type: i32) -> &'static str {
    if sock_type == libc::SOCK_DGRAM {
        "udp"
    } else {
        "tcp"
    }
}

/// Resolve the URL scheme for a tracee fd. Tries `get_socket_type` first;
/// on any failure, returns the per-syscall default. `sockfd` comes from
/// `notif.data.args[0]` for sendto/sendmsg/sendmmsg/connect.
fn scheme_for_fd(notif: &SeccompNotif, sockfd: u64, default: &str) -> String {
    let Some(sockfd_i32) = i32::try_from(sockfd).ok() else {
        return default.to_owned();
    };
    get_socket_type(notif.pid, sockfd_i32)
        .map_or(default, |sock_type| scheme_for_socket_type(sock_type))
        .to_owned()
}
/// Parse a raw sockaddr buffer into a `SockaddrTarget`.
///
/// Supports `AF_INET`/`AF_INET6` (`IpAddr` + port) and `AF_UNIX`
/// (filesystem path or kernel abstract-namespace name). `addrlen` is the
/// tracee-supplied sockaddr length; for abstract Unix names the policy key
/// uses the full `addrlen` span (including embedded NULs), not C-string
/// truncation. Returns `None` for any other family or a buffer too short
/// to hold the family prefix.
#[must_use]
pub fn parse_sockaddr(bytes: &[u8], addrlen: usize) -> Option<SockaddrTarget> {
    let addrlen = addrlen.min(bytes.len());
    if addrlen < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match i32::from(family) {
        libc::AF_INET if addrlen >= 16 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(ip),
                port,
            })
        }
        libc::AF_INET6 if addrlen >= 28 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            })
        }
        libc::AF_UNIX => {
            let raw = bytes[..addrlen].to_vec();
            if addrlen <= 2 {
                // Empty path: unnamed Unix socket. Treat as no target.
                return None;
            }
            // Abstract namespace: the first byte of `sun_path` is NUL.
            if bytes[2] == 0 {
                // Abstract names CAN contain embedded NULs. The kernel uses
                // `addrlen`, not a C string, to bound the name. Use the full
                // span so the policy key matches the emulated connect target.
                let name_end = addrlen.min(bytes.len());
                let name = if name_end > 3 {
                    &bytes[3..name_end]
                } else {
                    &[]
                };
                let key = format_abstract_name(name);
                Some(SockaddrTarget::Unix {
                    address: UnixAddress::AbstractHex(key),
                    raw,
                })
            } else {
                // Filesystem path: NUL-terminated C string in sun_path.
                let path_end = addrlen.min(bytes.len());
                let path_bytes = &bytes[2..path_end];
                let end = path_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(path_bytes.len());
                let path = std::str::from_utf8(&path_bytes[..end]).ok()?.to_owned();
                Some(SockaddrTarget::Unix {
                    address: UnixAddress::Path(path),
                    raw,
                })
            }
        }
        _ => None,
    }
}

/// Extract a target from a `connect` syscall notification.
///
/// `connect` on an `AF_INET`/`AF_INET6` sockaddr yields a `Network` target
/// routed through the `Check` RPC. `connect` on an `AF_UNIX` sockaddr yields
/// a `Resource` target of kind `UnixSocket` with `Connect` access.
///
/// # Errors
///
/// Returns an error if reading tracee memory via `process_vm_readv` fails.
pub fn target_from_connect(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let scheme = scheme_for_fd(notif, notif.data.args[0], "tcp");
    sockaddr_target(
        notif,
        notif.data.args[1],
        notif.data.args[2],
        &scheme,
        ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
    )
}
/// Extract a target from a `sendto` syscall notification.
///
/// `sendto` on an `AF_INET`/`AF_INET6` sockaddr yields a `Network` target
/// routed through the `Check` RPC. `sendto` on an `AF_UNIX` sockaddr yields
/// a `Resource` target of kind `UnixSocket` with `Send` access. A connected
/// socket calling `sendto` with a null `dest_addr` returns `None` because no
/// policy decision can be made from the syscall args alone (the socket is
/// already connected and the destination is fixed by the prior `connect`).
///
/// # Errors
///
/// Returns an error if reading tracee memory via `process_vm_readv` fails.
pub fn target_from_sendto(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let scheme = scheme_for_fd(notif, notif.data.args[0], "udp");
    sockaddr_target(
        notif,
        notif.data.args[4],
        notif.data.args[5],
        &scheme,
        ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Send),
    )
}

/// Extracted name pointer and length from a `msghdr` structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MsghdrParts {
    name: u64,
    name_len: u32,
}
/// Extract the `(name_ptr, name_len)` pair from a raw `msghdr` buffer read
/// from the tracee. Returns `None` if the buffer is too short to contain
/// both the pointer and the length, or if the name pointer is null.
#[cfg(target_pointer_width = "64")]
fn parse_msghdr_target(bytes: &[u8]) -> Option<MsghdrParts> {
    if bytes.len() < MSG_NAMELEN_OFFSET + 4 {
        return None;
    }
    let name = u64::from_ne_bytes(
        bytes[MSG_NAME_OFFSET..MSG_NAME_OFFSET + 8]
            .try_into()
            .expect("checked length above"),
    );
    if name == 0 {
        return None;
    }
    let name_len = u32::from_ne_bytes(
        bytes[MSG_NAMELEN_OFFSET..MSG_NAMELEN_OFFSET + 4]
            .try_into()
            .expect("checked length above"),
    );
    Some(MsghdrParts { name, name_len })
}

/// Extract a target from a `sendmsg` syscall notification.
///
/// `sendmsg` on an `AF_UNIX` sockaddr yields a `Resource` target of kind
/// `UnixSocket` with `Send` access. `sendmsg` on an `AF_INET`/`AF_INET6`
/// sockaddr yields a `Network` target. A `sendmsg` with a null `msg_name`
/// returns `None`: the socket is already connected and the message has no
/// destination address to policy-check, so the broker continues the syscall.
///
/// # Errors
///
/// Returns an error if reading the tracee's `msghdr` or sockaddr via
/// `process_vm_readv` fails.
pub fn target_from_sendmsg(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let msg = notif.data.args[1];
    if msg == 0 {
        return Ok(None);
    }
    let bytes = read_tracee_bytes(notif.pid, msg, MSGHDR_LEN)?;
    let Some(mhdr) = parse_msghdr_target(&bytes) else {
        return Ok(None);
    };
    let scheme = scheme_for_fd(notif, notif.data.args[0], "udp");
    sockaddr_target(
        notif,
        mhdr.name,
        u64::from(mhdr.name_len),
        &scheme,
        ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Send),
    )
}

/// Extract a target from a `sendmmsg` syscall notification.
///
/// `sendmmsg` sends a vector of messages. When the batch carries more than
/// one distinct destination address the broker denies the syscall: only the
/// first message was historically policy-checked while the whole batch would
/// run under `CONTINUE`, which is a TOCTOU/multi-destination bypass.
///
/// # Errors
///
/// Returns an error if reading tracee memory via `process_vm_readv` fails.
pub fn target_from_sendmmsg(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let msgvec = notif.data.args[1];
    let vlen = usize::try_from(notif.data.args[2]).unwrap_or(0);
    if msgvec == 0 || vlen == 0 {
        return Ok(None);
    }
    if vlen > 1 {
        let destinations = sendmmsg_destination_bytes(notif, msgvec, vlen)?;
        if destinations.len() > 1 {
            let Some(first) = destinations.first() else {
                return Ok(None);
            };
            if destinations.iter().any(|dest| dest != first) {
                return Ok(Some(SyscallTarget::Errno(libc::EACCES)));
            }
        }
        if destinations.is_empty() {
            return Ok(None);
        }
    }
    target_from_sendmsg(&SeccompNotif {
        data: SeccompData {
            args: [notif.data.args[0], msgvec, notif.data.args[3], 0, 0, 0],
            ..notif.data
        },
        ..*notif
    })
}

#[cfg(target_pointer_width = "64")]
const MMSGHDR_LEN: usize = 64;

/// Read destination sockaddr bytes for each non-null `msg_name` in a batch.
#[cfg(target_pointer_width = "64")]
fn sendmmsg_destination_bytes(
    notif: &SeccompNotif,
    msgvec: u64,
    vlen: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let mut destinations = Vec::new();
    for index in 0..vlen.min(1024) {
        let offset = msgvec.saturating_add(u64::try_from(index * MMSGHDR_LEN).unwrap_or(u64::MAX));
        let entry = read_tracee_bytes(notif.pid, offset, MMSGHDR_LEN)?;
        let Some(mhdr) = parse_msghdr_target(&entry) else {
            continue;
        };
        let name_len = usize::try_from(mhdr.name_len).unwrap_or(0);
        if name_len == 0 {
            continue;
        }
        let bytes = read_tracee_bytes(notif.pid, mhdr.name, name_len.min(128))?;
        destinations.push(bytes);
    }
    Ok(destinations)
}

#[cfg(not(target_pointer_width = "64"))]
fn sendmmsg_destination_bytes(
    _notif: &SeccompNotif,
    _msgvec: u64,
    vlen: usize,
) -> io::Result<Vec<Vec<u8>>> {
    if vlen > 1 {
        return Ok(vec![vec![1], vec![2]]);
    }
    Ok(Vec::new())
}

/// Parse a tracee sockaddr buffer and classify it. `Inet` results become a
/// `Network` target (gated by policyd's `Check` RPC) and `Unix` results
/// become a `Resource` target of kind `UnixSocket` gated by `CheckResource`.
/// `access` selects `Connect` (for `connect`) or `Send` (for
/// `sendto`/`sendmsg`/`sendmmsg`).
fn sockaddr_target(
    notif: &SeccompNotif,
    addr: u64,
    addr_len: u64,
    scheme: &str,
    access: ResourceAccess,
) -> io::Result<Option<SyscallTarget>> {
    let addr_len = usize::try_from(addr_len).unwrap_or(0);
    if addr == 0 || addr_len == 0 {
        return Ok(None);
    }
    let bytes = read_tracee_bytes(notif.pid, addr, addr_len.min(128))?;
    let Some(sockaddr) = parse_sockaddr(&bytes, addr_len) else {
        return Ok(None);
    };

    let target = match sockaddr {
        // Port 0 means "unspecified" in sockaddr_in(6). We cannot form a
        // meaningful policy key (and must never prompt for `host:0`), so
        // skip gating here and let the tracee run the syscall. NFQUEUE still
        // enforces egress on the real destination port from the packet header.
        SockaddrTarget::Inet { port: 0, .. } => return Ok(None),
        SockaddrTarget::Inet { ip, port } => SyscallTarget::Network(NetworkTarget {
            host: ip.to_string(),
            connect_host: ip.to_string(),
            port,
            scheme: scheme.to_string(),
        }),
        SockaddrTarget::Unix { address, raw } => {
            let path = match address {
                UnixAddress::Path(p) => normalize_unix_path(Path::new(&p)),
                // Abstract namespace names are hex-encoded strings (@hex:...),
                // not filesystem paths, but ride in the same PathBuf field and
                // serde-serialize as strings for policyd's Path::New matching.
                UnixAddress::AbstractHex(h) => PathBuf::from(h),
            };
            SyscallTarget::Resource(ResourceTarget {
                kind: ResourceKind::UnixSocket,
                path,
                access,
                raw,
                open_flags: 0,
                open_mode: 0,
            })
        }
    };
    Ok(Some(target))
}

fn filesystem_target(checks: Vec<(PathBuf, FileAccess)>) -> Option<SyscallTarget> {
    if checks.is_empty() {
        None
    } else {
        Some(SyscallTarget::Filesystem(FilesystemTarget { checks }))
    }
}

fn normalize_check_path(path: &Path) -> PathBuf {
    normalize_unix_path(path)
}

fn filesystem_checks_rename(old: &Path, new: &Path) -> Option<SyscallTarget> {
    filesystem_target(vec![
        (normalize_check_path(old), FileAccess::ReadWrite),
        (normalize_check_path(new), FileAccess::ReadWrite),
    ])
}

fn filesystem_checks_link(old: &Path, new: &Path) -> Option<SyscallTarget> {
    filesystem_target(vec![
        (normalize_check_path(old), FileAccess::ReadWrite),
        (normalize_check_path(new), FileAccess::ReadWrite),
    ])
}

fn filesystem_checks_symlink(target: Option<&Path>, linkpath: &Path) -> Option<SyscallTarget> {
    let mut checks = Vec::new();
    if let Some(target) = target {
        checks.push((normalize_check_path(target), FileAccess::Read));
    }
    checks.push((normalize_check_path(linkpath), FileAccess::Write));
    filesystem_target(checks)
}

fn filesystem_checks_unlink(path: &Path) -> Option<SyscallTarget> {
    filesystem_target(vec![(normalize_check_path(path), FileAccess::Write)])
}

fn filesystem_checks_truncate(path: &Path) -> Option<SyscallTarget> {
    filesystem_target(vec![(normalize_check_path(path), FileAccess::Write)])
}

/// Read a NUL-terminated path pointer from the tracee. Returns `None` for a
/// null pointer or non-UTF-8 path.
fn read_tracee_path_ptr(pid: u32, path_ptr: u64) -> io::Result<Option<PathBuf>> {
    if path_ptr == 0 {
        return Ok(None);
    }
    let bytes = read_tracee_bytes(pid, path_ptr, 4096)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(std::str::from_utf8(&bytes[..end]).ok().map(PathBuf::from))
}

/// Resolve a relative tracee path against `dirfd` or cwd (`AT_FDCWD`).
fn resolve_tracee_path(pid: u32, dirfd: u64, path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }
    let base = tracee_open_dir_base(pid, dirfd)?;
    Ok(resolve_open_path(&path, &base, false))
}

fn resolve_symlink_target(target: Option<PathBuf>, linkpath: &Path) -> Option<PathBuf> {
    let target = target?;
    if target.is_absolute() {
        Some(target)
    } else {
        Some(
            linkpath
                .parent()
                .map_or_else(|| target.clone(), |parent| parent.join(&target)),
        )
    }
}

/// Resolve a tracee `(dirfd, path)` pair the same way the open-family helpers do.
fn read_resolved_path_arg(pid: u32, dirfd: u64, path_ptr: u64) -> io::Result<Option<PathBuf>> {
    let Some(path) = read_tracee_path_ptr(pid, path_ptr)? else {
        return Ok(None);
    };
    Ok(Some(resolve_tracee_path(pid, dirfd, path)?))
}

/// Resolve `/proc/<pid>/fd/<fd>` for an open tracee descriptor.
fn tracee_fd_path(pid: u32, fd: u64) -> io::Result<PathBuf> {
    let link = format!("/proc/{pid}/fd/{fd}");
    std::fs::read_link(link)
}

/// Generate a two-path filesystem-mutation target extractor (`rename`/`link`).
///
/// Indices are passed as integer literals and dereferenced inside the macro
/// so the `notif` binding resolves under the macro's own hygiene.
macro_rules! fs_two_path_target {
    ($name:ident, $check:ident, cwd, $old_idx:expr, cwd, $new_idx:expr) => {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        fn $name(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
            let old = read_resolved_path_arg(notif.pid, at_fdcwd_arg(), notif.data.args[$old_idx])?;
            let new = read_resolved_path_arg(notif.pid, at_fdcwd_arg(), notif.data.args[$new_idx])?;
            Ok(match (old, new) {
                (Some(o), Some(n)) => $check(&o, &n),
                _ => None,
            })
        }
    };
    ($name:ident, $check:ident, arg($od:expr), $old_idx:expr, arg($nd:expr), $new_idx:expr) => {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        fn $name(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
            let old =
                read_resolved_path_arg(notif.pid, notif.data.args[$od], notif.data.args[$old_idx])?;
            let new =
                read_resolved_path_arg(notif.pid, notif.data.args[$nd], notif.data.args[$new_idx])?;
            Ok(match (old, new) {
                (Some(o), Some(n)) => $check(&o, &n),
                _ => None,
            })
        }
    };
}
fs_two_path_target!(target_from_rename, filesystem_checks_rename, cwd, 0, cwd, 1);
fs_two_path_target!(
    target_from_renameat_family,
    filesystem_checks_rename,
    arg(0),
    1,
    arg(2),
    3
);
fs_two_path_target!(target_from_link, filesystem_checks_link, cwd, 0, cwd, 1);
fs_two_path_target!(
    target_from_linkat,
    filesystem_checks_link,
    arg(0),
    1,
    arg(2),
    3
);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn target_from_symlink(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let target = read_tracee_path_ptr(notif.pid, notif.data.args[0])?;
    let linkpath = read_resolved_path_arg(notif.pid, at_fdcwd_arg(), notif.data.args[1])?;
    Ok(linkpath.and_then(|linkpath| {
        let target = resolve_symlink_target(target, &linkpath);
        filesystem_checks_symlink(target.as_deref(), &linkpath)
    }))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn target_from_symlinkat(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let target = read_tracee_path_ptr(notif.pid, notif.data.args[0])?;
    let linkpath = read_resolved_path_arg(notif.pid, notif.data.args[1], notif.data.args[2])?;
    Ok(linkpath.and_then(|linkpath| {
        let target = resolve_symlink_target(target, &linkpath);
        filesystem_checks_symlink(target.as_deref(), &linkpath)
    }))
}

/// Generate a single-path filesystem-mutation target extractor
/// (`unlink`/`truncate`). See [`fs_two_path_target`] for the index hygiene.
macro_rules! fs_path_target {
    ($name:ident, $check:ident, cwd, $arg_idx:expr) => {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        fn $name(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
            let path =
                read_resolved_path_arg(notif.pid, at_fdcwd_arg(), notif.data.args[$arg_idx])?;
            Ok(path.and_then(|p| $check(&p)))
        }
    };
    ($name:ident, $check:ident, arg($d:expr), $arg_idx:expr) => {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        fn $name(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
            let path =
                read_resolved_path_arg(notif.pid, notif.data.args[$d], notif.data.args[$arg_idx])?;
            Ok(path.and_then(|p| $check(&p)))
        }
    };
}
fs_path_target!(target_from_unlink, filesystem_checks_unlink, cwd, 0);
fs_path_target!(target_from_unlinkat, filesystem_checks_unlink, arg(0), 1);
fs_path_target!(target_from_truncate, filesystem_checks_truncate, cwd, 0);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn target_from_ftruncate(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let fd = notif.data.args[0];
    let path = tracee_fd_path(notif.pid, fd)?;
    Ok(filesystem_checks_truncate(&path))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn target_from_filesystem_mutation(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    match i64::from(notif.data.nr) {
        nr::RENAME => target_from_rename(notif),
        nr::RENAMEAT | nr::RENAMEAT2 => target_from_renameat_family(notif),
        nr::LINK => target_from_link(notif),
        nr::LINKAT => target_from_linkat(notif),
        nr::SYMLINK => target_from_symlink(notif),
        nr::SYMLINKAT => target_from_symlinkat(notif),
        nr::UNLINK => target_from_unlink(notif),
        nr::UNLINKAT => target_from_unlinkat(notif),
        nr::TRUNCATE => target_from_truncate(notif),
        nr::FTRUNCATE => target_from_ftruncate(notif),
        _ => Ok(None),
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn target_from_filesystem_mutation(_notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    Ok(None)
}

/// Re-read filesystem mutation paths and verify they still match the
/// snapshot taken at classification time.
///
/// # Errors
///
/// Returns an error when path re-resolution fails or the live paths differ
/// from the captured `FilesystemTarget`. Callers should deny the syscall.
///
/// Residual TOCTOU: directory entry identity can still change between this
/// check and kernel execution because mutation syscalls cannot be emulated.
pub fn revalidate_filesystem_mutation(
    notif: &SeccompNotif,
    target: &FilesystemTarget,
) -> io::Result<()> {
    let Some(fresh) = target_from_filesystem_mutation(notif)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem mutation paths no longer resolve",
        ));
    };
    let SyscallTarget::Filesystem(fresh_target) = fresh else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "notification no longer classifies as filesystem mutation",
        ));
    };
    if fresh_target.checks != target.checks {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "filesystem mutation paths changed after policy check",
        ));
    }
    Ok(())
}

/// Route a notification to the target extractor based on syscall number.
///
/// Network-egress syscalls (`connect`/`sendto`/`sendmsg`/`sendmmsg`)
/// are classified by the sockaddr they target. Resource-open syscalls
/// (`open`/`openat`/`openat2`/`creat`) are classified by the path they
/// target: `/dev` paths become a `Resource` target of kind `Device`,
/// except for a built-in bypass list of safe devices the broker always
/// continues without a policy check. Filesystem mutation syscalls are
/// classified into path/access checks against policyd's filesystem gate.
/// `io_uring_*` syscalls are denied with `ENOSYS` so runtimes fall back to
/// ordinary syscalls that seccomp/fanotify can mediate.
///
/// # Errors
///
/// Returns an error if the underlying target extraction (reading tracee
/// memory or resolving tracee paths/fds) fails.
pub fn target_from_notification(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    match i64::from(notif.data.nr) {
        nr::SENDTO => target_from_sendto(notif),
        nr::CONNECT => target_from_connect(notif),
        nr::SENDMSG => target_from_sendmsg(notif),
        nr::SENDMMSG => target_from_sendmmsg(notif),
        nr::OPEN | nr::OPENAT | nr::OPENAT2 | nr::CREAT => Ok(target_from_open(notif)),
        nr::IO_URING_SETUP | nr::IO_URING_ENTER | nr::IO_URING_REGISTER => {
            Ok(Some(SyscallTarget::Errno(libc::ENOSYS)))
        }
        _ => target_from_filesystem_mutation(notif),
    }
}

/// Canonicalize a filesystem path by resolving symlinks. Used for `AF_UNIX`
/// socket paths and device paths so policy rules match consistently
/// regardless of which symlink alias the tracee used (e.g. `/var/run`
/// resolves to `/run`). Falls back to the original path if canonicalization
/// fails (e.g. the socket file does not exist yet).
fn normalize_unix_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Built-in bypass list of `/dev` paths the broker always continues without
/// a policy check. These are safe, side-effect-free devices that every
/// sandboxed runtime expects to open without prompting.
const DEVICE_BYPASS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/full",
    "/dev/tty",
];

/// Check whether `path` refers to a block or character device by examining
/// the file type via `stat`. A missing path (`ENOENT`/`ENOTDIR`) is a
/// definitively non-device target (e.g. `open(O_CREAT)` of a new file), so it
/// returns `Some(false)`. Any other error (permission, I/O) leaves the type
/// indeterminate and returns `None`.
#[cfg(test)]
fn device_file_type(path: &Path) -> Option<bool> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(path) {
        Ok(meta) => Some(meta.file_type().is_block_device() || meta.file_type().is_char_device()),
        Err(err) if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => Some(false),
        Err(_) => None,
    }
}

/// Whether an open syscall should be resource-gated as a device node.
///
/// Regular files and directories return false; fanotify/policyd handle those.
/// When `stat` fails on a non-`/dev` path we treat it as non-device and let
/// the open continue so fanotify can decide — fail-closed `stat` here caused
/// instant `EACCES` on `opendir`/`ls` with no fsmon log line.
fn is_device_node_for_resource_gate(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path).map_or_else(
        |_| path.starts_with("/dev"),
        |meta| meta.file_type().is_block_device() || meta.file_type().is_char_device(),
    )
}

/// Legacy helper retained for tests that assert device classification behavior.
#[cfg(test)]
fn is_device_file(path: &Path) -> bool {
    is_device_node_for_resource_gate(path)
}

/// Return true if `path` is on the device bypass list, under `/dev/pts/`
/// (any pty device the kernel assigns), or an fd alias under `/dev/fd`.
/// The broker continues these opens directly because they are structurally
/// safe and unavoidable for interactive agents.
fn is_device_bypass(path: &Path) -> bool {
    if DEVICE_BYPASS.iter().any(|d| Path::new(d) == path) {
        return true;
    }
    path == Path::new("/dev/pts")
        || path.starts_with("/dev/pts/")
        || path == Path::new("/dev/fd")
        || path.starts_with("/dev/fd/")
}

/// Classify an `open`/`openat`/`openat2`/`creat` notification.
///
/// Only non-bypass device nodes are gated: they become `Resource(Device)`
/// for a policy check and TOCTOU-safe broker-side `ADDFD` emulation (the
/// broker re-opens the resolved path it captured, so the tracee cannot swap
/// the pointer after approval). Regular files, directories, and bypass devices
/// continue unmodified — their access is covered by fanotify/fsmon, and
/// emulating every open would proxy all file I/O through the broker (which
/// breaks the dynamic linker and is a severe performance regression).
///
/// If the tracee path cannot be read, or `stat` is inconclusive on a
/// non-`/dev` path, the open is allowed to continue so fanotify can gate it.
fn target_from_open(notif: &SeccompNotif) -> Option<SyscallTarget> {
    let Ok(Some(raw_path)) = read_tracee_open_path(notif) else {
        return None;
    };
    let path = normalize_unix_path(&raw_path);
    if !is_device_node_for_resource_gate(&path) {
        return None;
    }
    if is_device_bypass(&path) {
        return None;
    }
    let (open_flags, open_mode) = read_tracee_open_flags_mode(notif);
    let raw = path.to_string_lossy().into_owned().into_bytes();

    let acc = open_flags & libc::O_ACCMODE;
    let access = if acc == libc::O_WRONLY {
        ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Write)
    } else if acc == libc::O_RDWR {
        ResourceAccess::Device(agent_sandbox_core::DeviceAccess::ReadWrite)
    } else {
        ResourceAccess::Device(agent_sandbox_core::DeviceAccess::Read)
    };
    Some(SyscallTarget::Resource(ResourceTarget {
        kind: ResourceKind::Device,
        path,
        access,
        raw,
        open_flags,
        open_mode,
    }))
}

const RESOLVE_IN_ROOT: u64 = 0x10;

/// Resolve an open-family path against the directory base that the kernel will
/// use. Plain absolute paths stay absolute. `openat2(RESOLVE_IN_ROOT)` scopes
/// even absolute paths under `dir_base`, so `/kvm` with `dirfd=/dev` resolves
/// as `/dev/kvm`.
fn resolve_open_path(path: &Path, dir_base: &Path, absolute_in_dir: bool) -> PathBuf {
    if path.is_absolute() {
        if absolute_in_dir {
            return dir_base.join(path.strip_prefix("/").unwrap_or(path));
        }
        path.to_path_buf()
    } else {
        dir_base.join(path)
    }
}

/// True when `dirfd` is the `AT_FDCWD` sentinel (-100). Seccomp stores
/// syscall args as u64 with the register's sign extension.
fn is_at_fdcwd(dirfd: u64) -> bool {
    dirfd.cast_signed() == i64::from(libc::AT_FDCWD)
}

fn at_fdcwd_arg() -> u64 {
    i64::from(libc::AT_FDCWD).cast_unsigned()
}

/// Resolve the tracee directory used for a relative open-family path: cwd for
/// `AT_FDCWD`, otherwise the path of the dirfd via `/proc/<pid>/fd/<n>`.
fn tracee_open_dir_base(pid: u32, dirfd: u64) -> io::Result<PathBuf> {
    let link = if is_at_fdcwd(dirfd) {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    std::fs::read_link(link)
}

/// Resolve the path the tracee passed to `open`/`openat`/`openat2`/`creat`.
/// `open(path, ...)`, `openat(dirfd, path, ...)`, and `openat2(dirfd, path,
/// how, size)` all carry the path as args[1] (a pointer). `open` and `creat`
/// carry it as args[0]. Relative names are joined against the tracee cwd or
/// `dirfd` directory before callers canonicalize or classify the target.
/// Returns `None` if the pointer is null or the path is not valid UTF-8 (treat
/// as no target).
fn read_tracee_open_path(notif: &SeccompNotif) -> io::Result<Option<PathBuf>> {
    let nr_val = i64::from(notif.data.nr);
    let path_arg = if nr_val == nr::OPEN || nr_val == nr::CREAT {
        notif.data.args[0]
    } else {
        // openat / openat2: args[0] is dirfd, args[1] is pathname.
        notif.data.args[1]
    };
    if path_arg == 0 {
        return Ok(None);
    }
    // Read up to PATH_MAX (4096) bytes, then truncate at the first NUL.
    let bytes = read_tracee_bytes(notif.pid, path_arg, 4096)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let Some(path) = std::str::from_utf8(&bytes[..end]).ok().map(PathBuf::from) else {
        return Ok(None);
    };
    let dirfd = if nr_val == nr::OPEN || nr_val == nr::CREAT {
        at_fdcwd_arg()
    } else {
        notif.data.args[0]
    };
    let absolute_in_dir = nr_val == nr::OPENAT2
        && openat2_resolve_flags(notif).is_ok_and(|r| r & RESOLVE_IN_ROOT != 0);
    if path.is_absolute() && !absolute_in_dir {
        return Ok(Some(path));
    }
    let base = tracee_open_dir_base(notif.pid, dirfd)?;
    Ok(Some(resolve_open_path(&path, &base, absolute_in_dir)))
}

fn openat2_resolve_flags(notif: &SeccompNotif) -> io::Result<u64> {
    let how_ptr = notif.data.args[2];
    if how_ptr == 0 {
        return Ok(0);
    }
    let bytes = read_tracee_bytes(notif.pid, how_ptr, 24)?;
    if bytes.len() < 24 {
        return Ok(0);
    }
    Ok(u64::from_ne_bytes(
        bytes[16..24].try_into().expect("checked length"),
    ))
}

/// Extract the raw `(flags, mode)` from an open-family notification at
/// target-parsing time. This captures the exact flags and mode the tracee
/// requested, including reading `struct open_how` for `openat2`, so the
/// broker never re-reads these pointer-bearing args after policy approval.
/// For `creat`, returns `O_WRONLY | O_CREAT | O_TRUNC` with the tracee's mode.
fn read_tracee_open_flags_mode(notif: &SeccompNotif) -> (i32, u32) {
    let nr_val = i64::from(notif.data.nr);
    match nr_val {
        nr::OPEN => (
            i32::try_from(notif.data.args[1]).unwrap_or(libc::O_RDONLY),
            u32::try_from(notif.data.args[2]).unwrap_or(0),
        ),
        nr::CREAT => (
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            u32::try_from(notif.data.args[1]).unwrap_or(0),
        ),
        nr::OPENAT => (
            i32::try_from(notif.data.args[2]).unwrap_or(libc::O_RDONLY),
            u32::try_from(notif.data.args[3]).unwrap_or(0),
        ),
        _ => {
            // openat2: args[2] points to struct open_how { flags, mode, resolve }.
            let how_ptr = notif.data.args[2];
            if how_ptr == 0 {
                return (libc::O_RDONLY, 0);
            }
            let Ok(bytes) = read_tracee_bytes(notif.pid, how_ptr, 16) else {
                return (libc::O_RDONLY, 0);
            };
            if bytes.len() < 16 {
                return (libc::O_RDONLY, 0);
            }
            let flags = i32::try_from(u64::from_ne_bytes(
                bytes[..8].try_into().expect("checked length"),
            ))
            .unwrap_or(libc::O_RDONLY);
            let mode = u32::try_from(u64::from_ne_bytes(
                bytes[8..16].try_into().expect("checked length"),
            ))
            .unwrap_or(0);
            (flags, mode)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FileAccess, FilesystemTarget, SECCOMP_IOCTL_NOTIF_ADDFD, SECCOMP_IOCTL_NOTIF_ID_VALID,
        SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND, SeccompData, SeccompNotif,
        SockaddrTarget, SyscallTarget, UnixAddress, at_fdcwd_arg, device_file_type,
        filesystem_checks_link, filesystem_checks_rename, filesystem_checks_symlink,
        filesystem_checks_truncate, filesystem_checks_unlink, hex_encode_lower, is_at_fdcwd,
        is_device_bypass, is_device_file, is_device_node_for_resource_gate,
        notification_arch_valid, parse_sockaddr, read_resolved_path_arg, resolve_open_path,
        resolve_tracee_path, revalidate_filesystem_mutation, scheme_for_socket_type,
        target_from_notification, tracee_fd_path, tracee_open_dir_base,
    };

    use agent_sandbox_syscall::policy::nr;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};

    #[test]
    fn network_mode_requires_exact_trusted_values() {
        assert_eq!(
            super::parse_network_mode(Some("direct")),
            Ok(super::NetworkMode::Direct)
        );
        assert_eq!(
            super::parse_network_mode(Some("proxy")),
            Ok(super::NetworkMode::Proxy)
        );
        assert!(super::parse_network_mode(None).is_err());
        assert!(super::parse_network_mode(Some("DIRECT")).is_err());
        assert!(super::parse_network_mode(Some("sandbox")).is_err());
    }

    #[test]
    fn transient_tracee_io_err_classifies_expected_errno() {
        assert!(super::is_transient_tracee_io_err(
            &std::io::Error::from_raw_os_error(libc::EPERM)
        ));
        assert!(super::is_transient_tracee_io_err(
            &std::io::Error::from_raw_os_error(libc::EACCES)
        ));
        assert!(super::is_transient_tracee_io_err(
            &std::io::Error::from_raw_os_error(libc::ESRCH)
        ));
        assert!(!super::is_transient_tracee_io_err(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
    }

    #[test]
    fn seccomp_ioctl_numbers_match_linux_uapi() {
        // SECCOMP_IOC_MAGIC = 0x21; see include/uapi/linux/seccomp.h.
        fn ioc(dir: u32, nr: u32, size: u32) -> libc::c_ulong {
            libc::c_ulong::from((dir << 30) | (0x21 << 8) | nr | (size << 16))
        }
        const IOREWR: u32 = 3;
        const IOW: u32 = 1;
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, ioc(IOREWR, 0, 80));
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, ioc(IOREWR, 1, 24));
        // ID_VALID is IOW(2, __u64), not IOREWR like SEND — mixing them up
        // makes every send_continue fail with EINVAL.
        assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, ioc(IOW, 2, 8));
        assert_eq!(SECCOMP_IOCTL_NOTIF_ADDFD, ioc(IOW, 3, 24));
    }

    #[test]
    fn parse_ipv4_sockaddr() {
        let bytes = [2, 0, 0, 53, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&bytes, bytes.len()),
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 53
            })
        );
    }

    #[test]
    fn parse_ipv4_sockaddr_port_zero() {
        // Port 0 in a sockaddr is 'unspecified'. sockaddr_target drops these
        // before sending a Check RPC. parse_sockaddr still returns the raw
        // value so the caller can decide.
        let bytes = [2, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&bytes, bytes.len()),
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 0
            })
        );
    }
    #[test]
    fn inet_sockaddr_skips_port_zero_gating() {
        let bytes = [2, 0, 0, 0, 75, 101, 254, 170, 0, 0, 0, 0, 0, 0, 0, 0];
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("parses");
        let SockaddrTarget::Inet { port, .. } = parsed else {
            panic!("expected inet");
        };
        assert_eq!(port, 0);
        // sockaddr_target would return Ok(None) for port 0; we only test the
        // parsed shape here because target extraction needs a live tracee.
    }

    #[test]
    fn scheme_for_socket_type_dgram_is_udp() {
        assert_eq!(scheme_for_socket_type(libc::SOCK_DGRAM), "udp");
    }

    #[test]
    fn scheme_for_socket_type_stream_is_tcp() {
        assert_eq!(scheme_for_socket_type(libc::SOCK_STREAM), "tcp");
    }

    #[test]
    fn scheme_for_socket_type_raw_and_seqpacket_are_tcp() {
        // Policyd only knows tcp/udp today; raw and seqpacket default to tcp.
        assert_eq!(scheme_for_socket_type(libc::SOCK_RAW), "tcp");
        assert_eq!(scheme_for_socket_type(libc::SOCK_SEQPACKET), "tcp");
    }

    #[test]
    fn parse_unix_sockaddr_path() {
        // AF_UNIX (family=1), path "/tmp/agent-sandbox.sock".
        let mut bytes = vec![1, 0]; // sa_family = AF_UNIX
        let path = b"/tmp/agent-sandbox.sock";
        bytes.extend_from_slice(path);
        bytes.push(0); // NUL terminator
        bytes.resize(32, 0); // pad to a realistic length
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX path parses");
        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(
                    address,
                    UnixAddress::Path("/tmp/agent-sandbox.sock".to_string())
                );
                assert_eq!(raw.len(), 32);
            }
            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_abstract_printable_uses_decoded_text() {
        // Printable UTF-8 abstract names become `@abstract:<text>` so glob
        // rules like `nv_target_process_*` match the decoded name.
        let mut bytes = vec![1, 0, 0]; // family + abstract marker
        bytes.extend_from_slice(b"nv_target_process_1104286");
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX abstract parses");
        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(
                    address,
                    UnixAddress::AbstractHex("@abstract:nv_target_process_1104286".into())
                );
                assert_eq!(raw, bytes);
            }
            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_abstract_uses_addrlen_not_nul_truncation() {
        // Abstract names can contain embedded NULs. The policy key must use
        // the full addrlen span so it matches the emulated connect target.
        let mut bytes = vec![1, 0, 0]; // family + abstract marker
        bytes.extend_from_slice(b"agent\x00sandbox");
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX abstract parses");
        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(
                    address,
                    UnixAddress::AbstractHex("@hex:6167656e740073616e64626f78".into())
                );
                assert_eq!(raw, bytes);
            }
            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_abstract_binary_falls_back_to_hex() {
        // Non-UTF-8 or control-byte names keep the `@hex:` form so the key
        // stays byte-stable when there is no printable text to decode.
        let mut bytes = vec![1, 0, 0]; // family + abstract marker
        bytes.extend_from_slice(&[0xff, 0xab, 0x01]);
        let parsed = parse_sockaddr(&bytes, bytes.len()).expect("AF_UNIX abstract parses");
        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                assert_eq!(address, UnixAddress::AbstractHex("@hex:ffab01".into()));
                assert_eq!(raw, bytes);
            }
            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_unnamed_is_none() {
        // AF_UNIX with empty sun_path: unnamed socket.
        let bytes = [1, 0];
        assert_eq!(parse_sockaddr(&bytes, bytes.len()), None);
    }

    #[test]
    fn hex_encode_lower_matches_hex_crate() {
        // Ponytail: inlined encoder must match the canonical lowercase
        // hex alphabet so policyd's @hex: keys are byte-stable.
        assert_eq!(hex_encode_lower(b""), "");
        assert_eq!(hex_encode_lower(&[0x00, 0xff, 0xab, 0x10]), "00ffab10");
        assert_eq!(hex_encode_lower(b"agent"), "6167656e74");
    }

    #[test]
    fn device_file_type_fails_closed_on_missing_path() {
        assert_eq!(
            device_file_type(Path::new("/definitely/not/a/device-node")),
            Some(false)
        );
        assert_eq!(
            device_file_type(Path::new("/definitely/not/a/device-node/evil")),
            Some(false)
        );
    }

    #[test]
    fn notification_arch_valid_accepts_native_audit_arch() {
        let notif = SeccompNotif {
            data: SeccompData {
                arch: agent_sandbox_syscall::policy::AUDIT_ARCH_NATIVE,
                ..SeccompData::default()
            },
            ..SeccompNotif::default()
        };
        assert!(notification_arch_valid(&notif));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn notification_arch_valid_rejects_compat_audit_arch() {
        use agent_sandbox_syscall::policy::{AUDIT_ARCH_I686, AUDIT_ARCH_X86_32};
        for arch in [AUDIT_ARCH_X86_32, AUDIT_ARCH_I686, 0] {
            let notif = SeccompNotif {
                data: SeccompData {
                    arch,
                    ..SeccompData::default()
                },
                ..SeccompNotif::default()
            };
            assert!(
                !notification_arch_valid(&notif),
                "compat/non-native arch {arch:#x} must be rejected"
            );
        }
    }

    #[test]
    fn open_of_regular_file_continues_unmodified() {
        let path = std::env::temp_dir().join(format!(
            "agent-sandbox-syscall-broker-open-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, b"open-target").expect("write temp file");
        let path_str = path.to_string_lossy().into_owned();
        let cpath = std::ffi::CString::new(path_str.as_str()).expect("nul-free path");
        let notif = SeccompNotif {
            pid: std::process::id(),
            data: SeccompData {
                nr: i32::try_from(nr::OPEN).expect("open nr"),
                args: [
                    cpath.as_ptr().cast::<u8>() as u64,
                    libc::O_RDONLY as u64,
                    0,
                    0,
                    0,
                    0,
                ],
                ..SeccompData::default()
            },
            ..SeccompNotif::default()
        };
        std::mem::forget(cpath);
        let target = target_from_notification(&notif).expect("classify open");
        assert!(
            target.is_none(),
            "regular file open must continue unmodified (not gated), got {target:?}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn open_of_directory_continues_unmodified() {
        let path = std::env::temp_dir().join(format!(
            "agent-sandbox-syscall-broker-opendir-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        let path_str = path.to_string_lossy().into_owned();
        let cpath = std::ffi::CString::new(path_str.as_str()).expect("nul-free path");
        let notif = SeccompNotif {
            pid: std::process::id(),
            data: SeccompData {
                nr: i32::try_from(nr::OPENAT).expect("openat nr"),
                args: [
                    i64::from(libc::AT_FDCWD).cast_unsigned(),
                    cpath.as_ptr().cast::<u8>() as u64,
                    (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                    0,
                    0,
                    0,
                ],
                ..SeccompData::default()
            },
            ..SeccompNotif::default()
        };
        std::mem::forget(cpath);
        let target = target_from_notification(&notif).expect("classify openat");
        assert!(
            target.is_none(),
            "directory open must continue to fanotify, got {target:?}"
        );
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn inconclusive_stat_on_non_dev_path_continues_open() {
        assert!(!is_device_node_for_resource_gate(Path::new(
            "/definitely/not/a/device-node"
        )));
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn revalidate_filesystem_mutation_accepts_stable_paths() {
        let notif = SeccompNotif {
            pid: std::process::id(),
            data: SeccompData {
                nr: i32::try_from(nr::UNLINK).expect("unlink nr"),
                args: {
                    let path = std::ffi::CString::new("/tmp/agent-sandbox-revalidate-stable")
                        .expect("nul-free path");
                    let arg0 = path.as_ptr().cast::<u8>() as u64;
                    std::mem::forget(path);
                    [arg0, 0, 0, 0, 0, 0]
                },
                ..SeccompData::default()
            },
            ..SeccompNotif::default()
        };
        let target = target_from_notification(&notif).expect("classify unlink");
        let Some(SyscallTarget::Filesystem(fs_target)) = target else {
            panic!("expected filesystem target");
        };
        revalidate_filesystem_mutation(&notif, &fs_target).expect("stable paths revalidate");
    }

    #[test]
    fn device_bypass_list_matches_safe_devices() {
        for path in [
            "/dev/null",
            "/dev/zero",
            "/dev/urandom",
            "/dev/random",
            "/dev/full",
            "/dev/tty",
        ] {
            assert!(
                is_device_bypass(Path::new(path)),
                "{path} should be bypassed"
            );
        }
        assert!(is_device_bypass(Path::new("/dev/pts")));
        assert!(is_device_bypass(Path::new("/dev/pts/0")));
        assert!(is_device_bypass(Path::new("/dev/pts/42")));
    }

    #[test]
    fn device_bypass_rejects_real_devices() {
        assert!(!is_device_bypass(Path::new("/dev/dri/card0")));
        assert!(!is_device_bypass(Path::new("/dev/nvidia0")));
        assert!(!is_device_bypass(Path::new("/dev/video0")));
        assert!(!is_device_bypass(Path::new("/dev/sda")));
        assert!(!is_device_bypass(Path::new("/etc/hosts")));
        assert!(!is_device_bypass(Path::new("/dev")));
    }

    #[test]
    fn resolve_open_path_relative_under_dev_dir() {
        let resolved = resolve_open_path(Path::new("kvm"), Path::new("/dev"), false);
        assert_eq!(resolved, Path::new("/dev/kvm"));
        // Without dirfd resolution a bare "kvm" would not classify as a device.
        assert!(!is_device_file(Path::new("kvm")));
        assert!(is_device_file(&resolved));
    }

    #[test]
    fn resolve_open_path_absolute_ignores_dir_base() {
        assert_eq!(
            resolve_open_path(Path::new("/dev/kvm"), Path::new("/tmp"), false),
            Path::new("/dev/kvm")
        );
    }

    #[test]
    fn resolve_open_path_in_root_scopes_absolute_path_to_dirfd() {
        assert_eq!(
            resolve_open_path(Path::new("/kvm"), Path::new("/dev"), true),
            Path::new("/dev/kvm")
        );
        assert_eq!(
            resolve_open_path(Path::new("/"), Path::new("/dev"), true),
            Path::new("/dev/")
        );
    }

    #[test]
    fn is_at_fdcwd_recognizes_sentinel() {
        assert!(is_at_fdcwd(at_fdcwd_arg()));
        assert!(!is_at_fdcwd(3));
    }

    #[test]
    fn tracee_open_dir_base_at_fdcwd_reads_cwd() {
        let cwd = std::env::current_dir().expect("cwd");
        let base = tracee_open_dir_base(std::process::id(), at_fdcwd_arg()).expect("tracee cwd");
        assert_eq!(base, cwd);
    }

    #[test]
    fn tracee_open_dir_base_reads_open_dirfd() {
        let dir = std::env::temp_dir().join(format!(
            "agent-sandbox-syscall-broker-dirfd-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).expect("create temp dir");
        let dir_file = fs::File::open(&dir).expect("open temp dir");

        let base = tracee_open_dir_base(
            std::process::id(),
            u64::try_from(dir_file.as_raw_fd()).expect("non-negative dir fd"),
        )
        .expect("tracee dirfd");
        assert_eq!(base, dir);
        assert_eq!(
            resolve_open_path(Path::new("kvm"), &base, false),
            dir.join("kvm")
        );

        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    #[test]
    fn dev_fd_paths_are_bypassed_as_fd_aliases() {
        // /dev/fd and /dev/fd/<num> are fd aliases (equivalent to dup-ing
        // an already-open fd via /proc/self/fd), not device nodes that need
        // resource approval. The broker must continue these without
        // prompting; actual file access stays governed by bwrap/fanotify.
        assert!(is_device_bypass(Path::new("/dev/fd")));
        assert!(is_device_bypass(Path::new("/dev/fd/0")));
        assert!(is_device_bypass(Path::new("/dev/fd/1")));
        assert!(is_device_bypass(Path::new("/dev/fd/2")));
        assert!(is_device_bypass(Path::new("/dev/fd/63")));
        assert!(is_device_bypass(Path::new("/dev/fd/1023")));
    }

    #[test]
    fn filesystem_checks_rename_requires_read_write_on_both_paths() {
        let target = filesystem_checks_rename(Path::new("/tmp/old.txt"), Path::new("/tmp/new.txt"))
            .expect("rename target");
        let SyscallTarget::Filesystem(FilesystemTarget { checks }) = target else {
            panic!("expected filesystem target");
        };
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].1, FileAccess::ReadWrite);
        assert_eq!(checks[1].1, FileAccess::ReadWrite);
        assert!(checks[0].0.ends_with("old.txt"));
        assert!(checks[1].0.ends_with("new.txt"));
    }

    #[test]
    fn filesystem_checks_link_requires_read_write_on_both_paths() {
        let target = filesystem_checks_link(Path::new("/tmp/src"), Path::new("/tmp/dst"))
            .expect("link target");
        let SyscallTarget::Filesystem(FilesystemTarget { checks }) = target else {
            panic!("expected filesystem target");
        };
        assert_eq!(
            checks,
            vec![
                (PathBuf::from("/tmp/src"), FileAccess::ReadWrite),
                (PathBuf::from("/tmp/dst"), FileAccess::ReadWrite),
            ]
        );
    }

    /// Mirrors `dispatch_filesystem_target`: every `(path, access)` must pass
    /// before the broker may continue the syscall.
    #[cfg(test)]
    async fn filesystem_target_allowed_with<F, Fut>(target: &FilesystemTarget, mut check: F) -> bool
    where
        F: FnMut(&Path, FileAccess) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        for (path, access) in &target.checks {
            if !check(path, *access).await {
                return false;
            }
        }
        true
    }

    #[tokio::test]
    async fn filesystem_mutation_dispatch_denies_when_any_endpoint_denied() {
        let target = FilesystemTarget {
            checks: vec![
                (PathBuf::from("/repo/allowed.txt"), FileAccess::Write),
                (PathBuf::from("/repo/denied.txt"), FileAccess::Write),
            ],
        };
        let mut calls = 0_u32;
        let allowed = filesystem_target_allowed_with(&target, |path, _access| {
            calls += 1;
            let denied = path == Path::new("/repo/denied.txt");
            async move { !denied }
        })
        .await;
        assert!(
            !allowed,
            "broker must deny when any mutation endpoint fails"
        );
        assert_eq!(calls, 2, "broker must CheckFilesystem every affected path");
    }

    #[tokio::test]
    async fn filesystem_mutation_dispatch_short_circuits_on_first_denial() {
        let target = FilesystemTarget {
            checks: vec![
                (PathBuf::from("/repo/denied.txt"), FileAccess::Write),
                (PathBuf::from("/repo/allowed.txt"), FileAccess::Write),
            ],
        };
        let mut calls = 0_u32;
        let allowed = filesystem_target_allowed_with(&target, |path, _access| {
            calls += 1;
            let denied = path == Path::new("/repo/denied.txt");
            async move { !denied }
        })
        .await;
        assert!(!allowed);
        assert_eq!(
            calls, 1,
            "broker should stop checking once a mutation endpoint is denied"
        );
    }

    #[test]
    fn filesystem_mutation_multi_path_syscalls_cover_all_affected_endpoints() {
        let rename =
            filesystem_checks_rename(Path::new("/repo/old.txt"), Path::new("/repo/new.txt"))
                .expect("rename");
        let link = filesystem_checks_link(Path::new("/repo/src.txt"), Path::new("/repo/dst.txt"))
            .expect("link");
        for (name, target, expected_paths) in [
            ("rename", rename, ["/repo/old.txt", "/repo/new.txt"]),
            ("link", link, ["/repo/src.txt", "/repo/dst.txt"]),
        ] {
            let SyscallTarget::Filesystem(FilesystemTarget { checks }) = target else {
                panic!("{name} must classify as filesystem mutation");
            };
            assert_eq!(
                checks.len(),
                expected_paths.len(),
                "{name} must register every affected path for CheckFilesystem"
            );
            for (i, expected) in expected_paths.iter().enumerate() {
                assert!(
                    checks[i].0.ends_with(expected),
                    "{name} check {i} should cover {expected}"
                );
            }
        }
    }

    #[test]
    fn filesystem_checks_symlink_checks_target_read_and_linkpath_write() {
        let symlink =
            filesystem_checks_symlink(Some(Path::new("/tmp/source")), Path::new("/tmp/link"))
                .expect("symlink target");
        let SyscallTarget::Filesystem(FilesystemTarget { checks }) = symlink else {
            panic!("expected filesystem target");
        };
        assert_eq!(
            checks,
            vec![
                (PathBuf::from("/tmp/source"), FileAccess::Read),
                (PathBuf::from("/tmp/link"), FileAccess::Write),
            ]
        );

        let symlink_without_target =
            filesystem_checks_symlink(None, Path::new("/tmp/link")).expect("symlink target");
        let SyscallTarget::Filesystem(FilesystemTarget { checks }) = symlink_without_target else {
            panic!("expected filesystem target");
        };
        assert_eq!(
            checks,
            vec![(PathBuf::from("/tmp/link"), FileAccess::Write)]
        );
    }

    #[test]
    fn filesystem_checks_unlink_and_truncate_are_write_only() {
        let unlink = filesystem_checks_unlink(Path::new("/tmp/gone")).expect("unlink target");
        let truncate = filesystem_checks_truncate(Path::new("/tmp/file")).expect("truncate target");
        for target in [unlink, truncate] {
            let SyscallTarget::Filesystem(FilesystemTarget { checks }) = target else {
                panic!("expected filesystem target");
            };
            assert_eq!(checks, vec![(checks[0].0.clone(), FileAccess::Write)]);
        }
    }

    #[test]
    fn resolve_tracee_path_joins_relative_name_against_dirfd() {
        let dir = std::env::temp_dir().join(format!(
            "agent-sandbox-syscall-broker-fs-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).expect("create temp dir");
        let dir_file = fs::File::open(&dir).expect("open temp dir");

        let resolved = resolve_tracee_path(
            std::process::id(),
            u64::try_from(dir_file.as_raw_fd()).expect("dir fd"),
            PathBuf::from("child.txt"),
        )
        .expect("resolved path");
        assert_eq!(resolved, dir.join("child.txt"));

        let absolute = resolve_tracee_path(
            std::process::id(),
            at_fdcwd_arg(),
            PathBuf::from("/etc/hosts"),
        )
        .expect("absolute path");
        assert_eq!(absolute, PathBuf::from("/etc/hosts"));

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn read_resolved_path_arg_returns_none_for_null_pointer() {
        let resolved =
            read_resolved_path_arg(std::process::id(), at_fdcwd_arg(), 0).expect("read resolved");
        assert_eq!(resolved, None);
    }

    #[test]
    fn tracee_fd_path_resolves_open_file() {
        let file = std::env::temp_dir().join(format!(
            "agent-sandbox-syscall-broker-fd-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&file);
        let opened = fs::File::create(&file).expect("create temp file");
        let resolved = tracee_fd_path(
            std::process::id(),
            u64::try_from(opened.as_raw_fd()).expect("fd"),
        )
        .expect("fd path");
        assert_eq!(resolved, file);
        let _ = fs::remove_file(file);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn io_uring_syscalls_are_classified_as_enosys() {
        for nr in [
            nr::IO_URING_SETUP,
            nr::IO_URING_ENTER,
            nr::IO_URING_REGISTER,
        ] {
            let target = target_from_notification(&SeccompNotif {
                data: SeccompData {
                    nr: i32::try_from(nr).expect("syscall fits i32"),
                    ..SeccompData::default()
                },
                ..SeccompNotif::default()
            })
            .expect("classify io_uring");
            assert_eq!(target, Some(SyscallTarget::Errno(libc::ENOSYS)));
        }
    }
    mod msghdr_tests {
        use super::super::{MsghdrParts, parse_msghdr_target};

        #[test]
        fn parse_msghdr_target_extracts_namelen_and_name() {
            let mut bytes = [0u8; 56];
            bytes[0..8].copy_from_slice(&0x1000_u64.to_ne_bytes());
            bytes[8..12].copy_from_slice(&16_u32.to_ne_bytes());
            assert_eq!(
                parse_msghdr_target(&bytes),
                Some(MsghdrParts {
                    name: 0x1000,
                    name_len: 16
                })
            );
        }

        #[test]
        fn parse_msghdr_target_handles_short_buffer() {
            let bytes = [0u8; 4];
            assert_eq!(parse_msghdr_target(&bytes), None);
        }

        #[test]
        fn parse_msghdr_target_handles_null_name() {
            let bytes = [0u8; 56];
            assert_eq!(parse_msghdr_target(&bytes), None);
        }
    }
}
