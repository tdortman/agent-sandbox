#![allow(unsafe_code)]

use agent_sandbox_core::{
    ProcessIds, RequestContext, ResourceAccess, ResourceCheckReply, ResourceKind, RpcReply,
    RpcRequest, SandboxPaths, policy_rpc,
};
use agent_sandbox_syscall::policy::nr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
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

/// Classified target of a notified syscall, driving broker dispatch.
///
/// Network targets go through the `Check` RPC, resource targets through
/// `CheckResource`, and `None` means continue with no further work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallTarget {
    Network(NetworkTarget),
    Resource(ResourceTarget),
    None,
}
/// Parsed `AF_UNIX` address: a filesystem path or a kernel abstract name.
///
/// Abstract names are encoded as `@hex:<lower-hex>` so they survive JSON
/// round-trips (they may contain NULs and arbitrary bytes) and can be
/// matched verbatim by policyd's resource rule engine.
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

/// Receive a seccomp notification from the listener fd.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_RECV` ioctl fails.
pub fn recv_notification(listener_fd: i32) -> io::Result<SeccompNotif> {
    let mut notif = SeccompNotif::default();
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(notif)
}

/// Send a `SECCOMP_USER_NOTIF_FLAG_CONTINUE` response, allowing the syscall.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_SEND` ioctl fails.
pub fn send_continue(listener_fd: i32, id: u64) -> io::Result<()> {
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Inject an error return value into the tracee's syscall result.
///
/// # Errors
///
/// Returns an error if the `SECCOMP_IOCTL_NOTIF_SEND` ioctl fails.
pub fn send_errno(listener_fd: i32, id: u64, errno: i32) -> io::Result<()> {
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    let resp = SeccompNotifResp {
        id,
        val,
        error: 0,
        flags: 0,
    };
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    let addfd = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: u32::try_from(srcfd).unwrap_or(u32::MAX),
        newfd: 0,
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
/// Read `len` bytes from the tracee's address space at `addr`.
///
/// # Errors
///
/// Returns an error if `process_vm_readv` fails (e.g. the process is gone or the
/// address is invalid).
pub fn read_tracee_bytes(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0_u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: usize::try_from(addr).unwrap_or(0) as *mut libc::c_void,
        iov_len: len,
    };
    let n = unsafe {
        libc::process_vm_readv(
            i32::try_from(pid).unwrap_or(i32::MAX),
            &raw const local,
            1,
            &raw const remote,
            1,
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(n).unwrap_or(0));
    Ok(buf)
}

/// Look up the actual `SO_TYPE` of a tracee socket via `pidfd_open` +
/// `pidfd_getfd`. Returns `None` on any failure (process gone, fd not a
/// socket, kernel too old for the syscalls, etc.) so the caller can fall
/// back to a per-syscall default.
fn get_socket_type(pid: u32, sockfd: i32) -> Option<i32> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // pidfd_open(2): Linux 5.3+. Returns a pidfd referring to the tracee.
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.cast_signed(), 0) };
    let pidfd = i32::try_from(raw_pidfd).ok()?;
    if pidfd < 0 {
        return None;
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    // pidfd_getfd(2): Linux 5.6+. Duplicates the tracee's sockfd into our
    // fd table. The tracee and broker share the user namespace (bwrap uses
    // --unshare-user), so this works across the namespace boundary; opening
    // /proc/<pid>/fd/<sockfd> would not, because the symlink is gone for
    // sockets once the tracee has unshared.
    let raw_dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), sockfd, 0) };
    let dup_fd = i32::try_from(raw_dup).ok()?;
    if dup_fd < 0 {
        return None;
    }
    let dup_fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };
    // getsockopt(SO_TYPE): read the socket type. Returns SOCK_STREAM, SOCK_DGRAM,
    // SOCK_RAW, SOCK_SEQPACKET, etc.
    let mut sock_type: libc::c_int = 0;
    let mut optlen: libc::socklen_t =
        u32::try_from(std::mem::size_of::<libc::c_int>()).expect("size_of c_int fits in u32");
    let ret = unsafe {
        libc::getsockopt(
            dup_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut sock_type).cast::<libc::c_void>(),
            &raw mut optlen,
        )
    };
    if ret < 0 {
        return None;
    }
    Some(sock_type)
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
/// (filesystem path or kernel abstract-namespace name). Returns `None`
/// for any other family or a buffer too short to hold the family prefix.
#[must_use]
pub fn parse_sockaddr(bytes: &[u8]) -> Option<SockaddrTarget> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match i32::from(family) {
        libc::AF_INET if bytes.len() >= 16 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(ip),
                port,
            })
        }
        libc::AF_INET6 if bytes.len() >= 28 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            })
        }
        libc::AF_UNIX => {
            // `sizeof(sockaddr_un.sun_path)` is 108 on Linux. The read cap
            // upstream (128) already bounds us. Keep the raw bytes so the
            // caller can re-derive anything the high-level enum drops.
            let raw = bytes.to_vec();
            if bytes.len() <= 2 {
                // Empty path: unnamed Unix socket. Treat as no target.
                return None;
            }
            // Abstract namespace: the first byte of `sun_path` is NUL.
            if bytes[2] == 0 {
                let name = &bytes[3..];
                // Abstract names CAN contain embedded NULs. The kernel uses
                // the full `sun_path` length, not a C string, for them. We
                // truncate at the first NUL (the common case) so trailing
                // zero-padding does not leak into the policy match key.
                let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                let hex = hex_encode_lower(&name[..end]);
                Some(SockaddrTarget::Unix {
                    address: UnixAddress::AbstractHex(format!("@hex:{hex}")),
                    raw,
                })
            } else {
                // Filesystem path: NUL-terminated C string in sun_path.
                let path_bytes = &bytes[2..];
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
        ResourceAccess::Connect,
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
        ResourceAccess::Send,
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
        ResourceAccess::Send,
    )
}

/// Extract a target from a `sendmmsg` syscall notification.
///
/// `sendmmsg` sends a vector of messages. The first message's `msg_name`
/// drives the target classification, the same approach the broker takes for
/// a single `sendmsg`. Multi-name vectors with conflicting addresses are not
/// policy-checked per-message here: the broker emulates only the first, and a
/// later message with a different destination must await a separate
/// notification (the kernel re-traps per call when the syscall is retried).
///
/// # Errors
///
/// Returns an error if reading tracee memory via `process_vm_readv` fails.
pub fn target_from_sendmmsg(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let msgvec = notif.data.args[1];
    if msgvec == 0 {
        return Ok(None);
    }
    target_from_sendmsg(&SeccompNotif {
        data: SeccompData {
            args: [notif.data.args[0], msgvec, notif.data.args[3], 0, 0, 0],
            ..notif.data
        },
        ..*notif
    })
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
    let Some(sockaddr) = parse_sockaddr(&bytes) else {
        return Ok(None);
    };

    let target = match sockaddr {
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

/// Route a notification to the target extractor based on syscall number.
///
/// Network-egress syscalls (`connect`/`sendto`/`sendmsg`/`sendmmsg`)
/// are classified by the sockaddr they target. Resource-open syscalls
/// (`open`/`openat`/`openat2`/`creat`) are classified by the path they
/// target: `/dev` paths become a `Resource` target of kind `Device`,
/// except for a built-in bypass list of safe devices the broker always
/// continues without a policy check.
///
/// # Errors
///
/// Returns an error if the underlying target extraction (reading tracee
/// memory) fails.
pub fn target_from_notification(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    match i64::from(notif.data.nr) {
        nr::SENDTO => target_from_sendto(notif),
        nr::CONNECT => target_from_connect(notif),
        nr::SENDMSG => target_from_sendmsg(notif),
        nr::SENDMMSG => target_from_sendmmsg(notif),
        nr::OPEN | nr::OPENAT | nr::OPENAT2 | nr::CREAT => Ok(target_from_open(notif)),
        _ => Ok(None),
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
/// the file type via `stat`. This catches hardlinks to device nodes that
/// live outside `/dev`. Also returns true for paths under `/dev` that
/// cannot be stat'd (e.g. deleted between canonicalize and stat) to avoid
/// fail-open.
fn is_device_file(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path).map_or_else(
        |_| path.starts_with("/dev"),
        |meta| meta.file_type().is_block_device() || meta.file_type().is_char_device(),
    )
}

/// Return true if `path` is on the device bypass list, or under `/dev/pts/`
/// (any pty device the kernel assigns). The broker continues these opens
/// directly because they are structurally safe and unavoidable for
/// interactive agents.
fn is_device_bypass(path: &Path) -> bool {
    if DEVICE_BYPASS.iter().any(|d| Path::new(d) == path) {
        return true;
    }
    // /dev/pts and descendants: /dev/pts/0, /dev/pts/3, etc.
    path == Path::new("/dev/pts") || path.starts_with("/dev/pts/")
}

/// Classify an `open`/`openat`/`openat2`/`creat` notification. Returns
/// `Some(Resource(Device))` for non-bypass device opens (classified by file
/// type via `stat`, not path prefix, to catch hardlinks outside `/dev`), and
/// `None` (continue) for everything else: bypass devices and all regular
/// files. `None` means the broker performs no policy check and lets the
/// tracee's own open proceed, which is correct because regular file access is
/// governed by bwrap bind-mounts and the separate `filesystem` policy gate,
/// not by the seccomp resource gate.
fn target_from_open(notif: &SeccompNotif) -> Option<SyscallTarget> {
    // If we can't read the tracee's path (e.g. process_vm_readv returns EPERM
    // due to Yama ptrace_scope or credential changes), continue the syscall
    // rather than blocking it. Regular file access is gated by bwrap and
    // fanotify; device access is structurally limited by bwrap --dev-bind.
    let Ok(Some(raw_path)) = read_tracee_open_path(notif) else {
        return None;
    };
    // Classify by file type, not path prefix: a hardlink to /dev/nvidia0
    // at /home/user/evil would bypass a /dev prefix check. stat() reveals
    // the true file type (block/char device) regardless of the path used.
    let path = normalize_unix_path(&raw_path);
    if !is_device_file(&path) {
        return None;
    }
    if is_device_bypass(&path) {
        return None;
    }
    // Capture flags and mode once, then derive access from the exact
    // captured flags. This prevents an intra-parser race where the tracee
    // could swap flags between path resolution and flag capture.
    let (open_flags, open_mode) = read_tracee_open_flags_mode(notif);
    let acc = open_flags & libc::O_ACCMODE;
    let access = if acc == libc::O_WRONLY {
        ResourceAccess::OpenWrite
    } else if acc == libc::O_RDWR {
        ResourceAccess::OpenReadWrite
    } else {
        ResourceAccess::OpenRead
    };
    let raw = path.to_string_lossy().into_owned().into_bytes();
    Some(SyscallTarget::Resource(ResourceTarget {
        kind: ResourceKind::Device,
        path,
        access,
        raw,
        open_flags,
        open_mode,
    }))
}

/// Resolve the path the tracee passed to `open`/`openat`/`openat2`/`creat`.
/// `open(path, ...)`, `openat(dirfd, path, ...)`, and `openat2(dirfd, path,
/// how, size)` all carry the path as args[1] (a pointer). `open` and `creat`
/// carry it as args[0]. Returns `None` if the pointer is null or the path is
/// not valid UTF-8 (treat as no target).
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
    Ok(std::str::from_utf8(&bytes[..end]).ok().map(PathBuf::from))
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

pub async fn check_target(
    policy_socket: &Path,
    target: &NetworkTarget,
    sandbox_session_id: Option<String>,
    pid: u32,
    timeout: Duration,
) -> bool {
    let mut ctx = RequestContext::from_paths_and_ids(
        &SandboxPaths::default(),
        ProcessIds::from_options(Some(pid), None),
    );
    ctx.sandbox_session_id = sandbox_session_id;
    let req = RpcRequest::Check {
        host: Some(target.host.clone()),
        connect_host: Some(target.connect_host.clone()),
        port: Some(target.port),
        scheme: target.scheme.clone(),
        url: Some(format!(
            "{}://{}:{}",
            target.scheme, target.host, target.port
        )),
        ctx,
    };
    matches!(
        policy_rpc(&policy_socket.display().to_string(), req, timeout).await,
        Ok(RpcReply::Check(reply)) if reply.allowed
    )
}
/// Ask policyd whether a resource-gated syscall is allowed.
///
/// Returns the `ResourceCheckReply` so the broker can distinguish a policy
/// denial from a policyd error and log the source label policyd attached to
/// the verdict.
///
/// # Errors
///
/// Returns an error if the RPC itself fails (policyd unreachable, timeout,
/// malformed reply). A policy denial is returned as `Ok(ResourceCheckReply {
/// allowed: false, .. })`, not as an error.
pub async fn check_resource(
    policy_socket: &Path,
    target: &ResourceTarget,
    sandbox_session_id: Option<String>,
    pid: u32,
    timeout: Duration,
) -> io::Result<ResourceCheckReply> {
    let mut ctx = RequestContext::from_paths_and_ids(
        &SandboxPaths::default(),
        ProcessIds::from_options(Some(pid), None),
    );
    ctx.sandbox_session_id = sandbox_session_id;
    let req = RpcRequest::CheckResource {
        kind: target.kind,
        path: target.path.clone(),
        access: target.access,
        ctx,
    };
    match policy_rpc(&policy_socket.display().to_string(), req, timeout).await {
        Ok(RpcReply::ResourceCheck(reply)) => Ok(reply),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "policyd returned a non-ResourceCheck reply for CheckResource",
        )),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SockaddrTarget, UnixAddress, hex_encode_lower, is_device_bypass, parse_sockaddr,
        scheme_for_socket_type,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    #[test]
    fn parse_ipv4_sockaddr() {
        let bytes = [2, 0, 0, 53, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&bytes),
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
            parse_sockaddr(&bytes),
            Some(SockaddrTarget::Inet {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 0
            })
        );
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
        let parsed = parse_sockaddr(&bytes).expect("AF_UNIX path parses");
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
    fn parse_unix_sockaddr_abstract() {
        // AF_UNIX abstract namespace: bytes[2] == 0 marks abstract, the
        // name follows and may contain arbitrary bytes.
        let mut bytes = vec![1, 0, 0]; // family + abstract marker
        bytes.extend_from_slice(b"agent\x00sandbox");
        let parsed = parse_sockaddr(&bytes).expect("AF_UNIX abstract parses");
        match parsed {
            SockaddrTarget::Unix { address, raw } => {
                // Truncates at first embedded NUL, then hex-encodes the prefix.
                let expected_hex = hex_encode_lower(b"agent");
                assert_eq!(
                    address,
                    UnixAddress::AbstractHex(format!("@hex:{expected_hex}"))
                );
                assert_eq!(raw, bytes);
            }
            other @ SockaddrTarget::Inet { .. } => panic!("expected Unix, got {other:?}"),
        }
    }

    #[test]
    fn parse_unix_sockaddr_unnamed_is_none() {
        // AF_UNIX with empty sun_path: unnamed socket.
        let bytes = [1, 0];
        assert_eq!(parse_sockaddr(&bytes), None);
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
