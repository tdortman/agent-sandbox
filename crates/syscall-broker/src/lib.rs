//! Seccomp user-notification broker for the agent sandbox.
//!
//! This crate owns the kernel-facing side of syscall mediation: it defines
//! the seccomp notification ioctls and their `repr(C)` structs, classifies
//! notified syscalls into network / resource / filesystem targets, and
//! reaches policyd through [`PersistentPolicyClient`] to decide whether each
//! target is allowed.
mod policy_client;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::ffi::OsStringExt,
    },
    path::{Path, PathBuf},
};

use agent_sandbox_core::{DeviceAccess, FileAccess, ResourceAccess, ResourceKind, SocketAccess};
use agent_sandbox_syscall::policy::nr;
pub use policy_client::PersistentPolicyClient;
#[cfg(test)]
fn resolve_tracee_path(pid: u32, dirfd: u64, path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(resolve_open_path(
        &path,
        &tracee_open_dir_base(pid, dirfd)?,
        false,
    ))
}

#[cfg(test)]
fn tracee_fd_path(pid: u32, fd: u64) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
}

fn is_device_bypass(path: &Path) -> bool {
    DEVICE_BYPASS.iter().any(|entry| {
        let entry = Path::new(entry);
        path == entry || path.starts_with(entry)
    })
}

fn is_device_node_for_resource_gate(path: &Path) -> bool {
    path.starts_with("/dev") && device_file_type(path).unwrap_or(false)
}

/// Classify one seccomp notification for policy dispatch or emulation.
///
/// # Errors
/// Returns tracee memory, descriptor, and path-resolution errors.
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
        _ => Ok(target_from_filesystem_mutation(notif)),
    }
}
/// `SECCOMP_IOCTL_NOTIF_RECV` ioctl number: receive a seccomp user
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
/// `SECCOMP_IOCTL_NOTIF_SEND` ioctl number: send a seccomp user
/// notification response to the kernel.
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;

/// `SECCOMP_IOW(2, __u64)` — not `IOWR` like SEND; argument is a single u64 id.
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
/// `SECCOMP_IOCTL_NOTIF_ADDFD` ioctl number: install a file descriptor into
/// the tracee from the broker.
pub const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

/// `SECCOMP_ADDFD_FLAG_SEND` flag for the ADDFD ioctl: also send the
/// installed descriptor to the tracee.
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

/// `struct seccomp_notif_addfd` passed to `SECCOMP_IOCTL_NOTIF_ADDFD`.
/// Layout matches the Linux UAPI: a fixed-order tuple of u64/u32 fields
/// with no implicit padding on 64-bit targets.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifAddfd {
    /// Notification ID, matching the `id` of the received notification that
    /// this ADDFD request extends.
    pub id: u64,
    /// Flags for the ADDFD request; may include
    /// [`SECCOMP_ADDFD_FLAG_SEND`].
    pub flags: u32,
    /// File descriptor in the broker to install into the tracee.
    pub srcfd: u32,
    /// File descriptor number the kernel assigns in the tracee for the
    /// installed descriptor.
    pub newfd: u32,
    /// Flags applied to the new descriptor in the tracee (e.g. `O_CLOEXEC`).
    pub newfd_flags: u32,
}

/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` flag on a notification response:
/// continue running the tracee as if the syscall had not been intercepted.
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

/// Kernel `struct seccomp_data` for a notified syscall.
///
/// Captures the syscall number, its architecture, the tracee's instruction
/// pointer, and up to six arguments. Layout matches the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompData {
    /// Syscall number (`__NR_*` for the target architecture).
    pub nr: i32,
    /// Architecture identifier from `SECCOMP_ARCH_*` (`AUDIT_ARCH_*`).
    pub arch: u32,
    /// Instruction pointer in the tracee at the time of the notification.
    pub instruction_pointer: u64,
    /// Up to six syscall arguments (`__AUDIT_ARCH_64BIT` passes the
    /// full `x86_64` register set).
    pub args: [u64; 6],
}

/// `struct seccomp_notif` received from the kernel via
/// [`SECCOMP_IOCTL_NOTIF_RECV`]: identifies a notified syscall and which
/// tracee triggered it.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotif {
    /// Notification ID, echoed back in the matching response.
    pub id: u64,
    /// PID of the tracee that triggered the notification.
    pub pid: u32,
    /// Notification flags, e.g. [`SECCOMP_USER_NOTIF_FLAG_CONTINUE`].
    pub flags: u32,
    /// Syscall data (`nr`, `arch`, `instruction_pointer`, and `args`) for the
    /// intercepted syscall.
    pub data: SeccompData,
}

/// `struct seccomp_notif_resp` sent to the kernel via
/// [`SECCOMP_IOCTL_NOTIF_SEND`] to answer a notification.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifResp {
    /// Notification ID this response answers (echoed from the notification).
    pub id: u64,
    /// Value returned to the tracee when the syscall is answered with
    /// success (`error == 0`).
    pub val: i64,
    /// Errno-related value: a negative errno (e.g. `-EPERM`) reported to the
    /// tracee as the syscall result.
    pub error: i32,
    /// Response flags, e.g. [`SECCOMP_USER_NOTIF_FLAG_CONTINUE`].
    pub flags: u32,
}

/// Network mediation mode selected by the trusted launcher.
///
/// `Direct` preserves transport policy RPC checks. `Proxy` lets the
/// transparent proxy own only the configured HTTP(S) service-port
/// `AF_INET`/`AF_INET6` connect/send decisions; other network destinations
/// remain gated by seccomp user notification. Unix resources and filesystem
/// mediation remain unchanged in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkMode {
    /// Direct mediation: network transport policy checks are performed
    /// through the normal `Check` RPC, with no transparent proxy.
    Direct,
    /// Proxy mediation: the transparent proxy owns only the configured
    /// HTTP(S) service-port `AF_INET`/`AF_INET6` connect/send decisions;
    /// other network destinations stay gated by seccomp user notification.
    Proxy,
}

/// A network endpoint target from a sandboxed syscall: host, port, and
/// scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTarget {
    /// Hostname or IP address of the network destination.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// URL scheme of the request (e.g. `http` or `https`). Might be empty
    /// for non-URL destinations.
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
    /// Classifies what the target is: a Unix socket path or a device node.
    pub kind: ResourceKind,
    /// Filesystem path of the Unix socket or device node.
    pub path: PathBuf,
    /// Access mode (read/write/etc.) being requested.
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

/// Captured operation semantics for a filesystem mutation. Pointer-bearing
/// arguments and tracee descriptors are copied while classifying the syscall.
#[derive(Debug)]
pub enum FilesystemMutation {
    /// Rename one captured path to another.
    Rename {
        /// Source directory descriptor.
        old_dir: OwnedFd,
        /// Source pathname bytes.
        old: Vec<u8>,
        /// Destination directory descriptor.
        new_dir: OwnedFd,
        /// Destination pathname bytes.
        new: Vec<u8>,
        /// `renameat2` flags.
        flags: u32,
    },
    /// Create a hard link.
    Link {
        /// Source directory descriptor.
        old_dir: OwnedFd,
        /// Source pathname bytes.
        old: Vec<u8>,
        /// Destination directory descriptor.
        new_dir: OwnedFd,
        /// Destination pathname bytes.
        new: Vec<u8>,
        /// `linkat` flags.
        flags: u32,
    },
    /// Create a symbolic link.
    Symlink {
        /// Link target bytes.
        target: Vec<u8>,
        /// Link directory descriptor.
        link_dir: OwnedFd,
        /// Link pathname bytes.
        link: Vec<u8>,
    },
    /// Remove a directory entry.
    Unlink {
        /// Parent directory descriptor.
        dir: OwnedFd,
        /// Entry pathname bytes.
        path: Vec<u8>,
        /// `unlinkat` flags.
        flags: u32,
    },
    /// Truncate a named file.
    Truncate {
        /// Captured cwd descriptor.
        dir: OwnedFd,
        /// Captured pathname bytes.
        path: Vec<u8>,
        /// Requested length.
        len: i64,
    },
    /// Truncate an open file description.
    Ftruncate {
        /// Duplicated tracee descriptor.
        fd: OwnedFd,
        /// Requested length.
        len: i64,
    },
    /// Create a directory.
    Mkdir {
        /// Parent directory descriptor.
        dir: OwnedFd,
        /// Directory pathname bytes.
        path: Vec<u8>,
        /// Requested mode.
        mode: u32,
    },
    /// Remove a directory.
    Rmdir {
        /// Parent directory descriptor.
        dir: OwnedFd,
        /// Directory pathname bytes.
        path: Vec<u8>,
    },
}

/// Filesystem mutation target from a sandboxed syscall.
#[derive(Debug)]
pub struct FilesystemTarget {
    /// Path/access pairs to check against policyd's filesystem policy.
    pub checks: Vec<(PathBuf, FileAccess)>,

    /// Immutable syscall operation captured at classification time.
    pub operation: FilesystemMutation,
}

/// Classified target of a notified syscall, driving broker dispatch.
///
/// Network targets go through the `Check` RPC, resource targets through
/// `CheckResource`, filesystem targets through `CheckFilesystem`, `Errno`
/// completes the syscall with that errno, and `None` means continue with no
/// further work. Filesystem mutations are emulated or fail closed; they never
/// use `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
#[derive(Debug)]
pub enum SyscallTarget {
    /// Network target, dispatched through the `Check` RPC.
    Network(NetworkTarget),
    /// Resource target (Unix socket / device node), dispatched through
    /// `CheckResource`.
    Resource(ResourceTarget),
    /// Filesystem mutation target, dispatched through `CheckFilesystem`.
    Filesystem(FilesystemTarget),
    /// Complete the syscall by returning this errno value to the tracee.
    Errno(i32),
}

/// Parsed `AF_UNIX` address: a filesystem path or a kernel abstract name.
///
/// Abstract names are encoded as either `@abstract:<text>` (when the name
/// is printable UTF-8, so rules like `nv_target_process_*` match) or
/// `@hex:<lower-hex>` (fallback for binary names). Both survive JSON
/// round-trips and match verbatim in policyd's resource rule engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixAddress {
    /// Filesystem path of the Unix socket.
    Path(String),
    /// Kernel abstract socket name, hex-encoded (used for non-printable
    /// names).
    AbstractHex(String),
}

/// Parsed sockaddr: either an Internet (`AF_INET`/`AF_INET6`) endpoint or a
/// Unix-domain (`AF_UNIX`) address, paired with the raw bytes so callers can
/// re-derive fields the high-level enum drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockaddrTarget {
    /// Internet endpoint (`AF_INET`/`AF_INET6`): an IP address and port.
    Inet {
        /// IP address of the endpoint.
        ip: IpAddr,
        /// Port of the endpoint.
        port: u16,
    },
    /// Unix-domain endpoint (`AF_UNIX`): a parsed address plus the raw
    /// captured bytes.
    Unix {
        /// Parsed `AF_UNIX` address.
        address: UnixAddress,
        /// Raw captured sockaddr bytes.
        raw: Vec<u8>,
    },
}

/// Hex-encode a byte slice as lowercase ASCII, no `0x` prefix.
/// ponytail: inlined instead of pulling the `hex` crate for ~20 lines.
fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0F)] as char);
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
        && s.bytes().all(|b| b >= 0x20 && b != 0x7F)
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
pub fn notif_id_valid(listener_fd: i32, mut id: u64) -> io::Result<()> {
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

/// Send a response to a seccomp notification.
///
/// `val` is the syscall return value and `error` is the negative errno to
/// inject. `flags` may request `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
///
/// # Errors
///
/// Returns an error if the notification id is stale or the
/// `SECCOMP_IOCTL_NOTIF_SEND` ioctl fails.
pub fn send_response(
    listener_fd: i32,
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
) -> io::Result<()> {
    notif_id_valid(listener_fd, id)?;
    let mut resp = SeccompNotifResp {
        id,
        val,
        error,
        flags,
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
fn parse_sockaddr(bytes: &[u8], addrlen: usize) -> Option<SockaddrTarget> {
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
fn target_from_connect(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let scheme = scheme_for_fd(notif, notif.data.args[0], "tcp");

    sockaddr_target(
        notif,
        notif.data.args[1],
        notif.data.args[2],
        &scheme,
        ResourceAccess::Socket(SocketAccess::Connect),
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
fn target_from_sendto(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
    let scheme = scheme_for_fd(notif, notif.data.args[0], "udp");

    sockaddr_target(
        notif,
        notif.data.args[4],
        notif.data.args[5],
        &scheme,
        ResourceAccess::Socket(SocketAccess::Send),
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
fn target_from_sendmsg(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
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
        ResourceAccess::Socket(SocketAccess::Send),
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
fn target_from_sendmmsg(notif: &SeccompNotif) -> io::Result<Option<SyscallTarget>> {
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
            port,
            scheme: scheme.to_string(),
        }),

        SockaddrTarget::Unix { address, raw } => {
            let path = match address {
                UnixAddress::Path(p) => normalize_path(Path::new(&p)),
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
const fn filesystem_target(
    checks: Vec<(PathBuf, FileAccess)>,
    operation: FilesystemMutation,
) -> SyscallTarget {
    SyscallTarget::Filesystem(FilesystemTarget { checks, operation })
}

fn mutation_errno(err: &io::Error) -> SyscallTarget {
    SyscallTarget::Errno(err.raw_os_error().unwrap_or(libc::EACCES))
}

fn read_raw_path(pid: u32, ptr: u64) -> io::Result<Vec<u8>> {
    if ptr == 0 {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    let bytes = read_tracee_bytes(pid, ptr, libc::PATH_MAX as usize)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == bytes.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    Ok(bytes[..end].to_vec())
}

fn path_from_raw(raw: &[u8]) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(raw.to_vec()))
}

fn open_path_handle(path: &Path) -> io::Result<OwnedFd> {
    nix::fcntl::open(
        path,
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(io::Error::from)
}

fn tracee_dir_handle(pid: u32, dirfd: u64) -> io::Result<OwnedFd> {
    let fd = syscall_i32_arg(dirfd);
    if fd == libc::AT_FDCWD {
        return open_path_handle(Path::new(&format!("/proc/{pid}/cwd")));
    }
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }

    agent_sandbox_sysutil::dup_tracee_fd(pid, fd)
}

fn capture_path(
    notif: &SeccompNotif,
    dirfd: u64,
    ptr: u64,
) -> io::Result<(OwnedFd, Vec<u8>, PathBuf)> {
    let raw = read_raw_path(notif.pid, ptr)?;
    if raw.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let path = path_from_raw(&raw);
    if path.is_absolute() {
        return Ok((open_path_handle(Path::new("/"))?, raw, path));
    }
    let dir = tracee_dir_handle(notif.pid, dirfd)?;
    let base = std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))?;
    let resolved = base.join(path);
    Ok((dir, raw, resolved))
}
fn two_path_target(
    notif: &SeccompNotif,
    old_dirfd: u64,
    old_ptr: u64,
    new_dirfd: u64,
    new_ptr: u64,
    operation: impl FnOnce(OwnedFd, Vec<u8>, OwnedFd, Vec<u8>) -> FilesystemMutation,
) -> io::Result<SyscallTarget> {
    let (old_dir, old, old_check) = capture_path(notif, old_dirfd, old_ptr)?;
    let (new_dir, new, new_check) = capture_path(notif, new_dirfd, new_ptr)?;
    Ok(filesystem_target(
        vec![
            (normalize_path(&old_check), FileAccess::ReadWrite),
            (normalize_path(&new_check), FileAccess::ReadWrite),
        ],
        operation(old_dir, old, new_dir, new),
    ))
}

fn target_from_rename(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    two_path_target(
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        at_fdcwd_arg(),
        notif.data.args[1],
        |old_dir, old, new_dir, new| FilesystemMutation::Rename {
            old_dir,
            old,
            new_dir,
            new,
            flags: 0,
        },
    )
}

fn target_from_renameat_family(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let flags = if i64::from(notif.data.nr) == nr::RENAMEAT {
        0
    } else {
        u32::try_from(notif.data.args[4]).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
    };
    two_path_target(
        notif,
        notif.data.args[0],
        notif.data.args[1],
        notif.data.args[2],
        notif.data.args[3],
        |old_dir, old, new_dir, new| FilesystemMutation::Rename {
            old_dir,
            old,
            new_dir,
            new,
            flags,
        },
    )
}
fn target_from_link(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    two_path_target(
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        at_fdcwd_arg(),
        notif.data.args[1],
        |old_dir, old, new_dir, new| FilesystemMutation::Link {
            old_dir,
            old,
            new_dir,
            new,
            flags: 0,
        },
    )
}

fn target_from_linkat(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let flags = u32::try_from(notif.data.args[4])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    two_path_target(
        notif,
        notif.data.args[0],
        notif.data.args[1],
        notif.data.args[2],
        notif.data.args[3],
        |old_dir, old, new_dir, new| FilesystemMutation::Link {
            old_dir,
            old,
            new_dir,
            new,
            flags,
        },
    )
}

fn target_from_symlink(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let target = read_raw_path(notif.pid, notif.data.args[0])?;
    let (link_dir, link, resolved) = capture_path(notif, at_fdcwd_arg(), notif.data.args[1])?;
    let target_path = resolve_symlink_target_path(&target, &resolved);
    Ok(filesystem_target(
        vec![
            (normalize_path(&target_path), FileAccess::Read),
            (normalize_path(&resolved), FileAccess::Write),
        ],
        FilesystemMutation::Symlink {
            target,
            link_dir,
            link,
        },
    ))
}

fn target_from_symlinkat(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let target = read_raw_path(notif.pid, notif.data.args[0])?;
    let (link_dir, link, resolved) = capture_path(notif, notif.data.args[1], notif.data.args[2])?;
    let target_path = resolve_symlink_target_path(&target, &resolved);
    Ok(filesystem_target(
        vec![
            (normalize_path(&target_path), FileAccess::Read),
            (normalize_path(&resolved), FileAccess::Write),
        ],
        FilesystemMutation::Symlink {
            target,
            link_dir,
            link,
        },
    ))
}

fn resolve_symlink_target_path(target: &[u8], link: &Path) -> PathBuf {
    let target = PathBuf::from(std::ffi::OsString::from_vec(target.to_vec()));
    if target.is_absolute() {
        target
    } else {
        link.parent()
            .map_or_else(|| target.clone(), |parent| parent.join(&target))
    }
}
fn single_path_target(
    notif: &SeccompNotif,
    dirfd: u64,
    ptr: u64,
    operation: impl FnOnce(OwnedFd, Vec<u8>) -> FilesystemMutation,
    access: FileAccess,
) -> io::Result<SyscallTarget> {
    let (dir, raw, path) = capture_path(notif, dirfd, ptr)?;
    Ok(filesystem_target(
        vec![(normalize_path(&path), access)],
        operation(dir, raw),
    ))
}

fn target_from_unlink(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    single_path_target(
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        |dir, path| FilesystemMutation::Unlink {
            dir,
            path,
            flags: 0,
        },
        FileAccess::Write,
    )
}

fn target_from_unlinkat(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let flags = u32::try_from(notif.data.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    single_path_target(
        notif,
        notif.data.args[0],
        notif.data.args[1],
        |dir, path| FilesystemMutation::Unlink { dir, path, flags },
        FileAccess::Write,
    )
}

fn target_from_truncate(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let (dir, raw, path) = capture_path(notif, at_fdcwd_arg(), notif.data.args[0])?;
    let len = i64::try_from(notif.data.args[1])
        .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    Ok(filesystem_target(
        vec![(normalize_path(&path), FileAccess::Write)],
        FilesystemMutation::Truncate {
            dir,
            path: raw,
            len,
        },
    ))
}

fn target_from_ftruncate(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let fd = agent_sandbox_sysutil::dup_tracee_fd(
        notif.pid,
        i32::try_from(notif.data.args[0]).map_err(|_| io::Error::from_raw_os_error(libc::EBADF))?,
    )?;
    let mut path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    // An ordinary fd link already names the resolved, frozen file description.
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") {
        path = normalize_path(&path);
    }
    let len = i64::try_from(notif.data.args[1])
        .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    Ok(filesystem_target(
        vec![(path, FileAccess::Write)],
        FilesystemMutation::Ftruncate { fd, len },
    ))
}

fn mkdir_target(
    notif: &SeccompNotif,
    dirfd: u64,
    ptr: u64,
    mode: u32,
) -> io::Result<SyscallTarget> {
    let (dir, raw, path) = capture_path(notif, dirfd, ptr)?;
    if raw.is_empty() {
        return Ok(SyscallTarget::Errno(libc::ENOENT));
    }
    let exists = if raw.starts_with(b"/") {
        std::fs::symlink_metadata(&path).is_ok()
    } else {
        let mut candidate = format!("/proc/self/fd/{}/", dir.as_raw_fd()).into_bytes();
        candidate.extend_from_slice(&raw);
        std::fs::symlink_metadata(PathBuf::from(std::ffi::OsString::from_vec(candidate))).is_ok()
    };
    if exists {
        return Ok(SyscallTarget::Errno(libc::EEXIST));
    }
    Ok(filesystem_target(
        vec![(normalize_path(&path), FileAccess::Write)],
        FilesystemMutation::Mkdir {
            dir,
            path: raw,
            mode,
        },
    ))
}

fn target_from_mkdir(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let mode = u32::try_from(notif.data.args[1])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    mkdir_target(notif, at_fdcwd_arg(), notif.data.args[0], mode)
}

fn target_from_mkdirat(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let mode = u32::try_from(notif.data.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    mkdir_target(notif, notif.data.args[0], notif.data.args[1], mode)
}

fn target_from_rmdir(notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    single_path_target(
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        |dir, path| FilesystemMutation::Rmdir { dir, path },
        FileAccess::Write,
    )
}

fn target_from_filesystem_mutation(notif: &SeccompNotif) -> Option<SyscallTarget> {
    let result = match i64::from(notif.data.nr) {
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
        nr::MKDIR => target_from_mkdir(notif),
        nr::MKDIRAT => target_from_mkdirat(notif),
        nr::RMDIR => target_from_rmdir(notif),
        _ => return None,
    };
    Some(result.unwrap_or_else(|err| mutation_errno(&err)))
}

/// Canonicalize a filesystem path by resolving symlinks.
#[must_use]
pub fn normalize_path(path: &Path) -> PathBuf {
    let fd = match open_path_handle(path) {
        Ok(fd) => Some(fd),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
            return path.to_path_buf();
        }
        Err(_) => None,
    };
    if let Some(fd) = fd
        && let Ok(resolved) = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        && resolved.is_absolute()
        && !resolved
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b" (deleted)")
    {
        return resolved;
    }
    // Anonymous descriptors and unlinked handles have no canonical pathname.
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
#[cfg(any(target_os = "linux", test))]
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

    let path = normalize_path(&raw_path);
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
        ResourceAccess::Device(DeviceAccess::Write)
    } else if acc == libc::O_RDWR {
        ResourceAccess::Device(DeviceAccess::ReadWrite)
    } else {
        ResourceAccess::Device(DeviceAccess::Read)
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

/// Decode an `int` syscall argument from the register's low 32 bits.
const fn syscall_i32_arg(arg: u64) -> i32 {
    let bytes = arg.to_le_bytes();
    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

const fn is_at_fdcwd(dirfd: u64) -> bool {
    syscall_i32_arg(dirfd) == libc::AT_FDCWD
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
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr},
        os::fd::AsRawFd,
        path::{Path, PathBuf},
    };

    use agent_sandbox_syscall::policy::nr;

    use super::{
        MsghdrParts, SECCOMP_IOCTL_NOTIF_ADDFD, SECCOMP_IOCTL_NOTIF_ID_VALID,
        SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND, SeccompData, SeccompNotif,
        SockaddrTarget, SyscallTarget, UnixAddress, at_fdcwd_arg, device_file_type,
        hex_encode_lower, is_at_fdcwd, is_device_bypass, is_device_node_for_resource_gate,
        notification_arch_valid, parse_msghdr_target, parse_sockaddr, resolve_open_path,
        resolve_tracee_path, scheme_for_socket_type, target_from_notification, tracee_fd_path,
        tracee_open_dir_base,
    };

    #[test]
    fn canonical_paths_follow_live_aliases_and_preserve_unresolvable_paths() {
        let root = std::env::temp_dir().join(format!("broker-canonical-{}", std::process::id()));
        fs::create_dir(&root).expect("create temporary directory");
        let first = root.join("first");
        let second = root.join("second");
        let alias = root.join("alias");
        fs::write(&first, b"first").expect("write first file");
        fs::write(&second, b"second").expect("write second file");
        std::os::unix::fs::symlink(&first, &alias).expect("create alias");
        let before = super::normalize_path(&alias);
        fs::remove_file(&alias).expect("remove alias");
        std::os::unix::fs::symlink(&second, &alias).expect("retarget alias");
        let after = super::normalize_path(&alias);
        let missing = root.join("missing");
        let unresolved = super::normalize_path(&missing);
        let directory_alias = root.join("directory-alias");
        std::os::unix::fs::symlink(&root, &directory_alias).expect("create directory alias");
        let missing_alias = directory_alias.join("missing");
        let missing_alias_result = super::normalize_path(&missing_alias);
        let not_directory = alias.join("child");
        let not_directory_result = super::normalize_path(&not_directory);
        let held = fs::File::open(&first).expect("hold first file");
        fs::remove_file(&first).expect("unlink held file");
        let deleted = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
        let deleted_result = super::normalize_path(&deleted);
        let (reader, _writer) = nix::unistd::pipe().expect("create anonymous pipe");
        let anonymous = PathBuf::from(format!("/proc/self/fd/{}", reader.as_raw_fd()));
        let anonymous_result = super::normalize_path(&anonymous);
        fs::remove_dir_all(&root).expect("remove temporary directory");
        assert_eq!(before, first);
        assert_eq!(after, second);
        assert_eq!(unresolved, missing);
        assert_eq!(missing_alias_result, missing_alias);
        assert_eq!(not_directory_result, not_directory);
        assert_eq!(deleted_result, deleted);
        assert_eq!(anonymous_result, anonymous);
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

        // ID_VALID is IOW(2, __u64), not IOREWR like SEND. Mixing them up
        // makes every response fail with EINVAL.
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
                port: 53,
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
                port: 0,
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
        bytes.extend_from_slice(&[0xFF, 0xAB, 0x01]);
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
        assert_eq!(hex_encode_lower(&[0x00, 0xFF, 0xAB, 0x10]), "00ffab10");
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
        // x32 (0x4000_0002) and i686 (0x4000_0003) compat audit arch values,
        // kept as literals since the syscall crate no longer exports them.
        for arch in [0x4000_0002, 0x4000_0003, 0] {
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
        assert!(!is_device_node_for_resource_gate(Path::new("kvm")));
        assert!(is_device_node_for_resource_gate(&resolved));
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

            assert!(matches!(target, Some(SyscallTarget::Errno(libc::ENOSYS))));
        }
    }

    #[test]
    fn parse_msghdr_target_reads_name_and_length() {
        let mut bytes = [0u8; 56];
        bytes[0..8].copy_from_slice(&0x1000_u64.to_ne_bytes());
        bytes[8..12].copy_from_slice(&16_u32.to_ne_bytes());

        assert_eq!(
            parse_msghdr_target(&bytes),
            Some(MsghdrParts {
                name: 0x1000,
                name_len: 16,
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
