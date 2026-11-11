//! Seccomp user-notification broker for the agent sandbox.
//!
//! This crate owns the kernel-facing side of syscall mediation: it defines
//! the seccomp notification ioctls and their `repr(C)` structs, classifies
//! notified syscalls into network / resource / filesystem targets, and
//! reaches policyd through [`PersistentPolicyClient`] to decide whether each
//! target is allowed.
//!
//! Tracee arguments are read once per notification ([`capture`]), and the
//! objects they name are pinned through a [`Resolver`] ([`pinning`]); policy
//! dispatch and emulation consume those captured values.

mod capture;
mod filesystem;
mod open;
mod pinning;
mod policy_client;
mod socket;

use std::{io, os::fd::OwnedFd, path::PathBuf};

use agent_sandbox_core::{ResourceAccess, ResourceKind};
use agent_sandbox_syscall::policy::nr;
pub use capture::Msghdr;
pub use filesystem::{FilesystemMutation, FilesystemTarget, MutationDir};
pub use open::reopen_held_terminal;
pub use pinning::{DirBase, PinScope, Resolver, TraceeFd};
pub use policy_client::PersistentPolicyClient;

/// Classify one seccomp notification for policy dispatch or emulation.
///
/// # Errors
/// Returns tracee memory, descriptor, and path-resolution errors.
pub fn target_from_notification(
    resolver: &Resolver,
    notif: &SeccompNotif,
) -> io::Result<Option<SyscallTarget>> {
    match i64::from(notif.data.nr) {
        nr::SENDTO => socket::target_from_sendto(resolver, notif),
        nr::CONNECT => socket::target_from_connect(resolver, notif),
        nr::SENDMSG => socket::target_from_sendmsg(resolver, notif),
        nr::SENDMMSG => socket::target_from_sendmmsg(resolver, notif),
        nr::OPEN | nr::OPENAT | nr::OPENAT2 | nr::CREAT => {
            Ok(open::target_from_open(resolver, notif))
        }

        nr::IO_URING_SETUP | nr::IO_URING_ENTER | nr::IO_URING_REGISTER => {
            Ok(Some(SyscallTarget::Errno(libc::ENOSYS)))
        }

        // A file handle names a file without a path, so neither the path policy
        // nor the device classification can see the target. Obtaining one also
        // needs CAP_DAC_READ_SEARCH, which the sandbox never holds, so the API
        // is reported as absent rather than mapped onto a path check.
        nr::NAME_TO_HANDLE_AT | nr::OPEN_BY_HANDLE_AT => {
            Ok(Some(SyscallTarget::Errno(libc::ENOSYS)))
        }

        _ => Ok(filesystem::target_from_filesystem_mutation(resolver, notif)),
    }
}

/// The target that completes a syscall with the errno of a failed lookup.
fn errno_target(err: &io::Error) -> SyscallTarget {
    SyscallTarget::Errno(err.raw_os_error().unwrap_or(libc::EACCES))
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
/// transparent proxy own every TCP and UDP `AF_INET`/`AF_INET6`
/// connect/send decision (TCP is sniffed into HTTP or passthrough, UDP is
/// transport-checked per flow); other network destinations remain gated by
/// seccomp user notification. Unix resources and filesystem mediation remain
/// unchanged in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkMode {
    /// Direct mediation: network transport policy checks are performed
    /// through the normal `Check` RPC, with no transparent proxy.
    Direct,

    /// Proxy mediation: the transparent proxy owns every TCP and UDP
    /// `AF_INET`/`AF_INET6` connect/send decision; other network
    /// destinations stay gated by seccomp user notification.
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
/// `capture` carries everything emulation needs, read from the tracee while
/// classifying: the broker never re-reads a pointer-bearing argument after
/// policy approval, which would be TOCTOU-racy.
#[derive(Debug)]
pub struct ResourceTarget {
    /// Classifies what the target is: a Unix socket path or a device node.
    pub kind: ResourceKind,

    /// Canonical path of the pinned inode, or the abstract-name policy key.
    pub path: PathBuf,

    /// Access mode (read/write/etc.) being requested.
    pub access: ResourceAccess,

    /// Captured arguments consumed by emulation.
    pub capture: ResourceCapture,
}

/// Tracee arguments captured for emulating a [`ResourceTarget`].
#[derive(Debug)]
pub enum ResourceCapture {
    /// `connect`, `sendto`, `sendmsg` or `sendmmsg` to an `AF_UNIX` address.
    Unix(UnixCapture),

    /// `open`, `openat`, `openat2` or `creat` of a device node.
    Device(DeviceCapture),
}

/// Captured `AF_UNIX` destination of a socket syscall.
#[derive(Debug)]
pub struct UnixCapture {
    /// The sockaddr the emulated syscall uses. For a filesystem socket: the
    /// captured family followed by the procfs path of `pinned`. For an
    /// abstract name: the captured bytes.
    pub addr: Vec<u8>,

    /// Socket inode pinned for a filesystem `AF_UNIX` path; `addr` names it,
    /// so it must live until emulation. `None` for abstract sockets.
    pub pinned: Option<OwnedFd>,

    /// The `msghdr` of a `sendmsg`, captured with its destination.
    pub msghdr: Option<Msghdr>,
}

/// Captured device open.
#[derive(Debug)]
pub struct DeviceCapture {
    /// `O_PATH` handle of the device inode the policy decision names.
    pub pinned: OwnedFd,

    /// Open flags the tracee requested.
    pub flags: i32,

    /// Open mode the tracee requested.
    pub mode: u32,
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

/// Return true when `notif.data.arch` matches the broker's native audit arch.
#[must_use]
pub const fn notification_arch_valid(notif: &SeccompNotif) -> bool {
    notif.data.arch == agent_sandbox_syscall::policy::AUDIT_ARCH_NATIVE
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
/// The kernel validates the notification id while holding the filter lock, so
/// a stale id is rejected here with `ENOENT` without a preceding
/// `SECCOMP_IOCTL_NOTIF_ID_VALID` round trip on the per-syscall hot path.
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
/// Returns an error if the notification id is stale or the
/// `SECCOMP_IOCTL_NOTIF_ADDFD` ioctl fails.
pub fn send_addfd(listener_fd: i32, id: u64, srcfd: i32, cloexec: bool) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use agent_sandbox_syscall::policy::nr;

    use super::{
        Resolver, SECCOMP_IOCTL_NOTIF_ADDFD, SECCOMP_IOCTL_NOTIF_ID_VALID,
        SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND, SeccompData, SeccompNotif,
        SyscallTarget, notification_arch_valid, target_from_notification,
    };

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
    fn handle_lookups_are_refused_before_classification() {
        for syscall in [nr::NAME_TO_HANDLE_AT, nr::OPEN_BY_HANDLE_AT] {
            let notif = SeccompNotif {
                data: SeccompData {
                    nr: i32::try_from(syscall).expect("syscall number"),
                    ..SeccompData::default()
                },
                ..SeccompNotif::default()
            };

            match target_from_notification(&Resolver::default(), &notif) {
                Ok(Some(SyscallTarget::Errno(errno))) => assert_eq!(errno, libc::ENOSYS),
                other => panic!("handle lookup {syscall} must be refused, got {other:?}"),
            }
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn io_uring_syscalls_are_classified_as_enosys() {
        for nr in [
            nr::IO_URING_SETUP,
            nr::IO_URING_ENTER,
            nr::IO_URING_REGISTER,
        ] {
            let target = target_from_notification(&Resolver::default(), &SeccompNotif {
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
}
