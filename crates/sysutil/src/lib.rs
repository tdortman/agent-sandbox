#![allow(unsafe_code)]
//! Safe wrappers over Linux syscall surfaces used by the agent-sandbox daemons.
//!
//! Every `unsafe` in the workspace that touches a raw syscall lives behind one
//! of the audited functions in this crate. Callers never write their own
//! `unsafe` syscall code.

use std::ffi::CStr;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use nix::sys::socket::{SockaddrStorage, getpeername};
use nix::unistd::Pid;

/// Open a pidfd referring to `pid` (Linux 5.3+ `pidfd_open(2)`).
///
/// The returned `OwnedFd` closes the pidfd on drop.
///
/// # Errors
/// Returns the kernel error (`ESRCH` when the pid is gone, `EINVAL`/`ENOSYS`
/// on kernels without pidfd support).
pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: `pidfd_open(pid_t pid, unsigned int flags)` with flags=0. The
    // returned fd is owned exclusively by this call.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.cast_signed(), 0u32) };
    fd_from_syscall(raw)
}

/// Duplicate a foreign fd into this process via `pidfd_getfd(2)` (Linux 5.6+).
///
/// `pidfd` is a pidfd from [`pidfd_open`]. `fd` is the target fd in that
/// process. Returns an `OwnedFd` that closes on drop.
///
/// # Errors
/// Returns the kernel error.
pub fn pidfd_getfd(pidfd: impl AsFd, fd: i32) -> io::Result<OwnedFd> {
    // SAFETY: `pidfd_getfd(int pidfd, int targetfd, unsigned int flags)` with
    // flags=0. The returned fd is owned exclusively by this call.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_fd().as_raw_fd(), fd, 0u32) };
    fd_from_syscall(raw)
}

/// Duplicate a tracee's fd into our fd table: `pidfd_open` then `pidfd_getfd`.
///
/// Convenience wrapper combining [`pidfd_open`] and [`pidfd_getfd`].
///
/// # Errors
/// Returns the kernel error from either step.
pub fn dup_tracee_fd(pid: u32, fd: i32) -> io::Result<OwnedFd> {
    let pidfd = pidfd_open(pid)?;
    pidfd_getfd(&pidfd, fd)
}

fn fd_from_syscall(raw: libc::c_long) -> io::Result<OwnedFd> {
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fd out of range"))?;
    // SAFETY: `fd` is a freshly-returned kernel fd not owned by anyone else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Run an ioctl that takes a pointer to a single value, mapping a negative
/// return into the kernel error.
///
/// `arg` is passed by mutable reference. Callers guarantee `arg` matches the
/// shape the kernel expects for `request` on this fd.
///
/// # Errors
/// Returns the kernel error when the ioctl returns a negative value.
pub fn ioctl<T>(fd: std::os::fd::RawFd, request: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    // SAFETY: the caller guarantees the (fd, request, arg) triple is a valid
    // ioctl and owns `fd`. `arg` is derived from a live mutable reference.
    let rc = unsafe { libc::ioctl(fd, request, std::ptr::from_mut::<T>(arg)) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Read `len` bytes from `pid`'s address space at `addr` via `process_vm_readv`,
/// falling back to `/proc/<pid>/mem` when the syscall is unavailable.
///
/// # Errors
/// Returns an error when both paths fail (process gone, address invalid, or
/// `/proc/<pid>/mem` unreadable).
pub fn read_tracee_bytes(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    if let Some(n) = process_vm_readv_into(pid, addr, &mut buf) {
        buf.truncate(n);
        return Ok(buf);
    }
    let mem_path = format!("/proc/{pid}/mem");
    read_proc_mem(Path::new(&mem_path), addr, &mut buf)?;
    Ok(buf)
}

/// Attempt `process_vm_readv` into `buf`. Returns the byte count read, or
/// `None` when the syscall fails so the caller can apply its own fallback.
///
/// Exposed so callers with a non-default `/proc` mount (e.g. fsmon after
/// `setns`) can build their own `/proc/<pid>/mem` path for the fallback.
pub fn process_vm_readv_into(pid: u32, addr: u64, buf: &mut [u8]) -> Option<usize> {
    if buf.is_empty() {
        return Some(0);
    }
    let len = buf.len();
    let mut local = [std::io::IoSliceMut::new(buf)];
    let remote = [nix::sys::uio::RemoteIoVec {
        base: usize::try_from(addr).unwrap_or(0),
        len,
    }];
    nix::sys::uio::process_vm_readv(Pid::from_raw(pid.cast_signed()), &mut local, &remote).ok()
}

/// Read `buf.len()` bytes from a `/proc/<pid>/mem`-style file at `addr`.
///
/// # Errors
/// Returns an error if the file cannot be opened or `buf` cannot be filled.
pub fn read_proc_mem(mem_path: &Path, addr: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut mem = std::fs::File::open(mem_path)?;
    mem.seek(SeekFrom::Start(addr))?;
    mem.read_exact(buf)?;
    Ok(())
}

/// Read the `SO_TYPE` of a socket fd. Returns `None` on any failure so
/// callers fall through to a safe default.
///
/// # Panics
/// Never.
#[must_use]
pub fn socket_type(fd: impl AsFd) -> Option<i32> {
    let mut sock_type: libc::c_int = 0;
    let mut optlen: libc::socklen_t =
        u32::try_from(std::mem::size_of::<libc::c_int>()).expect("c_int size fits in socklen_t");
    // SAFETY: getsockopt writes into the live `sock_type` and `optlen`. The fd
    // is borrowed for the call. Arguments match the SO_TYPE signature.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut sock_type).cast::<libc::c_void>(),
            &raw mut optlen,
        )
    };
    (rc == 0).then_some(sock_type)
}

/// Return `true` when the socket fd has a connected peer. For `SOCK_STREAM`
/// and `SOCK_SEQPACKET` the kernel ignores `msg_name`, so `CONTINUE` is safe.
#[must_use]
pub fn is_socket_connected(fd: impl AsFd) -> bool {
    getpeername::<SockaddrStorage>(fd.as_fd().as_raw_fd()).is_ok()
}

/// Open `/proc/<pid>/ns/mnt` and `setns(CLONE_NEWNS)` into it.
///
/// The caller is responsible for any policy guard refusing to join the
/// caller's own mount namespace. The opened fd is closed on return.
///
/// # Errors
/// Returns an error if the namespace fd cannot be opened or `setns` fails.
pub fn join_mount_namespace(target_pid: u32) -> io::Result<()> {
    let ns_path = format!("/proc/{target_pid}/ns/mnt");
    let ns_fd = nix::fcntl::open(
        ns_path.as_str(),
        nix::fcntl::OFlag::O_RDONLY,
        nix::sys::stat::Mode::empty(),
    )?;
    nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWNS).map_err(io::Error::from)
}

/// Lower every ambient capability via `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, ...)`.
///
/// The loop stops when the kernel returns `EINVAL` (no more ambient caps to lower).
///
/// # Errors
/// Returns the kernel error when `prctl` fails for a reason other than `EINVAL`.
pub fn clear_ambient_capabilities() -> io::Result<()> {
    // SAFETY: `PR_CAP_AMBIENT` + `PR_CAP_AMBIENT_LOWER`. Stop when the kernel returns EINVAL.
    unsafe {
        for cap in 0_i32.. {
            if libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_LOWER, cap, 0, 0) < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    break;
                }
                return Err(err);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// fanotify. nix 0.31 fanotify is partial and does not cover the custom
// FAN_PRE_ACCESS mask, so init/mark stay as raw syscalls behind safe wrappers.
// ---------------------------------------------------------------------------

/// `fanotify_init` flags.
const FAN_CLASS_PRE_CONTENT: u32 = libc::FAN_CLASS_PRE_CONTENT;
const FAN_CLOEXEC: u32 = libc::FAN_CLOEXEC;

/// `fanotify_mark` flags.
const FAN_MARK_ADD: u32 = libc::FAN_MARK_ADD;
const FAN_MARK_MOUNT: u32 = libc::FAN_MARK_MOUNT;

/// Permission event masks.
pub const FAN_OPEN_PERM: u64 = libc::FAN_OPEN_PERM;
pub const FAN_OPEN_EXEC_PERM: u64 = libc::FAN_OPEN_EXEC_PERM;
pub const FAN_ACCESS_PERM: u64 = libc::FAN_ACCESS_PERM;
/// Pre-content access mask. Not exported by libc, matches the kernel UAPI.
pub const FAN_PRE_ACCESS: u64 = 0x0010_0000;

pub const FAN_ALLOW: u32 = 0x01;
pub const FAN_DENY: u32 = 0x02;

/// Open a fanotify fd suitable for pre-content permission events.
///
/// Returns `(fd, reports_tid)` where `reports_tid` is true when the kernel
/// honours `FAN_REPORT_TID` and `meta.pid` is the opener thread id.
///
/// # Errors
/// Returns an error if fanotify cannot be initialised on any flag combination.
pub fn fanotify_init_pre_content() -> io::Result<(OwnedFd, bool)> {
    for (flags, reports_tid) in [
        (
            FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | libc::FAN_REPORT_TID,
            true,
        ),
        (FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, false),
    ] {
        // SAFETY: `fanotify_init(unsigned int flags, unsigned int event_f_flags)`
        // with event_f_flags=0. The returned fd is owned exclusively by us.
        let raw_fd = unsafe { libc::syscall(libc::SYS_fanotify_init, flags, 0u32) };
        let fd = i32::try_from(raw_fd)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fanotify fd overflow"))?;
        if fd >= 0 {
            // SAFETY: freshly-returned kernel fd.
            return Ok((unsafe { OwnedFd::from_raw_fd(fd) }, reports_tid));
        }
        let err = io::Error::last_os_error();
        if reports_tid && matches!(err.raw_os_error(), Some(libc::EINVAL | libc::EOPNOTSUPP)) {
            continue;
        }
        return Err(err);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "fanotify_init failed",
    ))
}

/// Add a fanotify mark on a mount point path. Returns the mask actually
/// applied (without `FAN_PRE_ACCESS` when the kernel rejects it).
///
/// # Errors
/// Returns an error if the mark cannot be applied after the fallback attempt.
pub fn fanotify_mark(fan_fd: impl AsFd, path: &CStr, try_pre_access: bool) -> io::Result<u64> {
    let mask = if try_pre_access {
        FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM | FAN_PRE_ACCESS
    } else {
        FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM
    };
    // SAFETY: `fanotify_mark(int fanotify_fd, unsigned int flags, __u64 mask,
    // int dirfd, const char *pathname)`. The fd and path are live for the call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd.as_fd().as_raw_fd(),
            i64::from(FAN_MARK_ADD | FAN_MARK_MOUNT),
            mask,
            libc::AT_FDCWD,
            path.as_ptr(),
        )
    };
    if ret == 0 {
        return Ok(mask);
    }
    let err = io::Error::last_os_error();
    if try_pre_access && matches!(err.raw_os_error(), Some(libc::EINVAL | libc::EOPNOTSUPP)) {
        return fanotify_mark(fan_fd, path, false);
    }
    Err(err)
}

/// Kernel `struct fanotify_event_metadata`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FanotifyEventMetadata {
    /// Length of the event including any information records.
    pub event_len: u32,
    /// Version of this struct.
    pub vers: u8,
    pub reserved: u8,
    /// Length of the event metadata (not including information records).
    pub metadata_len: u16,
    /// Mask describing the event.
    pub mask: u64,
    /// Fd describing the object being accessed, or negative.
    pub fd: i32,
    /// Pid of the process that triggered the event.
    pub pid: i32,
}

/// Parse a `FanotifyEventMetadata` from a byte slice, bounds-checked.
///
/// Returns `None` when the slice is too short to hold the struct.
#[must_use]
pub const fn fanotify_event(bytes: &[u8]) -> Option<FanotifyEventMetadata> {
    let n = std::mem::size_of::<FanotifyEventMetadata>();
    if bytes.len() < n {
        return None;
    }
    let mut meta = std::mem::MaybeUninit::<FanotifyEventMetadata>::uninit();
    // SAFETY: `bytes` holds at least `n` bytes. `copy_nonoverlapping` copies
    // them into the `MaybeUninit` without forming a stricter-aligned pointer.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), std::ptr::addr_of_mut!(meta).cast::<u8>(), n);
    }
    Some(unsafe { meta.assume_init() })
}

/// Kernel `struct fanotify_response`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FanotifyResponse {
    pub fd: i32,
    pub response: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_type_reads_stream_socketpair() {
        let fds = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::empty(),
        )
        .expect("socketpair");
        assert_eq!(socket_type(&fds.0), Some(libc::SOCK_STREAM));
    }

    #[test]
    fn is_socket_connected_for_stream_pair() {
        let fds = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::empty(),
        )
        .expect("socketpair");
        assert!(is_socket_connected(&fds.0));
    }

    #[test]
    fn read_tracee_bytes_reads_self_memory() {
        let probe: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let self_pid = std::process::id();
        let addr = &raw const probe as u64;
        let out = read_tracee_bytes(self_pid, addr, probe.len()).expect("read self memory");
        assert_eq!(out, probe);
    }

    #[test]
    fn dup_tracee_fd_round_trips_dev_null() {
        use std::io::Read;
        let devnull = std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/null")
            .expect("open /dev/null");
        let self_pid = std::process::id();
        let dup = dup_tracee_fd(self_pid, devnull.as_fd().as_raw_fd()).expect("dup own fd");
        // The duplicated fd must be readable (devnull reads as EOF).
        let mut buf = [0u8; 1];
        let mut f = std::fs::File::from(dup);
        assert_eq!(f.read(&mut buf).unwrap_or(0), 0);
    }
}
