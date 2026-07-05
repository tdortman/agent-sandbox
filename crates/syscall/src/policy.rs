//! Default syscall sets for the seccomp BPF filter.
//!
//! Numbers are sourced from the `libc` crate (which tracks the kernel
//! syscall table per arch) and re-exported under short names so the
//! broker and tests can spell out what they want to trap. On both
//! `x86_64` and aarch64 the agent-side filter traps packet-emitting
//! syscalls and routes them to the user-notification broker.

use std::collections::BTreeSet;

/// Syscall numbers for the native arch.
///
/// Sourced from `libc` so the values follow the kernel's per-arch
/// syscall table without manual duplication. Re-exported under short
/// names so the broker and tests can reference them without the
/// `SYS_` prefix.
pub mod nr {
    pub use libc::{
        SYS_clone3 as CLONE3, SYS_connect as CONNECT, SYS_creat as CREAT,
        SYS_io_uring_enter as IO_URING_ENTER, SYS_io_uring_register as IO_URING_REGISTER,
        SYS_io_uring_setup as IO_URING_SETUP, SYS_open as OPEN, SYS_openat as OPENAT,
        SYS_openat2 as OPENAT2, SYS_sendfile as SENDFILE, SYS_sendmmsg as SENDMMSG,
        SYS_sendmsg as SENDMSG, SYS_sendto as SENDTO, SYS_socket as SOCKET,
        SYS_socketpair as SOCKETPAIR, SYS_unshare as UNSHARE, SYS_write as WRITE,
        SYS_writev as WRITEV,
    };

    /// Filesystem mutation syscalls, re-exported when `libc` defines them for the target.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub use libc::{
        SYS_ftruncate as FTRUNCATE, SYS_link as LINK, SYS_linkat as LINKAT, SYS_rename as RENAME,
        SYS_renameat as RENAMEAT, SYS_renameat2 as RENAMEAT2, SYS_symlink as SYMLINK,
        SYS_symlinkat as SYMLINKAT, SYS_truncate as TRUNCATE, SYS_unlink as UNLINK,
        SYS_unlinkat as UNLINKAT,
    };
}

/// Audit arch value for the native architecture, used by the broker to
/// sanity-check tracee pointers. The constants match the values emitted by
/// the kernel in `struct seccomp_data.arch`.
pub const AUDIT_ARCH_NATIVE: u32 = match () {
    #[cfg(target_arch = "x86_64")]
    () => 0xc000_003e,
    #[cfg(target_arch = "aarch64")]
    () => 0xc000_00b7,
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    () => 0,
};

/// x32 compat audit arch on `x86_64`. Non-native values must never reach
/// broker policy checks; the BPF filter kills these before allow fallback.
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_X86_32: u32 = 0x4000_0002;

/// i686 compat audit arch on `x86_64`. Non-native values must never reach
/// broker policy checks; the BPF filter kills these before allow fallback.
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_I686: u32 = 0x4000_0003;

/// Syscalls trapped by the seccomp filter and routed to the broker.
///
/// Resource-gate set: the syscalls the broker policy-gates for both
/// network egress and sandboxed resource access. Network-egress syscalls
/// (`connect`, `sendto`, `sendmsg`, `sendmmsg`) are routed to policyd via
/// the `Check` RPC. Resource-access syscalls (`open`, `openat`, `openat2`,
/// `creat`) are routed to policyd via the `CheckResource` RPC and emulated
/// with the broker's own privileges, so the tracee cannot open the device
/// directly. Filesystem mutation syscalls (`rename*`, `link*`, `symlink*`,
/// `unlink*`, `truncate`, `ftruncate`) are routed to policyd via the
/// `CheckFilesystem` RPC and continued on approval (not emulated). `sendmsg`
/// is now trapped because the arm no longer uses `sendmsg(SCM_RIGHTS)` to
/// pass the listener fd. It uses a `pipe2` handoff instead, so the bootstrap
/// deadlock that previously excluded `sendmsg` no longer applies. `io_uring_*`
/// syscalls are trapped so the broker can return `ENOSYS`; allowing rings would
/// let `IORING_OP_OPENAT` execute in-kernel outside seccomp user notification.
/// Never trap high-frequency I/O (`write`, `writev`, `sendfile`) or
/// thread/namespace syscalls (`clone3`, `unshare`). The broker is
/// single-threaded, so trapping them serializes every I/O call and thread spawn
/// and starves the sandboxed process until its runtime aborts. `SOCKET` is
/// excluded because the broker duplicates tracee socket fds via `pidfd_getfd` to
/// emulate connect/send. Trapping `socket` would deadlock that emulation path.
/// `PR_SET_NO_NEW_PRIVS` blocks `clone3` escape.
#[must_use]
pub fn default_syscalls() -> BTreeSet<i64> {
    let mut syscalls = BTreeSet::from([
        nr::CONNECT,
        nr::SENDTO,
        nr::SENDMSG,
        nr::SENDMMSG,
        nr::OPEN,
        nr::OPENAT,
        nr::OPENAT2,
        nr::CREAT,
        nr::IO_URING_SETUP,
        nr::IO_URING_ENTER,
        nr::IO_URING_REGISTER,
    ]);
    push_filesystem_mutation_syscalls(&mut syscalls);
    syscalls
}

/// Extend `syscalls` with filesystem mutation traps when `libc` exposes them.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn push_filesystem_mutation_syscalls(syscalls: &mut BTreeSet<i64>) {
    use nr::{
        FTRUNCATE, LINK, LINKAT, RENAME, RENAMEAT, RENAMEAT2, SYMLINK, SYMLINKAT, TRUNCATE, UNLINK,
        UNLINKAT,
    };
    for nr in [
        RENAME, RENAMEAT, RENAMEAT2, LINK, LINKAT, SYMLINK, SYMLINKAT, UNLINK, UNLINKAT, TRUNCATE,
        FTRUNCATE,
    ] {
        syscalls.insert(nr);
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn push_filesystem_mutation_syscalls(_syscalls: &mut BTreeSet<i64>) {}

#[cfg(test)]
mod tests {
    use super::{default_syscalls, nr};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn default_syscalls_contains_udp_entry_points() {
        let syscalls = default_syscalls();
        // Network egress set.
        assert!(syscalls.contains(&nr::SENDTO));
        assert!(syscalls.contains(&nr::SENDMSG));
        // io_uring setup/operation syscalls are trapped and denied with ENOSYS
        // by the broker; otherwise IORING_OP_OPENAT bypasses path mediation.
        assert!(syscalls.contains(&nr::IO_URING_SETUP));
        assert!(syscalls.contains(&nr::IO_URING_ENTER));
        assert!(syscalls.contains(&nr::IO_URING_REGISTER));
        assert!(syscalls.contains(&nr::SENDMMSG));
        assert!(syscalls.contains(&nr::CONNECT));
        // Resource open* set (the broker policy-gates device access).
        assert!(syscalls.contains(&nr::OPEN));
        assert!(syscalls.contains(&nr::OPENAT));
        assert!(syscalls.contains(&nr::OPENAT2));
        assert!(syscalls.contains(&nr::CREAT));
        // Filesystem mutation set (broker policy-gates via CheckFilesystem).
        assert!(syscalls.contains(&nr::RENAME));
        assert!(syscalls.contains(&nr::RENAMEAT));
        assert!(syscalls.contains(&nr::RENAMEAT2));
        assert!(syscalls.contains(&nr::LINK));
        assert!(syscalls.contains(&nr::LINKAT));
        assert!(syscalls.contains(&nr::SYMLINK));
        assert!(syscalls.contains(&nr::SYMLINKAT));
        assert!(syscalls.contains(&nr::UNLINK));
        assert!(syscalls.contains(&nr::UNLINKAT));
        assert!(syscalls.contains(&nr::TRUNCATE));
        assert!(syscalls.contains(&nr::FTRUNCATE));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn default_syscalls_contains_udp_entry_points() {
        // The aarch64 default syscalls are the same resource-gate set as
        // x86_64; the broker path is the only thing that differs.
        let syscalls = default_syscalls();
        assert!(syscalls.contains(&nr::SENDTO));
        assert!(syscalls.contains(&nr::SENDMSG));
        assert!(syscalls.contains(&nr::SENDMMSG));
        assert!(syscalls.contains(&nr::CONNECT));
        assert!(syscalls.contains(&nr::OPEN));
        assert!(syscalls.contains(&nr::OPENAT));
        assert!(syscalls.contains(&nr::OPENAT2));
        assert!(syscalls.contains(&nr::CREAT));
        assert!(syscalls.contains(&nr::RENAME));
        assert!(syscalls.contains(&nr::RENAMEAT));
        assert!(syscalls.contains(&nr::RENAMEAT2));
        assert!(syscalls.contains(&nr::LINK));
        assert!(syscalls.contains(&nr::LINKAT));
        assert!(syscalls.contains(&nr::SYMLINK));
        assert!(syscalls.contains(&nr::SYMLINKAT));
        assert!(syscalls.contains(&nr::UNLINK));
        assert!(syscalls.contains(&nr::IO_URING_SETUP));
        assert!(syscalls.contains(&nr::IO_URING_ENTER));
        assert!(syscalls.contains(&nr::IO_URING_REGISTER));
        assert!(syscalls.contains(&nr::UNLINKAT));
        assert!(syscalls.contains(&nr::TRUNCATE));
        assert!(syscalls.contains(&nr::FTRUNCATE));
    }

    /// Regression: high-frequency I/O and thread/namespace syscalls must
    /// stay out of the trap set. Trapping them serializes every write
    /// and every thread spawn through the single-threaded broker,
    /// starving the sandboxed process until its runtime aborts.
    #[test]
    fn default_syscalls_excludes_high_frequency_and_thread_syscalls() {
        let syscalls = default_syscalls();
        assert!(!syscalls.contains(&libc::SYS_write));
        assert!(!syscalls.contains(&libc::SYS_writev));
        assert!(!syscalls.contains(&libc::SYS_sendfile));
        assert!(!syscalls.contains(&libc::SYS_socket));
        assert!(!syscalls.contains(&libc::SYS_socketpair));
        assert!(!syscalls.contains(&libc::SYS_clone3));
        assert!(!syscalls.contains(&libc::SYS_unshare));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn compat_audit_arch_constants_match_linux_headers() {
        use super::{AUDIT_ARCH_I686, AUDIT_ARCH_X86_32};
        assert_eq!(AUDIT_ARCH_X86_32, 0x4000_0002);
        assert_eq!(AUDIT_ARCH_I686, 0x4000_0003);
        assert_ne!(AUDIT_ARCH_X86_32, super::AUDIT_ARCH_NATIVE);
        assert_ne!(AUDIT_ARCH_I686, super::AUDIT_ARCH_NATIVE);
    }

    #[test]
    fn default_syscalls_is_non_empty_on_supported_arch() {
        let syscalls = default_syscalls();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert!(!syscalls.is_empty());
    }

    /// Regression: filesystem mutation syscalls must be seccomp-trapped so the
    /// broker can policy-gate them via `CheckFilesystem`. Untrapped mutations
    /// bypass fanotify (open/access only) and let a sandbox rewrite paths
    /// outside the declared allow rules.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn default_syscalls_traps_filesystem_mutation_syscalls() {
        let syscalls = default_syscalls();
        for nr in [
            nr::RENAME,
            nr::RENAMEAT,
            nr::RENAMEAT2,
            nr::LINK,
            nr::LINKAT,
            nr::SYMLINK,
            nr::SYMLINKAT,
            nr::UNLINK,
            nr::UNLINKAT,
            nr::TRUNCATE,
            nr::FTRUNCATE,
        ] {
            assert!(
                syscalls.contains(&nr),
                "filesystem mutation syscall {nr} must be in the seccomp trap set"
            );
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn default_syscalls_traps_io_uring_syscalls() {
        let syscalls = default_syscalls();
        for nr in [
            nr::IO_URING_SETUP,
            nr::IO_URING_ENTER,
            nr::IO_URING_REGISTER,
        ] {
            assert!(
                syscalls.contains(&nr),
                "io_uring syscall {nr} must be trapped so the broker can return ENOSYS"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn io_uring_syscall_numbers_match_linux_x86_64_table() {
        assert_eq!(nr::IO_URING_SETUP, 425);
        assert_eq!(nr::IO_URING_ENTER, 426);
        assert_eq!(nr::IO_URING_REGISTER, 427);
    }
}
