//! Default syscall sets for the seccomp BPF filter.
//!
//! Numbers are sourced from the `libc` crate (which tracks the kernel
//! syscall table per arch) and re-exported under short names so the
//! broker and tests can spell out what they want to trap. On both
//! x86_64 and aarch64 the agent-side filter traps packet-emitting
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
        SYS_clone3 as CLONE3, SYS_connect as CONNECT, SYS_sendfile as SENDFILE,
        SYS_sendmmsg as SENDMMSG, SYS_sendmsg as SENDMSG, SYS_sendto as SENDTO,
        SYS_socket as SOCKET, SYS_socketpair as SOCKETPAIR, SYS_unshare as UNSHARE,
        SYS_write as WRITE, SYS_writev as WRITEV,
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

/// Syscalls trapped by the seccomp filter and routed to the broker.
///
/// Network-egress only: the syscalls the broker actually policy-gates
/// (`connect`, `sendto`, `sendmmsg`). `sendmsg` is intentionally not
/// trapped: the arm uses `sendmsg(SCM_RIGHTS)` to pass the seccomp
/// listener fd to the broker, and trapping it would deadlock the
/// bootstrap. Never trap high-frequency I/O (`write`, `writev`,
/// `sendfile`) or thread/namespace syscalls (`clone3`, `unshare`):
/// the broker is single-threaded, so trapping them serializes every
/// I/O call and thread spawn and starves the sandboxed process until
/// its runtime aborts. `PR_SET_NO_NEW_PRIVS` blocks `clone3` escape.
#[must_use]
pub fn default_syscalls() -> BTreeSet<i64> {
    [nr::SENDTO, nr::SENDMMSG, nr::CONNECT]
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{default_syscalls, nr};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn default_syscalls_contains_udp_entry_points() {
        let syscalls = default_syscalls();
        assert!(syscalls.contains(&nr::SENDTO));
        assert!(!syscalls.contains(&nr::SENDMSG));
        assert!(syscalls.contains(&nr::SENDMMSG));
        assert!(syscalls.contains(&nr::CONNECT));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn default_syscalls_contains_udp_entry_points() {
        // The aarch64 default syscalls are the same packet-emitting set as
        // x86_64; the broker path is the only thing that differs.
        let syscalls = default_syscalls();
        assert!(syscalls.contains(&nr::SENDTO));
        assert!(!syscalls.contains(&nr::SENDMSG));
        assert!(syscalls.contains(&nr::SENDMMSG));
        assert!(syscalls.contains(&nr::CONNECT));
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

    #[test]
    fn default_syscalls_is_non_empty_on_supported_arch() {
        let syscalls = default_syscalls();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert!(!syscalls.is_empty());
    }
}
