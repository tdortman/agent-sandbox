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
        SYS_clone3 as CLONE3, SYS_connect as CONNECT, SYS_creat as CREAT, SYS_open as OPEN,
        SYS_openat as OPENAT, SYS_openat2 as OPENAT2, SYS_sendfile as SENDFILE,
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
/// Resource-gate set: the syscalls the broker policy-gates for both
/// network egress and sandboxed resource access. Network-egress syscalls
/// (`connect`, `sendto`, `sendmsg`, `sendmmsg`) are routed to policyd via
/// the `Check` RPC. Resource-access syscalls (`open`, `openat`, `openat2`,
/// `creat`) are routed to policyd via the `CheckResource` RPC and emulated
/// with the broker's own privileges, so the tracee cannot open the device
/// directly. `sendmsg` is now trapped because the arm no longer uses
/// `sendmsg(SCM_RIGHTS)` to pass the listener fd. It uses a `pipe2`
/// handoff instead, so the bootstrap deadlock that previously excluded
/// `sendmsg` no longer applies. Never trap high-frequency I/O (`write`,
/// `writev`, `sendfile`) or thread/namespace syscalls (`clone3`,
/// `unshare`). The broker is single-threaded, so trapping them serializes
/// every I/O call and thread spawn and starves the sandboxed process until
/// its runtime aborts. `SOCKET` is excluded because the broker duplicates
/// tracee socket fds via `pidfd_getfd` to emulate connect/send. Trapping
/// `socket` would deadlock that emulation path. `PR_SET_NO_NEW_PRIVS`
/// blocks `clone3` escape.
#[must_use]
pub fn default_syscalls() -> BTreeSet<i64> {
    [
        nr::CONNECT,
        nr::SENDTO,
        nr::SENDMSG,
        nr::SENDMMSG,
        nr::OPEN,
        nr::OPENAT,
        nr::OPENAT2,
        nr::CREAT,
    ]
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
        // Network egress set.
        assert!(syscalls.contains(&nr::SENDTO));
        assert!(syscalls.contains(&nr::SENDMSG));
        assert!(syscalls.contains(&nr::SENDMMSG));
        assert!(syscalls.contains(&nr::CONNECT));
        // Resource open* set (the broker policy-gates device access).
        assert!(syscalls.contains(&nr::OPEN));
        assert!(syscalls.contains(&nr::OPENAT));
        assert!(syscalls.contains(&nr::OPENAT2));
        assert!(syscalls.contains(&nr::CREAT));
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
