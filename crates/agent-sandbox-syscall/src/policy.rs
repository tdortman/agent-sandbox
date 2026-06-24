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

/// The set of syscalls the default policy cares about for the native arch.
#[must_use]
pub fn default_syscalls() -> BTreeSet<i64> {
    [
        nr::SENDTO,
        nr::SENDMMSG,
        nr::CONNECT,
        nr::WRITE,
        nr::WRITEV,
        nr::SENDFILE,
        nr::SOCKET,
        nr::SOCKETPAIR,
        nr::CLONE3,
        nr::UNSHARE,
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn default_syscalls_contains_socket_syscalls() {
        let syscalls = default_syscalls();
        assert!(syscalls.contains(&nr::SOCKET));
        assert!(syscalls.contains(&nr::SOCKETPAIR));
        assert!(syscalls.contains(&nr::CLONE3));
        assert!(syscalls.contains(&nr::UNSHARE));
    }

    #[test]
    fn default_syscalls_is_non_empty_on_supported_arch() {
        let syscalls = default_syscalls();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert!(!syscalls.is_empty());
    }
}
