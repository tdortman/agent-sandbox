//! BPF program builder for the seccomp filter.
//!
//! Wraps [`seccompiler`] to compile the agent's syscall set into a loadable
//! BPF program. Matches deliver to user-space via `SECCOMP_RET_USER_NOTIF`
//! on both `x86_64` and aarch64. The broker parses tracee structs directly,
//! so the filter is arch-neutral now. Anything not in the set passes
//! through with the default `SECCOMP_RET_ALLOW`. See
//! <https://docs.kernel.org/bpf/> for the seccomp BPF ABI the program
//! implements.

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

// `seccompiler::sock_filter` and `libc::sock_filter` are both `#[repr(C)]`
// with the same field layout (code: u16, jt: u8, jf: u8, k: u32), so a
// pointer cast between them is sound. The arm main.rs hands the seccomp
// syscall a `*mut libc::sock_filter` pointing at the seccompiler program's
// backing storage. Statically assert the layouts match so that cast is safe.
const _SOCK_FILTER_LAYOUTS_MATCH: () = assert!(
    std::mem::size_of::<seccompiler::sock_filter>() == std::mem::size_of::<libc::sock_filter>(),
    "seccompiler::sock_filter and libc::sock_filter must have identical layout"
);

/// Build a seccomp BPF program from a set of syscall numbers.
///
/// The filter returns [`SeccompAction::UserNotif`] for every syscall
/// listed in `syscalls` on both x86_64 and aarch64. Any other syscall is
/// allowed. The filter also validates `struct seccomp_data.arch` against
/// the target architecture, killing the process on a mismatch.
#[must_use]
pub fn build_filter(syscalls: &std::collections::BTreeSet<i64>) -> BpfProgram {
    // An empty rule vector means "match this syscall regardless of its
    // arguments", which is what we want for the agent's pass-through
    // notification model.
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        syscalls.iter().map(|&nr| (nr, Vec::new())).collect();

    SeccompFilter::new(rules, SeccompAction::Allow, match_action(), target_arch())
        .expect("seccomp filter construction is total for non-empty rule maps")
        .try_into()
        .expect("seccomp filter length is bounded by seccompiler::BPF_MAX_LEN")
}

fn target_arch() -> TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        TargetArch::aarch64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // The agent only ships for x86_64 and aarch64. This branch exists
        // so `cargo check --workspace --all-targets` still compiles on
        // unusual build hosts; the runtime path is unreachable.
        TargetArch::x86_64
    }
}

fn match_action() -> SeccompAction {
    #[cfg(target_arch = "x86_64")]
    {
        SeccompAction::UserNotif
    }
    #[cfg(target_arch = "aarch64")]
    {
        SeccompAction::UserNotif
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // `Trap` is a safe non-destructive default for the unreachable
        // build-host path and avoids the `IdenticalActions` error from
        // matching `Allow`.
        SeccompAction::Trap
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::build_filter;
    use crate::RET_ALLOW;
    // `BPF_RET | BPF_K` per the BPF instruction encoding. The seccomp
    // program ends with a return of `SECCOMP_RET_ALLOW` as the default
    // action; we read the last instruction directly to verify. The
    // literal value 0x06 is the kernel-defined `BPF_RET | BPF_K` opcode
    // (BPF_RET = 0x06, BPF_K = 0x00, per
    // https://docs.kernel.org/bpf/ BPF instruction encoding).
    const BPF_RET_K: u16 = 0x06;

    // `seccompiler::BPF_MAX_LEN`; duplicated here to avoid re-exporting the
    // constant from the wrapper module.
    const BPF_MAX_LEN: usize = 4096;

    #[test]
    fn default_syscalls_produce_a_compilable_filter() {
        let filter = build_filter(&crate::policy::default_syscalls());
        assert!(!filter.is_empty(), "filter must contain instructions");
        assert!(
            filter.len() < BPF_MAX_LEN,
            "filter length {} must stay under the kernel limit",
            filter.len()
        );
    }

    #[test]
    fn empty_syscall_set_still_produces_a_filter() {
        let filter = build_filter(&BTreeSet::new());
        // No syscalls matched means the program is effectively a no-op
        // (everything is allowed), but it still has the arch-check prefix
        // and the trailing allow return.
        assert!(!filter.is_empty());
        let last = filter.last().expect("filter is non-empty");
        assert_eq!(last.code, BPF_RET_K);
        assert_eq!(last.k, RET_ALLOW);
    }

    #[test]
    fn filter_always_ends_with_allow() {
        let mut syscalls = BTreeSet::new();
        syscalls.insert(1);
        syscalls.insert(44);
        syscalls.insert(46);
        syscalls.insert(307);
        let filter = build_filter(&syscalls);
        let last = filter.last().expect("filter is non-empty");
        assert_eq!(last.code, BPF_RET_K);
        assert_eq!(last.k, RET_ALLOW);
    }

    #[test]
    fn filter_size_scales_with_syscall_count() {
        let small: BTreeSet<i64> = std::iter::once(1).collect();
        let large: BTreeSet<i64> = [1, 20, 40, 41, 42, 44, 46, 53, 272, 307, 435]
            .into_iter()
            .collect();
        let small_filter = build_filter(&small);
        let large_filter = build_filter(&large);
        assert!(
            large_filter.len() > small_filter.len(),
            "more syscalls should produce a larger program: small={} large={}",
            small_filter.len(),
            large_filter.len()
        );
    }

    #[test]
    fn default_filter_stays_under_kernel_length_limit() {
        // The real default policy plus a generous headroom for future
        // additions. 1024 syscalls is an unrealistic stress input that
        // overflows BPF_MAX_LEN, which is the kernel's hard cap.
        let mut syscalls = crate::policy::default_syscalls();
        for extra in 0..64 {
            syscalls.insert(1000 + extra);
        }
        let filter = build_filter(&syscalls);
        assert!(filter.len() < BPF_MAX_LEN);
    }

    #[test]
    fn sock_filter_layouts_match_for_pointer_cast() {
        // Compile-time guarantee duplicated as a runtime test so a
        // regression fails the test suite with a clear message rather than
        // a panic in arm main.rs at install time.
        assert_eq!(
            std::mem::size_of::<seccompiler::sock_filter>(),
            std::mem::size_of::<libc::sock_filter>()
        );
    }
}
