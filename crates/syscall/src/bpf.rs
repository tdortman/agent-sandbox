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

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

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
/// listed in `syscalls` on both `x86_64` and aarch64, except that
/// `open`/`openat` with flags proving no device node is reachable are
/// allowed in-kernel with no notification round trip (see
/// [`open_notify_rules`]). Any other syscall is allowed. The filter also
/// validates `struct seccomp_data.arch` against the target architecture,
/// killing the process on a mismatch.
/// # Panics
/// Panics if seccomp filter construction fails or the compiled BPF program
/// exceeds [`seccompiler::BPF_MAX_LEN`].
#[must_use]
pub fn build_filter(syscalls: &std::collections::BTreeSet<i64>) -> BpfProgram {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &nr in syscalls {
        // `open` takes flags as args[1] and `openat` as args[2].
        let rule = if nr == crate::policy::nr::OPEN {
            open_notify_rules(1)
        } else if nr == crate::policy::nr::OPENAT {
            open_notify_rules(2)
        } else {
            // An empty rule vector means "match this syscall regardless of
            // its arguments", which is what the agent's pass-through
            // notification model wants for everything else.
            Vec::new()
        };
        rules.insert(nr, rule);
    }

    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::UserNotif,
        target_arch(),
    )
    .expect("seccomp filter construction is total for non-empty rule maps")
    .try_into()
    .expect("seccomp filter length is bounded by seccompiler::BPF_MAX_LEN")
}

/// Notify rules for an open-family syscall whose flags are a direct register
/// argument: trap unless the flags prove no device node is reachable.
///
/// This is the in-kernel form of the broker's `open_flags_prove_not_a_device`
/// predicate, kept identical so verdicts never differ by layer: `O_DIRECTORY`
/// only opens a directory, and `O_CREAT|O_EXCL` fails with `EEXIST` on
/// anything that already exists, so neither can reach an existing device
/// node (the only target class the open gate covers) and both are allowed
/// without waking the broker. The predicate's negation is a disjunction
/// (`O_DIRECTORY` clear and `O_CREAT` clear, or `O_DIRECTORY` clear and
/// `O_EXCL` clear), so it takes two rules; a syscall matching either rule
/// notifies, and anything else falls through to the filter's default allow.
fn open_notify_rules(flags_arg: u8) -> Vec<SeccompRule> {
    let dir_clear = || {
        SeccompCondition::new(
            flags_arg,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(u64::from(libc::O_DIRECTORY as u32)),
            0,
        )
        .expect("open flag conditions use a valid arg index")
    };
    let creat_clear = SeccompCondition::new(
        flags_arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(u64::from(libc::O_CREAT as u32)),
        0,
    )
    .expect("open flag conditions use a valid arg index");
    let excl_clear = SeccompCondition::new(
        flags_arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(u64::from(libc::O_EXCL as u32)),
        0,
    )
    .expect("open flag conditions use a valid arg index");
    vec![
        SeccompRule::new(vec![dir_clear(), creat_clear])
            .expect("an open notify rule always carries conditions"),
        SeccompRule::new(vec![dir_clear(), excl_clear])
            .expect("an open notify rule always carries conditions"),
    ]
}

const fn target_arch() -> TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        TargetArch::x86_64
    }

    #[cfg(target_arch = "aarch64")]
    {
        TargetArch::aarch64
    }
}

#[cfg(test)]
mod tests {
    use super::build_filter;

    const RET_KILL_PROCESS: u32 = 0x8000_0000;

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
    fn filter_rejects_non_native_audit_arch_before_allow() {
        // seccompiler prepends an arch check: mismatch returns KILL_PROCESS
        // so x32/i686 compat syscalls cannot fall through to SECCOMP_RET_ALLOW.
        let filter = build_filter(&crate::policy::default_syscalls());

        assert!(
            filter.iter().any(|insn| insn.k == RET_KILL_PROCESS),
            "filter must kill non-native audit arch before allow fallback"
        );
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
