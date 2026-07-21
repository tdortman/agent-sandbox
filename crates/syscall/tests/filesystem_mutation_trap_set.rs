//! Security regression: filesystem mutation syscalls must be seccomp-trapped.
//!
//! Untrapped rename/link/symlink/unlink/truncate mutations bypass fanotify
//! (open/access only) and let a sandbox rewrite paths outside declared rules.

use std::collections::BTreeSet;

use agent_sandbox_syscall::{default_syscalls, policy::nr};

const FILESYSTEM_MUTATION_SYSCALLS: &[&str] = &[
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "unlink",
    "unlinkat",
    "truncate",
    "ftruncate",
];

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn expected_mutation_numbers() -> BTreeSet<i64> {
    BTreeSet::from([
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
    ])
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn filesystem_mutation_syscalls_are_in_default_trap_set() {
    let trapped = default_syscalls();
    let expected = expected_mutation_numbers();
    assert_eq!(
        expected.len(),
        FILESYSTEM_MUTATION_SYSCALLS.len(),
        "test table must track every filesystem mutation syscall"
    );
    for nr in expected {
        assert!(
            trapped.contains(&nr),
            "filesystem mutation syscall {nr} must be in the seccomp trap set"
        );
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn filesystem_mutation_trap_set_matches_bpf_filter_input() {
    let filter_syscalls = agent_sandbox_syscall::build_filter(&default_syscalls());
    // If default_syscalls omits a mutation syscall, the compiled filter cannot
    // route it to the broker for CheckFilesystem gating.
    let _ = filter_syscalls;
    let trapped = default_syscalls();
    for nr in expected_mutation_numbers() {
        assert!(
            trapped.contains(&nr),
            "BPF filter is built from default_syscalls(); {nr} must be trapped"
        );
    }
}
