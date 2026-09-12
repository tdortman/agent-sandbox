//! The open/openat BPF conditions allow provably device-free opens in-kernel.
//!
//! A child installs the default filter with no notification listener, so any
//! trapped syscall fails with `ENOSYS` instead of reaching a broker. Opens
//! whose flags prove no device node is reachable must succeed; every other
//! open-family shape must trap. This pins the exact predicate the broker's
//! `open_flags_prove_not_a_device` check implements, so the two layers can
//! never disagree about what reaches userspace.
//!
//! Raw `fork`/`seccomp` oracle: no safe wrapper exists in this crate's
//! dependency closure for installing a filter in a child, so the test uses
//! libc directly and confines every effect to the forked child.
#![allow(
    unsafe_code,
    reason = "raw fork/seccomp oracle confined to a test child"
)]
#![cfg(target_os = "linux")]

use std::{ffi::CString, os::unix::ffi::OsStrExt, path::PathBuf};

use agent_sandbox_syscall::{build_filter, default_syscalls};

fn c(s: &std::ffi::OsStr) -> CString {
    CString::new(s.as_bytes()).expect("probe path has no interior nul")
}

#[test]
fn open_flag_conditions_match_the_broker_predicate() {
    let base: PathBuf = std::env::temp_dir().join(format!("bpf-open-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("probe dir");
    std::fs::write(base.join("exists.txt"), b"probe").expect("probe file");

    let dir = c(base.as_os_str());
    let exists = c(base.join("exists.txt").as_os_str());
    let fresh = c(base.join("fresh.txt").as_os_str());
    let fresh_creat = c(base.join("fresh-creat.txt").as_os_str());
    let filter = build_filter(&default_syscalls());

    // Everything the child touches is built before `fork`: after forking a
    // multithreaded test runner only async-signal-safe calls are allowed.
    // SAFETY: `fork` is called with no locks held by this test thread, and the
    // child only issues async-signal-safe syscalls before `_exit`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // SAFETY: `child` never returns and touches only the pre-built
        // arguments shared copy-on-write after `fork`.
        unsafe { child(&filter, &dir, &exists, &fresh, &fresh_creat) };
    }

    let mut status = 0;
    // SAFETY: `status` is a live stack slot and `pid` is the forked child.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "BPF probe failed at check {}",
        libc::WEXITSTATUS(status)
    );
}

/// Install the filter with no listener and exit with the first failing check.
unsafe fn child(
    filter: &[seccompiler::sock_filter],
    dir: &CString,
    exists: &CString,
    fresh: &CString,
    fresh_creat: &CString,
) -> ! {
    // SAFETY: all pointers (`filter`, the `CString` bytes) were built before
    // `fork` and are only read; every syscall below is async-signal-safe, and
    // the function never returns to the test runner.
    unsafe {
        // Check numbers start at 1; exit code 0 means every check passed.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            libc::_exit(100);
        }
        let mut prog = libc::sock_fprog {
            len: u16::try_from(filter.len()).unwrap_or(u16::MAX),
            filter: filter.as_ptr().cast::<libc::sock_filter>().cast_mut(),
        };
        let installed = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
            0,
            std::ptr::addr_of_mut!(prog),
        );
        if installed != 0 {
            libc::_exit(101);
        }

        // 1: O_DIRECTORY opens a directory, never a device.
        if libc::openat(
            libc::AT_FDCWD,
            dir.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        ) < 0
        {
            libc::_exit(1);
        }
        // 2: same predicate via `open` (flags are args[1] there).
        if libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) < 0 {
            libc::_exit(2);
        }
        // 3: a plain read open still traps (ENOSYS with no listener).
        if libc::openat(libc::AT_FDCWD, exists.as_ptr(), libc::O_RDONLY) >= 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
        {
            libc::_exit(3);
        }
        // 4: O_CREAT|O_EXCL fails EEXIST on anything existing, so it creates.
        if libc::openat(
            libc::AT_FDCWD,
            fresh.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) < 0
        {
            libc::_exit(4);
        }
        // 5: O_CREAT without O_EXCL can truncate a device, so it still traps.
        if libc::openat(
            libc::AT_FDCWD,
            exists.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT,
            0o600,
        ) >= 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
        {
            libc::_exit(5);
        }
        // 6: creat takes no flags and always traps.
        if libc::creat(fresh_creat.as_ptr(), 0o600) >= 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
        {
            libc::_exit(6);
        }
        libc::_exit(0);
    }
}
