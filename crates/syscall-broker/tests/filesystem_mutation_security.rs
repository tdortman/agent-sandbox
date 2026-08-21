//! Security regression: broker filesystem mutation classification and dispatch.
//!
//! Multi-path syscalls register every affected endpoint for
//! `CheckFilesystem`, and dispatch denies when any endpoint is denied.

use std::{
    ffi::CString,
    os::fd::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
};

use agent_sandbox_core::FileAccess;
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    FilesystemMutation, FilesystemTarget, SeccompData, SeccompNotif, SyscallTarget,
    target_from_notification,
};

fn as_seccomp_nr(raw: i64) -> i32 {
    i32::try_from(raw).expect("syscall number fits in seccomp_data.nr")
}

fn notif_with_path_args(syscall_nr: i64, paths: &[&str]) -> SeccompNotif {
    let cstrings: Vec<CString> = paths
        .iter()
        .map(|path| CString::new(*path).expect("nul-free test path"))
        .collect();

    let mut args = [0_u64; 6];

    for (index, path) in cstrings.iter().enumerate() {
        args[index] = path.as_ptr().cast::<u8>() as u64;
    }

    // Keep CString values alive until the notification is consumed.
    std::mem::forget(cstrings);

    SeccompNotif {
        pid: std::process::id(),
        data: SeccompData {
            nr: as_seccomp_nr(syscall_nr),
            args,
            ..SeccompData::default()
        },
        ..SeccompNotif::default()
    }
}

fn root_dir() -> OwnedFd {
    std::fs::File::open("/").expect("open root").into()
}

fn filesystem_checks(notif: &SeccompNotif) -> Vec<(PathBuf, FileAccess)> {
    let target = target_from_notification(notif).expect("classify notification");

    let Some(SyscallTarget::Filesystem(FilesystemTarget { checks, .. })) = target else {
        panic!("expected filesystem mutation target");
    };

    checks
}

/// Contract mirrored from filesystem target dispatch: every `(path, access)`
/// pair must pass before the broker emulates the syscall.
async fn filesystem_mutation_allowed<F, Fut>(target: &FilesystemTarget, mut check: F) -> bool
where
    F: FnMut(&Path, FileAccess) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for (path, access) in &target.checks {
        if !check(path, *access).await {
            return false;
        }
    }

    true
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn rename_and_link_register_all_mutation_endpoints() {
    let rename_checks = filesystem_checks(&notif_with_path_args(nr::RENAME, &[
        "/repo/old.txt",
        "/repo/new.txt",
    ]));

    assert_eq!(
        rename_checks,
        vec![
            (PathBuf::from("/repo/old.txt"), FileAccess::ReadWrite),
            (PathBuf::from("/repo/new.txt"), FileAccess::ReadWrite),
        ],
        "rename must CheckFilesystem both source and destination with read_write"
    );

    let link_checks = filesystem_checks(&notif_with_path_args(nr::LINK, &[
        "/repo/src.txt",
        "/repo/dst.txt",
    ]));

    assert_eq!(
        link_checks,
        vec![
            (PathBuf::from("/repo/src.txt"), FileAccess::ReadWrite),
            (PathBuf::from("/repo/dst.txt"), FileAccess::ReadWrite),
        ],
        "link must CheckFilesystem both source and destination with read_write"
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn symlink_checks_target_read_and_linkpath_write() {
    let symlink_checks = filesystem_checks(&notif_with_path_args(nr::SYMLINK, &[
        "/tmp/target",
        "/tmp/link",
    ]));

    assert_eq!(
        symlink_checks,
        vec![
            (PathBuf::from("/tmp/target"), FileAccess::Read),
            (PathBuf::from("/tmp/link"), FileAccess::Write),
        ],
        "symlink must CheckFilesystem target read and linkpath write"
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn single_path_mutation_syscalls_require_write_access() {
    for (syscall_nr, path) in [(nr::UNLINK, "/tmp/gone"), (nr::TRUNCATE, "/tmp/file")] {
        let checks = filesystem_checks(&notif_with_path_args(syscall_nr, &[path]));

        assert_eq!(
            checks,
            vec![(PathBuf::from(path), FileAccess::Write)],
            "syscall {syscall_nr} must require write on the affected path"
        );
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn mkdir_skips_policy_only_when_target_exists() {
    let current_dir = std::env::current_dir().expect("current directory");
    let existing = current_dir.to_string_lossy();
    let existing_target = target_from_notification(&notif_with_path_args(nr::MKDIR, &[&existing]))
        .expect("classify existing mkdir");
    assert!(matches!(
        existing_target,
        Some(SyscallTarget::Errno(libc::EEXIST))
    ));

    let missing = current_dir.join(format!(
        ".agent-sandbox-missing-mkdir-{}",
        std::process::id()
    ));
    assert!(!missing.exists());
    let missing_text = missing.to_string_lossy();
    let missing_target =
        target_from_notification(&notif_with_path_args(nr::MKDIR, &[&missing_text]))
            .expect("classify missing mkdir");
    let Some(SyscallTarget::Filesystem(FilesystemTarget { checks, .. })) = missing_target else {
        panic!("missing mkdir must still require policy");
    };
    assert_eq!(checks, vec![(missing, FileAccess::Write)]);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn filesystem_mutation_captures_path_before_policy() {
    let original = CString::new("/tmp/agent-sandbox-stable-path").expect("nul-free path");
    let swapped = CString::new("/tmp/agent-sandbox-swapped-path").expect("nul-free path");
    let mut notif = notif_with_path_args(nr::UNLINK, &[original.to_string_lossy().as_ref()]);
    let target = target_from_notification(&notif).expect("classify unlink");
    notif.data.args[0] = swapped.as_ptr().cast::<u8>() as u64;
    assert_eq!(notif.data.args[0], swapped.as_ptr().cast::<u8>() as u64);

    let Some(SyscallTarget::Filesystem(FilesystemTarget {
        operation: FilesystemMutation::Unlink { path, .. },
        ..
    })) = target
    else {
        panic!("expected captured unlink");
    };

    assert_eq!(path, original.as_bytes());
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn relative_mutation_captures_tracee_cwd() {
    let notif = notif_with_path_args(nr::UNLINK, &["relative-path"]);
    let target = target_from_notification(&notif).expect("classify relative unlink");
    let current_dir = std::env::current_dir().expect("current directory");

    let Some(SyscallTarget::Filesystem(FilesystemTarget {
        checks,
        operation: FilesystemMutation::Unlink { dir, path, .. },
    })) = target
    else {
        panic!("expected captured relative unlink");
    };

    assert_eq!(checks, vec![(
        current_dir.join("relative-path"),
        FileAccess::Write
    )]);
    assert_eq!(path, b"relative-path");
    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .expect("read captured cwd"),
        current_dir
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn relative_unlinkat_accepts_zero_extended_at_fdcwd() {
    let mut notif = notif_with_path_args(nr::UNLINKAT, &["relative-path"]);
    notif.data.args[1] = notif.data.args[0];
    notif.data.args[0] = u64::from(libc::AT_FDCWD.cast_unsigned());

    assert_eq!(filesystem_checks(&notif), vec![(
        std::env::current_dir()
            .expect("current directory")
            .join("relative-path"),
        FileAccess::Write,
    )]);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn relative_renameat2_accepts_zero_extended_at_fdcwd() {
    let mut notif = notif_with_path_args(nr::RENAMEAT2, &["old-path", "new-path"]);
    let old = notif.data.args[0];
    let new = notif.data.args[1];
    let at_fdcwd = u64::from(libc::AT_FDCWD.cast_unsigned());
    notif.data.args = [at_fdcwd, old, at_fdcwd, new, 0, 0];

    let current_dir = std::env::current_dir().expect("current directory");
    assert_eq!(filesystem_checks(&notif), vec![
        (current_dir.join("old-path"), FileAccess::ReadWrite,),
        (current_dir.join("new-path"), FileAccess::ReadWrite,),
    ]);
}

#[tokio::test]
async fn filesystem_mutation_dispatch_denies_when_any_endpoint_denied() {
    let target = FilesystemTarget {
        checks: vec![
            (PathBuf::from("/repo/allowed.txt"), FileAccess::ReadWrite),
            (PathBuf::from("/repo/denied.txt"), FileAccess::ReadWrite),
        ],
        operation: FilesystemMutation::Truncate {
            dir: root_dir(),
            path: b"/repo/allowed.txt".to_vec(),
            len: 0,
        },
    };

    let mut calls = 0_u32;

    let allowed = filesystem_mutation_allowed(&target, |path, _access| {
        calls += 1;
        let ok = path != Path::new("/repo/denied.txt");
        async move { ok }
    })
    .await;

    assert!(
        !allowed,
        "broker must deny the syscall when any mutation endpoint fails CheckFilesystem"
    );

    assert_eq!(
        calls, 2,
        "broker must evaluate every endpoint up to the first denial"
    );
}

#[tokio::test]
async fn filesystem_mutation_dispatch_short_circuits_on_first_denial() {
    let target = FilesystemTarget {
        checks: vec![
            (PathBuf::from("/repo/denied.txt"), FileAccess::ReadWrite),
            (PathBuf::from("/repo/allowed.txt"), FileAccess::ReadWrite),
        ],
        operation: FilesystemMutation::Truncate {
            dir: root_dir(),
            path: b"/repo/denied.txt".to_vec(),
            len: 0,
        },
    };

    let mut calls = 0_u32;

    let allowed = filesystem_mutation_allowed(&target, |path, _access| {
        calls += 1;
        let ok = path != Path::new("/repo/denied.txt");
        async move { ok }
    })
    .await;

    assert!(!allowed);

    assert_eq!(
        calls, 1,
        "broker should stop checking once a mutation endpoint is denied"
    );
}
