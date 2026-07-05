//! Security regression: broker filesystem mutation classification and dispatch.
//!
//! Multi-path syscalls must register every affected endpoint for
//! `CheckFilesystem`, and dispatch must deny when any endpoint is denied.
//! Re-validation must reject path swaps before CONTINUE.

use std::ffi::CString;
use std::path::{Path, PathBuf};

use agent_sandbox_core::FileAccess;
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    FilesystemTarget, SeccompData, SeccompNotif, SyscallTarget, revalidate_filesystem_mutation,
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

fn filesystem_checks(notif: &SeccompNotif) -> Vec<(PathBuf, FileAccess)> {
    let target = target_from_notification(notif).expect("classify notification");
    let Some(SyscallTarget::Filesystem(FilesystemTarget { checks })) = target else {
        panic!("expected filesystem mutation target");
    };
    checks
}

/// Contract mirrored from `dispatch_filesystem_target` in main.rs: every
/// `(path, access)` pair must pass before the broker may continue.
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
    let rename_checks = filesystem_checks(&notif_with_path_args(
        nr::RENAME,
        &["/repo/old.txt", "/repo/new.txt"],
    ));
    assert_eq!(
        rename_checks,
        vec![
            (PathBuf::from("/repo/old.txt"), FileAccess::ReadWrite),
            (PathBuf::from("/repo/new.txt"), FileAccess::ReadWrite),
        ],
        "rename must CheckFilesystem both source and destination with read_write"
    );

    let link_checks = filesystem_checks(&notif_with_path_args(
        nr::LINK,
        &["/repo/src.txt", "/repo/dst.txt"],
    ));
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
    let symlink_checks = filesystem_checks(&notif_with_path_args(
        nr::SYMLINK,
        &["/tmp/target", "/tmp/link"],
    ));
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
fn filesystem_mutation_revalidation_rejects_path_swap() {
    let stable = CString::new("/tmp/agent-sandbox-stable-path").expect("nul-free path");
    let swapped = CString::new("/tmp/agent-sandbox-swapped-path").expect("nul-free path");
    let mut notif = notif_with_path_args(nr::UNLINK, &[stable.to_string_lossy().as_ref()]);
    let target = target_from_notification(&notif).expect("classify unlink");
    let Some(SyscallTarget::Filesystem(fs_target)) = target else {
        panic!("expected filesystem target");
    };
    revalidate_filesystem_mutation(&notif, &fs_target).expect("initial paths match");

    notif.data.args[0] = swapped.as_ptr().cast::<u8>() as u64;
    std::mem::forget(swapped);
    std::mem::forget(stable);
    let err = revalidate_filesystem_mutation(&notif, &fs_target).expect_err("swapped path");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn filesystem_mutation_dispatch_denies_when_any_endpoint_denied() {
    let target = FilesystemTarget {
        checks: vec![
            (PathBuf::from("/repo/allowed.txt"), FileAccess::ReadWrite),
            (PathBuf::from("/repo/denied.txt"), FileAccess::ReadWrite),
        ],
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
