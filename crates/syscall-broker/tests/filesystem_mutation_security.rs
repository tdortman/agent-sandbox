//! Security regression: broker filesystem mutation classification and dispatch.
//!
//! Multi-path syscalls register every affected endpoint for
//! `CheckFilesystem`, and dispatch denies when any endpoint is denied.

use std::{
    ffi::CString,
    os::fd::{AsFd, AsRawFd},
    path::PathBuf,
};

use agent_sandbox_core::FileAccess;
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_syscall_broker::{
    FilesystemMutation, FilesystemTarget, MutationDir, SeccompData, SeccompNotif, SyscallTarget,
    init_root_handle, target_from_notification,
};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn ensure_root_handle() {
    init_root_handle().expect("init root handle");
}

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

    let Some(SyscallTarget::Filesystem(FilesystemTarget { checks, .. })) = target else {
        panic!("expected filesystem mutation target");
    };

    checks
}

fn ftruncate_target(fd: &impl AsFd, len: u64) -> FilesystemTarget {
    let notif = SeccompNotif {
        pid: std::process::id(),
        data: SeccompData {
            nr: as_seccomp_nr(nr::FTRUNCATE),
            args: [
                u64::try_from(fd.as_fd().as_raw_fd()).unwrap(),
                len,
                0,
                0,
                0,
                0,
            ],
            ..SeccompData::default()
        },
        ..SeccompNotif::default()
    };
    let Some(SyscallTarget::Filesystem(target)) =
        target_from_notification(&notif).expect("classify ftruncate")
    else {
        panic!("expected pinned filesystem operation");
    };
    target
}

#[test]
fn ftruncate_memfd_resizes_pinned_memory_without_path_approval() {
    ensure_root_handle();
    let mut fd =
        nix::sys::memfd::memfd_create(c"state table", nix::sys::memfd::MFdFlags::MFD_CLOEXEC)
            .expect("anonymous memory file");
    let target = ftruncate_target(&fd, 8192);
    assert_eq!(target.checks, Vec::new(), "memory is not a filesystem path");
    let FilesystemMutation::Ftruncate { fd: captured, len } = target.operation else {
        panic!("expected pinned ftruncate");
    };
    nix::unistd::dup2(std::fs::File::open("/dev/null").unwrap(), &mut fd).unwrap();
    agent_sandbox_sysutil::ftruncate(&captured, len).expect("resize pinned memory");
    assert_eq!(nix::sys::stat::fstat(&captured).unwrap().st_size, 8192);
    assert_eq!(nix::sys::stat::fstat(&fd).unwrap().st_size, 0);
}

#[test]
fn ftruncate_memfd_preserves_kernel_seals() {
    let fd = nix::sys::memfd::memfd_create(
        c"allocation fd",
        nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .unwrap();
    agent_sandbox_sysutil::ftruncate(&fd, 4096).unwrap();
    let target = ftruncate_target(&fd, 8192);
    assert_eq!(target.checks, Vec::new());
    nix::fcntl::fcntl(
        &fd,
        nix::fcntl::FcntlArg::F_ADD_SEALS(nix::fcntl::SealFlag::F_SEAL_GROW),
    )
    .unwrap();
    let FilesystemMutation::Ftruncate { fd: captured, len } = target.operation else {
        panic!("expected pinned ftruncate");
    };
    assert_eq!(
        agent_sandbox_sysutil::ftruncate(&captured, len)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM),
    );
    assert_eq!(nix::sys::stat::fstat(&fd).unwrap().st_size, 4096);
}

#[test]
fn ftruncate_named_deleted_and_tmpfile_objects_still_require_approval() {
    ensure_root_handle();
    for directory in [std::env::temp_dir(), PathBuf::from("/dev/shm")] {
        let path = directory.join(format!(
            "memfd:broker-regression-{} (deleted)",
            std::process::id()
        ));
        let fd = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let named = ftruncate_target(&fd, 8192);
        std::fs::remove_file(&path).unwrap();
        let deleted = ftruncate_target(&fd, 8192);
        assert_eq!(named.checks.len(), 1);
        assert_eq!(named.checks[0].0, path);
        assert_eq!(named.checks[0].1, FileAccess::Write);
        assert_eq!(deleted.checks.len(), 1);
        assert_eq!(deleted.checks[0].1, FileAccess::Write);

        let anonymous = nix::fcntl::open(
            &directory,
            nix::fcntl::OFlag::O_TMPFILE | nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let target = ftruncate_target(&anonymous, 8192);
        assert_eq!(target.checks.len(), 1);
        assert_eq!(target.checks[0].1, FileAccess::Write);
    }
}

fn linkat_notif(source: &str, destination: &str, flags: u64) -> SeccompNotif {
    let mut notif = notif_with_path_args(nr::LINKAT, &[source, destination]);
    notif.data.args = [
        i64::from(libc::AT_FDCWD).cast_unsigned(),
        notif.data.args[0],
        i64::from(libc::AT_FDCWD).cast_unsigned(),
        notif.data.args[1],
        flags,
        0,
    ];
    notif
}

#[test]
fn linkat_anonymous_file_checks_backing_directory() {
    ensure_root_handle();
    let root = std::env::temp_dir().join(format!("broker-tmpfile-{}", std::process::id()));
    std::fs::create_dir(&root).expect("temporary directory");
    let fd = nix::fcntl::open(
        &root,
        nix::fcntl::OFlag::O_TMPFILE | nix::fcntl::OFlag::O_RDWR,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("anonymous temporary file");
    nix::unistd::write(&fd, b"anonymous contents").expect("write source");
    let source = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let destination = root.join("installed");
    let notif = linkat_notif(
        &source,
        &destination.to_string_lossy(),
        libc::AT_SYMLINK_FOLLOW as u64,
    );
    let Some(SyscallTarget::Filesystem(FilesystemTarget {
        checks,
        operation:
            FilesystemMutation::LinkFd {
                fd: captured,
                new_dir,
                new,
                flags,
            },
    })) = target_from_notification(&notif).expect("classify anonymous source")
    else {
        panic!("expected pinned descriptor link");
    };
    drop(fd);
    let captured_path = CString::new(format!("/proc/self/fd/{}", captured.as_raw_fd())).unwrap();
    agent_sandbox_sysutil::linkat(
        &MutationDir::Root,
        &captured_path,
        &new_dir,
        &CString::new(new).unwrap(),
        flags.cast_signed(),
    )
    .expect("link pinned anonymous file after original fd closes");
    let contents = std::fs::read(&destination).expect("installed file");
    std::fs::remove_dir_all(&root).expect("remove temporary directory");
    assert_eq!(checks[0], (root, FileAccess::ReadWrite));
    assert_eq!(checks[1], (destination, FileAccess::ReadWrite));
    assert_eq!(contents, b"anonymous contents");
}

#[test]
fn linkat_named_source_pins_fd_and_checks_actual_path() {
    ensure_root_handle();
    let root = std::env::temp_dir().join(format!("broker-link-fd-{}", std::process::id()));
    std::fs::create_dir(&root).expect("temporary directory");
    let source = root.join("source");
    std::fs::write(&source, b"original contents").unwrap();
    let mut fd: std::os::fd::OwnedFd = std::fs::File::open(&source).unwrap().into();
    let alias = format!("/proc/thread-self/fd/{}", fd.as_raw_fd());
    let notif = linkat_notif(
        &alias,
        "/unapproved/destination",
        libc::AT_SYMLINK_FOLLOW as u64,
    );
    let Some(SyscallTarget::Filesystem(FilesystemTarget {
        checks,
        operation: FilesystemMutation::LinkFd { fd: captured, .. },
    })) = target_from_notification(&notif).expect("classify named source")
    else {
        panic!("expected pinned descriptor link");
    };
    nix::unistd::dup2(std::fs::File::open("/dev/null").unwrap(), &mut fd).unwrap();
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut std::fs::File::from(captured), &mut contents).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(contents, "original contents");
    assert_eq!(checks, vec![
        (source, FileAccess::ReadWrite),
        (
            PathBuf::from("/unapproved/destination"),
            FileAccess::ReadWrite
        ),
    ]);
}

#[test]
fn linkat_without_follow_does_not_capture_proc_descriptor() {
    ensure_root_handle();
    let fd = std::fs::File::open("/dev/null").unwrap();
    let alias = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let notif = linkat_notif(&alias, "/unapproved/destination", 0);
    assert!(matches!(
        target_from_notification(&notif).unwrap(),
        Some(SyscallTarget::Filesystem(FilesystemTarget {
            operation: FilesystemMutation::Link { flags: 0, .. },
            ..
        }))
    ));
}

#[test]
fn linkat_missing_proc_descriptor_returns_ebadf_without_policy() {
    ensure_root_handle();
    let notif = linkat_notif(
        "/proc/self/fd/2147483647",
        "/unapproved/destination",
        libc::AT_SYMLINK_FOLLOW as u64,
    );
    assert!(matches!(
        target_from_notification(&notif).unwrap(),
        Some(SyscallTarget::Errno(libc::EBADF))
    ));
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn rename_and_link_register_all_mutation_endpoints() {
    ensure_root_handle();
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
    ensure_root_handle();
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
    ensure_root_handle();
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
    ensure_root_handle();
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
fn long_multicomponent_path_classifies_full_endpoint() {
    ensure_root_handle();
    let mut long = String::from("/tmp");
    while long.len() <= 256 {
        long.push_str("/abcdefghijklmno");
    }
    let notif = notif_with_path_args(nr::UNLINK, &[&long]);
    assert_eq!(
        filesystem_checks(&notif),
        vec![(PathBuf::from(&long), FileAccess::Write)],
        "path beyond the 256-byte prefix must authorize the full endpoint"
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn unterminated_path_max_buffer_is_enametoolong() {
    ensure_root_handle();
    let len = libc::PATH_MAX as usize;
    let buf = vec![b'a'; len];
    let ptr = buf.as_ptr() as u64;
    let notif = SeccompNotif {
        pid: std::process::id(),
        data: SeccompData {
            nr: as_seccomp_nr(nr::UNLINK),
            args: [ptr, 0, 0, 0, 0, 0],
            ..SeccompData::default()
        },
        ..SeccompNotif::default()
    };

    let target = target_from_notification(&notif).expect("classify unterminated path");
    assert!(
        matches!(target, Some(SyscallTarget::Errno(libc::ENAMETOOLONG))),
        "PATH_MAX bytes without NUL must be ENAMETOOLONG, not a truncated authorization"
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn relative_mutation_captures_tracee_cwd() {
    ensure_root_handle();
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

    let MutationDir::Handle(dir) = dir else {
        panic!("relative unlink must pin a directory handle");
    };

    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .expect("read captured cwd"),
        current_dir
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn relative_mutation_resolves_live_symlink_targets() {
    ensure_root_handle();
    let cwd = std::env::current_dir().expect("current directory");
    let root = cwd.join(format!("broker-relative-{}", std::process::id()));
    std::fs::create_dir(&root).expect("temporary directory");
    let first = root.join("first");
    let second = root.join("second");
    let alias = root.join("alias");
    std::fs::write(&first, b"first").expect("first file");
    std::fs::write(&second, b"second").expect("second file");
    std::os::unix::fs::symlink(&first, &alias).expect("first alias");

    let relative = alias
        .strip_prefix(&cwd)
        .expect("relative alias")
        .to_string_lossy();

    let notif = notif_with_path_args(nr::UNLINK, &[&relative]);
    let before = filesystem_checks(&notif);
    std::fs::remove_file(&alias).expect("remove alias");
    std::os::unix::fs::symlink(&second, &alias).expect("retarget alias");
    let after = filesystem_checks(&notif);
    std::fs::remove_dir_all(&root).expect("remove temporary directory");
    assert_eq!(before, vec![(first, FileAccess::Write)]);
    assert_eq!(after, vec![(second, FileAccess::Write)]);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn relative_unlinkat_accepts_zero_extended_at_fdcwd() {
    ensure_root_handle();
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
    ensure_root_handle();
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
