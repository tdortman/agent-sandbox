//! Classification of filesystem mutations (`rename`, `link`, `symlink`,
//! `unlink`, `truncate`, `mkdir`, `mknod`, ...).
//!
//! Pointer-bearing arguments and tracee descriptors are copied while
//! classifying the syscall; the broker then emulates the captured operation.

use std::{
    ffi::OsStr,
    io,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    sync::OnceLock,
};

use agent_sandbox_core::{FileAccess, policy::FilesystemCheck};
use agent_sandbox_syscall::policy::nr;
use agent_sandbox_sysutil::read_tracee_path;

use crate::{
    SeccompNotif, SyscallTarget,
    capture::at_fdcwd_arg,
    errno_target,
    pinning::{DirBase, Resolver},
};

/// Captured operation semantics for a filesystem mutation. Pointer-bearing
/// arguments and tracee descriptors are copied while classifying the syscall.
#[derive(Debug)]
pub enum FilesystemMutation {
    /// Rename one captured path to another.
    Rename {
        /// Source directory descriptor.
        old_dir: MutationDir,

        /// Source pathname bytes.
        old: Vec<u8>,

        /// Destination directory descriptor.
        new_dir: MutationDir,

        /// Destination pathname bytes.
        new: Vec<u8>,

        /// `renameat2` flags.
        flags: u32,
    },

    /// Create a hard link.
    Link {
        /// Source directory descriptor.
        old_dir: MutationDir,

        /// Source pathname bytes.
        old: Vec<u8>,

        /// Destination directory descriptor.
        new_dir: MutationDir,

        /// Destination pathname bytes.
        new: Vec<u8>,

        /// `linkat` flags.
        flags: u32,
    },

    /// Follow a procfs descriptor link captured from the requesting task.
    LinkFd {
        /// Source descriptor pinned through authorization and execution.
        fd: OwnedFd,

        /// Destination directory descriptor.
        new_dir: MutationDir,

        /// Destination pathname bytes.
        new: Vec<u8>,

        /// Original `linkat` flags, including `AT_SYMLINK_FOLLOW`.
        flags: u32,
    },

    /// Create a symbolic link.
    Symlink {
        /// Link target bytes.
        target: Vec<u8>,

        /// Link directory descriptor.
        link_dir: MutationDir,

        /// Link pathname bytes.
        link: Vec<u8>,
    },

    /// Remove a directory entry.
    Unlink {
        /// Parent directory descriptor.
        dir: MutationDir,

        /// Entry pathname bytes.
        path: Vec<u8>,

        /// `unlinkat` flags.
        flags: u32,
    },

    /// Truncate a named file.
    Truncate {
        /// Captured cwd descriptor.
        dir: MutationDir,

        /// Captured pathname bytes.
        path: Vec<u8>,

        /// Requested length.
        len: i64,
    },

    /// Truncate an open file description.
    Ftruncate {
        /// Duplicated tracee descriptor.
        fd: OwnedFd,

        /// Requested length.
        len: i64,
    },

    /// Create a directory.
    Mkdir {
        /// Parent directory descriptor.
        dir: MutationDir,

        /// Directory pathname bytes.
        path: Vec<u8>,

        /// Requested mode.
        mode: u32,
    },

    /// Remove a directory.
    Rmdir {
        /// Parent directory descriptor.
        dir: MutationDir,

        /// Directory pathname bytes.
        path: Vec<u8>,
    },

    /// Create a filesystem node (regular file, FIFO, socket, device).
    Mknod {
        /// Parent directory descriptor.
        dir: MutationDir,

        /// Node pathname bytes.
        path: Vec<u8>,

        /// Requested mode, including the file type bits.
        mode: u32,

        /// Device number for device nodes.
        device: u64,
    },
}

/// Filesystem mutation target from a sandboxed syscall.
#[derive(Debug)]
pub struct FilesystemTarget {
    /// Path/access pairs to check against policyd's filesystem policy.
    pub checks: Vec<FilesystemCheck>,

    /// Immutable syscall operation captured at classification time.
    pub operation: FilesystemMutation,
}

/// Directory argument for an emulated filesystem syscall.
#[derive(Debug)]
pub enum MutationDir {
    /// Directory handle pinned at capture time; captured names are relative.
    Handle(OwnedFd),

    /// The captured name is absolute and the kernel ignores the directory, so
    /// `AT_FDCWD` stands in for it.
    Root,
}

impl AsFd for MutationDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Handle(fd) => fd.as_fd(),
            Self::Root => nix::fcntl::AT_FDCWD,
        }
    }
}

const fn filesystem_target(
    checks: Vec<FilesystemCheck>,
    operation: FilesystemMutation,
) -> SyscallTarget {
    SyscallTarget::Filesystem(FilesystemTarget { checks, operation })
}

fn path_from_raw(raw: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(raw))
}

/// Directory handle and raw name captured from the tracee at
/// classification time, before any policy round trip.
struct CapturedPath {
    dir: MutationDir,
    raw: Vec<u8>,
}

fn capture_path(
    resolver: &Resolver,
    notif: &SeccompNotif,
    dirfd: u64,
    ptr: u64,
) -> io::Result<CapturedPath> {
    let raw = read_tracee_path(notif.pid, ptr)?;

    if raw.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }

    if raw.starts_with(b"/") {
        return Ok(CapturedPath {
            dir: MutationDir::Root,
            raw,
        });
    }

    Ok(CapturedPath {
        dir: MutationDir::Handle(resolver.pin_dir(notif.pid, DirBase::from_arg(dirfd)?)?),
        raw,
    })
}

/// Policy path for a captured name: the pinned object's canonical path.
fn check_path(resolver: &Resolver, path: &CapturedPath) -> io::Result<PathBuf> {
    resolver.normalize_captured_path(&path.dir, &path.raw)
}

fn two_path_target(
    resolver: &Resolver,
    notif: &SeccompNotif,
    old_dirfd: u64,
    old_ptr: u64,
    new_dirfd: u64,
    new_ptr: u64,
    operation: impl FnOnce(MutationDir, Vec<u8>, MutationDir, Vec<u8>) -> FilesystemMutation,
) -> io::Result<SyscallTarget> {
    let old = capture_path(resolver, notif, old_dirfd, old_ptr)?;
    let new = capture_path(resolver, notif, new_dirfd, new_ptr)?;

    Ok(filesystem_target(
        vec![
            FilesystemCheck {
                path: check_path(resolver, &old)?,
                access: FileAccess::ReadWrite,
            },
            FilesystemCheck {
                path: check_path(resolver, &new)?,
                access: FileAccess::ReadWrite,
            },
        ],
        operation(old.dir, old.raw, new.dir, new.raw),
    ))
}

fn target_from_rename(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    two_path_target(
        resolver,
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        at_fdcwd_arg(),
        notif.data.args[1],
        |old_dir, old, new_dir, new| FilesystemMutation::Rename {
            old_dir,
            old,
            new_dir,
            new,
            flags: 0,
        },
    )
}

fn target_from_renameat_family(
    resolver: &Resolver,
    notif: &SeccompNotif,
) -> io::Result<SyscallTarget> {
    let flags = if i64::from(notif.data.nr) == nr::RENAMEAT {
        0
    } else {
        u32::try_from(notif.data.args[4]).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
    };

    two_path_target(
        resolver,
        notif,
        notif.data.args[0],
        notif.data.args[1],
        notif.data.args[2],
        notif.data.args[3],
        |old_dir, old, new_dir, new| FilesystemMutation::Rename {
            old_dir,
            old,
            new_dir,
            new,
            flags,
        },
    )
}

fn target_from_link(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    two_path_target(
        resolver,
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        at_fdcwd_arg(),
        notif.data.args[1],
        |old_dir, old, new_dir, new| FilesystemMutation::Link {
            old_dir,
            old,
            new_dir,
            new,
            flags: 0,
        },
    )
}

fn target_from_linkat(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let flags = u32::try_from(notif.data.args[4])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    if flags & libc::AT_SYMLINK_FOLLOW as u32 != 0 {
        let raw = read_tracee_path(notif.pid, notif.data.args[1])?;
        if let Some(source_fd) = proc_self_fd(&raw) {
            let fd = agent_sandbox_sysutil::dup_tracee_fd(notif.pid, source_fd)?;
            let mut source = resolver.fd_link(fd.as_fd())?;
            if !source.is_absolute() {
                return Err(io::Error::from_raw_os_error(libc::EXDEV));
            }
            // O_TMPFILE has no directory entry yet. Authorize its backing
            // directory rather than a procfs alias in another process's fd
            // table. Ordinary unlinked files cannot be relinked by linkat.
            if nix::sys::stat::fstat(&fd)?.st_nlink == 0 {
                source.pop();
            }
            let new = capture_path(resolver, notif, notif.data.args[2], notif.data.args[3])?;
            return Ok(filesystem_target(
                vec![
                    FilesystemCheck {
                        path: source,
                        access: FileAccess::ReadWrite,
                    },
                    FilesystemCheck {
                        path: check_path(resolver, &new)?,
                        access: FileAccess::ReadWrite,
                    },
                ],
                FilesystemMutation::LinkFd {
                    fd,
                    new_dir: new.dir,
                    new: new.raw,
                    flags,
                },
            ));
        }
    }

    two_path_target(
        resolver,
        notif,
        notif.data.args[0],
        notif.data.args[1],
        notif.data.args[2],
        notif.data.args[3],
        |old_dir, old, new_dir, new| FilesystemMutation::Link {
            old_dir,
            old,
            new_dir,
            new,
            flags,
        },
    )
}

fn proc_self_fd(raw: &[u8]) -> Option<i32> {
    let suffix = raw
        .strip_prefix(b"/proc/self/fd/")
        .or_else(|| raw.strip_prefix(b"/proc/thread-self/fd/"))?;
    if suffix.is_empty() || !suffix.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(suffix).ok()?.parse().ok()
}

fn symlink_target(
    resolver: &Resolver,
    notif: &SeccompNotif,
    target_ptr: u64,
    link_dirfd: u64,
    link_ptr: u64,
) -> io::Result<SyscallTarget> {
    let target = read_tracee_path(notif.pid, target_ptr)?;
    let link = capture_path(resolver, notif, link_dirfd, link_ptr)?;
    let resolved = resolver.absolute_name(&link.dir, &link.raw)?;
    let target_path = resolve_symlink_target_path(&target, &resolved);

    Ok(filesystem_target(
        vec![
            FilesystemCheck {
                path: resolver.normalize_path(&target_path),
                access: FileAccess::Read,
            },
            FilesystemCheck {
                path: check_path(resolver, &link)?,
                access: FileAccess::Write,
            },
        ],
        FilesystemMutation::Symlink {
            target,
            link_dir: link.dir,
            link: link.raw,
        },
    ))
}

fn resolve_symlink_target_path(target: &[u8], link: &Path) -> PathBuf {
    let target = path_from_raw(target);

    if target.is_absolute() {
        target
    } else {
        link.parent()
            .map_or_else(|| target.clone(), |parent| parent.join(&target))
    }
}

fn single_path_target(
    resolver: &Resolver,
    notif: &SeccompNotif,
    dirfd: u64,
    ptr: u64,
    operation: impl FnOnce(MutationDir, Vec<u8>) -> FilesystemMutation,
    access: FileAccess,
) -> io::Result<SyscallTarget> {
    let captured = capture_path(resolver, notif, dirfd, ptr)?;

    Ok(filesystem_target(
        vec![FilesystemCheck {
            path: check_path(resolver, &captured)?,
            access,
        }],
        operation(captured.dir, captured.raw),
    ))
}

fn target_from_unlinkat(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let flags = u32::try_from(notif.data.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    single_path_target(
        resolver,
        notif,
        notif.data.args[0],
        notif.data.args[1],
        |dir, path| FilesystemMutation::Unlink { dir, path, flags },
        FileAccess::Write,
    )
}

fn target_from_unlink(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    single_path_target(
        resolver,
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        |dir, path| FilesystemMutation::Unlink {
            dir,
            path,
            flags: 0,
        },
        FileAccess::Write,
    )
}

fn target_from_truncate(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let len = i64::try_from(notif.data.args[1])
        .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    single_path_target(
        resolver,
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        |dir, path| FilesystemMutation::Truncate { dir, path, len },
        FileAccess::Write,
    )
}

fn is_anonymous_memory_file(fd: &OwnedFd) -> io::Result<bool> {
    use nix::sys::{
        memfd::{MFdFlags, memfd_create},
        stat::fstat,
        statfs::{HUGETLBFS_MAGIC, TMPFS_MAGIC, fstatfs},
    };

    // Slot zero is shmem; hugepage slots are indexed by the page-size exponent.
    // These kernel-internal superblocks live for the lifetime of the kernel.
    static DEVICES: [OnceLock<libc::dev_t>; 64] = [const { OnceLock::new() }; 64];
    let stat = fstat(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 0 {
        return Ok(false);
    }
    if DEVICES[0]
        .get()
        .is_some_and(|device| *device == stat.st_dev)
    {
        return Ok(true);
    }

    let filesystem = fstatfs(fd)?;
    let huge_shift = match filesystem.filesystem_type() {
        TMPFS_MAGIC => 0,
        HUGETLBFS_MAGIC => {
            let size = u64::try_from(filesystem.block_size())
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            if !size.is_power_of_two() {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            size.ilog2()
        }
        _ => return Ok(false),
    };
    let device = &DEVICES[huge_shift as usize];
    let expected = if let Some(device) = device.get() {
        *device
    } else {
        let mut flags = MFdFlags::MFD_CLOEXEC;
        if huge_shift != 0 {
            flags |= MFdFlags::MFD_HUGETLB
                | MFdFlags::from_bits_retain(huge_shift << libc::MFD_HUGE_SHIFT);
        }
        let probe = memfd_create(c"agent-sandbox-memory", flags)?;
        let expected = fstat(&probe)?.st_dev;
        let _ = device.set(expected);
        expected
    };
    Ok(stat.st_dev == expected)
}

fn target_from_ftruncate(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let fd = agent_sandbox_sysutil::dup_tracee_fd(
        notif.pid,
        i32::try_from(notif.data.args[0]).map_err(|_| io::Error::from_raw_os_error(libc::EBADF))?,
    )?;

    let len = i64::try_from(notif.data.args[1])
        .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    // Anonymous memory has no pathname authority. Keep the duplicate for
    // emulation so an fd-table swap cannot redirect the unchecked operation.
    if is_anonymous_memory_file(&fd)? {
        return Ok(filesystem_target(
            Vec::new(),
            FilesystemMutation::Ftruncate { fd, len },
        ));
    }

    let mut path = resolver.fd_link(fd.as_fd())?;

    // An ordinary fd link already names the resolved, frozen file description.
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") {
        path = resolver.normalize_path(&path);
    }

    Ok(filesystem_target(
        vec![FilesystemCheck {
            path,
            access: FileAccess::Write,
        }],
        FilesystemMutation::Ftruncate { fd, len },
    ))
}

/// Whether the node to create already exists, so the kernel would fail the
/// syscall with `EEXIST` and no policy request is warranted.
fn node_already_exists(dir: &MutationDir, raw: &[u8]) -> bool {
    nix::sys::stat::fstatat(
        dir,
        Path::new(OsStr::from_bytes(raw)),
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .is_ok()
}

fn mknod_target(
    resolver: &Resolver,
    notif: &SeccompNotif,
    dirfd: u64,
    ptr: u64,
    mode: u32,
    device: u64,
) -> io::Result<SyscallTarget> {
    let captured = capture_path(resolver, notif, dirfd, ptr)?;

    if node_already_exists(&captured.dir, &captured.raw) {
        return Ok(SyscallTarget::Errno(libc::EEXIST));
    }

    Ok(filesystem_target(
        vec![FilesystemCheck {
            path: check_path(resolver, &captured)?,
            access: FileAccess::Write,
        }],
        FilesystemMutation::Mknod {
            dir: captured.dir,
            path: captured.raw,
            mode,
            device,
        },
    ))
}

fn target_from_mknod(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let mode = u32::try_from(notif.data.args[1]).unwrap_or(0);
    let device = notif.data.args[2];

    mknod_target(
        resolver,
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        mode,
        device,
    )
}

fn target_from_mknodat(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let mode = u32::try_from(notif.data.args[2]).unwrap_or(0);
    let device = notif.data.args[3];

    mknod_target(
        resolver,
        notif,
        notif.data.args[0],
        notif.data.args[1],
        mode,
        device,
    )
}

fn mkdir_target(
    resolver: &Resolver,
    notif: &SeccompNotif,
    dirfd: u64,
    ptr: u64,
    mode: u32,
) -> io::Result<SyscallTarget> {
    let captured = capture_path(resolver, notif, dirfd, ptr)?;

    if node_already_exists(&captured.dir, &captured.raw) {
        return Ok(SyscallTarget::Errno(libc::EEXIST));
    }

    Ok(filesystem_target(
        vec![FilesystemCheck {
            path: check_path(resolver, &captured)?,
            access: FileAccess::Write,
        }],
        FilesystemMutation::Mkdir {
            dir: captured.dir,
            path: captured.raw,
            mode,
        },
    ))
}

fn target_from_mkdir(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let mode = u32::try_from(notif.data.args[1])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    mkdir_target(resolver, notif, at_fdcwd_arg(), notif.data.args[0], mode)
}

fn target_from_mkdirat(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    let mode = u32::try_from(notif.data.args[2])
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    mkdir_target(
        resolver,
        notif,
        notif.data.args[0],
        notif.data.args[1],
        mode,
    )
}

fn target_from_rmdir(resolver: &Resolver, notif: &SeccompNotif) -> io::Result<SyscallTarget> {
    single_path_target(
        resolver,
        notif,
        at_fdcwd_arg(),
        notif.data.args[0],
        |dir, path| FilesystemMutation::Rmdir { dir, path },
        FileAccess::Write,
    )
}

/// Classify a filesystem-mutation syscall; `None` for any other syscall.
pub fn target_from_filesystem_mutation(
    resolver: &Resolver,
    notif: &SeccompNotif,
) -> Option<SyscallTarget> {
    let result = match i64::from(notif.data.nr) {
        nr::RENAME => target_from_rename(resolver, notif),
        nr::RENAMEAT | nr::RENAMEAT2 => target_from_renameat_family(resolver, notif),
        nr::LINK => target_from_link(resolver, notif),
        nr::LINKAT => target_from_linkat(resolver, notif),
        nr::SYMLINK => symlink_target(
            resolver,
            notif,
            notif.data.args[0],
            at_fdcwd_arg(),
            notif.data.args[1],
        ),
        nr::SYMLINKAT => symlink_target(
            resolver,
            notif,
            notif.data.args[0],
            notif.data.args[1],
            notif.data.args[2],
        ),
        nr::UNLINK => target_from_unlink(resolver, notif),
        nr::UNLINKAT => target_from_unlinkat(resolver, notif),
        nr::TRUNCATE => target_from_truncate(resolver, notif),
        nr::FTRUNCATE => target_from_ftruncate(resolver, notif),
        nr::MKDIR => target_from_mkdir(resolver, notif),
        nr::MKDIRAT => target_from_mkdirat(resolver, notif),
        nr::MKNOD => target_from_mknod(resolver, notif),
        nr::MKNODAT => target_from_mknodat(resolver, notif),
        nr::RMDIR => target_from_rmdir(resolver, notif),
        _ => return None,
    };

    Some(result.unwrap_or_else(|err| errno_target(&err)))
}
