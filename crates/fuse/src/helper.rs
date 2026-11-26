//! The root side of a mount or unmount: enter the requester's mount
//! namespace, check the request there, and act on it.
//!
//! The requester is a pidfd, so a pid that exits and is reused cannot
//! redirect the helper into another namespace. The helper is a single-threaded
//! process because `setns(CLONE_NEWNS)` refuses to run beside threads that
//! share its filesystem state.

use std::{
    io::{self, Read},
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{AtFlags, Mode, OFlags, open, openat, statat},
    mount::{UnmountFlags, unmount},
    process::fchdir,
    thread::{ThreadNameSpaceType, move_into_thread_name_spaces},
};
use thiserror::Error;

use crate::{
    kernel::{find_mount, mount_fuse, mount_id_from_fdinfo},
    mountpoint::{
        MountpointError, RefusedPaths, open_beneath, open_child, require_clean, validate,
    },
    options::{MountParams, OptionError, parse_mount_options},
    protocol::HelperReply,
};

/// Where the host administrator permits `allow_other`.
const FUSE_CONF: &str = "/etc/fuse.conf";

/// What to do at the mountpoint.
#[derive(Debug, Clone)]
pub enum Action {
    /// Mount a filesystem; carries the client's `-o` string.
    Mount {
        /// The fusermount `-o` option string.
        options: String,
    },

    /// Unmount the requester's own FUSE mount.
    Unmount {
        /// Detach lazily instead of failing while busy.
        lazy: bool,
    },
}

/// A request from policyd, with the identity it verified for the requester.
#[derive(Debug, Clone)]
pub struct HelperRequest {
    /// What to do.
    pub action: Action,

    /// The requester's uid: the mountpoint owner and the FUSE `user_id`.
    pub uid: u32,

    /// The requester's gid: the FUSE `group_id`.
    pub gid: u32,

    /// The mountpoint, as the requester sees it.
    pub mountpoint: PathBuf,

    /// Paths a mount may not touch beyond the built-in set.
    pub refused: RefusedPaths,
}

/// Why the helper refused or failed.
#[derive(Debug, Error)]
pub enum HelperError {
    /// A mount option was refused.
    #[error("{0}")]
    Option(#[from] OptionError),

    /// The mountpoint was refused.
    #[error("{0}")]
    Mountpoint(#[from] MountpointError),

    /// The requester runs in the host mount namespace.
    #[error("refusing to act in the host mount namespace")]
    HostNamespace,

    /// The mountpoint is not a mount the requester may unmount.
    #[error("{0}")]
    NotYours(&'static str),

    /// A mount on this directory would propagate out of the sandbox.
    #[error("mountpoint is on a shared mount that propagates to other mount namespaces")]
    Propagates,

    /// A system call failed.
    #[error("{what}: {source}")]
    Sys {
        /// The step that failed.
        what: &'static str,

        /// The kernel's error.
        source: io::Error,
    },
}

fn sys<E: Into<io::Error>>(what: &'static str) -> impl FnOnce(E) -> HelperError {
    move |source| HelperError::Sys {
        what,
        source: source.into(),
    }
}

/// Whether `/etc/fuse.conf` content enables `user_allow_other`.
#[must_use]
pub fn user_allow_other(conf: &str) -> bool {
    conf.lines().any(|line| line.trim() == "user_allow_other")
}

/// Carry out `request` in the mount namespace of `requester`.
///
/// # Errors
/// The first refusal or failing step; nothing is mounted or unmounted on error.
pub fn run(request: &HelperRequest, requester: BorrowedFd<'_>) -> Result<HelperReply, HelperError> {
    // Everything that must come from the host happens before `setns`.
    let prepared = match &request.action {
        Action::Mount { options } => {
            let conf = std::fs::read_to_string(FUSE_CONF).unwrap_or_default();

            Prepared::Mount(MountSetup {
                params: parse_mount_options(options, user_allow_other(&conf))?,
                dev_fuse: open("/dev/fuse", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(sys("open /dev/fuse"))?,
            })
        }
        Action::Unmount { lazy } => Prepared::Unmount { lazy: *lazy },
    };

    let proc = open(
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(sys("open /proc"))?;

    let host_namespace = namespace_id(proc.as_fd())?;

    move_into_thread_name_spaces(requester, ThreadNameSpaceType::MOUNT)
        .map_err(sys("enter mount namespace"))?;

    if namespace_id(proc.as_fd())? == host_namespace {
        return Err(HelperError::HostNamespace);
    }

    let root = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(sys("open sandbox root"))?;

    match prepared {
        Prepared::Mount(setup) => {
            mount_own(proc.as_fd(), root.as_fd(), request, &setup)?;

            Ok(HelperReply::Mounted(setup.dev_fuse))
        }

        Prepared::Unmount { lazy } => {
            unmount_own(proc.as_fd(), root.as_fd(), request, lazy)?;

            Ok(HelperReply::Unmounted)
        }
    }
}

/// What a mount needs from the host before the namespace changes.
struct MountSetup {
    params: MountParams,
    dev_fuse: OwnedFd,
}

enum Prepared {
    Mount(MountSetup),
    Unmount { lazy: bool },
}

/// Mount `/dev/fuse` at the request's mountpoint if the checks pass.
fn mount_own(
    proc: BorrowedFd<'_>,
    root: BorrowedFd<'_>,
    request: &HelperRequest,
    setup: &MountSetup,
) -> Result<(), HelperError> {
    let checked = validate(root, &request.mountpoint, request.uid, &request.refused)?;
    let mountinfo = read_proc(proc, "self/mountinfo")?;

    if mount_of(proc, checked.fd.as_fd(), &mountinfo)?.propagates() {
        return Err(HelperError::Propagates);
    }

    mount_fuse(
        setup.dev_fuse.as_fd(),
        checked.fd.as_fd(),
        &setup.params,
        checked.rootmode,
        request.uid,
        request.gid,
    )
    .map_err(sys("mount"))
}

/// Unmount the FUSE mount at the request's mountpoint if it is the
/// requester's.
///
/// The mountpoint is checked through a descriptor, then unmounted by name
/// relative to its parent directory's descriptor: a held descriptor on the
/// mount itself would make a non-lazy unmount fail as busy, and the pinned
/// parent keeps the name from being redirected through a swapped ancestor.
fn unmount_own(
    proc: BorrowedFd<'_>,
    root: BorrowedFd<'_>,
    request: &HelperRequest,
    lazy: bool,
) -> Result<(), HelperError> {
    require_clean(&request.mountpoint)?;

    let name = request
        .mountpoint
        .file_name()
        .ok_or(MountpointError::NotClean)?;

    let parent = match request.mountpoint.parent() {
        Some(parent) if parent != Path::new("/") => open_beneath(root, parent)?,
        _ => root.try_clone_to_owned().map_err(sys("duplicate root"))?,
    };

    {
        let target = open_child(parent.as_fd(), Path::new(name))?;

        let mountinfo = read_proc(proc, "self/mountinfo")?;
        let mount = mount_of(proc, target.as_fd(), &mountinfo)?;

        if !mount.is_fuse() {
            return Err(HelperError::NotYours("mountpoint is not a FUSE mount"));
        }

        if !mount.owned_by(request.uid) {
            return Err(HelperError::NotYours("FUSE mount belongs to another user"));
        }

        if mount.root != "/" {
            return Err(HelperError::NotYours(
                "mountpoint is not the root of a mount",
            ));
        }
    }

    fchdir(&parent).map_err(sys("enter mountpoint parent"))?;

    let mut flags = UnmountFlags::NOFOLLOW;
    flags.set(UnmountFlags::DETACH, lazy);

    unmount(name, flags).map_err(sys("unmount"))
}

/// The `mountinfo` entry of the mount `fd` lives on.
fn mount_of(
    proc: BorrowedFd<'_>,
    fd: BorrowedFd<'_>,
    mountinfo: &str,
) -> Result<crate::kernel::MountInfo, HelperError> {
    let fdinfo = read_proc(proc, &format!("self/fdinfo/{}", fd.as_raw_fd()))?;

    mount_id_from_fdinfo(&fdinfo)
        .and_then(|id| find_mount(mountinfo, id))
        .ok_or(HelperError::NotYours(
            "mountpoint is not visible in the mount table",
        ))
}

/// Read a file below the host `/proc` held open as `proc`.
fn read_proc(proc: BorrowedFd<'_>, path: &str) -> Result<String, HelperError> {
    let fd = openat(proc, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(sys("read /proc"))?;

    let mut text = String::new();

    std::fs::File::from(fd)
        .read_to_string(&mut text)
        .map_err(sys("read /proc"))?;

    Ok(text)
}

/// Identity of the calling process's mount namespace.
#[derive(Debug, PartialEq, Eq)]
struct NamespaceId {
    dev: u64,
    ino: u64,
}

fn namespace_id(proc: BorrowedFd<'_>) -> Result<NamespaceId, HelperError> {
    let stat =
        statat(proc, "self/ns/mnt", AtFlags::empty()).map_err(sys("stat mount namespace"))?;

    Ok(NamespaceId {
        dev: stat.st_dev,
        ino: stat.st_ino,
    })
}

#[cfg(test)]
mod tests {
    use super::user_allow_other;

    #[test]
    fn fuse_conf_enables_allow_other_only_by_its_own_line() {
        assert!(user_allow_other("mount_max = 1000\nuser_allow_other\n"));
        assert!(user_allow_other("  user_allow_other  "));
        assert!(!user_allow_other("# user_allow_other\n"));
        assert!(!user_allow_other(""));
    }
}
