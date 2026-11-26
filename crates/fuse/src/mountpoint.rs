//! Mountpoint resolution and the rules a mountpoint must satisfy.
//!
//! Resolution is relative to a root directory descriptor and never follows a
//! symlink, so the descriptor it returns names the directory that was checked
//! and the mount is attached to that same descriptor.

use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Component, Path, PathBuf},
};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, Stat, fstat, openat2};
use thiserror::Error;

/// Paths a FUSE mount is never attached to or below.
const REFUSED: &[&str] = &["/proc", "/sys", "/dev", "/nix/store", "/run/wrappers"];

/// Longest mountpoint accepted, matching `PATH_MAX`.
const MAX_PATH_BYTES: usize = 4096;

/// Why a mountpoint was refused.
#[derive(Debug, Error)]
pub enum MountpointError {
    /// The path is not absolute, or has a `.`, `..` or empty component.
    #[error("mountpoint must be an absolute path without '.' or '..' components")]
    NotClean,

    /// The path is `/`.
    #[error("refusing to mount over the root directory")]
    Root,

    /// A component of the path is a symlink.
    #[error("mountpoint path must not contain symlinks")]
    Symlink,

    /// The path does not resolve to a directory.
    #[error("mountpoint is not a directory")]
    NotDirectory,

    /// The directory belongs to another user.
    #[error("mountpoint is not owned by the requesting user")]
    ForeignOwner,

    /// The owner cannot write to the directory.
    #[error("mountpoint is not writable by its owner")]
    NotWritable,

    /// The path is, or lies under, a path the sandbox controls policy with.
    #[error("refusing to mount at or under {0}")]
    Refused(PathBuf),

    /// The directory is the same one as a refused path, reached by another
    /// name.
    #[error("refusing to mount over {0}")]
    RefusedAlias(PathBuf),

    /// Resolution failed for another reason.
    #[error("cannot resolve mountpoint: {0}")]
    Io(#[from] io::Error),
}

/// The paths a mount may not touch: a fixed set plus caller-supplied ones.
#[derive(Debug, Clone)]
pub struct RefusedPaths {
    paths: Vec<PathBuf>,
}

impl RefusedPaths {
    /// The fixed set plus `extra`.
    pub fn new(extra: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            paths: REFUSED.iter().map(PathBuf::from).chain(extra).collect(),
        }
    }

    /// The refused path that `path` is or lies under.
    #[must_use]
    pub fn covering(&self, path: &Path) -> Option<&Path> {
        self.paths
            .iter()
            .map(PathBuf::as_path)
            .find(|refused| path.starts_with(refused))
    }
}

/// Absolute, lexically clean form of `path` taken relative to `cwd`.
///
/// No filesystem access happens, so a mountpoint on a dead mount resolves.
#[must_use]
pub fn lexical_absolute(cwd: &Path, path: &Path) -> PathBuf {
    let mut clean = PathBuf::from("/");

    for component in cwd.join(path).components() {
        match component {
            Component::Normal(name) => clean.push(name),
            Component::ParentDir => {
                clean.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }

    clean
}

/// Require the shape [`lexical_absolute`] produces.
///
/// # Errors
/// [`MountpointError::NotClean`] when the path is relative, too long, or has
/// a `.`, `..` or empty component; [`MountpointError::Root`] for `/`.
pub fn require_clean(path: &Path) -> Result<(), MountpointError> {
    let bytes = path.as_os_str().as_encoded_bytes();

    if bytes.first() != Some(&b'/') || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
        return Err(MountpointError::NotClean);
    }

    if bytes == b"/" {
        return Err(MountpointError::Root);
    }

    if bytes[1..]
        .split(|byte| *byte == b'/')
        .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(MountpointError::NotClean);
    }

    Ok(())
}

/// Open `path` below `root` as an `O_PATH` directory descriptor, following no
/// symlink on the way.
///
/// # Errors
/// [`MountpointError::Symlink`] when a component is a symlink,
/// [`MountpointError::NotDirectory`] when the target is not a directory, and
/// [`MountpointError::Io`] otherwise.
pub fn open_beneath(root: BorrowedFd<'_>, path: &Path) -> Result<OwnedFd, MountpointError> {
    require_clean(path)?;

    let relative = path
        .strip_prefix("/")
        .map_err(|_| MountpointError::NotClean)?;

    open_child(root, relative)
}

/// Open `relative` below the directory `dir` as an `O_PATH` directory
/// descriptor, following no symlink and never leaving `dir`.
///
/// # Errors
/// Same as [`open_beneath`].
pub fn open_child(dir: BorrowedFd<'_>, relative: &Path) -> Result<OwnedFd, MountpointError> {
    openat2(
        dir,
        relative,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::BENEATH,
    )
    .map_err(|errno| match errno {
        rustix::io::Errno::LOOP => MountpointError::Symlink,
        rustix::io::Errno::NOTDIR => MountpointError::NotDirectory,
        other => MountpointError::Io(other.into()),
    })
}

/// A mountpoint that passed every check.
#[derive(Debug)]
pub struct Validated {
    /// The checked directory.
    pub fd: OwnedFd,

    /// The directory's file type bits, as the kernel's `rootmode`.
    pub rootmode: u32,
}

/// Resolve and check a mountpoint for a new mount by `uid`.
///
/// The directory must be owned by `uid` and writable by its owner, must not
/// be or lie under a refused path, and must not be the same directory as one
/// (a bind mount can give it a second name).
///
/// # Errors
/// The first rule the mountpoint breaks.
pub fn validate(
    root: BorrowedFd<'_>,
    path: &Path,
    uid: u32,
    refused: &RefusedPaths,
) -> Result<Validated, MountpointError> {
    require_clean(path)?;

    if let Some(covering) = refused.covering(path) {
        return Err(MountpointError::Refused(covering.to_path_buf()));
    }

    let fd = open_beneath(root, path)?;
    let stat = fstat(&fd).map_err(io::Error::from)?;

    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(MountpointError::NotDirectory);
    }

    if stat.st_uid != uid {
        return Err(MountpointError::ForeignOwner);
    }

    if stat.st_mode & 0o200 == 0 {
        return Err(MountpointError::NotWritable);
    }

    if let Some(alias) = refused_alias(root, &stat, refused) {
        return Err(MountpointError::RefusedAlias(alias));
    }

    Ok(Validated {
        fd,
        rootmode: stat.st_mode & 0o170_000,
    })
}

/// The refused path that names the directory `stat` describes, if any.
fn refused_alias(root: BorrowedFd<'_>, stat: &Stat, refused: &RefusedPaths) -> Option<PathBuf> {
    refused.paths.iter().find_map(|path| {
        let fd = open_beneath(root, path).ok()?;
        let other = fstat(fd.as_fd()).ok()?;

        (other.st_dev == stat.st_dev && other.st_ino == stat.st_ino).then(|| path.clone())
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::{fd::OwnedFd, unix::fs::symlink},
        path::Path,
    };

    use rustix::fs::{Mode, OFlags, open};

    use super::{MountpointError, RefusedPaths, lexical_absolute, refused_alias, validate};

    fn root_of(dir: &Path) -> OwnedFd {
        open(dir, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).expect("open root")
    }

    fn own_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn owned_writable_directory_is_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("mnt")).expect("mkdir");
        let root = root_of(dir.path());

        let checked = validate(
            std::os::fd::AsFd::as_fd(&root),
            Path::new("/mnt"),
            own_uid(),
            &RefusedPaths::new([]),
        )
        .expect("valid mountpoint");

        assert_eq!(checked.rootmode, 0o040_000);
    }

    #[test]
    fn symlinked_mountpoint_or_ancestor_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("real/mnt")).expect("mkdir");
        symlink("real", dir.path().join("link")).expect("symlink");
        symlink("real/mnt", dir.path().join("direct")).expect("symlink");
        let root = root_of(dir.path());

        for path in ["/link/mnt", "/direct"] {
            let result = validate(
                std::os::fd::AsFd::as_fd(&root),
                Path::new(path),
                own_uid(),
                &RefusedPaths::new([]),
            );

            assert!(
                matches!(result, Err(MountpointError::Symlink)),
                "{path}: {result:?}"
            );
        }
    }

    #[test]
    fn foreign_owner_unwritable_and_non_directory_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("mnt")).expect("mkdir");
        fs::write(dir.path().join("file"), "x").expect("file");
        let root = root_of(dir.path());
        let refused = RefusedPaths::new([]);
        let fd = std::os::fd::AsFd::as_fd(&root);

        assert!(matches!(
            validate(fd, Path::new("/mnt"), own_uid() + 1, &refused),
            Err(MountpointError::ForeignOwner)
        ));

        assert!(matches!(
            validate(fd, Path::new("/file"), own_uid(), &refused),
            Err(MountpointError::NotDirectory)
        ));

        fs::set_permissions(
            dir.path().join("mnt"),
            std::os::unix::fs::PermissionsExt::from_mode(0o500),
        )
        .expect("chmod");

        assert!(matches!(
            validate(fd, Path::new("/mnt"), own_uid(), &refused),
            Err(MountpointError::NotWritable)
        ));
    }

    #[test]
    fn control_paths_and_their_descendants_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = root_of(dir.path());
        let refused = RefusedPaths::new([Path::new("/run/agent-sandbox/shared").into()]);
        let fd = std::os::fd::AsFd::as_fd(&root);

        for path in [
            "/proc",
            "/sys/fs",
            "/dev/shm",
            "/nix/store/x",
            "/run/wrappers/bin",
            "/run/agent-sandbox/shared",
            "/run/agent-sandbox/shared/inner",
        ] {
            assert!(
                matches!(
                    validate(fd, Path::new(path), own_uid(), &refused),
                    Err(MountpointError::Refused(_))
                ),
                "{path}"
            );
        }

        assert!(matches!(
            validate(fd, Path::new("/"), own_uid(), &refused),
            Err(MountpointError::Root)
        ));
    }

    #[test]
    fn unclean_paths_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = root_of(dir.path());
        let fd = std::os::fd::AsFd::as_fd(&root);

        for path in ["mnt", "/a/../b", "/a/./b", "/a//b", "/a/"] {
            assert!(
                matches!(
                    validate(fd, Path::new(path), own_uid(), &RefusedPaths::new([])),
                    Err(MountpointError::NotClean)
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn a_second_name_for_a_refused_directory_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("shared")).expect("mkdir");
        fs::create_dir(dir.path().join("other")).expect("mkdir");
        let root = root_of(dir.path());
        let fd = std::os::fd::AsFd::as_fd(&root);
        let refused = RefusedPaths::new([Path::new("/shared").into()]);
        let stat_of = |name: &str| rustix::fs::stat(dir.path().join(name)).expect("stat");

        assert_eq!(
            refused_alias(fd, &stat_of("shared"), &refused).as_deref(),
            Some(Path::new("/shared"))
        );

        assert_eq!(refused_alias(fd, &stat_of("other"), &refused), None);
    }

    #[test]
    fn lexical_absolute_resolves_relative_and_dotted_paths() {
        let cwd = Path::new("/home/u");

        assert_eq!(
            lexical_absolute(cwd, Path::new("mnt")),
            Path::new("/home/u/mnt")
        );
        assert_eq!(
            lexical_absolute(cwd, Path::new("../x/./y/")),
            Path::new("/home/x/y")
        );
        assert_eq!(
            lexical_absolute(cwd, Path::new("/a//b/..")),
            Path::new("/a")
        );
    }
}
