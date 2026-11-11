//! Pinned handles for tracee-relative names.
//!
//! Every procfs path the broker builds and every lookup of a name the tracee
//! passed goes through [`Resolver`]: `(pid, dirfd | cwd | fd)` becomes a pinned
//! `O_PATH` handle plus the procfs path that names it. Authorization and
//! emulation both use the handle, so a path swapped after classification
//! cannot redirect an approval.

use std::{
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
};

use nix::fcntl::{AT_FDCWD, OFlag, OpenHow, ResolveFlag};

use crate::capture::syscall_i32_arg;

/// `RESOLVE_IN_ROOT`: the starting directory is also the root of the lookup.
pub const RESOLVE_IN_ROOT: u64 = 0x10;

/// Where a tracee-relative name starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirBase {
    /// The tracee's working directory (`AT_FDCWD`).
    Cwd,

    /// A directory descriptor in the tracee's table.
    Fd(i32),
}

impl DirBase {
    /// Decode a `dirfd` syscall argument from its low 32 bits.
    ///
    /// # Errors
    /// `EBADF` for a negative descriptor other than `AT_FDCWD`.
    pub fn from_arg(dirfd: u64) -> io::Result<Self> {
        match syscall_i32_arg(dirfd) {
            libc::AT_FDCWD => Ok(Self::Cwd),
            fd if fd < 0 => Err(io::Error::from_raw_os_error(libc::EBADF)),
            fd => Ok(Self::Fd(fd)),
        }
    }
}

/// How a pinned lookup follows the final component and its parents.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PinScope {
    /// The open asked for `O_NOFOLLOW`: a final symlink is pinned itself.
    pub nofollow: bool,

    /// `RESOLVE_*` flags from `open_how`; zero for plain lookups.
    pub resolve: u64,
}

/// A descriptor a tracee holds, as listed in its procfs `fd` directory.
#[derive(Debug)]
pub struct TraceeFd {
    /// Descriptor number in the tracee's table.
    pub fd: i32,

    /// Target of the procfs link.
    pub link: PathBuf,
}

/// A path that names the calling process, and what it means under that
/// process's procfs directory.
struct ProcAlias {
    alias: &'static str,
    under_proc: &'static str,
}

const PROC_ALIASES: &[ProcAlias] = &[
    ProcAlias {
        alias: "/proc/self",
        under_proc: "",
    },
    ProcAlias {
        alias: "/proc/thread-self",
        under_proc: "",
    },
    ProcAlias {
        alias: "/dev/fd",
        under_proc: "fd",
    },
    ProcAlias {
        alias: "/dev/stdin",
        under_proc: "fd/0",
    },
    ProcAlias {
        alias: "/dev/stdout",
        under_proc: "fd/1",
    },
    ProcAlias {
        alias: "/dev/stderr",
        under_proc: "fd/2",
    },
];

/// Builds procfs paths and pins the objects tracee names refer to.
#[derive(Debug, Clone)]
pub struct Resolver {
    proc: PathBuf,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new("/proc")
    }
}

impl Resolver {
    /// A resolver reading tracee state under the procfs mounted at `proc`.
    pub fn new(proc: impl Into<PathBuf>) -> Self {
        Self { proc: proc.into() }
    }

    fn task(&self, pid: u32) -> PathBuf {
        self.proc.join(pid.to_string())
    }

    /// Procfs link to the directory a tracee-relative name starts from.
    #[must_use]
    pub fn base_link(&self, pid: u32, base: DirBase) -> PathBuf {
        match base {
            DirBase::Cwd => self.task(pid).join("cwd"),
            DirBase::Fd(fd) => self.tracee_fd(pid, fd),
        }
    }

    /// Procfs link to descriptor `fd` of the tracee.
    #[must_use]
    pub fn tracee_fd(&self, pid: u32, fd: i32) -> PathBuf {
        self.task(pid).join("fd").join(fd.to_string())
    }

    /// Descriptors the tracee holds, with each procfs link target.
    ///
    /// # Errors
    /// Returns the error from reading the tracee's `fd` directory.
    pub fn tracee_fds(&self, pid: u32) -> io::Result<impl Iterator<Item = TraceeFd> + use<>> {
        Ok(std::fs::read_dir(self.task(pid).join("fd"))?
            .flatten()
            .filter_map(|entry| {
                let fd = entry.file_name().to_str()?.parse::<i32>().ok()?;
                let link = std::fs::read_link(entry.path()).ok()?;
                Some(TraceeFd { fd, link })
            }))
    }

    /// Contents of the tracee's `fdinfo` entry for `fd`.
    ///
    /// # Errors
    /// Returns the error from reading the entry.
    pub fn tracee_fdinfo(&self, pid: u32, fd: i32) -> io::Result<String> {
        std::fs::read_to_string(self.task(pid).join("fdinfo").join(fd.to_string()))
    }

    /// Procfs path naming `fd` in this process.
    #[must_use]
    pub fn self_fd(&self, fd: BorrowedFd<'_>) -> PathBuf {
        self.proc.join("self/fd").join(fd.as_raw_fd().to_string())
    }

    /// Raw target of the procfs link for `fd`, including `(deleted)` and
    /// anonymous names.
    ///
    /// # Errors
    /// Returns the `readlink` error.
    pub fn fd_link(&self, fd: BorrowedFd<'_>) -> io::Result<PathBuf> {
        std::fs::read_link(self.self_fd(fd))
    }

    /// Absolute path the kernel reports for `fd`; `None` for anonymous or
    /// unlinked objects.
    #[must_use]
    pub fn fd_path(&self, fd: BorrowedFd<'_>) -> Option<PathBuf> {
        self.fd_link(fd).ok().filter(|resolved| {
            resolved.is_absolute()
                && !resolved
                    .as_os_str()
                    .as_encoded_bytes()
                    .ends_with(b" (deleted)")
        })
    }

    /// Rewrite a path that names the calling process to the tracee task's
    /// procfs directory. The broker would otherwise resolve it as itself.
    fn alias(&self, pid: u32, path: &Path) -> PathBuf {
        PROC_ALIASES
            .iter()
            .find_map(|entry| {
                let rest = path.strip_prefix(entry.alias).ok()?;
                Some(self.task(pid).join(entry.under_proc).join(rest))
            })
            .unwrap_or_else(|| path.to_path_buf())
    }

    /// The path the kernel would walk for `name` as the tracee issued it:
    /// absolute names stay absolute (with process aliases rewritten to the
    /// tracee), relative names are joined to the directory they start from.
    /// `RESOLVE_IN_ROOT` scopes even absolute names under that directory.
    ///
    /// # Errors
    /// Returns the `readlink` error for the starting directory.
    pub fn lookup(
        &self,
        pid: u32,
        base: DirBase,
        name: &Path,
        in_root: bool,
    ) -> io::Result<PathBuf> {
        if name.is_absolute() && !in_root {
            return Ok(self.alias(pid, name));
        }

        let dir = std::fs::read_link(self.base_link(pid, base))?;
        let relative = name.strip_prefix("/").unwrap_or(name);

        Ok(self.alias(pid, &dir.join(relative)))
    }

    /// Pin the directory a tracee-relative name starts from.
    ///
    /// # Errors
    /// Returns the error from opening the working directory or duplicating the
    /// tracee's descriptor.
    pub fn pin_dir(&self, pid: u32, base: DirBase) -> io::Result<OwnedFd> {
        match base {
            DirBase::Cwd => pin_path(&self.base_link(pid, base), false),
            DirBase::Fd(fd) => agent_sandbox_sysutil::dup_tracee_fd(pid, fd),
        }
    }

    /// Pin the object `name` reaches when the tracee opens it under `scope`.
    ///
    /// Plain lookups resolve [`Resolver::lookup`]'s path. A lookup with
    /// `RESOLVE_*` flags is repeated through `openat2` from the pinned
    /// starting directory so the kernel applies the same restrictions, and
    /// fails where the tracee's own open would fail.
    ///
    /// # Errors
    /// Returns the lookup error, or `EINVAL` for unknown `RESOLVE_*` bits.
    pub fn pin_name(
        &self,
        pid: u32,
        base: DirBase,
        name: &Path,
        scope: PinScope,
    ) -> io::Result<OwnedFd> {
        let in_root = scope.resolve & RESOLVE_IN_ROOT != 0;

        if scope.resolve == 0 {
            return pin_path(&self.lookup(pid, base, name, false)?, scope.nofollow);
        }

        let resolve = ResolveFlag::from_bits(scope.resolve)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let how = OpenHow::new()
            .flags(path_flags(scope.nofollow))
            .resolve(resolve);

        if name.is_absolute() && !in_root {
            return nix::fcntl::openat2(AT_FDCWD, self.alias(pid, name).as_path(), how)
                .map_err(io::Error::from);
        }

        let dir = self.pin_dir(pid, base)?;
        nix::fcntl::openat2(&dir, name, how).map_err(io::Error::from)
    }

    /// Canonicalize a filesystem path by resolving symlinks.
    #[must_use]
    pub fn normalize_path(&self, path: &Path) -> PathBuf {
        let fd = pin_path(path, false);

        match fd {
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                return path.to_path_buf();
            }
            Ok(fd) => {
                if let Some(resolved) = self.fd_path(fd.as_fd()) {
                    return resolved;
                }
            }
            Err(_) => {}
        }

        // Anonymous descriptors and unlinked handles have no canonical
        // pathname.
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    }

    /// Canonicalize a captured name against its pinned directory.
    ///
    /// Fast path: an absolute, lexically normal captured name proved
    /// symlink-free by `RESOLVE_NO_SYMLINKS` is already canonical, so it is
    /// returned without `readlink`. `ELOOP` means a symlink (or magic link) was
    /// traversed, so the captured name is *not* canonical and the pin below
    /// runs; `ENOSYS`/`EINVAL` mean the kernel or the flags are unsupported and
    /// also fall through; any other error (for example `ENOENT`/`ENOTDIR` on a
    /// name that does not exist yet) means there is no alias to resolve, which
    /// is exactly what the absolute-name fallback returns.
    ///
    /// # Errors
    /// Returns the `readlink` error from building the fallback path.
    pub fn normalize_captured_path(&self, dir: impl AsFd, raw: &[u8]) -> io::Result<PathBuf> {
        let candidate = PathBuf::from(std::ffi::OsStr::from_bytes(raw));

        match agent_sandbox_sysutil::is_canonical_path(&candidate) {
            Ok(true) => return Ok(candidate),
            Ok(false) => {}
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP | libc::ENOSYS | libc::EINVAL)
                ) => {}
            Err(_) => return Ok(candidate),
        }

        match pin_at(&dir, &candidate) {
            Ok(fd) => {
                if let Some(resolved) = self.fd_path(fd.as_fd()) {
                    return Ok(resolved);
                }
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                return self.absolute_name(dir, raw);
            }
            Err(_) => {}
        }

        // Anonymous descriptors and unlinked handles have no canonical
        // pathname.
        let path = self.absolute_name(dir, raw)?;
        Ok(std::fs::canonicalize(&path).unwrap_or(path))
    }

    /// Absolute path for a captured name, joined to the pinned directory's
    /// path when it is relative. The policy fallback for names that do not
    /// resolve: anything that exists canonicalizes through its own handle, so
    /// the per-syscall hot path skips this `readlink`.
    ///
    /// # Errors
    /// Returns the `readlink` error for the pinned directory.
    pub fn absolute_name(&self, dir: impl AsFd, raw: &[u8]) -> io::Result<PathBuf> {
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(raw));

        if path.is_absolute() {
            return Ok(path);
        }

        Ok(self.fd_link(dir.as_fd())?.join(path))
    }
}

const fn path_flags(nofollow: bool) -> OFlag {
    if nofollow {
        OFlag::O_PATH
            .union(OFlag::O_CLOEXEC)
            .union(OFlag::O_NOFOLLOW)
    } else {
        OFlag::O_PATH.union(OFlag::O_CLOEXEC)
    }
}

/// Pin the object at `path` with an `O_PATH` handle.
///
/// # Errors
/// Returns the `open` error.
pub fn pin_path(path: &Path, nofollow: bool) -> io::Result<OwnedFd> {
    nix::fcntl::open(path, path_flags(nofollow), nix::sys::stat::Mode::empty())
        .map_err(io::Error::from)
}

/// Pin the object `name` reaches from the directory handle `dir`.
///
/// # Errors
/// Returns the `openat` error.
pub fn pin_at(dir: impl AsFd, name: &Path) -> io::Result<OwnedFd> {
    nix::fcntl::openat(dir, name, path_flags(false), nix::sys::stat::Mode::empty())
        .map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::fd::AsFd, path::Path};

    use super::{DirBase, PinScope, Resolver, pin_path};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("broker-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch directory");
        dir.canonicalize().expect("canonical scratch directory")
    }

    #[test]
    fn dirfd_arguments_decode_from_the_low_word() {
        let at_fdcwd = i64::from(libc::AT_FDCWD).cast_unsigned();
        let zero_extended = u64::from(libc::AT_FDCWD.cast_unsigned());
        assert_eq!(DirBase::from_arg(at_fdcwd).expect("cwd"), DirBase::Cwd);
        assert_eq!(
            DirBase::from_arg(zero_extended).expect("zero-extended cwd"),
            DirBase::Cwd
        );
        assert_eq!(DirBase::from_arg(7).expect("fd"), DirBase::Fd(7));
        assert_eq!(
            DirBase::from_arg(u64::from(u32::MAX - 1))
                .expect_err("negative descriptor")
                .raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn lookup_joins_relative_names_to_the_tracee_directory() {
        let resolver = Resolver::default();
        let dir = scratch("lookup");
        let held = fs::File::open(&dir).expect("open scratch directory");
        let pid = std::process::id();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&held);

        assert_eq!(
            resolver
                .lookup(pid, DirBase::Fd(fd), Path::new("kvm"), false)
                .expect("relative lookup"),
            dir.join("kvm")
        );
        assert_eq!(
            resolver
                .lookup(pid, DirBase::Fd(fd), Path::new("/etc/hosts"), false)
                .expect("absolute lookup"),
            Path::new("/etc/hosts")
        );
        assert_eq!(
            resolver
                .lookup(pid, DirBase::Fd(fd), Path::new("/kvm"), true)
                .expect("in-root lookup"),
            dir.join("kvm")
        );
        assert_eq!(
            resolver
                .lookup(pid, DirBase::Cwd, Path::new("x"), false)
                .expect("cwd lookup"),
            std::env::current_dir().expect("cwd").join("x")
        );

        fs::remove_dir_all(dir).expect("remove scratch directory");
    }

    #[test]
    fn lookup_rewrites_process_aliases_to_the_tracee() {
        let resolver = Resolver::default();
        let pid = std::process::id();

        for (alias, expected) in [
            ("/proc/self/fd/3", format!("/proc/{pid}/fd/3")),
            ("/dev/stdin", format!("/proc/{pid}/fd/0")),
            ("/dev/fd/5", format!("/proc/{pid}/fd/5")),
        ] {
            assert_eq!(
                resolver
                    .lookup(pid, DirBase::Cwd, Path::new(alias), false)
                    .expect("alias lookup"),
                Path::new(&expected)
            );
        }
    }

    #[test]
    fn pinned_name_survives_the_name_being_swapped() {
        let resolver = Resolver::default();
        let dir = scratch("pin-swap");
        fs::write(dir.join("approved"), b"approved").expect("write approved file");
        let pid = std::process::id();

        let pinned = resolver
            .pin_name(
                pid,
                DirBase::Cwd,
                &dir.join("approved"),
                PinScope::default(),
            )
            .expect("pin name");
        fs::remove_file(dir.join("approved")).expect("remove approved file");
        fs::write(dir.join("approved"), b"swapped").expect("write replacement");

        let reopened = fs::read(resolver.self_fd(pinned.as_fd())).expect("reopen through procfs");
        assert_eq!(reopened, b"approved");

        fs::remove_dir_all(dir).expect("remove scratch directory");
    }

    #[test]
    fn nofollow_pins_the_symlink_and_resolve_flags_restrict_the_lookup() {
        let resolver = Resolver::default();
        let dir = scratch("pin-scope");
        fs::write(dir.join("real"), b"real").expect("write file");
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).expect("create link");
        let pid = std::process::id();
        let link = dir.join("link");

        let followed = resolver
            .pin_name(pid, DirBase::Cwd, &link, PinScope::default())
            .expect("followed pin");
        assert_eq!(resolver.fd_path(followed.as_fd()), Some(dir.join("real")));

        let nofollow = resolver
            .pin_name(pid, DirBase::Cwd, &link, PinScope {
                nofollow: true,
                resolve: 0,
            })
            .expect("nofollow pin");
        assert_eq!(resolver.fd_path(nofollow.as_fd()), Some(link.clone()));

        let no_symlinks = nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS.bits();
        let refused = resolver
            .pin_name(pid, DirBase::Cwd, &link, PinScope {
                nofollow: false,
                resolve: no_symlinks,
            })
            .expect_err("RESOLVE_NO_SYMLINKS refuses the link");
        assert_eq!(refused.raw_os_error(), Some(libc::ELOOP));

        let unknown = resolver
            .pin_name(pid, DirBase::Cwd, &link, PinScope {
                nofollow: false,
                resolve: 1 << 40,
            })
            .expect_err("unknown resolve bits");
        assert_eq!(unknown.raw_os_error(), Some(libc::EINVAL));

        fs::remove_dir_all(dir).expect("remove scratch directory");
    }

    #[test]
    fn canonical_paths_follow_live_aliases_and_preserve_unresolvable_paths() {
        let resolver = Resolver::default();
        let root = scratch("canonical");
        let first = root.join("first");
        let second = root.join("second");
        let alias = root.join("alias");
        fs::write(&first, b"first").expect("write first file");
        fs::write(&second, b"second").expect("write second file");
        std::os::unix::fs::symlink(&first, &alias).expect("create alias");
        let before = resolver.normalize_path(&alias);
        fs::remove_file(&alias).expect("remove alias");
        std::os::unix::fs::symlink(&second, &alias).expect("retarget alias");
        let after = resolver.normalize_path(&alias);
        let missing = root.join("missing");
        let unresolved = resolver.normalize_path(&missing);
        let directory_alias = root.join("directory-alias");
        std::os::unix::fs::symlink(&root, &directory_alias).expect("create directory alias");
        let missing_alias = directory_alias.join("missing");
        let missing_alias_result = resolver.normalize_path(&missing_alias);
        let not_directory = alias.join("child");
        let not_directory_result = resolver.normalize_path(&not_directory);
        let held = fs::File::open(&first).expect("hold first file");
        fs::remove_file(&first).expect("unlink held file");
        let deleted = resolver.self_fd(held.as_fd());
        let deleted_result = resolver.normalize_path(&deleted);
        let (reader, _writer) = nix::unistd::pipe().expect("create anonymous pipe");
        let anonymous = resolver.self_fd(reader.as_fd());
        let anonymous_result = resolver.normalize_path(&anonymous);
        fs::remove_dir_all(&root).expect("remove temporary directory");
        assert_eq!(before, first);
        assert_eq!(after, second);
        assert_eq!(unresolved, missing);
        assert_eq!(missing_alias_result, missing_alias);
        assert_eq!(not_directory_result, not_directory);
        assert_eq!(deleted_result, deleted);
        assert_eq!(anonymous_result, anonymous);
    }

    #[test]
    fn captured_names_canonicalize_only_when_the_kernel_proves_them() {
        use std::os::unix::ffi::OsStrExt;

        let resolver = Resolver::default();
        let root = scratch("normalize-fast");
        fs::create_dir_all(root.join("target")).expect("create target dir");
        fs::create_dir_all(root.join("sub")).expect("create sub dir");
        let target_file = root.join("target").join("sub");
        fs::write(&target_file, b"target").expect("write target file");
        let plain = root.join("plain");
        fs::write(&plain, b"plain").expect("write plain file");
        std::os::unix::fs::symlink(&target_file, root.join("link")).expect("create link");
        let dir = pin_path(Path::new("/"), false).expect("pin root");

        let link = root.join("link");
        let resolved_link = resolver
            .normalize_captured_path(&dir, link.as_os_str().as_bytes())
            .expect("normalize link");
        assert_eq!(
            resolved_link, target_file,
            "symlink access path must resolve, not trust the captured name"
        );

        let resolved_plain = resolver
            .normalize_captured_path(&dir, plain.as_os_str().as_bytes())
            .expect("normalize plain");
        assert_eq!(resolved_plain, plain);

        let dotdot = root.join("sub").join("..").join("plain");
        let resolved_dotdot = resolver
            .normalize_captured_path(&dir, dotdot.as_os_str().as_bytes())
            .expect("normalize dotdot");
        assert_eq!(
            resolved_dotdot, plain,
            "non-normal name must canonicalize rather than trust the captured string"
        );

        fs::remove_dir_all(&root).expect("remove temp dir");
    }
}
