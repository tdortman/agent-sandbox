//! Classification of `open`, `openat`, `openat2` and `creat` against the
//! device gate, and reopening of terminals the tracee already holds.
//!
//! Regular files and directories continue unmodified: fanotify gates them, and
//! emulating every open would proxy all file I/O through the broker. Only
//! device nodes are emulated. The device inode is pinned while classifying, so
//! the approved object is the one the emulated open reaches.

use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    path::Path,
};

use agent_sandbox_core::{DeviceAccess, ResourceAccess, ResourceKind};

use crate::{
    DeviceCapture, ResourceCapture, ResourceTarget, SeccompNotif, SyscallTarget,
    capture::{OpenArgs, OpenCapture},
    pinning::{DirBase, PinScope, RESOLVE_IN_ROOT, Resolver},
};

fn is_device_bypass(path: &Path) -> bool {
    agent_sandbox_syscall::floor::UNGATED_DEVICES
        .iter()
        .any(|entry| path == Path::new(entry))
}

/// Check whether `path` refers to a block or character device by examining
/// the file type via `stat`. A missing path (`ENOENT`/`ENOTDIR`) is a
/// definitively non-device target (e.g. `open(O_CREAT)` of a new file), so it
/// returns `Some(false)`. Any other error (permission, I/O) leaves the type
/// indeterminate and returns `None`.
fn device_file_type(path: &Path) -> Option<bool> {
    use std::os::unix::fs::FileTypeExt;

    match std::fs::metadata(path) {
        Ok(meta) => Some(meta.file_type().is_block_device() || meta.file_type().is_char_device()),
        Err(err) if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => Some(false),
        Err(_) => None,
    }
}

/// Whether an open syscall should be resource-gated as a device node.
///
/// Regular files, directories and bypass devices return `None` and continue
/// unmodified: their access is covered by fanotify/fsmon. If the tracee
/// arguments cannot be read, or `stat` is inconclusive on a non-`/dev` path,
/// the open is allowed to continue so fanotify can gate it. A pathname with no
/// terminator within `PATH_MAX` is `ENAMETOOLONG`, as the kernel reports.
pub fn target_from_open(resolver: &Resolver, notif: &SeccompNotif) -> Option<SyscallTarget> {
    let args = OpenArgs::from_notification(notif)?;

    if args.proves_not_a_device() {
        return None;
    }

    match args.capture(notif.pid) {
        Ok(Some(capture)) => classify_open(resolver, notif.pid, &capture),
        Err(err) if err.raw_os_error() == Some(libc::ENAMETOOLONG) => {
            Some(SyscallTarget::Errno(libc::ENAMETOOLONG))
        }
        Ok(None) | Err(_) => None,
    }
}

/// Classify a captured open. Everything the decision and the emulated open
/// need comes from `capture`; the tracee is not read again.
pub fn classify_open(
    resolver: &Resolver,
    pid: u32,
    capture: &OpenCapture,
) -> Option<SyscallTarget> {
    // A non-UTF-8 name cannot be policy-keyed; fanotify gates it.
    let name = Path::new(std::str::from_utf8(&capture.path).ok()?);
    let how = capture.how;
    let in_root = how.resolve & RESOLVE_IN_ROOT != 0;

    // The kernel ignores `dirfd` for an absolute name, so a bogus one only
    // matters when the name is relative or scoped under it.
    let base = match DirBase::from_arg(capture.dirfd) {
        Ok(base) => base,
        Err(_) if name.is_absolute() && !in_root => DirBase::Cwd,
        Err(_) => return None,
    };

    // stat follows aliases, so definite non-devices need no pin.
    if device_file_type(&resolver.lookup(pid, base, name, in_root).ok()?) == Some(false) {
        return None;
    }

    let pinned = resolver
        .pin_name(pid, base, name, PinScope {
            nofollow: how.flags & libc::O_NOFOLLOW != 0,
            resolve: how.resolve,
        })
        .ok()?;

    let path = resolver.fd_path(pinned.as_fd())?;

    if !path.starts_with("/dev") || is_device_bypass(&path) {
        return None;
    }

    let file_type = nix::sys::stat::fstat(&pinned).ok()?.st_mode & libc::S_IFMT;

    if file_type != libc::S_IFCHR && file_type != libc::S_IFBLK {
        return None;
    }

    let access = match how.flags & libc::O_ACCMODE {
        libc::O_WRONLY => DeviceAccess::Write,
        libc::O_RDWR => DeviceAccess::ReadWrite,
        _ => DeviceAccess::Read,
    };

    Some(SyscallTarget::Resource(ResourceTarget {
        kind: ResourceKind::Device,
        path,
        access: ResourceAccess::Device(access),
        capture: ResourceCapture::Device(DeviceCapture {
            pinned,
            flags: how.flags,
            mode: how.mode,
        }),
    }))
}

impl DeviceCapture {
    /// Open the pinned device with the flags the tracee requested plus
    /// `extra_flags`.
    ///
    /// The handle is reopened through procfs, so the open reaches the pinned
    /// inode and never looks the name up again. `O_NOFOLLOW` applied when the
    /// handle was pinned and would fail on the procfs link, so it is dropped.
    ///
    /// # Errors
    /// Returns the `open` error.
    pub fn open(&self, resolver: &Resolver, extra_flags: i32) -> io::Result<OwnedFd> {
        let flags = (self.flags | extra_flags) & !libc::O_NOFOLLOW;

        nix::fcntl::open(
            &resolver.self_fd(self.pinned.as_fd()),
            nix::fcntl::OFlag::from_bits_truncate(flags),
            nix::sys::stat::Mode::from_bits_truncate(self.mode),
        )
        .map_err(io::Error::from)
    }
}

/// Inode identity of an open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl From<&std::fs::Metadata> for FileIdentity {
    fn from(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

impl From<&libc::stat> for FileIdentity {
    fn from(stat: &libc::stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        }
    }
}

/// Open a pty terminal (`/dev/pts/N`) the tracee already holds, without a
/// policy decision.
///
/// The tracee holds it when it has the terminal open (a sandbox reopening its
/// inherited terminal by path, as libuv does for every TTY stdio) or the pty's
/// controller from `/dev/ptmx` (`openpty` falling back to the terminal path,
/// or Go `creack/pty`). Reopening a terminal the process can already read and
/// write grants nothing new. Every other pty stays policy-gated, so a sandbox
/// cannot read or inject into another terminal's session.
///
/// Both cases match by inode against the pinned terminal, so a pty number
/// recycled in between, or one from another devpts instance, is refused. A
/// held controller yields its own terminal through `TIOCGPTPEER`.
#[must_use]
pub fn reopen_held_terminal(
    resolver: &Resolver,
    pid: u32,
    path: &Path,
    device: &DeviceCapture,
) -> Option<OwnedFd> {
    let index = path
        .strip_prefix("/dev/pts")
        .ok()?
        .to_str()?
        .parse::<u32>()
        .ok()?;
    let wanted = FileIdentity::from(&nix::sys::stat::fstat(&device.pinned).ok()?);

    let opened = resolver.tracee_fds(pid).ok()?.find_map(|held| {
        if held.link == path {
            held_terminal_reopen(resolver, pid, held.fd, device, wanted)
        } else if held.link == Path::new("/dev/ptmx") || held.link == Path::new("/dev/pts/ptmx") {
            held_controller_peer(resolver, pid, held.fd, index, device.flags, wanted)
        } else {
            None
        }
    })?;

    (FileIdentity::from(&opened.metadata().ok()?) == wanted).then(|| opened.into())
}

/// Reopen the pinned terminal when the tracee's descriptor `fd` is that same
/// terminal.
fn held_terminal_reopen(
    resolver: &Resolver,
    pid: u32,
    fd: i32,
    device: &DeviceCapture,
    wanted: FileIdentity,
) -> Option<std::fs::File> {
    let held = std::fs::metadata(resolver.tracee_fd(pid, fd)).ok()?;
    if FileIdentity::from(&held) != wanted {
        return None;
    }

    device
        .open(resolver, libc::O_NOCTTY)
        .ok()
        .map(std::fs::File::from)
}

/// Open the terminal of the tracee's pty controller `fd` when that controller
/// belongs to pty `index`.
fn held_controller_peer(
    resolver: &Resolver,
    pid: u32,
    fd: i32,
    index: u32,
    flags: i32,
    wanted: FileIdentity,
) -> Option<std::fs::File> {
    // Checking the index first keeps TIOCGPTPEER off unrelated controllers,
    // whose terminals would otherwise see an extra open and close.
    let fdinfo = resolver.tracee_fdinfo(pid, fd).ok()?;
    let held_index = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("tty-index:"))?
        .trim()
        .parse::<u32>()
        .ok()?;
    if held_index != index {
        return None;
    }

    let controller = agent_sandbox_sysutil::dup_tracee_fd(pid, fd).ok()?;
    let peer_flags = (flags | libc::O_NOCTTY)
        & (libc::O_ACCMODE | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let peer = rustix::pty::ioctl_tiocgptpeer(
        &controller,
        rustix::pty::OpenptFlags::from_bits_retain(peer_flags.cast_unsigned()),
    )
    .ok()?;
    let peer = std::fs::File::from(peer);

    (FileIdentity::from(&peer.metadata().ok()?) == wanted).then_some(peer)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, fs, io, path::Path};

    use agent_sandbox_core::{DeviceAccess, ResourceAccess};

    use super::{classify_open, device_file_type, is_device_bypass};
    use crate::{
        ResourceCapture, SeccompData, SeccompNotif, SyscallTarget,
        capture::{OpenArgs, OpenCapture, OpenHow, at_fdcwd_arg},
        pinning::Resolver,
        target_from_notification,
    };

    /// The terminal end of a fresh pty: a device that is never ungated and
    /// exists wherever the tests run.
    struct Terminal {
        _pty: nix::pty::OpenptyResult,
        path: std::path::PathBuf,
    }

    fn terminal() -> Terminal {
        let pty = nix::pty::openpty(None, None).expect("openpty");
        let path = nix::unistd::ttyname(&pty.slave).expect("terminal name");

        Terminal { _pty: pty, path }
    }

    fn capture(path: &Path, flags: i32, resolve: u64) -> OpenCapture {
        OpenCapture {
            path: path.as_os_str().as_encoded_bytes().to_vec(),
            dirfd: at_fdcwd_arg(),
            how: OpenHow {
                flags,
                mode: 0,
                resolve,
            },
        }
    }

    fn resource(target: Option<SyscallTarget>) -> crate::ResourceTarget {
        let Some(SyscallTarget::Resource(target)) = target else {
            panic!("expected a gated device, got {target:?}");
        };
        target
    }

    fn open_notif(syscall: i64, args: [u64; 6]) -> SeccompNotif {
        SeccompNotif {
            pid: std::process::id(),
            data: SeccompData {
                nr: i32::try_from(syscall).expect("syscall number"),
                args,
                ..SeccompData::default()
            },
            ..SeccompNotif::default()
        }
    }

    #[test]
    fn classification_and_emulated_open_use_one_capture_of_open_how() {
        use agent_sandbox_syscall::policy::nr;

        let terminal = terminal();
        let path = std::ffi::CString::new(terminal.path.as_os_str().as_encoded_bytes())
            .expect("nul-free path");
        let args = OpenArgs::from_notification(&open_notif(nr::OPENAT2, [
            at_fdcwd_arg(),
            0x1000,
            0x2000,
            24,
            0,
            0,
        ]))
        .expect("open-family notification");

        // The racing tracee thread flips `open_how` after the first read.
        let how_reads = Cell::new(0_u32);
        let captured = args
            .capture_with(|addr, _| match addr {
                0x1000 => Ok(path.as_bytes_with_nul().to_vec()),
                0x2000 => {
                    let writable = how_reads.get() == 0;
                    how_reads.set(how_reads.get() + 1);
                    let flags = if writable {
                        libc::O_RDWR
                    } else {
                        libc::O_RDONLY
                    };
                    let mut how = i64::from(flags).to_ne_bytes().to_vec();
                    how.extend_from_slice(&[0; 16]);
                    Ok(how)
                }
                _ => Err(io::Error::from_raw_os_error(libc::EFAULT)),
            })
            .expect("capture")
            .expect("non-null path");

        let target = resource(classify_open(
            &Resolver::default(),
            std::process::id(),
            &captured,
        ));

        assert_eq!(how_reads.get(), 1);
        assert_eq!(
            target.access,
            ResourceAccess::Device(DeviceAccess::ReadWrite)
        );
        let ResourceCapture::Device(device) = &target.capture else {
            panic!("device open carries a device capture");
        };
        assert_eq!(
            device.flags,
            libc::O_RDWR,
            "emulation opens what was classified"
        );
    }

    #[test]
    fn device_alias_outside_dev_remains_resource_gated() {
        let terminal = terminal();
        let resolver = Resolver::default();
        let alias =
            std::env::temp_dir().join(format!("broker-device-alias-{}", std::process::id()));
        std::os::unix::fs::symlink(&terminal.path, &alias).expect("create device alias");

        let followed = classify_open(
            &resolver,
            std::process::id(),
            &capture(&alias, libc::O_RDWR, 0),
        );
        let nofollow = classify_open(
            &resolver,
            std::process::id(),
            &capture(&alias, libc::O_RDWR | libc::O_NOFOLLOW, 0),
        );
        let no_symlinks = classify_open(
            &resolver,
            std::process::id(),
            &capture(
                &alias,
                libc::O_RDWR,
                nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS.bits(),
            ),
        );
        fs::remove_file(alias).expect("remove device alias");

        assert_eq!(
            resource(followed).path,
            fs::canonicalize(&terminal.path).expect("canonical device")
        );
        assert!(
            nofollow.is_none(),
            "O_NOFOLLOW on a symlink must not reach the device"
        );
        assert!(
            no_symlinks.is_none(),
            "RESOLVE_NO_SYMLINKS on a symlink must not reach the device"
        );
    }

    #[test]
    fn emulated_open_reaches_the_pinned_device_not_a_replacement() {
        let terminal = terminal();
        let resolver = Resolver::default();
        let target = resource(classify_open(
            &resolver,
            std::process::id(),
            &capture(&terminal.path, libc::O_RDWR | libc::O_NOFOLLOW, 0),
        ));
        let ResourceCapture::Device(device) = &target.capture else {
            panic!("device open carries a device capture");
        };

        let opened = std::fs::File::from(
            device
                .open(&resolver, libc::O_NOCTTY)
                .expect("open pinned device"),
        );
        let expected = fs::metadata(&terminal.path).expect("stat terminal");
        let reached = opened.metadata().expect("stat opened device");
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            (reached.dev(), reached.ino()),
            (expected.dev(), expected.ino())
        );
    }

    #[test]
    fn unterminated_open_path_is_enametoolong() {
        use agent_sandbox_syscall::policy::nr;

        let unterminated = vec![b'a'; libc::PATH_MAX as usize];
        let notif = open_notif(nr::OPEN, [
            unterminated.as_ptr() as u64,
            libc::O_RDONLY as u64,
            0,
            0,
            0,
            0,
        ]);

        assert!(matches!(
            target_from_notification(&Resolver::default(), &notif),
            Ok(Some(SyscallTarget::Errno(libc::ENAMETOOLONG)))
        ));
    }

    #[test]
    fn open_of_regular_file_and_directory_continues_unmodified() {
        use agent_sandbox_syscall::policy::nr;

        let dir = std::env::temp_dir().join(format!("broker-open-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("file");
        fs::write(&file, b"open-target").expect("write temp file");
        let resolver = Resolver::default();

        let cpath = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).expect("path");
        let regular = target_from_notification(
            &resolver,
            &open_notif(nr::OPEN, [
                cpath.as_ptr() as u64,
                libc::O_RDONLY as u64,
                0,
                0,
                0,
                0,
            ]),
        )
        .expect("classify open");
        assert!(
            regular.is_none(),
            "regular file open must continue, got {regular:?}"
        );

        let cdir = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).expect("path");
        let directory = target_from_notification(
            &resolver,
            &open_notif(nr::OPENAT, [
                at_fdcwd_arg(),
                cdir.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                0,
                0,
                0,
            ]),
        )
        .expect("classify openat");
        assert!(
            directory.is_none(),
            "directory open must continue, got {directory:?}"
        );

        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    #[test]
    fn device_file_type_fails_closed_on_missing_path() {
        assert_eq!(
            device_file_type(Path::new("/definitely/not/a/device-node")),
            Some(false)
        );

        assert_eq!(
            device_file_type(Path::new("/definitely/not/a/device-node/evil")),
            Some(false)
        );
    }

    #[test]
    fn device_bypass_list_matches_safe_devices() {
        for path in [
            "/dev/null",
            "/dev/zero",
            "/dev/urandom",
            "/dev/random",
            "/dev/full",
            "/dev/tty",
        ] {
            assert!(
                is_device_bypass(Path::new(path)),
                "{path} should be bypassed"
            );
        }
    }

    #[test]
    fn device_bypass_rejects_real_devices() {
        assert!(!is_device_bypass(Path::new("/dev/dri/card0")));
        assert!(!is_device_bypass(Path::new("/dev/nvidia0")));
        assert!(!is_device_bypass(Path::new("/dev/video0")));
        assert!(!is_device_bypass(Path::new("/dev/sda")));
        assert!(!is_device_bypass(Path::new("/etc/hosts")));
        assert!(!is_device_bypass(Path::new("/dev")));
    }
}
