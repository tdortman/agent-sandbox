//! Root fanotify monitor: setns into the sandbox mount namespace,
//! mark each mountpoint, then event-loop handling permission events.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io::Write;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::{fs, io, process};

use agent_sandbox_core::{FileAccess, FilesystemRule};
use agent_sandbox_fsmon::rpc_client;
use clap::Parser;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-fsmon",
    version,
    about = "fanotify filesystem policy monitor that brokers open() calls to policyd",
    long_about = "fanotify-based filesystem monitor that runs in the host mount namespace. \
        Given a target sandbox PID, it joins the sandbox mount namespace, marks every \
        mount that overlaps the sandbox's working directory/home/project, and processes \
        permission events for open/open-exec/access requests. Each event is forwarded \
        to policyd over a Unix domain socket and the verdict (allow/deny) is written \
        back to the kernel via the fanotify response fd.\n\n\
        Normally spawned by policyd in response to an \"agent-sandbox-fs-arm\" request, \
        not invoked directly.\n\n\
        EXAMPLES:\n\
        # Start a monitor for sandbox PID 12345 with the default policyd socket.\n\
        agent-sandbox-fsmon --pid 12345\n\n\
        # Override context for tools that do not export the AGENT_SANDBOX_* env vars.\n\
        agent-sandbox-fsmon \\\n\
            --pid 12345 \\\n\
            --cwd /home/user/project \\\n\
            --home /home/user \\\n\
            --project-root /home/user/project"
)]
struct Cli {
    /// PID of the sandbox arm helper. The monitor joins the mount namespace of this PID and marks its filesystems.
    #[arg(long, value_name = "PID")]
    pid: u32,

    /// Path to the policyd Unix domain socket. fsmon forwards every fanotify permission event here and waits for an allow/deny verdict.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: String,

    /// Working directory inside the sandbox. Used to scope per-project policy and to pick which mounts are marked. Defaults to the env var "AGENT_SANDBOX_CWD" if unset.
    #[arg(long, value_name = "DIR")]
    cwd: Option<String>,

    /// Home directory inside the sandbox. Used to expand "~" in filesystem rules and to gate "global" scope. Defaults to the env var "AGENT_SANDBOX_HOME" if unset.
    #[arg(long, value_name = "DIR")]
    home: Option<String>,

    /// Project root directory inside the sandbox. Required for "project" scope approvals to land in the right per-project policy file. Defaults to the env var "AGENT_SANDBOX_PROJECT_ROOT" if unset.
    #[arg(long, value_name = "DIR")]
    project_root: Option<String>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// fanotify_init flags.
const FAN_CLASS_PRE_CONTENT: u32 = libc::FAN_CLASS_PRE_CONTENT;
const FAN_CLOEXEC: u32 = libc::FAN_CLOEXEC;

/// fanotify_mark flags.
const FAN_MARK_ADD: u32 = libc::FAN_MARK_ADD;
const FAN_MARK_MOUNT: u32 = libc::FAN_MARK_MOUNT;

/// Permission event masks.
const FAN_OPEN_PERM: u64 = libc::FAN_OPEN_PERM;
const FAN_OPEN_EXEC_PERM: u64 = libc::FAN_OPEN_EXEC_PERM;
const FAN_ACCESS_PERM: u64 = libc::FAN_ACCESS_PERM;
const FAN_PRE_ACCESS: u64 = 0x0010_0000;

/// Event metadata struct (matches kernel struct fanotify_event_metadata).
#[repr(C)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// Response struct (matches kernel struct fanotify_response).
#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A mount point entry parsed from /proc/self/mountinfo.
struct MountRecord {
    mount_point: PathBuf,
    fstype: String,
}

/// Returns true if the filesystem type is synthetic and should be skipped
/// when adding fanotify marks.
fn is_synthetic_fs(fstype: &str) -> bool {
    matches!(
        fstype,
        "proc"
            | "sysfs"
            | "cgroup"
            | "cgroup2"
            | "devpts"
            | "tmpfs"
            | "devtmpfs"
            | "pstore"
            | "bpf"
            | "tracefs"
            | "securityfs"
            | "debugfs"
            | "hugetlbfs"
            | "mqueue"
            | "nsfs"
            | "none"
            | "overlay"
            | "fuse.gvfsd-fuse"
            | "fuse.portal"
    )
}

/// Open a fanotify fd suitable for pre-content permission events.
fn fanotify_init() -> io::Result<i32> {
    let raw_fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC,
            0,
        )
    };
    let fd = i32::try_from(raw_fd)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fanotify fd overflow"))?;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Add a fanotify mark on a mount point path.
///
/// Returns the mask that was actually applied. Kernels with
/// `FAN_PRE_ACCESS` support can also receive pre-content notification
/// events for content reads. Unlike the old behavior, `FAN_OPEN_PERM` is
/// always included so that file opens produce deniable permission events.
/// `FAN_PRE_ACCESS` is supplementary and provides fd-level visibility for
/// content classification but cannot deny access.
fn fanotify_mark(fan_fd: i32, path: &CStr, try_pre_access: bool) -> io::Result<u64> {
    let mask = if try_pre_access {
        FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM | FAN_PRE_ACCESS
    } else {
        FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd,
            (FAN_MARK_ADD | FAN_MARK_MOUNT) as i64,
            mask,
            libc::AT_FDCWD,
            path.as_ptr(),
        )
    };

    if ret == 0 {
        return Ok(mask);
    }

    let err = io::Error::last_os_error();
    // If FAN_PRE_ACCESS is not supported, try again without it.
    if try_pre_access && matches!(err.raw_os_error(), Some(libc::EINVAL | libc::EOPNOTSUPP)) {
        return fanotify_mark(fan_fd, path, false);
    }
    Err(err)
}

/// Parse `/proc/self/mountinfo` and return all mount entries with their fstype.
fn parse_mountinfo() -> io::Result<Vec<MountRecord>> {
    let content = fs::read_to_string("/proc/self/mountinfo")?;
    let mut mounts = Vec::new();

    for line in content.lines() {
        // Format: id parent_id major:minor root mount_point options ... - fstype source super_options
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 9 {
            continue;
        }

        // Fields: 0=id, 1=parent, 2=dev, 3=root, 4=mount_point, ...
        // The separator `-` is at position fields.len()-4.
        let mount_point = fields[4];
        let sep_idx = fields.iter().position(|&f| f == "-");
        let fstype = sep_idx
            .and_then(|i| fields.get(i + 1))
            .copied()
            .unwrap_or("");

        mounts.push(MountRecord {
            mount_point: PathBuf::from(mount_point),
            fstype: fstype.to_owned(),
        });
    }

    Ok(mounts)
}

/// Returns true if `mount_point` is an ancestor of or equal to `target`
/// (i.e., `target` resides at or under `mount_point`).
fn mount_covers(mount_point: &Path, target: &Path) -> bool {
    target.starts_with(mount_point)
}

/// Returns true if `mount_point` is at or under the `home` directory.
fn is_under_home(mount_point: &Path, home: &Path) -> bool {
    mount_point.starts_with(home)
}

/// Return the deepest mount point that contains `target`.
fn deepest_covering_mount<'a>(mounts: &'a [MountRecord], target: &Path) -> Option<&'a Path> {
    mounts
        .iter()
        .filter(|mount| mount_covers(&mount.mount_point, target))
        .max_by_key(|mount| mount.mount_point.as_os_str().len())
        .map(|mount| mount.mount_point.as_path())
}

fn resolve_event_path(event_fd: i32) -> io::Result<String> {
    let link = format!("/proc/self/fd/{event_fd}");
    let path = fs::read_link(&link)?;
    Ok(path.to_string_lossy().into_owned())
}

fn open_flags_to_access(flags: i32) -> FileAccess {
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => FileAccess::Read,
        libc::O_WRONLY => FileAccess::Write,
        _ => FileAccess::ReadWrite,
    }
}

fn combine_access(left: FileAccess, right: FileAccess) -> FileAccess {
    if left == right {
        return left;
    }
    if left == FileAccess::All || right == FileAccess::All {
        return FileAccess::All;
    }
    if left == FileAccess::ReadWrite || right == FileAccess::ReadWrite {
        return FileAccess::ReadWrite;
    }
    if matches!(
        (left, right),
        (FileAccess::Read, FileAccess::Write) | (FileAccess::Write, FileAccess::Read)
    ) {
        return FileAccess::ReadWrite;
    }
    FileAccess::All
}

fn fdinfo_flags(pid: i32, fd_name: &str) -> io::Result<i32> {
    let content = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd_name}"))?;
    let flags = content
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing fdinfo flags"))?
        .trim();
    i32::from_str_radix(flags, 8).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn event_fd_access(event_fd: i32) -> Option<FileAccess> {
    if event_fd < 0 {
        return None;
    }
    fdinfo_flags(self_pid_i32(), &event_fd.to_string())
        .ok()
        .map(open_flags_to_access)
}

fn self_pid_i32() -> i32 {
    i32::try_from(process::id()).unwrap_or(i32::MAX)
}

fn process_fd_access(pid: i32, event_fd: i32) -> Option<FileAccess> {
    if pid <= 0 {
        return None;
    }
    let event_meta = fs::metadata(format!("/proc/self/fd/{event_fd}")).ok()?;
    let dir = fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut access = None;
    for entry in dir.flatten() {
        let fd_name = entry.file_name();
        let Some(fd_name) = fd_name.to_str() else {
            continue;
        };
        let Ok(meta) = fs::metadata(entry.path()) else {
            continue;
        };
        if meta.dev() != event_meta.dev() || meta.ino() != event_meta.ino() {
            continue;
        }
        let Ok(flags) = fdinfo_flags(pid, fd_name) else {
            continue;
        };
        let fd_access = open_flags_to_access(flags);
        access = Some(access.map_or(fd_access, |current| combine_access(current, fd_access)));
        if access == Some(FileAccess::ReadWrite) {
            return access;
        }
    }
    access
}

fn event_fd_is_regular_file(event_fd: i32) -> bool {
    fs::metadata(format!("/proc/self/fd/{event_fd}")).is_ok_and(|meta| meta.is_file())
}

/// Translate a fanotify event mask to the corresponding `FileAccess`.
fn mask_to_access(mask: u64, event_fd: i32, pid: i32) -> FileAccess {
    if mask & FAN_OPEN_EXEC_PERM != 0 {
        return FileAccess::Execute;
    }
    if mask & FAN_PRE_ACCESS != 0 {
        return process_fd_access(pid, event_fd).unwrap_or(FileAccess::ReadWrite);
    }
    if mask & FAN_ACCESS_PERM != 0 {
        return FileAccess::Read;
    }
    if mask & FAN_OPEN_PERM != 0 {
        return event_fd_access(event_fd)
            .or_else(|| process_fd_access(pid, event_fd))
            .unwrap_or(FileAccess::ReadWrite);
    }
    FileAccess::All
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let self_pid = i32::try_from(process::id()).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-fsmon: process id does not fit in pid_t");
        process::exit(1);
    });

    // Open fanotify fd.
    let fan_fd = fanotify_init().unwrap_or_else(|e| {
        eprintln!("agent-sandbox-fsmon: fanotify_init failed: {e}");
        process::exit(1);
    });

    // setns into the target mount namespace.
    let ns_path = format!("/proc/{}/ns/mnt", cli.pid);
    let ns_cstr = CString::new(ns_path.as_bytes()).expect("null in ns path");
    let ns_fd = unsafe { libc::open(ns_cstr.as_ptr(), libc::O_RDONLY) };
    if ns_fd < 0 {
        eprintln!(
            "agent-sandbox-fsmon: open {}: {}",
            ns_path,
            io::Error::last_os_error()
        );
        process::exit(1);
    }
    let ret = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNS) };
    if ret < 0 {
        eprintln!(
            "agent-sandbox-fsmon: setns {}: {}",
            ns_path,
            io::Error::last_os_error()
        );
        process::exit(1);
    }
    unsafe { libc::close(ns_fd) };

    // Parse mountinfo from inside the target namespace.
    let mounts = parse_mountinfo().unwrap_or_else(|e| {
        eprintln!("agent-sandbox-fsmon: failed to parse mountinfo: {e}");
        process::exit(1);
    });
    let home_covering_mount = cli
        .home
        .as_deref()
        .and_then(|home| deepest_covering_mount(&mounts, Path::new(home)))
        .map(Path::to_path_buf);

    // Mark each mount point, skipping synthetic filesystem types.
    let mut saw_pre_access_mark = false;
    let mut home_covered = false;

    for mount in &mounts {
        if home_covering_mount.as_deref() == Some(mount.mount_point.as_path())
            && is_synthetic_fs(&mount.fstype)
        {
            eprintln!(
                "agent-sandbox-fsmon: --home {} is on unsupported synthetic filesystem {} at {}; \
                 cannot guarantee filesystem monitoring",
                cli.home.as_deref().unwrap_or("?"),
                mount.fstype,
                mount.mount_point.display()
            );
            process::exit(1);
        }
        if is_synthetic_fs(&mount.fstype) {
            tracing::debug!(
                path = %mount.mount_point.display(),
                fstype = %mount.fstype,
                "skipping synthetic mount"
            );
            continue;
        }

        let mp_cstr =
            CString::new(mount.mount_point.as_os_str().as_bytes()).expect("null in mount path");
        match fanotify_mark(fan_fd, &mp_cstr, true) {
            Ok(actual_mask) => {
                saw_pre_access_mark |= actual_mask & FAN_PRE_ACCESS != 0;
                if home_covering_mount.as_deref() == Some(mount.mount_point.as_path()) {
                    home_covered = true;
                }
                tracing::debug!(path = %mount.mount_point.display(), mask = %format_args!("{actual_mask:x}"), "marked mountpoint");
            }
            Err(e) => {
                // Non-synthetic mounts at or under --home must be successfully
                // marked to guarantee filesystem monitoring.
                if home_covering_mount.as_deref() == Some(mount.mount_point.as_path())
                    || cli
                        .home
                        .as_deref()
                        .is_some_and(|home| is_under_home(&mount.mount_point, Path::new(home)))
                {
                    eprintln!(
                        "agent-sandbox-fsmon: fanotify_mark {} (under --home): {e}",
                        mount.mount_point.display()
                    );
                    process::exit(1);
                }
                tracing::warn!(
                    path = %mount.mount_point.display(),
                    fstype = %mount.fstype,
                    error = %e,
                    "failed to mark mountpoint (not under home, continuing)"
                );
            }
        }
    }

    // Before signaling ready, require that at least one marked mount covers --home.
    if let Some(ref home) = cli.home
        && !home_covered
    {
        eprintln!(
            "agent-sandbox-fsmon: no successfully marked mount covers --home {home}; \
             cannot guarantee filesystem monitoring"
        );
        process::exit(1);
    }

    // Signal readiness.
    println!("ready");
    let _ = io::stdout().flush();

    let home = cli.home.clone();

    // Build the request context for RPC checks.
    let ctx = agent_sandbox_core::RequestContext {
        cwd: cli.cwd,
        home,
        project_root: cli.project_root,
        pid: None,
        uid: None,
        sandbox_session_id: std::env::var("AGENT_SANDBOX_SESSION_ID").ok(),
    };

    // Read static allow rules from environment (set by policyd).
    let static_allow: Vec<FilesystemRule> = std::env::var("AGENT_SANDBOX_FS_STATIC_ALLOW")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let socket_path = Path::new(&cli.socket);

    // Event loop.
    let mut buf = vec![0u8; 4096];
    loop {
        let n =
            match unsafe { libc::read(fan_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) }
            {
                -1 => {
                    let e = io::Error::last_os_error();
                    eprintln!("agent-sandbox-fsmon: read from fanotify fd: {e}");
                    continue;
                }
                n if n >= 0 => usize::try_from(n).expect("nonnegative read length"),
                _ => continue,
            };
        let mut offset = 0;
        while offset + size_of::<FanotifyEventMetadata>() <= n {
            let meta = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(offset).cast::<FanotifyEventMetadata>())
            };

            if meta.metadata_len == 0 {
                break;
            }

            if meta.event_len == 0 {
                break;
            }
            let Ok(event_len) = usize::try_from(meta.event_len) else {
                break;
            };

            if meta.fd >= 0
                && meta.mask
                    & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_PRE_ACCESS | FAN_ACCESS_PERM)
                    != 0
            {
                if meta.pid == self_pid {
                    respond(fan_fd, meta.fd, FAN_ALLOW);
                    offset += event_len;
                    continue;
                }
                if saw_pre_access_mark
                    && meta.mask & FAN_ACCESS_PERM != 0
                    && event_fd_is_regular_file(meta.fd)
                {
                    respond(fan_fd, meta.fd, FAN_ALLOW);
                    offset += event_len;
                    continue;
                }
                // FAN_PRE_ACCESS is a pre-content notification event, not a
                // permission event. The kernel does not wait for or honor a
                // deny response. Auto-allow these events and rely on
                // FAN_OPEN_PERM for deniable open permission checks.
                if meta.mask & FAN_PRE_ACCESS != 0 {
                    respond(fan_fd, meta.fd, FAN_ALLOW);
                    offset += event_len;
                    continue;
                }
                // Resolve the path from the event fd.
                let Ok(path) = resolve_event_path(meta.fd) else {
                    // Cannot resolve, allow by default.
                    respond(fan_fd, meta.fd, FAN_ALLOW);
                    offset += event_len;
                    continue;
                };
                let access = mask_to_access(meta.mask, meta.fd, meta.pid);

                // Auto-allow events matching a static allow rule.
                if static_allow.iter().any(|rule| rule.matches(&path, access)) {
                    respond(fan_fd, meta.fd, FAN_ALLOW);
                    offset += event_len;
                    continue;
                }
                // Tag the request with the fanotify event PID so policyd can
                // route to the correct UI client (e.g. the host policy UI client
                let mut event_ctx = ctx.clone();
                event_ctx.pid = u32::try_from(meta.pid).ok();
                let reply = rpc_client::check_filesystem(socket_path, &path, access, event_ctx);

                let verdict = match &reply {
                    Ok(r) if r.allowed => FAN_ALLOW,
                    _ => FAN_DENY,
                };

                if verdict == FAN_DENY {
                    tracing::info!(%path, ?access, "denied by policy");
                }

                respond(fan_fd, meta.fd, verdict);
            } else if meta.fd >= 0 {
                // Event without permission bit -> close fd and allow.
                unsafe { libc::close(meta.fd) };
            }

            offset += event_len;
        }
    }
}

/// Write a FAN_ALLOW or FAN_DENY response and close the event fd.
fn respond(fan_fd: i32, event_fd: i32, response: u32) {
    let resp = FanotifyResponse {
        fd: event_fd,
        response,
    };
    unsafe {
        let resp_ptr = (&raw const resp).cast::<libc::c_void>();
        libc::write(fan_fd, resp_ptr, size_of::<FanotifyResponse>());
        libc::close(event_fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn open_flags_map_to_granular_access() {
        assert_eq!(open_flags_to_access(libc::O_RDONLY), FileAccess::Read);
        assert_eq!(open_flags_to_access(libc::O_WRONLY), FileAccess::Write);
        assert_eq!(open_flags_to_access(libc::O_RDWR), FileAccess::ReadWrite);
        assert_eq!(
            open_flags_to_access(libc::O_RDWR | libc::O_APPEND),
            FileAccess::ReadWrite
        );
    }

    #[test]
    fn mask_to_access_prefers_exec_and_read_events() {
        assert_eq!(
            mask_to_access(FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM, -1, -1),
            FileAccess::Execute
        );
        assert_eq!(mask_to_access(FAN_ACCESS_PERM, -1, -1), FileAccess::Read);
        assert_eq!(mask_to_access(FAN_OPEN_PERM, -1, -1), FileAccess::ReadWrite);
    }

    #[test]
    fn open_perm_uses_event_fd_flags_when_available() {
        let path =
            std::env::temp_dir().join(format!("agent-sandbox-fsmon-test-{}", std::process::id()));
        {
            let mut file = File::create(&path).expect("create temp file");
            file.write_all(b"x").expect("write temp file");
        }

        let read_file = File::open(&path).expect("open read-only temp file");
        assert_eq!(
            mask_to_access(FAN_OPEN_PERM, read_file.as_raw_fd(), -1),
            FileAccess::Read
        );

        let read_write_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open read-write temp file");
        assert_eq!(
            mask_to_access(FAN_OPEN_PERM, read_write_file.as_raw_fd(), -1),
            FileAccess::ReadWrite
        );

        std::fs::remove_file(path).expect("remove temp file");
    }

    #[test]
    fn pre_access_without_fd_flags_stays_conservative() {
        assert_eq!(
            mask_to_access(FAN_PRE_ACCESS, -1, -1),
            FileAccess::ReadWrite
        );
    }

    #[test]
    fn combine_read_and_write_becomes_read_write() {
        assert_eq!(
            combine_access(FileAccess::Read, FileAccess::Write),
            FileAccess::ReadWrite
        );
        assert_eq!(
            combine_access(FileAccess::Read, FileAccess::Execute),
            FileAccess::All
        );
    }
}
