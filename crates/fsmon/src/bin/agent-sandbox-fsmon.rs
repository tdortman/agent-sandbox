//! Root fanotify monitor: setns into the sandbox mount namespace,
//! mark each mountpoint, then event-loop handling permission events.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::{fs, io, process};

use agent_sandbox_core::{
    FileAccess, normalize_directory_traverse_access, open_flags_to_file_access,
};
use agent_sandbox_fsmon::rpc_client;
use agent_sandbox_sysutil::{
    FanotifyEventMetadata, FanotifyResponse, fanotify_response_bytes, take_fanotify_event_fd,
};
use clap::Parser;
use nix::dir::Dir;
use nix::fcntl::{AtFlags, OFlag, openat, readlinkat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};

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
    socket: PathBuf,

    /// Working directory inside the sandbox. Used to scope per-project policy and to pick which mounts are marked. Defaults to the env var `AGENT_SANDBOX_CWD` if unset.
    #[arg(long, value_name = "DIR")]
    cwd: Option<PathBuf>,

    /// Home directory inside the sandbox. Used to expand "~" in filesystem rules and to gate "global" scope. Defaults to the env var `AGENT_SANDBOX_HOME` if unset.
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,

    /// Project root directory inside the sandbox. Required for "project" scope approvals to land in the right per-project policy file. Defaults to the env var `AGENT_SANDBOX_PROJECT_ROOT` if unset.
    #[arg(long, value_name = "DIR")]
    project_root: Option<PathBuf>,
}

// fanotify constants and event structs come from `agent_sandbox_sysutil`.
use agent_sandbox_sysutil::{
    FAN_ACCESS_PERM, FAN_ALLOW, FAN_DENY, FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM, FAN_PRE_ACCESS,
};

/// Host procfs directory opened before `setns` into a sandbox mount namespace.
///
/// Fanotify reports PIDs in the listener's PID namespace (host). After `setns`,
/// the mounted `/proc` belongs to the sandbox and may use different PID
/// assignments, so every procfs lookup must be relative to this saved fd.
struct HostProc {
    dir: File,
}

impl HostProc {
    fn open() -> io::Result<Self> {
        Ok(Self {
            dir: File::open("/proc")?,
        })
    }

    fn relative_path(pid: i32, leaf: &str) -> PathBuf {
        PathBuf::from(format!("{pid}/{leaf}"))
    }

    fn open_entry(&self, pid: i32, leaf: &str) -> io::Result<File> {
        let fd = openat(
            &self.dir,
            &Self::relative_path(pid, leaf),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        Ok(File::from(fd))
    }

    fn read_to_string(&self, pid: i32, leaf: &str) -> io::Result<String> {
        let mut file = self.open_entry(pid, leaf)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    fn read_link(&self, pid: i32, leaf: &str) -> io::Result<PathBuf> {
        Ok(PathBuf::from(readlinkat(
            &self.dir,
            &Self::relative_path(pid, leaf),
        )?))
    }

    fn read_self_fd_link(&self, fd: i32) -> io::Result<PathBuf> {
        Ok(PathBuf::from(readlinkat(
            &self.dir,
            Path::new(&format!("self/fd/{fd}")),
        )?))
    }

    fn metadata(&self, pid: i32, leaf: &str) -> io::Result<FileStat> {
        Ok(fstatat(
            &self.dir,
            &Self::relative_path(pid, leaf),
            AtFlags::empty(),
        )?)
    }

    fn numeric_entries(&self, pid: i32, leaf: &str) -> io::Result<Vec<i32>> {
        let dir = Dir::openat(
            &self.dir,
            &Self::relative_path(pid, leaf),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let entries = dir
            .into_iter()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                std::str::from_utf8(entry.file_name().to_bytes())
                    .ok()?
                    .parse()
                    .ok()
            })
            .collect();
        Ok(entries)
    }

    fn read_memory(&self, pid: i32, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.open_entry(pid, "mem")?.read_exact_at(buf, addr)
    }

    /// Thread group id for `pid` (accepts either a tid or tgid).
    fn thread_group_id(&self, pid: i32) -> Option<i32> {
        if pid <= 0 {
            return None;
        }
        let status = self.read_to_string(pid, "status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Tgid:") {
                return rest.trim().parse().ok();
            }
        }
        None
    }
}

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
///
/// Returns `(fd, reports_tid)` where `reports_tid` is true when the kernel
/// honours `FAN_REPORT_TID` and `meta.pid` is the thread id of the opener.
fn fanotify_init_pre_content() -> io::Result<(std::os::fd::OwnedFd, bool)> {
    agent_sandbox_sysutil::fanotify_init_pre_content()
}

/// Add a fanotify mark on a mount point path. Returns the mask that was
/// actually applied. Kernels with `FAN_PRE_ACCESS` support also receive
/// pre-content notification events for content reads.
fn fanotify_mark(
    fan_fd: impl std::os::fd::AsFd,
    path: &CStr,
    try_pre_access: bool,
) -> io::Result<u64> {
    agent_sandbox_sysutil::fanotify_mark(fan_fd, path, try_pre_access)
}

/// Parse mountinfo text and return all mount entries with their fstype.
fn parse_mountinfo_content(content: &str) -> Vec<MountRecord> {
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

    mounts
}

/// Parse mountinfo for a process before entering its mount namespace.
fn parse_mountinfo_for_pid(host_proc: &HostProc, pid: u32) -> io::Result<Vec<MountRecord>> {
    let pid = i32::try_from(pid).map_err(|_| io::Error::other("pid does not fit in pid_t"))?;
    Ok(parse_mountinfo_content(
        &host_proc.read_to_string(pid, "mountinfo")?,
    ))
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

fn resolve_event_path(host_proc: &HostProc, event_fd: &impl AsFd) -> io::Result<String> {
    let path = host_proc.read_self_fd_link(event_fd.as_fd().as_raw_fd())?;
    Ok(path.to_string_lossy().into_owned())
}

fn is_at_fdcwd(dirfd: i64) -> bool {
    dirfd == i64::from(libc::AT_FDCWD)
}

fn tracee_open_dir_base(host_proc: &HostProc, pid: i32, dirfd: i64) -> io::Result<PathBuf> {
    let leaf = if is_at_fdcwd(dirfd) {
        "cwd".to_owned()
    } else {
        format!("fd/{dirfd}")
    };
    host_proc.read_link(pid, &leaf)
}

fn read_tracee_path_ptr(
    host_proc: &HostProc,
    pid: i32,
    path_ptr: u64,
) -> io::Result<Option<PathBuf>> {
    if path_ptr == 0 {
        return Ok(None);
    }
    let bytes = read_tracee_bytes(host_proc, pid, path_ptr, 4096)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(std::str::from_utf8(&bytes[..end]).ok().map(PathBuf::from))
}

fn resolve_relative_open_path(
    host_proc: &HostProc,
    pid: i32,
    dirfd: i64,
    path: PathBuf,
) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(path);
    }
    let base = tracee_open_dir_base(host_proc, pid, dirfd).ok()?;
    Some(base.join(path))
}

/// Parse the pathname from a blocked open-family syscall in `/proc/<tid>/syscall`.
fn parse_open_syscall_path(host_proc: &HostProc, trace_pid: i32, content: &str) -> Option<PathBuf> {
    let content = content.trim();
    if content == "running" {
        return None;
    }

    let mut parts = content.split_whitespace();
    let nr: i64 = parts.next()?.parse().ok()?;
    if nr <= 0 {
        return None;
    }
    let args: Vec<&str> = parts.collect();
    match nr {
        n if n == libc::SYS_open || n == libc::SYS_creat => {
            let path_ptr = parse_proc_syscall_arg(args.first()?)?;
            let path = read_tracee_path_ptr(host_proc, trace_pid, path_ptr).ok()??;
            resolve_relative_open_path(host_proc, trace_pid, i64::from(libc::AT_FDCWD), path)
        }
        n if n == libc::SYS_openat || n == libc::SYS_openat2 => {
            let dirfd = i64::try_from(parse_proc_syscall_arg(args.first()?)?).ok()?;
            let path_ptr = parse_proc_syscall_arg(args.get(1)?)?;
            let path = read_tracee_path_ptr(host_proc, trace_pid, path_ptr).ok()??;
            resolve_relative_open_path(host_proc, trace_pid, dirfd, path)
        }
        _ => None,
    }
}

fn scan_threads_for_open_syscall_path(host_proc: &HostProc, tgid: i32) -> Option<PathBuf> {
    for thread_id in host_proc.numeric_entries(tgid, "task").ok()? {
        let content = host_proc.read_to_string(thread_id, "syscall").ok()?;
        if let Some(path) = parse_open_syscall_path(host_proc, thread_id, &content) {
            return Some(path);
        }
    }
    None
}

fn syscall_open_path(host_proc: &HostProc, trace_pid: i32) -> Option<PathBuf> {
    if trace_pid <= 0 {
        return None;
    }
    if let Ok(content) = host_proc.read_to_string(trace_pid, "syscall")
        && let Some(path) = parse_open_syscall_path(host_proc, trace_pid, &content)
    {
        return Some(path);
    }
    let tgid = host_proc.thread_group_id(trace_pid)?;
    scan_threads_for_open_syscall_path(host_proc, tgid)
}

/// Best-effort path for a fanotify permission event: event fd first, then the
/// blocked tracee's open syscall args.
fn resolve_blocked_open_path(
    host_proc: &HostProc,
    trace_pid: i32,
    event_fd: &OwnedFd,
) -> Option<String> {
    resolve_event_path(host_proc, event_fd).ok().or_else(|| {
        syscall_open_path(host_proc, trace_pid).map(|path| path.to_string_lossy().into_owned())
    })
}

/// Convert an unresolved fanotify path into a fail-closed verdict.
fn path_resolution_verdict(path: Option<String>) -> Result<String, u32> {
    path.ok_or(FAN_DENY)
}

fn fdinfo_flags(host_proc: &HostProc, pid: i32, fd_name: &str) -> io::Result<i32> {
    let content = host_proc.read_to_string(pid, &format!("fdinfo/{fd_name}"))?;
    let flags = content
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing fdinfo flags"))?
        .trim();
    i32::from_str_radix(flags, 8).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Read bytes from a tracee's address space via `process_vm_readv`, falling
/// back to `/proc/<pid>/mem` when the syscall is unavailable.
fn read_tracee_bytes(host_proc: &HostProc, pid: i32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0_u8; len];
    if let Some(n) =
        agent_sandbox_sysutil::process_vm_readv_into(pid.cast_unsigned(), addr, &mut buf)
    {
        buf.truncate(n);
        return Ok(buf);
    }
    host_proc.read_memory(pid, addr, &mut buf)?;
    Ok(buf)
}

/// Parse one hex argument from `/proc/<pid>/syscall` (`proc_pid_syscall(5)`).
fn parse_proc_syscall_arg(word: &str) -> Option<u64> {
    let word = word.trim();
    let hex = word.strip_prefix("0x").unwrap_or(word);
    u64::from_str_radix(hex, 16).ok()
}

/// `open(2)` / `openat(2)` pass flags as a signed `int`; the proc file
/// exposes the full register as an unsigned hex word.
fn open_flags_from_proc_arg(word: &str) -> Option<i32> {
    let raw = parse_proc_syscall_arg(word)?;
    i32::try_from(raw)
        .ok()
        .or_else(|| i32::try_from(raw & 0xffff_ffff).ok())
}

/// First eight bytes of `struct open_how` (`openat2(2)`): `__u64 flags`.
fn open_how_flags_from_bytes(bytes: &[u8]) -> Option<i32> {
    let raw = u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?);
    i32::try_from(raw)
        .ok()
        .or_else(|| i32::try_from(raw & 0xffff_ffff).ok())
}

/// `openat2` syscall arg2 (0-based) points at `struct open_how { flags, mode, resolve }`.
fn read_tracee_open_how_flags(host_proc: &HostProc, pid: i32, how_ptr: u64) -> Option<i32> {
    if how_ptr == 0 {
        return None;
    }
    let bytes = read_tracee_bytes(host_proc, pid, how_ptr, 24).ok()?;
    open_how_flags_from_bytes(&bytes)
}

/// Parse a blocked open-family syscall from `/proc/<tid>/syscall`.
///
/// Layout per `proc_pid_syscall(5)`: `nr arg0 arg1 … arg5 sp pc`, where each
/// `argN` is the corresponding syscall argument register in ABI order
/// (`openat(2)`: arg0 `dirfd`, arg1 `pathname`, arg2 `flags`, arg3 `mode`;
/// `openat2(2)`: arg2 `struct open_how *`; `open(2)`: arg1 `flags`).
///
/// Syscall numbers come from `libc::SYS_*` (per-arch). Kept in sync with
/// `syscall-broker` `read_tracee_open_flags_mode`.
fn parse_open_syscall_access(
    host_proc: &HostProc,
    trace_pid: i32,
    content: &str,
) -> Option<FileAccess> {
    let content = content.trim();
    if content == "running" {
        return None;
    }

    let mut parts = content.split_whitespace();
    let nr: i64 = parts.next()?.parse().ok()?;
    if nr <= 0 {
        // `0` = idle, `-1` = blocked but not in a syscall (`proc_pid_syscall(5)`).
        return None;
    }
    let args: Vec<&str> = parts.collect();
    match nr {
        // open(const char *pathname, int flags, mode_t mode)
        n if n == libc::SYS_open => Some(open_flags_to_file_access(open_flags_from_proc_arg(
            args.get(1)?,
        )?)),
        // openat(int dirfd, const char *pathname, int flags, mode_t mode)
        n if n == libc::SYS_openat => Some(open_flags_to_file_access(open_flags_from_proc_arg(
            args.get(2)?,
        )?)),
        // openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
        n if n == libc::SYS_openat2 => {
            let how_ptr = parse_proc_syscall_arg(args.get(2)?)?;
            let flags = read_tracee_open_how_flags(host_proc, trace_pid, how_ptr)?;
            Some(open_flags_to_file_access(flags))
        }
        // creat(const char *pathname, mode_t mode) — open(2) with O_WRONLY|O_CREAT|O_TRUNC
        n if n == libc::SYS_creat => Some(FileAccess::Write),
        _ => None,
    }
}

/// Scan every thread in `tgid` for a blocked open-family syscall.
fn scan_threads_for_open_syscall(host_proc: &HostProc, tgid: i32) -> Option<FileAccess> {
    for thread_id in host_proc.numeric_entries(tgid, "task").ok()? {
        let content = host_proc.read_to_string(thread_id, "syscall").ok()?;
        if let Some(access) = parse_open_syscall_access(host_proc, thread_id, &content) {
            return Some(access);
        }
    }
    None
}

/// Read the blocked tracee's open flags from `/proc/{pid}/syscall`.
///
/// During a `FAN_OPEN_PERM` event the open is blocked: the tracee's fd
/// does not exist yet, and the fanotify event fd is always `O_RDONLY`.
/// The only reliable way to learn the real access mode is to read the
/// syscall arguments from `/proc/{pid}/syscall`, which the kernel
/// exposes while the task is blocked inside the syscall.
///
/// Fanotify normally reports the process id. On multi-threaded programs the
/// blocked `open` runs on a worker thread, so `/proc/<tgid>/syscall` shows
/// `0` (not in a syscall) while `/proc/<tid>/syscall` has the real flags.
/// With `FAN_REPORT_TID`, `trace_pid` is already the opener's tid; otherwise
/// we scan `/proc/<tgid>/task/*/syscall`.
fn syscall_open_access(host_proc: &HostProc, trace_pid: i32) -> Option<FileAccess> {
    if trace_pid <= 0 {
        return None;
    }
    if let Ok(content) = host_proc.read_to_string(trace_pid, "syscall")
        && let Some(access) = parse_open_syscall_access(host_proc, trace_pid, &content)
    {
        return Some(access);
    }
    let tgid = host_proc.thread_group_id(trace_pid)?;
    scan_threads_for_open_syscall(host_proc, tgid)
}

fn process_fd_access(host_proc: &HostProc, pid: i32, event_fd: &impl AsFd) -> Option<FileAccess> {
    if pid <= 0 {
        return None;
    }
    let event_meta = fstat(event_fd).ok()?;
    let mut access = None;
    for fd in host_proc.numeric_entries(pid, "fd").ok()? {
        let fd_name = fd.to_string();
        let Ok(meta) = host_proc.metadata(pid, &format!("fd/{fd_name}")) else {
            continue;
        };
        if meta.st_dev != event_meta.st_dev || meta.st_ino != event_meta.st_ino {
            continue;
        }
        let Ok(flags) = fdinfo_flags(host_proc, pid, &fd_name) else {
            continue;
        };
        let fd_access = open_flags_to_file_access(flags);
        access = Some(access.map_or(fd_access, |current: FileAccess| {
            current.combine_observed(fd_access)
        }));
        if access == Some(FileAccess::ReadWrite) {
            return access;
        }
    }
    access
}

fn event_fd_has_type(event_fd: &impl AsFd, file_type: SFlag) -> bool {
    fstat(event_fd).is_ok_and(|meta| SFlag::from_bits_truncate(meta.st_mode).contains(file_type))
}

fn event_fd_is_regular_file(event_fd: &impl AsFd) -> bool {
    event_fd_has_type(event_fd, SFlag::S_IFREG)
}

/// Translate a fanotify event mask to the corresponding `FileAccess`.
fn mask_to_access(host_proc: &HostProc, mask: u64, event_fd: &impl AsFd, pid: i32) -> FileAccess {
    if mask & FAN_PRE_ACCESS != 0 {
        return process_fd_access(host_proc, pid, event_fd).unwrap_or(FileAccess::ReadWrite);
    }
    // ACCESS means read/opendir; must win over EXEC traverse on combined masks.
    if mask & FAN_ACCESS_PERM != 0 {
        return FileAccess::Read;
    }
    if mask & FAN_OPEN_EXEC_PERM != 0 {
        // Directories are never executed as programs; classifying them as
        // Execute would miss read_write allow rules (e.g. global `./.git*`).
        if event_fd_has_type(event_fd, SFlag::S_IFDIR) {
            return FileAccess::Read;
        }
        return FileAccess::Execute;
    }
    if mask & FAN_OPEN_PERM != 0 {
        // The fanotify event fd is always opened O_RDONLY, so fdinfo on
        // it always yields Read regardless of the tracee's intent. The
        // tracee's own fd does not exist yet (the open is blocked).
        // Read the blocked syscall args from /proc/{pid}/syscall to get
        // the real open flags.
        return syscall_open_access(host_proc, pid).unwrap_or_else(|| {
            tracing::warn!(
                pid,
                mask = format_args!("{mask:#x}"),
                "open syscall flags unavailable, defaulting to read_write"
            );
            FileAccess::ReadWrite
        });
    }
    FileAccess::All
}

struct MountpointMarks {
    saw_pre_access_mark: bool,
    home_covered: bool,
}

/// Mark each mount point, skipping synthetic filesystem types.
/// Returns a [`MountpointMarks`] struct indicating whether a pre-access mark was seen
/// and whether the home directory is covered.
fn mark_mountpoints(
    fan_fd: impl std::os::fd::AsFd,
    mounts: &[MountRecord],
    home_covering_mount: Option<&Path>,
    cli_home: Option<&Path>,
) -> MountpointMarks {
    let mut saw_pre_access_mark = false;
    let mut home_covered = false;

    for mount in mounts {
        if home_covering_mount == Some(mount.mount_point.as_path())
            && is_synthetic_fs(&mount.fstype)
        {
            eprintln!(
                "agent-sandbox-fsmon: --home {} is on unsupported synthetic filesystem {} at {}; \
                 cannot guarantee filesystem monitoring",
                cli_home.map_or_else(|| "?".into(), |h| h.to_string_lossy().into_owned()),
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
        match fanotify_mark(&fan_fd, &mp_cstr, true) {
            Ok(actual_mask) => {
                saw_pre_access_mark |= actual_mask & FAN_PRE_ACCESS != 0;
                if home_covering_mount == Some(mount.mount_point.as_path()) {
                    home_covered = true;
                }
                tracing::debug!(path = %mount.mount_point.display(), mask = %format_args!("{actual_mask:x}"), "marked mountpoint");
            }
            Err(e) => {
                if home_covering_mount == Some(mount.mount_point.as_path())
                    || cli_home.is_some_and(|home| is_under_home(&mount.mount_point, home))
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
    MountpointMarks {
        saw_pre_access_mark,
        home_covered,
    }
}

/// Returns true when `child` is `ancestor` or a descendant of `ancestor`.
fn is_descendant_of(host_proc: &HostProc, child: i32, ancestor: i32) -> bool {
    if child <= 0 || ancestor <= 0 {
        return false;
    }
    let mut pid = child;
    for _ in 0..256 {
        if pid == ancestor {
            return true;
        }
        if pid <= 1 {
            return false;
        }
        let Some(parent) = parent_pid(host_proc, pid) else {
            return false;
        };
        pid = parent;
    }
    false
}

fn parent_pid(host_proc: &HostProc, pid: i32) -> Option<i32> {
    let stat = host_proc.read_to_string(pid, "stat").ok()?;
    let end = stat.rfind(')')?;
    let after = stat[end + 1..].trim_start();
    let mut fields = after.split_whitespace();
    fields.next()?; // state
    fields.next()?.parse().ok()
}

/// Event loop: read fanotify events and forward to policyd for allow/deny verdicts.
fn run_event_loop(
    fan_fd: &std::os::fd::OwnedFd,
    self_pid: i32,
    target_pid: i32,
    saw_pre_access_mark: bool,
    host_proc: &HostProc,
    ctx: &agent_sandbox_core::RequestContext,
    socket_path: &Path,
) -> ! {
    use std::os::fd::AsFd;
    let mut buf = vec![0u8; 4096];
    let mut rpc = match rpc_client::PersistentClient::connect(socket_path) {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "initial policyd connection failed; will retry on demand");
            rpc_client::PersistentClient::new(socket_path)
        }
    };

    loop {
        let n = match nix::unistd::read(fan_fd.as_fd(), &mut buf) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("agent-sandbox-fsmon: read from fanotify fd: {e}");
                continue;
            }
        };
        let mut offset = 0;
        while offset + size_of::<FanotifyEventMetadata>() <= n {
            let Some(meta) = agent_sandbox_sysutil::fanotify_event(&buf[offset..n]) else {
                break;
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
                let event_fd = take_fanotify_event_fd(meta.fd).expect("event fd");
                if try_fast_path_allow(
                    fan_fd,
                    &meta,
                    &event_fd,
                    self_pid,
                    target_pid,
                    saw_pre_access_mark,
                    host_proc,
                ) {
                    offset += event_len;
                    continue;
                }
                let path = match path_resolution_verdict(resolve_blocked_open_path(
                    host_proc, meta.pid, &event_fd,
                )) {
                    Ok(path) => path,
                    Err(verdict) => {
                        tracing::warn!(
                            pid = meta.pid,
                            "path resolution failed, denying (fail-closed)"
                        );
                        respond(fan_fd, &event_fd, verdict);
                        offset += event_len;
                        continue;
                    }
                };
                let access = normalize_directory_traverse_access(
                    Path::new(&path),
                    mask_to_access(host_proc, meta.mask, &event_fd, meta.pid),
                );
                tracing::info!(%path, ?access, pid = meta.pid, "filesystem check");

                let mut event_ctx = ctx.clone();
                event_ctx.pid = u32::try_from(meta.pid).ok();
                let reply = rpc.check_filesystem(Path::new(&path), access, event_ctx);

                let verdict = match &reply {
                    Ok(r) if r.allowed => FAN_ALLOW,
                    _ => FAN_DENY,
                };

                if verdict == FAN_DENY {
                    tracing::info!(%path, ?access, "denied by policy");
                }

                respond(fan_fd, &event_fd, verdict);
            } else if meta.fd >= 0 {
                let _ = take_fanotify_event_fd(meta.fd);
            }

            offset += event_len;
        }
    }
}

/// Join the mount namespace of `target_pid`, refusing when it is our own.
fn join_target_mount_namespace(target_pid: u32) {
    let ns_path = format!("/proc/{target_pid}/ns/mnt");
    // Defense in depth: never mark our own (host) mount namespace. A wrong
    // --pid (e.g. a namespace-local pid like 1 resolving to systemd) would
    // otherwise put FAN_OPEN_PERM marks on every host mount and gate every
    // file access on the machine through policyd.
    match (fs::metadata("/proc/self/ns/mnt"), fs::metadata(&ns_path)) {
        (Ok(self_ns), Ok(target_ns))
            if self_ns.dev() == target_ns.dev() && self_ns.ino() == target_ns.ino() =>
        {
            eprintln!(
                "agent-sandbox-fsmon: refusing to monitor pid {target_pid}: it shares this \
                 process's own mount namespace (would mark every host mount)"
            );
            process::exit(1);
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("agent-sandbox-fsmon: cannot compare mount namespaces ({ns_path}): {e}");
            process::exit(1);
        }
        _ => {}
    }
    if let Err(e) = agent_sandbox_sysutil::join_mount_namespace(target_pid) {
        eprintln!("agent-sandbox-fsmon: setns {ns_path}: {e}");
        process::exit(1);
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let self_pid = i32::try_from(process::id()).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-fsmon: process id does not fit in pid_t");
        process::exit(1);
    });

    // Open fanotify fd.
    let (fan_fd, fanotify_reports_tid) = fanotify_init_pre_content().unwrap_or_else(|e| {
        eprintln!("agent-sandbox-fsmon: fanotify_init failed: {e}");
        process::exit(1);
    });
    if fanotify_reports_tid {
        tracing::debug!("fanotify reports opener thread ids (FAN_REPORT_TID)");
    }

    // Open host procfs before setns. After joining the sandbox mount namespace,
    // `/proc` no longer resolves tracee PIDs reported by fanotify.
    let host_proc = HostProc::open().unwrap_or_else(|e| {
        eprintln!("agent-sandbox-fsmon: open host /proc: {e}");
        process::exit(1);
    });

    // Read mountinfo through the host procfs before entering the target namespace.
    let mounts = parse_mountinfo_for_pid(&host_proc, cli.pid).unwrap_or_else(|e| {
        eprintln!("agent-sandbox-fsmon: failed to parse target mountinfo: {e}");
        process::exit(1);
    });

    // setns into the target mount namespace before marking its mounts.
    join_target_mount_namespace(cli.pid);
    let home_covering_mount = cli
        .home
        .as_deref()
        .and_then(|home| deepest_covering_mount(&mounts, home))
        .map(Path::to_path_buf);

    let MountpointMarks {
        saw_pre_access_mark,
        home_covered,
    } = mark_mountpoints(
        &fan_fd,
        &mounts,
        home_covering_mount.as_deref(),
        cli.home.as_deref(),
    );

    // Before signaling ready, require that at least one marked mount covers --home.
    if let Some(ref home) = cli.home
        && !home_covered
    {
        eprintln!(
            "agent-sandbox-fsmon: no successfully marked mount covers --home {}; \
             cannot guarantee filesystem monitoring",
            home.display()
        );
        process::exit(1);
    }

    // Signal readiness.
    println!("ready");
    let _ = io::stdout().flush();

    // Build the request context for RPC checks.
    let ctx = agent_sandbox_core::RequestContext {
        cwd: cli.cwd,
        home: cli.home,
        project_root: cli.project_root,
        pid: None,
        uid: None,
        sandbox_session_id: std::env::var("AGENT_SANDBOX_SESSION_ID").ok(),
    };

    let socket_path = cli.socket.as_path();

    let target_pid = i32::try_from(cli.pid).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-fsmon: --pid does not fit in pid_t");
        process::exit(1);
    });
    run_event_loop(
        &fan_fd,
        self_pid,
        target_pid,
        saw_pre_access_mark,
        &host_proc,
        &ctx,
        socket_path,
    );
}

/// Fast-path allow checks that do not need a policyd RPC.
/// Returns `true` when the event was already handled.
fn try_fast_path_allow(
    fan_fd: &OwnedFd,
    meta: &FanotifyEventMetadata,
    event_fd: &OwnedFd,
    self_pid: i32,
    target_pid: i32,
    saw_pre_access_mark: bool,
    host_proc: &HostProc,
) -> bool {
    if meta.pid == self_pid {
        respond(fan_fd, event_fd, FAN_ALLOW);
        return true;
    }
    let process_pid = host_proc.thread_group_id(meta.pid).unwrap_or(meta.pid);
    if !is_descendant_of(host_proc, process_pid, target_pid) {
        respond(fan_fd, event_fd, FAN_ALLOW);
        return true;
    }
    if saw_pre_access_mark && meta.mask & FAN_ACCESS_PERM != 0 && event_fd_is_regular_file(event_fd)
    {
        respond(fan_fd, event_fd, FAN_ALLOW);
        return true;
    }
    if meta.mask & FAN_PRE_ACCESS != 0 {
        respond(fan_fd, event_fd, FAN_ALLOW);
        return true;
    }
    false
}

/// Write a `FAN_ALLOW` or `FAN_DENY` response and close the event fd.
fn respond(fan_fd: impl AsFd, event_fd: &OwnedFd, response: u32) {
    let resp = FanotifyResponse {
        fd: event_fd.as_raw_fd(),
        response,
    };
    let resp_bytes = fanotify_response_bytes(&resp);
    let _ = nix::unistd::write(fan_fd.as_fd(), resp_bytes);
    // event_fd dropped here, closing the fd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn test_host_proc() -> HostProc {
        HostProc::open().expect("open host proc")
    }

    fn test_event_file() -> File {
        File::open("/dev/null").expect("open event fixture")
    }

    #[test]
    fn host_proc_fd_relative_access_resolves_tracee_status() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        assert!(host_proc.read_to_string(pid, "status").is_ok());
    }

    #[test]
    fn parse_openat_syscall_flags_rdonly() {
        let host_proc = test_host_proc();
        let flags = libc::O_RDONLY | libc::O_CLOEXEC;
        let content = format!(
            "{} 0xffffffffffffff9c 0x7fff00001000 0x{flags:x} 0",
            libc::SYS_openat
        );
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, &content),
            Some(FileAccess::Read)
        );
    }

    #[test]
    fn parse_open_syscall_flags_rdonly() {
        let host_proc = test_host_proc();
        let flags = libc::O_RDONLY | libc::O_CLOEXEC;
        let content = format!("{} 0x7fff00002000 0x{flags:x} 0", libc::SYS_open);
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, &content),
            Some(FileAccess::Read)
        );
    }

    #[test]
    fn parse_openat_syscall_flags_wronly() {
        let host_proc = test_host_proc();
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC;
        let content = format!(
            "{} 0xffffffffffffff9c 0x7fff00003000 0x{flags:x} 0x1a4",
            libc::SYS_openat
        );
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, &content),
            Some(FileAccess::Write)
        );
    }
    #[test]
    fn parse_openat_syscall_flags_rdonly_with_creat_is_write_semantics() {
        let host_proc = test_host_proc();
        let flags = libc::O_RDONLY | libc::O_CREAT | libc::O_CLOEXEC;
        let content = format!(
            "{} 0xffffffffffffff9c 0x7fff00003100 0x{flags:x} 0x1a4",
            libc::SYS_openat
        );
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, &content),
            Some(FileAccess::ReadWrite)
        );
    }

    #[test]
    fn parse_openat_syscall_flags_rdonly_with_trunc_is_write_semantics() {
        let host_proc = test_host_proc();
        let flags = libc::O_RDONLY | libc::O_TRUNC | libc::O_CLOEXEC;
        let content = format!(
            "{} 0xffffffffffffff9c 0x7fff00003200 0x{flags:x} 0x1a4",
            libc::SYS_openat
        );
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, &content),
            Some(FileAccess::ReadWrite)
        );
    }

    #[test]
    fn parse_creat_syscall_is_write() {
        let host_proc = test_host_proc();
        let content = format!("{} 0x7fff00004000 0x1a4", libc::SYS_creat);
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, &content),
            Some(FileAccess::Write)
        );
    }

    #[test]
    fn parse_openat2_syscall_arg_indices() {
        // openat2(dirfd, path, how*, size) — how pointer is arg2 in proc file.
        let flags = libc::O_RDONLY | libc::O_CLOEXEC;
        let mut how = [0_u8; 24];
        how[..8].copy_from_slice(&u64::from(flags.cast_unsigned()).to_ne_bytes());
        assert_eq!(
            open_how_flags_from_bytes(&how),
            Some(libc::O_RDONLY | libc::O_CLOEXEC)
        );
        let host_proc = test_host_proc();
        let content = format!(
            "{} 0xffffffffffffff9c 0x7fff00005000 0x0 0x18",
            libc::SYS_openat2
        );
        assert_eq!(parse_open_syscall_access(&host_proc, 1, &content), None);
    }

    #[test]
    fn parse_syscall_running_and_not_in_syscall() {
        let host_proc = test_host_proc();
        assert_eq!(parse_open_syscall_access(&host_proc, 1, "running"), None);
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, "-1 0 0 0 0 0 0"),
            None
        );
    }

    #[test]
    fn parse_syscall_nr_zero_is_not_open() {
        let host_proc = test_host_proc();
        assert_eq!(
            parse_open_syscall_access(&host_proc, 1, "0 0 0 0 0 0 0"),
            None
        );
    }

    #[test]
    fn thread_group_id_for_self() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        assert_eq!(host_proc.thread_group_id(pid), Some(pid));
    }

    #[test]
    fn mask_to_access_prefers_exec_and_read_events() {
        let host_proc = test_host_proc();
        let event_fd = test_event_file();
        assert_eq!(
            mask_to_access(
                &host_proc,
                FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM,
                &event_fd,
                -1,
            ),
            FileAccess::Read
        );
        assert_eq!(
            mask_to_access(&host_proc, FAN_OPEN_EXEC_PERM, &event_fd, -1),
            FileAccess::Execute
        );
        assert_eq!(
            mask_to_access(&host_proc, FAN_ACCESS_PERM, &event_fd, -1),
            FileAccess::Read
        );
        assert_eq!(
            mask_to_access(&host_proc, FAN_OPEN_PERM, &event_fd, -1),
            FileAccess::ReadWrite
        );
    }

    #[test]
    fn mask_to_access_access_perm_beats_open_perm() {
        let host_proc = test_host_proc();
        let event_fd = test_event_file();
        // Combined open events carry both masks. ACCESS means read/opendir;
        // do not let a failed OPEN syscall parse downgrade to read_write.
        assert_eq!(
            mask_to_access(&host_proc, FAN_OPEN_PERM | FAN_ACCESS_PERM, &event_fd, -1,),
            FileAccess::Read
        );
    }

    #[test]
    fn open_perm_without_pid_falls_back_to_read_write() {
        // Without a valid pid, syscall_open_access returns None.
        // The fallback is ReadWrite (conservative: may prompt but won't
        // misclassify a write as a read).
        let host_proc = test_host_proc();
        let path =
            std::env::temp_dir().join(format!("agent-sandbox-fsmon-test-{}", std::process::id()));
        {
            let mut file = File::create(&path).expect("create temp file");
            file.write_all(b"x").expect("write temp file");
        }

        let read_file = File::open(&path).expect("open read-only temp file");
        assert_eq!(
            mask_to_access(&host_proc, FAN_OPEN_PERM, &read_file, -1),
            FileAccess::ReadWrite
        );

        std::fs::remove_file(path).expect("remove temp file");
    }

    #[test]
    fn pre_access_without_fd_flags_stays_conservative() {
        let host_proc = test_host_proc();
        let event_fd = test_event_file();
        assert_eq!(
            mask_to_access(&host_proc, FAN_PRE_ACCESS, &event_fd, -1),
            FileAccess::ReadWrite
        );
    }

    #[test]
    fn process_fd_access_combines_read_and_write_descriptors_into_read_write() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        let path = std::env::temp_dir().join(format!(
            "agent-sandbox-fsmon-test-rw-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"x").expect("seed temp file");

        let access = {
            let read_file = File::open(&path).expect("open read-only temp file");
            let _write_file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open write-only temp file");
            process_fd_access(&host_proc, pid, &read_file)
        };

        assert_eq!(access, Some(FileAccess::ReadWrite));
        std::fs::remove_file(path).expect("remove temp file");
    }

    #[test]
    fn tmpfs_is_not_synthetic() {
        assert!(!is_synthetic_fs("tmpfs"));
    }

    #[test]
    fn proc_and_sysfs_remain_synthetic() {
        assert!(is_synthetic_fs("proc"));
        assert!(is_synthetic_fs("sysfs"));
        assert!(is_synthetic_fs("cgroup2"));
    }

    #[test]
    fn open_how_flags_classify_rdwr_as_read_write() {
        let flags = libc::O_RDWR;
        let mut how = [0_u8; 8];
        how.copy_from_slice(&u64::from(flags.cast_unsigned()).to_ne_bytes());
        assert_eq!(
            open_how_flags_from_bytes(&how).map(open_flags_to_file_access),
            Some(FileAccess::ReadWrite)
        );
    }

    #[test]
    fn path_resolution_failure_is_fail_closed() {
        let host_proc = test_host_proc();
        assert!(host_proc.read_self_fd_link(-1).is_err());
        assert_eq!(path_resolution_verdict(None), Err(FAN_DENY));
    }

    #[test]
    fn parent_pid_reads_ppid_from_proc_stat() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        let parent = parent_pid(&host_proc, pid).expect("parent pid");
        assert!(parent > 0);
        assert_ne!(parent, pid);
    }

    #[test]
    fn is_descendant_of_current_process() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        assert!(is_descendant_of(&host_proc, pid, pid));
    }
}
