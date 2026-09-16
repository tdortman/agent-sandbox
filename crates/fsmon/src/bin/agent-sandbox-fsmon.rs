//! Root fanotify monitor: setns into the sandbox mount namespace,
//! mark each mountpoint, then event-loop handling permission events.

use std::{
    collections::{HashSet, VecDeque},
    ffi::CString,
    fs,
    fs::File,
    io,
    io::{Read, Write},
    mem::size_of,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use agent_sandbox_core::{
    EXPORTED_POLICY_PATH, FileAccess, ProcessIds, StaticPolicyAllow,
    normalize_directory_traverse_access, open_flags_to_file_access, wire_context,
};
use agent_sandbox_fsmon::MonitorClient;
use agent_sandbox_sysutil::{
    FanotifyEventMetadata, FanotifyResponse, fanotify_mark_ignore, fanotify_response_bytes,
    fanotify_unmark_ignore, take_fanotify_event_fd,
};

fn respond(fan_fd: &OwnedFd, event_fd: &OwnedFd, verdict: u32) {
    let response = FanotifyResponse {
        fd: event_fd.as_raw_fd(),
        response: verdict,
    };

    let bytes = fanotify_response_bytes(&response);

    if let Err(error) = nix::unistd::write(fan_fd, bytes) {
        tracing::warn!(%error, "failed to send fanotify response");
    }
}

use clap::Parser;
use nix::{
    fcntl::{OFlag, openat, readlinkat},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::stat::{Mode, SFlag, fstat},
};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-fsmon",
    version,
    about = "fanotify filesystem policy monitor that brokers open() calls to policyd",
    long_about = r#"fanotify-based filesystem monitor that runs in the host mount namespace.
Given a target sandbox PID, it joins the sandbox mount namespace, marks every mount that overlaps the sandbox's working directory/home/project, and processes permission events for open and exec requests.
Each event is forwarded to policyd over a Unix domain socket and the verdict (allow/deny) is written back to the kernel via the fanotify response fd.

Normally spawned by policyd in response to an "agent-sandbox-fs-arm" request, not invoked directly.

EXAMPLES:
# Start a monitor for sandbox PID 12345 with the default policyd socket.
agent-sandbox-fsmon --pid 12345

# Override context for tools that do not export the AGENT_SANDBOX_* env vars.
agent-sandbox-fsmon \
    --pid 12345 \
    --cwd /home/user/project \
    --home /home/user \
    --project-root /home/user/project"#
)]
struct Cli {
    /// PID of the sandbox arm helper. The monitor joins the mount namespace of
    /// this PID and marks its filesystems.
    #[arg(long, value_name = "PID")]
    pid: u32,

    /// Path to the policyd Unix domain socket. fsmon forwards every fanotify
    /// permission event here and waits for an allow/deny verdict.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    socket: PathBuf,

    /// Working directory inside the sandbox. Used to scope per-project policy
    /// and to pick which mounts are marked. Defaults to the env var
    /// `AGENT_SANDBOX_CWD` if unset.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_CWD")]
    cwd: Option<PathBuf>,

    /// Home directory inside the sandbox. Used to expand "~" in filesystem
    /// rules and to gate "global" scope. Defaults to the env var
    /// `AGENT_SANDBOX_HOME` if unset.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_HOME")]
    home: Option<PathBuf>,

    /// Project root directory inside the sandbox. Required for "project" scope
    /// approvals to land in the right per-project policy file. Defaults to the
    /// env var `AGENT_SANDBOX_PROJECT_ROOT` if unset.
    #[arg(long, value_name = "DIR", env = "AGENT_SANDBOX_PROJECT_ROOT")]
    project_root: Option<PathBuf>,

    /// Merged policy JSON exported by policyd at startup. Events matching its
    /// static filesystem allow rules are answered locally without a policyd
    /// round trip. The snapshot is loaded once; runtime policy changes (new
    /// approvals, session verdicts) keep flowing through policyd.
    #[arg(
        long,
        value_name = "PATH",
        default_value = EXPORTED_POLICY_PATH
    )]
    static_policy: PathBuf,

    #[arg(
        long,
        value_name = "BOOL",
        action = clap::ArgAction::Set,
        default_value = "true",
        value_parser = clap::value_parser!(bool)
    )]
    fs_ignore_static_allows: bool,
}

// fanotify constants and event structs come from `agent_sandbox_sysutil`.
use agent_sandbox_sysutil::{FAN_ALLOW, FAN_DENY, FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM};

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

/// Parse mountinfo text and return all mount entries with their fstype.
fn parse_mountinfo_content(content: &str) -> Vec<MountRecord> {
    let mut mounts = Vec::new();

    for line in content.lines() {
        // Format: id parent_id major:minor root mount_point options ... - fstype source
        // super_options
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

/// Return the deepest mount point that contains `target`.
fn deepest_covering_mount<'a>(mounts: &'a [MountRecord], target: &Path) -> Option<&'a Path> {
    mounts
        .iter()
        .filter(|mount| target.starts_with(&mount.mount_point))
        .max_by_key(|mount| mount.mount_point.as_os_str().len())
        .map(|mount| mount.mount_point.as_path())
}

fn resolve_event_path(host_proc: &HostProc, event_fd: &impl AsFd) -> io::Result<String> {
    let path = host_proc.read_self_fd_link(event_fd.as_fd().as_raw_fd())?;
    Ok(path.to_string_lossy().into_owned())
}

fn tracee_open_dir_base(host_proc: &HostProc, pid: i32, dirfd: i64) -> io::Result<PathBuf> {
    let leaf = if dirfd == i64::from(libc::AT_FDCWD) {
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
    agent_sandbox_sysutil::read_tracee_path_ptr_with(
        |addr, len| read_tracee_bytes(host_proc, pid, addr, len),
        path_ptr,
    )
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

/// Parse the pathname from a blocked open-family syscall in
/// `/proc/<tid>/syscall`.
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

/// Read the blocked tracee's open syscall args from `/proc/{pid}/syscall`.
///
/// During a `FAN_OPEN_PERM` event the open is blocked: the tracee's fd
/// does not exist yet, and the fanotify event fd is always `O_RDONLY`.
/// The only reliable way to learn the real access mode (or path) is to
/// read the syscall arguments from `/proc/{pid}/syscall`, which the kernel
/// exposes while the task is blocked inside the syscall.
///
/// `FAN_REPORT_TID` identifies the exact opener. The event may reach the
/// monitor before that thread sleeps, when procfs still reports `running`.
/// Wait briefly for its syscall snapshot; another thread's arguments cannot
/// establish this opener's access.
fn syscall_lookup<T>(
    host_proc: &HostProc,
    trace_pid: i32,
    parse: fn(&HostProc, i32, &str) -> Option<T>,
) -> Option<T> {
    if trace_pid <= 0 {
        return None;
    }

    let file = host_proc.open_entry(trace_pid, "syscall").ok()?;

    // The procfs record contains at most nine 64-bit numeric fields. Reject
    // incomplete records rather than classifying truncated arguments.
    let mut buffer = [0u8; 256];

    let mut deadline = None;

    loop {
        let length = file.read_at(&mut buffer, 0).ok()?;
        let content = std::str::from_utf8(&buffer[..length]).ok()?;

        if !content.ends_with('\n') {
            return None;
        }

        if content.trim() != "running" {
            return parse(host_proc, trace_pid, content);
        }

        let deadline = deadline.get_or_insert_with(|| {
            std::time::Instant::now() + std::time::Duration::from_millis(10)
        });

        if std::time::Instant::now() >= *deadline {
            return None;
        }

        std::thread::sleep(std::time::Duration::from_micros(50));
    }
}

/// Best-effort path for a fanotify permission event: event fd first, then the
/// blocked tracee's open syscall args.
fn resolve_blocked_open_path(
    host_proc: &HostProc,
    trace_pid: i32,
    event_fd: &OwnedFd,
) -> Option<String> {
    resolve_event_path(host_proc, event_fd).ok().or_else(|| {
        syscall_lookup(host_proc, trace_pid, parse_open_syscall_path)
            .map(|path| path.to_string_lossy().into_owned())
    })
}

/// Read bytes from a tracee's address space via `process_vm_readv`, falling
/// back to `/proc/<pid>/mem` when the syscall is unavailable.
fn read_tracee_bytes(host_proc: &HostProc, pid: i32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    agent_sandbox_sysutil::read_tracee_bytes_with(pid.cast_unsigned(), addr, len, |addr, buf| {
        host_proc.read_memory(pid, addr, buf)
    })
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
        .or_else(|| i32::try_from(raw & 0xFFFF_FFFF).ok())
}

/// First eight bytes of `struct open_how` (`openat2(2)`): `__u64 flags`.
fn open_how_flags_from_bytes(bytes: &[u8]) -> Option<i32> {
    let raw = u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?);

    i32::try_from(raw)
        .ok()
        .or_else(|| i32::try_from(raw & 0xFFFF_FFFF).ok())
}

/// `openat2` syscall arg2 (0-based) points at `struct open_how { flags, mode,
/// resolve }`.
fn read_tracee_open_how_flags(host_proc: &HostProc, pid: i32, how_ptr: u64) -> Option<i32> {
    if how_ptr == 0 {
        return None;
    }

    let bytes = read_tracee_bytes(host_proc, pid, how_ptr, 24).ok()?;
    open_how_flags_from_bytes(&bytes)
}

/// Classify a blocked syscall that generated an open permission event.
///
/// Layout per `proc_pid_syscall(5)`: `nr arg0 arg1 ... arg5 sp pc`, where each
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

    match nr {
        // open(const char *pathname, int flags, mode_t mode)
        n if n == libc::SYS_open => Some(open_flags_to_file_access(open_flags_from_proc_arg(
            parts.nth(1)?,
        )?)),

        // openat(int dirfd, const char *pathname, int flags, mode_t mode)
        n if n == libc::SYS_openat => Some(open_flags_to_file_access(open_flags_from_proc_arg(
            parts.nth(2)?,
        )?)),

        // openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
        n if n == libc::SYS_openat2 => {
            let how_ptr = parse_proc_syscall_arg(parts.nth(2)?)?;
            let flags = read_tracee_open_how_flags(host_proc, trace_pid, how_ptr)?;
            Some(open_flags_to_file_access(flags))
        }

        // creat(const char *pathname, mode_t mode) — open(2) with O_WRONLY|O_CREAT|O_TRUNC
        n if n == libc::SYS_creat => Some(FileAccess::Write),

        // do_open_execat opens executables and interpreters with __FMODE_EXEC.
        // fsnotify sends OPEN_EXEC_PERM and OPEN_PERM separately for that open;
        // both occur inside execve/execveat, which have no open-flags argument.
        n if n == libc::SYS_execve || n == libc::SYS_execveat => Some(FileAccess::Execute),

        _ => None,
    }
}

fn event_fd_has_type(event_fd: &impl AsFd, file_type: SFlag) -> bool {
    fstat(event_fd).is_ok_and(|meta| SFlag::from_bits_truncate(meta.st_mode).contains(file_type))
}

/// Translate a fanotify event mask to the corresponding `FileAccess`.
fn mask_to_access(host_proc: &HostProc, mask: u64, event_fd: &impl AsFd, pid: i32) -> FileAccess {
    if mask & FAN_OPEN_EXEC_PERM != 0 {
        // Execute would miss read_write allow rules (e.g. global `./.git`).
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
        return syscall_lookup(host_proc, pid, parse_open_syscall_access).unwrap_or_else(|| {
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

/// Whether the blocked open's access mode must be recovered from the tracee.
///
/// A static rule granting read-write (or all) access covers every access a
/// non-exec open can request, so the verdict is already known and
/// `/proc/<pid>/syscall` need not be read. Execute events and narrower grants
/// still need the real flags: a read-only grant must not admit a write.
fn open_needs_access_lookup(mask: u64, path: &str, static_allow: &StaticPolicyAllow) -> bool {
    if mask & FAN_OPEN_EXEC_PERM != 0 {
        return true;
    }

    !static_allow.allows_literal(Path::new(path), FileAccess::ReadWrite)
}

/// Whether an ignore mark is sound for `path` opened under `mask`.
///
/// An ignore mask suppresses every future open of the inode, so it is only
/// sound where no access the policy denies can actually succeed: the event
/// must be an open-permission event, the path must allow read statically, and
/// either nothing can write the inode (read-only mount or no write mode bits)
/// or write is statically allowed too.
fn ignore_mark_eligible(
    static_allow: &StaticPolicyAllow,
    mask: u64,
    path: &Path,
    mode_writable: bool,
    mount_readonly: bool,
) -> bool {
    if mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM) == 0 {
        return false;
    }

    if mask & !(FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM) != 0 {
        return false;
    }

    if !static_allow.allows(path, FileAccess::Read) {
        return false;
    }

    if static_allow.allows(path, FileAccess::ReadWrite) {
        return true;
    }

    if !mode_writable {
        return true;
    }

    mount_readonly
}

/// Install an ignore mark for a statically allowed open when the full
/// predicate holds. Best effort: a failed mark leaves the event path
/// unchanged, and the tracked set stops growing at `IGNORE_MARK_CAP`.
fn maybe_mark_static_allow(shared: &Shared, mask: u64, path: &str, event_fd: &OwnedFd) {
    if !shared.ignore_static_allows {
        return;
    }

    let fs_path = Path::new(path);
    // An unwritable mode is the common sound case (immutable store files);
    // assume writable when the inode cannot be statted so a failed check
    // never marks.
    let mode_writable = fstat(event_fd.as_fd()).is_ok_and(|stat| stat.st_mode & 0o222 != 0);
    let mount_readonly = nix::sys::statvfs::statvfs(fs_path)
        .is_ok_and(|fs| fs.flags().contains(nix::sys::statvfs::FsFlags::ST_RDONLY));

    if !ignore_mark_eligible(
        &shared.static_allow,
        mask,
        fs_path,
        mode_writable,
        mount_readonly,
    ) {
        return;
    }

    let Ok(cstr) = CString::new(path) else {
        return;
    };
    let (already_marked, at_capacity) = {
        let marked = shared
            .marked
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        (marked.contains(fs_path), marked.len() >= IGNORE_MARK_CAP)
    };

    if already_marked {
        return;
    }

    if at_capacity {
        if !shared.cap_warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                cap = IGNORE_MARK_CAP,
                "ignore-mark set full; no further paths will be marked",
            );
        }
        return;
    }

    match fanotify_mark_ignore(&shared.fan_fd, &cstr) {
        Ok(()) => {
            let tracked = {
                let mut marked = shared
                    .marked
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());

                // The set can fill between the check above and here, so the
                // bound is enforced where the insert happens as well.
                if marked.len() < IGNORE_MARK_CAP {
                    marked.insert(fs_path.to_path_buf())
                } else {
                    false
                }
            };

            if tracked {
                shared.stats.marks_added.fetch_add(1, Ordering::Relaxed);
            }
        }
        Err(error) => {
            tracing::debug!(%path, %error, "ignore mark failed; events for this path keep flowing");
        }
    }
}

/// Remove every tracked ignore mark. Entries leave the set whether or not
/// their unmark succeeds, so a failed unmark cannot wedge future flushes.
fn flush_ignore_marks(shared: &Shared) {
    let paths: Vec<PathBuf> = shared
        .marked
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .drain()
        .collect();
    let mut flushed = 0_u64;

    for path in &paths {
        flushed += 1;
        let Ok(cstr) = CString::new(path.as_os_str().as_bytes()) else {
            continue;
        };

        if let Err(error) = fanotify_unmark_ignore(&shared.fan_fd, &cstr) {
            tracing::warn!(path = %path.display(), %error, "failed to remove ignore mark");
        }
    }

    if flushed > 0 {
        shared
            .stats
            .marks_flushed
            .fetch_add(flushed, Ordering::Relaxed);
    }
}

/// Snapshot key for the static policy export: mtime plus length, so a rewrite
/// within mtime granularity still invalidates. `None` when unreadable.
fn policy_snapshot_key(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Mark each mount point, skipping synthetic filesystem types. Returns whether
/// a marked mount covers the home directory.
fn mark_mountpoints(
    fan_fd: impl std::os::fd::AsFd,
    mounts: &[MountRecord],
    home_covering_mount: Option<&Path>,
    cli_home: Option<&Path>,
) -> bool {
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

        match agent_sandbox_sysutil::fanotify_mark(&fan_fd, &mp_cstr) {
            Ok(()) => {
                if home_covering_mount == Some(mount.mount_point.as_path()) {
                    home_covered = true;
                }
                tracing::debug!(path = %mount.mount_point.display(), "marked mountpoint");
            }

            Err(e) => {
                if home_covering_mount == Some(mount.mount_point.as_path())
                    || cli_home.is_some_and(|home| mount.mount_point.starts_with(home))
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

    home_covered
}

/// Immutable cgroup identity captured from the sandbox root before `setns`.
///
/// A process remains in its cgroup after daemonisation/reparenting, while its
/// `PPid` ancestry can immediately point at an unrelated host process.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SandboxCgroup(String);

impl SandboxCgroup {
    fn read(host_proc: &HostProc, pid: i32) -> Option<Self> {
        let content = host_proc.read_to_string(pid, "cgroup").ok()?;

        let path = content.lines().find_map(|line| {
            let (hierarchy, path) = line.split_once("::")?;
            (hierarchy == "0" && !path.is_empty()).then(|| path.to_string())
        })?;

        Some(Self(path))
    }

    fn contains(&self, host_proc: &HostProc, pid: i32) -> Option<bool> {
        Some(Self::read(host_proc, pid)?.0 == self.0)
    }
}

/// Permission events answered at the same time, bounded because each worker is
/// an independent event consumer rather than a CPU thread.
///
/// Answering one permission event at a time serialised parallel filesystem
/// work: every sandboxed process waited for the single event being handled,
/// so concurrent read-only opens ran at the monitor's service rate instead of
/// the filesystem's. Each worker instead owns a policy client and runtime and
/// blocks on the shared queue, so independent opens are mediated
/// concurrently. The bound avoids wakeup contention: workers beyond the event
/// rate only add condvar wakeups.
const WORKER_LIMIT: usize = 4;

/// Jobs waiting for a worker, bounded so a burst of permission events cannot
/// grow memory without limit: the reader blocks when the queue is full
/// (backpressure).
const QUEUE_LIMIT: usize = 256;

/// One fanotify permission event handed from the reader to a worker.
///
/// Carries only parsed fields plus the event fd, never a borrow of the read
/// buffer, so the reader reuses its buffer while workers run.
struct Job {
    mask: u64,
    pid: i32,
    event_fd: OwnedFd,
}

/// Shared state every fsmon worker reads, plus the ignore-mark set.
///
/// `marked` is the only lock-guarded member: workers insert after installing
/// an ignore mark, and the reader drains it on policy change and shutdown. The
/// lock is only taken on statically allowed opens, never on the policyd path;
/// the counters use lock-free atomics.
struct Shared {
    fan_fd: OwnedFd,
    self_pid: i32,
    sandbox_cgroup: SandboxCgroup,
    host_proc: HostProc,
    ctx: agent_sandbox_core::RequestContext,
    socket_path: PathBuf,
    static_allow: StaticPolicyAllow,
    ignore_static_allows: bool,
    static_policy_path: PathBuf,
    marked: Mutex<HashSet<PathBuf>>,
    cap_warned: AtomicBool,
    stats: FsmonStats,
}

/// Maximum tracked ignore-marked paths. Marking stops (with one warning)
/// instead of growing without bound.
const IGNORE_MARK_CAP: usize = 65536;

/// How often the reader re-stats the static policy export for changes.
const POLICY_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// How often the reader logs the decision counters.
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// How long the reader waits for a fanotify event before running its periodic
/// work. Bounds how long an idle sandbox takes to observe a shutdown request or
/// a static-policy change.
const READ_POLL_MILLIS: u16 = 1000;

/// Set by the terminate handler; the reader loop flushes ignore marks, logs
/// the final counters, and exits on its next iteration.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Decision counters. Relaxed atomics: workers bump them on the hot path
/// while the reader samples them for the periodic log line, with no locking.
#[derive(Debug, Default)]
struct FsmonStats {
    /// Permission events handled.
    events: AtomicU64,
    /// Answers that needed no policyd call (fast path and static allows).
    local_answers: AtomicU64,
    /// Answers that called policyd.
    policyd_calls: AtomicU64,
    /// Ignore marks installed.
    marks_added: AtomicU64,
    /// Tracked paths released by a flush.
    marks_flushed: AtomicU64,
}

/// Log the decision counters as one structured line.
fn log_stats(stats: &FsmonStats, reason: &str) {
    tracing::info!(
        events = stats.events.load(Ordering::Relaxed),
        local_answers = stats.local_answers.load(Ordering::Relaxed),
        policyd_calls = stats.policyd_calls.load(Ordering::Relaxed),
        marks_added = stats.marks_added.load(Ordering::Relaxed),
        marks_flushed = stats.marks_flushed.load(Ordering::Relaxed),
        reason,
        "fsmon decisions",
    );
}

/// Bounded hand-off from the reader to the workers: the reader blocks when
/// full, workers block on the condvar when empty.
type JobQueue = Arc<(Mutex<VecDeque<Job>>, Condvar)>;

/// Event loop: read fanotify events and forward to policyd for allow/deny
/// verdicts.
///
/// The reader only reads batches, parses the event framing, and enqueues
/// permission events; a dedicated pool of `WORKER_LIMIT` workers (the reader
/// does not double as a worker) answers them. On the same cadence it polls
/// the static policy export for changes (flushing ignore marks when it
/// changed) and logs the decision counters. A terminate request makes the
/// reader flush the marks, log the final counters, and return.
fn run_event_loop(
    fan_fd: std::os::fd::OwnedFd,
    self_pid: i32,
    sandbox_cgroup: SandboxCgroup,
    host_proc: HostProc,
    ctx: agent_sandbox_core::RequestContext,
    socket_path: &Path,
    static_allow: StaticPolicyAllow,
    ignore_static_allows: bool,
    static_policy_path: PathBuf,
) {
    use std::os::fd::AsFd;

    let shared = Arc::new(Shared {
        fan_fd,
        self_pid,
        sandbox_cgroup,
        host_proc,
        ctx,
        socket_path: socket_path.to_path_buf(),
        static_allow,
        ignore_static_allows,
        static_policy_path,
        marked: Mutex::new(HashSet::new()),
        cap_warned: AtomicBool::new(false),
        stats: FsmonStats::default(),
    });
    let queue: JobQueue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));

    for _ in 0..std::thread::available_parallelism()
        .map_or(1, |parallelism| parallelism.get().min(WORKER_LIMIT))
        .max(1)
    {
        let shared = Arc::clone(&shared);
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || worker(&shared, &queue));
    }

    let mut buf = vec![0u8; 4096];
    let mut batch = Vec::new();
    let mut last_policy_check = Instant::now();
    let mut last_policy_key = policy_snapshot_key(&shared.static_policy_path);
    let mut last_stats_log = Instant::now();

    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            tracing::info!("shutdown requested; flushing ignore marks");
            flush_ignore_marks(&shared);
            log_stats(&shared.stats, "shutdown");
            return;
        }

        // Poll rather than block in `read`: the terminate handler only sets a
        // flag, and the kernel restarts an interrupted read, so an idle sandbox
        // would never observe the request or reach its periodic work.
        match poll(
            &mut [PollFd::new(
                shared.fan_fd.as_fd(),
                PollFlags::POLLIN,
            )],
            PollTimeout::from(READ_POLL_MILLIS),
        ) {
            Ok(0) => {
                run_periodic_work(
                    &shared,
                    &mut last_policy_check,
                    &mut last_policy_key,
                    &mut last_stats_log,
                );
                continue;
            }
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => {
                eprintln!("agent-sandbox-fsmon: poll fanotify fd: {error}");
                continue;
            }
        }

        let n = match nix::unistd::read(shared.fan_fd.as_fd(), &mut buf) {
            Ok(n) => n,
            Err(error) => {
                eprintln!("agent-sandbox-fsmon: read from fanotify fd: {error}");
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

            if meta.fd >= 0 && meta.mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM) != 0 {
                let event_fd = take_fanotify_event_fd(meta.fd).expect("event fd");
                batch.push(Job {
                    mask: meta.mask,
                    pid: meta.pid,
                    event_fd,
                });
            } else if meta.fd >= 0 {
                let _ = take_fanotify_event_fd(meta.fd);
            }

            offset += event_len;
        }

        if !batch.is_empty() {
            enqueue(&queue, &mut batch);
        }

        run_periodic_work(
            &shared,
            &mut last_policy_check,
            &mut last_policy_key,
            &mut last_stats_log,
        );
    }
}

/// Work that must happen even when no event arrives: retire ignore marks after
/// the static policy changed, and log the decision counters.
fn run_periodic_work(
    shared: &Shared,
    last_policy_check: &mut Instant,
    last_policy_key: &mut Option<(SystemTime, u64)>,
    last_stats_log: &mut Instant,
) {
    if last_policy_check.elapsed() >= POLICY_POLL_INTERVAL {
        *last_policy_check = Instant::now();
        let key = policy_snapshot_key(&shared.static_policy_path);
        if key != *last_policy_key {
            *last_policy_key = key;
            tracing::info!(
                path = %shared.static_policy_path.display(),
                "static policy changed; flushing ignore marks",
            );
            flush_ignore_marks(shared);
        }
    }

    if last_stats_log.elapsed() >= STATS_LOG_INTERVAL {
        *last_stats_log = Instant::now();
        log_stats(&shared.stats, "interval");
    }
}

/// Serve queued permission events until killed, with worker-local RPC state.
///
/// Each worker owns its policy client, tokio runtime, and pid cgroup cache;
/// only the [`Shared`] state and the queue are shared.
fn worker(shared: &Shared, queue: &JobQueue) -> ! {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let mut rpc = MonitorClient::new(shared.socket_path.clone());
    let mut pid_cgroup_cache = HashSet::new();

    loop {
        let job = dequeue(queue);
        handle_permission_event(shared, job, &mut rpc, &runtime, &mut pid_cgroup_cache);
    }
}

/// Enqueue a read batch with one lock acquisition, blocking while the queue is
/// full (backpressure: no unbounded growth, no busy spin).
///
/// One lock and one wakeup per batch instead of per event: the reader is the
/// only producer, and a per-event hand-off made it the next serialisation
/// point after the workers took over the verdict work.
fn enqueue(queue: &JobQueue, batch: &mut Vec<Job>) {
    let incoming = std::mem::take(batch);
    let mut jobs = queue.0.lock().unwrap_or_else(|poison| poison.into_inner());
    while jobs.len() + incoming.len() > QUEUE_LIMIT {
        jobs = queue
            .1
            .wait(jobs)
            .unwrap_or_else(|poison| poison.into_inner());
    }
    jobs.extend(incoming);
    drop(jobs);
    queue.1.notify_all();
}
/// Dequeue a job, blocking on the condvar while the queue is empty. The
/// `while` loop guards against spurious wakeups; every push is followed by a
/// notify under the same lock, so no wakeup is lost.
fn dequeue(queue: &JobQueue) -> Job {
    let mut jobs = queue.0.lock().unwrap_or_else(|poison| poison.into_inner());
    while jobs.is_empty() {
        jobs = queue
            .1
            .wait(jobs)
            .unwrap_or_else(|poison| poison.into_inner());
    }
    let job = jobs.pop_front().expect("queued job");
    drop(jobs);
    // Wake a reader blocked on a full queue; a no-op when nobody waits.
    queue.1.notify_one();
    job
}

/// Answer one queued permission event, counting the decision and installing an
/// ignore mark for statically allowed opens. Every path responds exactly once;
/// unresolvable paths fail closed (`FAN_DENY`) with the same log messages as
/// before.
fn handle_permission_event(
    shared: &Shared,
    job: Job,
    rpc: &mut MonitorClient,
    runtime: &tokio::runtime::Runtime,
    pid_cgroup_cache: &mut HashSet<i32>,
) {
    let Job {
        mask,
        pid,
        event_fd,
    } = job;

    shared.stats.events.fetch_add(1, Ordering::Relaxed);

    // The fast path answers from process identity (self pid, non-sandbox
    // cgroup), not from static policy, so no ignore mark applies here.
    if try_fast_path_allow(
        &shared.fan_fd,
        pid,
        &event_fd,
        shared.self_pid,
        &shared.sandbox_cgroup,
        &shared.host_proc,
        pid_cgroup_cache,
    ) {
        shared.stats.local_answers.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let path = match resolve_blocked_open_path(&shared.host_proc, pid, &event_fd).ok_or(FAN_DENY) {
        Ok(path) => path,
        Err(verdict) => {
            tracing::warn!(pid, "path resolution failed, denying (fail-closed)");
            respond(&shared.fan_fd, &event_fd, verdict);
            shared.stats.local_answers.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if !open_needs_access_lookup(mask, &path, &shared.static_allow) {
        respond(&shared.fan_fd, &event_fd, FAN_ALLOW);
        shared.stats.local_answers.fetch_add(1, Ordering::Relaxed);
        maybe_mark_static_allow(shared, mask, &path, &event_fd);
        return;
    }

    let access = normalize_directory_traverse_access(
        Path::new(&path),
        mask_to_access(&shared.host_proc, mask, &event_fd, pid),
    );

    if shared.static_allow.allows(Path::new(&path), access) {
        respond(&shared.fan_fd, &event_fd, FAN_ALLOW);
        shared.stats.local_answers.fetch_add(1, Ordering::Relaxed);
        maybe_mark_static_allow(shared, mask, &path, &event_fd);
        return;
    }

    shared.stats.policyd_calls.fetch_add(1, Ordering::Relaxed);

    tracing::debug!(%path, ?access, pid, "filesystem check");
    let mut event_ctx = shared.ctx.clone();
    event_ctx.pid = u32::try_from(pid).ok();

    let reply = runtime.block_on(rpc.check_filesystem(Path::new(&path), access, event_ctx));

    let verdict = match &reply {
        Ok(r) if r.verdict.allowed => FAN_ALLOW,
        _ => FAN_DENY,
    };

    if verdict == FAN_DENY {
        tracing::info!(%path, ?access, "denied by policy");
    }

    respond(&shared.fan_fd, &event_fd, verdict);
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
    let (fan_fd, fanotify_reports_tid) = agent_sandbox_sysutil::fanotify_init_content()
        .unwrap_or_else(|e| {
            eprintln!("agent-sandbox-fsmon: fanotify_init failed: {e}");
            process::exit(1);
        });

    if !fanotify_reports_tid {
        eprintln!("agent-sandbox-fsmon: FAN_REPORT_TID is required to identify the opener safely");
        process::exit(1);
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

    // Resolve the request context before joining the sandbox mount namespace.
    // wire_context reads /run/agent-sandbox/session-context.json, and after
    // mark_mountpoints installs FAN_OPEN_PERM marks below, that read would
    // raise a permission event to our own fanotify group. The event loop that
    // answers it starts only after this read returns, so the read would
    // deadlock (the process wedges in the kernel, state D).
    let ctx = wire_context(
        cli.cwd,
        cli.home.clone(),
        cli.project_root.clone(),
        ProcessIds::default(),
        std::env::var("AGENT_SANDBOX_SESSION_ID").ok(),
    );

    // Load the exported policy snapshot before joining the sandbox mount
    // namespace: the file lives on the host filesystem, and reading it after
    // mark_mountpoints would raise a permission event to our own fanotify
    // group before the event loop exists to answer it.
    let static_allow = StaticPolicyAllow::load(&cli.static_policy, cli.project_root.clone());

    // setns into the target mount namespace before marking its mounts.
    join_target_mount_namespace(cli.pid);

    let home_covering_mount = cli
        .home
        .as_deref()
        .and_then(|home| deepest_covering_mount(&mounts, home))
        .map(Path::to_path_buf);

    let home_covered = mark_mountpoints(
        &fan_fd,
        &mounts,
        home_covering_mount.as_deref(),
        cli.home.as_deref(),
    );

    // Before signaling ready, require that at least one marked mount covers --home.
    if let Some(home) = &cli.home
        && !home_covered
    {
        eprintln!(
            "agent-sandbox-fsmon: no successfully marked mount covers --home {}; cannot guarantee \
             filesystem monitoring",
            home.display()
        );

        process::exit(1);
    }

    // Signal readiness.
    println!("ready");

    let _ = io::stdout().flush();
    let socket_path = cli.socket.as_path();

    let target_pid = i32::try_from(cli.pid).unwrap_or_else(|_| {
        eprintln!("agent-sandbox-fsmon: --pid does not fit in pid_t");
        process::exit(1);
    });

    let sandbox_cgroup = SandboxCgroup::read(&host_proc, target_pid).unwrap_or_else(|| {
        eprintln!("agent-sandbox-fsmon: cannot read target cgroup membership");
        process::exit(1);
    });

    // Ask the reader loop to flush ignore marks and exit on SIGTERM/SIGINT.
    // Closing the fanotify fd would drop the marks anyway; the explicit flush
    // keeps the unmark path exercised and the counters exact.
    if let Err(error) = agent_sandbox_sysutil::install_shutdown_signals(request_shutdown) {
        tracing::warn!(%error, "cannot install shutdown signals; ignore marks will not be flushed");
    }

    run_event_loop(
        fan_fd,
        self_pid,
        sandbox_cgroup,
        host_proc,
        ctx,
        socket_path,
        static_allow,
        cli.fs_ignore_static_allows,
        cli.static_policy,
    );
}

/// Note a terminate request for the reader loop. Runs in signal context:
/// only a lock-free atomic store.
extern "C" fn request_shutdown(_signum: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

/// Fast-path allow checks that do not need a policyd RPC.
/// Returns `true` when the event was already handled.
///
/// `pid_cgroup_cache` remembers pids already proven to belong to the sandbox
/// cgroup. Every fanotify event otherwise costs two procfs reads (status for
/// the thread-group id, cgroup for membership). Both are immutable for the
/// lifetime of a process, and only sandbox-namespace processes can generate
/// events on the marked mounts, so only membership is cached: a reused pid
/// can only ever belong to another sandbox process, and a hypothetical host
/// process hitting a stale entry is still policy-mediated rather than
/// auto-allowed.
fn try_fast_path_allow(
    fan_fd: &OwnedFd,
    pid: i32,
    event_fd: &OwnedFd,
    self_pid: i32,
    sandbox_cgroup: &SandboxCgroup,
    host_proc: &HostProc,
    pid_cgroup_cache: &mut HashSet<i32>,
) -> bool {
    if pid == self_pid {
        respond(fan_fd, event_fd, FAN_ALLOW);
        return true;
    }

    if pid_cgroup_cache.insert(pid) {
        // First observation of this pid: classify its cgroup membership.
        let process_pid = host_proc.thread_group_id(pid).unwrap_or(pid);

        match sandbox_cgroup.contains(host_proc, process_pid) {
            Some(true) => {}

            Some(false) => {
                pid_cgroup_cache.remove(&pid);
                respond(fan_fd, event_fd, FAN_ALLOW);
                return true;
            }

            None => {
                pid_cgroup_cache.remove(&pid);
                respond(fan_fd, event_fd, FAN_DENY);
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use super::*;

    fn test_host_proc() -> HostProc {
        HostProc::open().expect("open host proc")
    }

    fn test_event_file() -> File {
        File::open("/dev/null").expect("open event fixture")
    }

    fn static_allow(rule: &str) -> StaticPolicyAllow {
        let path = std::env::temp_dir().join(format!("fsmon-static-{}.json", std::process::id()));
        std::fs::write(
            &path,
            format!("{{\"filesystem\": {{\"allow\": [{rule}]}}}}"),
        )
        .expect("write policy fixture");
        let allow = StaticPolicyAllow::load(&path, None);
        std::fs::remove_file(&path).expect("remove policy fixture");
        allow
    }

    #[test]
    fn read_write_grant_skips_access_lookup_for_non_exec_opens_only() {
        let read_write = static_allow(r#"{"path": "/srv/project", "access": "read_write"}"#);
        assert!(!open_needs_access_lookup(
            FAN_OPEN_PERM,
            "/srv/project/file",
            &read_write
        ));
        assert!(open_needs_access_lookup(
            FAN_OPEN_PERM,
            "/srv/elsewhere/file",
            &read_write
        ));
        assert!(open_needs_access_lookup(
            FAN_OPEN_EXEC_PERM,
            "/srv/project/tool",
            &read_write
        ));

        let all = static_allow(r#"{"path": "/srv/project", "access": "all"}"#);
        assert!(!open_needs_access_lookup(
            FAN_OPEN_PERM,
            "/srv/project/file",
            &all
        ));

        let read_only = static_allow(r#"{"path": "/srv/project", "access": "read"}"#);
        assert!(
            open_needs_access_lookup(FAN_OPEN_PERM, "/srv/project/file", &read_only),
            "a read-only grant must not admit a write without the tracee's flags"
        );
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
    fn exec_syscalls_classify_plain_open_permission_as_execute() {
        let host_proc = test_host_proc();

        for nr in [libc::SYS_execve, libc::SYS_execveat] {
            let content = format!("{nr} 0x7fff00004000 0x0 0x0 0x0 0x0 0x0");

            assert_eq!(
                parse_open_syscall_access(&host_proc, 1, &content),
                Some(FileAccess::Execute)
            );
        }
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
    fn mask_to_access_maps_open_and_exec_events() {
        let host_proc = test_host_proc();
        let event_fd = test_event_file();

        assert_eq!(
            mask_to_access(&host_proc, FAN_OPEN_EXEC_PERM, &event_fd, -1),
            FileAccess::Execute
        );

        assert_eq!(
            mask_to_access(&host_proc, FAN_OPEN_PERM, &event_fd, -1),
            FileAccess::ReadWrite
        );
    }

    #[test]
    fn open_perm_without_pid_falls_back_to_read_write() {
        // Without a valid pid, syscall_lookup returns None.
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
    fn cgroup_membership_is_stable_identity_not_parent_ancestry() {
        let session = SandboxCgroup("/sandbox/session.scope".to_string());
        assert_eq!(session.0, "/sandbox/session.scope");
        assert_ne!(session.0, "/");
    }

    #[test]
    fn context_arguments_declare_environment_defaults() {
        use clap::CommandFactory;

        let command = Cli::command();

        for (argument, environment) in [
            ("cwd", "AGENT_SANDBOX_CWD"),
            ("home", "AGENT_SANDBOX_HOME"),
            ("project_root", "AGENT_SANDBOX_PROJECT_ROOT"),
        ] {
            let argument = command
                .get_arguments()
                .find(|candidate| candidate.get_id().as_str() == argument)
                .expect("context argument should exist");

            assert_eq!(
                argument.get_env().and_then(|value| value.to_str()),
                Some(environment)
            );
        }
    }

    fn static_allow_named(test: &str, rule: &str) -> StaticPolicyAllow {
        let path =
            std::env::temp_dir().join(format!("fsmon-static-{}-{test}.json", std::process::id()));
        std::fs::write(
            &path,
            format!("{{\"filesystem\": {{\"allow\": [{rule}]}}}}"),
        )
        .expect("write policy fixture");
        let allow = StaticPolicyAllow::load(&path, None);
        std::fs::remove_file(&path).expect("remove policy fixture");
        allow
    }

    fn test_shared(test: &str, rule: &str, ignore_static_allows: bool) -> Shared {
        let fan_fd = OwnedFd::from(File::open("/dev/null").expect("open fanotify fd stand-in"));
        Shared {
            fan_fd,
            self_pid: i32::try_from(process::id()).expect("pid fits in i32"),
            sandbox_cgroup: SandboxCgroup("test.scope".to_string()),
            host_proc: test_host_proc(),
            ctx: agent_sandbox_core::RequestContext::default(),
            socket_path: PathBuf::from("/tmp/fsmon-test.sock"),
            static_allow: static_allow_named(test, rule),
            ignore_static_allows,
            static_policy_path: PathBuf::from("/tmp/fsmon-test-policy.json"),
            marked: Mutex::new(HashSet::new()),
            cap_warned: AtomicBool::new(false),
            stats: FsmonStats::default(),
        }
    }

    fn read_only_fixture(test: &str) -> (PathBuf, OwnedFd) {
        let path = std::env::temp_dir().join(format!("fsmon-mark-{test}-{}", std::process::id()));
        std::fs::write(&path, b"immutable").expect("write mark fixture");
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o444))
            .expect("chmod mark fixture");
        let event_fd = OwnedFd::from(File::open(&path).expect("open mark fixture"));
        (path, event_fd)
    }

    #[test]
    fn ignore_mark_needs_open_event_read_allow_and_a_write_bar() {
        let allow = static_allow_named("eligible", r#"{"path": "/srv/project", "access": "read"}"#);
        let path = Path::new("/srv/project/file");

        assert!(ignore_mark_eligible(
            &allow,
            FAN_OPEN_PERM,
            path,
            false,
            false
        ));
        assert!(ignore_mark_eligible(
            &allow,
            FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM,
            path,
            false,
            false
        ));
        assert!(ignore_mark_eligible(
            &allow,
            FAN_OPEN_PERM,
            path,
            true,
            true
        ));

        // Writable inode on a writable mount under a read-only grant: a denied
        // write open could succeed at the VFS layer, so the event must keep
        // flowing.
        assert!(!ignore_mark_eligible(
            &allow,
            FAN_OPEN_PERM,
            path,
            true,
            false
        ));

        // No open-permission bit, or bits outside the open family.
        assert!(!ignore_mark_eligible(&allow, 0, path, false, false));
        assert!(!ignore_mark_eligible(
            &allow,
            FAN_OPEN_PERM | 0x0000_0004,
            path,
            false,
            false
        ));

        // A path the static snapshot denies is never marked.
        assert!(!ignore_mark_eligible(
            &allow,
            FAN_OPEN_PERM,
            Path::new("/srv/elsewhere/file"),
            false,
            false
        ));
    }

    #[test]
    fn ignore_mark_disabled_leaves_the_set_empty() {
        let shared = test_shared(
            "disabled",
            r#"{"path": "/srv/project", "access": "read"}"#,
            false,
        );
        let (path, event_fd) = read_only_fixture("disabled");

        maybe_mark_static_allow(&shared, FAN_OPEN_PERM, "/srv/project/file", &event_fd);
        std::fs::remove_file(&path).expect("remove mark fixture");

        assert!(
            shared
                .marked
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .is_empty()
        );
        assert_eq!(shared.stats.marks_added.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ignore_mark_failure_is_best_effort() {
        // The stand-in fd is not a fanotify fd, so the mark syscall fails;
        // the event path must be unchanged: nothing tracked, nothing counted.
        let shared = test_shared(
            "best-effort",
            r#"{"path": "/srv/project", "access": "read"}"#,
            true,
        );
        let (path, event_fd) = read_only_fixture("best-effort");

        maybe_mark_static_allow(&shared, FAN_OPEN_PERM, "/srv/project/file", &event_fd);
        std::fs::remove_file(&path).expect("remove mark fixture");

        assert!(
            shared
                .marked
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .is_empty()
        );
        assert_eq!(shared.stats.marks_added.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ignore_mark_write_allow_covers_writable_inodes() {
        let allow = static_allow_named(
            "write-allow",
            r#"{"path": "/srv/project", "access": "read_write"}"#,
        );

        assert!(ignore_mark_eligible(
            &allow,
            FAN_OPEN_PERM,
            Path::new("/srv/project/file"),
            true,
            false
        ));
    }

    #[test]
    fn ignore_mark_set_stops_at_cap() {
        let shared = test_shared("cap", r#"{"path": "/srv/project", "access": "read"}"#, true);
        let (path, event_fd) = read_only_fixture("cap");
        std::fs::remove_file(&path).expect("remove mark fixture");

        shared
            .marked
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .extend((0..IGNORE_MARK_CAP).map(|i| PathBuf::from(format!("/srv/filler/{i}"))));

        maybe_mark_static_allow(&shared, FAN_OPEN_PERM, "/srv/project/file", &event_fd);
        maybe_mark_static_allow(&shared, FAN_OPEN_PERM, "/srv/project/other", &event_fd);

        assert!(shared.cap_warned.load(Ordering::Relaxed));
        assert_eq!(
            shared
                .marked
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .len(),
            IGNORE_MARK_CAP
        );
        assert_eq!(shared.stats.marks_added.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn flush_ignore_marks_drains_and_counts() {
        let shared = test_shared(
            "flush",
            r#"{"path": "/srv/project", "access": "read"}"#,
            true,
        );

        shared
            .marked
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .extend([
                PathBuf::from("/srv/project/a"),
                PathBuf::from("/srv/project/b"),
            ]);

        flush_ignore_marks(&shared);

        assert!(
            shared
                .marked
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .is_empty()
        );
        assert_eq!(shared.stats.marks_flushed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn policy_snapshot_key_tracks_rewrites() {
        let path = std::env::temp_dir().join(format!("fsmon-policy-{}.json", std::process::id()));
        std::fs::write(&path, r#"{"filesystem": {"allow": []}}"#).expect("write policy");
        let before = policy_snapshot_key(&path);

        assert!(before.is_some());

        std::fs::write(
            &path,
            r#"{"filesystem": {"allow": [{"path": "/x", "access": "read"}]}}"#,
        )
        .expect("rewrite policy");
        let after = policy_snapshot_key(&path);

        std::fs::remove_file(&path).expect("remove policy");

        assert!(after.is_some());
        assert_ne!(before, after);
        assert_eq!(policy_snapshot_key(&path), None);
    }

    #[test]
    fn ignore_static_allows_defaults_to_true() {
        use clap::Parser;

        let cli =
            Cli::try_parse_from(["agent-sandbox-fsmon", "--pid", "1"]).expect("defaults parse");

        assert!(cli.fs_ignore_static_allows);

        let cli = Cli::try_parse_from([
            "agent-sandbox-fsmon",
            "--pid",
            "1",
            "--fs-ignore-static-allows",
            "false",
        ])
        .expect("explicit disable parses");

        assert!(!cli.fs_ignore_static_allows);
    }
}
