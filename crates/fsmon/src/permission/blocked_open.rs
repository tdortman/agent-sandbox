//! Path and access mode of an open blocked on a fanotify permission event.

use std::{
    io,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::fs::FileExt,
    },
    path::PathBuf,
};

use agent_sandbox_core::{FileAccess, PathResolution, open_flags_to_file_access};
use agent_sandbox_sysutil::{FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM};
use nix::sys::stat::{SFlag, fstat};

use super::host_proc::HostProc;

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

/// Path of a fanotify permission event and how far it is resolved.
pub(super) struct EventPath {
    pub(super) path: String,
    pub(super) resolution: PathResolution,
}

/// Best-effort path for a fanotify permission event: event fd first (the
/// kernel reports it canonical), then the blocked tracee's open syscall args.
pub(super) fn resolve_blocked_open_path(
    host_proc: &HostProc,
    trace_pid: i32,
    event_fd: &OwnedFd,
) -> Option<EventPath> {
    resolve_event_path(host_proc, event_fd)
        .ok()
        .map(|path| EventPath {
            path,
            resolution: PathResolution::Canonical,
        })
        .or_else(|| {
            syscall_lookup(host_proc, trace_pid, parse_open_syscall_path).map(|path| EventPath {
                path: path.to_string_lossy().into_owned(),
                resolution: PathResolution::Unresolved,
            })
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
        // `0` = idle, `-1` = blocked but not in a syscall
        // (`proc_pid_syscall(5)`).
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

        // openat2(int dirfd, const char *pathname, struct open_how *how, size_t
        // size)
        n if n == libc::SYS_openat2 => {
            let how_ptr = parse_proc_syscall_arg(parts.nth(2)?)?;
            let flags = read_tracee_open_how_flags(host_proc, trace_pid, how_ptr)?;
            Some(open_flags_to_file_access(flags))
        }

        // creat(const char *pathname, mode_t mode) — open(2) with
        // O_WRONLY|O_CREAT|O_TRUNC
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
pub(super) fn mask_to_access(
    host_proc: &HostProc,
    mask: u64,
    event_fd: &impl AsFd,
    pid: i32,
) -> FileAccess {
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

    #[test]
    fn tracee_path_reader_rejects_unterminated_names_instead_of_truncating() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits i32");
        let unterminated = vec![b'a'; agent_sandbox_sysutil::PATH_MAX];
        let terminated = b"/dev/kvm\0";

        let error = read_tracee_path_ptr(&host_proc, pid, unterminated.as_ptr() as u64)
            .expect_err("unterminated name");
        assert_eq!(error.raw_os_error(), Some(libc::ENAMETOOLONG));
        assert_eq!(
            read_tracee_path_ptr(&host_proc, pid, terminated.as_ptr() as u64)
                .expect("read terminated name"),
            Some(PathBuf::from("/dev/kvm"))
        );
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
    fn open_how_flags_classify_rdwr_as_read_write() {
        let flags = libc::O_RDWR;
        let mut how = [0_u8; 8];
        how.copy_from_slice(&u64::from(flags.cast_unsigned()).to_ne_bytes());

        assert_eq!(
            open_how_flags_from_bytes(&how).map(open_flags_to_file_access),
            Some(FileAccess::ReadWrite)
        );
    }
}
