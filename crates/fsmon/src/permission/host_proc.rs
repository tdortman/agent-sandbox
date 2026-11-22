//! Host procfs lookups for the pids fanotify reports.

use std::{
    fs::File,
    io,
    io::Read,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};

use nix::{
    fcntl::{OFlag, openat, readlinkat},
    sys::stat::Mode,
};

/// Host procfs directory opened before `setns` into a sandbox mount namespace.
///
/// Fanotify reports PIDs in the listener's PID namespace (host). After `setns`,
/// the mounted `/proc` belongs to the sandbox and may use different PID
/// assignments, so every procfs lookup must be relative to this saved fd.
pub struct HostProc {
    dir: File,
}

impl HostProc {
    /// Open the procfs mounted at `/proc` in the current mount namespace.
    ///
    /// # Errors
    /// Returns the error from opening `/proc`.
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            dir: File::open("/proc")?,
        })
    }

    fn relative_path(pid: i32, leaf: &str) -> PathBuf {
        PathBuf::from(format!("{pid}/{leaf}"))
    }

    /// Open `/proc/<pid>/<leaf>` read-only.
    ///
    /// # Errors
    /// Returns the error from opening the entry.
    pub fn open_entry(&self, pid: i32, leaf: &str) -> io::Result<File> {
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

    /// Target of the symlink `/proc/<pid>/<leaf>`.
    ///
    /// # Errors
    /// Returns the error from reading the link.
    pub fn read_link(&self, pid: i32, leaf: &str) -> io::Result<PathBuf> {
        Ok(PathBuf::from(readlinkat(
            &self.dir,
            &Self::relative_path(pid, leaf),
        )?))
    }

    pub(super) fn read_self_fd_link(&self, fd: i32) -> io::Result<PathBuf> {
        Ok(PathBuf::from(readlinkat(
            &self.dir,
            Path::new(&format!("self/fd/{fd}")),
        )?))
    }

    pub(super) fn read_memory(&self, pid: i32, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.open_entry(pid, "mem")?.read_exact_at(buf, addr)
    }

    /// Thread group id for `pid` (accepts either a tid or tgid).
    pub(super) fn thread_group_id(&self, pid: i32) -> Option<i32> {
        self.status_pid_field(pid, "Tgid:")
    }

    /// Parent pid of `pid` as seen from the host pid namespace.
    #[must_use]
    pub fn parent_pid(&self, pid: i32) -> Option<i32> {
        self.status_pid_field(pid, "PPid:")
    }

    fn status_pid_field(&self, pid: i32, field: &str) -> Option<i32> {
        if pid <= 0 {
            return None;
        }

        let status = self.read_to_string(pid, "status").ok()?;

        status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|rest| rest.trim().parse().ok())
    }
}

/// Immutable cgroup identity captured from the sandbox root before `setns`.
///
/// A process remains in its cgroup after daemonisation/reparenting, while its
/// `PPid` ancestry can immediately point at an unrelated host process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupPath {
    path: String,
}

impl CgroupPath {
    /// The cgroup v2 path of `pid`, or `None` when it cannot be read.
    #[must_use]
    pub fn read(host_proc: &HostProc, pid: i32) -> Option<Self> {
        let content = host_proc.read_to_string(pid, "cgroup").ok()?;

        let path = content.lines().find_map(|line| {
            let (hierarchy, path) = line.split_once("::")?;
            (hierarchy == "0" && !path.is_empty()).then(|| path.to_string())
        })?;

        Some(Self { path })
    }

    pub(super) fn contains(&self, host_proc: &HostProc, pid: i32) -> Option<bool> {
        Some(Self::read(host_proc, pid)?.path == self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::{CgroupPath, HostProc};

    fn test_host_proc() -> HostProc {
        HostProc::open().expect("open host proc")
    }

    #[test]
    fn host_proc_fd_relative_access_resolves_tracee_status() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        assert!(host_proc.read_to_string(pid, "status").is_ok());
    }

    #[test]
    fn thread_group_id_for_self() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        assert_eq!(host_proc.thread_group_id(pid), Some(pid));
    }

    #[test]
    fn cgroup_membership_is_stable_identity_not_parent_ancestry() {
        let host_proc = test_host_proc();
        let pid = i32::try_from(std::process::id()).expect("pid fits in i32");
        let own = CgroupPath::read(&host_proc, pid).expect("own cgroup");

        assert_eq!(own.contains(&host_proc, pid), Some(true));
        assert_eq!(own.contains(&host_proc, i32::MAX), None);
    }
}
