//! Read sandbox context from a client process via /proc (host pid namespace).

use std::path::{Path, PathBuf};

use std::net::{Ipv4Addr, SocketAddr};

use crate::merge_policy::ProjectPolicyContext;
use std::os::fd::AsFd;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials as NixPeerCredentials};

const TCP_ESTABLISHED: &str = "01";

#[must_use]
pub fn read_proc_environ(pid: u32) -> std::collections::HashMap<String, String> {
    let path = format!("/proc/{pid}/environ");
    let Ok(raw) = std::fs::read(&path) else {
        return std::collections::HashMap::new();
    };
    let mut env = std::collections::HashMap::new();
    for item in raw.split(|&b| b == 0) {
        if let Some(eq) = item.iter().position(|&b| b == b'=') {
            let (key, value) = item.split_at(eq);
            let value = &value[1..];
            env.insert(
                String::from_utf8_lossy(key).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            );
        }
    }
    env
}

#[must_use]
pub fn read_proc_cwd(pid: u32) -> Option<PathBuf> {
    let link = format!("/proc/{pid}/cwd");
    std::fs::read_link(&link).ok()
}

#[must_use]
pub fn home_from_uid(uid: Option<u32>) -> Option<String> {
    let uid = uid?;
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir.to_string_lossy().into_owned())
}

/// UID and socket inode from a `/proc/net/tcp` row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpSocketEntry {
    uid: u32,
    inode: String,
}

/// Process credentials for an RPC peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: i32,
}

/// Cwd / home / `project_root` resolved from a process's environment and `/proc`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcContext {
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
}

#[must_use]
pub fn context_from_pid(pid: u32) -> ProcContext {
    if pid == 0 {
        return ProcContext {
            cwd: None,
            home: None,
            project_root: None,
        };
    }
    let env = read_proc_environ(pid);
    let cwd = env
        .get("AGENT_SANDBOX_CWD")
        .cloned()
        .map(PathBuf::from)
        .or_else(|| read_proc_cwd(pid));
    let home = env
        .get("AGENT_SANDBOX_HOME")
        .cloned()
        .or_else(|| env.get("HOME").cloned())
        .map(PathBuf::from);
    let project_root = env
        .get("AGENT_SANDBOX_PROJECT_ROOT")
        .cloned()
        .map(PathBuf::from);
    ProcContext {
        cwd,
        home,
        project_root,
    }
}

/// Cwd / home / `project_root` for policyd trust decisions.
///
/// Home comes from the verified peer uid, cwd from `/proc/<pid>/cwd`, and
/// `project_root` is inferred from those — never from agent-controlled environ.
#[must_use]
pub fn trusted_context_from_pid(pid: u32, uid: Option<u32>) -> ProcContext {
    if pid == 0 {
        return ProcContext::default();
    }
    let env = read_proc_environ(pid);
    let mut cwd = env
        .get("AGENT_SANDBOX_CWD")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| read_proc_cwd(pid));
    let home = env
        .get("AGENT_SANDBOX_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| uid.and_then(|u| home_from_uid(Some(u))).map(PathBuf::from));
    let mut project_root = env
        .get("AGENT_SANDBOX_PROJECT_ROOT")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if project_root.is_none() {
        let project =
            ProjectPolicyContext::new(home.as_deref().map(Path::new), cwd.as_deref(), None);
        project_root = project.project_root().map(Path::to_path_buf);
    }
    if cwd.is_none()
        && let Some(root) = project_root.as_deref()
    {
        cwd = Some(root.to_path_buf());
    }
    ProcContext {
        cwd,
        home,
        project_root,
    }
}

/// If `path` lies inside a Git work tree, return that tree's root directory.
///
/// Walks upward from `path` looking for a `.git` directory or gitfile. Used when
/// matching project-relative allow rules (e.g. `./.git`) so Git metadata under
/// `.git/objects` is allowed even if the sandbox launcher froze a stale
/// `AGENT_SANDBOX_PROJECT_ROOT` or the tracee changed directory into another
/// repository.
#[must_use]
pub fn discover_git_project_root(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        let git_meta = current.join(".git");
        if git_meta.is_dir() || git_meta.is_file() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Whether `child` is the same as or under `ancestor` after canonicalization.
#[must_use]
pub fn is_path_descendant(child: &Path, ancestor: &Path) -> bool {
    let Ok(child) = child.canonicalize() else {
        return false;
    };
    let Ok(ancestor) = ancestor.canonicalize() else {
        return false;
    };
    child == ancestor || child.starts_with(&ancestor)
}

#[must_use]
pub fn sandbox_session_id_from_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    read_proc_environ(pid)
        .get("AGENT_SANDBOX_SESSION_ID")
        .filter(|value| !value.is_empty())
        .cloned()
}

fn tcp_addr_field(ip: &str, port: u16) -> String {
    let octets = ip.parse::<Ipv4Addr>().expect("ipv4").octets();
    let reversed = octets
        .iter()
        .rev()
        .fold(String::with_capacity(8), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02X}");
            s
        });
    format!("{reversed}:{port:04X}")
}

fn find_tcp_entry(local: SocketAddr, peer: SocketAddr) -> Option<TcpSocketEntry> {
    let local_field = tcp_addr_field(&local.ip().to_string(), local.port());
    let peer_field = tcp_addr_field(&peer.ip().to_string(), peer.port());
    let lines = std::fs::read_to_string("/proc/net/tcp").ok()?;
    for line in lines.lines().skip(1) {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        if parts[3] != TCP_ESTABLISHED {
            continue;
        }
        if parts[1] == local_field && parts[2] == peer_field {
            let uid = parts[7].parse().ok()?;
            return Some(TcpSocketEntry {
                uid,
                inode: parts[9].to_string(),
            });
        }
    }
    None
}

fn pid_for_socket_inode(inode: &str) -> Option<u32> {
    let needle = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = name.parse().ok()?;
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path())
                .ok()
                .is_some_and(|l| l.to_string_lossy() == needle)
            {
                return Some(pid);
            }
        }
    }
    None
}

/// Return process credentials for the peer of a connected Unix domain socket.
pub fn peer_cred_unix(stream: &tokio::net::UnixStream) -> Option<PeerCredentials> {
    let cred = stream.peer_cred().ok()?;
    let pid = u32::try_from(cred.pid()?).ok()?;
    let uid = cred.uid();
    let gid = i32::try_from(cred.gid()).unwrap_or(-1);
    Some(PeerCredentials { pid, uid, gid })
}

/// Return process credentials for the peer of a connected socket.
///
/// For accepted TCP connections, the local endpoint's `/proc/net/tcp` row
/// belongs to this process. Look up the inverse quad first so we resolve the
/// connecting client's pid for policy UI routing.
pub fn peer_cred(stream: &tokio::net::TcpStream) -> Option<PeerCredentials> {
    let local = stream.local_addr().ok()?;
    let peer = stream.peer_addr().ok()?;
    if local.is_ipv4() && peer.is_ipv4() {
        // Server-side accept: peer's socket row is (peer, local).
        if let Some(entry) = find_tcp_entry(peer, local) {
            let pid = pid_for_socket_inode(&entry.inode).unwrap_or(0);
            if pid > 0 {
                return Some(PeerCredentials {
                    pid,
                    uid: entry.uid,
                    gid: -1,
                });
            }
        }
        // Client-side connect: our socket row is (local, peer).
        if let Some(entry) = find_tcp_entry(local, peer) {
            let pid = pid_for_socket_inode(&entry.inode).unwrap_or(0);
            return Some(PeerCredentials {
                pid,
                uid: entry.uid,
                gid: -1,
            });
        }
    }
    peer_cred_fd(stream.as_fd())
}

fn peer_cred_fd(fd: impl AsFd) -> Option<PeerCredentials> {
    let cred = getsockopt(&fd, NixPeerCredentials).ok()?;
    let pid = u32::try_from(cred.pid()).ok()?;
    let uid = cred.uid();
    let gid = i32::try_from(cred.gid()).ok()?;
    if pid == 0 && i32::try_from(uid).is_err() {
        return None;
    }
    Some(PeerCredentials { pid, uid, gid })
}

/// Parent pid from `/proc/<pid>/status` (`PPid` field).
#[must_use]
pub fn read_proc_ppid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Whether `pid` is `ancestor` or one of its descendants in the host pid namespace.
#[must_use]
pub fn is_descendant_of(ancestor: u32, pid: u32) -> bool {
    if ancestor == 0 || pid == 0 {
        return false;
    }
    if ancestor == pid {
        return true;
    }
    let mut current = pid;
    for _ in 0..256 {
        let Some(parent_pid) = read_proc_ppid(current) else {
            break;
        };
        if parent_pid == ancestor {
            return true;
        }
        if parent_pid <= 1 {
            break;
        }
        current = parent_pid;
    }
    false
}

#[cfg(test)]
mod discover_git_tests {
    use super::discover_git_project_root;

    #[test]
    fn discover_git_root_from_objects_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git/objects/pack")).expect("git tree");
        let objects = repo.join(".git/objects/pack");
        assert_eq!(
            discover_git_project_root(&objects),
            Some(repo.canonicalize().expect("canonicalize"))
        );
    }

    #[test]
    fn discover_git_root_from_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).expect("git dir");
        std::fs::write(repo.join(".git/config"), "[core]\n").expect("config");
        assert_eq!(
            discover_git_project_root(&repo.join(".git/config")),
            Some(repo.canonicalize().expect("canonicalize"))
        );
    }

    #[test]
    fn discover_git_root_returns_none_outside_repo() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-a-repo/file");
        std::fs::create_dir_all(&path).expect("mkdir");
        assert_eq!(discover_git_project_root(&path), None);
    }
}
