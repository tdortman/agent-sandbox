//! Read sandbox context from a client process via /proc (host pid namespace).

use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::path::Path;

#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

const TCP_ESTABLISHED: &str = "01";

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

pub fn read_proc_cwd(pid: u32) -> Option<String> {
    let link = format!("/proc/{pid}/cwd");
    std::fs::read_link(&link)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

pub fn home_from_uid(uid: Option<u32>) -> Option<String> {
    let uid = uid?;
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir.to_string_lossy().into_owned())
}

pub fn context_from_pid(pid: u32) -> (Option<String>, Option<String>, Option<String>) {
    if pid == 0 {
        return (None, None, None);
    }
    let env = read_proc_environ(pid);
    let cwd = env
        .get("AGENT_SANDBOX_CWD")
        .cloned()
        .or_else(|| read_proc_cwd(pid));
    let home = env
        .get("AGENT_SANDBOX_HOME")
        .cloned()
        .or_else(|| env.get("HOME").cloned());
    let project_root = env.get("AGENT_SANDBOX_PROJECT_ROOT").cloned();
    (cwd, home, project_root)
}

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

fn find_tcp_entry(local: SocketAddr, peer: SocketAddr) -> Option<(u32, String)> {
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
            return Some((uid, parts[9].to_string()));
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

/// Return `(pid, uid, gid)` for the peer of a connected Unix domain socket.
#[allow(unsafe_code)]
pub fn peer_cred_unix(stream: &tokio::net::UnixStream) -> Option<(u32, u32, i32)> {
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    peer_cred_fd(fd)
}

/// Return `(pid, uid, gid)` for the peer of a connected socket.
///
/// For accepted TCP connections (e.g. `agent-sandbox-proxy`), the local endpoint's
/// `/proc/net/tcp` row belongs to this process. Look up the inverse quad first so we
/// resolve the connecting client's pid for policy UI routing.
#[allow(unsafe_code)]
pub fn peer_cred(stream: &tokio::net::TcpStream) -> Option<(u32, u32, i32)> {
    let local = stream.local_addr().ok()?;
    let peer = stream.peer_addr().ok()?;
    if local.is_ipv4() && peer.is_ipv4() {
        // Server-side accept: peer's socket row is (peer, local).
        if let Some((uid, inode)) = find_tcp_entry(peer, local) {
            let pid = pid_for_socket_inode(&inode).unwrap_or(0);
            if pid > 0 {
                return Some((pid, uid, -1));
            }
        }
        // Client-side connect: our socket row is (local, peer).
        if let Some((uid, inode)) = find_tcp_entry(local, peer) {
            let pid = pid_for_socket_inode(&inode).unwrap_or(0);
            return Some((pid, uid, -1));
        }
    }
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    peer_cred_fd(fd)
}

#[allow(unsafe_code)]
fn peer_cred_fd(fd: std::os::fd::BorrowedFd<'_>) -> Option<(u32, u32, i32)> {
    let cred = getsockopt(&fd, PeerCredentials).ok()?;
    let pid = u32::try_from(cred.pid()).ok()?;
    let uid = cred.uid();
    let gid = i32::try_from(cred.gid()).ok()?;
    if pid == 0 && i32::try_from(uid).is_err() {
        return None;
    }
    Some((pid, uid, gid))
}

/// Inode of a process namespace link (`/proc/<pid>/ns/<kind>`).
#[must_use]
pub fn namespace_inode(pid: u32, kind: &str) -> Option<u64> {
    #[cfg(unix)]
    {
        let path = if pid == 0 {
            format!("/proc/self/ns/{kind}")
        } else {
            format!("/proc/{pid}/ns/{kind}")
        };
        std::fs::metadata(path).ok().map(|meta| meta.st_ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, kind);
        None
    }
}

/// Whether `peer_pid` is in the network namespace referenced by `netns_path`.
#[must_use]
pub fn peer_in_netns(peer_pid: u32, netns_path: &Path) -> bool {
    if peer_pid == 0 {
        return false;
    }
    let Some(peer_net) = namespace_inode(peer_pid, "net") else {
        return false;
    };
    let Ok(netns_meta) = std::fs::metadata(netns_path) else {
        return false;
    };
    #[cfg(unix)]
    {
        peer_net == netns_meta.st_ino()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Whether `peer_pid` is in a different mount namespace than the current process.
#[must_use]
pub fn peer_in_different_mount_ns(peer_pid: u32) -> bool {
    if peer_pid == 0 {
        return false;
    }
    let Some(peer_mnt) = namespace_inode(peer_pid, "mnt") else {
        return false;
    };
    let Some(self_mnt) = namespace_inode(0, "mnt") else {
        return false;
    };
    peer_mnt != self_mnt
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

/// Nearest OMP-like ancestor of `pid` in the host pid namespace (usually the agent process).
#[must_use]
pub fn omp_ui_owner_for_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }
    let mut current = pid;
    for _ in 0..256 {
        if looks_like_omp_ui_process(current) {
            return Some(current);
        }
        let Some(ppid) = read_proc_ppid(current) else {
            break;
        };
        if ppid <= 1 {
            break;
        }
        current = ppid;
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
        let Some(ppid) = read_proc_ppid(current) else {
            break;
        };
        if ppid == ancestor {
            return true;
        }
        if ppid <= 1 {
            break;
        }
        current = ppid;
    }
    false
}

/// NUL-separated `/proc/<pid>/cmdline` rendered as a single string.
#[must_use]
pub fn read_proc_cmdline(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split(|&b| b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

const OMP_UI_CMDLINE_MARKERS: &[&str] = &[
    ".omp/agent",
    "oh-my-pi",
    "pi-coding-agent",
    "@oh-my-pi",
    "/lib/omp/omp",
    "/bin/omp",
];

const OMP_UI_EXE_SUFFIXES: &[&str] = &["/lib/omp/omp", "/bin/omp"];

const BLOCKED_SANDBOX_POLICY_TOOLS: &[&str] = &["agent-sandbox-approve", "agent-sandbox-ui"];

fn cmdline_contains_any(cmdline: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| cmdline.contains(needle))
}

/// Resolved `/proc/<pid>/exe` when the process is still alive.
#[must_use]
pub fn read_proc_exe(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// Whether `peer_pid` looks like the OMP agent process hosting the policy UI extension.
#[must_use]
pub fn looks_like_omp_ui_process(peer_pid: u32) -> bool {
    if read_proc_cmdline(peer_pid)
        .is_some_and(|cmdline| cmdline_contains_any(&cmdline, OMP_UI_CMDLINE_MARKERS))
    {
        return true;
    }
    read_proc_exe(peer_pid).is_some_and(|exe| {
        OMP_UI_EXE_SUFFIXES
            .iter()
            .any(|suffix| exe.ends_with(suffix))
    })
}

/// Host policy tools that must never act as UI from inside the sandbox.
#[must_use]
pub fn is_blocked_sandbox_policy_tool(peer_pid: u32) -> bool {
    read_proc_cmdline(peer_pid)
        .is_some_and(|cmdline| cmdline_contains_any(&cmdline, BLOCKED_SANDBOX_POLICY_TOOLS))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        OMP_UI_CMDLINE_MARKERS, OMP_UI_EXE_SUFFIXES, cmdline_contains_any,
        is_blocked_sandbox_policy_tool, is_descendant_of, looks_like_omp_ui_process,
        namespace_inode, omp_ui_owner_for_pid, peer_in_different_mount_ns, peer_in_netns,
        read_proc_cmdline, read_proc_exe,
    };

    #[test]
    fn self_net_namespace_inode_is_stable() {
        let a = namespace_inode(0, "net");
        let b = namespace_inode(std::process::id(), "net");
        assert_eq!(a, b);
    }

    #[test]
    fn self_not_in_missing_netns_path() {
        assert!(!peer_in_netns(
            std::process::id(),
            Path::new("/run/netns/does-not-exist-for-agent-sandbox-test")
        ));
    }

    #[test]
    fn self_not_in_different_mount_ns() {
        assert!(!peer_in_different_mount_ns(std::process::id()));
    }

    #[test]
    fn self_is_descendant_of_self() {
        let pid = std::process::id();
        assert!(is_descendant_of(pid, pid));
    }

    #[test]
    fn omp_ui_owner_finds_nearest_marked_ancestor() {
        let pid = std::process::id();
        if looks_like_omp_ui_process(pid) {
            assert_eq!(omp_ui_owner_for_pid(pid), Some(pid));
        }
        if let Some(owner_pid) = omp_ui_owner_for_pid(pid) {
            assert!(looks_like_omp_ui_process(owner_pid));
        }
    }

    #[test]
    fn read_self_cmdline_is_non_empty() {
        let pid = std::process::id();
        let cmdline = read_proc_cmdline(pid).expect("cmdline");
        assert!(!cmdline.is_empty());
        let exe = read_proc_exe(pid);
        assert_eq!(
            looks_like_omp_ui_process(pid),
            cmdline_contains_any(&cmdline, OMP_UI_CMDLINE_MARKERS)
                || exe.as_ref().is_some_and(|path| {
                    OMP_UI_EXE_SUFFIXES
                        .iter()
                        .any(|suffix| path.ends_with(suffix))
                })
        );
        assert_eq!(
            is_blocked_sandbox_policy_tool(pid),
            cmdline.contains("agent-sandbox-approve") || cmdline.contains("agent-sandbox-ui")
        );
    }

    #[test]
    fn tcp_addr_field_encodes_ipv4_loopback() {
        assert_eq!(super::tcp_addr_field("127.0.0.1", 8080), "0100007F:1F90");
    }

    #[test]
    fn nix_packaged_omp_cmdline_is_recognized() {
        let cmdline = "/nix/store/fh1ph0hvmfk2cx5zd7m5wfrm1w9vbg07-omp-15.10.0/lib/omp/omp --resume abc --model=cursor/composer-2.5";
        assert!(cmdline_contains_any(cmdline, OMP_UI_CMDLINE_MARKERS));
    }
}
