//! Read sandbox context from a client process via /proc (host pid namespace).

use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

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

/// Return `(pid, uid, gid)` for the peer of a connected socket.
#[allow(unsafe_code)]
pub fn peer_cred(stream: &tokio::net::TcpStream) -> Option<(u32, u32, i32)> {
    let local = stream.local_addr().ok()?;
    let peer = stream.peer_addr().ok()?;
    if local.is_ipv4()
        && peer.is_ipv4()
        && let Some((uid, inode)) = find_tcp_entry(local, peer)
    {
        let pid = pid_for_socket_inode(&inode).unwrap_or(0);
        return Some((pid, uid, -1));
    }
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let cred = getsockopt(&fd, PeerCredentials).ok()?;
    let pid = u32::try_from(cred.pid()).ok()?;
    let uid = cred.uid();
    let gid = i32::try_from(cred.gid()).ok()?;
    if pid == 0 && i32::try_from(uid).is_err() {
        return None;
    }
    Some((pid, uid, gid))
}
