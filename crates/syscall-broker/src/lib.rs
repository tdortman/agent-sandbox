#![allow(unsafe_code)]

use agent_sandbox_core::{
    ProcessIds, RequestContext, RpcReply, RpcRequest, SandboxPaths, policy_rpc,
};
use agent_sandbox_syscall::policy::nr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// Layout of the tracee's `struct msghdr` for the SENDMSG and SENDMMSG
// broker path. The `msg_name` field at offset 0 carries the sockaddr
// pointer and the `msg_namelen` field at offset 8 carries its length.
// `MSGHDR_LEN` is the size of the prefix we read. Values assume 64-bit
// LP64 and are verified at compile time against the libc layout below.
#[cfg(target_pointer_width = "64")]
const MSG_NAME_OFFSET: usize = 0;
#[cfg(target_pointer_width = "64")]
const MSG_NAMELEN_OFFSET: usize = 8;
#[cfg(target_pointer_width = "64")]
const MSGHDR_LEN: usize = 56;

#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::offset_of;
    assert!(offset_of!(libc::msghdr, msg_name) == MSG_NAME_OFFSET);
    assert!(offset_of!(libc::msghdr, msg_namelen) == MSG_NAMELEN_OFFSET);
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTarget {
    pub host: String,
    pub connect_host: String,
    pub port: u16,
    pub scheme: String,
}

pub fn recv_notification(listener_fd: i32) -> io::Result<SeccompNotif> {
    let mut notif = SeccompNotif::default();
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(notif)
}

pub fn send_continue(listener_fd: i32, id: u64) -> io::Result<()> {
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn send_errno(listener_fd: i32, id: u64, errno: i32) -> io::Result<()> {
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    let rc = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn read_tracee_bytes(pid: u32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0_u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: usize::try_from(addr).unwrap_or(0) as *mut libc::c_void,
        iov_len: len,
    };
    let n = unsafe {
        libc::process_vm_readv(
            i32::try_from(pid).unwrap_or(i32::MAX),
            &raw const local,
            1,
            &raw const remote,
            1,
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(n).unwrap_or(0));
    Ok(buf)
}

/// Look up the actual `SO_TYPE` of a tracee socket via `pidfd_open` +
/// `pidfd_getfd`. Returns `None` on any failure (process gone, fd not a
/// socket, kernel too old for the syscalls, etc.) so the caller can fall
/// back to a per-syscall default.
fn get_socket_type(pid: u32, sockfd: i32) -> Option<i32> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // pidfd_open(2): Linux 5.3+. Returns a pidfd referring to the tracee.
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.cast_signed(), 0) };
    let pidfd = i32::try_from(raw_pidfd).ok()?;
    if pidfd < 0 {
        return None;
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    // pidfd_getfd(2): Linux 5.6+. Duplicates the tracee's sockfd into our
    // fd table. The tracee and broker share the user namespace (bwrap uses
    // --unshare-user), so this works across the namespace boundary; opening
    // /proc/<pid>/fd/<sockfd> would not, because the symlink is gone for
    // sockets once the tracee has unshared.
    let raw_dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), sockfd, 0) };
    let dup_fd = i32::try_from(raw_dup).ok()?;
    if dup_fd < 0 {
        return None;
    }
    let dup_fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };
    // getsockopt(SO_TYPE): read the socket type. Returns SOCK_STREAM, SOCK_DGRAM,
    // SOCK_RAW, SOCK_SEQPACKET, etc.
    let mut sock_type: libc::c_int = 0;
    let mut optlen: libc::socklen_t =
        u32::try_from(std::mem::size_of::<libc::c_int>()).expect("size_of c_int fits in u32");
    let ret = unsafe {
        libc::getsockopt(
            dup_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut sock_type).cast::<libc::c_void>(),
            &raw mut optlen,
        )
    };
    if ret < 0 {
        return None;
    }
    Some(sock_type)
}

/// Map a `SO_TYPE` value to a URL scheme. DGRAM sockets are UDP; everything
/// else (STREAM, RAW, SEQPACKET, ...) is reported as TCP for policy purposes,
/// because policyd only knows those two schemes today.
fn scheme_for_socket_type(sock_type: i32) -> &'static str {
    if sock_type == libc::SOCK_DGRAM {
        "udp"
    } else {
        "tcp"
    }
}

/// Resolve the URL scheme for a tracee fd. Tries `get_socket_type` first;
/// on any failure, returns the per-syscall default. `sockfd` comes from
/// `notif.data.args[0]` for sendto/sendmsg/sendmmsg/connect.
fn scheme_for_fd(notif: &SeccompNotif, sockfd: u64, default: &str) -> String {
    let Some(sockfd_i32) = i32::try_from(sockfd).ok() else {
        return default.to_owned();
    };
    match get_socket_type(notif.pid, sockfd_i32) {
        Some(sock_type) => scheme_for_socket_type(sock_type),
        None => default,
    }
    .to_owned()
}

pub fn parse_sockaddr(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match i32::from(family) {
        libc::AF_INET if bytes.len() >= 16 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some((IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if bytes.len() >= 28 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

pub fn target_from_connect(notif: &SeccompNotif) -> io::Result<Option<NetworkTarget>> {
    let scheme = scheme_for_fd(notif, notif.data.args[0], "tcp");
    sockaddr_target(notif, notif.data.args[1], notif.data.args[2], &scheme)
}
pub fn target_from_sendto(notif: &SeccompNotif) -> io::Result<Option<NetworkTarget>> {
    let scheme = scheme_for_fd(notif, notif.data.args[0], "udp");
    sockaddr_target(notif, notif.data.args[4], notif.data.args[5], &scheme)
}

/// Extract the `(name_ptr, name_len)` pair from a raw `msghdr` buffer read
/// from the tracee. Returns `None` if the buffer is too short to contain
/// both the pointer and the length, or if the name pointer is null.
#[cfg(target_pointer_width = "64")]
fn parse_msghdr_target(bytes: &[u8]) -> Option<(u64, u32)> {
    if bytes.len() < MSG_NAMELEN_OFFSET + 4 {
        return None;
    }
    let name = u64::from_ne_bytes(
        bytes[MSG_NAME_OFFSET..MSG_NAME_OFFSET + 8]
            .try_into()
            .expect("checked length above"),
    );
    if name == 0 {
        return None;
    }
    let name_len = u32::from_ne_bytes(
        bytes[MSG_NAMELEN_OFFSET..MSG_NAMELEN_OFFSET + 4]
            .try_into()
            .expect("checked length above"),
    );
    Some((name, name_len))
}

pub fn target_from_sendmsg(notif: &SeccompNotif) -> io::Result<Option<NetworkTarget>> {
    let msg = notif.data.args[1];
    if msg == 0 {
        return Ok(None);
    }
    let bytes = read_tracee_bytes(notif.pid, msg, MSGHDR_LEN)?;
    let Some((name, name_len)) = parse_msghdr_target(&bytes) else {
        return Ok(None);
    };
    let scheme = scheme_for_fd(notif, notif.data.args[0], "udp");
    sockaddr_target(notif, name, u64::from(name_len), &scheme)
}

pub fn target_from_sendmmsg(notif: &SeccompNotif) -> io::Result<Option<NetworkTarget>> {
    let msgvec = notif.data.args[1];
    if msgvec == 0 {
        return Ok(None);
    }
    target_from_sendmsg(&SeccompNotif {
        data: SeccompData {
            args: [notif.data.args[0], msgvec, notif.data.args[3], 0, 0, 0],
            ..notif.data
        },
        ..*notif
    })
}

fn sockaddr_target(
    notif: &SeccompNotif,
    addr: u64,
    addr_len: u64,
    scheme: &str,
) -> io::Result<Option<NetworkTarget>> {
    let addr_len = usize::try_from(addr_len).unwrap_or(0);
    if addr == 0 || addr_len == 0 {
        return Ok(None);
    }
    let bytes = read_tracee_bytes(notif.pid, addr, addr_len.min(128))?;
    let Some((ip, port)) = parse_sockaddr(&bytes) else {
        return Ok(None);
    };

    Ok(Some(NetworkTarget {
        host: ip.to_string(),
        connect_host: ip.to_string(),
        port,
        scheme: scheme.to_string(),
    }))
}

pub fn target_from_notification(notif: &SeccompNotif) -> io::Result<Option<NetworkTarget>> {
    match i64::from(notif.data.nr) {
        nr::SENDTO => target_from_sendto(notif),
        nr::CONNECT => target_from_connect(notif),
        nr::SENDMSG => target_from_sendmsg(notif),
        nr::SENDMMSG => target_from_sendmmsg(notif),
        _ => Ok(None),
    }
}

pub async fn check_target(
    policy_socket: &Path,
    target: &NetworkTarget,
    sandbox_session_id: Option<String>,
    pid: u32,
    timeout: Duration,
) -> bool {
    let mut ctx = RequestContext::from_paths_and_ids(
        &SandboxPaths::default(),
        ProcessIds::from_options(Some(pid), None),
    );
    ctx.sandbox_session_id = sandbox_session_id;
    let req = RpcRequest::Check {
        host: Some(target.host.clone()),
        connect_host: Some(target.connect_host.clone()),
        port: Some(target.port),
        scheme: target.scheme.clone(),
        url: Some(format!(
            "{}://{}:{}",
            target.scheme, target.host, target.port
        )),
        ctx,
    };
    matches!(
        policy_rpc(&policy_socket.display().to_string(), req, timeout).await,
        Ok(RpcReply::Check(reply)) if reply.allowed
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_sockaddr, scheme_for_socket_type};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parse_ipv4_sockaddr() {
        let bytes = [2, 0, 0, 53, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&bytes),
            Some((IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53))
        );
    }

    #[test]
    fn parse_ipv4_sockaddr_port_zero() {
        // Port 0 in a sockaddr is 'unspecified'. sockaddr_target drops these
        // before sending a Check RPC; parse_sockaddr still returns the raw
        // value so the caller can decide.
        let bytes = [2, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&bytes),
            Some((IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 0))
        );
    }
    #[test]
    fn scheme_for_socket_type_dgram_is_udp() {
        assert_eq!(scheme_for_socket_type(libc::SOCK_DGRAM), "udp");
    }

    #[test]
    fn scheme_for_socket_type_stream_is_tcp() {
        assert_eq!(scheme_for_socket_type(libc::SOCK_STREAM), "tcp");
    }

    #[test]
    fn scheme_for_socket_type_raw_and_seqpacket_are_tcp() {
        // Policyd only knows tcp/udp today; raw and seqpacket default to tcp.
        assert_eq!(scheme_for_socket_type(libc::SOCK_RAW), "tcp");
        assert_eq!(scheme_for_socket_type(libc::SOCK_SEQPACKET), "tcp");
    }
    mod msghdr_tests {
        use super::super::parse_msghdr_target;

        #[test]
        fn parse_msghdr_target_extracts_namelen_and_name() {
            let mut bytes = [0u8; 56];
            bytes[0..8].copy_from_slice(&0x1000_u64.to_ne_bytes());
            bytes[8..12].copy_from_slice(&16_u32.to_ne_bytes());
            assert_eq!(parse_msghdr_target(&bytes), Some((0x1000, 16)));
        }

        #[test]
        fn parse_msghdr_target_handles_short_buffer() {
            let bytes = [0u8; 4];
            assert_eq!(parse_msghdr_target(&bytes), None);
        }

        #[test]
        fn parse_msghdr_target_handles_null_name() {
            let bytes = [0u8; 56];
            assert_eq!(parse_msghdr_target(&bytes), None);
        }
    }
}
