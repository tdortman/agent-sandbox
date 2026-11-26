//! Whether a downstream client closed its socket completely.
//!
//! A client that gave up on a request (a timeout, a killed tool) usually just
//! closes its socket, and the proxy sees only a FIN, which is also what a
//! `shutdown(SHUT_WR)` after a complete request looks like. The two differ on
//! the client's side. After a full close the kernel keeps the client socket
//! only as an orphan: it has no inode any more. After a half-close the socket
//! is still owned by a descriptor and keeps its inode. The proxy runs in the
//! network namespace its clients use, so the client socket is in its socket
//! table, and `inet_diag` reports the inode to any user: the dump needs no
//! capability.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::{
        socket::{
            AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recvfrom,
            sendto, setsockopt, socket, sockopt,
        },
        time::{TimeVal, TimeValLike as _},
    },
};

const NETLINK_HEADER_LEN: usize = 16;
const INET_DIAG_REQUEST_LEN: usize = 56;
const INET_DIAG_MESSAGE_LEN: usize = 72;
const DIAG_BUFFER_LEN: usize = 64 * 1024;
const DIAG_TIMEOUT: Duration = Duration::from_millis(100);
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NLM_F_DUMP_INTR: u16 = 0x0010;
const NLMSG_NOOP: u16 = 0x0001;
const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_DONE: u16 = 0x0003;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const TCPF_ALL: u32 = 0x0FFF;

/// What the socket table says about a client's end of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSocket {
    /// A descriptor still owns the socket: the client is alive, possibly
    /// half-closed.
    Open,
    /// The socket is an orphan: the client closed it completely.
    Closed,
    /// The table has no answer: the socket is not visible from here, or the
    /// query failed.
    Unknown,
}

/// Look up the socket bound to `client` (the address the proxy sees as the
/// peer) in the socket table. Runs the netlink dump on a blocking thread.
pub async fn client_socket(client: SocketAddr) -> ClientSocket {
    tokio::task::spawn_blocking(move || query(client).unwrap_or(ClientSocket::Unknown))
        .await
        .unwrap_or(ClientSocket::Unknown)
}

/// One socket of the dump.
struct Bound {
    /// Whether it is bound to the client's address.
    matches: bool,
    inode: u32,
}

fn query(client: SocketAddr) -> Option<ClientSocket> {
    let family = match client.ip() {
        IpAddr::V4(_) => u8::try_from(nix::libc::AF_INET).ok()?,
        IpAddr::V6(_) => u8::try_from(nix::libc::AF_INET6).ok()?,
    };
    let request = build_request(client, family)?;

    let socket = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )
    .ok()?;
    let timeout = TimeVal::milliseconds(i64::try_from(DIAG_TIMEOUT.as_millis()).ok()?);
    setsockopt(&socket, sockopt::ReceiveTimeout, &timeout).ok()?;
    bind(socket.as_raw_fd(), &NetlinkAddr::new(0, 0)).ok()?;
    let sent = sendto(
        socket.as_raw_fd(),
        &request,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )
    .ok()?;
    if sent != request.len() {
        return None;
    }

    let deadline = Instant::now() + DIAG_TIMEOUT;
    let mut buffer = vec![0_u8; DIAG_BUFFER_LEN];
    let mut bound = Vec::new();

    loop {
        if Instant::now() >= deadline {
            return None;
        }

        match recvfrom::<NetlinkAddr>(socket.as_raw_fd(), &mut buffer) {
            Ok((length, sender)) => {
                // A full buffer may have been truncated.
                if length == 0
                    || length == buffer.len()
                    || !sender.is_some_and(|sender| sender.pid() == 0 && sender.groups() == 0)
                {
                    return None;
                }
                if parse_datagram(&buffer[..length], client, &mut bound)? {
                    break;
                }
            }
            Err(Errno::EINTR) => {}
            Err(_) => return None,
        }
    }

    Some(if bound.iter().any(|socket| socket.inode != 0) {
        ClientSocket::Open
    } else if bound.is_empty() {
        ClientSocket::Unknown
    } else {
        ClientSocket::Closed
    })
}

/// A dump request for every TCP socket whose local port is the client's.
fn build_request(client: SocketAddr, family: u8) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(INET_DIAG_REQUEST_LEN);
    body.push(family);
    body.push(u8::try_from(nix::libc::IPPROTO_TCP).ok()?);
    body.push(0);
    body.push(0);
    body.extend(TCPF_ALL.to_ne_bytes());
    body.extend(client.port().to_be_bytes());
    body.extend(0_u16.to_be_bytes());
    // Source and destination address wildcards, interface, cookie.
    body.extend([0_u8; 32]);
    body.extend(0_u32.to_ne_bytes());
    body.extend(u32::MAX.to_ne_bytes());
    body.extend(u32::MAX.to_ne_bytes());
    if body.len() != INET_DIAG_REQUEST_LEN {
        return None;
    }

    let length = u32::try_from(NETLINK_HEADER_LEN + body.len()).ok()?;
    let mut request = Vec::with_capacity(NETLINK_HEADER_LEN + body.len());
    request.extend(length.to_ne_bytes());
    request.extend(SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request.extend((NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request.extend(1_u32.to_ne_bytes());
    request.extend(0_u32.to_ne_bytes());
    request.extend(body);
    Some(request)
}

/// Collect the dump's sockets bound to `client`. `Some(true)` once the dump
/// is complete, `None` on anything malformed.
fn parse_datagram(datagram: &[u8], client: SocketAddr, bound: &mut Vec<Bound>) -> Option<bool> {
    let mut offset = 0;
    let mut done = false;

    while offset < datagram.len() {
        let remaining = datagram.len() - offset;
        if done || remaining < NETLINK_HEADER_LEN {
            return None;
        }

        let length = usize::try_from(read_u32(datagram, offset)?).ok()?;
        if length < NETLINK_HEADER_LEN || length > remaining {
            return None;
        }
        let kind = u16::from_ne_bytes(datagram.get(offset + 4..offset + 6)?.try_into().ok()?);
        let flags = u16::from_ne_bytes(datagram.get(offset + 6..offset + 8)?.try_into().ok()?);
        if flags & NLM_F_DUMP_INTR != 0 {
            return None;
        }
        let payload = &datagram[offset + NETLINK_HEADER_LEN..offset + length];

        match kind {
            NLMSG_NOOP => {}
            NLMSG_ERROR => {
                if i32::from_ne_bytes(payload.get(..4)?.try_into().ok()?) != 0 {
                    return None;
                }
            }
            NLMSG_DONE => done = true,
            SOCK_DIAG_BY_FAMILY => {
                let socket = parse_entry(payload, client)?;
                if socket.matches {
                    bound.push(socket);
                }
            }
            _ => return None,
        }

        offset += (length + 3) & !3;
    }

    Some(done)
}

/// One `inet_diag_msg`.
fn parse_entry(payload: &[u8], client: SocketAddr) -> Option<Bound> {
    if payload.len() < INET_DIAG_MESSAGE_LEN {
        return None;
    }

    let local_port = u16::from_be_bytes(payload.get(4..6)?.try_into().ok()?);
    let local_ip = match client.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(payload.get(8..12)?).ok()?,
        )),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(payload.get(8..24)?).ok()?,
        )),
    };

    Some(Bound {
        matches: local_port == client.port() && local_ip == client.ip(),
        inode: read_u32(payload, 68)?,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    use super::{ClientSocket, client_socket};

    #[tokio::test]
    async fn half_close_keeps_the_client_socket_owned_and_a_full_close_orphans_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().expect("address"))
            .await
            .expect("connect");
        let client_address = client.local_addr().expect("client address");
        let (_server, _) = listener.accept().await.expect("accept");

        assert_eq!(client_socket(client_address).await, ClientSocket::Open);

        client.shutdown().await.expect("half-close");
        assert_eq!(
            client_socket(client_address).await,
            ClientSocket::Open,
            "a shutdown(SHUT_WR) leaves the socket owned"
        );

        drop(client);
        assert_eq!(
            client_socket(client_address).await,
            ClientSocket::Closed,
            "a close() leaves an orphan with no inode"
        );
    }

    #[tokio::test]
    async fn an_address_with_no_socket_is_unknown() {
        let address = "127.0.0.1:1".parse().expect("address");
        assert_eq!(client_socket(address).await, ClientSocket::Unknown);
    }
}
