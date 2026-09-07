use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
    sync::atomic::{AtomicU32, Ordering},
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

use super::{SocketInode, SocketTableEntry, SocketTuple};

const NETLINK_HEADER_LEN: usize = 16;
const INET_DIAG_REQUEST_LEN: usize = 56;
const INET_DIAG_MESSAGE_LEN: usize = 72;
const DIAG_BUFFER_LEN: usize = 64 * 1024;
const DIAG_RECEIVE_TIMEOUT: Duration = Duration::from_millis(25);
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NLM_F_DUMP_INTR: u16 = 0x0010;
const NLMSG_NOOP: u16 = 0x0001;
const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_DONE: u16 = 0x0003;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const TCPF_ALL: u32 = 0x0FFF;
static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DiagError;

pub(super) fn entries(tuple: SocketTuple) -> Result<Vec<SocketTableEntry>, DiagError> {
    if tuple.local_port == 0 {
        return Ok(Vec::new());
    }

    let family = u8::try_from(address_family(tuple.local_ip)).map_err(|_| DiagError)?;

    if tuple.remote_port != 0 && address_family(tuple.remote_ip) != i32::from(family) {
        return Err(DiagError);
    }

    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let request = build_request(tuple, family, sequence)?;

    let socket = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )
    .map_err(|_| DiagError)?;

    setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::milliseconds(25))
        .map_err(|_| DiagError)?;

    let local = NetlinkAddr::new(0, 0);
    bind(socket.as_raw_fd(), &local).map_err(|_| DiagError)?;
    let kernel = NetlinkAddr::new(0, 0);

    let sent =
        sendto(socket.as_raw_fd(), &request, &kernel, MsgFlags::empty()).map_err(|_| DiagError)?;

    if sent != request.len() {
        return Err(DiagError);
    }

    let deadline = Instant::now() + DIAG_RECEIVE_TIMEOUT;
    let mut buffer = vec![0u8; DIAG_BUFFER_LEN];
    let mut entries = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());

        if remaining.is_zero() {
            return Err(DiagError);
        }

        match recvfrom::<NetlinkAddr>(socket.as_raw_fd(), &mut buffer) {
            Ok((length, sender)) => {
                // recvfrom does not expose MSG_TRUNC. Treat a full buffer as
                // truncated instead of accepting a possibly partial dump.
                if length == 0 || length == buffer.len() || !is_kernel_sender(sender) {
                    return Err(DiagError);
                }

                if parse_datagram(&buffer[..length], sequence, family, tuple, &mut entries)? {
                    return Ok(entries);
                }
            }

            Err(Errno::EINTR) => {}
            Err(_) => return Err(DiagError),
        }
    }
}

const fn address_family(ip: IpAddr) -> i32 {
    match ip {
        IpAddr::V4(_) => libc::AF_INET,
        IpAddr::V6(_) => libc::AF_INET6,
    }
}

fn build_request(tuple: SocketTuple, family: u8, sequence: u32) -> Result<Vec<u8>, DiagError> {
    let remote = tuple.remote_port != 0;
    let mut body = Vec::with_capacity(INET_DIAG_REQUEST_LEN);
    body.push(family);
    body.push(u8::try_from(libc::IPPROTO_TCP).map_err(|_| DiagError)?);
    body.push(0);
    body.push(0);
    body.extend(TCPF_ALL.to_ne_bytes());

    // idiag_sport is the kernel's local source-port filter. Keep the source
    // address wildcarded so both exact and wildcard local listeners remain
    // visible to NFQ's local-only attribution. A bytecode filter adds no
    // selectivity for this one field.
    body.extend(tuple.local_port.to_be_bytes());

    body.extend(if remote {
        tuple.remote_port.to_be_bytes()
    } else {
        0u16.to_be_bytes()
    });

    append_address(&mut body, None, family)?;
    append_address(&mut body, remote.then_some(tuple.remote_ip), family)?;
    body.extend(0u32.to_ne_bytes());
    body.extend(u32::MAX.to_ne_bytes());
    body.extend(u32::MAX.to_ne_bytes());

    if body.len() != INET_DIAG_REQUEST_LEN {
        return Err(DiagError);
    }

    let message_len = NETLINK_HEADER_LEN
        .checked_add(body.len())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(DiagError)?;

    let mut request = Vec::with_capacity(message_len as usize);
    request.extend(message_len.to_ne_bytes());
    request.extend(SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request.extend((NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request.extend(sequence.to_ne_bytes());
    request.extend(0u32.to_ne_bytes());
    request.extend(body);
    Ok(request)
}

fn append_address(
    output: &mut Vec<u8>,
    address: Option<IpAddr>,
    family: u8,
) -> Result<(), DiagError> {
    match (i32::from(family), address) {
        (libc::AF_INET | libc::AF_INET6, None) => {
            output.extend([0; 16]);
        }

        (libc::AF_INET, Some(IpAddr::V4(address))) => {
            output.extend(address.octets());
            output.extend([0; 12]);
        }

        (libc::AF_INET6, Some(IpAddr::V6(address))) => {
            output.extend(address.octets());
        }

        _ => return Err(DiagError),
    }

    Ok(())
}

fn is_kernel_sender(sender: Option<NetlinkAddr>) -> bool {
    sender.is_some_and(|sender| sender.pid() == 0 && sender.groups() == 0)
}

fn parse_datagram(
    datagram: &[u8],
    sequence: u32,
    family: u8,
    tuple: SocketTuple,
    entries: &mut Vec<SocketTableEntry>,
) -> Result<bool, DiagError> {
    if datagram.is_empty() {
        return Err(DiagError);
    }

    let mut offset = 0;
    let mut done = false;

    while offset < datagram.len() {
        if done {
            return Err(DiagError);
        }

        let remaining = datagram.len() - offset;

        if remaining < NETLINK_HEADER_LEN {
            return Err(DiagError);
        }

        let message_len = read_u32(datagram, offset)? as usize;

        if message_len < NETLINK_HEADER_LEN || message_len > remaining {
            return Err(DiagError);
        }

        let aligned_len = message_len.checked_add(3).ok_or(DiagError)? & !3;

        if aligned_len > remaining {
            return Err(DiagError);
        }

        let message_type = u16::from_ne_bytes(
            datagram[offset + 4..offset + 6]
                .try_into()
                .map_err(|_| DiagError)?,
        );

        let flags = u16::from_ne_bytes(
            datagram[offset + 6..offset + 8]
                .try_into()
                .map_err(|_| DiagError)?,
        );

        let message_sequence = read_u32(datagram, offset + 8)?;

        // The header port ID names the receiver; recvfrom authenticates the kernel
        // sender.
        if message_sequence != sequence {
            return Err(DiagError);
        }

        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(DiagError);
        }

        let payload_start = offset + NETLINK_HEADER_LEN;
        let payload_end = offset + message_len;
        let payload = &datagram[payload_start..payload_end];

        match message_type {
            NLMSG_NOOP => {}

            NLMSG_ERROR => {
                let error = i32::from_ne_bytes(
                    payload
                        .get(..4)
                        .ok_or(DiagError)?
                        .try_into()
                        .map_err(|_| DiagError)?,
                );
                if error != 0 {
                    return Err(DiagError);
                }
            }

            NLMSG_DONE => {
                if !payload.is_empty() && read_u32(payload, 0)? != 0 {
                    return Err(DiagError);
                }
                done = true;
            }

            SOCK_DIAG_BY_FAMILY => parse_entry(payload, family, tuple, entries)?,
            _ => return Err(DiagError),
        }

        offset += aligned_len;
    }

    Ok(done)
}

fn parse_entry(
    payload: &[u8],
    family: u8,
    tuple: SocketTuple,
    entries: &mut Vec<SocketTableEntry>,
) -> Result<(), DiagError> {
    if payload.len() < INET_DIAG_MESSAGE_LEN || payload[0] != family {
        return Err(DiagError);
    }

    let local_port = read_u16(payload, 4)?;

    if local_port != tuple.local_port {
        return Err(DiagError);
    }

    let remote_port = read_u16(payload, 6)?;
    let local_ip = decode_address(family, payload.get(8..24).ok_or(DiagError)?)?;
    let remote_ip = decode_address(family, payload.get(24..40).ok_or(DiagError)?)?;
    let uid = read_u32(payload, 64)?;

    let Ok(inode) = SocketInode::new(read_u32(payload, 68)? as u64) else {
        // TIME_WAIT and request sockets have no owning descriptor, as in procfs.
        return Ok(());
    };

    let wildcard_ip = match tuple.local_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    if local_ip != tuple.local_ip && local_ip != wildcard_ip {
        return Ok(());
    }

    if tuple.remote_port != 0 && (remote_port != tuple.remote_port || remote_ip != tuple.remote_ip)
    {
        return Ok(());
    }

    if let Some(existing) = entries.iter().find(|entry| entry.inode == inode) {
        if existing.uid != uid {
            return Err(DiagError);
        }
    } else {
        entries.push(SocketTableEntry { uid, inode });
    }

    Ok(())
}

fn decode_address(family: u8, bytes: &[u8]) -> Result<IpAddr, DiagError> {
    if bytes.len() != 16 {
        return Err(DiagError);
    }

    match i32::from(family) {
        libc::AF_INET => {
            if bytes[4..].iter().any(|byte| *byte != 0) {
                return Err(DiagError);
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }

        libc::AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| DiagError)?,
        ))),

        _ => Err(DiagError),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DiagError> {
    bytes
        .get(offset..offset + 2)
        .ok_or(DiagError)?
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| DiagError)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DiagError> {
    bytes
        .get(offset..offset + 4)
        .ok_or(DiagError)?
        .try_into()
        .map(u32::from_ne_bytes)
        .map_err(|_| DiagError)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use crate::socket_owner::SocketProtocol;

    fn message(message_type: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NETLINK_HEADER_LEN + payload.len();
        let aligned_length = (length + 3) & !3;
        let mut output = Vec::with_capacity(aligned_length);
        output.extend(
            u32::try_from(length)
                .expect("diagnostic test message length fits in u32")
                .to_ne_bytes(),
        );
        output.extend(message_type.to_ne_bytes());
        output.extend(flags.to_ne_bytes());
        output.extend(sequence.to_ne_bytes());
        output.extend(0u32.to_ne_bytes());
        output.extend(payload);
        output.resize(aligned_length, 0);
        output
    }

    fn entry_keys(entries: &[SocketTableEntry]) -> Vec<(u32, SocketInode)> {
        let mut keys: Vec<_> = entries
            .iter()
            .map(|entry| (entry.uid, entry.inode))
            .collect();

        keys.sort_unstable();
        keys
    }

    #[test]
    fn diag_dump_matches_proc_entries_and_requires_fast_path() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind TCP listener");
        let address = listener.local_addr().expect("listener address");
        let tuple = SocketTuple::from_local(address.ip(), address.port());
        let proc_entries = super::super::socket_table_entries_from_proc(SocketProtocol::Tcp, tuple);
        let diag_entries = entries(tuple).expect("NETLINK_SOCK_DIAG must be available");
        assert_eq!(entry_keys(&proc_entries), entry_keys(&diag_entries));
    }

    #[test]
    fn ipv4_and_ipv6_connected_tuples_match_procfs() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let listener = TcpListener::bind((ip, 0)).expect("loopback listener");
            let remote = listener.local_addr().expect("remote address");
            let client = std::net::TcpStream::connect(remote).expect("connect");
            let (_server, _) = listener.accept().expect("accept");
            let local = client.local_addr().expect("local address");

            for tuple in [
                SocketTuple::from_local(local.ip(), local.port()),
                SocketTuple::new(local.ip(), local.port(), remote.ip(), remote.port()),
            ] {
                let diag = entries(tuple).expect("complete diagnostic dump");
                assert_eq!(diag.len(), 1);

                assert_eq!(
                    entry_keys(&diag),
                    entry_keys(&super::super::socket_table_entries_from_proc(
                        SocketProtocol::Tcp,
                        tuple
                    ))
                );
            }
        }
    }

    #[tokio::test]
    async fn reused_listener_port_retains_every_owner() {
        let mut address = "127.0.0.1:0".parse().expect("loopback address");
        let socket = tokio::net::TcpSocket::new_v4().expect("TCP socket");
        socket.set_reuseport(true).expect("SO_REUSEPORT");
        socket.bind(address).expect("bind shared port");
        let first_listener = socket.listen(8).expect("listen");
        address = first_listener.local_addr().expect("listener address");

        let socket = tokio::net::TcpSocket::new_v4().expect("TCP socket");
        socket.set_reuseport(true).expect("SO_REUSEPORT");
        socket.bind(address).expect("bind shared port");
        let second_listener = socket.listen(8).expect("listen");
        let listeners = [first_listener, second_listener];

        let tuple = SocketTuple::from_local(address.ip(), address.port());
        let diag = entries(tuple).expect("complete diagnostic dump");
        assert_eq!(diag.len(), 2);

        assert_eq!(
            entry_keys(&diag),
            entry_keys(&super::super::socket_table_entries_from_proc(
                SocketProtocol::Tcp,
                tuple
            ))
        );

        assert_eq!(
            super::super::resolve_owner_snapshot(SocketProtocol::Tcp, tuple),
            super::super::OwnerResolution::Ambiguous
        );
        drop(listeners);
    }

    #[test]
    fn failed_dump_completion_is_rejected() {
        let datagram = message(NLMSG_DONE, 0, 1, &(-libc::EINVAL).to_ne_bytes());

        assert!(
            parse_datagram(
                &datagram,
                1,
                u8::try_from(libc::AF_INET).expect("IPv4 family fits u8"),
                SocketTuple::from_local(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                &mut Vec::new()
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_netlink_length_is_rejected() {
        let mut datagram = vec![0u8; NETLINK_HEADER_LEN];
        datagram[..4].copy_from_slice(&15u32.to_ne_bytes());

        assert!(
            parse_datagram(
                &datagram,
                1,
                u8::try_from(libc::AF_INET).expect("IPv4 family fits u8"),
                SocketTuple::from_local(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                &mut Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn truncated_multipart_dump_is_not_complete() {
        let datagram = message(NLMSG_NOOP, 0, 1, &[]);

        assert!(
            !parse_datagram(
                &datagram,
                1,
                u8::try_from(libc::AF_INET).expect("IPv4 family fits u8"),
                SocketTuple::from_local(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                &mut Vec::new(),
            )
            .expect("valid non-terminal message")
        );
    }

    #[test]
    fn interrupted_dump_is_rejected() {
        let datagram = message(NLMSG_DONE, NLM_F_DUMP_INTR, 1, &[]);

        assert!(
            parse_datagram(
                &datagram,
                1,
                u8::try_from(libc::AF_INET).expect("IPv4 family fits u8"),
                SocketTuple::from_local(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                &mut Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn kernel_error_is_rejected() {
        let datagram = message(NLMSG_ERROR, 0, 1, &(-libc::EINVAL).to_ne_bytes());

        assert!(
            parse_datagram(
                &datagram,
                1,
                u8::try_from(libc::AF_INET).expect("IPv4 family fits u8"),
                SocketTuple::from_local(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                &mut Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn sender_must_be_the_kernel() {
        assert!(is_kernel_sender(Some(NetlinkAddr::new(0, 0))));
        assert!(!is_kernel_sender(Some(NetlinkAddr::new(1, 0))));
        assert!(!is_kernel_sender(Some(NetlinkAddr::new(0, 1))));
        assert!(!is_kernel_sender(None));
    }
}
