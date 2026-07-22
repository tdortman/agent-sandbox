//! NFQ compatibility wrapper for shared procfs socket-owner resolution.

use std::net::IpAddr;

use agent_sandbox_core::{
    OwnerResolution, OwnerSnapshot, SocketProtocol, SocketTuple, resolve_owner_snapshot,
};

use crate::packet::TransportProtocol;

/// Find the checked process/socket snapshot for the socket bound to
/// `src_ip:src_port`.
///
/// NFQ uses the snapshot as a capability: the owner identity and tuple were
/// read together from procfs, so a later policy/proxy registration cannot
/// accidentally attribute a recycled PID or inode.
#[must_use]
pub fn owner_snapshot(
    protocol: TransportProtocol,
    src_ip: IpAddr,
    src_port: u16,
) -> Option<OwnerSnapshot> {
    let protocol = match protocol {
        TransportProtocol::Tcp => SocketProtocol::Tcp,
        TransportProtocol::Udp => SocketProtocol::Udp,
    };
    let tuple = SocketTuple::from_local(src_ip, src_port);
    match resolve_owner_snapshot(protocol, tuple) {
        OwnerResolution::Unique(snapshot) => Some(snapshot),
        OwnerResolution::Missing | OwnerResolution::Ambiguous => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn owner_snapshot_resolves_current_process_for_loopback_tcp_client() {
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        let listener_addr = listener.local_addr().expect("listener address");
        let client = std::net::TcpStream::connect(listener_addr).expect("connect loopback client");
        let (_server, _) = listener.accept().expect("accept loopback client");
        let client_addr = client.local_addr().expect("client local address");

        let resolved_pid =
            owner_snapshot(TransportProtocol::Tcp, client_addr.ip(), client_addr.port())
                .map(OwnerSnapshot::pid_value);

        assert_eq!(resolved_pid, Some(std::process::id()));
    }
}
