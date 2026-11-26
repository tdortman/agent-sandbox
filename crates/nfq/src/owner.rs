//! NFQ compatibility wrapper for shared procfs socket-owner resolution.

#[cfg(test)]
use std::net::IpAddr;

use agent_sandbox_core::{
    OwnerResolution, OwnerSnapshot, SocketProtocol, SocketTuple, resolve_owner_snapshot,
    socket_owner::KernelOwnerResolver,
};

use crate::packet::TransportProtocol;

/// Find the checked process/socket snapshot matching the supplied tuple,
/// preserving ambiguous ownership for fail-closed enforcement.
///
/// NFQ uses the snapshot as a capability: the owner identity and tuple were
/// read together from procfs, so a later policy/proxy registration cannot
/// accidentally attribute a recycled PID or inode.
#[must_use]
pub fn owner_resolution(
    kernel: Option<&KernelOwnerResolver>,
    protocol: TransportProtocol,
    tuple: SocketTuple,
) -> OwnerResolution<OwnerSnapshot> {
    let protocol = match protocol {
        TransportProtocol::Tcp => SocketProtocol::Tcp,
        TransportProtocol::Udp => SocketProtocol::Udp,
    };

    if let Some(kernel) = kernel {
        match kernel.resolve(protocol, tuple) {
            Ok(owner) => {
                tracing::debug!("kernel owner query completed");
                return owner;
            }

            Err(error) => {
                tracing::debug!(%error, "kernel owner query failed; resolving through procfs");
            }
        }
    }

    retry_missing(|| resolve_owner_snapshot(protocol, tuple))
}

/// Procfs socket tables are read in several `read` calls and are not a
/// snapshot: a socket opened or closed elsewhere in the namespace between two
/// calls can make the table skip a live socket's line. A flow whose socket
/// owner is not found is dropped, so a single torn read would drop a
/// legitimate flow. The owner is declared missing only after this many
/// consecutive misses; an ambiguous or unique answer is final.
const MISSING_OWNER_ATTEMPTS: u32 = 4;

fn retry_missing<T>(mut resolve: impl FnMut() -> OwnerResolution<T>) -> OwnerResolution<T> {
    for _ in 1..MISSING_OWNER_ATTEMPTS {
        match resolve() {
            OwnerResolution::Missing => {}
            found => return found,
        }
    }

    resolve()
}

#[cfg(test)]
pub fn owner_snapshot(
    protocol: TransportProtocol,
    src_ip: IpAddr,
    src_port: u16,
) -> Option<OwnerSnapshot> {
    match owner_resolution(None, protocol, SocketTuple::from_local(src_ip, src_port)) {
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

        let tuple = SocketTuple::new(
            client_addr.ip(),
            client_addr.port(),
            listener_addr.ip(),
            listener_addr.port(),
        );

        assert!(matches!(
            owner_resolution(None, TransportProtocol::Tcp, tuple),
            OwnerResolution::Unique(owner) if owner.pid_value() == std::process::id()
        ));
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;

    #[test]
    fn a_torn_read_that_misses_the_owner_once_is_retried() {
        let mut answers = vec![
            OwnerResolution::Missing,
            OwnerResolution::Missing,
            OwnerResolution::Unique(7_u32),
        ]
        .into_iter();

        let resolved = retry_missing(|| answers.next().expect("no further attempt"));

        assert_eq!(resolved, OwnerResolution::Unique(7));
    }

    #[test]
    fn an_ambiguous_owner_is_final() {
        let mut attempts = 0_u32;

        let resolved = retry_missing(|| {
            attempts += 1;
            OwnerResolution::<u32>::Ambiguous
        });

        assert_eq!(resolved, OwnerResolution::Ambiguous);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn a_socket_that_stays_missing_is_missing_after_bounded_attempts() {
        let mut attempts = 0_u32;

        let resolved = retry_missing(|| {
            attempts += 1;
            OwnerResolution::<u32>::Missing
        });

        assert_eq!(resolved, OwnerResolution::Missing);
        assert_eq!(attempts, MISSING_OWNER_ATTEMPTS);
    }
}
