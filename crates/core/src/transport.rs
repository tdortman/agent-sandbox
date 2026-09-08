//! Shared transport-protocol vocabulary and flow ownership.
//!
//! Ports do not identify protocols, so TCP carries no scheme table: every
//! non-loopback TCP flow in proxy mode registers for the transparent proxy,
//! which peeks at the first stream bytes (`crate::sniff`) to choose between
//! the HTTP(S) path and a raw passthrough. UDP keeps one configured
//! intercept port (QUIC needs a bound socket per port), but the payload
//! still decides: only long-header QUIC registers for the HTTP/3 backend.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Transport protocol attached to a registered flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProtocol {
    /// TCP transport.
    Tcp,

    /// UDP transport.
    Udp,
}

impl FlowProtocol {
    /// The lower-case wire name of this protocol (`"tcp"` or `"udp"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// The scheme label for a flow on `port`.
///
/// TCP is always `"tcp"`: whether it carries HTTP is only known after the
/// proxy sniffs the stream. UDP 443 keeps its `"http3"` label for the
/// configured HTTP/3 intercept port; everything else is `"udp"`.
#[must_use]
pub const fn scheme_for(protocol: FlowProtocol, port: u16) -> &'static str {
    match (protocol, port) {
        (FlowProtocol::Udp, 443) => "http3",
        (FlowProtocol::Tcp, _) => "tcp",
        (FlowProtocol::Udp, _) => "udp",
    }
}

/// Which layer owns a flow's policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOwner {
    /// The transparent proxy backend decodes and authorises the flow.
    ProxyBackend,

    /// The packet classifier consults policy directly for this flow.
    DirectPolicy,
}

/// The proxy-ownership facts the syscall gate and the packet classifier must
/// agree on: whether proxy mode is on and which UDP ports belong to the
/// transparent HTTP/3 route.
#[derive(Debug, Clone)]
pub struct NetworkOwnership {
    /// Whether sandbox flows are routed through the transparent proxy.
    pub proxy_mode: bool,

    /// UDP ports registered for the transparent HTTP/3 proxy. Only consulted
    /// by the packet classifier; the syscall gate skips every UDP target in
    /// proxy mode because the packet filter owns that decision.
    pub udp_proxy_ports: Vec<u16>,
}

impl NetworkOwnership {
    /// Classify one queued flow: does it register for the transparent proxy
    /// backend, or stay on the direct policy path?
    ///
    /// Every TCP flow registers: the proxy sniffs the stream to tell HTTP
    /// apart from raw TCP. UDP registers on its configured intercept ports;
    /// the QUIC payload check happens against the queued datagram. Loopback
    /// never traverses the transparent route in either case.
    #[must_use]
    pub fn flow_owner(&self, protocol: FlowProtocol, dst_ip: IpAddr, dst_port: u16) -> FlowOwner {
        let owned = self.proxy_mode
            && !dst_ip.is_loopback()
            && match protocol {
                FlowProtocol::Tcp => true,
                FlowProtocol::Udp => self.udp_proxy_ports.contains(&dst_port),
            };

        if owned {
            FlowOwner::ProxyBackend
        } else {
            FlowOwner::DirectPolicy
        }
    }

    /// Broker question: may the syscall gate skip this target because another
    /// layer already owns its policy decision?
    ///
    /// In proxy mode the packet filter queues every TCP `SYN` for proxy
    /// registration and every new UDP flow for one deduped transport check,
    /// so a per-syscall prompt would double-gate; the gate therefore skips
    /// all TCP and UDP targets. The configured DNS endpoint is
    /// infrastructure traffic in every mode.
    #[must_use]
    pub fn syscall_gate_skips(
        &self,
        target_scheme: &str,
        target_host: &str,
        target_port: u16,
        dns_endpoint: Option<SocketAddr>,
    ) -> bool {
        if dns_endpoint.is_some_and(|endpoint| {
            endpoint.port() == target_port && target_host.parse() == Ok(endpoint.ip())
        }) {
            return true;
        }

        if !self.proxy_mode {
            return false;
        }

        target_scheme == "tcp" || target_scheme == "udp"
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };

    use super::{FlowOwner, FlowProtocol, NetworkOwnership, scheme_for};

    #[test]
    fn tcp_has_no_scheme_table() {
        // Ports do not identify protocols: every TCP flow is plain "tcp"
        // until the proxy sniffs the stream.
        for port in [0, 53, 80, 443, 8008, 8080, 8443, 853, 9443, 3000] {
            assert_eq!(scheme_for(FlowProtocol::Tcp, port), "tcp");
        }

        assert_eq!(scheme_for(FlowProtocol::Udp, 443), "http3");
        assert_eq!(scheme_for(FlowProtocol::Udp, 53), "udp");
        assert_eq!(scheme_for(FlowProtocol::Udp, 8443), "udp");
    }

    fn ownership(proxy_mode: bool, udp_ports: &[u16]) -> NetworkOwnership {
        NetworkOwnership {
            proxy_mode,
            udp_proxy_ports: udp_ports.to_vec(),
        }
    }

    #[test]
    fn proxy_backed_flows_need_proxy_mode() {
        let owner = ownership(true, &[443]);

        // Every TCP flow registers: the proxy sniffs HTTP apart from raw TCP.
        for port in [80, 443, 853, 9443, 3000] {
            assert_eq!(
                owner.flow_owner(
                    FlowProtocol::Tcp,
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    port
                ),
                FlowOwner::ProxyBackend,
                "tcp:{port}"
            );
        }

        // Only configured UDP ports register for the HTTP/3 route.
        assert_eq!(
            owner.flow_owner(
                FlowProtocol::Udp,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443
            ),
            FlowOwner::ProxyBackend
        );

        assert_eq!(
            owner.flow_owner(
                FlowProtocol::Udp,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                8080
            ),
            FlowOwner::DirectPolicy
        );

        // Loopback never traverses the transparent route.
        assert_eq!(
            owner.flow_owner(FlowProtocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            FlowOwner::DirectPolicy
        );

        // Direct mode registers nothing for the proxy backend.
        let direct = ownership(false, &[443]);

        assert_eq!(
            direct.flow_owner(
                FlowProtocol::Tcp,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443
            ),
            FlowOwner::DirectPolicy
        );
    }

    #[test]
    fn syscall_gate_skips_only_what_another_layer_owns() {
        let dns = SocketAddr::from_str("169.254.100.1:53").expect("dns endpoint");
        let owner = ownership(true, &[443]);

        // The DNS endpoint is infrastructure in every mode.
        assert!(owner.syscall_gate_skips("udp", "169.254.100.1", 53, Some(dns)));

        // Mismatched host or port falls through to the mode rules, which in
        // direct mode gate every non-DNS target.
        let direct = ownership(false, &[]);

        assert!(!direct.syscall_gate_skips("udp", "169.254.100.2", 53, Some(dns)));
        assert!(!direct.syscall_gate_skips("udp", "169.254.100.1", 54, Some(dns)));

        // Proxy mode: every TCP target and every UDP target skips the gate.
        for port in [80, 443, 853, 8443, 9443] {
            assert!(owner.syscall_gate_skips("tcp", "93.184.216.34", port, None));
        }

        assert!(owner.syscall_gate_skips("tcp", "example.com", 8443, None));
        assert!(owner.syscall_gate_skips("udp", "93.184.216.34", 9999, None));

        // Direct mode gates everything except the DNS endpoint.
        let direct = ownership(false, &[]);

        assert!(!direct.syscall_gate_skips("tcp", "93.184.216.34", 443, None));
        assert!(!direct.syscall_gate_skips("udp", "93.184.216.34", 9999, None));
        assert!(direct.syscall_gate_skips("udp", "169.254.100.1", 53, Some(dns)));
    }
}
