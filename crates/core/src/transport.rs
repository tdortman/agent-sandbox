//! Shared transport-protocol vocabulary and the HTTP(S) scheme table.
//!
//! One decision table answers "which protocol and port is a transparent-proxy
//! HTTP(S) service port, and what scheme does it get". The enforcement crates
//! (syscall-broker, nfq, policyd, cli) consume this table instead of carrying
//! their own copies.

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

/// The scheme a flow on `port` is classified as.
///
/// The TCP HTTP(S) ports here plus the configured UDP ports (nfq defaults to
/// 443, HTTP/3 over QUIC) are the intercepted-flow port set. The table is the
/// single source for broker bypass, nfq flow routing, policyd check
/// classification, and cli URL rendering.
#[must_use]
pub const fn scheme_for(protocol: FlowProtocol, port: u16) -> &'static str {
    match (protocol, port) {
        (FlowProtocol::Tcp, 80 | 8008 | 8080) => "http",
        (FlowProtocol::Tcp, 443 | 8443) => "https",
        (FlowProtocol::Udp, 443) => "http3",
        (FlowProtocol::Tcp, _) => "tcp",
        (FlowProtocol::Udp, _) => "udp",
    }
}

/// Whether a flow is routed to the transparent proxy as an HTTP(S) service
/// port. This is the broker bypass list and the nfq TCP proxy-flow set.
#[must_use]
pub fn is_http_service_port(protocol: FlowProtocol, port: u16) -> bool {
    matches!(scheme_for(protocol, port), "http" | "https")
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
    /// Loopback never traverses the transparent route in either case.
    #[must_use]
    pub fn flow_owner(&self, protocol: FlowProtocol, dst_ip: IpAddr, dst_port: u16) -> FlowOwner {
        let owned = self.proxy_mode
            && !dst_ip.is_loopback()
            && match protocol {
                FlowProtocol::Tcp => is_http_service_port(FlowProtocol::Tcp, dst_port),
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
    /// In proxy mode the packet filter queues every new UDP flow for one
    /// deduped transport check, so a per-syscall prompt would double-gate;
    /// the gate therefore skips all UDP targets. Registered HTTP(S) service
    /// ports are decoded by the proxy backend per request. The configured DNS
    /// endpoint is infrastructure traffic in every mode.
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

        (target_scheme == "tcp" && is_http_service_port(FlowProtocol::Tcp, target_port))
            || target_scheme == "udp"
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };

    use super::{FlowOwner, FlowProtocol, NetworkOwnership, is_http_service_port, scheme_for};
    #[test]
    fn scheme_table_matches_the_intercepted_proxy_ports() {
        for port in [80, 8008, 8080] {
            assert_eq!(scheme_for(FlowProtocol::Tcp, port), "http");
        }

        // tcp:443 and tcp:8443 are HTTPS service ports, not bare tcp flows.
        for port in [443, 8443] {
            assert_eq!(scheme_for(FlowProtocol::Tcp, port), "https");
        }

        assert_eq!(scheme_for(FlowProtocol::Udp, 443), "http3");
        assert_eq!(scheme_for(FlowProtocol::Tcp, 853), "tcp");
        assert_eq!(scheme_for(FlowProtocol::Udp, 53), "udp");
        assert!(is_http_service_port(FlowProtocol::Tcp, 443));
        assert!(!is_http_service_port(FlowProtocol::Tcp, 853));
        assert!(!is_http_service_port(FlowProtocol::Udp, 443));
    }

    fn ownership(proxy_mode: bool, udp_ports: &[u16]) -> NetworkOwnership {
        NetworkOwnership {
            proxy_mode,
            udp_proxy_ports: udp_ports.to_vec(),
        }
    }

    #[test]
    fn proxy_backed_flows_need_proxy_mode_and_public_service_ports() {
        let owner = ownership(true, &[443]);

        assert_eq!(
            owner.flow_owner(
                FlowProtocol::Tcp,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443
            ),
            FlowOwner::ProxyBackend
        );

        // Non-service TCP ports stay on the direct policy path.
        assert_eq!(
            owner.flow_owner(
                FlowProtocol::Tcp,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                853
            ),
            FlowOwner::DirectPolicy
        );

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

        // Proxy mode: service ports and every UDP target skip the gate.
        assert!(owner.syscall_gate_skips("tcp", "93.184.216.34", 443, None));
        assert!(owner.syscall_gate_skips("tcp", "example.com", 8443, None));
        assert!(owner.syscall_gate_skips("udp", "93.184.216.34", 9999, None));
        assert!(!owner.syscall_gate_skips("tcp", "93.184.216.34", 853, None));

        // Direct mode gates everything except the DNS endpoint.
        let direct = ownership(false, &[]);
        assert!(!direct.syscall_gate_skips("tcp", "93.184.216.34", 443, None));
        assert!(!direct.syscall_gate_skips("udp", "93.184.216.34", 9999, None));
        assert!(direct.syscall_gate_skips("udp", "169.254.100.1", 53, Some(dns)));
    }

    #[test]
    fn scheme_table_matches_the_service_port_set_via_is_http_service_port() {
        assert!(is_http_service_port(FlowProtocol::Tcp, 8080));
        assert!(is_http_service_port(FlowProtocol::Tcp, 8443));
        assert!(!is_http_service_port(FlowProtocol::Udp, 53));
    }
}
