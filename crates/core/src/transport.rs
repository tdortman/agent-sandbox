//! Shared transport-protocol vocabulary and the HTTP(S) scheme table.
//!
//! One decision table answers "which protocol and port is a transparent-proxy
//! HTTP(S) service port, and what scheme does it get". The enforcement crates
//! (syscall-broker, nfq, policyd, cli) consume this table instead of carrying
//! their own copies.

use serde::{Deserialize, Serialize};

/// Transport protocol attached to a registered flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

impl FlowProtocol {
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

#[cfg(test)]
mod tests {
    use super::{FlowProtocol, is_http_service_port, scheme_for};

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
}
