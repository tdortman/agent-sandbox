//! First-byte protocol sniffing for transparent routing decisions.
//!
//! Port numbers do not identify protocols: HTTPS serves on 9443, dev servers
//! speak plain HTTP on 3000, and raw TCP (SSH, Postgres, SMTP) can appear on
//! any port. The routing decision therefore inspects bytes, not ports:
//!
//! - TCP: a `SYN` carries no payload, so NFQUEUE cannot classify it. Every TCP
//!   `SYN` is queued, the flow is registered for the proxy, and the proxy peeks
//!   (without consuming, via `MSG_PEEK`) at the first stream bytes to decide
//!   between the HTTP(S) path and a raw passthrough.
//! - UDP: the first datagram already carries its payload, so NFQUEUE checks for
//!   a QUIC long header directly. Per-port socket binds still steer UDP to the
//!   proxy listeners, but the payload decides the policy path.

/// Outcome of inspecting the first bytes of a TCP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSniff {
    /// TLS record header (`0x16 0x03xx`): terminate and HTTP-proxy.
    Tls,
    /// Plain HTTP request line (`GET `, `POST `, `PRI `, ...): HTTP-proxy.
    Http,
    /// Prefix is consistent with TLS or HTTP but too short to decide.
    NeedMore,
    /// Matches neither TLS nor HTTP: splice raw TCP upstream.
    Unknown,
}

/// Classify the first bytes of a downstream TCP stream.
///
/// Pure prefix match, safe to call on every `MSG_PEEK` refill: `NeedMore`
/// means "wait for more bytes", anything else is final.
#[must_use]
pub fn sniff_tcp(prefix: &[u8]) -> TcpSniff {
    let Some(&first) = prefix.first() else {
        return TcpSniff::NeedMore;
    };

    if first == 0x16 {
        // TLS handshake record: content type (0x16), version (major 3),
        // length. Three bytes pin it down; anything else starting with
        // 0x16 is some other protocol's length prefix.
        if prefix.len() < 3 {
            return TcpSniff::NeedMore;
        }
        return if prefix[1] == 0x03 && prefix[2] <= 0x04 {
            TcpSniff::Tls
        } else {
            TcpSniff::Unknown
        };
    }

    if !matches!(first, b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T') {
        // Outside every HTTP method's first byte (`PRI` covers h2c
        // prior-knowledge): SSH banners, Postgres startup, MySQL, SMTP
        // greetings waited out by the caller, etc. Decided immediately so
        // raw protocols pay no peek latency.
        return TcpSniff::Unknown;
    }

    // Candidates carry their trailing space so a bare `GETX` prefix cannot
    // match.
    const METHODS: [&[u8]; 10] = [
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"CONNECT ",
        b"OPTIONS ",
        b"TRACE ",
        b"PATCH ",
        b"PRI ",
    ];
    for method in METHODS {
        if prefix.len() < method.len() {
            if method.starts_with(prefix) {
                return TcpSniff::NeedMore;
            }
        } else if prefix.starts_with(method) {
            return TcpSniff::Http;
        }
    }
    TcpSniff::Unknown
}

/// Whether a UDP datagram opens a QUIC association (long header, RFC 9000 §6).
///
/// Any long-header packet (Initial, Handshake, Retry, 0-RTT) means a QUIC
/// handshake is in flight and the flow belongs on the HTTP/3 path.
/// Short-header (1-RTT) packets only appear after the handshake, which the
/// approved-flow cache already steered, so they never reach this check.
/// Version zero (version negotiation) is server-to-client and rejected.
#[must_use]
pub fn is_quic_initial(datagram: &[u8]) -> bool {
    if datagram.len() < 7 {
        return false;
    }
    if datagram[0] & 0x80 == 0 {
        return false;
    }
    if u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]) == 0 {
        return false;
    }
    let dcid_len = usize::from(datagram[5]);
    if dcid_len > 20 {
        return false;
    }
    // The SCID length byte must be present after the connection ID.
    datagram.len() > 6 + dcid_len
}

#[cfg(test)]
mod tests {
    use super::{TcpSniff, is_quic_initial, sniff_tcp};

    #[test]
    fn tls_client_hello_prefix_is_detected() {
        // Record header of a real ClientHello: handshake, TLS 1.2 wire
        // version, length.
        assert_eq!(sniff_tcp(&[0x16, 0x03, 0x01, 0x00, 0xC0]), TcpSniff::Tls);
        assert_eq!(sniff_tcp(&[0x16, 0x03, 0x03, 0x01, 0x00]), TcpSniff::Tls);
        // TLS 1.3 pretends to be 1.2 on the wire; minor 4 accepted too.
        assert_eq!(sniff_tcp(&[0x16, 0x03, 0x04]), TcpSniff::Tls);
    }

    #[test]
    fn tls_detection_needs_three_bytes() {
        assert_eq!(sniff_tcp(&[0x16]), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(&[0x16, 0x03]), TcpSniff::NeedMore);
    }

    #[test]
    fn non_tls_handshake_type_is_unknown() {
        // 0x16 alone is also a plausible length prefix (e.g. MongoDB OP_MSG
        // framing); a non-TLS version byte rules TLS out.
        assert_eq!(sniff_tcp(&[0x16, 0x02, 0x00]), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(&[0x16, 0x04, 0x00]), TcpSniff::Unknown);
    }

    #[test]
    fn http_methods_are_detected() {
        for request in [
            "GET / HTTP/1.1\r\n",
            "HEAD / HTTP/1.1\r\n",
            "POST /submit HTTP/1.1\r\n",
            "PUT /x HTTP/1.1\r\n",
            "DELETE /x HTTP/1.1\r\n",
            "CONNECT example.test:443 HTTP/1.1\r\n",
            "OPTIONS * HTTP/1.1\r\n",
            "TRACE / HTTP/1.1\r\n",
            "PATCH /x HTTP/1.1\r\n",
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        ] {
            assert_eq!(sniff_tcp(request.as_bytes()), TcpSniff::Http, "{request}");
        }
    }

    #[test]
    fn partial_method_prefixes_need_more() {
        assert_eq!(sniff_tcp(b""), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"G"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"GE"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"GET"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"CONNECT"), TcpSniff::NeedMore);
    }

    #[test]
    fn raw_protocols_are_rejected_fast() {
        // SSH banner, Postgres SSLRequest length prefix, junk: decided on
        // the first byte without waiting out the peek deadline.
        assert_eq!(sniff_tcp(b"SSH-2.0-OpenSSH"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(&[0x00, 0x00, 0x00, 0x08]), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(b"X"), TcpSniff::Unknown);
        // Bare method name without its trailing space is not HTTP.
        assert_eq!(sniff_tcp(b"GETX /"), TcpSniff::Unknown);
    }

    #[test]
    fn quic_long_header_is_detected() {
        // v1 Initial: long header, version 1, 8-byte DCID, SCID follows.
        let mut initial = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x08];
        initial.extend([0xAA; 8]);
        initial.extend([0x04, 0xBB, 0xBB, 0xBB, 0xBB]);
        assert!(is_quic_initial(&initial));
    }

    #[test]
    fn non_quic_datagrams_are_rejected() {
        assert!(!is_quic_initial(&[]));
        assert!(!is_quic_initial(&[0xC0, 0x00]));
        // Short header (1-RTT): never a handshake opener.
        assert!(!is_quic_initial(&[
            0x40, 0x00, 0x00, 0x00, 0x01, 0x08, 0xAA
        ]));
        // Version negotiation is server-to-client.
        assert!(!is_quic_initial(&[
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x08, 0xAA
        ]));
        // Absurd connection ID length: not QUIC framing.
        assert!(!is_quic_initial(&[0xC0, 0x00, 0x00, 0x00, 0x01, 0xFF]));
        // DNS query over UDP.
        assert!(!is_quic_initial(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00
        ]));
    }
}
