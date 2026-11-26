//! Leading-bytes protocol sniffing for transparent routing decisions.
//!
//! Port numbers do not identify protocols: HTTPS serves on 9443, dev servers
//! speak plain HTTP on 3000, and raw TCP (SSH, Postgres, SMTP) can appear on
//! any port. The routing decision therefore inspects bytes, not ports:
//!
//! - TCP: a `SYN` carries no payload, so NFQUEUE cannot classify it. Every TCP
//!   `SYN` is queued, the flow is registered for the proxy, and the proxy peeks
//!   at the first stream bytes (replaying them to the chosen path) to decide
//!   between the HTTP(S) path and a raw passthrough. A TLS record header, an
//!   HTTP/1 request line (standard or extension method, after any empty lines)
//!   or the h2c preface selects the HTTP(S) path.
//! - UDP: the first datagram already carries its payload, so NFQUEUE checks for
//!   a QUIC long header directly. Per-port socket binds still steer UDP to the
//!   proxy listeners, but the payload decides the policy path.

/// Longest method token the sniffer considers (`UPDATEREDIRECTREF`).
const MAX_METHOD_LEN: usize = 17;

/// Methods accepted with any request target after their trailing space.
const COMMON_METHODS: [&[u8]; 10] = [
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH",
    // h2c prior knowledge: `PRI * HTTP/2.0`.
    b"PRI",
];

/// Absolute-form request-target openers, matched case-insensitively.
const ABSOLUTE_TARGETS: [&[u8]; 2] = [b"http://", b"https://"];

/// Outcome of inspecting the first bytes of a TCP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSniff {
    /// TLS record header (`0x16 0x03xx`): terminate and HTTP-proxy.
    Tls,
    /// Plain HTTP request line (`GET `, `PROPFIND /`, `PRI `, ...): HTTP-proxy.
    Http,
    /// Prefix is consistent with TLS or HTTP but too short to decide.
    NeedMore,
    /// Matches neither TLS nor HTTP: splice raw TCP upstream.
    Unknown,
}

/// Classify the first bytes of a downstream TCP stream.
///
/// Pure prefix match, safe to call on every peek refill: `NeedMore` means
/// "wait for more bytes", anything else is final.
///
/// HTTP/1 is recognised by its request line, after any leading empty lines
/// (RFC 9112 §2.2). The common methods are accepted with any target. Any
/// other all-uppercase method token (`PROPFIND`, `MKCOL`, `PURGE`, ...) needs
/// a request-target start that raw protocols do not produce: `/` or an
/// absolute-form `http://` / `https://`. Asterisk-form is not accepted for
/// them because the HTTP stack only allows it for `OPTIONS`.
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

    let Some(request_line) = skip_empty_lines(prefix) else {
        return TcpSniff::NeedMore;
    };
    let Some(&first) = request_line.first() else {
        return TcpSniff::NeedMore;
    };
    if !first.is_ascii_uppercase() {
        // Postgres startup, MySQL, RESP and the like never start with an
        // uppercase letter, so raw protocols pay no peek latency.
        return TcpSniff::Unknown;
    }

    let method_len = request_line
        .iter()
        .take_while(|byte| byte.is_ascii_uppercase())
        .count();
    if method_len > MAX_METHOD_LEN {
        return TcpSniff::Unknown;
    }
    let Some(&delimiter) = request_line.get(method_len) else {
        return TcpSniff::NeedMore;
    };
    if delimiter != b' ' {
        return TcpSniff::Unknown;
    }

    let method = &request_line[..method_len];
    let target = &request_line[method_len + 1..];
    if COMMON_METHODS.contains(&method) {
        return TcpSniff::Http;
    }
    classify_extension_target(target)
}

/// Drop RFC 9112 §2.2 empty lines (`\r\n` or bare `\n`) before the request
/// line. `None` when the prefix ends in a lone `\r` that may still become one.
const fn skip_empty_lines(mut prefix: &[u8]) -> Option<&[u8]> {
    loop {
        match prefix {
            [b'\n', rest @ ..] | [b'\r', b'\n', rest @ ..] => prefix = rest,
            [b'\r'] => return None,
            _ => return Some(prefix),
        }
    }
}

/// Decide on the request-target start following an extension method.
fn classify_extension_target(target: &[u8]) -> TcpSniff {
    let Some(&first) = target.first() else {
        return TcpSniff::NeedMore;
    };
    if first == b'/' {
        return TcpSniff::Http;
    }

    let mut partial = false;
    for opener in ABSOLUTE_TARGETS {
        let shared = target.len().min(opener.len());
        if target[..shared].eq_ignore_ascii_case(&opener[..shared]) {
            if target.len() >= opener.len() {
                return TcpSniff::Http;
            }
            partial = true;
        }
    }
    if partial {
        TcpSniff::NeedMore
    } else {
        TcpSniff::Unknown
    }
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
    fn extension_methods_with_http_only_targets_are_http() {
        for request in [
            "PROPFIND /dav/ HTTP/1.1\r\n",
            "PROPPATCH http://example.test/dav/x HTTP/1.1\r\n",
            "MKCOL /dav/new HTTP/1.1\r\n",
            "COPY HTTPS://example.test/a HTTP/1.1\r\n",
            "MOVE /a HTTP/1.1\r\n",
            "LOCK /a HTTP/1.1\r\n",
            "UNLOCK /a HTTP/1.1\r\n",
            "REPORT /a HTTP/1.1\r\n",
            "SEARCH /a HTTP/1.1\r\n",
            "PURGE /cache HTTP/1.1\r\n",
            "UPDATEREDIRECTREF /a HTTP/1.1\r\n",
        ] {
            assert_eq!(sniff_tcp(request.as_bytes()), TcpSniff::Http, "{request}");
        }
    }

    #[test]
    fn leading_empty_lines_are_skipped() {
        assert_eq!(sniff_tcp(b"\r\nGET / HTTP/1.1\r\n"), TcpSniff::Http);
        assert_eq!(sniff_tcp(b"\n\r\nPROPFIND /x HTTP/1.1\r\n"), TcpSniff::Http);
        assert_eq!(sniff_tcp(b"\r"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"\r\n"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"\r\nGE"), TcpSniff::NeedMore);
        // A bare CR is not an empty line.
        assert_eq!(sniff_tcp(b"\rGET / HTTP/1.1\r\n"), TcpSniff::Unknown);
        // Empty lines never turn a non-TLS stream into TLS.
        assert_eq!(sniff_tcp(b"\r\n\x16\x03\x01"), TcpSniff::Unknown);
    }

    #[test]
    fn partial_method_prefixes_need_more() {
        assert_eq!(sniff_tcp(b""), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"G"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"GE"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"GET"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"CONNECT"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"PROPFIND"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"PROPFIND "), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"PROPPATCH http:/"), TcpSniff::NeedMore);
        assert_eq!(sniff_tcp(b"COPY HT"), TcpSniff::NeedMore);
    }

    #[test]
    fn raw_protocols_are_rejected_fast() {
        // SSH banner, Postgres SSLRequest, RESP array, SMTP greeting from
        // the client, junk: decided without waiting out the peek deadline.
        assert_eq!(sniff_tcp(b"SSH-2.0-OpenSSH"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(&[0x00, 0x00, 0x00, 0x08]), TcpSniff::Unknown);
        assert_eq!(
            sniff_tcp(&[0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F]),
            TcpSniff::Unknown
        );
        assert_eq!(sniff_tcp(b"*1\r\n$4\r\nPING\r\n"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(b"EHLO host\r\n"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(b"HELO host\r\n"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(b"USER alice\r\n"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(b"X\x00"), TcpSniff::Unknown);
        // A method token without a space, or an asterisk target the HTTP
        // stack only accepts for OPTIONS, is not HTTP.
        assert_eq!(sniff_tcp(b"GETX\r\n"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(b"MKCOL * HTTP/1.1\r\n"), TcpSniff::Unknown);
        assert_eq!(sniff_tcp(b"ABCDEFGHIJKLMNOPQR /"), TcpSniff::Unknown);
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
