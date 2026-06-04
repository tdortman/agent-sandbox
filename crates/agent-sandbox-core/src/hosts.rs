//! Hostname normalization, SNI peek, and policy host resolution.

use std::net::IpAddr;
use std::path::Path;

use tls_parser::{
    SNIType, TlsExtension, TlsMessage, TlsMessageHandshake, TlsRecordType, parse_tls_extensions,
    parse_tls_handshake_msg_client_hello, parse_tls_plaintext, parse_tls_record_header,
    parse_tls_record_with_header,
};

use crate::dns_cache::lookup_dns_cache;

const TLS_RECORD_HEADER_LEN: usize = 5;

pub fn is_ipv4_literal(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

pub fn normalize_host(host: &str) -> String {
    host.trim().to_lowercase().trim_end_matches('.').to_string()
}

pub fn reverse_hostname(ip: &str) -> Option<String> {
    if !is_ipv4_literal(ip) {
        return None;
    }
    let ip: IpAddr = ip.parse().ok()?;
    dns_lookup::lookup_addr(&ip)
        .ok()
        .map(|h| normalize_host(&h))
}

fn sni_from_client_hello(ch: &tls_parser::TlsClientHelloContents<'_>) -> Option<String> {
    let ext_bytes = ch.ext?;
    let (_, extensions) = parse_tls_extensions(ext_bytes).ok()?;
    for ext in extensions {
        let TlsExtension::SNI(names) = ext else {
            continue;
        };
        for (typ, host) in names {
            if typ == SNIType::HostName && !host.is_empty() {
                let name = std::str::from_utf8(host).ok()?;
                return Some(normalize_host(name));
            }
        }
    }
    None
}

fn client_hello_in_buffer(buf: &[u8]) -> Option<tls_parser::TlsClientHelloContents<'_>> {
    if let Ok((_, plaintext)) = parse_tls_plaintext(buf) {
        for msg in &plaintext.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                return Some(ch.clone());
            }
        }
    }

    // First record may be incomplete (proxy peek); parse what we have.
    let (_, hdr) = parse_tls_record_header(buf).ok()?;
    if hdr.record_type != TlsRecordType::Handshake {
        return None;
    }
    if buf.len() <= TLS_RECORD_HEADER_LEN {
        return None;
    }
    let available = buf[TLS_RECORD_HEADER_LEN..].len().min(hdr.len as usize);
    let payload = &buf[TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + available];
    let mut hdr = hdr;
    hdr.len = u16::try_from(available).ok()?;

    let (_, msgs) = parse_tls_record_with_header(payload, &hdr).ok()?;
    for msg in msgs {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            return Some(ch.clone());
        }
    }

    let (_, hs) = parse_tls_handshake_msg_client_hello(payload).ok()?;
    let TlsMessageHandshake::ClientHello(ch) = hs else {
        return None;
    };
    Some(ch)
}

/// Extract server name from a TLS ClientHello (first record may be partial).
pub fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    let ch = client_hello_in_buffer(buf)?;
    sni_from_client_hello(&ch)
}

/// Return `(policy_host, connect_host)` — policy uses DNS names, TCP uses original target.
pub fn policy_host_for_connect(
    connect_host: &str,
    initial_data: Option<&[u8]>,
    cache_path: Option<&Path>,
) -> (String, String) {
    let connect_host = connect_host.trim();
    if !is_ipv4_literal(connect_host) {
        let name = normalize_host(connect_host);
        return (name, connect_host.to_string());
    }

    if let Some(cached) = lookup_dns_cache(connect_host, cache_path) {
        return (cached, connect_host.to_string());
    }

    if let Some(data) = initial_data
        && let Some(sni) = parse_tls_sni(data)
    {
        return (sni, connect_host.to_string());
    }

    if let Some(ptr) = reverse_hostname(connect_host) {
        return (ptr, connect_host.to_string());
    }

    (connect_host.to_string(), connect_host.to_string())
}

pub fn allow_keys(host: &str, port: u16) -> Vec<(String, u16)> {
    let host = normalize_host(host);
    let mut keys = vec![(host.clone(), port)];
    if is_ipv4_literal(&host)
        && let Some(ptr) = reverse_hostname(&host)
    {
        keys.push((ptr, port));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::DnsCache;

    fn test_u8(n: usize) -> u8 {
        u8::try_from(n).expect("test fixture fits in u8")
    }

    fn test_u16(n: usize) -> u16 {
        u16::try_from(n).expect("test fixture fits in u16")
    }

    fn client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let mut sni_list = vec![0_u8];
        sni_list.extend_from_slice(&test_u16(name.len()).to_be_bytes());
        sni_list.extend_from_slice(name);
        let sni_ext_len = test_u16(sni_list.len() + 2);
        let mut sni_ext = vec![0x00, 0x00];
        sni_ext.extend_from_slice(&sni_ext_len.to_be_bytes());
        sni_ext.extend_from_slice(&test_u16(sni_list.len()).to_be_bytes());
        sni_ext.extend_from_slice(&sni_list);
        let extensions = sni_ext;
        let ext_block_len = test_u16(extensions.len());
        let mut ext_block = ext_block_len.to_be_bytes().to_vec();
        ext_block.extend_from_slice(&extensions);

        let session_id: &[u8] = &[];
        let cipher_suites = [0x00_u8, 0x2f];
        let compression = [0x00_u8];

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(test_u8(session_id.len()));
        body.extend_from_slice(session_id);
        body.extend_from_slice(&(2_u16).to_be_bytes());
        body.extend_from_slice(&cipher_suites);
        body.push(test_u8(compression.len()));
        body.extend_from_slice(&compression);
        body.extend_from_slice(&ext_block);

        let mut handshake = vec![0x01];
        let len = u32::try_from(body.len()).expect("test handshake fits in u32");
        handshake.extend_from_slice(&len.to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(
            &u16::try_from(handshake.len())
                .expect("handshake fits in u16")
                .to_be_bytes(),
        );
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parse_tls_sni_extracts_hostname() {
        let pkt = client_hello_with_sni("api.openai.com");
        assert_eq!(parse_tls_sni(&pkt), Some("api.openai.com".into()));
    }

    #[test]
    fn policy_host_prefers_sni_over_ptr() {
        let pkt = client_hello_with_sni("chatgpt.com");
        let (policy_host, connect) = policy_host_for_connect("52.54.28.178", Some(&pkt), None);
        assert_eq!(policy_host, "chatgpt.com");
        assert_eq!(connect, "52.54.28.178");
    }

    #[test]
    fn policy_host_prefers_dns_cache_over_sni() {
        let pkt = client_hello_with_sni("other.example");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-cache.json");

        let mut cache = DnsCache::new(Some(&path), 300);
        cache.remember("52.54.28.178", "api.openai.com", 300);

        let (policy_host, connect) =
            policy_host_for_connect("52.54.28.178", Some(&pkt), Some(&path));
        assert_eq!(policy_host, "api.openai.com");
        assert_eq!(connect, "52.54.28.178");
    }

    #[test]
    fn policy_host_uses_sni_when_cache_miss() {
        let pkt = client_hello_with_sni("cached-miss.example");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-cache.json");
        let (policy_host, _) = policy_host_for_connect("10.0.0.9", Some(&pkt), Some(&path));
        assert_eq!(policy_host, "cached-miss.example");
    }
}
