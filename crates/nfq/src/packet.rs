//! IP/TCP/UDP header parsing for NFQUEUE packet payloads.
//!
//! Supports both IPv4 and IPv6, TCP SYN detection, and UDP parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of walking IPv6 extension headers: the transport protocol number
/// and its offset within the packet (total extension header length + 40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6ExtResult {
    pub protocol: u8,
    pub transport_offset: usize,
}

/// Transport protocols enforced by the network policy daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Parsed metadata from a queued IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    pub tcp_syn: bool,
}

impl PacketMeta {
    /// Whether this packet should trigger a policy check.
    #[must_use]
    pub const fn is_policy_boundary(self) -> bool {
        match self.protocol {
            TransportProtocol::Tcp => self.tcp_syn,
            TransportProtocol::Udp => true,
        }
    }

    /// The IP-level protocol number from the wire (`4` or `6`).
    #[must_use]
    pub const fn ip_version(self) -> u8 {
        match self.src_ip {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }
    }
}

/// Parse an IPv4 packet payload into source/destination IPs, ports, and TCP SYN
/// flag.
///
/// Returns `None` for non-IPv4, truncated, or non-TCP/UDP packets.
pub fn parse_ipv4(payload: &[u8]) -> Option<PacketMeta> {
    if payload.len() < 20 {
        return None;
    }

    let version_ihl = payload[0];
    let version = version_ihl >> 4;
    let ihl = usize::from(version_ihl & 0x0F) * 4;
    if version != 4 || ihl < 20 || payload.len() < ihl {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    let packet_len = total_len.min(payload.len());
    if packet_len < ihl {
        return None;
    }

    let protocol = payload[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        payload[16],
        payload[17],
        payload[18],
        payload[19],
    ));

    match protocol {
        6 => parse_tcp(&payload[..packet_len], ihl, src_ip, dst_ip),
        17 => parse_udp(&payload[..packet_len], ihl, src_ip, dst_ip),
        _ => None,
    }
}
/// Walk IPv6 extension headers to find the transport protocol and its total
/// offset.
///
/// Recognised extension headers: Hop-by-Hop (0), Routing (43), Destination
/// Options (60), Fragment (44, first-fragment only), Authentication Header
/// (51). Returns `None` for No Next Header (59), ESP (50), unknown headers,
/// truncated extension headers, and non-first fragments.
fn walk_ipv6_ext_headers(payload: &[u8], packet_len: usize) -> Option<Ipv6ExtResult> {
    let mut next_header = payload[6];
    let mut offset = 40;

    loop {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-Hop (0), Routing (43), Destination Options (60)
                // Format: Next Header (1) + Hdr Ext Len (1) + content
                if offset + 2 > packet_len {
                    return None;
                }
                let hdr_ext_len = usize::from(payload[offset + 1]);
                let hdr_len = 8 + hdr_ext_len * 8;
                if offset + hdr_len > packet_len {
                    return None;
                }
                next_header = payload[offset];
                offset += hdr_len;
            }
            44 => {
                // Fragment header: fixed 8 bytes
                if offset + 8 > packet_len {
                    return None;
                }
                let frag_field = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
                let frag_offset = frag_field >> 3;
                if frag_offset != 0 {
                    return None; // Non-first fragment
                }
                next_header = payload[offset];
                offset += 8;
            }
            51 => {
                // Authentication Header
                if offset + 2 > packet_len {
                    return None;
                }
                let ah_len = usize::from(payload[offset + 1]);
                let hdr_len = (ah_len + 2) * 4;
                if offset + hdr_len > packet_len {
                    return None;
                }
                next_header = payload[offset];
                offset += hdr_len;
            }
            6 | 17 => {
                return Some(Ipv6ExtResult {
                    protocol: next_header,
                    transport_offset: offset,
                });
            }
            // No Next Header (59), ESP (50), or unknown
            _ => return None,
        }
    }
}

/// Parse an IPv6 packet payload into source/destination IPs, ports, and TCP SYN
/// flag.
///
/// Returns `None` for non-IPv6, truncated, or non-TCP/UDP packets.
pub fn parse_ipv6(payload: &[u8]) -> Option<PacketMeta> {
    if payload.len() < 40 {
        return None;
    }

    let version = payload[0] >> 4;
    if version != 6 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    let packet_len = (40 + payload_len).min(payload.len());
    if packet_len < 40 {
        return None;
    }

    let src_bytes = {
        let mut b = [0u8; 16];
        b.copy_from_slice(&payload[8..24]);
        b
    };
    let dst_bytes = {
        let mut b = [0u8; 16];
        b.copy_from_slice(&payload[24..40]);
        b
    };
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    let ext = walk_ipv6_ext_headers(payload, packet_len)?;
    let protocol = ext.protocol;
    let ip_hdr_len = ext.transport_offset;
    match protocol {
        6 => parse_tcp(&payload[..packet_len], ip_hdr_len, src_ip, dst_ip),
        17 => parse_udp(&payload[..packet_len], ip_hdr_len, src_ip, dst_ip),
        _ => unreachable!(),
    }
}

fn parse_tcp(
    payload: &[u8],
    ip_hdr_len: usize,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<PacketMeta> {
    let tcp_start = ip_hdr_len;
    if payload.len() < tcp_start + 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([payload[tcp_start], payload[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([payload[tcp_start + 2], payload[tcp_start + 3]]);
    let tcp_header_len = usize::from(payload[tcp_start + 12] >> 4) * 4;
    if tcp_header_len < 20 || payload.len() < tcp_start + tcp_header_len {
        return None;
    }
    let flags = payload[tcp_start + 13];
    let tcp_syn = flags & 0x02 != 0 && flags & 0x10 == 0;

    Some(PacketMeta {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: TransportProtocol::Tcp,
        tcp_syn,
    })
}

fn parse_udp(
    payload: &[u8],
    ip_hdr_len: usize,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<PacketMeta> {
    let udp_start = ip_hdr_len;
    if payload.len() < udp_start + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([payload[udp_start], payload[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([payload[udp_start + 2], payload[udp_start + 3]]);

    Some(PacketMeta {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: TransportProtocol::Udp,
        tcp_syn: false,
    })
}

/// Extract the UDP payload (bytes after the 8-byte UDP header) from a parsed
/// packet.
///
/// Works for both IPv4 and IPv6. Returns `None` if the packet is shorter than
/// the UDP data offset.
#[must_use]
pub fn udp_payload<'a>(payload: &'a [u8], meta: &PacketMeta) -> Option<&'a [u8]> {
    if meta.protocol != TransportProtocol::Udp {
        return None;
    }
    let ip_hdr_len = if meta.ip_version() == 6 {
        if payload.len() < 40 {
            return None;
        }
        let plen = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
        let pkt_len = (40 + plen).min(payload.len());
        walk_ipv6_ext_headers(payload, pkt_len).map(|ext| ext.transport_offset)?
    } else {
        if payload.len() < 20 {
            return None;
        }
        let ihl = usize::from(payload[0] & 0x0F) * 4;
        if ihl < 20 || payload.len() < ihl {
            return None;
        }
        ihl
    };
    if payload.len() < ip_hdr_len + 8 {
        return None;
    }
    let total_len = {
        let raw = if meta.ip_version() == 6 {
            u16::from_be_bytes([payload[4], payload[5]])
        } else {
            u16::from_be_bytes([payload[2], payload[3]])
        };
        if meta.ip_version() == 6 {
            (40 + usize::from(raw)).min(payload.len())
        } else {
            usize::from(raw).min(payload.len())
        }
    };
    if total_len < ip_hdr_len + 8 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([
        payload[ip_hdr_len + 4],
        payload[ip_hdr_len + 5],
    ]));
    if udp_len < 8 {
        return None;
    }
    let udp_data_start = ip_hdr_len + 8;
    let udp_data_end = (ip_hdr_len + udp_len).min(total_len);
    if udp_data_end < udp_data_start {
        return None;
    }
    Some(&payload[udp_data_start..udp_data_end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tcp_syn_v4(dst_ip: [u8; 4], dst_port: u16, src_port: u16) -> Vec<u8> {
        let mut pkt = vec![0_u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40_u16.to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x02;
        pkt
    }

    fn build_udp_v4(dst_ip: [u8; 4], dst_port: u16, src_port: u16) -> Vec<u8> {
        let mut pkt = vec![0_u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28_u16.to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[169, 254, 100, 2]);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    fn build_tcp_syn_v6(dst_ip: [u8; 16], dst_port: u16, src_port: u16) -> Vec<u8> {
        let mut pkt = vec![0_u8; 60]; // 40 IPv6 + 20 TCP
        pkt[0] = 0x60;
        // Payload length = TCP header = 20
        pkt[4..6].copy_from_slice(&20_u16.to_be_bytes());
        pkt[6] = 6; // Next header: TCP
        pkt[7] = 64; // Hop limit
        // src_ip: bytes 8..23
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst_ip: bytes 24..39
        pkt[24..40].copy_from_slice(&dst_ip);
        // TCP header at byte 40
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt[52] = 0x50; // data offset = 5 words
        pkt[53] = 0x02; // SYN flag
        pkt
    }

    fn build_udp_v6(dst_ip: [u8; 16], dst_port: u16, src_port: u16) -> Vec<u8> {
        let mut pkt = vec![0_u8; 48]; // 40 IPv6 + 8 UDP
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8_u16.to_be_bytes()); // UDP is 8 bytes
        pkt[6] = 17; // Next header: UDP
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt[24..40].copy_from_slice(&dst_ip);
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    fn build_tcp_syn_v6_with_dest_opts(dst_ip: [u8; 16], dst_port: u16, src_port: u16) -> Vec<u8> {
        // 40 IPv6 + 8 DestOpts + 20 TCP = 68 bytes
        let mut pkt = vec![0_u8; 68];
        pkt[0] = 0x60;
        // Payload length = 8 DestOpts + 20 TCP = 28
        pkt[4..6].copy_from_slice(&28_u16.to_be_bytes());
        pkt[6] = 60; // Next header: Destination Options
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&dst_ip);
        // Destination Options header at byte 40 (hdr_ext_len = 0 -> 8 bytes)
        pkt[40] = 6; // Next header: TCP
        pkt[41] = 0; // Hdr Ext Len
        // TCP header at byte 48
        pkt[48..50].copy_from_slice(&src_port.to_be_bytes());
        pkt[50..52].copy_from_slice(&dst_port.to_be_bytes());
        pkt[60] = 0x50; // data offset = 5 words
        pkt[61] = 0x02; // SYN flag
        pkt
    }

    fn build_udp_v6_with_dest_opts_and_payload(
        dst_ip: [u8; 16],
        dst_port: u16,
        src_port: u16,
        udp_payload: &[u8],
    ) -> Vec<u8> {
        // 40 IPv6 + 8 DestOpts + 8 UDP + payload
        let total = 56 + udp_payload.len();
        let mut pkt = vec![0_u8; total];
        let plen = 16 + udp_payload.len(); // 8 DestOpts + 8 UDP + payload
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(
            &u16::try_from(plen)
                .expect("convert packet length to u16")
                .to_be_bytes(),
        );
        pkt[6] = 60; // Next header: Destination Options
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt[24..40].copy_from_slice(&dst_ip);
        // Destination Options header at byte 40
        pkt[40] = 17; // Next header: UDP
        pkt[41] = 0; // Hdr Ext Len
        // UDP header at byte 48
        pkt[48..50].copy_from_slice(&src_port.to_be_bytes());
        pkt[50..52].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = 8 + udp_payload.len();
        pkt[52..54].copy_from_slice(
            &u16::try_from(udp_len)
                .expect("convert udp length to u16")
                .to_be_bytes(),
        );
        pkt[56..56 + udp_payload.len()].copy_from_slice(udp_payload);
        pkt
    }

    fn build_ipv6_fragment(next_header: u8, frag_offset: u16, more_frags: bool) -> Vec<u8> {
        // 40 IPv6 + 8 Fragment header = 48 bytes
        let mut pkt = vec![0_u8; 48];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8_u16.to_be_bytes()); // payload = 8 (fragment header only)
        pkt[6] = 44; // Next header: Fragment
        pkt[7] = 64;
        // Fragment header at byte 40
        pkt[40] = next_header;
        // Fragment offset (13 bits) + More Fragments flag
        let frag_field = (frag_offset << 3) | u16::from(more_frags);
        pkt[42..44].copy_from_slice(&frag_field.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_tcp_syn_v4_extracts_transport_tuple() {
        let pkt = build_tcp_syn_v4([93, 184, 216, 34], 443, 12345);
        let meta = parse_ipv4(&pkt).expect("parse");
        assert_eq!(meta.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(meta.dst_ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.src_port, 12345);
        assert_eq!(meta.protocol, TransportProtocol::Tcp);
        assert!(meta.tcp_syn);
        assert!(meta.is_policy_boundary());
    }

    #[test]
    fn parse_tcp_non_syn_is_not_policy_boundary() {
        let mut pkt = build_tcp_syn_v4([1, 2, 3, 4], 80, 5000);
        pkt[33] = 0x12;
        let meta = parse_ipv4(&pkt).expect("parse");
        assert!(!meta.tcp_syn);
        assert!(!meta.is_policy_boundary());
    }

    #[test]
    fn parse_udp_v4_extracts_transport_tuple() {
        let pkt = build_udp_v4([8, 8, 8, 8], 53, 53000);
        let meta = parse_ipv4(&pkt).expect("parse");
        assert_eq!(meta.src_ip, IpAddr::V4(Ipv4Addr::new(169, 254, 100, 2)));
        assert_eq!(meta.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(meta.dst_port, 53);
        assert_eq!(meta.src_port, 53000);
        assert_eq!(meta.protocol, TransportProtocol::Udp);
        assert!(meta.is_policy_boundary());
    }

    #[test]
    fn parse_truncated_ipv4_returns_none() {
        assert!(parse_ipv4(&[0x45, 0, 0]).is_none());
    }

    #[test]
    fn parse_non_ipv4_returns_none() {
        let mut pkt = build_tcp_syn_v4([1, 2, 3, 4], 80, 5000);
        pkt[0] = 0x60;
        assert!(parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn parse_ipv6_tcp_syn_extracts_transport_tuple() {
        let dst = [
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
        ];
        let pkt = build_tcp_syn_v6(dst, 443, 54321);
        let meta = parse_ipv6(&pkt).expect("parse IPv6");
        assert_eq!(
            meta.src_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            meta.dst_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x20))
        );
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.src_port, 54321);
        assert_eq!(meta.protocol, TransportProtocol::Tcp);
        assert!(meta.tcp_syn);
        assert!(meta.is_policy_boundary());
    }

    #[test]
    fn parse_ipv6_tcp_non_syn_is_not_policy_boundary() {
        let dst = [0; 16];
        let mut pkt = build_tcp_syn_v6(dst, 80, 5000);
        pkt[53] = 0x12;
        let meta = parse_ipv6(&pkt).expect("parse IPv6");
        assert!(!meta.tcp_syn);
        assert!(!meta.is_policy_boundary());
    }

    #[test]
    fn parse_ipv6_udp_extracts_transport_tuple() {
        let dst = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ];
        let pkt = build_udp_v6(dst, 53, 53000);
        let meta = parse_ipv6(&pkt).expect("parse IPv6");
        assert_eq!(
            meta.src_ip,
            IpAddr::V6(Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 2))
        );
        assert_eq!(
            meta.dst_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))
        );
        assert_eq!(meta.dst_port, 53);
        assert_eq!(meta.src_port, 53000);
        assert_eq!(meta.protocol, TransportProtocol::Udp);
        assert!(meta.is_policy_boundary());
    }

    #[test]
    fn parse_truncated_ipv6_returns_none() {
        assert!(parse_ipv6(&[0x60, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn parse_non_ipv6_returns_none() {
        let mut pkt = build_tcp_syn_v6([0; 16], 80, 5000);
        pkt[0] = 0x45; // IPv4 version
        assert!(parse_ipv6(&pkt).is_none());
    }

    #[test]
    fn parse_ipv6_non_tcp_udp_returns_none() {
        let mut pkt = build_tcp_syn_v6([0; 16], 80, 5000);
        pkt[6] = 58; // ICMPv6
        assert!(parse_ipv6(&pkt).is_none());
    }

    #[test]
    fn parse_ipv6_tcp_syn_behind_dest_opts_is_policy_boundary() {
        let dst = [
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
        ];
        let pkt = build_tcp_syn_v6_with_dest_opts(dst, 443, 54321);
        let meta = parse_ipv6(&pkt).expect("parse IPv6 with DestOpts");
        assert_eq!(
            meta.src_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            meta.dst_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x20))
        );
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.src_port, 54321);
        assert_eq!(meta.protocol, TransportProtocol::Tcp);
        assert!(meta.tcp_syn);
        assert!(meta.is_policy_boundary());
    }

    #[test]
    fn parse_ipv6_udp_behind_dest_opts_returns_udp_payload() {
        let dst = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let pkt = build_udp_v6_with_dest_opts_and_payload(dst, 53, 53000, b"testdata");
        let meta = parse_ipv6(&pkt).expect("parse IPv6 UDP with DestOpts");
        let data = udp_payload(&pkt, &meta).expect("udp_payload with DestOpts");
        assert_eq!(data, b"testdata");
    }

    #[test]
    fn parse_ipv6_non_first_fragment_returns_none() {
        let pkt = build_ipv6_fragment(6, 1, false);
        assert!(parse_ipv6(&pkt).is_none());
    }

    #[test]
    fn udp_payload_v4_returns_data_after_udp_header() {
        let mut pkt = vec![0_u8; 32];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&32_u16.to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&53000_u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53_u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&12_u16.to_be_bytes());
        pkt[28..32].copy_from_slice(b"test");

        let meta = parse_ipv4(&pkt).expect("parse");
        let data = udp_payload(&pkt, &meta).expect("udp_payload");
        assert_eq!(data, b"test");
    }

    #[test]
    fn udp_payload_v4_empty_payload_returns_empty_slice() {
        let mut pkt = vec![0_u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28_u16.to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&53_u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53000_u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&8_u16.to_be_bytes());

        let meta = parse_ipv4(&pkt).expect("parse");
        let data = udp_payload(&pkt, &meta).expect("udp_payload");
        assert!(data.is_empty());
    }

    #[test]
    fn udp_payload_v6_returns_data_after_udp_header() {
        let mut pkt = vec![0_u8; 52]; // 40 IPv6 + 8 UDP + 4 payload
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&12_u16.to_be_bytes()); // UDP len 8 + 4 payload
        pkt[6] = 17; // UDP
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt[24..40].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[40..42].copy_from_slice(&53000_u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&53_u16.to_be_bytes());
        pkt[44..46].copy_from_slice(&12_u16.to_be_bytes()); // UDP length
        pkt[48..52].copy_from_slice(b"test");

        let meta = parse_ipv6(&pkt).expect("parse IPv6");
        let data = udp_payload(&pkt, &meta).expect("udp_payload");
        assert_eq!(data, b"test");
    }

    #[test]
    fn ip_version_detected_correctly() {
        let v4 = parse_ipv4(&build_tcp_syn_v4([1, 2, 3, 4], 80, 5000)).expect("v4");
        assert_eq!(v4.ip_version(), 4);
        let v6 = parse_ipv6(&build_tcp_syn_v6([0; 16], 80, 5000)).expect("v6");
        assert_eq!(v6.ip_version(), 6);
    }
}
