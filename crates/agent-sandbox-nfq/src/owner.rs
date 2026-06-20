//! Look up the PID of the process that sent a packet, using the source
//! socket found in `/proc/net/{tcp,udp}` or `/proc/net/{tcp6,udp6}` inside
//! the sandbox netns.

use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::TransportProtocol;

/// Find the PID that owns the socket bound to `src_ip:src_port`.
///
/// Scans `/proc/net/tcp` or `/proc/net/udp` (IPv4) or `/proc/net/tcp6` or
/// `/proc/net/udp6` (IPv6) for a matching local address, extracts the socket
/// inode, then scans `/proc/*/fd/*` to find the owning PID.
pub fn pid_from_src_port(
    protocol: TransportProtocol,
    src_ip: IpAddr,
    src_port: u16,
) -> Option<u32> {
    let exact = proc_addr_field(src_ip, src_port);
    let wildcard = match src_ip {
        IpAddr::V4(_) => proc_addr_field(IpAddr::V4(Ipv4Addr::UNSPECIFIED), src_port),
        IpAddr::V6(_) => proc_addr_field(IpAddr::V6(Ipv6Addr::UNSPECIFIED), src_port),
    };
    let inode = find_socket_inode(protocol, src_ip.is_ipv6(), &exact, &wildcard)?;
    pid_for_inode(&inode)
}

/// Read `/proc/net/{tcp,udp}` or `/proc/net/{tcp6,udp6}` and find the inode
/// for a local address entry.
fn find_socket_inode(
    protocol: TransportProtocol,
    is_ipv6: bool,
    exact: &str,
    wildcard: &str,
) -> Option<String> {
    let table_path = match (protocol, is_ipv6) {
        (TransportProtocol::Tcp, false) => "/proc/net/tcp",
        (TransportProtocol::Udp, false) => "/proc/net/udp",
        (TransportProtocol::Tcp, true) => "/proc/net/tcp6",
        (TransportProtocol::Udp, true) => "/proc/net/udp6",
    };
    let table = fs::read_to_string(table_path).ok()?;
    for line in table.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        if parts[1] == exact || parts[1] == wildcard {
            return Some(parts[9].to_string());
        }
    }
    None
}

/// Scan `/proc/*/fd/*` for a socket matching the given inode.
fn pid_for_inode(inode: &str) -> Option<u32> {
    let needle = format!("socket:[{inode}]");
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid = name.parse().ok()?;
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if fs::read_link(fd.path()).is_ok_and(|link| link.to_string_lossy() == needle) {
                return Some(pid);
            }
        }
    }
    None
}

/// Format an IP address:port as `/proc/net/{tcp,udp}` hex.
///
/// For IPv4, the 32-bit address written as 8 hex digits in little-endian byte
/// order (matches the kernel's `%08X` format of `__be32` on LE hosts).
///
/// For IPv6, the 128-bit address is written as 32 hex digits in four 8-digit
/// groups, each group in little-endian byte order within the group (matches
/// the kernel's `%08X` format of `__be32[4]` on LE hosts).
fn proc_addr_field(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let mut reversed = String::with_capacity(8);
            for byte in octets.iter().rev() {
                write!(&mut reversed, "{byte:02X}").expect("writing to String cannot fail");
            }
            format!("{reversed}:{port:04X}")
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut reversed = String::with_capacity(32);
            for chunk in octets.chunks(4) {
                for byte in chunk.iter().rev() {
                    write!(&mut reversed, "{byte:02X}").expect("writing to String cannot fail");
                }
            }
            format!("{reversed}:{port:04X}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn proc_addr_field_ipv4_little_endian() {
        let field = proc_addr_field(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 443);
        assert_eq!(field, "0501A8C0:01BB");
    }

    #[test]
    fn proc_addr_field_ipv4_loopback() {
        let field = proc_addr_field(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(field, "0100007F:1F90");
    }

    #[test]
    fn proc_addr_field_ipv4_unspecified() {
        let field = proc_addr_field(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53000);
        assert_eq!(field, "00000000:CF08");
    }

    #[test]
    fn proc_addr_field_ipv6_loopback() {
        // ::1 -> bytes [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]
        // Each 4-byte chunk reversed:
        //   chunk 0: [0,0,0,0] -> 00000000
        //   chunk 1: [0,0,0,0] -> 00000000
        //   chunk 2: [0,0,0,0] -> 00000000
        //   chunk 3: [0,0,0,1] -> 01000000
        let field = proc_addr_field(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
        assert_eq!(field, "00000000000000000000000001000000:0050");
    }

    #[test]
    fn proc_addr_field_ipv6_unspecified() {
        let field = proc_addr_field(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        assert_eq!(field, "00000000000000000000000000000000:0000");
    }

    #[test]
    fn proc_addr_field_ipv6_2001_db8() {
        // 2001:db8::1 -> octets
        // [0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1]
        //   chunk 0 rev: [0xb8,0x0d,0x01,0x20] -> B80D0120
        //   chunk 1 rev: [0,0,0,0]             -> 00000000
        //   chunk 2 rev: [0,0,0,0]             -> 00000000
        //   chunk 3 rev: [0x01,0,0,0]          -> 01000000
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let field = proc_addr_field(ip, 443);
        assert_eq!(field, "B80D0120000000000000000001000000:01BB");
    }
}
