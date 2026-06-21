//! Audit logging and host pattern matching.

use std::net::Ipv4Addr;

/// Parsed IPv4 prefix octets and count for wildcard matching.
struct Ipv4Prefix {
    octets: [u8; 3],
    count: usize,
}

fn parse_ipv4_prefix(prefix: &str) -> Option<Ipv4Prefix> {
    let mut octets = [0_u8; 3];
    let mut count = 0_usize;
    for part in prefix.split('.') {
        if count == octets.len() {
            return None;
        }
        octets[count] = part.parse().ok()?;
        count += 1;
    }
    if (1..=3).contains(&count) {
        Some(Ipv4Prefix { octets, count })
    } else {
        None
    }
}

fn ipv4_prefix_matches(pattern: &str, host: &str) -> Option<bool> {
    let prefix = pattern.strip_suffix(".*")?;
    let Ipv4Prefix {
        octets: prefix_octets,
        count: prefix_len,
    } = parse_ipv4_prefix(prefix)?;
    let host_octets = host.parse::<Ipv4Addr>().ok()?.octets();
    Some(host_octets[..prefix_len] == prefix_octets[..prefix_len])
}

fn parse_ipv6_hextets(prefix: &str) -> Option<Vec<u16>> {
    let hextets: Vec<&str> = prefix.split(':').collect();
    if hextets.is_empty() || hextets.len() > 7 {
        return None;
    }
    let mut result = Vec::with_capacity(hextets.len());
    for h in &hextets {
        if h.is_empty() || h.len() > 4 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        result.push(u16::from_str_radix(h, 16).ok()?);
    }
    Some(result)
}

fn ipv6_prefix_matches(pattern: &str, host: &str) -> Option<bool> {
    let prefix = pattern.strip_suffix(":*")?;
    let prefix_hextets = parse_ipv6_hextets(prefix)?;
    let host_addr = host.parse::<std::net::Ipv6Addr>().ok()?;
    let host_segments = host_addr.segments();
    Some(host_segments[..prefix_hextets.len()] == prefix_hextets[..])
}

impl super::types::PolicyStore {
    pub(crate) fn audit(action: &str, host: Option<&str>, port: Option<u16>, detail: &str) {
        tracing::info!(target: "audit", action, host, port, detail, "policy event");
    }

    pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
        let pattern = pattern.to_lowercase();
        let host = host.to_lowercase();
        if let Some(bare) = pattern.strip_prefix("*.") {
            // DNS suffix wildcard: "*.baz.com" matches "foo.bar.baz.com"
            let suffix = &pattern[1..];
            return host == bare || host.ends_with(suffix);
        }
        if let Some(matches) = ipv4_prefix_matches(&pattern, &host) {
            return matches;
        }
        // Try IPv6 prefix wildcard: "2001:db8:*" matches "2001:db8::1"
        if let Some(matches) = ipv6_prefix_matches(&pattern, &host) {
            return matches;
        }
        // Exact IP comparison: parse both sides so equivalent forms match.
        if let (Ok(ip_pat), Ok(ip_host)) = (
            pattern.parse::<std::net::IpAddr>(),
            host.parse::<std::net::IpAddr>(),
        ) {
            return ip_pat == ip_host;
        }
        pattern == host
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::PolicyStore;

    #[test]
    fn host_matches_dns_suffix_wildcard() {
        assert!(PolicyStore::host_matches("*.baz.com", "foo.bar.baz.com"));
        assert!(PolicyStore::host_matches("*.baz.com", "bar.baz.com"));
        // "*.baz.com" matches bare "baz.com" (existing behavior via `bare`).
        assert!(PolicyStore::host_matches("*.baz.com", "baz.com"));
        assert!(!PolicyStore::host_matches("*.baz.com", "other.com"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_exact() {
        assert!(PolicyStore::host_matches("34.230.40.69", "34.230.40.69"));
        assert!(!PolicyStore::host_matches("34.230.40.69", "34.230.40.70"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_full_octet() {
        assert!(PolicyStore::host_matches("34.230.40.*", "34.230.40.69"));
        assert!(PolicyStore::host_matches("34.230.40.*", "34.230.40.1"));
        assert!(PolicyStore::host_matches("34.230.*", "34.230.40.69"));
        assert!(PolicyStore::host_matches("34.*", "34.230.40.69"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_partial_octet_rejected() {
        // "34.230.4.*" must NOT match "34.230.40.69" (partial octet).
        assert!(!PolicyStore::host_matches("34.230.4.*", "34.230.40.69"));
        assert!(!PolicyStore::host_matches("34.2.*", "34.230.40.69"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_different_subnet() {
        assert!(!PolicyStore::host_matches("34.230.40.*", "34.230.41.69"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_does_not_match_bare_prefix() {
        assert!(!PolicyStore::host_matches("34.230.40.*", "34.230.40"));
    }

    #[test]
    fn host_matches_trailing_star_only_applies_to_ipv4_prefixes() {
        assert!(!PolicyStore::host_matches("example.*", "example.com"));
        assert!(!PolicyStore::host_matches("34.230.40.69.*", "34.230.40.69"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard() {
        assert!(PolicyStore::host_matches("2001:db8:*", "2001:db8::1"));
        assert!(PolicyStore::host_matches(
            "2001:db8:0:0:0:0:0:*",
            "2001:db8::1"
        ));
        assert!(PolicyStore::host_matches("2001:*", "2001:db8::1"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard_mismatch() {
        assert!(!PolicyStore::host_matches("2001:db9:*", "2001:db8::1"));
        assert!(!PolicyStore::host_matches("2002:*", "2001:db8::1"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard_hextet_boundary_respected() {
        // "2001:db" is a valid 2-digit hex prefix. Need a case where a part is not 1-4 hex chars.
        assert!(!PolicyStore::host_matches("2001:dbg:*", "2001:db8::1"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard_does_not_match_dns() {
        assert!(!PolicyStore::host_matches("example:*", "example.com"));
        assert!(!PolicyStore::host_matches("2001:*", "2001.com"));
    }

    #[test]
    fn host_matches_ipv6_exact_literal() {
        assert!(PolicyStore::host_matches("2001:db8::1", "2001:db8::1"));
        // Different representations of the same address.
        assert!(PolicyStore::host_matches(
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1"
        ));
    }

    #[test]
    fn host_matches_ipv6_exact_literal_mismatch() {
        assert!(!PolicyStore::host_matches("2001:db8::1", "2001:db8::2"));
    }
}
