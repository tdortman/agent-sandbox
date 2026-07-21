//! Hostname normalization and policy host resolution.

use std::{net::IpAddr, path::Path};

use globset::GlobBuilder;
use hickory_proto::rr::Name;
use idna::domain_to_ascii;
use thiserror::Error;

use crate::dns_cache::lookup_dns_cache;
#[must_use]
pub fn is_ip_literal(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.parse::<IpAddr>().is_ok()
}

#[must_use]
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    // Strip surrounding brackets from IPv6 literals for policy matching.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.to_lowercase().trim_end_matches('.').to_string()
}

/// Error returned when a DNS name cannot be canonicalized safely.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DnsNameError {
    #[error("DNS name is empty")]
    Empty,

    #[error("DNS name is not a valid IDNA name")]
    Invalid,

    #[error("DNS name exceeds the 253-byte wire limit")]
    TooLong,

    #[error("DNS label exceeds the 63-byte wire limit")]
    LabelTooLong,
}

/// Canonicalize a DNS name to lowercase ASCII without a terminal dot.
///
/// # Errors
///
/// Returns [`DnsNameError`] when the input is empty, invalid, or exceeds DNS
/// wire-format limits.
pub fn normalize_dns_name(host: &str) -> Result<String, DnsNameError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(DnsNameError::Empty);
    }
    let ascii = domain_to_ascii(trimmed).map_err(|_| DnsNameError::Invalid)?;
    let canonical = ascii.trim_end_matches('.');
    if canonical.is_empty() {
        return Err(DnsNameError::Empty);
    }
    if canonical.len() > 253 {
        return Err(DnsNameError::TooLong);
    }
    for label in canonical.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(if label.is_empty() {
                DnsNameError::Invalid
            } else {
                DnsNameError::LabelTooLong
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DnsNameError::Invalid);
        }
    }
    let name = Name::from_ascii(format!("{canonical}.")).map_err(|_| DnsNameError::Invalid)?;
    Ok(name.to_ascii().trim_end_matches('.').to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkRuleKey {
    pub host: String,
    pub port: u16,
}

impl NetworkRuleKey {
    #[must_use]
    pub fn new(host: impl AsRef<str>, port: u16) -> Self {
        Self {
            host: normalize_host(host.as_ref()),
            port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkSortKey {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub port: u16,
}

impl NetworkSortKey {
    #[must_use]
    pub fn new(host: &str, port: u16) -> Self {
        let host = normalize_host(host);
        if host.is_empty() || is_ip_literal(&host) {
            return Self {
                domain: host,
                subdomains: Vec::new(),
                port,
            };
        }

        let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
        if labels.len() < 2 {
            return Self {
                domain: host,
                subdomains: Vec::new(),
                port,
            };
        }

        Self {
            domain: format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]),
            subdomains: labels[..labels.len() - 2]
                .iter()
                .rev()
                .map(|label| (*label).to_string())
                .collect(),
            port,
        }
    }
}
#[must_use]
pub fn approval_host_patterns(host: &str) -> Vec<String> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Vec::new();
    }
    let labels: Vec<_> = host.split('.').collect();
    let mut patterns = vec![host.clone()];

    // IPv4 literals: generate prefix wildcards on octet boundaries.
    // "34.230.40.69" -> ["34.230.40.69", "34.230.40.*", "34.230.*", "34.*"]
    if labels.len() == 4 && labels.iter().all(|l| l.parse::<u8>().is_ok()) {
        for idx in (0..labels.len() - 1).rev() {
            let prefix = labels[..=idx].join(".");
            patterns.push(format!("{prefix}.*"));
        }
    } else if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        // IPv6 literals: generate hextet-prefix wildcards using trailing ":*".
        // "2001:db8::1" -> ["2001:db8::1", "2001:db8:0:0:0:0:0:*",
        // "2001:db8:0:0:0:0:*", ..., "2001:*"]
        let segments: Vec<String> = ipv6.segments().iter().map(|s| format!("{s:x}")).collect();
        for len in (1..=7).rev() {
            let prefix = segments[..len].join(":");
            patterns.push(format!("{prefix}:*"));
        }
    } else {
        // DNS hostname: suffix wildcards.
        for idx in 1..labels.len() {
            let suffix = labels[idx..].join(".");
            if suffix.contains('.') {
                patterns.push(format!("*.{suffix}"));
            }
        }
    }
    patterns
}

#[must_use]
pub fn reverse_hostname(ip: &str) -> Option<String> {
    let ip: IpAddr = ip.parse().ok()?;
    dns_lookup::lookup_addr(&ip)
        .ok()
        .map(|h| normalize_host(&h))
}

/// Resolved policy host and original connect target for a network destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResolution {
    /// Normalized hostname used for policy matching (DNS name or IP literal).
    pub policy_host: String,
    /// Original connect target (IP or hostname) used for transport connections.
    pub connect_host: String,
}

impl HostResolution {
    #[must_use]
    pub fn new(policy_host: impl Into<String>, connect_host: impl Into<String>) -> Self {
        Self {
            policy_host: policy_host.into(),
            connect_host: connect_host.into(),
        }
    }
}

/// Resolve a network destination into a policy host and original connect
/// target.
///
/// For IP literals, tries the DNS forwarder cache first, then falls back to the
/// raw IP.
#[must_use]
pub fn policy_host_for_connect(connect_host: &str, cache_path: Option<&Path>) -> HostResolution {
    let connect_host = connect_host.trim();
    if !is_ip_literal(connect_host) {
        let name = normalize_host(connect_host);
        return HostResolution::new(name, connect_host);
    }

    let policy_host = normalize_host(connect_host);
    if let Some(cached) = lookup_dns_cache(&policy_host, cache_path) {
        return HostResolution::new(cached, connect_host);
    }

    HostResolution::new(policy_host, connect_host)
}

#[must_use]
pub fn allow_keys(host: &str, port: u16) -> Vec<NetworkRuleKey> {
    vec![NetworkRuleKey::new(host, port)]
}

/// Whether `host` matches a policy `pattern` using globset syntax and
/// normalized IP-prefix aliases.
#[must_use]
pub fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let host = host.to_lowercase();
    if let Some(bare) = pattern.strip_prefix("*.")
        && !host_pattern_has_glob(bare)
    {
        let suffix = &pattern[1..];
        return host == bare || host.ends_with(suffix);
    }

    if let Ok(glob) = GlobBuilder::new(&pattern)
        .backslash_escape(true)
        .literal_separator(true)
        .build()
        && glob.compile_matcher().is_match(&host)
    {
        return true;
    }

    if let Some(matches) = ipv4_prefix_matches(&pattern, &host) {
        return matches;
    }

    if let Some(matches) = ipv6_prefix_matches(&pattern, &host) {
        return matches;
    }

    if let (Ok(ip_pat), Ok(ip_host)) = (
        pattern.parse::<std::net::IpAddr>(),
        host.parse::<std::net::IpAddr>(),
    ) {
        return ip_pat == ip_host;
    }

    false
}

#[must_use]
pub(crate) fn host_pattern_has_glob(pattern: &str) -> bool {
    pattern.contains(['*', '?', '[', '{', '\\'])
}

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
    let host_octets = host.parse::<std::net::Ipv4Addr>().ok()?.octets();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::DnsCache;

    #[test]
    fn policy_host_uses_dns_cache() {
        let dir = tempfile::tempdir().expect("create temp dir for hosts policy test");
        let path = dir.path().join("dns-cache.json");

        let mut cache = DnsCache::new(Some(&path), 300);
        cache.remember("104.18.32.47", "example.com", 300);

        let result = policy_host_for_connect("104.18.32.47", Some(&path));
        assert_eq!(result.policy_host, "example.com");
        assert_eq!(result.connect_host, "104.18.32.47");
    }

    #[test]
    fn approval_host_patterns_ipv4_prefix_wildcards() {
        assert_eq!(approval_host_patterns("34.230.40.69"), vec![
            "34.230.40.69".to_string(),
            "34.230.40.*".to_string(),
            "34.230.*".to_string(),
            "34.*".to_string(),
        ]);
    }

    #[test]
    fn approval_host_patterns_ipv6_prefix_wildcards() {
        let patterns = approval_host_patterns("2001:db8::1");
        assert_eq!(patterns[0], "2001:db8::1");
        assert!(patterns.contains(&"2001:db8:0:0:0:0:0:*".to_string()));
        assert!(patterns.contains(&"2001:db8:*".to_string()));
        assert!(patterns.contains(&"2001:*".to_string()));
        assert_eq!(patterns.len(), 8);
    }

    #[test]
    fn approval_host_patterns_ipv6_loopback() {
        let patterns = approval_host_patterns("::1");
        assert_eq!(patterns[0], "::1");
        assert!(patterns.contains(&"0:0:0:0:0:0:0:*".to_string()));
        assert!(patterns.contains(&"0:*".to_string()));
        assert_eq!(patterns.len(), 8);
    }

    #[test]
    fn approval_host_patterns_ipv6_bracketed_normalizes() {
        let patterns = approval_host_patterns("[::1]");
        assert_eq!(patterns[0], "::1");
        assert_eq!(patterns.len(), 8);
    }
    #[test]
    fn approval_host_patterns_ipv4_loopback_prefix_wildcards() {
        assert_eq!(approval_host_patterns("127.0.0.1"), vec![
            "127.0.0.1".to_string(),
            "127.0.0.*".to_string(),
            "127.0.*".to_string(),
            "127.*".to_string(),
        ]);
    }
    #[test]
    fn approval_host_patterns_include_parent_domains() {
        assert_eq!(approval_host_patterns("Foo.Bar.Baz.com."), vec![
            "foo.bar.baz.com".to_string(),
            "*.bar.baz.com".to_string(),
            "*.baz.com".to_string(),
        ]);
    }

    #[test]
    fn host_pattern_matches_general_globs() {
        assert!(host_pattern_matches(
            "api.*.example.com",
            "API.V1.EXAMPLE.COM"
        ));
        assert!(!host_pattern_matches(
            "api.*.example.com",
            "api.example.com"
        ));
        assert!(!host_pattern_matches(
            "api.*.example.com",
            "api.v1.example.net"
        ));
    }
    #[test]
    fn host_pattern_matches_full_globset_syntax() {
        assert!(host_pattern_matches(
            "{api,cdn}.example.com",
            "cdn.example.com"
        ));
        assert!(!host_pattern_matches(
            "{api,cdn}.example.com",
            "www.example.com"
        ));
        assert!(host_pattern_matches(
            "[a-c]pi.example.com",
            "api.example.com"
        ));
        assert!(!host_pattern_matches(
            "[a-c]pi.example.com",
            "dpi.example.com"
        ));
        assert!(host_pattern_matches(
            r"api\*.example.com",
            "api*.example.com"
        ));
        assert!(!host_pattern_matches(
            r"api\*.example.com",
            "api1.example.com"
        ));
    }

    #[test]
    fn host_pattern_matches_preserves_existing_wildcards() {
        assert!(host_pattern_matches("*.example.com", "example.com"));
        assert!(host_pattern_matches("*.example.com", "api.example.com"));
        assert!(host_pattern_matches("34.230.*", "34.230.40.69"));
        assert!(!host_pattern_matches("34.230.*", "34.231.40.69"));
    }

    #[test]
    fn policy_host_falls_back_to_ip_when_cache_miss() {
        let dir = tempfile::tempdir().expect("create temp dir for hosts policy test");
        let path = dir.path().join("dns-cache.json");
        let result = policy_host_for_connect("10.0.0.9", Some(&path));
        assert_eq!(result.policy_host, "10.0.0.9");
    }

    #[test]
    fn allow_keys_does_not_add_ptr_host_for_ip_literal() {
        // allow_keys must not insert a reverse-DNS/PTR-derived hostname.
        let keys = allow_keys("104.18.32.47", 443);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].host, "104.18.32.47");
        assert_eq!(keys[0].port, 443);
    }

    #[test]
    fn cache_miss_returns_raw_ip_not_ptr() {
        // Even for an IP that would produce a PTR like "lb-*.github.com",
        // the policy host must be the raw IP literal on cache miss.
        let dir = tempfile::tempdir().expect("create temp dir for hosts policy test");
        let path = dir.path().join("dns-cache.json");

        let result = policy_host_for_connect("93.184.216.34", Some(&path));
        assert_eq!(result.policy_host, "93.184.216.34");
        assert_eq!(result.connect_host, "93.184.216.34");
    }
    #[test]
    fn policy_host_for_ipv6_literal_cache_miss() {
        let dir = tempfile::tempdir().expect("create temp dir for hosts policy test");
        let path = dir.path().join("dns-cache.json");
        let result = policy_host_for_connect("::1", Some(&path));
        assert_eq!(result.policy_host, "::1");
        assert_eq!(result.connect_host, "::1");
    }

    #[test]
    fn policy_host_for_ipv6_literal_cache_hit() {
        let dir = tempfile::tempdir().expect("create temp dir for hosts policy test");
        let path = dir.path().join("dns-cache.json");
        let mut cache = DnsCache::new(Some(&path), 300);
        cache.remember("2001:db8::1", "ipv6.example.com", 300);
        let result = policy_host_for_connect("2001:db8::1", Some(&path));
        assert_eq!(result.policy_host, "ipv6.example.com");
        assert_eq!(result.connect_host, "2001:db8::1");
    }

    #[test]
    fn policy_host_for_bracketed_ipv6_literal_uses_normalized_cache_key() {
        let dir = tempfile::tempdir().expect("create temp dir for hosts policy test");
        let path = dir.path().join("dns-cache.json");
        let mut cache = DnsCache::new(Some(&path), 300);
        cache.remember("2001:db8::1", "ipv6.example.com", 300);
        let result = policy_host_for_connect("[2001:db8::1]", Some(&path));
        assert_eq!(result.policy_host, "ipv6.example.com");
        assert_eq!(result.connect_host, "[2001:db8::1]");
    }

    #[test]
    fn normalize_host_strips_ipv6_brackets() {
        assert_eq!(normalize_host("[::1]"), "::1");
        assert_eq!(normalize_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(normalize_host("::1"), "::1");
    }

    #[test]
    fn is_ip_literal_accepts_ipv6() {
        assert!(is_ip_literal("::1"));
        assert!(is_ip_literal("[::1]"));
        assert!(!is_ip_literal("example.com"));
    }
}
