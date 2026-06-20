//! Hostname normalization and policy host resolution.

use std::net::IpAddr;
use std::path::Path;

use crate::dns_cache::lookup_dns_cache;
pub fn is_ip_literal(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.parse::<IpAddr>().is_ok()
}

pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    // Strip surrounding brackets from IPv6 literals for policy matching.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.to_lowercase().trim_end_matches('.').to_string()
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
pub fn approval_host_patterns(host: &str) -> Vec<String> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Vec::new();
    }
    let labels: Vec<_> = host.split('.').collect();
    let mut patterns = vec![host.clone()];
    for idx in 1..labels.len() {
        let suffix = labels[idx..].join(".");
        if suffix.contains('.') {
            patterns.push(format!("*.{suffix}"));
        }
    }
    patterns
}

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

/// Resolve a network destination into a policy host and original connect target.
///
/// For IP literals, tries the DNS forwarder cache first, then falls back to the raw IP.
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

pub fn allow_keys(host: &str, port: u16) -> Vec<NetworkRuleKey> {
    let host = normalize_host(host);
    vec![NetworkRuleKey::new(&host, port)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::DnsCache;

    #[test]
    fn policy_host_uses_dns_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-cache.json");

        let mut cache = DnsCache::new(Some(&path), 300);
        cache.remember("104.18.32.47", "example.com", 300);

        let result = policy_host_for_connect("104.18.32.47", Some(&path));
        assert_eq!(result.policy_host, "example.com");
        assert_eq!(result.connect_host, "104.18.32.47");
    }

    #[test]
    fn approval_host_patterns_include_parent_domains() {
        assert_eq!(
            approval_host_patterns("Foo.Bar.Baz.com."),
            vec![
                "foo.bar.baz.com".to_string(),
                "*.bar.baz.com".to_string(),
                "*.baz.com".to_string(),
            ]
        );
    }

    #[test]
    fn policy_host_falls_back_to_ip_when_cache_miss() {
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-cache.json");

        let result = policy_host_for_connect("93.184.216.34", Some(&path));
        assert_eq!(result.policy_host, "93.184.216.34");
        assert_eq!(result.connect_host, "93.184.216.34");
    }
    #[test]
    fn policy_host_for_ipv6_literal_cache_miss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-cache.json");
        let result = policy_host_for_connect("::1", Some(&path));
        assert_eq!(result.policy_host, "::1");
        assert_eq!(result.connect_host, "::1");
    }

    #[test]
    fn policy_host_for_ipv6_literal_cache_hit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-cache.json");
        let mut cache = DnsCache::new(Some(&path), 300);
        cache.remember("2001:db8::1", "ipv6.example.com", 300);
        let result = policy_host_for_connect("2001:db8::1", Some(&path));
        assert_eq!(result.policy_host, "ipv6.example.com");
        assert_eq!(result.connect_host, "2001:db8::1");
    }

    #[test]
    fn policy_host_for_bracketed_ipv6_literal_uses_normalized_cache_key() {
        let dir = tempfile::tempdir().unwrap();
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
