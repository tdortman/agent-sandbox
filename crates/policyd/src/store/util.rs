//! Audit logging and host pattern matching.

use agent_sandbox_core::host_pattern_matches;

impl super::types::PolicyStore {
    pub(crate) fn audit(action: &str, host: Option<&str>, port: Option<u16>, detail: &str) {
        tracing::info!(target: "audit", action, host, port, detail, "policy event");
    }

    pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
        host_pattern_matches(pattern, host)
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
    fn host_matches_general_globs_after_ipv4_prefix_checks() {
        assert!(PolicyStore::host_matches("example.*", "example.com"));
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
