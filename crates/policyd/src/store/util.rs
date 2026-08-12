//! Audit logging and host pattern matching.

use super::decisions::DecisionAction;
use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths};
use std::path::PathBuf;

impl super::types::PolicyStore {
    pub(crate) fn audit(action: &str, host: Option<&str>, port: Option<u16>, detail: &str) {
        tracing::info!(target: "audit", action, host, port, detail, "policy event");
    }

    /// Shared tail of every scope-apply flow: export policy files, emit the
    /// audit event, then build the scope reply. Only the audit target, the
    /// audit detail, and the concrete `ok_*` reply differ across capabilities.
    pub(crate) fn finalize_scope_reply<F>(
        &self,
        paths: &SandboxPaths,
        scope: ApprovalScope,
        action: DecisionAction,
        audit: (Option<&str>, Option<u16>, &str),
        reply: F,
    ) -> RpcReply
    where
        F: FnOnce(ApprovalScope, Option<PathBuf>) -> RpcReply,
    {
        let _ = self.export_policy_files(paths.clone());

        Self::audit(action.audit_verb(), audit.0, audit.1, audit.2);

        let policy_path = match (paths.home(), paths.project_root()) {
            (_, Some(p)) if scope == ApprovalScope::Project => Self::project_policy_path_display(p),
            _ => None,
        };

        reply(scope, policy_path.map(PathBuf::from))
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::host_pattern_matches;

    #[test]
    fn host_matches_dns_suffix_wildcard() {
        assert!(host_pattern_matches("*.baz.com", "foo.bar.baz.com"));
        assert!(host_pattern_matches("*.baz.com", "bar.baz.com"));

        // "*.baz.com" matches bare "baz.com" (existing behavior via `bare`).
        assert!(host_pattern_matches("*.baz.com", "baz.com"));

        assert!(!host_pattern_matches("*.baz.com", "other.com"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_exact() {
        assert!(host_pattern_matches("34.230.40.69", "34.230.40.69"));
        assert!(!host_pattern_matches("34.230.40.69", "34.230.40.70"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_full_octet() {
        assert!(host_pattern_matches("34.230.40.*", "34.230.40.69"));
        assert!(host_pattern_matches("34.230.40.*", "34.230.40.1"));
        assert!(host_pattern_matches("34.230.*", "34.230.40.69"));
        assert!(host_pattern_matches("34.*", "34.230.40.69"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_partial_octet_rejected() {
        // "34.230.4.*" must NOT match "34.230.40.69" (partial octet).
        assert!(!host_pattern_matches("34.230.4.*", "34.230.40.69"));

        assert!(!host_pattern_matches("34.2.*", "34.230.40.69"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_different_subnet() {
        assert!(!host_pattern_matches("34.230.40.*", "34.230.41.69"));
    }

    #[test]
    fn host_matches_ipv4_prefix_wildcard_does_not_match_bare_prefix() {
        assert!(!host_pattern_matches("34.230.40.*", "34.230.40"));
    }

    #[test]
    fn host_matches_general_globs_after_ipv4_prefix_checks() {
        assert!(host_pattern_matches("example.*", "example.com"));
        assert!(!host_pattern_matches("34.230.40.69.*", "34.230.40.69"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard() {
        assert!(host_pattern_matches("2001:db8:*", "2001:db8::1"));
        assert!(host_pattern_matches("2001:db8:0:0:0:0:0:*", "2001:db8::1"));
        assert!(host_pattern_matches("2001:*", "2001:db8::1"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard_mismatch() {
        assert!(!host_pattern_matches("2001:db9:*", "2001:db8::1"));
        assert!(!host_pattern_matches("2002:*", "2001:db8::1"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard_hextet_boundary_respected() {
        // "2001:db" is a valid 2-digit hex prefix. Need a case where a part is not 1-4
        // hex chars.
        assert!(!host_pattern_matches("2001:dbg:*", "2001:db8::1"));
    }

    #[test]
    fn host_matches_ipv6_prefix_wildcard_does_not_match_dns() {
        assert!(!host_pattern_matches("example:*", "example.com"));
        assert!(!host_pattern_matches("2001:*", "2001.com"));
    }

    #[test]
    fn host_matches_ipv6_exact_literal() {
        assert!(host_pattern_matches("2001:db8::1", "2001:db8::1"));

        // Different representations of the same address.
        assert!(host_pattern_matches(
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1"
        ));
    }

    #[test]
    fn host_matches_ipv6_exact_literal_mismatch() {
        assert!(!host_pattern_matches("2001:db8::1", "2001:db8::2"));
    }
}
