//! Audit logging and host pattern matching.

impl super::types::PolicyStore {
    pub(crate) fn audit(action: &str, host: Option<&str>, port: Option<u16>, detail: &str) {
        tracing::info!(target: "audit", action, host, port, detail, "policy event");
    }

    pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
        let pattern = pattern.to_lowercase();
        let host = host.to_lowercase();
        if let Some(bare) = pattern.strip_prefix("*.") {
            let suffix = &pattern[1..];
            return host == bare || host.ends_with(suffix);
        }
        pattern == host
    }
}
