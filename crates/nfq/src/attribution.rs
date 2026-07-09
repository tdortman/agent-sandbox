//! Session-scoped, in-memory hostname attribution for policy-bound connections.

use std::collections::HashMap;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SessionIpKey {
    session_id: String,
    ip: String,
}

impl SessionIpKey {
    fn new(session_id: &str, ip: &str) -> Self {
        Self {
            session_id: session_id.to_owned(),
            ip: ip.to_owned(),
        }
    }
}

/// Session-scoped retention of hostname mappings attributed to sandbox connections.
#[derive(Debug)]
pub struct SessionAttribution {
    entries: HashMap<SessionIpKey, String>,
}

impl SessionAttribution {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn remember(&mut self, session_id: &str, ip: &str, hostname: &str) {
        let key = SessionIpKey::new(session_id, ip);
        if let Some(existing) = self.entries.get_mut(&key) {
            hostname.clone_into(existing);
            return;
        }
        self.entries.insert(key, hostname.to_owned());
    }

    pub fn lookup(&self, session_id: &str, ip: &str) -> Option<&str> {
        self.entries
            .get(&SessionIpKey::new(session_id, ip))
            .map(String::as_str)
    }
}

impl Default for SessionAttribution {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::SessionAttribution;

    #[test]
    fn mapping_is_scoped_to_exact_session_and_ip() {
        let mut attribution = SessionAttribution::new();
        attribution.remember("session-a", "192.0.2.10", "example.test");

        assert_eq!(
            attribution.lookup("session-a", "192.0.2.10"),
            Some("example.test")
        );
        assert_eq!(attribution.lookup("session-b", "192.0.2.10"), None);
        assert_eq!(attribution.lookup("session-a", "192.0.2.11"), None);
        assert_eq!(attribution.lookup("", "192.0.2.10"), None);
    }

    #[test]
    fn remembering_same_session_and_ip_replaces_hostname() {
        let mut attribution = SessionAttribution::new();
        attribution.remember("session-a", "192.0.2.10", "old.example");
        attribution.remember("session-a", "192.0.2.10", "new.example");

        assert_eq!(
            attribution.lookup("session-a", "192.0.2.10"),
            Some("new.example")
        );
    }
    #[test]
    fn retains_earliest_mapping_beyond_former_capacity() {
        let mut attribution = SessionAttribution::new();
        attribution.remember("session-a", "192.0.2.10", "earliest.example");

        for index in 0..=4096 {
            attribution.remember("session-b", &format!("198.51.100.{index}"), "later.example");
        }

        assert_eq!(
            attribution.lookup("session-a", "192.0.2.10"),
            Some("earliest.example")
        );
    }
}
