//! Session-scoped hostname attribution persisted across NFQUEUE restarts.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

pub const SESSION_ATTRIBUTION_PATH: &str = "/run/agent-sandbox/session-attribution.json";

const FILE_VERSION: u32 = 1;

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

#[derive(Debug, Deserialize, Serialize)]
struct AttributionFile {
    version: u32,
    entries: Vec<AttributionEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttributionEntry {
    session_id: String,
    ip: String,
    hostname: String,
}

/// Session-scoped retention of hostname mappings attributed to sandbox
/// connections.
#[derive(Debug)]
pub struct SessionAttribution {
    path: Option<PathBuf>,
    entries: HashMap<SessionIpKey, String>,
    dirty: bool,
}

impl SessionAttribution {
    /// Construct an in-memory attribution map, primarily for unit tests.
    pub fn new() -> Self {
        Self {
            path: None,
            entries: HashMap::new(),
            dirty: false,
        }
    }

    /// Load attribution state from `path`; malformed, missing, and old-version
    /// files are treated as an empty map so network operation can continue.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<AttributionFile>(&raw).ok())
            .and_then(|file| {
                if file.version != FILE_VERSION {
                    return None;
                }
                let mut entries = HashMap::new();
                for entry in file.entries {
                    let key = SessionIpKey {
                        session_id: entry.session_id,
                        ip: entry.ip,
                    };
                    if entries.insert(key, entry.hostname).is_some() {
                        return None;
                    }
                }
                Some(entries)
            })
            .unwrap_or_default();
        Self {
            path: Some(path),
            entries,
            dirty: false,
        }
    }

    /// Remember a mapping and persist changed state when this map is
    /// path-backed.
    ///
    /// A failed persistence leaves the map dirty. A later remember retries the
    /// complete snapshot, while clean unchanged mappings perform no write.
    pub fn remember(&mut self, session_id: &str, ip: &str, hostname: &str) -> std::io::Result<()> {
        let key = SessionIpKey::new(session_id, ip);
        if let Some(existing) = self.entries.get_mut(&key) {
            if existing != hostname {
                hostname.clone_into(existing);
                self.dirty = true;
            }
        } else {
            self.entries.insert(key, hostname.to_owned());
            self.dirty = true;
        }
        if !self.dirty {
            return Ok(());
        }
        self.persist()
    }

    pub fn lookup(&self, session_id: &str, ip: &str) -> Option<&str> {
        self.entries
            .get(&SessionIpKey::new(session_id, ip))
            .map(String::as_str)
    }

    fn persist(&mut self) -> std::io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            self.dirty = false;
            return Ok(());
        };
        let mut entries: Vec<AttributionEntry> = self
            .entries
            .iter()
            .map(|(key, hostname)| AttributionEntry {
                session_id: key.session_id.clone(),
                ip: key.ip.clone(),
                hostname: hostname.clone(),
            })
            .collect();
        entries.sort_unstable_by(|left, right| {
            left.session_id
                .cmp(&right.session_id)
                .then_with(|| left.ip.cmp(&right.ip))
        });
        let snapshot = AttributionFile {
            version: FILE_VERSION,
            entries,
        };
        let data = serde_json::to_vec(&snapshot).map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, path)?;
        self.dirty = false;
        Ok(())
    }
}

impl Default for SessionAttribution {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::SessionAttribution;

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "agent-sandbox-nfq-attribution-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[test]
    fn mapping_is_scoped_to_exact_session_and_ip() {
        let mut attribution = SessionAttribution::new();
        attribution
            .remember("session-a", "192.0.2.10", "example.test")
            .expect("remember attribution");

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
        attribution
            .remember("session-a", "192.0.2.10", "old.example")
            .expect("remember old attribution");
        attribution
            .remember("session-a", "192.0.2.10", "new.example")
            .expect("remember replacement attribution");

        assert_eq!(
            attribution.lookup("session-a", "192.0.2.10"),
            Some("new.example")
        );
    }

    #[test]
    fn retains_earliest_mapping_beyond_former_capacity() {
        let mut attribution = SessionAttribution::new();
        attribution
            .remember("session-a", "192.0.2.10", "earliest.example")
            .expect("remember earliest attribution");

        for index in 0..=4096 {
            attribution
                .remember("session-b", &format!("198.51.100.{index}"), "later.example")
                .expect("remember later attribution");
        }

        assert_eq!(
            attribution.lookup("session-a", "192.0.2.10"),
            Some("earliest.example")
        );
    }

    #[test]
    fn persisted_mapping_survives_fresh_reconstruction() {
        let path = test_path("reconstruction");
        let mut writer = SessionAttribution::load(&path);
        writer
            .remember("session-a", "192.0.2.10", "example.test")
            .expect("persist attribution");

        let fresh = SessionAttribution::load(&path);
        assert_eq!(
            fresh.lookup("session-a", "192.0.2.10"),
            Some("example.test")
        );
        std::fs::remove_file(path).expect("remove test attribution state");
    }

    #[test]
    fn persisted_mapping_is_scoped_to_exact_session_and_ip_after_reload() {
        let path = test_path("isolation");
        let mut writer = SessionAttribution::load(&path);
        writer
            .remember("session-a", "192.0.2.10", "example.test")
            .expect("persist attribution");

        let fresh = SessionAttribution::load(&path);
        assert_eq!(
            fresh.lookup("session-a", "192.0.2.10"),
            Some("example.test")
        );
        assert_eq!(fresh.lookup("session-b", "192.0.2.10"), None);
        assert_eq!(fresh.lookup("session-a", "192.0.2.11"), None);
        assert_eq!(fresh.lookup("", "192.0.2.10"), None);
        std::fs::remove_file(path).expect("remove test attribution state");
    }

    #[test]
    fn replacement_persists_across_reload() {
        let path = test_path("replacement");
        let mut writer = SessionAttribution::load(&path);
        writer
            .remember("session-a", "192.0.2.10", "old.example")
            .expect("persist old attribution");
        writer
            .remember("session-a", "192.0.2.10", "new.example")
            .expect("persist replacement attribution");

        let fresh = SessionAttribution::load(&path);
        assert_eq!(fresh.lookup("session-a", "192.0.2.10"), Some("new.example"));
        std::fs::remove_file(path).expect("remove test attribution state");
    }

    #[test]
    fn unchanged_mapping_is_a_clean_noop() {
        let path = test_path("unchanged");
        let mut attribution = SessionAttribution::load(&path);
        attribution
            .remember("session-a", "192.0.2.10", "example.test")
            .expect("persist attribution");
        std::fs::remove_file(&path).expect("remove persisted state");

        attribution
            .remember("session-a", "192.0.2.10", "example.test")
            .expect("unchanged attribution is a successful no-op");
        assert!(
            !path.exists(),
            "unchanged clean state must not rewrite the persistence file"
        );
    }

    #[test]
    fn malformed_persisted_state_loads_empty() {
        let path = test_path("malformed");
        std::fs::write(&path, b"{not valid json").expect("write malformed state");

        let attribution = SessionAttribution::load(&path);
        assert_eq!(attribution.lookup("session-a", "192.0.2.10"), None);
        std::fs::remove_file(path).expect("remove malformed state");
    }

    #[test]
    fn unsupported_version_persisted_state_loads_empty() {
        let path = test_path("version");
        std::fs::write(
            &path,
            br#"{"version":999,"entries":[{"session_id":"session-a","ip":"192.0.2.10","hostname":"example.test"}]}"#,
        )
        .expect("write unsupported-version state");

        let attribution = SessionAttribution::load(&path);
        assert_eq!(attribution.lookup("session-a", "192.0.2.10"), None);
        std::fs::remove_file(path).expect("remove unsupported-version state");
    }

    #[test]
    fn duplicate_persisted_mapping_loads_empty() {
        let path = test_path("duplicate");
        std::fs::write(
            &path,
            br#"{"version":1,"entries":[{"session_id":"session-a","ip":"192.0.2.10","hostname":"first.example"},{"session_id":"session-a","ip":"192.0.2.10","hostname":"second.example"}]}"#,
        )
        .expect("write duplicate state");

        let attribution = SessionAttribution::load(&path);
        assert_eq!(attribution.lookup("session-a", "192.0.2.10"), None);
        std::fs::remove_file(path).expect("remove duplicate state");
    }
}
