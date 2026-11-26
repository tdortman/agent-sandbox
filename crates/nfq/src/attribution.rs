//! Session-scoped hostname attribution persisted across NFQUEUE restarts.
//!
//! A session is keyed by the agent scope cgroup path of the sandbox's
//! processes, which the kernel reports; a key taken from a process
//! environment would let one sandbox attribute names to another.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use agent_sandbox_core::hosts::is_displayable_hostname;
use serde::{Deserialize, Serialize};

pub const SESSION_ATTRIBUTION_PATH: &str = "/run/agent-sandbox/session-attribution.json";
const FILE_VERSION: u32 = 3;

/// Mappings kept in total. Bounds memory, the file under `/run` and the
/// cost of rewriting it on every new mapping; a mapping beyond the bound is
/// simply not retained, so the flow is judged under the shared cache's newest
/// name instead.
const MAX_ENTRIES: usize = 4096;

/// Mappings one session may hold, so a single sandbox cannot use up the
/// table for the others.
const MAX_ENTRIES_PER_SESSION: usize = 512;

/// Longest session key retained; a key is a cgroup path.
const MAX_SESSION_ID_LEN: usize = 256;

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
    /// Unix seconds after which the mapping no longer attributes.
    expires: f64,
}

#[derive(Debug)]
struct AttributedHost {
    hostname: String,
    expires: f64,
}

/// Whether the in-memory map matches what was last persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncState {
    Clean,
    /// A change is not yet on disk; the next remember retries the write.
    Dirty,
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64())
}

/// Session-scoped retention of hostname mappings attributed to sandbox
/// connections. Each mapping expires with the DNS record it came from.
#[derive(Debug)]
pub struct SessionAttribution {
    path: Option<PathBuf>,
    entries: HashMap<SessionIpKey, AttributedHost>,
    sync: SyncState,
}

impl SessionAttribution {
    /// Construct an in-memory attribution map, primarily for unit tests.
    #[cfg(test)]
    pub fn new() -> Self {
        Self {
            path: None,
            entries: HashMap::new(),
            sync: SyncState::Clean,
        }
    }

    /// Load attribution state from `path`; malformed, missing, and old-version
    /// files are treated as an empty map so network operation can continue.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let now = unix_now();

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

                    let host = AttributedHost {
                        hostname: entry.hostname,
                        expires: entry.expires,
                    };

                    if !is_displayable_hostname(&host.hostname) {
                        continue;
                    }

                    if entries.insert(key, host).is_some() {
                        return None;
                    }
                }

                if entries.len() > MAX_ENTRIES {
                    return None;
                }

                entries.retain(|_, host: &mut AttributedHost| host.expires > now);
                Some(entries)
            })
            .unwrap_or_default();

        Self {
            path: Some(path),
            entries,
            sync: SyncState::Clean,
        }
    }

    /// Remember a mapping for `ttl` seconds and persist changed state when
    /// this map is path-backed.
    ///
    /// A failed persistence leaves the map dirty. A later remember retries the
    /// complete snapshot, while clean unchanged mappings perform no write.
    pub fn remember(
        &mut self,
        session_id: &str,
        ip: &str,
        hostname: &str,
        ttl: u32,
    ) -> std::io::Result<()> {
        self.remember_at(unix_now(), session_id, ip, hostname, ttl)
    }

    fn remember_at(
        &mut self,
        now: f64,
        session_id: &str,
        ip: &str,
        hostname: &str,
        ttl: u32,
    ) -> std::io::Result<()> {
        if session_id.len() > MAX_SESSION_ID_LEN || !is_displayable_hostname(hostname) {
            return Ok(());
        }

        let key = SessionIpKey::new(session_id, ip);
        let expires = now + f64::from(ttl);
        self.entries.retain(|_, host| host.expires > now);

        match self.entries.get_mut(&key) {
            // A later expiry of the same name rewrites the file only once it
            // moves by more than a second, so repeated flows stay write-free.
            Some(existing)
                if existing.hostname == hostname && expires <= existing.expires + 1.0 => {}

            Some(existing) => {
                hostname.clone_into(&mut existing.hostname);
                existing.expires = expires;
                self.sync = SyncState::Dirty;
            }

            None => {
                let session_entries = self
                    .entries
                    .keys()
                    .filter(|existing| existing.session_id == session_id)
                    .count();

                if self.entries.len() >= MAX_ENTRIES || session_entries >= MAX_ENTRIES_PER_SESSION {
                    return Ok(());
                }

                self.entries.insert(key, AttributedHost {
                    hostname: hostname.to_owned(),
                    expires,
                });
                self.sync = SyncState::Dirty;
            }
        }

        match self.sync {
            SyncState::Clean => Ok(()),
            SyncState::Dirty => self.persist(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The hostname this session last resolved for `ip`, while its record is
    /// still live.
    pub fn lookup(&self, session_id: &str, ip: &str) -> Option<&str> {
        self.lookup_at(unix_now(), session_id, ip)
    }

    fn lookup_at(&self, now: f64, session_id: &str, ip: &str) -> Option<&str> {
        self.entries
            .get(&SessionIpKey::new(session_id, ip))
            .filter(|host| host.expires > now)
            .map(|host| host.hostname.as_str())
    }

    fn persist(&mut self) -> std::io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            self.sync = SyncState::Clean;
            return Ok(());
        };

        let mut entries: Vec<AttributionEntry> = self
            .entries
            .iter()
            .map(|(key, host)| AttributionEntry {
                session_id: key.session_id.clone(),
                ip: key.ip.clone(),
                hostname: host.hostname.clone(),
                expires: host.expires,
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
        self.sync = SyncState::Clean;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{MAX_ENTRIES, MAX_ENTRIES_PER_SESSION, SessionAttribution};

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
        assert!(attribution.is_empty());

        attribution
            .remember("session-a", "192.0.2.10", "example.test", 300)
            .expect("remember attribution");

        assert!(!attribution.is_empty());
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
            .remember("session-a", "192.0.2.10", "old.example", 300)
            .expect("remember old attribution");

        attribution
            .remember("session-a", "192.0.2.10", "new.example", 300)
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
            .remember("session-a", "192.0.2.10", "earliest.example", 300)
            .expect("remember earliest attribution");

        for index in 0..=4096 {
            attribution
                .remember(
                    "session-b",
                    &format!("198.51.100.{index}"),
                    "later.example",
                    300,
                )
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
            .remember("session-a", "192.0.2.10", "example.test", 300)
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
            .remember("session-a", "192.0.2.10", "example.test", 300)
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
            .remember("session-a", "192.0.2.10", "old.example", 300)
            .expect("persist old attribution");

        writer
            .remember("session-a", "192.0.2.10", "new.example", 300)
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
            .remember("session-a", "192.0.2.10", "example.test", 300)
            .expect("persist attribution");

        std::fs::remove_file(&path).expect("remove persisted state");

        attribution
            .remember("session-a", "192.0.2.10", "example.test", 300)
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
            br#"{"version":2,"entries":[{"session_id":"session-a","ip":"192.0.2.10","hostname":"first.example","expires":99999999999.0},{"session_id":"session-a","ip":"192.0.2.10","hostname":"second.example","expires":99999999999.0}]}"#,
        )
        .expect("write duplicate state");

        let attribution = SessionAttribution::load(&path);
        assert_eq!(attribution.lookup("session-a", "192.0.2.10"), None);
        std::fs::remove_file(path).expect("remove duplicate state");
    }

    #[test]
    fn old_format_persisted_state_loads_empty() {
        let path = test_path("old-format");

        std::fs::write(
            &path,
            br#"{"version":1,"entries":[{"session_id":"session-a","ip":"192.0.2.10","hostname":"example.test"}]}"#,
        )
        .expect("write old-format state");

        let attribution = SessionAttribution::load(&path);
        assert_eq!(attribution.lookup("session-a", "192.0.2.10"), None);
        std::fs::remove_file(path).expect("remove old-format state");
    }

    #[test]
    fn mapping_stops_attributing_when_its_ttl_elapses() {
        let mut attribution = SessionAttribution::new();

        attribution
            .remember_at(1_000.0, "session-a", "192.0.2.10", "example.test", 60)
            .expect("remember attribution");

        assert_eq!(
            attribution.lookup_at(1_059.0, "session-a", "192.0.2.10"),
            Some("example.test")
        );

        assert_eq!(
            attribution.lookup_at(1_060.0, "session-a", "192.0.2.10"),
            None
        );
    }

    #[test]
    fn expired_mapping_is_not_loaded_from_disk() {
        let path = test_path("expired");
        let mut writer = SessionAttribution::load(&path);

        writer
            .remember_at(1_000.0, "session-a", "192.0.2.10", "example.test", 60)
            .expect("persist attribution");

        let fresh = SessionAttribution::load(&path);
        assert_eq!(fresh.lookup("session-a", "192.0.2.10"), None);
        std::fs::remove_file(path).expect("remove expired state");
    }

    #[test]
    fn hostile_names_and_session_ids_are_not_retained() {
        let mut attribution = SessionAttribution::new();

        for host in ["bad host.example", "a#b.example", "10.0.0.1"] {
            attribution
                .remember("session-a", "192.0.2.10", host, 300)
                .expect("remember");
        }

        attribution
            .remember(&"s".repeat(4096), "192.0.2.10", "ok.example", 300)
            .expect("remember");

        assert!(attribution.is_empty());
    }

    #[test]
    fn one_session_cannot_fill_the_table_for_others() {
        let mut attribution = SessionAttribution::new();

        for index in 0..(MAX_ENTRIES_PER_SESSION + 50) {
            attribution
                .remember(
                    "greedy",
                    &format!("10.1.{}.{}", index / 256, index % 256),
                    "a.example",
                    300,
                )
                .expect("remember");
        }

        assert_eq!(attribution.entries.len(), MAX_ENTRIES_PER_SESSION);

        // Other sessions still get entries until the global bound.
        for index in 0..MAX_ENTRIES {
            attribution
                .remember(
                    &format!("session-{}", index / 100),
                    &format!("10.2.{}.{}", index / 256, index % 256),
                    "b.example",
                    300,
                )
                .expect("remember");
        }

        assert_eq!(attribution.entries.len(), MAX_ENTRIES);
        assert_eq!(attribution.lookup("greedy", "10.1.0.0"), Some("a.example"));
    }
}
