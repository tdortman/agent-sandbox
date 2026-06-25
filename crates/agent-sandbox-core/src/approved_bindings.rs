//! Long-lived IP→hostname attribution hints from prior user approvals.
//!
//! Used only for UI display when the DNS cache has expired. Policy resolution
//! must not consult this table.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const APPROVED_BINDINGS_PATH: &str = "/run/agent-sandbox/approved-bindings.json";
pub const APPROVED_BINDINGS_TTL_SECS: u64 = 30 * 24 * 60 * 60;

const FILE_VERSION: u32 = 1;
const MAX_ALIASES_PER_IP: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
struct BindingsFile {
    version: u32,
    entries: HashMap<String, IpBindingEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IpBindingEntry {
    hosts: HashMap<String, f64>,
}

struct LiveIpBindings {
    hosts: HashMap<String, Instant>,
}

pub struct ApprovedBindings {
    path: PathBuf,
    ttl_secs: u64,
    entries: HashMap<String, LiveIpBindings>,
}

impl ApprovedBindings {
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let mut bindings = Self {
            path,
            ttl_secs: APPROVED_BINDINGS_TTL_SECS,
            entries: HashMap::new(),
        };
        bindings.reload_from_disk();
        bindings
    }

    fn reload_from_disk(&mut self) {
        let Ok(raw) = std::fs::read_to_string(&self.path) else {
            return;
        };
        let Ok(file) = serde_json::from_str::<BindingsFile>(&raw) else {
            return;
        };
        if file.version != FILE_VERSION {
            return;
        }
        let wall_now = unix_now();
        let live_now = Instant::now();
        self.entries.clear();
        for (ip, item) in file.entries {
            let mut hosts = HashMap::new();
            for (host, expires) in item.hosts {
                if expires <= wall_now {
                    continue;
                }
                let remaining = expires - wall_now;
                hosts.insert(host, live_now + Duration::from_secs_f64(remaining));
            }
            if !hosts.is_empty() {
                self.entries.insert(ip, LiveIpBindings { hosts });
            }
        }
    }

    /// Hostnames previously approved for `ip`, for UI attribution only.
    pub fn aliases(&self, ip: &str) -> Vec<String> {
        let now = Instant::now();
        let Some(entry) = self.entries.get(ip) else {
            return Vec::new();
        };
        let mut aliases: Vec<String> = entry
            .hosts
            .iter()
            .filter(|(host, expires)| **expires > now && !host.is_empty() && host.as_str() != ip)
            .map(|(host, _)| host.clone())
            .collect();
        aliases.sort();
        aliases.dedup();
        aliases
    }

    /// Remember that `host` was approved for `ip`.
    pub fn record(&mut self, host: &str, ip: &str) {
        let host = host.trim().to_lowercase().trim_end_matches('.').to_string();
        if host.is_empty() || host == ip {
            return;
        }
        let now = Instant::now();
        self.prune_expired(now);
        let entry = self
            .entries
            .entry(ip.to_string())
            .or_insert_with(|| LiveIpBindings {
                hosts: HashMap::new(),
            });
        entry
            .hosts
            .insert(host, now + Duration::from_secs(self.ttl_secs));
        self.enforce_limits(ip);
    }

    fn prune_expired(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            entry.hosts.retain(|_, expires| *expires > now);
            !entry.hosts.is_empty()
        });
    }

    fn enforce_limits(&mut self, ip: &str) {
        let Some(entry) = self.entries.get_mut(ip) else {
            return;
        };
        while entry.hosts.len() > MAX_ALIASES_PER_IP {
            let Some(oldest_host) = entry
                .hosts
                .iter()
                .min_by_key(|(_, expires)| *expires)
                .map(|(host, _)| host.clone())
            else {
                break;
            };
            entry.hosts.remove(&oldest_host);
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let now = Instant::now();
        let mut entries: HashMap<String, IpBindingEntry> = HashMap::new();
        for (ip, entry) in &self.entries {
            let mut hosts = HashMap::new();
            for (host, expires) in &entry.hosts {
                if *expires <= now {
                    continue;
                }
                let remaining = expires.duration_since(now).as_secs_f64();
                hosts.insert(host.clone(), unix_now() + remaining);
            }
            if !hosts.is_empty() {
                entries.insert(ip.clone(), IpBindingEntry { hosts });
            }
        }

        if let Ok(raw) = std::fs::read_to_string(&self.path)
            && let Ok(file) = serde_json::from_str::<BindingsFile>(&raw)
        {
            let wall_now = unix_now();
            for (ip, item) in file.entries {
                let mut merged: HashMap<String, f64> = item
                    .hosts
                    .into_iter()
                    .filter(|(_, expires)| *expires > wall_now)
                    .collect();
                if merged.is_empty() {
                    continue;
                }
                let slot = entries.entry(ip).or_insert_with(|| IpBindingEntry {
                    hosts: HashMap::new(),
                });
                for (host, expires) in merged.drain() {
                    slot.hosts.entry(host).or_insert(expires);
                }
            }
        }

        let snapshot = BindingsFile {
            version: FILE_VERSION,
            entries,
        };
        let data = serde_json::to_vec(&snapshot)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::{ApprovedBindings, BindingsFile, unix_now};

    #[test]
    fn record_and_aliases_roundtrip() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut bindings = ApprovedBindings::load(&path);
        bindings.record("chatgpt.com", "104.18.32.47");
        assert_eq!(
            bindings.aliases("104.18.32.47"),
            vec!["chatgpt.com".to_string()]
        );
    }

    #[test]
    fn record_normalizes_hostname() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut bindings = ApprovedBindings::load(&path);
        bindings.record("Example.COM.", "104.18.32.47");
        assert_eq!(
            bindings.aliases("104.18.32.47"),
            vec!["example.com".to_string()]
        );
    }

    #[test]
    fn record_skips_ip_literal_host() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut bindings = ApprovedBindings::load(&path);
        bindings.record("104.18.32.47", "104.18.32.47");
        assert!(bindings.aliases("104.18.32.47").is_empty());
    }

    #[test]
    fn save_and_load_persist_bindings() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut writer = ApprovedBindings::load(&path);
        writer.record("chatgpt.com", "104.18.32.47");
        writer.save().expect("save bindings");

        let reader = ApprovedBindings::load(&path);
        assert_eq!(
            reader.aliases("104.18.32.47"),
            vec!["chatgpt.com".to_string()]
        );
    }

    #[test]
    fn persisted_bindings_use_wall_clock_expiry() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let before = unix_now();
        let mut bindings = ApprovedBindings::load(&path);
        bindings.record("chatgpt.com", "104.18.32.47");
        bindings.save().expect("save bindings");

        let raw = std::fs::read_to_string(&path).expect("read bindings file");
        let file: BindingsFile = serde_json::from_str(&raw).expect("parse bindings json");
        let entry = file
            .entries
            .get("104.18.32.47")
            .expect("bindings file should contain IP entry");
        let expires = entry
            .hosts
            .get("chatgpt.com")
            .expect("bindings file should contain host entry");
        assert!(*expires > 30.0f64.mul_add(86_400.0, before) - 5.0);
    }

    #[test]
    fn two_writers_preserve_both_bindings() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut writer_a = ApprovedBindings::load(&path);
        writer_a.record("chatgpt.com", "104.18.32.47");
        writer_a.save().expect("save writer a");

        let mut writer_b = ApprovedBindings::load(&path);
        writer_b.record("example.com", "93.184.216.34");
        writer_b.save().expect("save writer b");

        let raw = std::fs::read_to_string(&path).expect("read bindings file");
        let file: BindingsFile = serde_json::from_str(&raw).expect("parse bindings json");
        assert_eq!(file.entries.len(), 2);
        assert!(file.entries.contains_key("104.18.32.47"));
        assert!(file.entries.contains_key("93.184.216.34"));
    }
}
