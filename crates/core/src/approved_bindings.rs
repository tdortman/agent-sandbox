//! Long-lived IP→hostname attribution hints from prior user approvals.
//!
//! Shown in prompts next to the names the DNS cache currently maps to the same
//! IP, so the user sees every name the destination may belong to. Policy
//! resolution must not consult this table.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    dns_cache::{evict_oldest, unix_now, write_json_atomic},
    hosts::{is_displayable_hostname, normalize_host},
};

/// Default on-disk approved-bindings location:
/// `/run/agent-sandbox/approved-bindings.json`.
pub const APPROVED_BINDINGS_PATH: &str = "/run/agent-sandbox/approved-bindings.json";

/// How long (in seconds) an approved binding is retained before it expires.
pub const APPROVED_BINDINGS_TTL_SECS: u64 = 30 * 24 * 60 * 60;

const FILE_VERSION: u32 = 1;
const MAX_ALIASES_PER_IP: usize = 16;

/// Addresses the table keeps; the one whose newest binding is oldest goes
/// first. Bounds memory and the file under `/run` against flows to many
/// addresses under one approved name.
const MAX_IPS: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
struct BindingsFile {
    version: u32,
    entries: HashMap<String, IpBindingEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IpBindingEntry {
    hosts: HashMap<String, f64>,
}

#[derive(Clone)]
struct LiveIpBindings {
    hosts: HashMap<String, Instant>,
}

/// Long-lived IP→hostname attribution table persisted to a JSON file.
///
/// Used only for UI display when the DNS cache has expired; policy resolution
/// must not consult this table.
#[derive(Clone)]
pub struct ApprovedBindings {
    path: PathBuf,
    entries: HashMap<String, LiveIpBindings>,
}

impl ApprovedBindings {
    /// Load approved bindings from `path`, merging any existing entries.
    ///
    /// A missing or unreadable file yields an empty table rather than an error.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();

        let mut bindings = Self {
            path,
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
                if expires <= wall_now || !is_displayable_hostname(&host) {
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
    ///
    /// An IP can be shared by unrelated names, so these are other names the IP
    /// has been seen under, not names the current flow is known to be for.
    #[must_use]
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
        let host = normalize_host(host);

        if host.is_empty() || host == ip || !is_displayable_hostname(&host) {
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
            .insert(host, now + Duration::from_secs(APPROVED_BINDINGS_TTL_SECS));

        self.enforce_limits(ip);

        evict_oldest(&mut self.entries, MAX_IPS, |entry| {
            entry.hosts.values().max().copied().unwrap_or(now)
        });
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

        evict_oldest(&mut entry.hosts, MAX_ALIASES_PER_IP, |expires| *expires);
    }

    /// Save bindings to the JSON cache file at `self.path`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the parent directory cannot be created, the data cannot
    /// be serialized to JSON, or the atomic write (temp file + rename)
    /// fails.
    pub fn save(&self) -> std::io::Result<()> {
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

        bound_entries(&mut entries);

        let snapshot = BindingsFile {
            version: FILE_VERSION,
            entries,
        };

        write_json_atomic(&self.path, &snapshot)
    }
}

/// Trim a snapshot to [`MAX_ALIASES_PER_IP`] hosts per address and
/// [`MAX_IPS`] addresses; the soonest-expiring go first.
fn bound_entries(entries: &mut HashMap<String, IpBindingEntry>) {
    for entry in entries.values_mut() {
        if entry.hosts.len() > MAX_ALIASES_PER_IP {
            let mut expiries: Vec<f64> = entry.hosts.values().copied().collect();
            expiries.sort_by(f64::total_cmp);
            let cutoff = expiries[expiries.len() - MAX_ALIASES_PER_IP - 1];
            entry.hosts.retain(|_, expires| *expires > cutoff);
        }
    }

    if entries.len() > MAX_IPS {
        let mut newest: Vec<f64> = entries
            .values()
            .map(|entry| entry.hosts.values().copied().fold(0.0, f64::max))
            .collect();

        newest.sort_by(f64::total_cmp);
        let cutoff = newest[newest.len() - MAX_IPS - 1];
        entries.retain(|_, entry| entry.hosts.values().copied().fold(0.0, f64::max) > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovedBindings, BindingsFile, MAX_IPS, unix_now};

    #[test]
    fn record_and_aliases_roundtrip() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut bindings = ApprovedBindings::load(&path);
        bindings.record("chatgpt.com", "104.18.32.47");

        assert_eq!(bindings.aliases("104.18.32.47"), vec![
            "chatgpt.com".to_string()
        ]);
    }

    #[test]
    fn record_normalizes_hostname() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut bindings = ApprovedBindings::load(&path);
        bindings.record("Example.COM.", "104.18.32.47");

        assert_eq!(bindings.aliases("104.18.32.47"), vec![
            "example.com".to_string()
        ]);
    }

    #[test]
    fn record_skips_ip_literal_host() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut bindings = ApprovedBindings::load(&path);
        bindings.record("104.18.32.47", "104.18.32.47");
        assert_eq!(bindings.aliases("104.18.32.47"), Vec::<String>::new());
    }

    #[test]
    fn save_and_load_persist_bindings() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut writer = ApprovedBindings::load(&path);
        writer.record("chatgpt.com", "104.18.32.47");
        writer.save().expect("save bindings");
        let reader = ApprovedBindings::load(&path);

        assert_eq!(reader.aliases("104.18.32.47"), vec![
            "chatgpt.com".to_string()
        ]);
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

    #[test]
    fn hostile_names_are_not_recorded_and_addresses_stay_bounded() {
        let dir = tempfile::tempdir().expect("create temp dir for bindings test");
        let path = dir.path().join("approved-bindings.json");
        let mut bindings = ApprovedBindings::load(&path);

        for host in [
            "bad host.example",
            "a#b.example",
            "good.example?.evil.example",
        ] {
            bindings.record(host, "203.0.113.9");
        }

        assert_eq!(bindings.aliases("203.0.113.9"), Vec::<String>::new());

        for index in 0..(MAX_IPS + 50) {
            bindings.record(
                "wild.example",
                &format!("10.{}.{}.1", index / 256, index % 256),
            );
        }

        assert_eq!(bindings.entries.len(), MAX_IPS);
        bindings.save().expect("save bindings");

        let raw = std::fs::read_to_string(&path).expect("read bindings file");
        let file: BindingsFile = serde_json::from_str(&raw).expect("parse bindings json");
        assert!(file.entries.len() <= MAX_IPS);
    }
}
