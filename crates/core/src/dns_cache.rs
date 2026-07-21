//! Shared IP→hostname cache populated by the DNS forwarder.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub const DEFAULT_CACHE_PATH: &str = "/run/agent-sandbox/dns-cache.json";
pub const DEFAULT_MAX_TTL: u32 = 600;
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    host: String,
    expires: f64,
}

struct LiveCacheEntry {
    host: String,
    expires: Instant,
}

pub struct DnsCache {
    path: Option<PathBuf>,
    max_ttl: u32,
    max_entries: usize,
    entries: HashMap<String, LiveCacheEntry>,
}
impl DnsCache {
    pub fn new(path: Option<impl AsRef<Path>>, max_ttl: u32) -> Self {
        Self {
            path: path.map(|p| p.as_ref().to_path_buf()),
            max_ttl: max_ttl.max(1),
            max_entries: DEFAULT_MAX_ENTRIES.max(1),
            entries: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn new_with_max_entries(
        path: Option<impl AsRef<Path>>,
        max_ttl: u32,
        max_entries: usize,
    ) -> Self {
        Self {
            path: path.map(|p| p.as_ref().to_path_buf()),
            max_ttl: max_ttl.max(1),
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
        }
    }

    /// Remember a hostname mapping in memory only: never writes to disk.
    pub fn remember_ephemeral(&mut self, ip: &str, hostname: &str, ttl: u32) {
        self.insert_entry(ip, hostname, ttl);
    }

    pub fn remember(&mut self, ip: &str, hostname: &str, ttl: u32) {
        self.insert_entry(ip, hostname, ttl);
        if self.path.is_some() {
            let _ = self.persist();
        }
    }

    /// Shared validation, normalization, and insertion logic.
    fn insert_entry(&mut self, ip: &str, hostname: &str, ttl: u32) {
        let host = hostname
            .trim()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();
        if host.is_empty() || host == ip {
            return;
        }
        let ttl = ttl.clamp(1, self.max_ttl);
        let now = Instant::now();
        self.prune_expired(now);
        self.entries.insert(ip.to_string(), LiveCacheEntry {
            host,
            expires: now + Duration::from_secs(u64::from(ttl)),
        });
        self.enforce_max_entries();
    }

    fn prune_expired(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires > now);
    }

    fn enforce_max_entries(&mut self) {
        while self.entries.len() > self.max_entries {
            let Some(oldest_ip) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(ip, _)| ip.clone())
            else {
                break;
            };
            self.entries.remove(&oldest_ip);
        }
    }

    #[must_use]
    pub fn lookup(&self, ip: &str) -> Option<String> {
        let entry = self.entries.get(ip)?;
        if Instant::now() >= entry.expires {
            return None;
        }
        Some(entry.host.clone())
    }

    fn persist(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let now = Instant::now();

        // Build live entries (live → wall-clock expiry).
        let mut entries: HashMap<String, CacheEntry> = HashMap::new();
        for (ip, entry) in &self.entries {
            if entry.expires <= now {
                continue;
            }
            let remaining = entry.expires.duration_since(now).as_secs_f64();
            entries.insert(ip.clone(), CacheEntry {
                host: entry.host.clone(),
                expires: unix_now() + remaining,
            });
        }

        // Merge existing unexpired disk entries so a writer with a partial
        // in-memory view does not drop unrelated mappings.
        if let Ok(raw) = std::fs::read_to_string(path)
            && let Ok(file) = serde_json::from_str::<CacheFile>(&raw)
        {
            let wall_now = unix_now();
            for (ip, item) in file.entries {
                if item.expires <= wall_now {
                    continue;
                }
                // Live entries take precedence for the same IP.
                entries.entry(ip).or_insert(item);
            }
        }

        let snapshot = CacheFile {
            version: 1,
            entries,
        };
        let data = serde_json::to_vec(&snapshot)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    /// Reload entries from disk, replacing the in-memory cache.
    pub fn reload(&mut self) {
        let Some(path) = &self.path else {
            return;
        };
        let Ok(raw) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(file) = serde_json::from_str::<CacheFile>(&raw) else {
            return;
        };
        if file.version != 1 {
            return;
        }
        let now = unix_now();
        self.entries.clear();
        for (ip, item) in file.entries {
            if item.expires <= now {
                continue;
            }
            let remaining = item.expires - now;
            self.entries.insert(ip, LiveCacheEntry {
                host: item.host,
                expires: Instant::now() + Duration::from_secs_f64(remaining),
            });
        }
    }
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64())
}

pub fn lookup_dns_cache(ip: &str, cache_path: Option<&Path>) -> Option<String> {
    let path = cache_path
        .map(std::path::Path::to_path_buf)
        .or_else(|| {
            std::env::var("AGENT_SANDBOX_DNS_CACHE")
                .ok()
                .map(PathBuf::from)
        })
        .or_else(|| Some(PathBuf::from(DEFAULT_CACHE_PATH)));
    let mut cache = DnsCache::new(path, DEFAULT_MAX_TTL);
    cache.reload();
    cache.lookup(ip)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CacheFile, DnsCache, unix_now};

    #[test]
    fn persisted_cache_uses_wall_clock_expiry() {
        let dir = tempfile::tempdir().expect("create temp dir for dns cache test");
        let path = dir.path().join("dns-cache.json");
        let before = unix_now();

        let mut cache = DnsCache::new(Some(&path), 300);
        cache.remember("104.18.32.47", "example.com", 60);

        let raw = std::fs::read_to_string(&path).expect("read persisted dns cache file");
        let file: CacheFile = serde_json::from_str(&raw).expect("parse persisted dns cache json");
        let entry = file
            .entries
            .get("104.18.32.47")
            .expect("cache file should contain 104.18.32.47 entry");
        assert_eq!(entry.host, "example.com");
        assert!(entry.expires > before + 1.0);
    }

    #[test]
    fn lookup_reads_hostname_from_persisted_cache() {
        let dir = tempfile::tempdir().expect("create temp dir for dns cache test");
        let path = dir.path().join("dns-cache.json");

        let mut writer = DnsCache::new(Some(&path), 300);
        writer.remember("104.18.32.47", "Example.COM.", 60);

        let mut reader = DnsCache::new(Some(&path), 300);
        reader.reload();
        assert_eq!(
            reader.lookup("104.18.32.47"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn reload_picks_up_new_entries_without_recreating_cache() {
        let dir = tempfile::tempdir().expect("create temp dir for dns cache test");
        let path = dir.path().join("dns-cache.json");

        let mut writer = DnsCache::new(Some(&path), 300);
        writer.remember("10.0.0.1", "first.example", 60);

        let mut reader = DnsCache::new(Some(&path), 300);
        reader.reload();
        assert_eq!(reader.lookup("10.0.0.1"), Some("first.example".to_string()));
        assert!(reader.lookup("10.0.0.2").is_none());

        writer.remember("10.0.0.2", "second.example", 60);

        reader.reload();
        assert_eq!(reader.lookup("10.0.0.1"), Some("first.example".to_string()));
        assert_eq!(
            reader.lookup("10.0.0.2"),
            Some("second.example".to_string())
        );
    }

    #[test]
    fn lookup_without_reload_returns_none_for_disk_only_entries() {
        let dir = tempfile::tempdir().expect("create temp dir for dns cache test");
        let path = dir.path().join("dns-cache.json");

        let mut writer = DnsCache::new(Some(&path), 300);
        writer.remember("10.0.0.3", "disk-only.example", 60);

        let reader = DnsCache::new(Some(&path), 300);
        // Without reload(), lookup() only sees in-memory entries.
        assert!(reader.lookup("10.0.0.3").is_none());
    }

    #[test]
    fn remember_ephemeral_does_not_touch_disk() {
        let dir = tempfile::tempdir().expect("create temp dir for dns cache test");
        let path = dir.path().join("dns-cache.json");

        let mut cache = DnsCache::new(Some(&path), 300);
        assert!(!path.exists());

        cache.remember_ephemeral("10.0.0.1", "ephemeral.example", 60);

        // Memory-only: no file should exist.
        assert!(!path.exists(), "ephemeral remember created a cache file");

        // The mapping IS usable from this instance.
        assert_eq!(
            cache.lookup("10.0.0.1"),
            Some("ephemeral.example".to_string())
        );

        // A second instance cannot see it (never persisted).
        let mut reader = DnsCache::new(Some(&path), 300);
        reader.reload();
        assert!(reader.lookup("10.0.0.1").is_none());
    }

    #[test]
    fn two_writers_preserve_both_mappings() {
        let dir = tempfile::tempdir().expect("create temp dir for dns cache test");
        let path = dir.path().join("dns-cache.json");

        // Writer A knows about IP 1.
        let mut writer_a = DnsCache::new(Some(&path), 300);
        writer_a.remember("192.168.1.1", "host-a.example", 60);

        // Writer B knows only about IP 2.  Without merge, its persist would
        // drop the host-a mapping.
        let mut writer_b = DnsCache::new(Some(&path), 300);
        writer_b.reload();
        writer_b.remember("192.168.1.2", "host-b.example", 60);

        // Both mappings survive on disk.
        let raw = std::fs::read_to_string(&path).expect("read persisted dns cache file");
        let file: CacheFile = serde_json::from_str(&raw).expect("parse persisted dns cache json");
        assert_eq!(file.entries.len(), 2, "expected both IPs in cache file");
        assert_eq!(
            file.entries.get("192.168.1.1").map(|e| &*e.host),
            Some("host-a.example")
        );
        assert_eq!(
            file.entries.get("192.168.1.2").map(|e| &*e.host),
            Some("host-b.example")
        );
    }

    #[test]
    fn expired_entries_removed_on_next_insert() {
        let mut cache = DnsCache::new_with_max_entries(None::<std::path::PathBuf>, 1, 10);
        cache.remember_ephemeral("10.0.0.1", "first.example", 1);
        cache.remember_ephemeral("10.0.0.2", "second.example", 1);
        assert_eq!(cache.entries.len(), 2);
        std::thread::sleep(Duration::from_millis(1_100));
        cache.remember_ephemeral("10.0.0.3", "third.example", 1);
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.lookup("10.0.0.3").is_some());
    }

    #[test]
    fn bounded_cache_evicts_earliest_expiring_entries() {
        let mut cache = DnsCache::new_with_max_entries(None::<std::path::PathBuf>, 300, 3);
        cache.remember_ephemeral("10.0.0.1", "first.example", 60);
        cache.remember_ephemeral("10.0.0.2", "second.example", 120);
        cache.remember_ephemeral("10.0.0.3", "third.example", 180);
        cache.remember_ephemeral("10.0.0.4", "fourth.example", 240);
        assert_eq!(cache.entries.len(), 3);
        assert!(cache.lookup("10.0.0.1").is_none());
        assert!(cache.lookup("10.0.0.4").is_some());
    }
}
