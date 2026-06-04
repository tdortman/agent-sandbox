//! Shared IP→hostname cache populated by the DNS proxy.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

pub const DEFAULT_CACHE_PATH: &str = "/run/agent-sandbox/dns-cache.json";
pub const DEFAULT_MAX_TTL: u32 = 600;

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

pub struct DnsCache {
    path: Option<PathBuf>,
    max_ttl: u32,
    entries: HashMap<String, (String, Instant)>,
}

impl DnsCache {
    pub fn new(path: Option<impl AsRef<Path>>, max_ttl: u32) -> Self {
        Self {
            path: path.map(|p| p.as_ref().to_path_buf()),
            max_ttl: max_ttl.max(1),
            entries: HashMap::new(),
        }
    }

    pub fn remember(&mut self, ip: &str, hostname: &str, ttl: u32) {
        let host = hostname
            .trim()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();
        if host.is_empty() || host == ip {
            return;
        }
        let ttl = ttl.clamp(1, self.max_ttl);
        self.entries.insert(
            ip.to_string(),
            (
                host,
                Instant::now() + std::time::Duration::from_secs(ttl as u64),
            ),
        );
        if self.path.is_some() {
            let _ = self.persist();
        }
    }

    pub fn lookup(&mut self, ip: &str) -> Option<String> {
        if self.path.as_ref().is_some_and(|p| p.is_file()) {
            self.load();
        }
        let (host, expires) = self.entries.get(ip)?;
        if Instant::now() >= *expires {
            self.entries.remove(ip);
            if self.path.is_some() {
                let _ = self.persist();
            }
            return None;
        }
        Some(host.clone())
    }

    fn persist(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let now = Instant::now();
        let mut entries = HashMap::new();
        for (ip, (host, expires)) in &self.entries {
            if *expires <= now {
                continue;
            }
            let mono = expires.duration_since(now).as_secs_f64();
            entries.insert(
                ip.clone(),
                CacheEntry {
                    host: host.clone(),
                    expires: mono_now() + mono,
                },
            );
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

    fn load(&mut self) {
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
        let now = mono_now();
        for (ip, item) in file.entries {
            if item.expires <= now {
                continue;
            }
            let remaining = item.expires - now;
            self.entries.insert(
                ip,
                (
                    item.host,
                    Instant::now() + std::time::Duration::from_secs_f64(remaining),
                ),
            );
        }
    }
}

fn mono_now() -> f64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_secs_f64()
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
    cache.lookup(ip)
}
