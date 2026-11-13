//! Pinned verdict cache between nfq and the in-kernel destination gate.
//!
//! The daemon publishes policyd's replayable destination verdicts into the
//! `verdicts` map and consults them before the next RPC for the same
//! (namespace, protocol, IP, port). Entries carry the namespace generation
//! they were published under; a generation mismatch is a miss, so revocation
//! retires every entry with one map write instead of a scan.

use std::{
    io,
    os::fd::AsFd,
    path::Path,
    sync::{Arc, Mutex},
};

use agent_sandbox_core::verdict_map::{
    DestKey, NamespaceState, VERDICT_PROTO_TCP, VERDICT_PROTO_UDP, VerdictMap,
};
use tracing::{debug, info, warn};

use crate::{
    args::Cli,
    packet::{PacketMeta, TransportProtocol},
};

/// Read the current network namespace cookie from a throwaway socket.
///
/// The daemon runs inside the sandbox namespace, so a socket it creates
/// there carries that namespace's cookie.
fn current_netns_cookie() -> io::Result<u64> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    agent_sandbox_sysutil::netns_cookie(socket.as_fd())
}

/// Destination verdicts the daemon may consult and publish.
///
/// The trait keeps the packet path testable without pinned kernel maps: the
/// production implementation wraps [`VerdictMap`], tests inject a fake.
pub trait VerdictCache: Send + Sync {
    /// Cached verdict for `key` when its generation is still current, or
    /// `None` on a miss, a stale generation, or a read failure.
    fn cached_verdict(&self, key: &DestKey) -> Option<u8>;

    /// Publish one decision under the current generation. Failures are
    /// logged inside and never propagate to the packet loop.
    fn publish_verdict(&self, key: &DestKey, verdict: u8);

    /// Drop one cached decision. Used when policyd returns a fresh approval
    /// the cache refuses to publish, so a stale deny cannot shadow it.
    fn clear_verdict(&self, key: &DestKey);

    /// Retire every entry for this namespace: block new flows, bump the
    /// generation so published entries go inert without a scan, then unblock
    /// once the new state is published. Failures are logged inside.
    fn invalidate(&self);
}

/// Production [`VerdictCache`] over the pinned maps for one namespace.
#[derive(Debug)]
pub struct MapVerdictCache {
    map: Mutex<VerdictMap>,
    netns: u64,
}

impl MapVerdictCache {
    /// Open the pinned maps and publish the initial namespace state.
    ///
    /// # Errors
    /// Returns an error when the pins are missing or unreadable, or when the
    /// initial state cannot be published.
    pub fn open(directory: &Path, netns: u64, proxy_uid: u32) -> io::Result<Self> {
        let mut map = VerdictMap::open(directory)?;
        map.set_state(netns, NamespaceState {
            generation: 1,
            blocked: 0,
            proxy_uid,
            reserved: 0,
        })?;
        Ok(Self {
            map: Mutex::new(map),
            netns,
        })
    }
}

impl VerdictCache for MapVerdictCache {
    fn cached_verdict(&self, key: &DestKey) -> Option<u8> {
        let Ok(map) = self.map.lock() else {
            return None;
        };
        match map.lookup(key) {
            Ok(Some(value)) if value.generation == map.generation() => Some(value.verdict),
            Ok(_) => None,
            Err(error) => {
                debug!(%error, "verdict cache lookup failed; consulting policyd");
                None
            }
        }
    }

    fn publish_verdict(&self, key: &DestKey, verdict: u8) {
        let Ok(map) = self.map.lock() else {
            warn!("verdict cache lock poisoned; skipping publish");
            return;
        };
        if let Err(error) = map.publish(key, verdict) {
            warn!(%error, "verdict cache publish failed");
        }
    }

    fn clear_verdict(&self, key: &DestKey) {
        let Ok(map) = self.map.lock() else {
            warn!("verdict cache lock poisoned; skipping clear");
            return;
        };
        if let Err(error) = map.remove(key) {
            debug!(%error, "verdict cache clear failed");
        }
    }

    fn invalidate(&self) {
        let Ok(mut map) = self.map.lock() else {
            warn!("verdict cache lock poisoned; skipping invalidation");
            return;
        };
        let blocked = match BlockedNamespace::enter(&mut map, self.netns) {
            Ok(blocked) => blocked,
            Err(error) => {
                warn!(%error, "verdict cache block failed");
                return;
            }
        };
        match blocked.bump() {
            Ok(bumped) => bumped.reopen(),
            Err(error) => warn!(%error, "verdict cache invalidation failed"),
        }
    }
}

/// A namespace whose new flows the kernel gate is blocking.
///
/// Dropping it unblocks the namespace, so every early return after the block
/// reopens the gate instead of leaving the kernel wedged.
struct BlockedNamespace<'a> {
    map: &'a mut VerdictMap,
    netns: u64,
}

impl<'a> BlockedNamespace<'a> {
    /// Block new flows for `netns`.
    fn enter(map: &'a mut VerdictMap, netns: u64) -> io::Result<Self> {
        map.set_blocked(netns, true)?;
        Ok(Self { map, netns })
    }

    /// Bump the generation so every published entry goes inert. On failure
    /// the error is returned and dropping `self` unblocks the namespace.
    fn bump(self) -> io::Result<BumpedNamespace<'a>> {
        self.map.invalidate(self.netns)?;
        Ok(BumpedNamespace(self))
    }
}

impl Drop for BlockedNamespace<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.map.set_blocked(self.netns, false) {
            warn!(%error, "verdict cache unblock failed");
        }
    }
}

/// A blocked namespace whose generation has been bumped.
struct BumpedNamespace<'a>(BlockedNamespace<'a>);

impl BumpedNamespace<'_> {
    /// Unblock new flows now that the new generation is published.
    fn reopen(self) {
        drop(self.0);
    }
}

/// Map key for one transport destination in one sandbox namespace.
#[must_use]
pub fn dest_key(netns: u64, meta: PacketMeta) -> DestKey {
    let proto = match meta.protocol {
        TransportProtocol::Tcp => VERDICT_PROTO_TCP,
        TransportProtocol::Udp => VERDICT_PROTO_UDP,
    };
    DestKey::new(netns, proto, meta.dst_ip, meta.dst_port)
}

/// Verdict cache state for this daemon.
///
/// Any failure to open the cache degrades to [`Self::Disabled`]: the daemon
/// consults policyd for every flow, exactly as without the flag.
#[derive(Clone)]
pub enum VerdictCacheHandle<V: VerdictCache = MapVerdictCache> {
    /// No cache: every flow consults policyd.
    Disabled,
    /// Pinned-map cache opened for one namespace and proxy uid.
    Enabled {
        /// Pinned-map verdict cache.
        cache: Arc<V>,
        /// Namespace cookie the cache was opened for.
        netns: u64,
        /// Proxy uid the cache was opened for.
        proxy_uid: u32,
    },
}

impl<V: VerdictCache> VerdictCacheHandle<V> {
    /// The cache itself, when enabled.
    #[must_use]
    pub const fn cache(&self) -> Option<&Arc<V>> {
        match self {
            Self::Disabled => None,
            Self::Enabled { cache, .. } => Some(cache),
        }
    }
}

/// Open the verdict cache for this daemon, or explain once why it stays off.
pub fn open_verdict_cache(cli: &Cli) -> VerdictCacheHandle {
    let Some(directory) = cli.verdict_map.as_deref() else {
        info!(
            "verdict cache unavailable: no verdict map directory; consulting policyd for every \
             flow"
        );
        return VerdictCacheHandle::Disabled;
    };
    let Some(proxy_uid) = cli.proxy_uid else {
        info!("verdict cache unavailable: no proxy uid; consulting policyd for every flow");
        return VerdictCacheHandle::Disabled;
    };
    let netns = match current_netns_cookie() {
        Ok(netns) => netns,
        Err(error) => {
            info!(%error, "verdict cache unavailable: cannot read namespace cookie");
            return VerdictCacheHandle::Disabled;
        }
    };
    match MapVerdictCache::open(directory, netns, proxy_uid) {
        Ok(cache) => {
            info!(netns, proxy_uid, "verdict cache enabled");
            VerdictCacheHandle::Enabled {
                cache: Arc::new(cache),
                netns,
                proxy_uid,
            }
        }
        Err(error) => {
            info!(%error, "verdict cache unavailable: cannot open verdict maps");
            VerdictCacheHandle::Disabled
        }
    }
}
