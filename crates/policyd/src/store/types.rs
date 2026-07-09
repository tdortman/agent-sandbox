//! Policy store types and shared state.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use agent_sandbox_core::{
    CheckReply, ElevateReply, FileAccess, FilesystemCheckReply, FilesystemRule, FilesystemRuleKey,
    NetworkRuleKey, ResourceAccess, ResourceCheckReply, ResourceKind, ResourceRuleKey,
    VerdictSource,
};
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex, oneshot};

/// Hard cap on the number of pending approval requests held in memory.
/// Beyond this cap new prompts are blocked instead of being added.
pub const MAX_PENDING_APPROVALS: usize = 512;

/// Hard cap on the number of waiters that may join a single pending request.
/// Beyond this cap extra waiters are blocked instead of being queued.
pub const MAX_WAITERS_PER_PENDING: usize = 64;

/// Hard cap on the size of the verdict caches. Older entries are evicted
/// (by `time` for the verdict cache, by `Instant` for the spawn throttle
/// map) when the cap is exceeded.
pub const MAX_VERDICT_CACHE_ENTRIES: usize = 1024;

/// Cap on the number of static filesystem allow rules retained per sandbox session.
pub const MAX_STATIC_ALLOW_RULES: usize = 4096;

/// Cap on concurrent RPC connections per local uid.
pub const MAX_CONNECTIONS_PER_UID: usize = 64;

/// Maximum JSON-line RPC payload size.
pub const MAX_RPC_LINE_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedPeer {
    pub pid: u32,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct SandboxSessionRegistration {
    pub root_pid: u32,
    pub owner_uid: u32,
    pub project_root: PathBuf,
}

/// Key for the network verdict cache: hostname and port.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NetworkVerdictKey {
    pub host: String,
    pub port: u16,
}

/// Key for the filesystem verdict cache: path and access type.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FilesystemVerdictKey {
    pub path: PathBuf,
    pub access: FileAccess,
}

/// Key for the resource verdict cache: kind, path, and access.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ResourceVerdictKey {
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
}

/// A cached verdict: whether it was allowed, from which source, and when.
#[derive(Debug, Clone)]
pub struct VerdictEntry {
    pub allowed: bool,
    pub source: VerdictSource,
    pub time: Instant,
}

/// Evict the oldest entries (by `VerdictEntry.time`) from a verdict cache
/// until the map is within the global cap.
pub fn enforce_verdict_cache_limit<K: Clone + Eq + std::hash::Hash>(
    map: &mut HashMap<K, VerdictEntry>,
) {
    while map.len() > MAX_VERDICT_CACHE_ENTRIES {
        let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, entry)| entry.time)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        map.remove(&oldest_key);
    }
}

pub static CLIENT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct PolicydArgs {
    pub host_socket: PathBuf,
    pub sandbox_socket: PathBuf,
    pub declarative: PathBuf,
    pub export_json: PathBuf,
    pub export_nix: Option<PathBuf>,
    pub approval_timeout: Duration,
    pub interactive_approval: bool,
    pub ui_spawn_cmd: Option<PathBuf>,
    /// Path to the agent-sandbox-fsmon binary.
    pub fs_monitor_cmd: Option<PathBuf>,
    /// Path to the agent-sandbox-syscall-broker binary.
    pub syscall_broker_cmd: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PendingElevation {
    pub id: String,
    pub created_at: f64,
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub sandbox_session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingNetwork {
    pub id: String,
    pub created_at: f64,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub url: String,
    pub aliases: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub sandbox_session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingFilesystem {
    pub id: String,
    pub created_at: f64,
    pub path: PathBuf,
    pub access: FileAccess,
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub sandbox_session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingResource {
    pub id: String,
    pub created_at: f64,
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub sandbox_session_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    Elevation,
    Network,
    Filesystem,
    Resource,
}

/// Discriminated union of pending approval requests.
///
/// The variant determines which fields are meaningful:
/// - `Elevation`: `argv` is required. `host`/`port`/`scheme`/`url` absent.
#[derive(Debug, Clone)]
pub enum Pending {
    Elevation(PendingElevation),
    Network(PendingNetwork),
    Filesystem(PendingFilesystem),
    Resource(PendingResource),
}

impl Pending {
    #[must_use]
    pub const fn kind(&self) -> PendingKind {
        match self {
            Self::Elevation(_) => PendingKind::Elevation,
            Self::Network(_) => PendingKind::Network,
            Self::Filesystem(_) => PendingKind::Filesystem,
            Self::Resource(_) => PendingKind::Resource,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Elevation(p) => &p.id,
            Self::Network(p) => &p.id,
            Self::Filesystem(p) => &p.id,
            Self::Resource(p) => &p.id,
        }
    }

    #[must_use]
    pub const fn created_at(&self) -> f64 {
        match self {
            Self::Elevation(p) => p.created_at,
            Self::Network(p) => p.created_at,
            Self::Filesystem(p) => p.created_at,
            Self::Resource(p) => p.created_at,
        }
    }

    #[must_use]
    pub fn cwd(&self) -> Option<&Path> {
        match self {
            Self::Elevation(p) => p.cwd.as_deref(),
            Self::Network(p) => p.cwd.as_deref(),
            Self::Filesystem(p) => p.cwd.as_deref(),
            Self::Resource(p) => p.cwd.as_deref(),
        }
    }

    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        match self {
            Self::Elevation(p) => p.home.as_deref(),
            Self::Network(p) => p.home.as_deref(),
            Self::Filesystem(p) => p.home.as_deref(),
            Self::Resource(p) => p.home.as_deref(),
        }
    }

    #[must_use]
    pub fn project_root(&self) -> Option<&Path> {
        match self {
            Self::Elevation(p) => p.project_root.as_deref(),
            Self::Network(p) => p.project_root.as_deref(),
            Self::Filesystem(p) => p.project_root.as_deref(),
            Self::Resource(p) => p.project_root.as_deref(),
        }
    }

    #[must_use]
    pub fn sandbox_session_id(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.sandbox_session_id.as_deref(),
            Self::Network(p) => p.sandbox_session_id.as_deref(),
            Self::Filesystem(p) => p.sandbox_session_id.as_deref(),
            Self::Resource(p) => p.sandbox_session_id.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UiSessionContext {
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub sandbox_session_id: Option<String>,
    pub owner_uid: Option<u32>,
    pub client_id: u64,
}

pub struct UiClientHandle {
    pub id: u64,
    pub(crate) writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
}

pub struct UiClient {
    pub session_id: String,
    pub writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
}

pub struct PolicyStore {
    pub(crate) args: PolicydArgs,
    pub(crate) inner: Mutex<StoreInner>,
    /// Single-flight guard for deny inode cache rebuilds: concurrent
    /// filesystem checks must wait for one rebuild instead of each starting
    /// their own recursive directory walk.
    pub(crate) deny_inode_rebuild: Mutex<()>,
    pub(crate) sandbox_sessions: Arc<RwLock<HashMap<String, SandboxSessionRegistration>>>,
    pub(crate) merged_cache: std::sync::Mutex<MergedPolicyCache>,
}

/// LRU-ish cache of merged policies keyed by context paths and source mtimes.
#[derive(Debug, Default)]
pub struct MergedPolicyCache {
    pub entries: HashMap<MergedCacheKey, agent_sandbox_core::Policy>,
    order: std::collections::VecDeque<MergedCacheKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergedCacheKey {
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub declarative_mtime: Option<MtimeKey>,
    pub home_policy_mtime: Option<MtimeKey>,
    pub project_policy_mtime: Option<MtimeKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MtimeKey {
    pub secs: u64,
    pub nanos: u32,
}

impl MergedPolicyCache {
    pub const MAX_ENTRIES: usize = 32;

    pub fn get(&self, key: &MergedCacheKey) -> Option<agent_sandbox_core::Policy> {
        self.entries.get(key).cloned()
    }

    pub fn insert(&mut self, key: MergedCacheKey, policy: agent_sandbox_core::Policy) {
        if let Some(existing) = self.entries.get_mut(&key) {
            *existing = policy;
            return;
        }
        while self.order.len() >= Self::MAX_ENTRIES {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, policy);
    }
}

pub struct StoreInner {
    pub session_allow: HashMap<String, HashSet<NetworkRuleKey>>,
    pub once_allow: HashSet<NetworkRuleKey>,
    pub pending: HashMap<String, Pending>,
    pub elevation_futures: HashMap<String, oneshot::Sender<ElevateReply>>,
    pub network_futures: HashMap<String, Vec<oneshot::Sender<CheckReply>>>,
    pub filesystem_futures: HashMap<String, Vec<oneshot::Sender<FilesystemCheckReply>>>,
    pub resource_futures: HashMap<String, Vec<oneshot::Sender<ResourceCheckReply>>>,
    pub ui_clients: HashMap<u64, UiClient>,
    pub ui_context_by_session: HashMap<String, UiSessionContext>,
    pub network_verdict_cache: HashMap<NetworkVerdictKey, VerdictEntry>,
    pub filesystem_verdict_cache: HashMap<FilesystemVerdictKey, VerdictEntry>,
    pub resource_verdict_cache: HashMap<ResourceVerdictKey, VerdictEntry>,
    pub ui_spawn_last: HashMap<String, Instant>,
    pub session_deny: HashMap<String, HashSet<NetworkRuleKey>>,
    pub session_sudo_allow: HashMap<String, HashSet<Vec<String>>>,
    pub session_sudo_deny: HashMap<String, HashSet<Vec<String>>>,
    pub session_filesystem_allow: HashMap<String, HashSet<FilesystemRuleKey>>,
    pub session_filesystem_deny: HashMap<String, HashSet<FilesystemRuleKey>>,
    pub session_resource_allow: HashMap<String, HashSet<ResourceRuleKey>>,
    pub session_resource_deny: HashMap<String, HashSet<ResourceRuleKey>>,
    /// Static filesystem allow rules registered by `StartFilesystemMonitor`,
    /// keyed by sandbox session id (or cwd/project-root context fallback).
    pub sandbox_filesystem_static_allow: HashMap<String, Vec<FilesystemRule>>,
    /// Inode cache for hardlink defense. Maps `(inode, device)` to canonical
    /// paths for files under deny rules. Built by walking deny directories and
    /// stat'ing concrete deny files. Fingerprinted by deny rule path mtimes.
    /// When the fingerprint changes the cache is rebuilt on next access.
    pub deny_inode_cache: DenyInodeCache,
    /// Active RPC connections per peer uid.
    pub connections_by_uid: HashMap<u32, usize>,
}

/// Fingerprint entry for a single deny rule path.
/// When any entry's path or mtime changes, the inode cache is rebuilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyFingerprint {
    pub path: PathBuf,
    pub access: FileAccess,
    pub mtime: Option<std::time::SystemTime>,
}

/// Inode→entries cache for hardlink defense against deny rule bypass.
///
/// When a request path's `InodeIdentity` is found in this cache, the
/// request is for a file that lives under (or is) a denied path.
/// The canonical paths and access levels are stored for matching.
#[derive(Debug, Clone, Default)]
pub struct DenyInodeCache {
    pub inodes: HashMap<agent_sandbox_core::InodeIdentity, Vec<DenyCacheEntry>>,
    pub fingerprint: Vec<DenyFingerprint>,
}

/// A single entry in the deny inode cache: the canonical path of the
/// denied file and the access level the deny rule covers.
#[derive(Debug, Clone)]
pub struct DenyCacheEntry {
    pub path: PathBuf,
    pub access: FileAccess,
}
