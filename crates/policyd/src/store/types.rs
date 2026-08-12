//! Policy store types and shared state.

use agent_sandbox_core::{
    AttributionToken, DbusTarget, FileAccess, FlowRegistration, HttpContextKey, HttpRequest,
    HttpRuleTarget, PendingHttpId, ProxyConnectionId, ProxySessionToken, ResolvedRequestContext,
    ResourceAccess, ResourceKind, SocketIdentity, VerdictSource,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock, atomic::AtomicU64},
    time::{Duration, Instant},
};
use tokio::{
    net::unix::OwnedWriteHalf,
    sync::{Mutex, oneshot},
};

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

/// Cap on the number of static filesystem allow rules retained per sandbox
/// session.
pub const MAX_STATIC_ALLOW_RULES: usize = 4096;

/// Cap on concurrent RPC connections per local uid.
pub const MAX_CONNECTIONS_PER_UID: usize = 64;

/// Maximum JSON-line RPC payload size.
pub const MAX_RPC_LINE_BYTES: usize = 1 << 20;

/// Hard cap on registered proxy flow identities.
pub const MAX_PROXY_FLOWS: usize = 65_536;

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
    pub package: Option<String>,

    /// PID of the launcher (wrapper) process that pre-registered the
    /// session. 0 means the session was not pre-registered. Such sessions
    /// keep the first-peer-claims-root adoption model.
    pub launcher_pid: u32,
}

/// Exact HTTP request and context used for pending approval deduplication.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HttpPendingKey {
    pub request: HttpRequest,
    pub context: HttpContextKey,
}

/// HTTP scope rule and context used for session/project/global state.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HttpScopeKey {
    pub target: HttpRuleTarget,
    pub context: HttpContextKey,
}

/// A cached verdict: whether it was allowed, from which source, and when.
#[derive(Debug, Clone)]
pub struct VerdictEntry {
    pub allowed: bool,
    pub source: VerdictSource,
    pub time: Instant,
}

pub fn evict_oldest<K, V, S>(
    map: &mut HashMap<K, V, S>,
    max_entries: usize,
    timestamp: impl Fn(&V) -> Instant,
) where
    K: Clone + Eq + std::hash::Hash,
    S: std::hash::BuildHasher,
{
    while map.len() > max_entries {
        let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, value)| timestamp(value))
            .map(|(key, _)| key.clone())
        else {
            break;
        };

        map.remove(&oldest_key);
    }
}

pub fn enforce_verdict_cache_limit<K: Clone + Eq + std::hash::Hash>(
    map: &mut HashMap<K, VerdictEntry>,
) {
    evict_oldest(map, MAX_VERDICT_CACHE_ENTRIES, |entry| entry.time);
}

pub static CLIENT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct PolicydArgs {
    pub host_socket: PathBuf,
    pub sandbox_socket: PathBuf,
    pub proxy_socket: Option<PathBuf>,
    pub proxy_gid: Option<u32>,
    pub declarative: PathBuf,
    pub export_json: PathBuf,
    pub export_nix: Option<PathBuf>,
    pub approval_timeout: Duration,
    pub interactive_approval: bool,
    pub ui_spawn_cmd: Option<PathBuf>,

    /// Per-package declarative base policy files, keyed by package name.
    /// Loaded as the package layer (between the global declarative policy
    /// and the user policy) for sessions attributed to that package.
    pub package_declarative: Vec<(String, PathBuf)>,

    /// Path to the agent-sandbox-fsmon binary.
    pub fs_monitor_cmd: Option<PathBuf>,

    /// Path to the agent-sandbox-syscall-broker binary.
    pub syscall_broker_cmd: Option<PathBuf>,
}

pub(super) struct PendingResult<I, T> {
    pub(super) id: I,
    pub(super) is_new: bool,
    pub(super) rx: oneshot::Receiver<T>,
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
    pub package: Option<String>,
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
    pub package: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingHttp {
    /// Wire/display identifier. The typed ID is retained in `pending_id`.
    pub id: String,

    pub pending_id: PendingHttpId,
    pub created_at: f64,
    pub request: HttpRequest,
    pub context: HttpContextKey,
    pub package: Option<String>,
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
    pub package: Option<String>,
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
    pub package: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingDbus {
    pub id: String,
    pub created_at: f64,
    pub target: DbusTarget,
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
    pub sandbox_session_id: Option<String>,
    pub package: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    Elevation,
    Network,
    Http,
    Filesystem,
    Resource,
    Dbus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingContext<'a> {
    pub(super) cwd: Option<&'a Path>,
    pub(super) home: Option<&'a Path>,
    pub(super) project_root: Option<&'a Path>,
    pub(super) sandbox_session_id: Option<&'a str>,
    pub(super) package: Option<&'a str>,
}

/// Discriminated union of pending approval requests.
///
/// The variant determines which fields are meaningful:
#[derive(Debug, Clone)]
pub enum Pending {
    Elevation(PendingElevation),
    Network(PendingNetwork),
    Http(PendingHttp),
    Filesystem(PendingFilesystem),
    Resource(PendingResource),
    Dbus(PendingDbus),
}

impl Pending {
    #[must_use]
    pub const fn kind(&self) -> PendingKind {
        match self {
            Self::Elevation(_) => PendingKind::Elevation,
            Self::Network(_) => PendingKind::Network,
            Self::Http(_) => PendingKind::Http,
            Self::Filesystem(_) => PendingKind::Filesystem,
            Self::Resource(_) => PendingKind::Resource,
            Self::Dbus(_) => PendingKind::Dbus,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Elevation(p) => &p.id,
            Self::Network(p) => &p.id,
            Self::Http(p) => &p.id,
            Self::Filesystem(p) => &p.id,
            Self::Resource(p) => &p.id,
            Self::Dbus(p) => &p.id,
        }
    }

    #[must_use]
    pub const fn created_at(&self) -> f64 {
        match self {
            Self::Elevation(p) => p.created_at,
            Self::Network(p) => p.created_at,
            Self::Http(p) => p.created_at,
            Self::Filesystem(p) => p.created_at,
            Self::Resource(p) => p.created_at,
            Self::Dbus(p) => p.created_at,
        }
    }

    #[must_use]
    pub fn cwd(&self) -> Option<&Path> {
        match self {
            Self::Elevation(p) => p.cwd.as_deref(),
            Self::Network(p) => p.cwd.as_deref(),
            Self::Http(p) => p.context.cwd.as_deref(),
            Self::Filesystem(p) => p.cwd.as_deref(),
            Self::Resource(p) => p.cwd.as_deref(),
            Self::Dbus(p) => p.cwd.as_deref(),
        }
    }

    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        match self {
            Self::Elevation(p) => p.home.as_deref(),
            Self::Network(p) => p.home.as_deref(),
            Self::Http(p) => p.context.home.as_deref(),
            Self::Filesystem(p) => p.home.as_deref(),
            Self::Resource(p) => p.home.as_deref(),
            Self::Dbus(p) => p.home.as_deref(),
        }
    }

    #[must_use]
    pub fn project_root(&self) -> Option<&Path> {
        match self {
            Self::Elevation(p) => p.project_root.as_deref(),
            Self::Network(p) => p.project_root.as_deref(),
            Self::Http(p) => p.context.project_root.as_deref(),
            Self::Filesystem(p) => p.project_root.as_deref(),
            Self::Resource(p) => p.project_root.as_deref(),
            Self::Dbus(p) => p.project_root.as_deref(),
        }
    }

    #[must_use]
    pub fn sandbox_session_id(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.sandbox_session_id.as_deref(),
            Self::Network(p) => p.sandbox_session_id.as_deref(),
            Self::Http(p) => p.context.sandbox_session_id.as_deref(),
            Self::Filesystem(p) => p.sandbox_session_id.as_deref(),
            Self::Resource(p) => p.sandbox_session_id.as_deref(),
            Self::Dbus(p) => p.sandbox_session_id.as_deref(),
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

#[derive(Clone)]
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
    pub(crate) inner: Mutex<PolicyDecisionState>,

    /// Single-flight guard for deny inode cache rebuilds: concurrent
    /// filesystem checks must wait for one rebuild instead of each starting
    /// their own recursive directory walk.
    pub(crate) deny_inode_rebuild: Mutex<()>,

    /// Serializes UI spawn decisions so concurrent requests cannot launch
    /// duplicate clients from the same throttle snapshot.
    pub(crate) ui_spawn_lock: Mutex<()>,

    pub(crate) sandbox_sessions: Arc<RwLock<HashMap<String, SandboxSessionRegistration>>>,
    pub(crate) merged_cache: std::sync::Mutex<MergedPolicyCache>,
    pub(crate) cgroup_freeze: super::freeze::CgroupFreezeManager,
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
    pub package: Option<String>,
    pub package_base_mtime: Option<MtimeKey>,
    pub package_home_mtime: Option<MtimeKey>,
    pub package_project_mtime: Option<MtimeKey>,
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

#[derive(Debug)]
pub struct ProxySessionState {
    pub token: ProxySessionToken,
    pub connection_id: u64,
    pub opened_at: Instant,
}

#[derive(Debug)]
pub struct ProxyFlowState {
    pub registration: FlowRegistration,
    pub owner: SocketIdentity,
    pub context: ResolvedRequestContext,
    pub attribution_token: Option<AttributionToken>,
    pub connection_id: Option<ProxyConnectionId>,
    pub claimed_at: Option<Instant>,
    pub last_check: Instant,
}

pub enum ProxyCancellation {
    Active(oneshot::Sender<()>),
    Canceled,
}

// The decision state lives in `state`, where the deny-wins session
// buckets and the pending board concentrate their invariants.
pub use super::state::{HttpWaiter, NetworkWaiter, PolicyDecisionState, ProxyCheckId};

/// Fingerprint entry for one concrete deny rule path.
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
