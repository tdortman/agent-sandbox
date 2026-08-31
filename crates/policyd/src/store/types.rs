//! Policy store types and shared state.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock, atomic::AtomicU64},
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    AttributionToken, DbusTarget, FileAccess, FlowRegistration, HttpContextKey, HttpRequest,
    HttpRuleTarget, PendingHttpId, PendingSummary, ProxyConnectionId, ProxySessionToken,
    ResolvedRequestContext, ResourceAccess, ResourceKind, SocketIdentity, VerdictSource,
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

/// A process trusted as a policy connection peer, identified by pid and uid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedPeer {
    /// Pid of the trusted peer process.
    pub pid: u32,
    /// Uid of the trusted peer.
    pub uid: u32,
}

/// Registration of a sandbox session against the policy store.
#[derive(Debug, Clone)]
pub struct SandboxSessionRegistration {
    /// Root pid of the sandbox session.
    pub root_pid: u32,
    /// Uid that owns the sandbox session.
    pub owner_uid: u32,
    /// Optional package the session is attributed to.
    pub package: Option<String>,

    /// PID of the launcher (wrapper) process that pre-registered the
    /// session. 0 means the session was not pre-registered. Such sessions
    /// keep the first-peer-claims-root adoption model.
    pub launcher_pid: u32,
    /// Process start time paired with `launcher_pid` to reject PID reuse.
    pub launcher_start_time_ticks: u64,
}

/// Exact HTTP request and context used for pending approval deduplication.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HttpPendingKey {
    /// HTTP request captured for deduplication.
    pub request: HttpRequest,
    /// Context key identifying the request origin.
    pub context: HttpContextKey,
}

/// HTTP scope rule and context used for session/project/global state.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HttpScopeKey {
    /// HTTP rule target for the scope.
    pub target: HttpRuleTarget,
    /// Context key identifying the request origin.
    pub context: HttpContextKey,
}

/// A cached verdict: whether it was allowed, from which source, and when.
#[derive(Debug, Clone)]
pub struct VerdictEntry {
    /// Whether the verdict allowed the request.
    pub allowed: bool,
    /// Source the verdict derived from.
    pub source: VerdictSource,
    /// When the verdict was recorded.
    pub time: Instant,
}

/// Evict oldest map entries (by the caller-supplied timestamp) until the map
/// fits within `max_entries`.
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

/// Enforce the verdict-cache entry cap, evicting oldest verdict entries.
pub fn enforce_verdict_cache_limit<K: Clone + Eq + std::hash::Hash>(
    map: &mut HashMap<K, VerdictEntry>,
) {
    evict_oldest(map, MAX_VERDICT_CACHE_ENTRIES, |entry| entry.time);
}

/// Monotonic source of client ids across the store.
pub static CLIENT_ID: AtomicU64 = AtomicU64::new(1);

/// Process startup and policy arguments for the policy daemon.
#[derive(Debug, Clone)]
pub struct PolicydArgs {
    /// Path of the host policy RPC socket.
    pub host_socket: PathBuf,
    /// Path of the sandbox policy RPC socket.
    pub sandbox_socket: PathBuf,
    /// Optional proxy RPC socket path.
    pub proxy_socket: Option<PathBuf>,
    /// Optional gid authorized to use the proxy socket.
    pub proxy_gid: Option<u32>,
    /// Path of the declarative base policy file.
    pub declarative: PathBuf,
    /// Path to write exported JSON policy state.
    pub export_json: PathBuf,
    /// Optional path to write exported Nix policy state.
    pub export_nix: Option<PathBuf>,
    /// Timeout applied to untrusted approval requests.
    pub approval_timeout: Duration,
    /// Whether approvals may prompt interactively.
    pub interactive_approval: bool,
    /// Optional command used to spawn the approval UI.
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

/// A pending elevation approval request.
#[derive(Debug, Clone)]
pub struct PendingElevation {
    /// Stable id identifying this pending request.
    pub id: String,
    /// Creation timestamp (epoch seconds, fractional).
    pub created_at: f64,
    /// Commandline arguments to elevate.
    pub argv: Vec<String>,
    /// Optional current working directory.
    pub cwd: Option<PathBuf>,
    /// Optional home directory.
    pub home: Option<PathBuf>,
    /// Optional project root directory.
    pub project_root: Option<PathBuf>,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<String>,
    /// Optional package attribution.
    pub package: Option<String>,
}

/// A pending network approval request.
#[derive(Debug, Clone)]
pub struct PendingNetwork {
    /// Stable id identifying this pending request.
    pub id: String,
    /// Creation timestamp (epoch seconds, fractional).
    pub created_at: f64,
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// URL scheme.
    pub scheme: String,
    /// Full request URL.
    pub url: String,
    /// Host aliases supplied for attribution.
    pub aliases: Vec<String>,
    /// Optional current working directory.
    pub cwd: Option<PathBuf>,
    /// Optional home directory.
    pub home: Option<PathBuf>,
    /// Optional project root directory.
    pub project_root: Option<PathBuf>,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<String>,
    /// Optional package attribution.
    pub package: Option<String>,
}

/// A pending HTTP approval request.
#[derive(Debug, Clone)]
pub struct PendingHttp {
    /// Wire/display identifier. The typed ID is retained in `pending_id`.
    pub id: String,

    /// Typed id retained for matching against the wire.
    pub pending_id: PendingHttpId,
    /// Creation timestamp (epoch seconds, fractional).
    pub created_at: f64,
    /// HTTP request awaiting approval.
    pub request: HttpRequest,
    /// Context key identifying the request origin.
    pub context: HttpContextKey,
    /// Optional package attribution.
    pub package: Option<String>,
}

/// A pending filesystem approval request.
#[derive(Debug, Clone)]
pub struct PendingFilesystem {
    /// Stable id identifying this pending request.
    pub id: String,
    /// Creation timestamp (epoch seconds, fractional).
    pub created_at: f64,
    /// Filesystem path being accessed.
    pub path: PathBuf,
    /// Access mode requested.
    pub access: FileAccess,
    /// Optional current working directory.
    pub cwd: Option<PathBuf>,
    /// Optional home directory.
    pub home: Option<PathBuf>,
    /// Optional project root directory.
    pub project_root: Option<PathBuf>,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<String>,
    /// Optional package attribution.
    pub package: Option<String>,
}

/// A pending resource approval request.
#[derive(Debug, Clone)]
pub struct PendingResource {
    /// Stable id identifying this pending request.
    pub id: String,
    /// Creation timestamp (epoch seconds, fractional).
    pub created_at: f64,
    /// Resource kind being requested.
    pub kind: ResourceKind,
    /// Resource path being accessed.
    pub path: PathBuf,
    /// Access mode requested.
    pub access: ResourceAccess,
    /// Optional current working directory.
    pub cwd: Option<PathBuf>,
    /// Optional home directory.
    pub home: Option<PathBuf>,
    /// Optional project root directory.
    pub project_root: Option<PathBuf>,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<String>,
    /// Optional package attribution.
    pub package: Option<String>,
}

/// A pending D-Bus approval request.
#[derive(Debug, Clone)]
pub struct PendingDbus {
    /// Stable id identifying this pending request.
    pub id: String,
    /// Creation timestamp (epoch seconds, fractional).
    pub created_at: f64,
    /// D-Bus target being addressed.
    pub target: DbusTarget,
    /// Optional current working directory.
    pub cwd: Option<PathBuf>,
    /// Optional home directory.
    pub home: Option<PathBuf>,
    /// Optional project root directory.
    pub project_root: Option<PathBuf>,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<String>,
    /// Optional package attribution.
    pub package: Option<String>,
}

/// Kind of a pending approval request, mirroring the [`Pending`] variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// Elevation approval request.
    Elevation,
    /// Network approval request.
    Network,
    /// HTTP approval request.
    Http,
    /// Filesystem approval request.
    Filesystem,
    /// Resource approval request.
    Resource,
    /// D-Bus approval request.
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

/// Pending approval awaiting a policy decision.
#[derive(Clone)]
pub enum Pending {
    /// Privileged command request.
    Elevation(PendingElevation),
    /// Network connection request.
    Network(PendingNetwork),
    /// HTTP request.
    Http(PendingHttp),
    /// Filesystem access request.
    Filesystem(PendingFilesystem),
    /// Named resource request.
    Resource(PendingResource),
    /// Session-bus request.
    Dbus(PendingDbus),
}

impl Pending {
    /// Return the kind of this pending request.
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

    /// Return the stable id identifying this pending request.
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

    /// Return the creation timestamp (epoch seconds, fractional).
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

    /// Return the optional current working directory.
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

    /// Return the optional home directory.
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

    /// Return the optional project root directory.
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

    /// Return the optional sandbox session id.
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

/// The single `Pending` → `PendingSummary` conversion: the status RPC and the
/// tests both render through this impl so the six-arm mapping lives once.
impl From<&Pending> for PendingSummary {
    fn from(pending: &Pending) -> Self {
        match pending {
            Pending::Network(net) => Self::Network {
                id: net.id.clone(),
                host: Some(net.host.clone()),
                port: Some(net.port),
                scheme: Some(net.scheme.clone()),
                url: Some(net.url.clone()),
                cwd: net.cwd.clone(),
                home: net.home.clone(),
                package: net.package.clone(),
            },
            Pending::Http(http) => Self::Http {
                id: http.pending_id,
                request: http.request.clone(),
                cwd: http.context.cwd.clone(),
                home: http.context.home.clone(),
                project_root: http.context.project_root.clone(),
                sandbox_session_id: http.context.sandbox_session_id.clone(),
                package: http.package.clone(),
            },
            Pending::Elevation(elev) => Self::Elevation {
                id: elev.id.clone(),
                argv: Some(elev.argv.clone()),
                cwd: elev.cwd.clone(),
                home: elev.home.clone(),
                package: elev.package.clone(),
            },
            Pending::Filesystem(fs) => Self::Filesystem {
                id: fs.id.clone(),
                path: Some(fs.path.clone()),
                access: Some(fs.access),
                cwd: fs.cwd.clone(),
                home: fs.home.clone(),
                package: fs.package.clone(),
            },
            Pending::Resource(res) => Self::Resource {
                id: res.id.clone(),
                resource_kind: res.kind,
                path: Some(res.path.clone()),
                access: Some(res.access),
                cwd: res.cwd.clone(),
                home: res.home.clone(),
                package: res.package.clone(),
            },
            Pending::Dbus(dbus) => Self::Dbus {
                id: dbus.id.clone(),
                target: dbus.target.clone(),
                cwd: dbus.cwd.clone(),
                home: dbus.home.clone(),
                project_root: dbus.project_root.clone(),
                sandbox_session_id: dbus.sandbox_session_id.clone(),
                package: dbus.package.clone(),
            },
        }
    }
}

/// Display context describing a connected UI approval session.
#[derive(Debug, Clone, Default)]
pub struct UiSessionContext {
    /// Optional current working directory.
    pub cwd: Option<PathBuf>,
    /// Optional home directory.
    pub home: Option<PathBuf>,
    /// Optional project root directory.
    pub project_root: Option<PathBuf>,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<String>,
    /// Optional uid owning the UI session.
    pub owner_uid: Option<u32>,
    /// Client id of the connected UI.
    pub client_id: u64,
}

/// Handle to a connected UI approval client.
#[derive(Clone)]
pub struct UiClientHandle {
    /// Client id of the UI.
    pub id: u64,
    pub(crate) writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
}

/// A live UI approval client connection.
pub struct UiClient {
    /// Session id the UI is bound to.
    pub session_id: String,
    /// Writer half to push messages to the client.
    pub writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
}

/// The policy daemon's central state and decision engine.
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
    pub(crate) project_context: std::sync::Mutex<crate::project_context::ProjectContextRegistry>,
    pub(crate) cgroup_freeze: super::freeze::CgroupFreezeManager,
}

/// LRU-ish cache of merged policies keyed by context paths and source mtimes.
#[derive(Debug, Default)]
pub struct MergedPolicyCache {
    /// Current merged-policy cache entries, keyed by context and source mtime.
    pub entries: HashMap<MergedCacheKey, agent_sandbox_core::Policy>,
    order: std::collections::VecDeque<MergedCacheKey>,
}

/// Cache key identifying a merged policy: context paths, package, and the
/// modification times of the contributing policy sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergedCacheKey {
    /// Optional home directory.
    pub home: Option<PathBuf>,
    /// Optional project root directory.
    pub project_root: Option<PathBuf>,
    /// Mtime of the declarative policy source.
    pub declarative_mtime: Option<MtimeKey>,
    /// Mtime of the home policy source.
    pub home_policy_mtime: Option<MtimeKey>,
    /// Mtime of the project policy source.
    pub project_policy_mtime: Option<MtimeKey>,
    /// Optional package attribution.
    pub package: Option<String>,
    /// Mtime of the package declarative base source.
    pub package_base_mtime: Option<MtimeKey>,
    /// Mtime of the package-home policy source.
    pub package_home_mtime: Option<MtimeKey>,
    /// Mtime of the package-project policy source.
    pub package_project_mtime: Option<MtimeKey>,
}

/// A filesystem modification time key (seconds + nanoseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MtimeKey {
    /// Whole seconds of the mtime.
    pub secs: u64,
    /// Nanosecond fraction of the mtime.
    pub nanos: u32,
}

impl MergedPolicyCache {
    /// Maximum number of merged-policy cache entries retained.
    pub const MAX_ENTRIES: usize = 32;

    /// Look up a merged policy by cache key, if present.
    pub fn get(&self, key: &MergedCacheKey) -> Option<agent_sandbox_core::Policy> {
        self.entries.get(key).cloned()
    }

    /// Insert or replace a merged policy, evicting oldest entries as needed.
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

/// State for an established proxy session.
#[derive(Debug)]
pub struct ProxySessionState {
    /// Session token authorizing proxy use.
    pub token: ProxySessionToken,
    /// Identifier of the connection mapped to this session.
    pub connection_id: u64,
    /// When the session was opened.
    pub opened_at: Instant,
}

/// State tracking a registered proxy flow.
#[derive(Debug)]
pub struct ProxyFlowState {
    /// Flow registration credentials.
    pub registration: FlowRegistration,
    /// Socket identity of the flow owner.
    pub owner: SocketIdentity,
    /// Resolved request context for attribution.
    pub context: ResolvedRequestContext,
    /// Optional attribution token.
    pub attribution_token: Option<AttributionToken>,
    /// Optional mapped connection id.
    pub connection_id: Option<ProxyConnectionId>,
    /// When the flow was claimed.
    pub claimed_at: Option<Instant>,
    /// Time of the last check against the flow.
    pub last_check: Instant,
}

/// Outstanding proxy cancellation signal.
pub enum ProxyCancellation {
    /// Cancellation is still pending; sender fires on completion.
    Active(oneshot::Sender<()>),
    /// The proxy was canceled.
    Canceled,
}

// The decision state lives in `state`, where the deny-wins session
// buckets and the pending board concentrate their invariants.
pub use super::state::{HttpWaiter, NetworkWaiter, PolicyDecisionState, ProxyCheckId};

/// Fingerprint entry for one concrete deny rule path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyFingerprint {
    /// Canonical denied path.
    pub path: PathBuf,
    /// Access level the deny rule covers.
    pub access: FileAccess,
    /// Optional mtime of the denied path.
    pub mtime: Option<std::time::SystemTime>,
}

/// Inode→entries cache for hardlink defense against deny rule bypass.
///
/// When a request path's `InodeIdentity` is found in this cache, the
/// request is for a file that lives under (or is) a denied path.
/// The canonical paths and access levels are stored for matching.
#[derive(Debug, Clone, Default)]
pub struct DenyInodeCache {
    /// Inode→denied-entry map for hardlink defense.
    pub inodes: HashMap<agent_sandbox_core::InodeIdentity, Vec<DenyCacheEntry>>,
    /// Fingerprints of the deny rules backing the cache.
    pub fingerprint: Vec<DenyFingerprint>,
}

/// A single entry in the deny inode cache: the canonical path of the
/// denied file and the access level the deny rule covers.
#[derive(Debug, Clone)]
pub struct DenyCacheEntry {
    /// Canonical path of the denied file.
    pub path: PathBuf,
    /// Access level the deny rule covers.
    pub access: FileAccess,
}
