//! Policy store types and shared state.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use agent_sandbox_core::{
    CheckReply, ElevateReply, FileAccess, FilesystemCheckReply, FilesystemRuleKey, NetworkRuleKey,
};
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex, oneshot};

/// Hard cap on the number of pending approval requests held in memory.
/// Beyond this cap new prompts are blocked instead of being added.
pub(crate) const MAX_PENDING_APPROVALS: usize = 512;

/// Hard cap on the number of waiters that may join a single pending request.
/// Beyond this cap extra waiters are blocked instead of being queued.
pub(crate) const MAX_WAITERS_PER_PENDING: usize = 64;

/// Hard cap on the size of the verdict caches. Older entries are evicted
/// (by `time` for the verdict cache, by `Instant` for the spawn throttle
/// map) when the cap is exceeded.
pub(crate) const MAX_VERDICT_CACHE_ENTRIES: usize = 1024;

/// Cap on the number of static filesystem allow rules accepted by fsmon.
pub(crate) const MAX_STATIC_ALLOW_RULES: usize = 4096;

/// Key for the network verdict cache: hostname and port.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct NetworkVerdictKey {
    pub host: String,
    pub port: u16,
}

/// Key for the filesystem verdict cache: path and access type.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct FilesystemVerdictKey {
    pub path: String,
    pub access: FileAccess,
}

/// A cached verdict: whether it was allowed, from which source, and when.
#[derive(Debug, Clone)]
pub(crate) struct VerdictEntry {
    pub allowed: bool,
    pub source: String,
    pub time: Instant,
}

/// Evict the oldest entries (by `VerdictEntry.time`) from a verdict cache
/// until the map is within the global cap.
pub(crate) fn enforce_verdict_cache_limit<K: Clone + Eq + std::hash::Hash>(
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

pub(crate) static CLIENT_ID: AtomicU64 = AtomicU64::new(1);

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
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
    pub request_pid: Option<u32>,
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
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
    pub request_pid: Option<u32>,
    pub sandbox_session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingFilesystem {
    pub id: String,
    pub created_at: f64,
    pub path: String,
    pub access: FileAccess,
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
    pub request_pid: Option<u32>,
    pub sandbox_session_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    Elevation,
    Network,
    Filesystem,
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
}

impl Pending {
    pub fn kind(&self) -> PendingKind {
        match self {
            Self::Elevation(_) => PendingKind::Elevation,
            Self::Network(_) => PendingKind::Network,
            Self::Filesystem(_) => PendingKind::Filesystem,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Elevation(p) => &p.id,
            Self::Network(p) => &p.id,
            Self::Filesystem(p) => &p.id,
        }
    }

    pub fn created_at(&self) -> f64 {
        match self {
            Self::Elevation(p) => p.created_at,
            Self::Network(p) => p.created_at,
            Self::Filesystem(p) => p.created_at,
        }
    }

    pub fn cwd(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.cwd.as_deref(),
            Self::Network(p) => p.cwd.as_deref(),
            Self::Filesystem(p) => p.cwd.as_deref(),
        }
    }

    pub fn home(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.home.as_deref(),
            Self::Network(p) => p.home.as_deref(),
            Self::Filesystem(p) => p.home.as_deref(),
        }
    }

    pub fn project_root(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.project_root.as_deref(),
            Self::Network(p) => p.project_root.as_deref(),
            Self::Filesystem(p) => p.project_root.as_deref(),
        }
    }

    pub fn request_pid(&self) -> Option<u32> {
        match self {
            Self::Elevation(p) => p.request_pid,
            Self::Network(p) => p.request_pid,
            Self::Filesystem(p) => p.request_pid,
        }
    }

    pub fn sandbox_session_id(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.sandbox_session_id.as_deref(),
            Self::Network(p) => p.sandbox_session_id.as_deref(),
            Self::Filesystem(p) => p.sandbox_session_id.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UiSessionOwner {
    pub uid: u32,
    pub pid: u32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UiSessionContext {
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
    pub sandbox_session_id: Option<String>,
}

pub struct UiClientHandle {
    pub id: u64,
    pub(crate) writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
}

pub(crate) struct UiClient {
    pub session_id: String,
    pub ui_client: String,
    pub writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
    #[allow(dead_code)]
    pub owner_uid: u32,
    pub owner_pid: u32,
}

pub struct PolicyStore {
    pub(crate) args: PolicydArgs,
    pub(crate) inner: Mutex<StoreInner>,
}

pub(crate) struct StoreInner {
    pub session_allow: HashMap<String, HashSet<NetworkRuleKey>>,
    pub once_allow: HashSet<NetworkRuleKey>,
    pub pending: HashMap<String, Pending>,
    pub elevation_futures: HashMap<String, oneshot::Sender<ElevateReply>>,
    pub network_futures: HashMap<String, Vec<oneshot::Sender<CheckReply>>>,
    pub filesystem_futures: HashMap<String, Vec<oneshot::Sender<FilesystemCheckReply>>>,
    pub ui_clients: HashMap<u64, UiClient>,
    pub ui_context_by_session: HashMap<String, UiSessionContext>,
    pub network_verdict_cache: HashMap<NetworkVerdictKey, VerdictEntry>,
    pub filesystem_verdict_cache: HashMap<FilesystemVerdictKey, VerdictEntry>,
    pub ui_spawn_last: HashMap<String, Instant>,
    pub session_deny: HashMap<String, HashSet<NetworkRuleKey>>,
    pub session_sudo_allow: HashMap<String, HashSet<Vec<String>>>,
    pub session_sudo_deny: HashMap<String, HashSet<Vec<String>>>,
    pub session_filesystem_allow: HashMap<String, HashSet<FilesystemRuleKey>>,
    pub session_filesystem_deny: HashMap<String, HashSet<FilesystemRuleKey>>,
    pub network_pending_delivered_to_standalone: HashSet<String>,
}
