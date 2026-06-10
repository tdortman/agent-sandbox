//! Policy store types and shared state.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use agent_sandbox_core::{CheckReply, ElevateReply};
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex, oneshot};

pub(crate) static CLIENT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct PolicydArgs {
    pub socket: PathBuf,
    pub sandbox_netns: Option<PathBuf>,
    pub declarative: PathBuf,
    pub export_json: PathBuf,
    pub export_nix: Option<PathBuf>,
    pub approval_timeout: Duration,
    pub interactive_approval: bool,
    pub ui_spawn_cmd: Option<PathBuf>,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    Elevation,
    Network,
}

/// Discriminated union of pending approval requests.
///
/// The variant determines which fields are meaningful:
/// - `Elevation`: `argv` is required; `host`/`port`/`scheme`/`url` absent.
/// - `Network`: `host`/`port`/`scheme`/`url` required; `argv` absent.
#[derive(Debug, Clone)]
pub enum Pending {
    Elevation(PendingElevation),
    Network(PendingNetwork),
}

impl Pending {
    pub fn kind(&self) -> PendingKind {
        match self {
            Self::Elevation(_) => PendingKind::Elevation,
            Self::Network(_) => PendingKind::Network,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Elevation(p) => &p.id,
            Self::Network(p) => &p.id,
        }
    }

    pub fn created_at(&self) -> f64 {
        match self {
            Self::Elevation(p) => p.created_at,
            Self::Network(p) => p.created_at,
        }
    }

    pub fn cwd(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.cwd.as_deref(),
            Self::Network(p) => p.cwd.as_deref(),
        }
    }

    pub fn home(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.home.as_deref(),
            Self::Network(p) => p.home.as_deref(),
        }
    }

    pub fn project_root(&self) -> Option<&str> {
        match self {
            Self::Elevation(p) => p.project_root.as_deref(),
            Self::Network(p) => p.project_root.as_deref(),
        }
    }

    pub fn request_pid(&self) -> Option<u32> {
        match self {
            Self::Elevation(p) => p.request_pid,
            Self::Network(p) => p.request_pid,
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
}

pub struct UiClientHandle {
    pub id: u64,
    pub(crate) writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
}

pub(crate) struct UiClient {
    pub session_id: String,
    pub ui_client: String,
    pub writer: std::sync::Arc<Mutex<OwnedWriteHalf>>,
    pub owner_uid: u32,
    pub owner_pid: u32,
}

pub struct PolicyStore {
    pub(crate) args: PolicydArgs,
    pub(crate) inner: Mutex<StoreInner>,
}

pub(crate) struct StoreInner {
    pub session_allow: HashMap<String, HashSet<(String, u16)>>,
    pub once_allow: HashSet<(String, u16)>,
    pub pending: HashMap<String, Pending>,
    pub elevation_futures: HashMap<String, oneshot::Sender<ElevateReply>>,
    pub network_futures: HashMap<String, oneshot::Sender<CheckReply>>,
    pub ui_clients: HashMap<u64, UiClient>,
    pub ui_context_by_session: HashMap<String, UiSessionContext>,
    pub ui_spawn_last: HashMap<String, Instant>,
    pub session_deny: HashMap<String, HashSet<(String, u16)>>,
    pub session_sudo_allow: HashMap<String, HashSet<Vec<String>>>,
    pub session_sudo_deny: HashMap<String, HashSet<Vec<String>>>,
}
