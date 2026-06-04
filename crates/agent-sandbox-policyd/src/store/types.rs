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
    pub declarative: PathBuf,
    pub export_json: PathBuf,
    pub export_nix: Option<PathBuf>,
    pub approval_timeout: Duration,
    pub interactive_approval: bool,
    pub ui_spawn_cmd: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub id: String,
    pub created_at: f64,
    pub kind: PendingKind,
    pub argv: Option<Vec<String>>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub scheme: Option<String>,
    pub url: Option<String>,
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    Elevation,
    Network,
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
    pub ui_spawn_last_by_uid: HashMap<u32, Instant>,
    pub session_deny: HashMap<String, HashSet<(String, u16)>>,
    pub session_sudo_allow: HashMap<String, HashSet<Vec<String>>>,
    pub session_sudo_deny: HashMap<String, HashSet<Vec<String>>>,
}
