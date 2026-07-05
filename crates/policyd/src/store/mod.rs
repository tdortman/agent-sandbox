//! Policy merge, pending approvals, and UI session state.

mod access;
mod context;
mod decisions;
mod elevation;
mod filesystem;
mod network;
pub(crate) mod persist;
mod resource;
mod scope_filesystem;
mod scope_network;
mod scope_sudo;
mod status;
mod types;
mod ui;
mod ui_route;
mod util;

pub use types::{
    DenyFingerprint, DenyInodeCache, MAX_CONNECTIONS_PER_UID, MAX_RPC_LINE_BYTES, Pending,
    PendingElevation, PendingFilesystem, PendingKind, PendingNetwork, PendingResource, PolicyStore,
    PolicydArgs, ResourceVerdictKey, TrustedPeer, UiClientHandle, UiSessionContext,
};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use types::{MergedPolicyCache, StoreInner};

impl PolicyStore {
    #[must_use]
    pub fn new(args: PolicydArgs) -> Self {
        Self {
            args,
            sandbox_sessions: Arc::new(RwLock::new(HashMap::new())),
            inner: tokio::sync::Mutex::new(StoreInner {
                session_allow: HashMap::new(),
                once_allow: HashSet::new(),
                pending: HashMap::new(),
                elevation_futures: HashMap::new(),
                network_futures: HashMap::new(),
                filesystem_futures: HashMap::new(),
                resource_futures: HashMap::new(),
                ui_clients: HashMap::new(),
                ui_context_by_session: HashMap::new(),
                ui_spawn_last: HashMap::<String, Instant>::new(),
                session_deny: HashMap::new(),
                session_sudo_allow: HashMap::new(),
                session_sudo_deny: HashMap::new(),
                session_filesystem_allow: HashMap::new(),
                session_filesystem_deny: HashMap::new(),
                session_resource_allow: HashMap::new(),
                session_resource_deny: HashMap::new(),
                sandbox_filesystem_static_allow: HashMap::new(),
                network_verdict_cache: HashMap::new(),
                filesystem_verdict_cache: HashMap::new(),
                resource_verdict_cache: HashMap::new(),
                deny_inode_cache: DenyInodeCache::default(),
                connections_by_uid: HashMap::new(),
            }),
            deny_inode_rebuild: tokio::sync::Mutex::new(()),
            merged_cache: std::sync::Mutex::new(MergedPolicyCache::default()),
        }
    }

    pub const fn args(&self) -> &PolicydArgs {
        &self.args
    }
}
