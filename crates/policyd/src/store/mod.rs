//! Policy merge, pending approvals, and UI session state.

mod access;
mod context;
mod dbus;
mod decisions;
mod elevation;
pub(crate) mod evaluator;
mod filesystem;
mod freeze;
mod http;
mod network;
pub(crate) mod persist;
mod proxy;
mod resource;
mod scope_filesystem;
mod scope_http;
mod scope_network;
mod scope_sudo;
mod status;
mod types;
mod ui;
mod ui_route;
mod util;
pub use freeze::cleanup_default_registry as cleanup_cgroup_freeze;
pub use types::{
    DenyFingerprint, DenyInodeCache, HttpPendingKey, HttpScopeKey, HttpVerdictKey,
    MAX_CONNECTIONS_PER_UID, MAX_PROXY_FLOWS, MAX_RPC_LINE_BYTES, Pending, PendingElevation,
    PendingFilesystem, PendingHttp, PendingKind, PendingNetwork, PendingResource, PolicyStore,
    PolicydArgs, ProxyFlowState, ProxySessionState, ResourceVerdictKey, TrustedPeer,
    UiClientHandle, UiSessionContext,
};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use types::{MergedPolicyCache, PolicyDecisionState};

impl PolicyStore {
    #[must_use]
    pub fn new(args: PolicydArgs) -> Self {
        Self {
            args,
            sandbox_sessions: Arc::new(RwLock::new(HashMap::new())),
            inner: tokio::sync::Mutex::new(PolicyDecisionState {
                session_allow: HashMap::new(),
                once_allow: HashSet::new(),
                pending: HashMap::new(),
                elevation_futures: HashMap::new(),
                network_futures: HashMap::new(),
                filesystem_futures: HashMap::new(),
                http_futures: HashMap::new(),
                http_waiters: HashMap::new(),
                proxy_cancellations: HashMap::new(),
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
                session_dbus_allow: HashMap::new(),
                session_dbus_deny: HashMap::new(),
                http_once_allow: HashSet::new(),
                http_once_deny: HashSet::new(),
                http_session_allow: HashMap::new(),
                http_session_deny: HashMap::new(),
                sandbox_filesystem_static_allow: HashMap::new(),
                http_verdict_cache: HashMap::new(),
                network_verdict_cache: HashMap::new(),
                filesystem_verdict_cache: HashMap::new(),
                resource_verdict_cache: HashMap::new(),
                deny_inode_cache: DenyInodeCache::default(),
                connections_by_uid: HashMap::new(),
                proxy_flows: HashMap::new(),
                proxy_session: None,
            }),
            deny_inode_rebuild: tokio::sync::Mutex::new(()),
            ui_spawn_lock: tokio::sync::Mutex::new(()),
            merged_cache: std::sync::Mutex::new(MergedPolicyCache::default()),
            cgroup_freeze: freeze::CgroupFreezeManager::new_without_recovery(),
        }
    }

    pub fn enable_cgroup_freezer(&mut self) {
        self.cgroup_freeze = freeze::CgroupFreezeManager::new();
    }
    pub const fn args(&self) -> &PolicydArgs {
        &self.args
    }
}
