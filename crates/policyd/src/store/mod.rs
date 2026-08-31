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
mod scope_apply;
mod scope_filesystem;
mod scope_http;
mod scope_network;
mod scope_sudo;
mod state;
mod status;

mod types;
mod ui;
mod ui_route;
mod util;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
#[cfg(test)]
use std::{path::PathBuf, time::Duration};

pub(crate) use decisions::DecisionAction;
pub use freeze::cleanup_cgroup_freeze;
use types::MergedPolicyCache;
pub(crate) use types::evict_oldest;
pub use types::{
    DenyFingerprint, DenyInodeCache, HttpPendingKey, HttpScopeKey, MAX_CONNECTIONS_PER_UID,
    MAX_PROXY_FLOWS, MAX_RPC_LINE_BYTES, Pending, PendingElevation, PendingFilesystem, PendingHttp,
    PendingKind, PendingNetwork, PendingResource, PolicyStore, PolicydArgs, ProxyCheckId,
    ProxyFlowState, ProxySessionState, TrustedPeer, UiClientHandle, UiSessionContext,
};

#[cfg(test)]
pub(crate) const fn test_args(
    host_socket: PathBuf,
    sandbox_socket: PathBuf,
    declarative: PathBuf,
    export_json: PathBuf,
    approval_timeout: Duration,
    interactive_approval: bool,
) -> PolicydArgs {
    PolicydArgs {
        host_socket,
        sandbox_socket,
        proxy_socket: None,
        proxy_gid: None,
        declarative,
        export_json,
        export_nix: None,
        approval_timeout,
        interactive_approval,
        ui_spawn_cmd: None,
        package_declarative: Vec::new(),
        fs_monitor_cmd: None,
        syscall_broker_cmd: None,
    }
}

impl PolicyStore {
    /// Create a new [`PolicyStore`] from the given daemon arguments.
    #[must_use]
    pub fn new(args: PolicydArgs) -> Self {
        Self {
            args,
            sandbox_sessions: Arc::new(RwLock::new(HashMap::new())),
            inner: tokio::sync::Mutex::new(types::PolicyDecisionState::default()),
            deny_inode_rebuild: tokio::sync::Mutex::new(()),
            ui_spawn_lock: tokio::sync::Mutex::new(()),
            merged_cache: std::sync::Mutex::new(MergedPolicyCache::default()),
            project_context: std::sync::Mutex::new(
                crate::project_context::ProjectContextRegistry::default(),
            ),
            cgroup_freeze: freeze::CgroupFreezeManager::new_without_recovery(),
        }
    }

    /// Enable the cgroup freezer (used across cgroup freeze requests).
    pub fn enable_cgroup_freezer(&mut self) {
        self.cgroup_freeze = freeze::CgroupFreezeManager::new();
    }

    /// Return the daemon arguments the store was created with.
    pub const fn args(&self) -> &PolicydArgs {
        &self.args
    }
}
