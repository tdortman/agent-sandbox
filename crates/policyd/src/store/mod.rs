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
mod network_snapshot;
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

#[cfg(test)]
pub(crate) fn test_store() -> PolicyStore {
    PolicyStore::new(test_args(
        "/tmp/test.sock".into(),
        "/tmp/test-sandbox.sock".into(),
        "/tmp/declarative.json".into(),
        "/tmp/export.json".into(),
        Duration::from_secs(30),
        true,
    ))
}

impl PolicyStore {
    /// Create a new [`PolicyStore`] from the given daemon arguments.
    #[must_use]
    pub fn new(args: PolicydArgs) -> Self {
        Self {
            args,
            sandbox_sessions: Arc::new(RwLock::new(HashMap::new())),
            inner: tokio::sync::Mutex::new(types::PolicyDecisionState::default()),
            network_observation: std::sync::Mutex::new(None),
            network_revocation: std::sync::Mutex::new(None),
            deny_inode_rebuild: tokio::sync::Mutex::new(()),
            ui_spawn_lock: tokio::sync::Mutex::new(()),
            cgroup_freeze: freeze::CgroupFreezeManager::new_without_recovery(),
        }
    }

    /// Enable the cgroup freezer (used across cgroup freeze requests).
    pub fn enable_cgroup_freezer(&mut self) {
        self.cgroup_freeze = freeze::CgroupFreezeManager::new();
    }

    /// Bind experimental file-only network grants to runtime decisions.
    ///
    /// # Errors
    /// Returns an error if the map cannot be opened or existing decisions
    /// cannot revoke it.
    pub async fn enable_network_revocation(&self, path: &std::path::Path) -> std::io::Result<()> {
        let revocation =
            agent_sandbox_core::network_revocation::NetworkPolicyRevocation::open(path)?;
        let inner = self.inner.lock().await;
        let session = &inner.session;
        let mut observation = self
            .network_observation
            .lock()
            .map_err(|_| std::io::Error::other("network observation lock poisoned"))?;
        let mut current = self
            .network_revocation
            .lock()
            .map_err(|_| std::io::Error::other("network revocation lock poisoned"))?;
        if !session.once_allow.is_empty()
            || session
                .session_allow
                .values()
                .any(|rules| !rules.is_empty())
            || session.session_deny.values().any(|rules| !rules.is_empty())
        {
            revocation.revoke()?;
        }
        if let Some(previous) = &*current {
            previous.revoke()?;
        }
        *current = Some(revocation);
        *observation = None;
        drop(current);
        drop(observation);
        drop(inner);
        Ok(())
    }

    pub(crate) fn revoke_network_grants(&self) -> std::io::Result<()> {
        let current = self
            .network_revocation
            .lock()
            .map_err(|_| std::io::Error::other("network revocation lock poisoned"))?;
        if let Some(revocation) = &*current {
            revocation.revoke()?;
        }
        drop(current);
        Ok(())
    }

    /// Return the daemon arguments the store was created with.
    pub const fn args(&self) -> &PolicydArgs {
        &self.args
    }
}
