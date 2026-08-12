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
use crate::error::PolicydError;
use agent_sandbox_core::ScopeTarget;
pub(crate) use decisions::DecisionAction;
pub use freeze::cleanup_cgroup_freeze;
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Instant,
};
pub(crate) use types::evict_oldest;
pub use types::{
    DenyFingerprint, DenyInodeCache, HttpPendingKey, HttpScopeKey, MAX_CONNECTIONS_PER_UID,
    MAX_PROXY_FLOWS, MAX_RPC_LINE_BYTES, Pending, PendingElevation, PendingFilesystem, PendingHttp,
    PendingKind, PendingNetwork, PendingResource, PolicyStore, PolicydArgs, ProxyFlowState,
    ProxySessionState, TrustedPeer, UiClientHandle, UiSessionContext,
};
use types::{MergedPolicyCache, PolicyDecisionState};

fn apply_session_rule<T>(
    action: decisions::DecisionAction,
    session_id: &str,
    key: &T,
    allow: &mut HashMap<String, HashSet<T>>,
    deny: &mut HashMap<String, HashSet<T>>,
) where
    T: Clone + Eq + std::hash::Hash,
{
    match action {
        decisions::DecisionAction::Approve => {
            allow
                .entry(session_id.to_owned())
                .or_default()
                .insert(key.clone());
            if let Some(deny_bucket) = deny.get_mut(session_id) {
                deny_bucket.remove(key);
            }
        }

        decisions::DecisionAction::Deny => {
            deny.entry(session_id.to_owned())
                .or_default()
                .insert(key.clone());
            if let Some(allow_bucket) = allow.get_mut(session_id) {
                allow_bucket.remove(key);
            }
        }
    }
}

/// Whether a persistent scope write invalidates the merged-policy cache.
///
/// `global` covers the `Global` and `Project` arms; `package` covers the
/// `GlobalPackage` and `ProjectPackage` arms. Values preserve the per
/// capability behaviour of the former copy-pasted `match` blocks.
#[derive(Clone, Copy)]
pub(crate) struct ScopePersistFlags {
    /// `invalidate` for `Global` and `Project`.
    pub global: bool,
    /// `invalidate` for `GlobalPackage` and `ProjectPackage`.
    pub package: bool,
}

impl ScopePersistFlags {
    const fn new(global: bool, package: bool) -> Self {
        Self { global, package }
    }
}

/// Run the four persistent `ScopeTarget` arms against a per-capability
/// `persist` closure, returning the written policy path.
///
/// `project_log` and `project_package_log` are the tracing messages emitted
/// after a project-file write for the two project arms; pass `None` to
/// suppress the log (as D-Bus does).
pub(crate) fn apply_persistent_scope<F>(
    scope_target: ScopeTarget,
    home: Option<&Path>,
    flags: ScopePersistFlags,
    project_log: Option<&str>,
    project_package_log: Option<&str>,
    persist: F,
) -> Result<Option<PathBuf>, PolicydError>
where
    F: FnOnce(&Path, Option<&Path>, bool) -> std::io::Result<()>,
{
    match scope_target {
        ScopeTarget::Ephemeral | ScopeTarget::Session { .. } => Ok(None),

        ScopeTarget::Global { policy_path, home } => {
            persist(&policy_path, Some(home.as_path()), flags.global)
                .map_err(PolicydError::from)?;
            Ok(Some(policy_path))
        }

        ScopeTarget::GlobalPackage {
            policy_path, home, ..
        } => {
            persist(&policy_path, Some(home.as_path()), flags.package)
                .map_err(PolicydError::from)?;
            Ok(Some(policy_path))
        }

        ScopeTarget::Project { policy_path, .. } => {
            persist(&policy_path, home, flags.global).map_err(PolicydError::from)?;

            if let Some(log) = project_log {
                tracing::info!(path = ?policy_path, "{log}");
            }

            Ok(Some(policy_path))
        }

        ScopeTarget::ProjectPackage { policy_path, .. } => {
            persist(&policy_path, home, flags.package).map_err(PolicydError::from)?;

            if let Some(log) = project_package_log {
                tracing::info!(path = ?policy_path, "{log}");
            }

            Ok(Some(policy_path))
        }
    }
}

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
                dbus_futures: HashMap::new(),
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
                dbus_verdict_cache: HashMap::new(),
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
