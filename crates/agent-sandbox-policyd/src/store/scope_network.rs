//! Policy store — scope_network.

use agent_sandbox_core::{
    ApprovalScope, RpcReply, SandboxPaths, ScopeActionReply, ScopeContext, ScopeTarget, allow_keys,
};

use crate::error::PolicydError;
use crate::wire::{NetworkScopeOp, ScopeWire};

use super::types::PolicyStore;

impl PolicyStore {
    pub(crate) async fn approve_network_scope(&self, op: NetworkScopeOp) -> RpcReply {
        let NetworkScopeOp {
            host,
            port,
            scope,
            wire,
        } = op;
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
        } = wire;
        let cwd = paths.cwd_string();
        let home = paths.home_string();
        let project_root = paths.project_root_string();
        let keys = allow_keys(&host, port);
        let active = self.active_session_ids().await;
        let ctx = ScopeContext {
            scope,
            session_id: session_id.as_deref(),
            home: home.as_deref(),
            project_root: project_root.as_deref(),
            active_session_ids: &active,
        };
        let target = match ScopeTarget::resolve(&ctx) {
            Ok(t) => t,
            Err(e) => return e.into(),
        };
        let scope_label = scope.as_str();
        match target {
            ScopeTarget::Ephemeral => {
                let mut inner = self.inner.lock().await;
                for key in keys {
                    inner.once_allow.insert(key);
                }
            }
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                let bucket = inner.session_allow.entry(session_id).or_default();
                for key in keys {
                    bucket.insert(key);
                }
                drop(inner);
            }
            ScopeTarget::Global {
                ref policy_path,
                ref home,
            } => {
                if let Err(err) = Self::persist_network_allow(
                    policy_path,
                    &host,
                    port,
                    scope_label,
                    Some(home),
                    owner_uid,
                ) {
                    return PolicydError::from(err).into();
                }
            }
            ScopeTarget::Project {
                ref policy_path, ..
            } => {
                if let Err(err) = Self::persist_network_allow(
                    policy_path,
                    &host,
                    port,
                    scope_label,
                    home.as_deref(),
                    owner_uid,
                ) {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project policy saved");
            }
        }
        let _ = self
            .export_policy_files(SandboxPaths::from_wire(
                cwd,
                home.clone(),
                project_root.clone(),
            ))
            .await;
        Self::audit("approve", Some(&host), Some(port), scope_label);
        let path = project_root
            .as_deref()
            .filter(|_| scope == ApprovalScope::Project)
            .and_then(Self::project_policy_path_display);
        RpcReply::ScopeAction(ScopeActionReply::ok_network(host, port, scope_label, path))
    }

    pub(crate) async fn deny_network_scope(&self, op: NetworkScopeOp) -> RpcReply {
        let NetworkScopeOp {
            host,
            port,
            scope,
            wire,
        } = op;
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
        } = wire;
        let cwd = paths.cwd_string();
        let home = paths.home_string();
        let project_root = paths.project_root_string();
        let keys = allow_keys(&host, port);
        let active = self.active_session_ids().await;
        if scope != ApprovalScope::Once {
            let ctx = ScopeContext {
                scope,
                session_id: session_id.as_deref(),
                home: home.as_deref(),
                project_root: project_root.as_deref(),
                active_session_ids: &active,
            };
            let target = match ScopeTarget::resolve(&ctx) {
                Ok(t) => t,
                Err(e) => return e.into(),
            };
            let scope_label = scope.as_str();
            match target {
                ScopeTarget::Ephemeral => {}
                ScopeTarget::Session { session_id } => {
                    let mut inner = self.inner.lock().await;
                    let bucket = inner.session_deny.entry(session_id.clone()).or_default();
                    for key in &keys {
                        bucket.insert(key.clone());
                    }
                    if let Some(allow_bucket) = inner.session_allow.get_mut(&session_id) {
                        for key in keys {
                            allow_bucket.remove(&key);
                        }
                    }
                }
                ScopeTarget::Global {
                    ref policy_path,
                    ref home,
                } => {
                    if let Err(err) = Self::persist_network_deny(
                        policy_path,
                        &host,
                        port,
                        scope_label,
                        Some(home),
                        owner_uid,
                    ) {
                        return PolicydError::from(err).into();
                    }
                }
                ScopeTarget::Project {
                    ref policy_path, ..
                } => {
                    if let Err(err) = Self::persist_network_deny(
                        policy_path,
                        &host,
                        port,
                        scope_label,
                        home.as_deref(),
                        owner_uid,
                    ) {
                        return PolicydError::from(err).into();
                    }
                    tracing::info!(path = ?policy_path, "project policy saved");
                }
            }
        }
        let scope_label = scope.as_str();
        let _ = self
            .export_policy_files(SandboxPaths::from_wire(
                cwd,
                home.clone(),
                project_root.clone(),
            ))
            .await;
        Self::audit("deny", Some(&host), Some(port), scope_label);
        let path = project_root
            .as_deref()
            .filter(|_| scope == ApprovalScope::Project)
            .and_then(Self::project_policy_path_display);
        RpcReply::ScopeAction(ScopeActionReply::ok_network(host, port, scope_label, path))
    }
}
