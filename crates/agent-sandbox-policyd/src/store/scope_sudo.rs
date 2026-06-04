//! Policy store — scope_sudo.

use agent_sandbox_core::{
    ApprovalScope, RpcReply, SandboxPaths, ScopeActionReply, ScopeContext, ScopeTarget,
};

use crate::error::PolicydError;
use crate::wire::{ScopeWire, SudoScopeOp};

use super::types::PolicyStore;

impl PolicyStore {
    pub(crate) async fn approve_sudo_scope(&self, op: SudoScopeOp) -> RpcReply {
        let SudoScopeOp { argv, scope, wire } = op;
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
        } = wire;
        let cwd = paths.cwd_string();
        let home = paths.home_string();
        let project_root = paths.project_root_string();
        let key: Vec<String> = argv.clone();
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
            ScopeTarget::Ephemeral => {}
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                inner
                    .session_sudo_allow
                    .entry(session_id.clone())
                    .or_default()
                    .insert(key.clone());
                if let Some(deny_bucket) = inner.session_sudo_deny.get_mut(&session_id) {
                    deny_bucket.remove(&key);
                }
            }
            ScopeTarget::Global {
                ref policy_path,
                ref home,
            } => {
                if let Err(err) =
                    Self::persist_sudo_allow(policy_path, &argv, scope_label, Some(home), owner_uid)
                {
                    return PolicydError::from(err).into();
                }
            }
            ScopeTarget::Project {
                ref policy_path, ..
            } => {
                if let Err(err) = Self::persist_sudo_allow(
                    policy_path,
                    &argv,
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
        let detail = format!("argv={argv:?} scope={scope_label}");
        Self::audit("approve", None, None, &detail);
        let path = project_root
            .as_deref()
            .filter(|_| scope == ApprovalScope::Project)
            .and_then(Self::project_policy_path_display);
        RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope_label, path))
    }

    pub(crate) async fn deny_sudo_scope(&self, op: SudoScopeOp) -> RpcReply {
        let SudoScopeOp { argv, scope, wire } = op;
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
        } = wire;
        let cwd = paths.cwd_string();
        let home = paths.home_string();
        let project_root = paths.project_root_string();
        let key: Vec<String> = argv.clone();
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
                    inner
                        .session_sudo_deny
                        .entry(session_id.clone())
                        .or_default()
                        .insert(key.clone());
                    if let Some(allow_bucket) = inner.session_sudo_allow.get_mut(&session_id) {
                        allow_bucket.remove(&key);
                    }
                }
                ScopeTarget::Global {
                    ref policy_path,
                    ref home,
                } => {
                    if let Err(err) = Self::persist_sudo_deny(
                        policy_path,
                        &argv,
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
                    if let Err(err) = Self::persist_sudo_deny(
                        policy_path,
                        &argv,
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
        let detail = format!("argv={argv:?} scope={scope_label}");
        Self::audit("deny", None, None, &detail);
        let path = project_root
            .as_deref()
            .filter(|_| scope == ApprovalScope::Project)
            .and_then(Self::project_policy_path_display);
        RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope_label, path))
    }
}
