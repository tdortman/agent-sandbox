//! Policy store — network scope application.

use agent_sandbox_core::{
    ApprovalScope, RpcReply, SandboxPaths, ScopeActionReply, ScopeContext, ScopeTarget, allow_keys,
};

use crate::error::PolicydError;
use crate::wire::{NetworkScopeOp, ScopeWire};

use super::decisions::DecisionAction;
use super::types::PolicyStore;

impl PolicyStore {
    pub(crate) async fn apply_network_scope(
        &self,
        op: NetworkScopeOp,
        action: DecisionAction,
    ) -> RpcReply {
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
        let target = match self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                home.as_deref(),
                project_root.as_deref(),
            )
            .await
        {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let scope_label = scope.as_str();
        match target {
            ScopeTarget::Ephemeral => {
                if action == DecisionAction::Approve {
                    let mut inner = self.inner.lock().await;
                    for key in keys {
                        inner.once_allow.insert(key);
                    }
                }
            }
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                match action {
                    DecisionAction::Approve => {
                        let bucket = inner.session_allow.entry(session_id.clone()).or_default();
                        for key in &keys {
                            bucket.insert(key.clone());
                        }
                        if let Some(deny_bucket) = inner.session_deny.get_mut(&session_id) {
                            for key in keys {
                                deny_bucket.remove(&key);
                            }
                        }
                    }
                    DecisionAction::Deny => {
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
                }
            }
            ScopeTarget::Global { policy_path, home } => {
                let persist = match action {
                    DecisionAction::Approve => Self::persist_network_allow(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        Some(&home),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_network_deny(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        Some(&home),
                        owner_uid,
                    ),
                };
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
            }
            ScopeTarget::Project {
                policy_path,
                project_root: _,
            } => {
                let persist = match action {
                    DecisionAction::Approve => Self::persist_network_allow(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        home.as_deref(),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_network_deny(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        home.as_deref(),
                        owner_uid,
                    ),
                };
                if let Err(err) = persist {
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
        Self::audit(action.audit_verb(), Some(&host), Some(port), scope_label);
        let path = project_root
            .as_deref()
            .filter(|_| scope == ApprovalScope::Project)
            .and_then(Self::project_policy_path_display);
        RpcReply::ScopeAction(ScopeActionReply::ok_network(host, port, scope, path))
    }

    pub(crate) async fn resolve_scope_target(
        &self,
        scope: ApprovalScope,
        session_id: Option<&str>,
        home: Option<&str>,
        project_root: Option<&str>,
    ) -> Result<ScopeTarget, RpcReply> {
        let active = self.active_session_ids().await;
        let ctx = ScopeContext {
            scope,
            session_id,
            home,
            project_root,
            active_session_ids: &active,
        };
        ScopeTarget::resolve(&ctx).map_err(RpcReply::from)
    }
}
