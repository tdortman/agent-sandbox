//! Policy store: network scope application.
use std::path::Path;

use agent_sandbox_core::{
    ApprovalScope, NetworkRuleKey, RpcReply, SandboxPaths, ScopeActionReply, ScopeContext,
    ScopeTarget, allow_keys,
};

use crate::error::PolicydError;
use crate::wire::{NetworkScopeOp, ScopeWire};

use super::decisions::DecisionAction;
use super::types::PolicyStore;

fn session_network_entries(host: &str, port: u16) -> Vec<NetworkRuleKey> {
    if host.starts_with("*.") {
        vec![NetworkRuleKey::new(host, port)]
    } else {
        allow_keys(host, port)
    }
}

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
            sandbox_session_id: _,
        } = wire;
        let cwd = paths.cwd_string();
        let home = paths.home_string();
        let project_root = paths.project_root_string();
        let session_entries = session_network_entries(&host, port);
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
                    for key in allow_keys(&host, port) {
                        inner.once_allow.insert(key);
                    }
                }
            }
            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                match action {
                    DecisionAction::Approve => {
                        let bucket = inner.session_allow.entry(session_id.clone()).or_default();
                        for entry in &session_entries {
                            bucket.insert(entry.clone());
                        }
                        if let Some(deny_bucket) = inner.session_deny.get_mut(&session_id) {
                            for entry in session_entries {
                                deny_bucket.remove(&entry);
                            }
                        }
                    }
                    DecisionAction::Deny => {
                        let bucket = inner.session_deny.entry(session_id.clone()).or_default();
                        for entry in &session_entries {
                            bucket.insert(entry.clone());
                        }
                        if let Some(allow_bucket) = inner.session_allow.get_mut(&session_id) {
                            for entry in session_entries {
                                allow_bucket.remove(&entry);
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
                        Some(Path::new(&home)),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_network_deny(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        Some(Path::new(&home)),
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
                        home.as_deref().map(Path::new),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_network_deny(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        home.as_deref().map(Path::new),
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
        let path = match (home.as_deref(), project_root.as_deref()) {
            (_, Some(p)) if scope == ApprovalScope::Project => {
                Self::project_policy_path_display(Path::new(p))
            }
            _ => None,
        };
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

#[cfg(test)]
mod tests {
    use super::session_network_entries;
    use agent_sandbox_core::NetworkRuleKey;

    #[test]
    fn wildcard_session_entry_is_kept_as_pattern() {
        assert_eq!(
            session_network_entries("*.baz.com", 443),
            vec![NetworkRuleKey::new("*.baz.com", 443)]
        );
    }
}
