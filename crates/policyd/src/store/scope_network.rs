//! Policy store: network scope application.
use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, NetworkRuleKey, RpcReply, SandboxPaths, ScopeActionReply, ScopeContext,
    ScopeTarget, allow_keys,
};

use super::{decisions::DecisionAction, types::PolicyStore};
use crate::{
    error::PolicydError,
    wire::{NetworkScopeOp, ScopeWire},
};

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
            comment,
        } = wire;
        let home = paths.home();
        let project_root = paths.project_root();
        let session_entries = session_network_entries(&host, port);
        let target = match self
            .resolve_scope_target(scope, session_id.as_deref(), home, project_root)
            .await
        {
            Ok(target) => target,
            Err(reply) => return *reply,
        };
        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());
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
                self.apply_network_scope_session(action, session_id, session_entries)
                    .await;
            }
            ScopeTarget::Global { policy_path, home } => {
                let persist = match action {
                    DecisionAction::Approve => Self::persist_network_allow(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        Some(home.as_path()),
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_network_deny(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        Some(home.as_path()),
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
                        home,
                        owner_uid,
                    ),
                    DecisionAction::Deny => Self::persist_network_deny(
                        &policy_path,
                        &host,
                        port,
                        scope_label,
                        home,
                        owner_uid,
                    ),
                };
                if let Err(err) = persist {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project policy saved");
            }
        }
        self.finalize_network_scope(&paths, host, port, scope, action)
    }

    async fn apply_network_scope_session(
        &self,
        action: DecisionAction,
        session_id: String,
        entries: Vec<NetworkRuleKey>,
    ) {
        let mut inner = self.inner.lock().await;
        match action {
            DecisionAction::Approve => {
                let bucket = inner.session_allow.entry(session_id.clone()).or_default();
                for entry in &entries {
                    bucket.insert(entry.clone());
                }
                if let Some(deny_bucket) = inner.session_deny.get_mut(&session_id) {
                    for entry in entries {
                        deny_bucket.remove(&entry);
                    }
                }
            }
            DecisionAction::Deny => {
                let bucket = inner.session_deny.entry(session_id.clone()).or_default();
                for entry in &entries {
                    bucket.insert(entry.clone());
                }
                if let Some(allow_bucket) = inner.session_allow.get_mut(&session_id) {
                    for entry in entries {
                        allow_bucket.remove(&entry);
                    }
                }
            }
        }
    }

    fn finalize_network_scope(
        &self,
        paths: &SandboxPaths,
        host: String,
        port: u16,
        scope: ApprovalScope,
        action: DecisionAction,
    ) -> RpcReply {
        let _ = self.export_policy_files(SandboxPaths::from_wire(
            paths.cwd_path(),
            paths.home_path(),
            paths.project_root_path(),
        ));
        Self::audit(action.audit_verb(), Some(&host), Some(port), scope.as_str());
        let path = match (paths.home(), paths.project_root()) {
            (_, Some(p)) if scope == ApprovalScope::Project => Self::project_policy_path_display(p),
            _ => None,
        };
        RpcReply::ScopeAction(ScopeActionReply::ok_network(
            host,
            port,
            scope,
            path.map(PathBuf::from),
        ))
    }

    pub(crate) async fn resolve_scope_target(
        &self,
        scope: ApprovalScope,
        session_id: Option<&str>,
        home: Option<&Path>,
        project_root: Option<&Path>,
    ) -> Result<ScopeTarget, Box<RpcReply>> {
        let active = self.active_session_ids().await;
        let home_str = home.and_then(Path::to_str);
        let project_root_str = project_root.and_then(Path::to_str);
        let ctx = ScopeContext {
            scope,
            session_id,
            home: home_str,
            project_root: project_root_str,
            active_session_ids: &active,
        };
        ScopeTarget::resolve(&ctx).map_err(|err| Box::new(RpcReply::from(err)))
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::NetworkRuleKey;

    use super::session_network_entries;

    #[test]
    fn wildcard_session_entry_is_kept_as_pattern() {
        assert_eq!(session_network_entries("*.baz.com", 443), vec![
            NetworkRuleKey::new("*.baz.com", 443)
        ]);
    }
}
