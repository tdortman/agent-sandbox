//! Policy store: network scope application.

use super::{
    apply_session_rule,
    decisions::DecisionAction,
    types::{PolicyDecisionState, PolicyStore},
};

use crate::{
    error::PolicydError,
    wire::{NetworkScopeOp, ScopeWire},
};

use agent_sandbox_core::{
    ApprovalScope, NetworkRuleKey, RpcReply, SandboxPaths, ScopeActionReply, ScopeContext,
    ScopeTarget,
};

use std::path::{Path, PathBuf};

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
            package,
        } = wire;

        let home = paths.home();
        let project_root = paths.project_root();
        let session_entries = vec![NetworkRuleKey::new(&host, port)];

        let target = match self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                home,
                project_root,
                package.as_deref(),
            )
            .await
        {
            Ok(target) => target,
            Err(reply) => return *reply,
        };

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());

        let persist =
            |policy_path: &Path, home: Option<&Path>, invalidate: bool| -> std::io::Result<()> {
                Self::persist_network_rule(
                    policy_path,
                    &host,
                    port,
                    scope_label,
                    action == DecisionAction::Approve,
                    home,
                    owner_uid,
                )?;

                if invalidate {
                    self.invalidate_merged_policy_cache();
                }

                Ok(())
            };

        match target {
            ScopeTarget::Ephemeral => {
                if action == DecisionAction::Approve {
                    let mut inner = self.inner.lock().await;
                    inner.once_allow.insert(NetworkRuleKey::new(&host, port));
                }
            }

            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                let PolicyDecisionState {
                    session_allow: allow,
                    session_deny: deny,
                    ..
                } = &mut *inner;
                for key in session_entries {
                    apply_session_rule(action, &session_id, &key, allow, deny);
                }
                drop(inner);
            }

            ScopeTarget::Global { policy_path, home } => {
                if let Err(err) = persist(&policy_path, Some(home.as_path()), false) {
                    return PolicydError::from(err).into();
                }
            }

            ScopeTarget::GlobalPackage {
                policy_path, home, ..
            } => {
                if let Err(err) = persist(&policy_path, Some(home.as_path()), true) {
                    return PolicydError::from(err).into();
                }
            }

            ScopeTarget::Project {
                policy_path,
                project_root: _,
            } => {
                if let Err(err) = persist(&policy_path, home, false) {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project policy saved");
            }

            ScopeTarget::ProjectPackage { policy_path, .. } => {
                if let Err(err) = persist(&policy_path, home, true) {
                    return PolicydError::from(err).into();
                }
                tracing::info!(path = ?policy_path, "project package policy saved");
            }
        }

        self.finalize_network_scope(&paths, host, port, scope, action)
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
        package: Option<&str>,
    ) -> Result<ScopeTarget, Box<RpcReply>> {
        let active = self.active_session_ids().await;
        let home_str = home.and_then(Path::to_str);
        let project_root_str = project_root.and_then(Path::to_str);

        let ctx = ScopeContext {
            scope,
            session_id,
            home: home_str,
            project_root: project_root_str,
            package,
            active_session_ids: &active,
        };

        ScopeTarget::resolve(&ctx).map_err(|err| Box::new(RpcReply::from(err)))
    }
}
