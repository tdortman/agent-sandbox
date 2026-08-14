//! Policy store: sudo scope application.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{RpcReply, SandboxPaths, ScopeActionReply, ScopeTarget};

use super::{
    ScopePersistFlags, apply_persistent_scope, decisions::DecisionAction, types::PolicyStore,
};
use crate::wire::{ScopeWire, SudoScopeOp};

impl PolicyStore {
    pub(crate) async fn apply_sudo_scope(
        &self,
        op: SudoScopeOp,
        action: DecisionAction,
    ) -> RpcReply {
        let SudoScopeOp { argv, scope, wire } = op;

        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id: _,
            comment,
            package,
        } = wire;

        let cwd = paths.cwd_path();
        let home = paths.home();
        let project_root = paths.project_root();
        let key = argv.clone();

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
                Self::persist_sudo_rule(
                    policy_path,
                    &argv,
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
            ScopeTarget::Ephemeral => {}

            ScopeTarget::Session { session_id } => {
                let mut inner = self.inner.lock().await;
                inner.session.sudo().apply(action, &session_id, &key);
                drop(inner);
            }

            ScopeTarget::Global { .. }
            | ScopeTarget::GlobalPackage { .. }
            | ScopeTarget::Project { .. }
            | ScopeTarget::ProjectPackage { .. } => {
                if let Err(err) = apply_persistent_scope(
                    target,
                    home,
                    ScopePersistFlags::new(false, true),
                    Some("project sudo policy saved"),
                    Some("project package sudo policy saved"),
                    persist,
                ) {
                    return err.into();
                }
            }
        }

        let scope_label = scope.as_str();
        let audit_detail = format!("argv={argv:?} scope={scope_label}");

        self.finalize_scope_reply(
            &SandboxPaths::from_wire(
                cwd,
                home.map(PathBuf::from),
                project_root.map(PathBuf::from),
            ),
            scope,
            action,
            (None, None, &audit_detail),
            |scope, policy_path| {
                RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope, policy_path))
            },
        )
    }
}
