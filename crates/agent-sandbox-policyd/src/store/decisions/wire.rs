//! Scope wire resolution and helper for pending decisions.

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths};

use crate::wire::{PendingDecision, ScopeWire};

use super::super::types::{Pending, PolicyStore};

impl PolicyStore {
    pub(crate) fn scope_wire_for_pending(wire: ScopeWire, pending: &Pending) -> ScopeWire {
        ScopeWire {
            paths: SandboxPaths::from_wire(
                pending.cwd.clone().or(wire.paths.cwd_string()),
                pending.home.clone().or(wire.paths.home_string()),
                pending
                    .project_root
                    .clone()
                    .or(wire.paths.project_root_string()),
            ),
            session_id: wire.session_id,
            owner_uid: wire.owner_uid,
        }
    }

    pub(crate) async fn take_pending_decision(
        &self,
        decision: PendingDecision,
    ) -> Result<(Pending, ApprovalScope, ScopeWire), RpcReply> {
        let PendingDecision {
            pending_id,
            scope,
            wire,
        } = decision;
        let scope = scope.parse::<ApprovalScope>().map_err(RpcReply::from)?;
        let pending = {
            let mut inner = self.inner.lock().await;
            inner.pending.remove(&pending_id)
        };
        let pending = pending.ok_or_else(|| {
            let err: RpcReply = crate::error::PolicydError::UnknownPendingId.into();
            err
        })?;
        Ok((pending, scope, wire))
    }
}
