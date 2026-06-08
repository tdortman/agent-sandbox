//! Shared decision helpers for pending approvals.

use agent_sandbox_core::{ApprovalScope, ApprovalTarget, RpcReply};

use crate::wire::{PendingDecision, ScopeWire};

use super::super::types::{Pending, PolicyStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionAction {
    Approve,
    Deny,
}

impl DecisionAction {
    pub const fn audit_verb(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

impl PolicyStore {
    pub(crate) fn scope_wire_for_pending(wire: ScopeWire, pending: &Pending) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
        } = wire;
        ScopeWire {
            paths: paths.merged_with(
                pending.cwd.clone(),
                pending.home.clone(),
                pending.project_root.clone(),
            ),
            session_id,
            owner_uid,
        }
    }

    pub(crate) async fn take_pending_decision(
        &self,
        decision: PendingDecision,
    ) -> Result<(Pending, ScopeWire, ApprovalScope, Option<ApprovalTarget>), RpcReply> {
        let PendingDecision {
            pending_id,
            scope,
            target,
            wire,
        } = decision;
        let pending = {
            let mut inner = self.inner.lock().await;
            inner.pending.remove(&pending_id)
        };
        let pending = pending.ok_or_else(|| {
            let err: RpcReply = crate::error::PolicydError::UnknownPendingId.into();
            err
        })?;
        Ok((pending, wire, scope, target))
    }
}
