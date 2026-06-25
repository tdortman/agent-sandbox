//! Deny a pending network or elevation request.

use agent_sandbox_core::RpcReply;

use crate::wire::PendingDecision;

use super::super::types::PolicyStore;
use super::DecisionAction;

impl PolicyStore {
    pub async fn deny(&self, decision: PendingDecision) -> RpcReply {
        self.apply_pending_decision(decision, DecisionAction::Deny)
            .await
    }
}
