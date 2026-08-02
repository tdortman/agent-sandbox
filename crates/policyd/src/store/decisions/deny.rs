//! Deny a pending network or elevation request.

use super::{super::types::PolicyStore, DecisionAction};
use crate::wire::PendingDecision;
use agent_sandbox_core::RpcReply;

impl PolicyStore {
    pub async fn deny(&self, decision: PendingDecision) -> RpcReply {
        self.apply_pending_decision(decision, DecisionAction::Deny)
            .await
    }
}
