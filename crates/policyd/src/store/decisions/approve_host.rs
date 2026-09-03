//! Approve a host directly (without a pending id).

use agent_sandbox_core::{ApprovalScope, ResolvedRequestContext, RpcReply, normalize_host};

use super::{super::types::PolicyStore, DecisionAction};
use crate::{
    error::PolicydError,
    wire::{NetworkScopeOp, ScopeWire},
};

impl PolicyStore {
    /// Approve a network host directly (without a pending approval id).
    pub async fn approve_host(
        &self,
        host: String,
        port: u16,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: ResolvedRequestContext,
    ) -> RpcReply {
        let policy_host = normalize_host(&host);

        if policy_host.is_empty() {
            return PolicydError::HostRequired.into();
        }

        if port == 0 {
            return PolicydError::InvalidPort.into();
        }

        let wire_ids = ctx.ids;
        let paths = ctx.paths.clone();

        let deny_ctx = agent_sandbox_core::ResolvedRequestContext {
            paths: paths.clone(),
            ids: wire_ids,
            sandbox_session_id: ctx.sandbox_session_id.clone(),
            package: None,
        };

        if self.policy_denied(&policy_host, port, &deny_ctx) {
            return PolicydError::HostDeniedByPolicy.into();
        }

        self.apply_network_scope(
            NetworkScopeOp {
                host: policy_host,
                port,
                scope,
                wire: ScopeWire {
                    paths,
                    session_id,
                    owner_uid: wire_ids.uid(),
                    sandbox_session_id: ctx.sandbox_session_id,
                    comment: None,
                    package: ctx.package.clone(),
                },
            },
            DecisionAction::Approve,
        )
        .await
    }
}
