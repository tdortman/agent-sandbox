//! Approve a host directly (without a pending id).

use agent_sandbox_core::{RpcReply, normalize_host};

use crate::error::PolicydError;
use crate::wire::{HostApproveRequest, MergeContext, NetworkScopeOp, ScopeWire};

use super::super::types::PolicyStore;
use super::DecisionAction;

impl PolicyStore {
    pub async fn approve_host(&self, req: HostApproveRequest) -> RpcReply {
        let HostApproveRequest {
            host,
            port,
            scope,
            session_id,
            ctx,
        } = req;
        let policy_host = normalize_host(&host);
        if policy_host.is_empty() {
            return PolicydError::HostRequired.into();
        }
        if port == 0 {
            return PolicydError::InvalidPort.into();
        }
        let resolved = self.resolve_context(&ctx);
        let wire_ids = resolved.ids;
        let paths = resolved.paths;
        let deny_ctx = MergeContext {
            paths: paths.clone(),
            ids: wire_ids,
            sandbox_session_id: resolved.sandbox_session_id.clone(),
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
                    sandbox_session_id: resolved.sandbox_session_id,
                },
            },
            DecisionAction::Approve,
        )
        .await
    }
}
