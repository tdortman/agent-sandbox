//! Approve a host directly (without a pending id).

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths, normalize_host};

use crate::error::PolicydError;
use crate::wire::{HostApproveRequest, MergeContext, NetworkScopeOp, ScopeWire};

use super::super::types::PolicyStore;

impl PolicyStore {
    pub async fn approve_host(&self, req: HostApproveRequest) -> RpcReply {
        let HostApproveRequest {
            host,
            port,
            scope,
            session_id,
            ctx,
        } = req;
        let scope = match scope.parse::<ApprovalScope>() {
            Ok(s) => s,
            Err(err) => return err.into(),
        };
        let policy_host = normalize_host(&host);
        if policy_host.is_empty() {
            return PolicydError::HostRequired.into();
        }
        if port == 0 {
            return PolicydError::InvalidPort.into();
        }
        let wire_ids = ctx.ids;
        let (cwd, home, project_root) = self
            .resolve_context(
                ctx.paths.cwd_string(),
                ctx.paths.home_string(),
                ctx.paths.project_root_string(),
                wire_ids.pid(),
                wire_ids.uid(),
            )
            .await;
        let paths = SandboxPaths::from_wire(cwd, home, project_root);
        if self
            .policy_denied(
                &policy_host,
                port,
                MergeContext {
                    paths: paths.clone(),
                    ids: wire_ids,
                },
            )
            .await
        {
            return PolicydError::HostDeniedByPolicy.into();
        }
        self.approve_network_scope(NetworkScopeOp {
            host: policy_host,
            port,
            scope,
            wire: ScopeWire {
                paths,
                session_id,
                owner_uid: wire_ids.uid(),
            },
        })
        .await
    }
}
