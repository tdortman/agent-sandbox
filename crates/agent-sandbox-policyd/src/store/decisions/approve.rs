//! Approve a pending network or elevation request.

use agent_sandbox_core::{allow_keys, ApprovalScope, RpcReply, ScopeActionReply};

use crate::wire::{NetworkScopeOp, PendingDecision, SudoScopeOp};

use super::super::types::{PendingKind, PolicyStore};

impl PolicyStore {
    pub async fn approve(&self, decision: PendingDecision) -> RpcReply {
        let crate::wire::PendingDecision {
            pending_id,
            scope,
            wire,
        } = decision;
        let scope = match Self::parse_scope(&scope) {
            Ok(s) => s,
            Err(err) => return err.into(),
        };
        let scope_label = scope.as_str();
        let pending = {
            let mut inner = self.inner.lock().await;
            inner.pending.remove(&pending_id)
        };
        let Some(pending) = pending else {
            return crate::error::PolicydError::UnknownPendingId.into();
        };

        if pending.kind == PendingKind::Network {
            let host = pending.host.clone().unwrap_or_default();
            let port = pending.port.unwrap_or(0);
            if scope == ApprovalScope::Once {
                Self::audit("approve", Some(&host), Some(port), scope_label);
                self.finish_network(&pending_id, true, "once").await;
                return RpcReply::ScopeAction(ScopeActionReply::ok_network(
                    host,
                    port,
                    scope_label,
                    None,
                ));
            }
            let result = self
                .approve_network_scope(NetworkScopeOp {
                    host: host.clone(),
                    port,
                    scope,
                    wire: Self::scope_wire_for_pending(wire, &pending),
                })
                .await;
            if result.scope_succeeded() {
                let source = result.scope_label().unwrap_or(scope_label);
                self.finish_network(&pending_id, true, source).await;
            } else {
                self.finish_network(&pending_id, false, "blocked").await;
            }
            return result;
        }

        let argv = pending.argv.clone().unwrap_or_default();
        let scope_wire = Self::scope_wire_for_pending(wire, &pending);
        let saved_path = if scope == ApprovalScope::Once {
            None
        } else {
            let scope_result = self
                .approve_sudo_scope(SudoScopeOp {
                    argv: argv.clone(),
                    scope,
                    wire: scope_wire.clone(),
                })
                .await;
            if !scope_result.scope_succeeded() {
                self.inner
                    .lock()
                    .await
                    .pending
                    .insert(pending.id.clone(), pending);
                return scope_result;
            }
            scope_result.scope_path()
        };
        let detail = format!("id={pending_id} argv={argv:?}");
        Self::audit("approve", None, None, &detail);
        let elevation = self
            .exec_elevation(
                &argv,
                pending.cwd.as_deref().or(scope_wire.paths.cwd()),
                pending.home.as_deref().or(scope_wire.paths.home()),
            )
            .await;
        self.finish_elevation(&pending_id, elevation).await;
        RpcReply::ScopeAction(ScopeActionReply::ok_elevation_approve(
            scope_label,
            saved_path,
        ))
    }
}
