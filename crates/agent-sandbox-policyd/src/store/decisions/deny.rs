//! Deny a pending network or elevation request.

use agent_sandbox_core::{ApprovalScope, ElevateReply, RpcReply, ScopeActionReply};

use crate::wire::{NetworkScopeOp, PendingDecision, SudoScopeOp};

use super::super::types::{PendingKind, PolicyStore};

impl PolicyStore {
    pub async fn deny(&self, decision: PendingDecision) -> RpcReply {
        let (pending, scope, wire) = match self.take_pending_decision(decision).await {
            Ok(v) => v,
            Err(err) => return err,
        };
        let pending_id = pending.id.clone();
        let scope_label = scope.as_str();

        if pending.kind == PendingKind::Network {
            let host = pending.host.clone().unwrap_or_default();
            let port = pending.port.unwrap_or(0);
            if scope == ApprovalScope::Once {
                Self::audit(
                    "deny",
                    Some(&host),
                    Some(port),
                    pending.scheme.as_deref().unwrap_or(""),
                );
                self.finish_network(&pending_id, false, "denied").await;
                return RpcReply::ScopeAction(ScopeActionReply::ok_network(
                    host,
                    port,
                    scope_label,
                    None,
                ));
            }
            let result = self
                .deny_network_scope(NetworkScopeOp {
                    host: host.clone(),
                    port,
                    scope,
                    wire: Self::scope_wire_for_pending(wire, &pending),
                })
                .await;
            if result.scope_succeeded() {
                self.finish_network(&pending_id, false, "denied").await;
            } else {
                let id = pending.id.clone();
                self.inner.lock().await.pending.insert(id, pending);
            }
            return result;
        }

        let argv = pending.argv.clone().unwrap_or_default();
        if scope == ApprovalScope::Once {
            let detail = format!("id={pending_id} argv={argv:?}");
            Self::audit("deny", None, None, &detail);
            self.finish_elevation(&pending_id, ElevateReply::denied())
                .await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope_label, None));
        }
        let result = self
            .deny_sudo_scope(SudoScopeOp {
                argv: argv.clone(),
                scope,
                wire: Self::scope_wire_for_pending(wire, &pending),
            })
            .await;
        if result.scope_succeeded() {
            self.finish_elevation(&pending_id, ElevateReply::denied())
                .await;
        } else {
            let id = pending.id.clone();
            self.inner.lock().await.pending.insert(id, pending);
        }
        result
    }
}
