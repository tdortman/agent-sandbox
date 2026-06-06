//! Apply pending network or elevation decisions.

use agent_sandbox_core::{ApprovalScope, ElevateReply, RpcReply, ScopeActionReply};

use crate::wire::{NetworkScopeOp, PendingDecision, SudoScopeOp};

use super::super::types::{Pending, PendingKind, PolicyStore};
use super::DecisionAction;

impl PolicyStore {
    pub async fn approve(&self, decision: PendingDecision) -> RpcReply {
        self.apply_pending_decision(decision, DecisionAction::Approve)
            .await
    }

    pub(crate) async fn apply_pending_decision(
        &self,
        decision: PendingDecision,
        action: DecisionAction,
    ) -> RpcReply {
        let (pending, wire, scope) = match self.take_pending_decision(decision).await {
            Ok(value) => value,
            Err(err) => return err,
        };
        match pending.kind {
            PendingKind::Network => {
                self.apply_pending_network_decision(pending, wire, scope, action)
                    .await
            }
            PendingKind::Elevation => {
                self.apply_pending_sudo_decision(pending, wire, scope, action)
                    .await
            }
        }
    }

    async fn apply_pending_network_decision(
        &self,
        pending: Pending,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = pending.id.clone();
        let host = pending.host.clone().unwrap_or_default();
        let port = pending.port.unwrap_or(0);

        if action == DecisionAction::Approve && scope == ApprovalScope::Once {
            // UI "allow once" only unblocks this pending check. Do not add to once_allow —
            // that would auto-allow the next connection without a prompt (see Python policyd).
            Self::audit(action.audit_verb(), Some(&host), Some(port), scope.as_str());
            self.finish_network(&pending_id, true, "once").await;
            return RpcReply::ScopeAction(ScopeActionReply::ok_network(host, port, scope, None));
        }

        let result = self
            .apply_network_scope(
                NetworkScopeOp {
                    host: host.clone(),
                    port,
                    scope,
                    wire: Self::scope_wire_for_pending(wire, &pending),
                },
                action,
            )
            .await;

        if result.scope_succeeded() {
            match action {
                DecisionAction::Approve => {
                    let source = result.scope_label().unwrap_or(scope.as_str());
                    self.finish_network(&pending_id, true, source).await;
                }
                DecisionAction::Deny => {
                    self.finish_network(&pending_id, false, "denied").await;
                }
            }
        } else if action == DecisionAction::Approve {
            self.finish_network(&pending_id, false, "blocked").await;
        } else {
            self.inner.lock().await.pending.insert(pending_id, pending);
        }
        result
    }

    async fn apply_pending_sudo_decision(
        &self,
        pending: Pending,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = pending.id.clone();
        let argv = pending.argv.clone().unwrap_or_default();
        let scope_wire = Self::scope_wire_for_pending(wire, &pending);

        if action == DecisionAction::Deny {
            if scope == ApprovalScope::Once {
                let detail = format!("id={pending_id} argv={argv:?}");
                Self::audit(action.audit_verb(), None, None, &detail);
                self.finish_elevation(&pending_id, ElevateReply::denied())
                    .await;
                return RpcReply::ScopeAction(ScopeActionReply::ok_sudo(argv, scope, None));
            }
            let result = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv: argv.clone(),
                        scope,
                        wire: scope_wire,
                    },
                    action,
                )
                .await;
            if result.scope_succeeded() {
                self.finish_elevation(&pending_id, ElevateReply::denied())
                    .await;
            } else {
                self.inner.lock().await.pending.insert(pending_id, pending);
            }
            return result;
        }

        let saved_path = if scope == ApprovalScope::Once {
            None
        } else {
            let scope_result = self
                .apply_sudo_scope(
                    SudoScopeOp {
                        argv: argv.clone(),
                        scope,
                        wire: scope_wire.clone(),
                    },
                    action,
                )
                .await;
            if !scope_result.scope_succeeded() {
                self.inner.lock().await.pending.insert(pending_id, pending);
                return scope_result;
            }
            scope_result.scope_path()
        };

        let detail = format!("id={pending_id} argv={argv:?}");
        Self::audit(action.audit_verb(), None, None, &detail);
        let elevation = self
            .exec_elevation(
                &argv,
                pending.cwd.as_deref().or(scope_wire.paths.cwd()),
                pending.home.as_deref().or(scope_wire.paths.home()),
            )
            .await;
        self.finish_elevation(&pending_id, elevation).await;
        RpcReply::ScopeAction(ScopeActionReply::ok_elevation_approve(scope, saved_path))
    }
}
