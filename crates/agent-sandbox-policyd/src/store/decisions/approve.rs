//! Apply pending network or elevation decisions.

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, ElevateReply, RpcReply, ScopeActionReply, SudoRule,
    approval_host_patterns,
};

use crate::error::PolicydError;
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
        let (pending, wire, scope, target) = match self.take_pending_decision(decision).await {
            Ok(value) => value,
            Err(err) => return err,
        };
        match pending.kind {
            PendingKind::Network => {
                self.apply_pending_network_decision(pending, wire, scope, target.as_ref(), action)
                    .await
            }
            PendingKind::Elevation => {
                self.apply_pending_sudo_decision(pending, wire, scope, target.as_ref(), action)
                    .await
            }
        }
    }

    async fn apply_pending_network_decision(
        &self,
        pending: Pending,
        wire: crate::wire::ScopeWire,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = pending.id.clone();
        let (host, port) = match Self::resolve_pending_network_target(&pending, scope, target) {
            Ok(value) => value,
            Err(err) => {
                self.inner.lock().await.pending.insert(pending_id, pending);
                return err.into();
            }
        };

        if action == DecisionAction::Approve && scope == ApprovalScope::Once {
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
        target: Option<&ApprovalTarget>,
        action: DecisionAction,
    ) -> RpcReply {
        let pending_id = pending.id.clone();
        let argv = match Self::resolve_pending_sudo_target(&pending, scope, target) {
            Ok(value) => value,
            Err(err) => {
                self.inner.lock().await.pending.insert(pending_id, pending);
                return err.into();
            }
        };
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

    fn resolve_pending_network_target(
        pending: &Pending,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
    ) -> Result<(String, u16), PolicydError> {
        let pending_host = pending.host.clone().unwrap_or_default();
        let pending_port = pending.port.unwrap_or(0);
        let host = match target {
            None => pending_host.clone(),
            Some(ApprovalTarget::NetworkHost { host }) => host.clone(),
            Some(ApprovalTarget::SudoCommand { .. }) => {
                return Err(PolicydError::InvalidDecisionTarget);
            }
        };
        let valid_host = approval_host_patterns(&pending_host)
            .into_iter()
            .any(|candidate| candidate == host);
        if !valid_host {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        if scope == ApprovalScope::Once && host != pending_host {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        Ok((host, pending_port))
    }

    fn resolve_pending_sudo_target(
        pending: &Pending,
        scope: ApprovalScope,
        target: Option<&ApprovalTarget>,
    ) -> Result<Vec<String>, PolicydError> {
        let pending_argv = pending.argv.clone().unwrap_or_default();
        let argv = match target {
            None => pending_argv.clone(),
            Some(ApprovalTarget::SudoCommand { argv }) => argv.clone(),
            Some(ApprovalTarget::NetworkHost { .. }) => {
                return Err(PolicydError::InvalidDecisionTarget);
            }
        };
        let valid_argv = SudoRule::approval_prefixes(&pending_argv)
            .into_iter()
            .any(|candidate| candidate == argv);
        if !valid_argv {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        if scope == ApprovalScope::Once && argv != pending_argv {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        Ok(argv)
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{ApprovalScope, ApprovalTarget};

    use crate::store::{Pending, PendingKind, PolicyStore};

    #[test]
    fn network_target_accepts_parent_domain_patterns() {
        let pending = Pending {
            id: "p1".into(),
            created_at: 0.0,
            kind: PendingKind::Network,
            argv: None,
            host: Some("foo.bar.baz.com".into()),
            port: Some(443),
            scheme: None,
            url: None,
            cwd: None,
            home: None,
            project_root: None,
            request_pid: None,
        };
        let target = ApprovalTarget::NetworkHost {
            host: "*.baz.com".into(),
        };
        assert_eq!(
            PolicyStore::resolve_pending_network_target(
                &pending,
                ApprovalScope::Project,
                Some(&target),
            )
            .unwrap(),
            ("*.baz.com".to_string(), 443)
        );
    }

    #[test]
    fn sudo_target_accepts_command_prefixes() {
        let pending = Pending {
            id: "p1".into(),
            created_at: 0.0,
            kind: PendingKind::Elevation,
            argv: Some(vec!["foo".into(), "bar".into(), "baz".into()]),
            host: None,
            port: None,
            scheme: None,
            url: None,
            cwd: None,
            home: None,
            project_root: None,
            request_pid: None,
        };
        let target = ApprovalTarget::SudoCommand {
            argv: vec!["foo".into(), "bar".into()],
        };
        assert_eq!(
            PolicyStore::resolve_pending_sudo_target(
                &pending,
                ApprovalScope::Session,
                Some(&target),
            )
            .unwrap(),
            vec!["foo".to_string(), "bar".to_string()]
        );
    }
}
