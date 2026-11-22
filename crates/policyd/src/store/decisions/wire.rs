//! Shared decision helpers for pending approvals.

use agent_sandbox_core::{ApprovalScope, ApprovalTarget, ResolvedRequestContext, RpcReply};

use super::super::types::{Pending, PolicyStore};
use crate::wire::{PendingDecision, ScopeWire};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAction {
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

pub struct TakenPendingDecision {
    pub pending: Pending,
    pub wire: ScopeWire,
    pub scope: ApprovalScope,
    pub target: Option<ApprovalTarget>,
}

impl PolicyStore {
    pub(in crate::store) fn scope_wire_for_context(
        wire: ScopeWire,
        context: &ResolvedRequestContext,
    ) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id,
            comment,
            package,
        } = wire;

        ScopeWire {
            paths: paths.merged_with(
                context.paths.cwd_path(),
                context.paths.home_path(),
                context.paths.project_root_path(),
            ),
            session_id,
            owner_uid,
            sandbox_session_id: sandbox_session_id.or_else(|| context.sandbox_session_id.clone()),
            comment,
            package: package.or_else(|| context.package.clone()),
        }
    }

    /// The scope wire of a decision on a pending of `context`. A session
    /// decision that names no session the context routes to is bound to the
    /// first one that does.
    pub(in crate::store) async fn session_scope_wire(
        &self,
        wire: ScopeWire,
        context: &ResolvedRequestContext,
        scope: ApprovalScope,
    ) -> ScopeWire {
        let mut scope_wire = Self::scope_wire_for_context(wire, context);

        if scope != ApprovalScope::Session {
            return scope_wire;
        }

        let session_ids = self.session_ids_for_context(context).await;

        if scope_wire
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_ids.contains(session_id))
        {
            return scope_wire;
        }

        if let Some(session_id) = session_ids.into_iter().min() {
            scope_wire.session_id = Some(session_id);
        }

        scope_wire
    }

    async fn approval_client_authorized(
        &self,
        client_id: u64,
        ui_session_id: Option<&str>,
        sandbox_session_id: Option<&str>,
        approver_uid: Option<u32>,
    ) -> bool {
        let inner = self.inner.lock().await;

        let ui_session_id = inner
            .ui_clients
            .get(&client_id)
            .map(|client| client.session_id.as_str())
            .or(ui_session_id);

        let ui_authorized = ui_session_id
            .and_then(|session_id| {
                let ctx = inner.ui_context_by_session.get(session_id)?;

                inner
                    .ui_clients
                    .get(&ctx.client_id)
                    .filter(|client| client.session_id == session_id)
                    .map(|_| ctx)
            })
            .is_some_and(|ctx| {
                ctx.sandbox_session_id.as_deref() == sandbox_session_id
                    && approver_uid.is_none_or(|uid| uid > 0 && ctx.owner_uid == Some(uid))
            });

        drop(inner);

        if ui_authorized {
            return true;
        }

        let (Some(uid), Some(session)) = (approver_uid.filter(|uid| *uid > 0), sandbox_session_id)
        else {
            return false;
        };

        self.sandbox_sessions
            .snapshot()
            .get(session)
            .is_some_and(|registration| registration.owner_uid == uid)
    }

    pub(crate) async fn take_pending_decision(
        &self,
        decision: PendingDecision,
    ) -> Result<TakenPendingDecision, Box<RpcReply>> {
        let PendingDecision {
            pending_id,
            scope,
            target,
            wire,
            client_id,
            approver_uid,
        } = decision;

        let pending = {
            let mut inner = self.inner.lock().await;
            inner.pending.pending.remove(&pending_id)
        };

        let pending = pending.ok_or_else(|| {
            let err: RpcReply = crate::error::PolicydError::UnknownPendingId.into();
            Box::new(err)
        })?;

        if !self
            .approval_client_authorized(
                client_id,
                wire.session_id.as_deref(),
                pending.sandbox_session_id(),
                approver_uid,
            )
            .await
        {
            self.put_back(pending).await;

            return Err(Box::new(
                crate::error::PolicydError::UnauthorizedApprovalClient.into(),
            ));
        }

        Ok(TakenPendingDecision {
            pending,
            wire,
            scope,
            target,
        })
    }
}
