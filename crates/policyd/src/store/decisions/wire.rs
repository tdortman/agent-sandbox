//! Shared decision helpers for pending approvals.

use agent_sandbox_core::{ApprovalScope, ApprovalTarget, RpcReply};

use super::super::types::{
    Pending, PendingContext, PendingDbus, PendingElevation, PendingFilesystem, PendingNetwork,
    PendingResource, PolicyStore,
};
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

/// Extracts the context-style fields shared by every pending record that
/// flows through [`scope_wire_for_pending`].
pub(super) trait PendingContextSource {
    fn pending_context(&self) -> PendingContext<'_>;
}

impl PendingContextSource for PendingElevation {
    fn pending_context(&self) -> PendingContext<'_> {
        PendingContext {
            cwd: self.cwd.as_deref(),
            home: self.home.as_deref(),
            project_root: self.project_root.as_deref(),
            sandbox_session_id: self.sandbox_session_id.as_deref(),
            package: self.package.as_deref(),
        }
    }
}

impl PendingContextSource for PendingNetwork {
    fn pending_context(&self) -> PendingContext<'_> {
        PendingContext {
            cwd: self.cwd.as_deref(),
            home: self.home.as_deref(),
            project_root: self.project_root.as_deref(),
            sandbox_session_id: self.sandbox_session_id.as_deref(),
            package: self.package.as_deref(),
        }
    }
}

impl PendingContextSource for PendingFilesystem {
    fn pending_context(&self) -> PendingContext<'_> {
        PendingContext {
            cwd: self.cwd.as_deref(),
            home: self.home.as_deref(),
            project_root: self.project_root.as_deref(),
            sandbox_session_id: self.sandbox_session_id.as_deref(),
            package: self.package.as_deref(),
        }
    }
}

impl PendingContextSource for PendingResource {
    fn pending_context(&self) -> PendingContext<'_> {
        PendingContext {
            cwd: self.cwd.as_deref(),
            home: self.home.as_deref(),
            project_root: self.project_root.as_deref(),
            sandbox_session_id: self.sandbox_session_id.as_deref(),
            package: self.package.as_deref(),
        }
    }
}

impl PendingContextSource for PendingDbus {
    fn pending_context(&self) -> PendingContext<'_> {
        PendingContext {
            cwd: self.cwd.as_deref(),
            home: self.home.as_deref(),
            project_root: self.project_root.as_deref(),
            sandbox_session_id: self.sandbox_session_id.as_deref(),
            package: self.package.as_deref(),
        }
    }
}

impl PolicyStore {
    fn scope_wire_for_context(wire: ScopeWire, context: PendingContext<'_>) -> ScopeWire {
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
                context.cwd.map(std::path::Path::to_path_buf),
                context.home.map(std::path::Path::to_path_buf),
                context.project_root.map(std::path::Path::to_path_buf),
            ),
            session_id,
            owner_uid,
            sandbox_session_id: sandbox_session_id
                .or_else(|| context.sandbox_session_id.map(str::to_owned)),
            comment,
            package: package.or_else(|| context.package.map(str::to_owned)),
        }
    }

    pub(super) fn scope_wire_for_pending<P: PendingContextSource>(
        wire: ScopeWire,
        pending: &P,
    ) -> ScopeWire {
        Self::scope_wire_for_context(wire, pending.pending_context())
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

        self.sandbox_sessions.read().is_ok_and(|sessions| {
            sessions
                .get(session)
                .is_some_and(|registration| registration.owner_uid == uid)
        })
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
            inner.pending.take_pending(&pending_id)
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
            let mut inner = self.inner.lock().await;
            inner.pending.restore_pending(pending);
            drop(inner);

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
