//! Shared decision helpers for pending approvals.

use super::super::types::{
    Pending, PendingContext, PendingDbus, PendingElevation, PendingFilesystem, PendingNetwork,
    PendingResource, PolicyStore,
};
use crate::wire::{PendingDecision, ScopeWire};
use agent_sandbox_core::{ApprovalScope, ApprovalTarget, RpcReply};

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
        sandbox_session_id: Option<&str>,
        approver_uid: Option<u32>,
    ) -> bool {
        // Host-scoped pendings (no sandbox session) may be resolved by any
        // connection on the host control socket. That socket is local and
        // sensitive ops bind to SO_PEERCRED; the sandbox socket cannot issue
        // Approve/Deny (see auth.rs).
        let Some(pending_session) = sandbox_session_id else {
            return true;
        };

        // Registered UI for this exact sandbox session (UiFd after RegisterUi).
        let inner = self.inner.lock().await;

        let ui_authorized = inner
            .ui_clients
            .get(&client_id)
            .and_then(|client| inner.ui_context_by_session.get(&client.session_id))
            .is_some_and(|ctx| {
                ctx.client_id == client_id
                    && ctx.sandbox_session_id.as_deref() == Some(pending_session)
            });

        drop(inner);

        if ui_authorized {
            return true;
        }

        // Host-side CLI (`agent-sandbox-approve`) and auto-spawned UI: the
        // sandbox socket cannot reach the host socket, so matching session
        // owner uid is sufficient. Blocks cross-user approval and a
        // registered UI for a different sandbox session.
        let Some(uid) = approver_uid.filter(|&u| u > 0) else {
            return false;
        };

        self.sandbox_sessions
            .read()
            .ok()
            .and_then(|sessions| {
                sessions
                    .get(pending_session)
                    .map(|reg| reg.owner_uid == uid)
            })
            .unwrap_or(false)
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
            .approval_client_authorized(client_id, pending.sandbox_session_id(), approver_uid)
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
