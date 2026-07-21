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

impl PolicyStore {
    fn scope_wire_for_context(wire: ScopeWire, context: PendingContext<'_>) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id,
            comment,
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
        }
    }

    pub(crate) fn scope_wire_for_pending_network(
        wire: ScopeWire,
        net: &PendingNetwork,
    ) -> ScopeWire {
        Self::scope_wire_for_context(wire, PendingContext {
            cwd: net.cwd.as_deref(),
            home: net.home.as_deref(),
            project_root: net.project_root.as_deref(),
            sandbox_session_id: net.sandbox_session_id.as_deref(),
        })
    }

    pub(crate) fn scope_wire_for_pending_elevation(
        wire: ScopeWire,
        elev: &PendingElevation,
    ) -> ScopeWire {
        Self::scope_wire_for_context(wire, PendingContext {
            cwd: elev.cwd.as_deref(),
            home: elev.home.as_deref(),
            project_root: elev.project_root.as_deref(),
            sandbox_session_id: elev.sandbox_session_id.as_deref(),
        })
    }

    pub(crate) fn scope_wire_for_pending_filesystem(
        wire: ScopeWire,
        fs: &PendingFilesystem,
    ) -> ScopeWire {
        Self::scope_wire_for_context(wire, PendingContext {
            cwd: fs.cwd.as_deref(),
            home: fs.home.as_deref(),
            project_root: fs.project_root.as_deref(),
            sandbox_session_id: fs.sandbox_session_id.as_deref(),
        })
    }

    pub(crate) fn scope_wire_for_pending_resource(
        wire: ScopeWire,
        res: &PendingResource,
    ) -> ScopeWire {
        Self::scope_wire_for_context(wire, PendingContext {
            cwd: res.cwd.as_deref(),
            home: res.home.as_deref(),
            project_root: res.project_root.as_deref(),
            sandbox_session_id: res.sandbox_session_id.as_deref(),
        })
    }

    pub(crate) fn scope_wire_for_pending_dbus(wire: ScopeWire, dbus: &PendingDbus) -> ScopeWire {
        Self::scope_wire_for_context(wire, PendingContext {
            cwd: dbus.cwd.as_deref(),
            home: dbus.home.as_deref(),
            project_root: dbus.project_root.as_deref(),
            sandbox_session_id: dbus.sandbox_session_id.as_deref(),
        })
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
    ) -> Result<TakenPendingDecision, RpcReply> {
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
            inner.take_pending(&pending_id)
        };
        let pending = pending.ok_or_else(|| {
            let err: RpcReply = crate::error::PolicydError::UnknownPendingId.into();
            err
        })?;
        if !self
            .approval_client_authorized(client_id, pending.sandbox_session_id(), approver_uid)
            .await
        {
            let mut inner = self.inner.lock().await;
            inner.restore_pending(pending);
            drop(inner);
            return Err(crate::error::PolicydError::UnauthorizedApprovalClient.into());
        }
        Ok(TakenPendingDecision {
            pending,
            wire,
            scope,
            target,
        })
    }
}
