//! Shared decision helpers for pending approvals.

use agent_sandbox_core::{ApprovalScope, ApprovalTarget, RpcReply};

use crate::wire::{PendingDecision, ScopeWire};

use super::super::types::{
    Pending, PendingDbus, PendingElevation, PendingFilesystem, PendingNetwork, PendingResource,
    PolicyStore,
};
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
    pub(crate) fn scope_wire_for_pending_network(
        wire: ScopeWire,
        net: &PendingNetwork,
    ) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id,
            comment,
        } = wire;
        ScopeWire {
            paths: paths.merged_with(net.cwd.clone(), net.home.clone(), net.project_root.clone()),
            session_id,
            owner_uid,
            sandbox_session_id: sandbox_session_id.or_else(|| net.sandbox_session_id.clone()),
            comment,
        }
    }

    pub(crate) fn scope_wire_for_pending_elevation(
        wire: ScopeWire,
        elev: &PendingElevation,
    ) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id,
            comment,
        } = wire;
        ScopeWire {
            paths: paths.merged_with(
                elev.cwd.clone(),
                elev.home.clone(),
                elev.project_root.clone(),
            ),
            session_id,
            owner_uid,
            sandbox_session_id: sandbox_session_id.or_else(|| elev.sandbox_session_id.clone()),
            comment,
        }
    }

    pub(crate) fn scope_wire_for_pending_filesystem(
        wire: ScopeWire,
        fs: &PendingFilesystem,
    ) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id,
            comment,
        } = wire;
        ScopeWire {
            paths: paths.merged_with(fs.cwd.clone(), fs.home.clone(), fs.project_root.clone()),
            session_id,
            owner_uid,
            sandbox_session_id: sandbox_session_id.or_else(|| fs.sandbox_session_id.clone()),
            comment,
        }
    }

    pub(crate) fn scope_wire_for_pending_resource(
        wire: ScopeWire,
        res: &PendingResource,
    ) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id,
            comment,
        } = wire;
        ScopeWire {
            paths: paths.merged_with(res.cwd.clone(), res.home.clone(), res.project_root.clone()),
            session_id,
            owner_uid,
            sandbox_session_id: sandbox_session_id.or_else(|| res.sandbox_session_id.clone()),
            comment,
        }
    }
    pub(crate) fn scope_wire_for_pending_dbus(wire: ScopeWire, dbus: &PendingDbus) -> ScopeWire {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id,
            comment,
        } = wire;
        ScopeWire {
            paths: paths.merged_with(
                dbus.cwd.clone(),
                dbus.home.clone(),
                dbus.project_root.clone(),
            ),
            session_id,
            owner_uid,
            sandbox_session_id: sandbox_session_id.or_else(|| dbus.sandbox_session_id.clone()),
            comment,
        }
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
            inner.pending.remove(&pending_id)
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
            inner.pending.insert(pending_id, pending);
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
