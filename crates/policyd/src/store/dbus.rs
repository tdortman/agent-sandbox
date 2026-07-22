use std::path::PathBuf;

use agent_sandbox_core::{
    ApprovalScope, DbusCheckReply, ResourceAccess, ResourceKind, Verdict, VerdictSource,
};

use super::PolicyStore;
use crate::wire::DbusCheckRequest;

impl PolicyStore {
    /// Check a D-Bus target against declarative rules, then route unknown
    /// capabilities through the typed approval path. The encoded target is
    /// retained only as an internal deduplication key.
    pub async fn check_dbus(&self, req: DbusCheckRequest) -> DbusCheckReply {
        let DbusCheckRequest { target, ctx } = req;
        let policy_verdict = self.policy_evaluation(&ctx).dbus_verdict(&target);
        if let Some(verdict) = policy_verdict.as_ref()
            && !verdict.allowed
        {
            return DbusCheckReply::from_verdict(verdict.clone(), target);
        }
        if self.session_dbus_denied(&target, &ctx).await {
            return DbusCheckReply::denied(VerdictSource::policy(), target);
        }
        if self.session_dbus_allowed(&target, &ctx).await {
            return DbusCheckReply::from_verdict(
                Verdict::allowed(VerdictSource::Scope(ApprovalScope::Session)),
                target,
            );
        }
        if let Some(verdict) = policy_verdict {
            return DbusCheckReply::from_verdict(verdict, target);
        }
        let encoded = match serde_json::to_string(&target) {
            Ok(value) => value,
            Err(err) => {
                return DbusCheckReply::blocked(
                    format!("agent-sandbox: invalid D-Bus target: {err}"),
                    target,
                );
            }
        };
        let Some(pid) = ctx.ids.pid() else {
            return DbusCheckReply::blocked(
                "agent-sandbox: cannot identify sandbox process for D-Bus approval",
                target,
            );
        };
        let _freeze_hold = match self.cgroup_freeze.acquire(Some(pid), ctx.ids.uid()) {
            Ok(hold) => hold,
            Err(error) => {
                return DbusCheckReply::blocked(
                    format!("agent-sandbox: cannot freeze sandbox for D-Bus approval: {error}"),
                    target,
                );
            }
        };
        let reply = self
            .request_resource_approval_with_target(
                crate::wire::ResourceCheckRequest {
                    kind: ResourceKind::UnixSocket,
                    path: PathBuf::from(format!("@dbus:{encoded}")),
                    access: ResourceAccess::default(),
                    ctx,
                },
                Some(target.clone()),
            )
            .await;
        let mut result = DbusCheckReply::from_verdict(
            Verdict {
                allowed: reply.allowed,
                source: reply.source,
            },
            target,
        );
        result.error = reply.error;
        result
    }
}
