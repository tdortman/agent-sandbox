use super::PolicyStore;
use crate::wire::DbusCheckRequest;
use agent_sandbox_core::{ApprovalScope, DbusCheckReply, Verdict, VerdictSource};

impl PolicyStore {
    /// Check a D-Bus target against declarative rules, then route unknown
    /// capabilities through the typed approval path.
    pub async fn check_dbus(&self, req: DbusCheckRequest) -> DbusCheckReply {
        let DbusCheckRequest { target, ctx } = req;
        let policy_verdict = self.dbus_verdict(&target, &ctx);

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

        self.request_dbus_approval(target, ctx).await
    }
}
