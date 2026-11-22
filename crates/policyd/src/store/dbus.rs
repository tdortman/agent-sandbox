use agent_sandbox_core::{DbusCheckReply, DbusTarget, ResolvedRequestContext};

use super::PolicyStore;

impl PolicyStore {
    /// Check a D-Bus target against declarative rules, then route unknown
    /// capabilities through the typed approval path.
    pub async fn check_dbus(
        &self,
        target: DbusTarget,
        ctx: ResolvedRequestContext,
    ) -> DbusCheckReply {
        if let Some(verdict) = self.dbus_decided_verdict(&target, &ctx).await {
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
