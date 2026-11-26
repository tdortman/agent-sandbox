//! Policy store: D-Bus capability checks and their approval prompt.

use std::{collections::HashMap, time::Duration};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, DbusCheckReply, DbusRule, DbusTarget, ResolvedRequestContext,
    RpcReply, ScopeActionReply, Verdict, VerdictSource,
};
use tokio::sync::oneshot;

use super::{
    decision_context::ContextKey,
    pending::{ApprovalKind, Decision, PromptKind},
    state::{PendingBoard, PolicyDecisionState},
    types::{Pending, PendingDbus, PolicyStore, VerdictEntry},
};
use crate::error::PolicydError;

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

        if ctx.ids.pid().is_none() {
            return DbusCheckReply::blocked(
                "agent-sandbox: cannot identify sandbox process for D-Bus approval",
                target,
            );
        }

        self.request_dbus_approval(target, ctx).await
    }

    /// Route a D-Bus capability through the interactive approval pipeline.
    /// Callers apply declarative rules first. `target` is the typed
    /// capability, so no path encoding is involved.
    pub async fn request_dbus_approval(
        &self,
        target: DbusTarget,
        ctx: ResolvedRequestContext,
    ) -> DbusCheckReply {
        if !self.args.interactive_approval {
            return DbusCheckReply::denied(VerdictSource::Blocked, target);
        }

        if let Some(reply) = self.cached_reply::<DbusApproval>(&target, &ctx).await {
            return reply;
        }

        self.prompt::<DbusApproval>(target, &ctx).await
    }
}

/// The D-Bus kind of pending approval.
pub(super) struct DbusApproval;

impl ApprovalKind for DbusApproval {
    type Key = DbusTarget;
    type Pending = PendingDbus;
    type Target = DbusTarget;

    const FAILED_APPROVAL_BLOCKS: bool = false;

    fn into_pending(pending: PendingDbus) -> Pending {
        Pending::Dbus(pending)
    }

    fn id(pending: &PendingDbus) -> &str {
        &pending.id
    }

    fn ctx(pending: &PendingDbus) -> &ResolvedRequestContext {
        &pending.ctx
    }

    fn key(pending: &PendingDbus) -> DbusTarget {
        pending.target.clone()
    }

    async fn decided_verdict(store: &PolicyStore, pending: &PendingDbus) -> Option<Verdict> {
        store
            .dbus_decided_verdict(&pending.target, &pending.ctx)
            .await
    }

    async fn finish(
        store: &PolicyStore,
        pending_id: &str,
        key: ContextKey<DbusTarget>,
        verdict: Verdict,
    ) {
        store.finish_prompt::<Self>(pending_id, key, verdict).await;
    }

    fn approval_target(
        pending: &PendingDbus,
        decision: &Decision,
    ) -> Result<DbusTarget, PolicydError> {
        match &decision.target {
            None => Ok(pending.target.clone()),
            Some(ApprovalTarget::Dbus { target }) => {
                let rule = DbusRule::new(target.clone(), "");

                if rule.matches(&pending.target) {
                    Ok(rule.target)
                } else {
                    Err(PolicydError::InvalidDecisionTarget)
                }
            }
            Some(_) => Err(PolicydError::InvalidDecisionTarget),
        }
    }

    // The waiters asked for the pending target, whatever broader target the
    // decision names.
    fn decided_key(pending: &PendingDbus, _target: &DbusTarget) -> DbusTarget {
        pending.target.clone()
    }

    fn once_reply(_pending: &PendingDbus, target: DbusTarget) -> ScopeActionReply {
        ScopeActionReply::ok_dbus(target, ApprovalScope::Once, None)
    }

    async fn apply_scope(
        store: &PolicyStore,
        pending: &PendingDbus,
        target: DbusTarget,
        decision: Decision,
    ) -> RpcReply {
        let wire = PolicyStore::scope_wire_for_context(decision.wire, &pending.ctx);

        store
            .apply_dbus_scope(target, decision.scope, wire, decision.action)
            .await
    }
}

impl PromptKind for DbusApproval {
    type Reply = DbusCheckReply;

    const APPROVAL_NAME: &'static str = "D-Bus";
    const ID_PREFIX: &'static str = "dbus";
    const NO_UI: &'static str =
        "agent-sandbox: no standalone policy UI registered (agent-sandbox-ui or auto-spawn)";
    const TIMED_OUT: &'static str =
        "agent-sandbox: D-Bus approval timed out (no response from policy UI)";
    const TOO_MANY_WAITERS: &'static str = "agent-sandbox: too many waiters for one D-Bus approval";
    const VERDICT_TTL: Duration = Duration::from_secs(2);

    fn waiters(
        board: &mut PendingBoard,
    ) -> &mut HashMap<String, Vec<oneshot::Sender<DbusCheckReply>>> {
        &mut board.dbus_futures
    }

    fn verdict_cache(
        state: &mut PolicyDecisionState,
    ) -> &mut HashMap<ContextKey<DbusTarget>, VerdictEntry> {
        &mut state.dbus_verdict_cache
    }

    fn same_prompt(pending: &Pending, key: &DbusTarget, ctx: &ResolvedRequestContext) -> bool {
        matches!(
            pending,
            Pending::Dbus(dbus)
                if &dbus.target == key && dbus.ctx.sandbox_session_id == ctx.sandbox_session_id
        )
    }

    fn new_pending(
        id: String,
        created_at: f64,
        key: &DbusTarget,
        ctx: &ResolvedRequestContext,
    ) -> Pending {
        Pending::Dbus(PendingDbus {
            id,
            created_at,
            target: key.clone(),
            ctx: ctx.clone(),
        })
    }

    fn reply(key: &DbusTarget, verdict: Verdict) -> DbusCheckReply {
        DbusCheckReply::from_verdict(verdict, key.clone())
    }

    fn blocked(key: &DbusTarget, message: &str) -> DbusCheckReply {
        DbusCheckReply::blocked(message, key.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use agent_sandbox_core::{
        DbusMessageKind, DbusTarget, ProcessIds, ResolvedRequestContext, SandboxPaths, Verdict,
        VerdictSource,
    };
    use tokio::{io::AsyncReadExt, net::UnixStream, sync::Mutex};

    use super::DbusApproval;
    use crate::store::{
        UiSessionContext, decision_context::ContextKey, pending::record_verdict, test_store,
        types::UiClient,
    };

    #[tokio::test]
    async fn request_dbus_approval_prompts_standalone_ui_with_typed_target() {
        let store = Arc::new(test_store());
        let (a, b) = UnixStream::pair().expect("unix stream pair");
        let (_, standalone_write) = a.into_split();
        let (mut standalone_read, _) = b.into_split();

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "ui1".into(),
                writer: Arc::new(Mutex::new(standalone_write)),
            });
            inner
                .ui_context_by_session
                .insert("ui1".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-cap".into()),
                    ..Default::default()
                });
        }

        let target = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );

        let store_for_task = store.clone();
        let target_for_task = target.clone();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::from_wire(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
            ),
            ids: ProcessIds::from_options(None, Some(1000)),
            sandbox_session_id: Some("sandbox-cap".into()),
            package: None,
        };
        let ctx_for_task = ctx.clone();

        let task = tokio::spawn(async move {
            store_for_task
                .request_dbus_approval(target_for_task, ctx_for_task)
                .await
        });

        let mut buf = [0u8; 4096];

        let n = tokio::time::timeout(Duration::from_millis(200), standalone_read.read(&mut buf))
            .await
            .expect("standalone UI should receive D-Bus prompt within 200ms")
            .expect("read should succeed");

        let received = String::from_utf8_lossy(&buf[..n]);

        assert!(
            received.contains("dbus:") && received.contains("org.example.Service"),
            "expected pending id and typed D-Bus target in prompt, got: {received}"
        );

        assert!(
            !received.contains("@dbus:"),
            "no fake resource path may appear in the D-Bus prompt, got: {received}"
        );

        let pending_id = {
            let inner = store.inner.lock().await;
            inner
                .pending
                .pending
                .keys()
                .find(|k| k.starts_with("dbus:"))
                .cloned()
                .expect("pending D-Bus request should be tracked")
        };

        store
            .finish_prompt::<DbusApproval>(
                &pending_id,
                ContextKey::new(&ctx, target.clone()),
                Verdict::allowed(VerdictSource::policy_with_comment("test")),
            )
            .await;

        let reply = task.await.expect("task should not panic");

        assert!(
            reply.verdict.allowed,
            "expected allowed reply, got: {reply:?}"
        );

        assert_eq!(
            reply.verdict.source,
            VerdictSource::policy_with_comment("test")
        );

        assert_eq!(reply.target, target);
        let inner = store.inner.lock().await;

        assert!(
            inner
                .dbus_verdict_cache
                .contains_key(&ContextKey::new(&ctx, target.clone())),
            "approved D-Bus target should be cached under the typed key"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn cached_dbus_verdict_answers_without_freezing_the_sandbox() {
        let store = test_store();

        let target = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );

        // No process has this pid, so a freeze attempt would fail.
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::default(),
            ids: ProcessIds::from_options(Some(u32::MAX), None),
            sandbox_session_id: None,
            package: None,
        };

        record_verdict(
            &mut store.inner.lock().await.dbus_verdict_cache,
            ContextKey::new(&ctx, target.clone()),
            Verdict::allowed(VerdictSource::policy()),
        );

        let reply = store.check_dbus(target, ctx).await;

        assert!(reply.verdict.allowed, "got: {reply:?}");
    }
}
