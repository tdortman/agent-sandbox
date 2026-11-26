//! Policy store: resource gate (declarative approval flow).

use std::{collections::HashMap, path::PathBuf, time::Duration};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, ResolvedRequestContext, ResourceAccess, ResourceCheckReply,
    ResourceKind, ResourceRule, ResourceRuleKey, RpcReply, ScopeActionReply, SocketAccess, Verdict,
    VerdictSource,
};
use tokio::sync::oneshot;

use super::{
    decision_context::ContextKey,
    decisions::DecisionAction,
    pending::{ApprovalKind, Decision, PromptKind},
    state::{PendingBoard, PolicyDecisionState},
    types::{Pending, PendingResource, PolicyStore, VerdictEntry},
};
use crate::{error::PolicydError, wire::ResourceScopeOp};

impl PolicyStore {
    /// Evaluate a resource access request, returning an immediate verdict
    /// when declarative rules or the verdict cache decide it, otherwise
    /// routing it through interactive approval.
    pub async fn check_resource(
        &self,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        ctx: ResolvedRequestContext,
    ) -> ResourceCheckReply {
        if let Some(verdict) = self.resource_allow_source(kind, &path, access, &ctx).await {
            return ResourceCheckReply::from_verdict(verdict, kind, path.clone(), access);
        }

        self.request_resource_approval(kind, path, access, ctx)
            .await
    }

    /// Request interactive approval for a resource access, prompting the
    /// policy UI if needed and waiting for the verdict.
    pub async fn request_resource_approval(
        &self,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        ctx: ResolvedRequestContext,
    ) -> ResourceCheckReply {
        if self.resource_policy_denied(kind, &path, access, &ctx).await {
            return ResourceCheckReply::denied(VerdictSource::policy(), kind, path, access);
        }

        if !self.args.interactive_approval {
            return ResourceCheckReply::denied(VerdictSource::Blocked, kind, path, access);
        }

        let key = ResourceRuleKey { kind, path, access };

        if let Some(reply) = self.cached_reply::<ResourceApproval>(&key, &ctx).await {
            return reply;
        }

        self.prompt::<ResourceApproval>(key, &ctx).await
    }
}

/// The resource kind of pending approval.
pub(super) struct ResourceApproval;

impl ApprovalKind for ResourceApproval {
    type Key = ResourceRuleKey;
    type Pending = PendingResource;
    type Target = PathBuf;

    const FAILED_APPROVAL_BLOCKS: bool = true;

    fn into_pending(pending: PendingResource) -> Pending {
        Pending::Resource(pending)
    }

    fn id(pending: &PendingResource) -> &str {
        &pending.id
    }

    fn ctx(pending: &PendingResource) -> &ResolvedRequestContext {
        &pending.ctx
    }

    fn key(pending: &PendingResource) -> ResourceRuleKey {
        ResourceRuleKey {
            kind: pending.kind,
            path: pending.path.clone(),
            access: pending.access,
        }
    }

    async fn decided_verdict(store: &PolicyStore, pending: &PendingResource) -> Option<Verdict> {
        store
            .resource_allow_source(pending.kind, &pending.path, pending.access, &pending.ctx)
            .await
    }

    async fn finish(
        store: &PolicyStore,
        pending_id: &str,
        key: ContextKey<ResourceRuleKey>,
        verdict: Verdict,
    ) {
        store.finish_prompt::<Self>(pending_id, key, verdict).await;
    }

    fn approval_target(
        pending: &PendingResource,
        decision: &Decision,
    ) -> Result<PathBuf, PolicydError> {
        let path = match &decision.target {
            None => pending.path.clone(),
            Some(ApprovalTarget::ResourcePath {
                resource_kind,
                path,
            }) if *resource_kind == pending.kind => path.clone(),
            Some(_) => return Err(PolicydError::InvalidDecisionTarget),
        };

        if path == pending.path {
            return Ok(path);
        }

        // A once decision covers exactly the requested path.
        if decision.scope == ApprovalScope::Once {
            return Err(PolicydError::InvalidDecisionTarget);
        }

        // Broader scopes also accept an ancestor of the requested path.
        let project_root = decision
            .wire
            .paths
            .project_root()
            .or_else(|| pending.ctx.paths.project_root());

        let rule = ResourceRule::new(
            pending.kind,
            path,
            ResourceAccess::Socket(SocketAccess::Connect),
            "",
        );

        if rule.path_matches(&pending.path, project_root) {
            return Ok(rule.path);
        }

        Err(PolicydError::InvalidDecisionTarget)
    }

    fn audit_once(pending: &PendingResource, target: &PathBuf, action: DecisionAction) {
        let detail = if action == DecisionAction::Approve {
            format!(
                "id={} kind={:?} path={} access={:?}",
                pending.id,
                pending.kind,
                target.display(),
                pending.access
            )
        } else {
            format!(
                "id={} kind={:?} path={}",
                pending.id,
                pending.kind,
                target.display()
            )
        };

        PolicyStore::audit(action.audit_verb(), None, None, &detail);
    }

    fn decided_key(pending: &PendingResource, target: &PathBuf) -> ResourceRuleKey {
        ResourceRuleKey {
            kind: pending.kind,
            path: target.clone(),
            access: pending.access,
        }
    }

    fn once_reply(pending: &PendingResource, target: PathBuf) -> ScopeActionReply {
        ScopeActionReply::ok_resource(
            pending.kind,
            target,
            pending.access,
            ApprovalScope::Once,
            None,
        )
    }

    async fn apply_scope(
        store: &PolicyStore,
        pending: &PendingResource,
        target: PathBuf,
        decision: Decision,
    ) -> RpcReply {
        let wire = store
            .session_scope_wire(decision.wire, &pending.ctx, decision.scope)
            .await;

        store
            .apply_resource_scope(
                ResourceScopeOp {
                    kind: pending.kind,
                    path: target,
                    access: pending.access,
                    scope: decision.scope,
                    wire,
                },
                decision.action,
            )
            .await
    }
}

impl PromptKind for ResourceApproval {
    type Reply = ResourceCheckReply;

    const APPROVAL_NAME: &'static str = "resource";
    const ID_PREFIX: &'static str = "res";
    const NO_UI: &'static str = "agent-sandbox: no standalone resource policy UI registered \
                                 (agent-sandbox-ui or auto-spawn)";
    const TIMED_OUT: &'static str =
        "agent-sandbox: resource approval timed out (no response from policy UI)";
    const TOO_MANY_WAITERS: &'static str =
        "agent-sandbox: too many waiters for one resource approval";
    const VERDICT_TTL: Duration = Duration::from_secs(2);

    fn waiters(
        board: &mut PendingBoard,
    ) -> &mut HashMap<String, Vec<oneshot::Sender<ResourceCheckReply>>> {
        &mut board.resource_futures
    }

    fn verdict_cache(
        state: &mut PolicyDecisionState,
    ) -> &mut HashMap<ContextKey<ResourceRuleKey>, VerdictEntry> {
        &mut state.resource_verdict_cache
    }

    // The sandbox session is part of the prompt's identity, so one sandbox's
    // stale pending is not reused for another's request to the same socket.
    fn same_prompt(pending: &Pending, key: &ResourceRuleKey, ctx: &ResolvedRequestContext) -> bool {
        matches!(
            pending,
            Pending::Resource(res)
                if res.kind == key.kind
                    && res.path == key.path
                    && res.access == key.access
                    && res.ctx.sandbox_session_id == ctx.sandbox_session_id
        )
    }

    fn new_pending(
        id: String,
        created_at: f64,
        key: &ResourceRuleKey,
        ctx: &ResolvedRequestContext,
    ) -> Pending {
        Pending::Resource(PendingResource {
            id,
            created_at,
            kind: key.kind,
            path: key.path.clone(),
            access: key.access,
            ctx: ctx.clone(),
        })
    }

    fn reply(key: &ResourceRuleKey, verdict: Verdict) -> ResourceCheckReply {
        ResourceCheckReply::from_verdict(verdict, key.kind, key.path.clone(), key.access)
    }

    fn blocked(key: &ResourceRuleKey, message: &str) -> ResourceCheckReply {
        ResourceCheckReply::blocked(message, key.kind, key.path.clone(), key.access)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };

    use agent_sandbox_core::{
        ProcessIds, ResolvedRequestContext, ResourceAccess, ResourceKind, ResourceRuleKey,
        SandboxPaths, SocketAccess, Verdict, VerdictSource,
    };
    use tokio::{io::AsyncReadExt, net::UnixStream, sync::Mutex};

    use super::ResourceApproval;
    use crate::store::{
        UiSessionContext, decision_context::ContextKey, test_store, types::UiClient,
    };

    fn resource_ctx() -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(
                Some("/repo".into()),
                Some("/home/user".into()),
                Some("/repo".into()),
            ),
            ids: ProcessIds::from_options(Some(0), Some(1000)),
            sandbox_session_id: Some("sandbox-cap".into()),
            package: None,
        }
    }

    #[tokio::test]
    async fn request_resource_approval_prompts_already_registered_standalone_immediately() {
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

        let store_for_task = store.clone();

        let task = tokio::spawn(async move {
            store_for_task
                .request_resource_approval(
                    ResourceKind::UnixSocket,
                    PathBuf::from("/repo/fast.sock"),
                    ResourceAccess::Socket(SocketAccess::Connect),
                    resource_ctx(),
                )
                .await
        });

        let mut buf = [0u8; 4096];

        let n = tokio::time::timeout(Duration::from_millis(200), standalone_read.read(&mut buf))
            .await
            .expect("standalone UI should receive resource prompt within 200ms")
            .expect("read should succeed");

        let received = String::from_utf8_lossy(&buf[..n]);

        assert!(
            received.contains("res:") && received.contains("/repo/fast.sock"),
            "expected pending id and resource path in prompt, got: {received}"
        );

        let pending_id = {
            let inner = store.inner.lock().await;
            inner
                .pending
                .pending
                .keys()
                .find(|k| k.starts_with("res:"))
                .cloned()
                .expect("pending resource request should be tracked")
        };

        store
            .finish_prompt::<ResourceApproval>(
                &pending_id,
                ContextKey::new(&resource_ctx(), ResourceRuleKey {
                    kind: ResourceKind::UnixSocket,
                    path: PathBuf::from("/repo/fast.sock"),
                    access: ResourceAccess::Socket(SocketAccess::Connect),
                }),
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
    }

    #[tokio::test]
    async fn cli_approval_during_ui_wait_unblocks_resource_promptly() {
        let store = Arc::new(test_store());
        let store_for_task = store.clone();

        let task = tokio::spawn(async move {
            store_for_task
                .request_resource_approval(
                    ResourceKind::UnixSocket,
                    PathBuf::from("/repo/slow.sock"),
                    ResourceAccess::Socket(SocketAccess::Connect),
                    resource_ctx(),
                )
                .await
        });

        let pending_id = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let inner = store.inner.lock().await;
                if let Some(id) = inner
                    .pending
                    .pending
                    .keys()
                    .find(|k| k.starts_with("res:"))
                    .cloned()
                {
                    break id;
                }
                assert!(
                    Instant::now() < deadline,
                    "request never registered a pending"
                );
                drop(inner);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        store
            .finish_prompt::<ResourceApproval>(
                &pending_id,
                ContextKey::new(&resource_ctx(), ResourceRuleKey {
                    kind: ResourceKind::UnixSocket,
                    path: PathBuf::from("/repo/slow.sock"),
                    access: ResourceAccess::Socket(SocketAccess::Connect),
                }),
                Verdict::allowed(VerdictSource::policy_with_comment("cli")),
            )
            .await;

        let reply = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("request should unblock within 2s of the CLI approval")
            .expect("task should not panic");

        assert!(
            reply.verdict.allowed,
            "expected allowed reply, got: {reply:?}"
        );

        assert_eq!(
            reply.verdict.source,
            VerdictSource::policy_with_comment("cli")
        );
    }

    #[tokio::test]
    async fn resource_pending_dedup_is_scoped_to_the_sandbox_session() {
        fn pending_ctx(session: &str) -> ResolvedRequestContext {
            ResolvedRequestContext {
                paths: SandboxPaths::from_wire(
                    Some("/repo".into()),
                    Some("/home/user".into()),
                    Some("/repo".into()),
                ),
                ids: ProcessIds::default(),
                sandbox_session_id: Some(session.into()),
                package: None,
            }
        }

        let store = Arc::new(test_store());

        let tasks: Vec<_> = ["sandbox-a", "sandbox-b", "sandbox-a"]
            .into_iter()
            .map(|session| {
                let store = store.clone();

                tokio::spawn(async move {
                    store
                        .request_resource_approval(
                            ResourceKind::UnixSocket,
                            PathBuf::from("/repo/shared.sock"),
                            ResourceAccess::Socket(SocketAccess::Connect),
                            pending_ctx(session),
                        )
                        .await
                })
            })
            .collect();

        let deadline = Instant::now() + Duration::from_secs(2);

        let prompts = loop {
            let inner = store.inner.lock().await;
            let waiting: usize = inner.pending.resource_futures.values().map(Vec::len).sum();

            if waiting == tasks.len() {
                break inner.pending.pending.len();
            }

            assert!(Instant::now() < deadline, "requests never queued");
            drop(inner);
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        assert_eq!(
            prompts, 2,
            "requests of one sandbox session share a prompt; another session gets its own"
        );

        for task in tasks {
            task.abort();
        }
    }
}
