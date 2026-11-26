//! Secret Service (`org.freedesktop.secrets`) policy evaluation, interactive
//! approval, scope persistence, and package identity resolution.

use std::{collections::HashMap, path::Path, time::Duration};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, ResolvedRequestContext, RpcReply, SandboxPackageReply,
    ScopeActionReply, SecretCheckReply, SecretRequest, SecretTarget, Verdict, VerdictSource,
};
use tokio::sync::oneshot;

use super::{
    PolicyStore,
    decision_context::ContextKey,
    decisions::DecisionAction,
    pending::{ApprovalKind, Decision, PromptKind},
    scope_apply::{NoEffects, ScopeLadder},
    state::{PendingBoard, PolicyDecisionState, SessionState},
    types::{Pending, PendingSecret, SecretVerdictCacheKey, VerdictEntry},
    util::ScopeAudit,
};
use crate::{error::PolicydError, wire::ScopeWire};

impl PolicyStore {
    /// Return the authoritative package registered for the resolved sandbox
    /// instance context.
    #[must_use]
    pub fn resolve_sandbox_package(&self, ctx: &ResolvedRequestContext) -> SandboxPackageReply {
        SandboxPackageReply::ok(ctx.package.clone())
    }

    /// Evaluate a runtime Secret Service request against merged policy layers
    /// and session buckets, then route undecided requests through interactive
    /// approval.
    ///
    /// Deny rules always take precedence over allow rules. When a prompt is
    /// needed, the caller's cgroup is frozen only until the verdict is ready
    /// and thawed before the reply is returned so host keyring unlock or
    /// create dialogs triggered after forwarding never deadlock a frozen
    /// sandbox. A reply served from the verdict cache never freezes.
    pub async fn check_secret(
        &self,
        request: SecretRequest,
        ctx: ResolvedRequestContext,
    ) -> SecretCheckReply {
        if let Some(verdict) = self.secret_decided_verdict(&request, &ctx).await {
            return SecretCheckReply::from_verdict(verdict, request);
        }

        if !self.args.interactive_approval {
            return SecretCheckReply::blocked(
                "agent-sandbox: secret access not allowed by policy",
                request,
            );
        }

        if ctx.ids.pid().is_none() {
            return SecretCheckReply::blocked(
                "agent-sandbox: cannot identify sandbox process for secret approval",
                request,
            );
        }

        self.request_secret_approval(request, ctx).await
    }

    /// Verdict the merged file policy layers give a runtime secret request, or
    /// `None` when undecided. Denies win over allows.
    pub(crate) fn secret_verdict(
        &self,
        request: &SecretRequest,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let merged = self.merged_for(ctx);
        let attributed_package = ctx.package.is_some();

        if merged
            .secrets
            .deny
            .iter()
            .any(|rule| rule.target.validate().is_ok() && rule.matches(request, attributed_package))
        {
            return Some(Verdict::denied(VerdictSource::policy()));
        }

        merged
            .secrets
            .allow
            .iter()
            .find(|rule| {
                rule.target.validate_for_allow().is_ok()
                    && rule.matches(request, attributed_package)
            })
            .map(|rule| match rule.comment.as_deref() {
                Some(comment) if !comment.is_empty() => {
                    Verdict::allowed(VerdictSource::policy_with_comment(comment))
                }
                _ => Verdict::allowed(VerdictSource::policy()),
            })
    }

    /// Route an undecided secret request through the interactive approval
    /// pipeline.
    pub async fn request_secret_approval(
        &self,
        request: SecretRequest,
        ctx: ResolvedRequestContext,
    ) -> SecretCheckReply {
        if !self.args.interactive_approval {
            return SecretCheckReply::denied(VerdictSource::Blocked, request);
        }

        let key = SecretVerdictCacheKey {
            request,
            package: ctx.package.clone(),
        };

        if let Some(reply) = self.cached_reply::<SecretApproval>(&key, &ctx).await {
            return reply;
        }

        self.prompt::<SecretApproval>(key, &ctx).await
    }

    pub(crate) async fn apply_secret_scope(
        &self,
        target: SecretTarget,
        scope: ApprovalScope,
        wire: ScopeWire,
        action: DecisionAction,
    ) -> RpcReply {
        let ScopeWire {
            paths,
            session_id,
            owner_uid,
            sandbox_session_id: _,
            comment,
            package,
        } = wire;

        let scope_label = comment.as_deref().unwrap_or_else(|| scope.as_str());

        let mut persist = |policy_path: &Path, home: Option<&Path>| -> std::io::Result<()> {
            Self::persist_secret_rule(
                policy_path,
                &target,
                scope_label,
                action == DecisionAction::Approve,
                home,
                owner_uid,
            )
        };

        let applied = self
            .apply_scope_ladder(
                ScopeLadder {
                    action,
                    key: &target,
                    bucket: SessionState::secret_buckets,
                    effects: NoEffects,
                    scope,
                    session_id: session_id.as_deref(),
                    package: package.as_deref(),
                    paths: &paths,
                    project_log: Some("project secret policy saved"),
                    project_package_log: Some("project package secret policy saved"),
                },
                &mut persist,
            )
            .await;

        let policy_path = match applied {
            Ok(applied) => applied.policy_path,
            Err(err) => return err.into(),
        };

        self.record_scope_applied(&paths, action, ScopeAudit {
            host: None,
            port: None,
            detail: &format!("secret target={target:?} scope={scope_label}"),
        });

        RpcReply::ScopeAction(ScopeActionReply::ok_secret(target, scope, policy_path))
    }
}

/// The secret kind of pending approval.
pub(super) struct SecretApproval;

impl ApprovalKind for SecretApproval {
    type Key = SecretVerdictCacheKey;
    type Pending = PendingSecret;
    type Target = SecretTarget;

    const FAILED_APPROVAL_BLOCKS: bool = false;

    fn into_pending(pending: PendingSecret) -> Pending {
        Pending::Secret(pending)
    }

    fn id(pending: &PendingSecret) -> &str {
        &pending.id
    }

    fn ctx(pending: &PendingSecret) -> &ResolvedRequestContext {
        &pending.ctx
    }

    fn key(pending: &PendingSecret) -> SecretVerdictCacheKey {
        SecretVerdictCacheKey {
            request: pending.request.clone(),
            package: pending.ctx.package.clone(),
        }
    }

    async fn decided_verdict(store: &PolicyStore, pending: &PendingSecret) -> Option<Verdict> {
        store
            .secret_decided_verdict(&pending.request, &pending.ctx)
            .await
    }

    async fn finish(
        store: &PolicyStore,
        pending_id: &str,
        key: ContextKey<SecretVerdictCacheKey>,
        verdict: Verdict,
    ) {
        store.finish_prompt::<Self>(pending_id, key, verdict).await;
    }

    fn approval_target(
        pending: &PendingSecret,
        decision: &Decision,
    ) -> Result<SecretTarget, PolicydError> {
        let target = match &decision.target {
            None => SecretTarget::exact_for_request(&pending.request),
            Some(ApprovalTarget::Secret { target }) => target.clone(),
            Some(_) => return Err(PolicydError::InvalidDecisionTarget),
        };

        let well_formed = if decision.action == DecisionAction::Approve {
            target.validate_for_allow().is_ok()
        } else {
            target.validate().is_ok()
        };

        if target.partition == pending.request.partition
            && well_formed
            && target.matches(&pending.request, pending.ctx.package.is_some())
        {
            Ok(target)
        } else {
            Err(PolicydError::InvalidDecisionTarget)
        }
    }

    // The waiters asked for the pending request, whatever broader target the
    // decision names.
    fn decided_key(pending: &PendingSecret, _target: &SecretTarget) -> SecretVerdictCacheKey {
        Self::key(pending)
    }

    fn once_reply(_pending: &PendingSecret, target: SecretTarget) -> ScopeActionReply {
        ScopeActionReply::ok_secret(target, ApprovalScope::Once, None)
    }

    async fn apply_scope(
        store: &PolicyStore,
        pending: &PendingSecret,
        target: SecretTarget,
        decision: Decision,
    ) -> RpcReply {
        let wire = PolicyStore::scope_wire_for_context(decision.wire, &pending.ctx);

        store
            .apply_secret_scope(target, decision.scope, wire, decision.action)
            .await
    }
}

impl PromptKind for SecretApproval {
    type Reply = SecretCheckReply;

    const APPROVAL_NAME: &'static str = "secret";
    const ID_PREFIX: &'static str = "secret";
    const NO_UI: &'static str =
        "agent-sandbox: no standalone policy UI registered (agent-sandbox-ui or auto-spawn)";
    const TIMED_OUT: &'static str =
        "agent-sandbox: secret approval timed out (no response from policy UI)";
    const TOO_MANY_WAITERS: &'static str =
        "agent-sandbox: too many waiters for one secret approval";
    const VERDICT_TTL: Duration = Duration::from_secs(2);

    fn waiters(
        board: &mut PendingBoard,
    ) -> &mut HashMap<String, Vec<oneshot::Sender<SecretCheckReply>>> {
        &mut board.secret_futures
    }

    fn verdict_cache(
        state: &mut PolicyDecisionState,
    ) -> &mut HashMap<ContextKey<SecretVerdictCacheKey>, VerdictEntry> {
        &mut state.secret_verdict_cache
    }

    fn same_prompt(
        pending: &Pending,
        key: &SecretVerdictCacheKey,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        matches!(
            pending,
            Pending::Secret(secret)
                if secret.request == key.request
                    && secret.ctx.sandbox_session_id == ctx.sandbox_session_id
                    && secret.ctx.package == ctx.package
        )
    }

    fn new_pending(
        id: String,
        created_at: f64,
        key: &SecretVerdictCacheKey,
        ctx: &ResolvedRequestContext,
    ) -> Pending {
        Pending::Secret(PendingSecret {
            id,
            created_at,
            request: key.request.clone(),
            ctx: ctx.clone(),
        })
    }

    fn reply(key: &SecretVerdictCacheKey, verdict: Verdict) -> SecretCheckReply {
        SecretCheckReply::from_verdict(verdict, key.request.clone())
    }

    fn blocked(key: &SecretVerdictCacheKey, message: &str) -> SecretCheckReply {
        SecretCheckReply::blocked(message, key.request.clone())
    }
}
