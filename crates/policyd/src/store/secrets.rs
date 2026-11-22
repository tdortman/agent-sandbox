//! Secret Service (`org.freedesktop.secrets`) policy evaluation, interactive
//! approval, scope persistence, and package identity resolution.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    ApprovalScope, ResolvedRequestContext, RpcReply, SandboxPackageReply, ScopeActionReply,
    SecretCheckReply, SecretRequest, SecretTarget, UiPush, Verdict, VerdictSource,
};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::{
    PolicyStore,
    decisions::DecisionAction,
    scope_apply::{NoEffects, ScopeLadder},
    state::SessionState,
    types::{
        MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, Pending, PendingResult, PendingSecret,
        SecretVerdictCacheKey, VerdictEntry, enforce_verdict_cache_limit,
    },
    ui::VerdictExit,
    util::ScopeAudit,
};
use crate::wire::ScopeWire;

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
    /// Deny rules always take precedence over allow rules. When prompting is
    /// required, the caller's cgroup is frozen only until the verdict is ready
    /// and thawed before returning so host keyring unlock or create dialogs
    /// triggered after forwarding never deadlock a frozen sandbox.
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

        let Some(pid) = ctx.ids.pid() else {
            return SecretCheckReply::blocked(
                "agent-sandbox: cannot identify sandbox process for secret approval",
                request,
            );
        };

        let _freeze_hold = match self.cgroup_freeze.acquire(Some(pid), ctx.ids.uid()) {
            Ok(hold) => hold,
            Err(error) => {
                return SecretCheckReply::blocked(
                    format!("agent-sandbox: cannot freeze sandbox for secret approval: {error}"),
                    request,
                );
            }
        };

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

        if let Some(reply) = self
            .check_secret_verdict_cache(&request, ctx.package.as_deref())
            .await
        {
            return reply;
        }

        let cwd = ctx.paths.cwd_path();
        let home = ctx.paths.home_path();
        let project_root = ctx.paths.project_root_path();
        let sandbox_session_id = ctx.sandbox_session_id.clone();

        let result = match self.dedup_or_create_pending_secret(&request, &ctx).await {
            Ok(result) => result,
            Err(reply) => return *reply,
        };

        if result.is_new {
            let push = UiPush::SecretRequest {
                id: result.id.clone(),
                request: request.clone(),
                cwd: cwd.clone(),
                home: home.clone(),
                project_root: project_root.clone(),
                sandbox_session_id: sandbox_session_id.clone(),
                package: ctx.package.clone(),
            };

            self.notify_general_ui(&ctx, &push).await;

            self.maybe_spawn_ui(
                || self.has_ui_for_context(&ctx),
                ctx.ids.uid(),
                home.as_deref(),
                cwd.as_deref(),
                project_root.as_deref(),
                sandbox_session_id.as_deref(),
            )
            .await;
        }

        self.await_secret_verdict(&ctx, &result.id, request, result.rx)
            .await
    }

    async fn check_secret_verdict_cache(
        &self,
        request: &SecretRequest,
        package: Option<&str>,
    ) -> Option<SecretCheckReply> {
        let key = SecretVerdictCacheKey {
            request: request.clone(),
            package: package.map(str::to_owned),
        };
        let inner = self.inner.lock().await;

        if let Some(entry) = inner.secret_verdict_cache.get(&key)
            && entry.time.elapsed() < Duration::from_secs(2)
        {
            return Some(if entry.allowed {
                SecretCheckReply::allowed(entry.source.clone(), request.clone())
            } else {
                SecretCheckReply::denied(entry.source.clone(), request.clone())
            });
        }

        drop(inner);
        None
    }

    async fn dedup_or_create_pending_secret(
        &self,
        request: &SecretRequest,
        ctx: &ResolvedRequestContext,
    ) -> Result<PendingResult<String, SecretCheckReply>, Box<SecretCheckReply>> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().await;

        let existing_id = inner
            .pending
            .pending
            .values()
            .find_map(|pending| match pending {
                Pending::Secret(secret)
                    if &secret.request == request
                        && secret.ctx.sandbox_session_id == ctx.sandbox_session_id
                        && secret.ctx.package == ctx.package =>
                {
                    Some(secret.id.clone())
                }
                _ => None,
            });

        if let Some(existing_id) = existing_id {
            let waiter_count = inner
                .pending
                .secret_futures
                .get(&existing_id)
                .map_or(0, Vec::len);

            if waiter_count >= MAX_WAITERS_PER_PENDING {
                return Err(Box::new(SecretCheckReply::blocked(
                    "agent-sandbox: too many waiters for one secret approval",
                    request.clone(),
                )));
            }

            inner
                .pending
                .secret_futures
                .entry(existing_id.clone())
                .or_default()
                .push(tx);

            drop(inner);

            return Ok(PendingResult {
                id: existing_id,
                is_new: false,
                rx,
            });
        }

        if inner.pending.pending.len() >= MAX_PENDING_APPROVALS {
            return Err(Box::new(SecretCheckReply::blocked(
                "agent-sandbox: too many pending approvals",
                request.clone(),
            )));
        }

        let pending_id = format!("secret:{}", Uuid::now_v7().simple());

        inner
            .pending
            .secret_futures
            .insert(pending_id.clone(), vec![tx]);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |duration| duration.as_secs_f64());

        let pending = Pending::Secret(PendingSecret {
            id: pending_id.clone(),
            created_at,
            request: request.clone(),
            ctx: ctx.clone(),
        });

        let id = pending.id().to_owned();
        inner.pending.pending.insert(id, pending);
        drop(inner);

        Ok(PendingResult {
            id: pending_id,
            is_new: true,
            rx,
        })
    }

    async fn await_secret_verdict(
        &self,
        ctx: &ResolvedRequestContext,
        pending_id: &str,
        request: SecretRequest,
        rx: oneshot::Receiver<SecretCheckReply>,
    ) -> SecretCheckReply {
        self.wait_for_ui_or_verdict(
            || self.has_ui_for_context(ctx),
            rx,
            None,
            |reason| async move {
                match reason {
                    VerdictExit::NoUi => {
                        let mut inner = self.inner.lock().await;
                        inner.pending.pending.remove(pending_id);
                        inner.pending.secret_futures.remove(pending_id);
                        drop(inner);

                        SecretCheckReply::blocked(
                            "agent-sandbox: no standalone policy UI registered (agent-sandbox-ui \
                             or auto-spawn)",
                            request,
                        )
                    }
                    VerdictExit::ChannelClosed => {
                        SecretCheckReply::denied(VerdictSource::Blocked, request)
                    }
                    VerdictExit::Timeout => {
                        let mut inner = self.inner.lock().await;
                        inner.pending.pending.remove(pending_id);
                        inner.pending.secret_futures.remove(pending_id);
                        drop(inner);

                        SecretCheckReply::blocked(
                            "agent-sandbox: secret approval timed out (no response from policy UI)",
                            request,
                        )
                    }
                    VerdictExit::Cancelled => {
                        unreachable!("no cancel channel wired for secret waits")
                    }
                }
            },
        )
        .await
    }

    pub(crate) async fn finish_secret(
        &self,
        pending_id: &str,
        request: SecretRequest,
        package: Option<String>,
        allowed: bool,
        source: VerdictSource,
    ) {
        let mut inner = self.inner.lock().await;

        if let Some(waiters) = inner.pending.secret_futures.remove(pending_id) {
            let reply = if allowed {
                SecretCheckReply::allowed(source.clone(), request.clone())
            } else {
                SecretCheckReply::denied(source.clone(), request.clone())
            };

            for tx in waiters {
                let _ = tx.send(reply.clone());
            }
        }

        inner.secret_verdict_cache.insert(
            SecretVerdictCacheKey { request, package },
            VerdictEntry {
                allowed,
                source,
                time: Instant::now(),
            },
        );

        enforce_verdict_cache_limit(&mut inner.secret_verdict_cache);
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
