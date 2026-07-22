//! Typed HTTP policy evaluation, pending requests, and cancellation.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_sandbox_core::{
    ApprovalScope, HttpCheckReply, HttpContextKey, HttpMethodMatcher, HttpRequest, HttpRuleTarget,
    PendingHttpId, ResolvedRequestContext, UiPush, Verdict, VerdictSource,
};

use super::types::{
    HttpPendingKey, HttpWaiter, MAX_PENDING_APPROVALS, MAX_WAITERS_PER_PENDING, Pending,
    PendingHttp, PendingResult, PolicyStore, enforce_verdict_cache_limit,
};
use crate::{error::PolicydError, wire::UiSpawnContext};

const HTTP_VERDICT_CACHE_TTL: Duration = Duration::from_secs(30);

pub(super) fn http_context(ctx: &ResolvedRequestContext) -> HttpContextKey {
    HttpContextKey {
        cwd: ctx.paths.cwd_path(),
        home: ctx.paths.home_path(),
        project_root: ctx.paths.project_root_path(),
        sandbox_session_id: ctx.sandbox_session_id.clone(),
    }
}

fn http_key(request: &HttpRequest, ctx: &ResolvedRequestContext) -> HttpPendingKey {
    HttpPendingKey {
        request: request.clone(),
        context: http_context(ctx),
    }
}

fn target_for_request(request: &HttpRequest) -> HttpRuleTarget {
    // A request has already passed core HTTP validation, so constructing the
    // exact matcher cannot fail here.
    HttpRuleTarget::new(
        HttpMethodMatcher::Exact(request.method.clone()),
        request.url.clone(),
    )
    .expect("validated HTTP request must construct an exact target")
}

impl PolicyStore {
    fn http_policy_verdicts(
        &self,
        request: &HttpRequest,
        ctx: &ResolvedRequestContext,
    ) -> (Option<Verdict>, Option<Verdict>) {
        let merged = self.merged_for_worker(ctx);
        let denied = merged.network.http.deny.iter().find_map(|rule| {
            let target = rule.target().ok()?;
            target.matches(request).then(|| {
                rule.comment
                    .as_deref()
                    .map_or_else(VerdictSource::policy, VerdictSource::policy_with_comment)
            })
        });
        let allowed = merged.network.http.allow.iter().find_map(|rule| {
            let target = rule.target().ok()?;
            target.matches(request).then(|| {
                rule.comment
                    .as_deref()
                    .map_or_else(VerdictSource::policy, VerdictSource::policy_with_comment)
            })
        });
        (denied.map(Verdict::denied), allowed.map(Verdict::allowed))
    }

    async fn evaluate_http(
        &self,
        request: &HttpRequest,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        let (policy_deny, policy_allow) = self.http_policy_verdicts(request, ctx);
        if let Some(verdict) = policy_deny {
            return Some(verdict);
        }
        let key = http_key(request, ctx);
        let session_ids = self.session_ids_for_context(ctx).await;
        {
            let mut inner = self.inner.lock().await;
            let denied = session_ids.iter().any(|session_id| {
                inner
                    .http_session_deny
                    .get(session_id)
                    .is_some_and(|rules| {
                        rules.iter().any(|entry| {
                            entry.context == key.context && entry.target.matches(request)
                        })
                    })
            });
            if denied {
                return Some(Verdict::denied(VerdictSource::Scope(
                    ApprovalScope::Session,
                )));
            }
            if inner.http_once_deny.remove(&key) {
                return Some(Verdict::denied(VerdictSource::User));
            }
            if inner.http_once_allow.remove(&key) {
                return Some(Verdict::allowed(VerdictSource::Scope(ApprovalScope::Once)));
            }
            let allowed = session_ids.iter().any(|session_id| {
                inner
                    .http_session_allow
                    .get(session_id)
                    .is_some_and(|rules| {
                        rules.iter().any(|entry| {
                            entry.context == key.context && entry.target.matches(request)
                        })
                    })
            });
            if allowed {
                return Some(Verdict::allowed(VerdictSource::Scope(
                    ApprovalScope::Session,
                )));
            }
            if let Some(entry) = inner.http_verdict_cache.get(&HttpPendingKey {
                request: request.clone(),
                context: key.context.clone(),
            }) && entry.time.elapsed() < HTTP_VERDICT_CACHE_TTL
            {
                return Some(if entry.allowed {
                    Verdict::allowed(entry.source.clone())
                } else {
                    Verdict::denied(entry.source.clone())
                });
            }
        }
        policy_allow
    }

    /// Evaluate one decoded HTTP request and wait for a typed policy verdict.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the request cannot be registered or the
    /// proxy session is invalid.
    pub async fn request_http_approval(
        &self,
        proxy_session: agent_sandbox_core::ProxySessionToken,
        request_id: agent_sandbox_core::ProxyRequestId,
        attribution_token: agent_sandbox_core::AttributionToken,
        request: HttpRequest,
        ctx: ResolvedRequestContext,
    ) -> Result<HttpCheckReply, PolicydError> {
        if let Some(verdict) = self.evaluate_http(&request, &ctx).await {
            return Ok(HttpCheckReply::from_verdict(request, verdict));
        }
        if !self.args.interactive_approval {
            return Ok(HttpCheckReply::blocked(
                "agent-sandbox: HTTP approval is disabled",
            ));
        }
        let Some(pid) = ctx.ids.pid() else {
            return Ok(HttpCheckReply::blocked(
                "agent-sandbox: cannot identify sandbox process for HTTP approval",
            ));
        };
        let _freeze_hold = match self.cgroup_freeze.acquire(Some(pid), ctx.ids.uid()) {
            Ok(hold) => hold,
            Err(error) => {
                return Ok(HttpCheckReply::blocked(format!(
                    "agent-sandbox: cannot freeze sandbox for HTTP approval: {error}",
                )));
            }
        };

        let pending = self
            .dedup_or_create_http(
                proxy_session.clone(),
                request_id,
                attribution_token,
                &request,
                &ctx,
            )
            .await?;
        let pending_id = pending.id;
        let is_new = pending.is_new;
        let rx = pending.rx;
        if is_new {
            let pending = {
                let inner = self.inner.lock().await;
                match inner.pending_get(&pending_id.to_string()) {
                    Some(Pending::Http(value)) => value.clone(),
                    _ => {
                        return Ok(HttpCheckReply::blocked(
                            "agent-sandbox: HTTP pending request disappeared",
                        ));
                    }
                }
            };
            self.notify_general_ui(&ctx, &UiPush::HttpRequest {
                id: pending.pending_id,
                request: pending.request.clone(),
                cwd: pending.context.cwd.clone(),
                home: pending.context.home.clone(),
                project_root: pending.context.project_root.clone(),
                sandbox_session_id: pending.context.sandbox_session_id.clone(),
            })
            .await;
            if !self.has_ui_for_context(&ctx).await {
                let spawn = UiSpawnContext {
                    has_matching_ui: false,
                    uid: ctx.ids.uid(),
                    home: pending.context.home.as_deref(),
                    cwd: pending.context.cwd.as_deref(),
                    project_root: pending.context.project_root.as_deref(),
                    sandbox_session_id: pending.context.sandbox_session_id.as_deref(),
                };
                self.spawn_policy_ui(spawn).await;
            }
        }
        Ok(self
            .await_http_verdict(proxy_session, request_id, &request, &ctx, pending_id, rx)
            .await)
    }

    async fn dedup_or_create_http(
        &self,
        proxy_session: agent_sandbox_core::ProxySessionToken,
        request_id: agent_sandbox_core::ProxyRequestId,
        attribution_token: agent_sandbox_core::AttributionToken,
        request: &HttpRequest,
        ctx: &ResolvedRequestContext,
    ) -> Result<PendingResult<PendingHttpId, HttpCheckReply>, PolicydError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let key = http_key(request, ctx);
        let mut inner = self.inner.lock().await;
        if inner
            .http_waiters
            .contains_key(&(proxy_session.clone(), request_id))
        {
            return Err(PolicydError::Proxy(
                "duplicate in-flight HTTP request ID".into(),
            ));
        }
        let existing = inner.pending_values().find_map(|pending| {
            let Pending::Http(value) = pending else {
                return None;
            };
            (value.request == key.request && value.context == key.context)
                .then_some(value.pending_id)
        });
        let pending_id = if let Some(id) = existing {
            let waiters = inner.http_futures.get(&id).map_or(0, Vec::len);
            if waiters >= MAX_WAITERS_PER_PENDING {
                return Err(PolicydError::Proxy(
                    "too many waiters for one HTTP approval".into(),
                ));
            }
            id
        } else {
            if inner.pending_len() >= MAX_PENDING_APPROVALS {
                return Err(PolicydError::Proxy("too many pending approvals".into()));
            }
            let id = PendingHttpId::new();
            let pending = PendingHttp {
                id: id.to_string(),
                pending_id: id,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0.0, |value| value.as_secs_f64()),
                request: request.clone(),
                context: key.context.clone(),
            };
            inner.insert_pending(Pending::Http(pending));
            inner.http_futures.insert(id, Vec::new());
            id
        };
        inner
            .http_futures
            .entry(pending_id)
            .or_default()
            .push(HttpWaiter {
                request_id,
                proxy_session: proxy_session.clone(),
                attribution_token,
                tx,
            });
        inner
            .http_waiters
            .insert((proxy_session, request_id), pending_id);
        drop(inner);
        Ok(PendingResult {
            id: pending_id,
            is_new: existing.is_none(),
            rx,
        })
    }

    async fn await_http_verdict(
        &self,
        proxy_session: agent_sandbox_core::ProxySessionToken,
        request_id: agent_sandbox_core::ProxyRequestId,
        request: &HttpRequest,
        ctx: &ResolvedRequestContext,
        pending_id: PendingHttpId,
        rx: tokio::sync::oneshot::Receiver<HttpCheckReply>,
    ) -> HttpCheckReply {
        let ui_wait = self.args.approval_timeout.min(Duration::from_mins(1));
        let deadline = Instant::now() + ui_wait;
        tokio::pin!(rx);
        loop {
            if self.has_ui_for_context(ctx).await {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                self.remove_http_waiter(proxy_session, request_id).await;
                return HttpCheckReply::blocked("agent-sandbox: no policy UI registered");
            }
            tokio::select! {
                biased;
                () = tokio::time::sleep((deadline - now).min(Duration::from_millis(50))) => {}
                result = &mut rx => {
                    return result.unwrap_or_else(|_| HttpCheckReply::blocked("agent-sandbox: HTTP approval waiter closed"));
                }
            }
        }
        match tokio::time::timeout(self.args.approval_timeout, &mut rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => HttpCheckReply::blocked("agent-sandbox: HTTP approval waiter closed"),
            Err(_) => {
                self.remove_http_waiter(proxy_session, request_id).await;
                let _ = (request, pending_id);
                HttpCheckReply::blocked("agent-sandbox: HTTP approval timed out")
            }
        }
    }

    /// Cancel exactly one HTTP waiter identified by its proxy session and
    /// request ID.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the proxy session is not active.
    pub async fn cancel_http_check(
        &self,
        proxy_session: agent_sandbox_core::ProxySessionToken,
        request_id: agent_sandbox_core::ProxyRequestId,
    ) -> Result<(), PolicydError> {
        let tx = {
            let mut inner = self.inner.lock().await;
            if inner
                .proxy_session
                .as_ref()
                .is_none_or(|session| session.token != proxy_session)
            {
                return Err(PolicydError::Proxy("proxy session is not active".into()));
            }
            let tx = Self::remove_http_waiter_locked(&mut inner, &proxy_session, request_id);
            drop(inner);
            tx
        };
        if let Some(tx) = tx {
            let _ = tx.send(HttpCheckReply::blocked(
                "agent-sandbox: HTTP check cancelled",
            ));
        }
        Ok(())
    }

    async fn remove_http_waiter(
        &self,
        proxy_session: agent_sandbox_core::ProxySessionToken,
        request_id: agent_sandbox_core::ProxyRequestId,
    ) {
        let tx = {
            let mut inner = self.inner.lock().await;
            Self::remove_http_waiter_locked(&mut inner, &proxy_session, request_id)
        };
        if let Some(tx) = tx {
            let _ = tx.send(HttpCheckReply::blocked(
                "agent-sandbox: HTTP check cancelled",
            ));
        }
    }

    fn remove_http_waiter_locked(
        inner: &mut super::types::PolicyDecisionState,
        proxy_session: &agent_sandbox_core::ProxySessionToken,
        request_id: agent_sandbox_core::ProxyRequestId,
    ) -> Option<tokio::sync::oneshot::Sender<HttpCheckReply>> {
        let pending_id = inner
            .http_waiters
            .remove(&(proxy_session.clone(), request_id))?;
        let waiters = inner.http_futures.get_mut(&pending_id)?;
        let index = waiters.iter().position(|waiter| {
            waiter.proxy_session == *proxy_session && waiter.request_id == request_id
        })?;
        let waiter = waiters.remove(index);
        if waiters.is_empty() {
            inner.http_futures.remove(&pending_id);
            inner.take_pending(&pending_id.to_string());
        }
        Some(waiter.tx)
    }

    fn http_waiter_is_live(inner: &super::types::PolicyDecisionState, waiter: &HttpWaiter) -> bool {
        !waiter.tx.is_closed()
            && inner
                .proxy_session
                .as_ref()
                .is_some_and(|session| session.token == waiter.proxy_session)
            && inner.proxy_flows.values().any(|flow| {
                flow.connection_id.is_some()
                    && flow.attribution_token.as_ref() == Some(&waiter.attribution_token)
            })
    }

    /// Resolve a pending HTTP ID. `once` releases all live waiters already
    /// coalesced.
    pub(crate) async fn finish_http(
        &self,
        pending_id: PendingHttpId,
        allowed: bool,
        source: VerdictSource,
        once: bool,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        let Some(Pending::Http(pending)) = inner.take_pending(&pending_id.to_string()) else {
            return false;
        };
        let waiters = inner.http_futures.remove(&pending_id).unwrap_or_default();
        let mut live_waiters = Vec::with_capacity(waiters.len());
        for waiter in waiters {
            if Self::http_waiter_is_live(&inner, &waiter) {
                live_waiters.push(waiter);
            } else {
                inner
                    .http_waiters
                    .remove(&(waiter.proxy_session.clone(), waiter.request_id));
                let _ = waiter
                    .tx
                    .send(HttpCheckReply::blocked("agent-sandbox: HTTP flow expired"));
            }
        }
        if live_waiters.is_empty() {
            return false;
        }
        let reply = HttpCheckReply::from_verdict(pending.request.clone(), Verdict {
            allowed,
            source: source.clone(),
        });
        for waiter in live_waiters {
            inner
                .http_waiters
                .remove(&(waiter.proxy_session, waiter.request_id));
            let _ = waiter.tx.send(reply.clone());
        }
        if !once {
            inner.http_verdict_cache.insert(
                HttpPendingKey {
                    request: pending.request,
                    context: pending.context,
                },
                super::types::VerdictEntry {
                    allowed,
                    source,
                    time: Instant::now(),
                },
            );
            enforce_verdict_cache_limit(&mut inner.http_verdict_cache);
        }
        drop(inner);
        true
    }

    pub(crate) fn clear_http_verdict_cache_locked(inner: &mut super::types::PolicyDecisionState) {
        inner.http_verdict_cache.clear();
    }

    pub(crate) fn exact_http_target(request: &HttpRequest) -> HttpRuleTarget {
        target_for_request(request)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agent_sandbox_core::{
        ApprovalScope, AttributionToken, FlowContext, FlowProtocol, FlowRegistration, HttpRequest,
        HttpRule, NetworkFlowKey, NormalizedPolicyHost, Policy, ProcessIdentity, ProcessIds,
        ProxyConnectionId, ProxyRequestId, ProxySessionToken, ResolvedRequestContext, SandboxPaths,
        SocketIdentity, SocketInode, Verdict, VerdictSource, atomic_write_policy,
    };

    use super::super::types::{PendingResult, PolicyStore};
    #[tokio::test]
    async fn documented_network_http_rule_allows_without_prompt() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project_root = dir.path().join("project");
        let policy_path = home.join(".config/agent-sandbox/policy.json");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(policy_path.parent().expect("policy parent"))
            .expect("create policy directory");
        std::fs::write(
            &policy_path,
            r#"{
    "network": {
        "direct": { "allow": [], "deny": [] },
        "http": {
            "allow": [{ "methods": ["GET"], "url": "https://api.example.com/v1" }],
            "deny": []
        }
    },
    "sudo": { "allow": [], "deny": [] },
    "filesystem": { "allow": [], "deny": [] },
    "resources": { "allow": [], "deny": [] }
}"#,
        )
        .expect("write global policy");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_mins(1),
            true,
        ));
        let request = HttpRequest::parse_absolute("GET", "https://api.example.com/v1")
            .expect("valid request");
        let home_s = home.to_string_lossy().into_owned();
        let project_s = project_root.to_string_lossy().into_owned();
        let ctx = ResolvedRequestContext::new(
            SandboxPaths::new(&project_s, &home_s, &project_s),
            ProcessIds::default(),
            None,
        );

        let reply = store
            .request_http_approval(
                ProxySessionToken::new(),
                ProxyRequestId::new(),
                AttributionToken::new(),
                request,
                ctx,
            )
            .await
            .expect("policy evaluation");

        assert!(reply.allowed);
        assert_eq!(reply.source, VerdictSource::policy());
        assert!(
            store.pending_summaries().await.is_empty(),
            "policy allow must not prompt"
        );
    }
    #[test]
    fn partial_http_method_deny_preserves_allow_and_narrow_path() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let project_root = dir.path().join("project");
        let policy_path = home.join(".config/agent-sandbox/policy.json");
        std::fs::create_dir_all(policy_path.parent().expect("policy parent"))
            .expect("create policy directory");

        let mut policy = Policy::default();
        policy.network.http.allow.push(HttpRule::new(
            vec!["GET".to_owned()],
            "https://api.example.com/v1",
            "allow GET",
        ));
        policy.network.http.deny.push(HttpRule::new(
            vec!["POST".to_owned()],
            "https://api.example.com/v1/private",
            "deny POST",
        ));
        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_mins(1),
            false,
        ));
        let home_s = home.to_string_lossy().into_owned();
        let project_s = project_root.to_string_lossy().into_owned();
        let ctx = ResolvedRequestContext::new(
            SandboxPaths::new(&project_s, &home_s, &project_s),
            ProcessIds::default(),
            None,
        );
        let get_public = HttpRequest::parse_absolute("GET", "https://api.example.com/v1/public")
            .expect("valid GET request");
        let post_public = HttpRequest::parse_absolute("POST", "https://api.example.com/v1/public")
            .expect("valid POST request");
        let post_private =
            HttpRequest::parse_absolute("POST", "https://api.example.com/v1/private/item")
                .expect("valid POST request");

        let (get_deny, get_allow) = store.http_policy_verdicts(&get_public, &ctx);
        assert!(get_deny.is_none());
        assert_eq!(
            get_allow,
            Some(Verdict::allowed(VerdictSource::policy_with_comment(
                "allow GET"
            )))
        );
        let (post_deny, post_allow) = store.http_policy_verdicts(&post_public, &ctx);
        assert!(post_deny.is_none());
        assert!(post_allow.is_none());
        let (private_deny, _) = store.http_policy_verdicts(&post_private, &ctx);
        assert_eq!(
            private_deny,
            Some(Verdict::denied(VerdictSource::policy_with_comment(
                "deny POST"
            )))
        );
    }
    async fn test_http_store() -> (PolicyStore, ProxySessionToken, AttributionToken) {
        let store = PolicyStore::new(crate::store::test_args(
            "/tmp/http-once-test.sock".into(),
            "/tmp/http-once-test-sandbox.sock".into(),
            "/tmp/http-once-test-declarative.json".into(),
            "/tmp/http-once-test-export.json".into(),
            Duration::from_secs(30),
            true,
        ));
        let proxy_session = store
            .open_proxy_session(1)
            .await
            .expect("open proxy session")
            .proxy_session;
        let owner = SocketIdentity::new(
            ProcessIdentity::new(1, nix::unistd::getuid().as_raw(), 1)
                .expect("valid process identity"),
            SocketInode::new(1).expect("valid socket inode"),
        );
        let flow = NetworkFlowKey::try_new(
            FlowProtocol::Tcp,
            "127.0.0.1".parse().expect("valid source address"),
            12345.try_into().expect("valid source port"),
            "93.184.216.34".parse().expect("valid destination address"),
            443.try_into().expect("valid destination port"),
        )
        .expect("valid flow");
        store
            .register_network_flow(FlowRegistration::new(
                flow.clone(),
                owner,
                NormalizedPolicyHost::parse("example.com").expect("valid policy host"),
                FlowContext::new(SandboxPaths::default(), Some("test-session".into())),
            ))
            .await
            .expect("register flow");
        let attribution_token = store
            .claim_network_flow(proxy_session.clone(), flow, ProxyConnectionId::new())
            .await
            .expect("claim flow")
            .attribution_token;
        (store, proxy_session, attribution_token)
    }

    #[tokio::test]
    async fn http_approval_requires_process_identity_for_freezing() {
        let (store, proxy_session, attribution_token) = test_http_store().await;
        let request =
            HttpRequest::parse_absolute("GET", "https://example.com/resource").expect("request");
        let context = ResolvedRequestContext::new(
            SandboxPaths::default(),
            ProcessIds::default(),
            Some("test-session".into()),
        );

        let reply = store
            .request_http_approval(
                proxy_session,
                ProxyRequestId::new(),
                attribution_token,
                request,
                context,
            )
            .await
            .expect("HTTP approval response");

        assert!(!reply.ok);
        assert_eq!(
            reply.error.as_deref(),
            Some("agent-sandbox: cannot identify sandbox process for HTTP approval")
        );
    }

    #[tokio::test]
    async fn once_http_decision_resolves_all_coalesced_waiters_without_cache() {
        let (store, proxy_session, attribution_token) = test_http_store().await;
        let request =
            HttpRequest::parse_absolute("GET", "https://example.com/resource").expect("request");
        let context = ResolvedRequestContext::new(
            SandboxPaths::default(),
            ProcessIds::default(),
            Some("test-session".into()),
        );
        let request_id_1 = ProxyRequestId::new();
        let request_id_2 = ProxyRequestId::new();
        let (first_result, second_result) = tokio::join!(
            store.dedup_or_create_http(
                proxy_session.clone(),
                request_id_1,
                attribution_token.clone(),
                &request,
                &context,
            ),
            store.dedup_or_create_http(
                proxy_session.clone(),
                request_id_2,
                attribution_token,
                &request,
                &context,
            ),
        );
        let PendingResult {
            id: pending_1,
            is_new: first,
            rx: rx_1,
        } = first_result.expect("first waiter");
        let PendingResult {
            id: pending_2,
            is_new: second,
            rx: rx_2,
        } = second_result.expect("second waiter");
        assert_eq!(pending_1, pending_2);
        assert_ne!(
            first, second,
            "exactly one waiter creates the pending request"
        );
        assert!(first || second);

        assert!(
            store
                .finish_http(
                    pending_1,
                    true,
                    VerdictSource::Scope(ApprovalScope::Once),
                    true,
                )
                .await
        );
        let reply_1 = tokio::time::timeout(Duration::from_secs(1), rx_1)
            .await
            .expect("first waiter reply timed out")
            .expect("first waiter reply");
        let reply_2 = tokio::time::timeout(Duration::from_secs(1), rx_2)
            .await
            .expect("second waiter reply timed out")
            .expect("second waiter reply");
        assert_eq!(reply_1.allowed, reply_2.allowed);
        assert_eq!(reply_1.source, reply_2.source);
        assert_eq!(reply_1.request, reply_2.request);
        assert!(
            store.pending_summaries().await.is_empty(),
            "once must not leave replacement pending"
        );
        let inner = store.inner.lock().await;
        assert!(
            inner.http_futures.is_empty(),
            "once must remove all pending waiter futures"
        );
        assert!(
            inner.http_waiters.is_empty(),
            "once must remove all waiter identities"
        );
        assert!(
            inner.http_verdict_cache.is_empty(),
            "once must not populate the verdict cache"
        );
        drop(inner);
        assert!(
            store.evaluate_http(&request, &context).await.is_none(),
            "once must not grant a later request"
        );
    }
}
