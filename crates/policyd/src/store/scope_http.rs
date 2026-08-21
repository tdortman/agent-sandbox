//! Typed HTTP session/project/global scope mutations.

use std::path::Path;

use agent_sandbox_core::{
    ApprovalScope, HttpContextKey, HttpMethod, HttpMethodMatcher, HttpRequest, HttpRuleTarget,
    ProcessIds, ResolvedRequestContext, SandboxPaths, ScopeActionReply, ScopeTarget, VerdictSource,
};

use super::{
    decisions::DecisionAction,
    http::{http_context, target_for_request},
    scope_apply::{ScopeApplyError, ScopeLadder, ScopePersistFlags},
    types::{HttpPendingKey, Pending, PendingHttp, PolicyStore},
};
use crate::{error::PolicydError, wire::ScopeWire};

fn context_for_pending(pending: &PendingHttp, ids: ProcessIds) -> ResolvedRequestContext {
    ResolvedRequestContext::new(
        SandboxPaths::new(
            pending.context.cwd.clone().unwrap_or_default(),
            pending.context.home.clone().unwrap_or_default(),
            pending.context.project_root.clone().unwrap_or_default(),
        ),
        ids,
        pending.context.sandbox_session_id.clone(),
    )
}

fn target_methods(target: &HttpRuleTarget) -> Result<Vec<HttpMethod>, PolicydError> {
    match &target.method {
        HttpMethodMatcher::Exact(method) => Ok(vec![method.clone()]),
        HttpMethodMatcher::AnyOf(methods) if !methods.is_empty() => Ok(methods.clone()),

        HttpMethodMatcher::AnyOf(_) | HttpMethodMatcher::All => {
            Err(PolicydError::InvalidDecisionTarget)
        }
    }
}

fn build_once_keys(
    target: &HttpRuleTarget,
    context: &HttpContextKey,
) -> Result<Vec<HttpPendingKey>, PolicydError> {
    Ok(target_methods(target)?
        .into_iter()
        .map(|method| HttpPendingKey {
            request: HttpRequest {
                method,
                url: target.url.clone(),
                session: None,
            },
            context: context.clone(),
        })
        .collect())
}

fn apply_http_memory_locked(
    inner: &mut super::types::PolicyDecisionState,
    target: &HttpRuleTarget,
    scope_target: &ScopeTarget,
    context: &HttpContextKey,
    allowed: bool,
) -> Result<(), PolicydError> {
    match scope_target {
        ScopeTarget::Ephemeral => {
            for key in build_once_keys(target, context)? {
                if allowed {
                    inner.session.http_once_deny.remove(&key);
                    inner.session.http_once_allow.insert(key);
                } else {
                    inner.session.http_once_allow.remove(&key);
                    inner.session.http_once_deny.insert(key);
                }
            }
        }

        ScopeTarget::Session { session_id } => {
            let key = super::types::HttpScopeKey {
                target: target.clone(),
                context: context.clone(),
            };
            let action = if allowed {
                DecisionAction::Approve
            } else {
                DecisionAction::Deny
            };

            inner.session.http().apply(action, session_id, &key);
        }

        ScopeTarget::Project { .. }
        | ScopeTarget::ProjectPackage { .. }
        | ScopeTarget::Global { .. }
        | ScopeTarget::GlobalPackage { .. } => {}
    }

    Ok(())
}

impl PolicyStore {
    /// Apply an HTTP approval requested by the host/UI without a pending ID.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError`] when the scope or target is invalid or
    /// persistence fails.
    pub async fn approve_http(
        &self,
        target: HttpRuleTarget,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: ResolvedRequestContext,
    ) -> Result<ScopeActionReply, PolicydError> {
        self.apply_http_scope(target, scope, session_id, ctx, true)
            .await
    }

    pub(crate) async fn apply_http_scope(
        &self,
        target: HttpRuleTarget,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: ResolvedRequestContext,
        allowed: bool,
    ) -> Result<ScopeActionReply, PolicydError> {
        self.apply_http_scope_with_comment(target, scope, session_id, ctx, allowed, None)
            .await
    }

    async fn apply_http_scope_with_comment(
        &self,
        target: HttpRuleTarget,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: ResolvedRequestContext,
        allowed: bool,
        comment: Option<&str>,
    ) -> Result<ScopeActionReply, PolicydError> {
        if scope == ApprovalScope::Once && matches!(target.method, HttpMethodMatcher::All) {
            return Err(PolicydError::InvalidDecisionTarget);
        }

        let context = http_context(&ctx);
        // HTTP invalidation is broader than the ladder's merged-policy flag:
        // every persistent write also drops the HTTP verdict cache, so this
        // caller clears both caches itself after the ladder's write and the
        // ladder's own invalidation stays off.
        let mut persist = |policy_path: &Path, home: Option<&Path>| -> std::io::Result<()> {
            Self::persist_http_rule(
                policy_path,
                &target,
                comment.unwrap_or_else(|| scope.as_str()),
                allowed,
                home,
                ctx.ids.uid(),
            )
        };

        let applied = self
            .apply_scope_ladder(
                ScopeLadder {
                    scope,
                    session_id: session_id.as_deref(),
                    package: ctx.package.as_deref(),
                    paths: &ctx.paths,
                    flags: ScopePersistFlags::new(false, false),
                    project_log: None,
                    project_package_log: None,
                },
                |inner, scope_target| {
                    Self::clear_http_verdict_cache_locked(inner);
                    apply_http_memory_locked(inner, &target, scope_target, &context, allowed)
                },
                &mut persist,
            )
            .await
            .map_err(|err| match err {
                ScopeApplyError::Resolve(reply) => {
                    PolicydError::Proxy(format!("invalid HTTP scope: {reply:?}"))
                }
                ScopeApplyError::Memory(err) | ScopeApplyError::Persist(err) => err,
            })?;

        let scope_path = match &applied.target {
            ScopeTarget::Global { policy_path, .. }
            | ScopeTarget::GlobalPackage { policy_path, .. }
            | ScopeTarget::Project { policy_path, .. }
            | ScopeTarget::ProjectPackage { policy_path, .. } => Some(policy_path.clone()),
            ScopeTarget::Session { .. } | ScopeTarget::Ephemeral => None,
        };

        if scope_path.is_some() {
            self.merged_cache
                .lock()
                .map(|mut cache| cache.entries.clear())
                .ok();

            let mut inner = self.inner.lock().await;
            Self::clear_http_verdict_cache_locked(&mut inner);
        }

        let pending_ids = {
            let inner = self.inner.lock().await;
            inner
                .pending
                .pending_values()
                .filter_map(|pending| {
                    let Pending::Http(value) = pending else {
                        return None;
                    };

                    (value.context == context && target.matches(&value.request))
                        .then_some(value.pending_id)
                })
                .collect::<Vec<_>>()
        };

        let once = scope == ApprovalScope::Once;

        let source = if allowed {
            VerdictSource::Scope(scope)
        } else {
            VerdictSource::User
        };

        let once_keys = once
            .then(|| build_once_keys(&target, &context))
            .transpose()?
            .unwrap_or_default();

        if once {
            let mut delivered = false;

            for pending_id in pending_ids {
                if self
                    .finish_http(pending_id, allowed, source.clone(), true)
                    .await
                {
                    delivered = true;
                    break;
                }
            }

            if delivered {
                let mut inner = self.inner.lock().await;

                for key in once_keys {
                    inner.session.http_once_allow.remove(&key);
                    inner.session.http_once_deny.remove(&key);
                }
            }
        } else {
            for pending_id in pending_ids {
                self.finish_http(pending_id, allowed, source.clone(), false)
                    .await;
            }
        }

        Ok(ScopeActionReply::ok_http(target, scope, scope_path))
    }

    pub(crate) async fn apply_pending_http(
        &self,
        pending: PendingHttp,
        scope: ApprovalScope,
        target: Option<HttpRuleTarget>,
        wire: ScopeWire,
        allowed: bool,
    ) -> Result<ScopeActionReply, PolicydError> {
        let ids = ProcessIds::from_options(None, wire.owner_uid);
        let mut pending_context = context_for_pending(&pending, ids);

        // The requester's package attribution was recorded on the pending at
        // request time. The approver's wire context (host CLI or dialog) has
        // no session and therefore no package, so the pending's attribution
        // is what scopes the rule.
        pending_context.package = pending.package.clone().or_else(|| wire.package.clone());

        let session_id = wire.session_id;
        let comment = wire.comment.as_deref();

        // A pending approval names no target; the rule applies to the
        // request's own target, like the other pending resource types.
        // An explicit target is honoured for persistent scopes only when it
        // matches the pending request, and is rejected for Once where the
        // rule must stay exact.
        let target = if scope == ApprovalScope::Once {
            if target.is_some() {
                return Err(PolicydError::InvalidDecisionTarget);
            }
            target_for_request(&pending.request)
        } else {
            match target {
                Some(target) if target.matches(&pending.request) => target,
                Some(_) => return Err(PolicydError::InvalidDecisionTarget),
                None => target_for_request(&pending.request),
            }
        };

        {
            let mut inner = self.inner.lock().await;
            inner.pending.insert_pending(Pending::Http(pending.clone()));
        }

        let reply = self
            .apply_http_scope_with_comment(
                target,
                scope,
                session_id,
                pending_context,
                allowed,
                comment,
            )
            .await?;

        // A pending decision can carry a context that has no sandbox session.
        // Direct application above handles the scope state; ensure this exact
        // pending request is resolved even when a broad target did not match
        // the caller's path context exactly.
        if scope == ApprovalScope::Once {
            let source = if allowed {
                VerdictSource::Scope(scope)
            } else {
                VerdictSource::User
            };

            self.finish_http(pending.pending_id, allowed, source, true)
                .await;
        }

        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use agent_sandbox_core::{
        HttpContextKey, HttpMethod, HttpMethodMatcher, HttpRuleTarget, HttpUrl, PendingHttpId,
        ProcessIds, ResolvedRequestContext, SandboxPaths, ScopeActionReply, load_policy,
    };

    use super::*;

    #[test]
    fn pending_http_scope_rebuilds_request_context() {
        let pending_id = PendingHttpId::new();

        let pending = PendingHttp {
            id: pending_id.to_string(),
            pending_id,
            created_at: 0.0,
            request: HttpRequest {
                method: HttpMethod::parse("GET").expect("valid method"),
                url: HttpUrl::parse("https://example.com/").expect("valid URL"),
                session: None,
            },
            context: HttpContextKey {
                cwd: Some(PathBuf::from("/pending/cwd")),
                home: Some(PathBuf::from("/pending/home")),
                project_root: Some(PathBuf::from("/pending/project")),
                sandbox_session_id: Some("pending-session".into()),
            },
            package: None,
        };

        let context = context_for_pending(&pending, ProcessIds::new(42, 1000));

        assert_eq!(
            context.paths.cwd_path(),
            Some(PathBuf::from("/pending/cwd"))
        );

        assert_eq!(
            context.paths.home_path(),
            Some(PathBuf::from("/pending/home"))
        );

        assert_eq!(
            context.paths.project_root_path(),
            Some(PathBuf::from("/pending/project"))
        );

        assert_eq!(context.ids, ProcessIds::new(42, 1000));

        assert_eq!(
            context.sandbox_session_id.as_deref(),
            Some("pending-session")
        );
    }

    #[tokio::test]
    async fn pending_http_scope_uses_pending_context_for_memory_rule() {
        use std::time::Duration;

        let store = PolicyStore::new(crate::store::test_args(
            "/tmp/test.sock".into(),
            "/tmp/test-sandbox.sock".into(),
            "/tmp/declarative.json".into(),
            "/tmp/export.json".into(),
            Duration::from_secs(30),
            true,
        ));

        let pending_id = PendingHttpId::new();

        let pending = PendingHttp {
            id: pending_id.to_string(),
            pending_id,
            created_at: 0.0,
            request: HttpRequest {
                method: HttpMethod::parse("GET").expect("valid method"),
                url: HttpUrl::parse("https://example.com/").expect("valid URL"),
                session: None,
            },
            context: HttpContextKey {
                cwd: Some("/pending/cwd".into()),
                home: Some("/pending/home".into()),
                project_root: Some("/pending/project".into()),
                sandbox_session_id: Some("pending-session".into()),
            },
            package: None,
        };

        let ui_context = ResolvedRequestContext::new(
            SandboxPaths::new("/ui/cwd", "/ui/home", "/ui/project"),
            ProcessIds::new(7, 1000),
            Some("ui-session".into()),
        );

        store
            .apply_pending_http(
                pending.clone(),
                ApprovalScope::Once,
                None,
                ScopeWire::from_resolved(&ui_context, None),
                true,
            )
            .await
            .expect("once approval");

        let (cwd, home, project_root, sandbox_session_id) = {
            let inner = store.inner.lock().await;
            let rule = inner
                .session
                .http_once_allow
                .iter()
                .next()
                .expect("once rule");
            let context = (
                rule.context.cwd.clone(),
                rule.context.home.clone(),
                rule.context.project_root.clone(),
                rule.context.sandbox_session_id.clone(),
            );
            drop(inner);
            context
        };

        assert_eq!(cwd, pending.context.cwd);
        assert_eq!(home, pending.context.home);
        assert_eq!(project_root, pending.context.project_root);
        assert_eq!(sandbox_session_id, pending.context.sandbox_session_id);
    }

    #[tokio::test]
    async fn any_of_once_target_tracks_each_method() {
        let store = PolicyStore::new(crate::store::test_args(
            "/tmp/test.sock".into(),
            "/tmp/test-sandbox.sock".into(),
            "/tmp/declarative.json".into(),
            "/tmp/export.json".into(),
            Duration::from_secs(30),
            true,
        ));

        let url = HttpUrl::parse("https://example.com/").expect("valid URL");

        let target = HttpRuleTarget::new(
            HttpMethodMatcher::AnyOf(vec![
                HttpMethod::parse("GET").expect("valid method"),
                HttpMethod::parse("POST").expect("valid method"),
            ]),
            url,
        )
        .expect("valid target");

        let context = HttpContextKey::default();
        let mut inner = store.inner.lock().await;

        apply_http_memory_locked(&mut inner, &target, &ScopeTarget::Ephemeral, &context, true)
            .expect("store any-of once target");

        assert_eq!(inner.session.http_once_allow.len(), 2);
        drop(inner);
    }

    #[tokio::test]
    async fn global_pending_http_approval_persists_to_pending_home_policy() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let pending_home = dir.path().join("pending-home");
        let pending_cwd = dir.path().join("pending-cwd");
        let pending_project = dir.path().join("pending-project");
        std::fs::create_dir_all(&pending_home).expect("create pending home");
        std::fs::create_dir_all(&pending_cwd).expect("create pending cwd");
        std::fs::create_dir_all(&pending_project).expect("create pending project");
        let policy_path = pending_home.join(".config/agent-sandbox/policy.json");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ));

        let pending_id = PendingHttpId::new();

        let request = HttpRequest {
            method: HttpMethod::parse("GET").expect("valid method"),
            url: HttpUrl::parse("https://api.example.com/v1").expect("valid URL"),
            session: None,
        };

        let pending = PendingHttp {
            id: pending_id.to_string(),
            pending_id,
            created_at: 0.0,
            request: request.clone(),
            context: HttpContextKey {
                cwd: Some(pending_cwd),
                home: Some(pending_home.clone()),
                project_root: Some(pending_project),
                sandbox_session_id: Some("pending-session".into()),
            },
            package: None,
        };

        let ui_context = ResolvedRequestContext::new(
            SandboxPaths::new(
                dir.path().join("ui-cwd"),
                dir.path().join("ui-home"),
                dir.path().join("ui-project"),
            ),
            ProcessIds::new(7, 0),
            Some("ui-session".into()),
        );

        let target = HttpRuleTarget::new(
            HttpMethodMatcher::Exact(request.method.clone()),
            request.url.clone(),
        )
        .expect("valid target");

        let reply = store
            .apply_pending_http(
                pending,
                ApprovalScope::Global,
                Some(target.clone()),
                ScopeWire::from_resolved(&ui_context, None),
                true,
            )
            .await
            .expect("global approval");

        match &reply {
            ScopeActionReply::Http(value) => {
                assert_eq!(value.path.as_deref(), Some(policy_path.as_path()));
            }

            _ => panic!("expected HTTP scope reply"),
        }

        let policy = load_policy(&policy_path, Some(&pending_home), None);

        let found = policy
            .network
            .http
            .allow
            .iter()
            .filter_map(|rule| rule.target().ok())
            .any(|value| value == target && value.matches(&request));

        assert!(found, "global HTTP approval missing from {policy_path:?}");
    }

    #[tokio::test]
    async fn pending_http_approval_without_target_persists_at_package_project_scope() {
        // The CLI "approve" and "deny" commands send no target. policyd must
        // derive the rule from the pending request itself, like the other
        // pending resource types, instead of rejecting the decision.
        let dir = tempfile::tempdir().expect("create tempdir");

        let pending_home = dir.path().join("pending-home");
        let pending_cwd = dir.path().join("pending-cwd");
        let pending_project = dir.path().join("pending-project");
        std::fs::create_dir_all(&pending_home).expect("create pending home");
        std::fs::create_dir_all(&pending_cwd).expect("create pending cwd");
        std::fs::create_dir_all(&pending_project).expect("create pending project");
        let policy_path = pending_project.join(".agent-sandbox/packages/curl.json");

        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ));

        let pending_id = PendingHttpId::new();

        let request = HttpRequest {
            method: HttpMethod::parse("GET").expect("valid method"),
            url: HttpUrl::parse("https://example.com/").expect("valid URL"),
            session: None,
        };

        let pending = PendingHttp {
            id: pending_id.to_string(),
            pending_id,
            created_at: 0.0,
            request: request.clone(),
            context: HttpContextKey {
                cwd: Some(pending_cwd.clone()),
                home: Some(pending_home.clone()),
                project_root: Some(pending_project.clone()),
                sandbox_session_id: Some("pending-session".into()),
            },
            package: Some("curl".into()),
        };

        // The approver (host CLI or dialog) has no session and so resolves
        // with no package; the rule must scope to the pending's attribution.
        let ui_context = ResolvedRequestContext::new(
            SandboxPaths::new(
                dir.path().join("ui-cwd"),
                dir.path().join("ui-home"),
                dir.path().join("ui-project"),
            ),
            ProcessIds::new(7, 0),
            Some("ui-session".into()),
        );

        let reply = store
            .apply_pending_http(
                pending,
                ApprovalScope::ProjectPackage,
                None,
                ScopeWire::from_resolved(&ui_context, None),
                true,
            )
            .await
            .expect("project_package approval without an explicit target");

        match &reply {
            ScopeActionReply::Http(value) => {
                assert_eq!(value.path.as_deref(), Some(policy_path.as_path()));
            }

            _ => panic!("expected HTTP scope reply"),
        }

        let policy = load_policy(&policy_path, Some(&pending_home), None);

        let found = policy
            .network
            .http
            .allow
            .iter()
            .filter_map(|rule| rule.target().ok())
            .any(|value| value.matches(&request));

        assert!(
            found,
            "project_package HTTP approval missing from {policy_path:?}"
        );
    }
    fn direct_target() -> HttpRuleTarget {
        HttpRuleTarget {
            url: HttpUrl::parse("https://example.com/api").expect("valid URL"),
            method: HttpMethodMatcher::Exact(HttpMethod::parse("GET").expect("valid method")),
        }
    }

    #[tokio::test]
    async fn direct_session_scope_applies_to_the_http_bucket() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).expect("create home");
        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ));

        store
            .inner
            .try_lock()
            .expect("the decision state lock is only held by this test")
            .ui_clients
            .insert(1, crate::store::types::UiClient {
                session_id: "sandbox-a".to_string(),
                writer: std::sync::Arc::new(tokio::sync::Mutex::new(
                    tokio::net::UnixStream::pair()
                        .expect("unix stream pair")
                        .0
                        .into_split()
                        .1,
                )),
            });

        let ctx = ResolvedRequestContext::new(
            SandboxPaths::new(&home, &home, &home),
            ProcessIds::default(),
            Some("sandbox-a".into()),
        );

        let reply = store
            .approve_http(
                direct_target(),
                ApprovalScope::Session,
                Some("sandbox-a".into()),
                ctx,
            )
            .await
            .expect("session approval must resolve");

        assert!(
            matches!(reply, ScopeActionReply::Http(_)),
            "the direct approval must return an http scope action reply"
        );

        let inner = store.inner.lock().await;

        assert_eq!(
            inner
                .session
                .http_session_allow
                .get("sandbox-a")
                .map(std::collections::HashSet::len),
            Some(1),
            "the session approval must land in the http session allow bucket"
        );

        drop(inner);
    }

    #[tokio::test]
    async fn direct_global_package_persists_home_extension() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).expect("create home");
        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        ));

        let ctx = ResolvedRequestContext {
            package: Some("omp".into()),
            ..ResolvedRequestContext::new(
                SandboxPaths::new(&home, &home, &home),
                ProcessIds::default(),
                None,
            )
        };

        store
            .approve_http(direct_target(), ApprovalScope::GlobalPackage, None, ctx)
            .await
            .expect("global package approval must resolve");

        let ext = home.join(".config/agent-sandbox/packages/omp.json");

        assert!(
            ext.exists(),
            "the global package approval must persist to the home extension file"
        );
    }
}
