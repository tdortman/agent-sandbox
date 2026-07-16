//! Typed HTTP session/project/global scope mutations.

use agent_sandbox_core::{
    ApprovalScope, HttpMethodMatcher, HttpRequest, HttpRuleTarget, ProcessIds,
    ResolvedRequestContext, SandboxPaths, ScopeActionReply, ScopeTarget, VerdictSource,
};

use super::http::http_context;
use super::types::{HttpPendingKey, Pending, PendingHttp, PolicyStore};
use crate::error::PolicydError;
use crate::wire::ScopeWire;

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

fn target_methods(
    target: &HttpRuleTarget,
) -> Result<Vec<agent_sandbox_core::HttpMethod>, PolicydError> {
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
    context: &agent_sandbox_core::HttpContextKey,
) -> Result<Vec<HttpPendingKey>, PolicydError> {
    Ok(target_methods(target)?
        .into_iter()
        .map(|method| HttpPendingKey {
            request: HttpRequest {
                method,
                url: target.url.clone(),
            },
            context: context.clone(),
        })
        .collect())
}

fn apply_http_memory_locked(
    inner: &mut super::types::PolicyDecisionState,
    target: &HttpRuleTarget,
    scope_target: &ScopeTarget,
    context: &agent_sandbox_core::HttpContextKey,
    allowed: bool,
) -> Result<(), PolicydError> {
    match scope_target {
        ScopeTarget::Ephemeral => {
            for key in build_once_keys(target, context)? {
                if allowed {
                    inner.http_once_deny.remove(&key);
                    inner.http_once_allow.insert(key);
                } else {
                    inner.http_once_allow.remove(&key);
                    inner.http_once_deny.insert(key);
                }
            }
        }
        ScopeTarget::Session { session_id } => {
            let key = super::types::HttpScopeKey {
                target: target.clone(),
                context: context.clone(),
            };
            if allowed {
                inner
                    .http_session_allow
                    .entry(session_id.clone())
                    .or_default()
                    .insert(key.clone());
                if let Some(bucket) = inner.http_session_deny.get_mut(session_id) {
                    bucket.remove(&key);
                }
            } else {
                inner
                    .http_session_deny
                    .entry(session_id.clone())
                    .or_default()
                    .insert(key.clone());
                if let Some(bucket) = inner.http_session_allow.get_mut(session_id) {
                    bucket.remove(&key);
                }
            }
        }
        ScopeTarget::Project { .. } | ScopeTarget::Global { .. } => {}
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
        ctx: agent_sandbox_core::ResolvedRequestContext,
    ) -> Result<ScopeActionReply, PolicydError> {
        self.apply_http_scope(target, scope, session_id, ctx, true)
            .await
    }

    pub(crate) async fn apply_http_scope(
        &self,
        target: HttpRuleTarget,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: agent_sandbox_core::ResolvedRequestContext,
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
        ctx: agent_sandbox_core::ResolvedRequestContext,
        allowed: bool,
        comment: Option<&str>,
    ) -> Result<ScopeActionReply, PolicydError> {
        if scope == ApprovalScope::Once && matches!(target.method, HttpMethodMatcher::All) {
            return Err(PolicydError::InvalidDecisionTarget);
        }
        let scope_target = self
            .resolve_scope_target(
                scope,
                session_id.as_deref(),
                ctx.paths.home_path().as_deref(),
                ctx.paths.project_root_path().as_deref(),
            )
            .await
            .map_err(|reply| PolicydError::Proxy(format!("invalid HTTP scope: {reply:?}")))?;
        let context = http_context(&ctx);
        let scope_path = match &scope_target {
            ScopeTarget::Global { policy_path, .. } | ScopeTarget::Project { policy_path, .. } => {
                Some(policy_path.clone())
            }
            ScopeTarget::Session { .. } | ScopeTarget::Ephemeral => None,
        };
        {
            let mut inner = self.inner.lock().await;
            Self::clear_http_verdict_cache_locked(&mut inner);
            apply_http_memory_locked(&mut inner, &target, &scope_target, &context, allowed)?;
        }

        let home = ctx.paths.home_path();
        if let Some(policy_path) = &scope_path {
            Self::persist_http_rule(
                policy_path,
                &target,
                comment.unwrap_or_else(|| scope.as_str()),
                allowed,
                home.as_deref(),
                ctx.ids.uid(),
            )?;
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
        let once_keys = once
            .then(|| build_once_keys(&target, &context))
            .transpose()?
            .unwrap_or_default();
        if once {
            let mut delivered = false;
            for pending_id in pending_ids {
                if self
                    .finish_http(pending_id, allowed, VerdictSource::Scope(scope), true)
                    .await
                {
                    delivered = true;
                    break;
                }
            }
            if delivered {
                let mut inner = self.inner.lock().await;
                for key in once_keys {
                    inner.http_once_allow.remove(&key);
                    inner.http_once_deny.remove(&key);
                }
            }
        } else {
            for pending_id in pending_ids {
                self.finish_http(pending_id, allowed, VerdictSource::Scope(scope), false)
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
        let pending_context = context_for_pending(&pending, ids);
        let session_id = wire.session_id;
        let comment = wire.comment.as_deref();
        let target = if scope == ApprovalScope::Once {
            if target.is_some() {
                return Err(PolicydError::InvalidDecisionTarget);
            }
            Self::exact_http_target(&pending.request)
        } else {
            let target = target.ok_or(PolicydError::InvalidDecisionTarget)?;
            if !target.matches(&pending.request) {
                return Err(PolicydError::InvalidDecisionTarget);
            }
            target
        };
        {
            let mut inner = self.inner.lock().await;
            inner.insert_pending(Pending::Http(pending.clone()));
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
            self.finish_http(
                pending.pending_id,
                allowed,
                VerdictSource::Scope(scope),
                true,
            )
            .await;
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use agent_sandbox_core::{
        HttpContextKey, HttpMethod, HttpMethodMatcher, HttpRuleTarget, HttpUrl, PendingHttpId,
        ProcessIds, ResolvedRequestContext, SandboxPaths, load_policy,
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
            },
            context: HttpContextKey {
                cwd: Some(PathBuf::from("/pending/cwd")),
                home: Some(PathBuf::from("/pending/home")),
                project_root: Some(PathBuf::from("/pending/project")),
                sandbox_session_id: Some("pending-session".into()),
            },
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

        use crate::store::types::PolicydArgs;

        let store = PolicyStore::new(PolicydArgs {
            host_socket: "/tmp/test.sock".into(),
            sandbox_socket: "/tmp/test-sandbox.sock".into(),
            declarative: "/tmp/declarative.json".into(),
            export_json: "/tmp/export.json".into(),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        });
        let pending_id = PendingHttpId::new();
        let pending = PendingHttp {
            id: pending_id.to_string(),
            pending_id,
            created_at: 0.0,
            request: HttpRequest {
                method: HttpMethod::parse("GET").expect("valid method"),
                url: HttpUrl::parse("https://example.com/").expect("valid URL"),
            },
            context: HttpContextKey {
                cwd: Some("/pending/cwd".into()),
                home: Some("/pending/home".into()),
                project_root: Some("/pending/project".into()),
                sandbox_session_id: Some("pending-session".into()),
            },
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
            let rule = inner.http_once_allow.iter().next().expect("once rule");
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
        let store = PolicyStore::new(crate::store::types::PolicydArgs {
            host_socket: "/tmp/test.sock".into(),
            sandbox_socket: "/tmp/test-sandbox.sock".into(),
            declarative: "/tmp/declarative.json".into(),
            export_json: "/tmp/export.json".into(),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        });
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
        assert_eq!(inner.http_once_allow.len(), 2);
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

        let store = PolicyStore::new(crate::store::types::PolicydArgs {
            host_socket: dir.path().join("host.sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        });
        let pending_id = PendingHttpId::new();
        let request = HttpRequest {
            method: HttpMethod::parse("GET").expect("valid method"),
            url: HttpUrl::parse("https://api.example.com/v1").expect("valid URL"),
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
            agent_sandbox_core::ScopeActionReply::Http(value) => {
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
}
