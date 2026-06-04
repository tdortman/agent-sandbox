//! Policy store — access.

use std::collections::HashSet;

use agent_sandbox_core::{SandboxPaths, allow_keys, normalize_host, sudo_argv_matches};

use crate::wire::MergeContext;

use super::types::PolicyStore;

impl PolicyStore {
    pub(crate) async fn once_allowed(&self, host: &str, port: u16, consume: bool) -> bool {
        let keys = allow_keys(host, port);
        let mut inner = self.inner.lock().await;
        let matched = keys.iter().any(|k| inner.once_allow.contains(k));
        if matched && consume {
            for key in keys {
                inner.once_allow.remove(&key);
            }
        }
        matched
    }

    pub(crate) async fn session_allowed(&self, host: &str, port: u16) -> bool {
        let keys = allow_keys(host, port);
        let inner = self.inner.lock().await;
        let active: HashSet<_> = inner.ui_clients.values().map(|c| &c.session_id).collect();
        if active.is_empty() {
            return false;
        }
        for session_id in active {
            if let Some(bucket) = inner.session_allow.get(session_id)
                && keys.iter().any(|k| bucket.contains(k))
            {
                return true;
            }
        }
        false
    }

    pub(crate) async fn session_denied(&self, host: &str, port: u16) -> bool {
        let keys = allow_keys(host, port);
        let inner = self.inner.lock().await;
        let active: HashSet<_> = inner.ui_clients.values().map(|c| &c.session_id).collect();
        if active.is_empty() {
            return false;
        }
        for session_id in active {
            if let Some(bucket) = inner.session_deny.get(session_id)
                && keys.iter().any(|k| bucket.contains(k))
            {
                return true;
            }
        }
        false
    }

    pub(crate) async fn policy_denied(&self, host: &str, port: u16, ctx: MergeContext) -> bool {
        let host = normalize_host(host);
        let merged = self.merged_for(ctx).await;
        merged
            .network
            .deny
            .iter()
            .any(|rule| Self::host_matches(&rule.host, &host) && rule.port == port)
    }

    pub(crate) async fn sudo_policy_denied(&self, argv: &[String], ctx: MergeContext) -> bool {
        let merged = self.merged_for(ctx).await;
        merged
            .sudo
            .deny
            .iter()
            .any(|rule| sudo_argv_matches(rule, argv))
    }

    pub(crate) async fn sudo_policy_allowed(&self, argv: &[String], ctx: MergeContext) -> bool {
        let merged = self.merged_for(ctx).await;
        merged
            .sudo
            .allow
            .iter()
            .any(|rule| sudo_argv_matches(rule, argv))
    }

    pub(crate) async fn session_sudo_denied(&self, argv: &[String]) -> bool {
        let key: Vec<String> = argv.to_vec();
        let active = self.active_session_ids().await;
        let inner = self.inner.lock().await;
        active.iter().any(|sid| {
            inner
                .session_sudo_deny
                .get(sid)
                .is_some_and(|b| b.contains(&key))
        })
    }

    pub(crate) async fn session_sudo_allowed(&self, argv: &[String]) -> bool {
        let key: Vec<String> = argv.to_vec();
        let active = self.active_session_ids().await;
        let inner = self.inner.lock().await;
        active.iter().any(|sid| {
            inner
                .session_sudo_allow
                .get(sid)
                .is_some_and(|b| b.contains(&key))
        })
    }

    pub async fn allow_source(&self, host: &str, port: u16, ctx: MergeContext) -> Option<String> {
        let host = normalize_host(host);
        let (cwd, home, project_root) = self
            .resolve_context(
                ctx.paths.cwd_string(),
                ctx.paths.home_string(),
                ctx.paths.project_root_string(),
                ctx.ids.pid(),
                ctx.ids.uid(),
            )
            .await;
        let resolved = MergeContext {
            paths: SandboxPaths::from_wire(cwd, home, project_root),
            ids: ctx.ids,
        };
        if self.policy_denied(&host, port, resolved.clone()).await {
            return Some("deny".into());
        }
        if self.session_denied(&host, port).await {
            return Some("deny".into());
        }
        if self.once_allowed(&host, port, false).await {
            return Some("once".into());
        }
        if self.session_allowed(&host, port).await {
            return Some("session".into());
        }
        let merged = self.merged_for(resolved).await;
        for rule in &merged.network.allow {
            if Self::host_matches(&rule.host, &host) && rule.port == port {
                if let Some(ref comment) = rule.comment
                    && !comment.is_empty()
                {
                    return Some(format!("allow:{comment}"));
                }
                return Some("allow".into());
            }
        }
        None
    }

    pub async fn is_allowed(
        &self,
        host: &str,
        port: u16,
        ctx: MergeContext,
        consume_once: bool,
    ) -> bool {
        let host = normalize_host(host);
        let (cwd, home, project_root) = self
            .resolve_context(
                ctx.paths.cwd_string(),
                ctx.paths.home_string(),
                ctx.paths.project_root_string(),
                ctx.ids.pid(),
                ctx.ids.uid(),
            )
            .await;
        let resolved = MergeContext {
            paths: SandboxPaths::from_wire(cwd, home, project_root),
            ids: ctx.ids,
        };
        if self.policy_denied(&host, port, resolved.clone()).await {
            return false;
        }
        if self.session_denied(&host, port).await {
            return false;
        }
        if self.once_allowed(&host, port, consume_once).await {
            return true;
        }
        if self.session_allowed(&host, port).await {
            return true;
        }
        let merged = self.merged_for(resolved).await;
        merged
            .network
            .allow
            .iter()
            .any(|rule| Self::host_matches(&rule.host, &host) && rule.port == port)
    }
}
