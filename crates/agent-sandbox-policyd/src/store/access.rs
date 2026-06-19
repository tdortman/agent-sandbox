//! Policy store — access.

use std::collections::HashSet;

use agent_sandbox_core::{FileAccess, allow_keys, normalize_host};

use crate::store::ui_route::UiRoute;
use crate::wire::MergeContext;

use super::types::PolicyStore;

fn session_network_matches(bucket: &HashSet<(String, u16)>, host: &str, port: u16) -> bool {
    let keys = allow_keys(host, port);
    bucket.iter().any(|(pattern, rule_port)| {
        *rule_port == port
            && keys
                .iter()
                .any(|(key_host, _)| PolicyStore::host_matches(pattern, key_host))
    })
}

fn session_sudo_matches(bucket: &HashSet<Vec<String>>, argv: &[String]) -> bool {
    bucket
        .iter()
        .any(|rule| !rule.is_empty() && argv.starts_with(rule))
}

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

    pub(crate) async fn session_allowed(&self, host: &str, port: u16, ctx: MergeContext) -> bool {
        let resolved = self.resolve_context(ctx).await;
        let route = UiRoute::new(
            resolved.ids.pid().filter(|&p| p != 0),
            resolved.paths.cwd_string(),
            resolved.paths.home_string(),
            resolved.paths.project_root_string(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.session_ids_for_route(&route).await;
        if session_ids.is_empty() {
            return false;
        }
        let inner = self.inner.lock().await;
        session_ids.iter().any(|session_id| {
            inner
                .session_allow
                .get(session_id)
                .is_some_and(|bucket| session_network_matches(bucket, host, port))
        })
    }

    pub(crate) async fn session_denied(&self, host: &str, port: u16, ctx: MergeContext) -> bool {
        let resolved = self.resolve_context(ctx).await;
        let route = UiRoute::new(
            resolved.ids.pid().filter(|&p| p != 0),
            resolved.paths.cwd_string(),
            resolved.paths.home_string(),
            resolved.paths.project_root_string(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.session_ids_for_route(&route).await;
        if session_ids.is_empty() {
            return false;
        }
        let inner = self.inner.lock().await;
        session_ids.iter().any(|session_id| {
            inner
                .session_deny
                .get(session_id)
                .is_some_and(|bucket| session_network_matches(bucket, host, port))
        })
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
        merged.sudo.deny.iter().any(|rule| rule.matches(argv))
    }

    pub(crate) async fn sudo_policy_allowed(&self, argv: &[String], ctx: MergeContext) -> bool {
        let merged = self.merged_for(ctx).await;
        merged.sudo.allow.iter().any(|rule| rule.matches(argv))
    }

    pub(crate) async fn session_sudo_denied(&self, argv: &[String], ctx: MergeContext) -> bool {
        let resolved = self.resolve_context(ctx).await;
        let route = UiRoute::new(
            resolved.ids.pid().filter(|&p| p != 0),
            resolved.paths.cwd_string(),
            resolved.paths.home_string(),
            resolved.paths.project_root_string(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_sudo_deny
                .get(sid)
                .is_some_and(|bucket| session_sudo_matches(bucket, argv))
        })
    }

    pub(crate) async fn session_sudo_allowed(&self, argv: &[String], ctx: MergeContext) -> bool {
        let resolved = self.resolve_context(ctx).await;
        let route = UiRoute::new(
            resolved.ids.pid().filter(|&p| p != 0),
            resolved.paths.cwd_string(),
            resolved.paths.home_string(),
            resolved.paths.project_root_string(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_sudo_allow
                .get(sid)
                .is_some_and(|bucket| session_sudo_matches(bucket, argv))
        })
    }

    pub async fn allow_source(&self, host: &str, port: u16, ctx: MergeContext) -> Option<String> {
        let host = normalize_host(host);
        let resolved = self.resolve_context(ctx).await;
        if self.policy_denied(&host, port, resolved.clone()).await {
            return Some("deny".into());
        }
        if self.session_denied(&host, port, resolved.clone()).await {
            return Some("deny".into());
        }
        if self.once_allowed(&host, port, false).await {
            return Some("once".into());
        }
        if self.session_allowed(&host, port, resolved.clone()).await {
            return Some("session".into());
        }
        let merged = self.merged_for(resolved).await;
        for rule in &merged.network.allow {
            if Self::host_matches(&rule.host, &host) && rule.port == port {
                if let Some(comment) = &rule.comment
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
        let resolved = self.resolve_context(ctx).await;
        if self.policy_denied(&host, port, resolved.clone()).await {
            return false;
        }
        if self.session_denied(&host, port, resolved.clone()).await {
            return false;
        }
        if self.once_allowed(&host, port, consume_once).await {
            return true;
        }
        if self.session_allowed(&host, port, resolved.clone()).await {
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

fn session_filesystem_matches(
    bucket: &HashSet<(String, FileAccess)>,
    path: &str,
    access: FileAccess,
) -> bool {
    bucket.iter().any(|(rule_path, rule_access)| {
        let rule = agent_sandbox_core::FilesystemRule::new(rule_path.as_str(), *rule_access, "");
        rule.matches(path, access)
    })
}

impl PolicyStore {
    pub(crate) async fn filesystem_policy_denied(
        &self,
        path: &str,
        access: FileAccess,
        ctx: MergeContext,
    ) -> bool {
        let merged = self.merged_for(ctx).await;
        merged
            .filesystem
            .deny
            .iter()
            .any(|rule| rule.matches(path, access))
    }

    pub(crate) async fn filesystem_policy_allowed(
        &self,
        path: &str,
        access: FileAccess,
        ctx: MergeContext,
    ) -> bool {
        let merged = self.merged_for(ctx).await;
        merged
            .filesystem
            .allow
            .iter()
            .any(|rule| rule.matches(path, access))
    }

    pub(crate) async fn session_filesystem_denied(
        &self,
        path: &str,
        access: FileAccess,
        ctx: MergeContext,
    ) -> bool {
        let resolved = self.resolve_context(ctx).await;
        let route = UiRoute::new(
            resolved.ids.pid().filter(|&p| p != 0),
            resolved.paths.cwd_string(),
            resolved.paths.home_string(),
            resolved.paths.project_root_string(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_filesystem_deny
                .get(sid)
                .is_some_and(|bucket| session_filesystem_matches(bucket, path, access))
        })
    }

    pub(crate) async fn session_filesystem_allowed(
        &self,
        path: &str,
        access: FileAccess,
        ctx: MergeContext,
    ) -> bool {
        let resolved = self.resolve_context(ctx).await;
        let route = UiRoute::new(
            resolved.ids.pid().filter(|&p| p != 0),
            resolved.paths.cwd_string(),
            resolved.paths.home_string(),
            resolved.paths.project_root_string(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_filesystem_allow
                .get(sid)
                .is_some_and(|bucket| session_filesystem_matches(bucket, path, access))
        })
    }

    pub(crate) async fn filesystem_allow_source(
        &self,
        path: &str,
        access: FileAccess,
        ctx: MergeContext,
    ) -> Option<String> {
        if self
            .filesystem_policy_denied(path, access, ctx.clone())
            .await
        {
            return Some("deny".into());
        }
        if self
            .session_filesystem_denied(path, access, ctx.clone())
            .await
        {
            return Some("deny".into());
        }
        if self
            .session_filesystem_allowed(path, access, ctx.clone())
            .await
        {
            return Some("session".into());
        }
        if self.filesystem_policy_allowed(path, access, ctx).await {
            return Some("allow".into());
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{session_network_matches, session_sudo_matches};

    #[test]
    fn session_network_matches_wildcard_hosts() {
        let bucket = HashSet::from([(String::from("*.baz.com"), 443_u16)]);
        assert!(session_network_matches(&bucket, "foo.bar.baz.com", 443));
        assert!(!session_network_matches(&bucket, "foo.bar.baz.com", 80));
    }

    #[test]
    fn session_sudo_matches_prefixes() {
        let bucket = HashSet::from([vec![String::from("sudo"), String::from("apt")]]);
        let argv = vec![
            String::from("sudo"),
            String::from("apt"),
            String::from("update"),
        ];
        assert!(session_sudo_matches(&bucket, &argv));
    }
}
