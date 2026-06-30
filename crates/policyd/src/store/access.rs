//! Policy store: access.
use std::collections::{HashMap, HashSet};
use std::path::Path;

use agent_sandbox_core::{
    FileAccess, FilesystemRule, FilesystemRuleKey, InodeIdentity, NetworkRuleKey, Policy,
    ResourceAccess, ResourceKind, ResourceRule, ResourceRuleKey, allow_keys, expand_policy_path,
    normalize_host,
};

use crate::store::ui_route::UiRoute;
use crate::wire::MergeContext;

use super::types::{DenyCacheEntry, DenyFingerprint, DenyInodeCache, PolicyStore};

fn session_network_matches(bucket: &HashSet<NetworkRuleKey>, host: &str, port: u16) -> bool {
    let keys = allow_keys(host, port);
    bucket.iter().any(|rule| {
        rule.port == port
            && keys
                .iter()
                .any(|key| PolicyStore::host_matches(&rule.host, &key.host))
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

    pub(crate) async fn session_allowed(&self, host: &str, port: u16, ctx: &MergeContext) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
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

    pub(crate) async fn session_denied(&self, host: &str, port: u16, ctx: &MergeContext) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
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

    pub(crate) fn policy_denied(&self, host: &str, port: u16, ctx: &MergeContext) -> bool {
        let host = normalize_host(host);
        let merged = self.merged_for(ctx);
        merged
            .network
            .deny
            .iter()
            .any(|rule| Self::host_matches(&rule.host, &host) && rule.port == port)
    }

    pub(crate) fn sudo_policy_denied(&self, argv: &[String], ctx: &MergeContext) -> bool {
        let merged = self.merged_for(ctx);
        merged.sudo.deny.iter().any(|rule| rule.matches(argv))
    }

    pub(crate) fn sudo_policy_allowed(&self, argv: &[String], ctx: &MergeContext) -> bool {
        let merged = self.merged_for(ctx);
        merged.sudo.allow.iter().any(|rule| rule.matches(argv))
    }

    pub(crate) async fn session_sudo_denied(&self, argv: &[String], ctx: &MergeContext) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
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

    pub(crate) async fn session_sudo_allowed(&self, argv: &[String], ctx: &MergeContext) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
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

    pub async fn allow_source(&self, host: &str, port: u16, ctx: &MergeContext) -> Option<String> {
        let host = normalize_host(host);
        let resolved = self.resolve_context(ctx);
        if self.policy_denied(&host, port, &resolved) {
            return Some("deny".into());
        }
        if self.session_denied(&host, port, &resolved).await {
            return Some("deny".into());
        }
        if self.once_allowed(&host, port, false).await {
            return Some("once".into());
        }
        if self.session_allowed(&host, port, &resolved).await {
            return Some("session".into());
        }
        let merged = self.merged_for(&resolved);
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
        ctx: &MergeContext,
        consume_once: bool,
    ) -> bool {
        let host = normalize_host(host);
        let resolved = self.resolve_context(ctx);
        if self.policy_denied(&host, port, &resolved) {
            return false;
        }
        if self.session_denied(&host, port, &resolved).await {
            return false;
        }
        if self.once_allowed(&host, port, consume_once).await {
            return true;
        }
        if self.session_allowed(&host, port, &resolved).await {
            return true;
        }
        let merged = self.merged_for(&resolved);
        merged
            .network
            .allow
            .iter()
            .any(|rule| Self::host_matches(&rule.host, &host) && rule.port == port)
    }
}

fn session_filesystem_matches(
    bucket: &HashSet<FilesystemRuleKey>,
    path: &Path,
    access: FileAccess,
) -> bool {
    bucket.iter().any(|entry| {
        let rule = FilesystemRule::new(entry.path.clone(), entry.access, "");
        rule.matches(path, access, None)
    })
}

impl PolicyStore {
    pub(crate) async fn filesystem_policy_denied(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &MergeContext,
    ) -> bool {
        let project_root = ctx.paths.project_root();
        let merged = self.merged_for(ctx);
        let home = ctx.paths.home();
        let path_match = merged
            .filesystem
            .deny
            .iter()
            .any(|rule| rule.matches(path, access, project_root));
        if path_match {
            return true;
        }
        // Hardlink defense: check if the request path's inode matches any
        // file under a deny rule. Rebuilds the cache when the fingerprint
        // (deny rule paths + mtimes) changes.
        let fingerprint = Self::deny_fingerprint(&merged, home, project_root);
        let mut inner = self.inner.lock().await;
        if Self::fingerprint_changed(&inner.deny_inode_cache, &fingerprint) {
            inner.deny_inode_cache = Self::rebuild_deny_inode_cache(fingerprint);
        }
        Self::is_denied_by_inode(path, access, &inner.deny_inode_cache)
    }
    pub(crate) fn filesystem_policy_allowed(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &MergeContext,
    ) -> bool {
        let project_root = ctx.paths.project_root();
        let merged = self.merged_for(ctx);
        merged
            .filesystem
            .allow
            .iter()
            .any(|rule| rule.matches(path, access, project_root))
    }

    pub(crate) async fn session_filesystem_denied(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &MergeContext,
    ) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.filesystem_session_ids_for_route(&route).await;
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
        path: &Path,
        access: FileAccess,
        ctx: &MergeContext,
    ) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.filesystem_session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_filesystem_allow
                .get(sid)
                .is_some_and(|bucket| session_filesystem_matches(bucket, path, access))
        })
    }

    /// Check if a request path is session-allowed by inode comparison.
    /// If a hardlink at a different path was already approved this session,
    /// skip the prompt. The inode is the same, so the approval covers it.
    pub(crate) async fn session_filesystem_allowed_by_inode(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &MergeContext,
    ) -> bool {
        let Some(identity) = InodeIdentity::from_path(path) else {
            return false;
        };
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.filesystem_session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_filesystem_allow
                .get(sid)
                .is_some_and(|bucket| {
                    bucket.iter().any(|entry| {
                        entry.access.covers(access)
                            && InodeIdentity::from_path(&entry.path)
                                .is_some_and(|id| id == identity)
                    })
                })
        })
    }

    pub(crate) async fn filesystem_allow_source(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &MergeContext,
    ) -> Option<String> {
        if self.filesystem_policy_denied(path, access, ctx).await {
            return Some("deny".into());
        }
        if self.session_filesystem_denied(path, access, ctx).await {
            return Some("deny".into());
        }
        if self.session_filesystem_allowed(path, access, ctx).await {
            return Some("session".into());
        }
        // Inode-based session allow: if a hardlink at a different path was
        // already approved this session, skip the prompt. The inode is the
        // same, so the approval covers it.
        if self
            .session_filesystem_allowed_by_inode(path, access, ctx)
            .await
        {
            return Some("session".into());
        }
        if self.filesystem_policy_allowed(path, access, ctx) {
            return Some("allow".into());
        }
        None
    }

    /// Compute a fingerprint for the deny rules: one `DenyFingerprint` per
    /// concrete (non-glob) deny rule path. When this changes the inode
    /// cache must be rebuilt.
    fn deny_fingerprint(
        merged: &Policy,
        home: Option<&Path>,
        project_root: Option<&Path>,
    ) -> Vec<DenyFingerprint> {
        let mut fps = Vec::new();
        for rule in &merged.filesystem.deny {
            let expanded = expand_policy_path(&rule.path, home, project_root);
            if !expanded.to_string_lossy().contains('*')
                && !expanded.to_string_lossy().contains('?')
            {
                let mtime = std::fs::metadata(&expanded).and_then(|m| m.modified()).ok();
                fps.push(DenyFingerprint {
                    path: expanded,
                    access: rule.access,
                    mtime,
                });
            }
        }
        for rule in &merged.resources.deny {
            let expanded = expand_policy_path(&rule.path, home, project_root);
            if !expanded.to_string_lossy().contains('*')
                && !expanded.to_string_lossy().contains('?')
            {
                let mtime = std::fs::metadata(&expanded).and_then(|m| m.modified()).ok();
                fps.push(DenyFingerprint {
                    path: expanded,
                    access: FileAccess::All,
                    mtime,
                });
            }
        }
        fps.sort_by(|a, b| a.path.cmp(&b.path));
        fps
    }

    fn fingerprint_changed(cache: &DenyInodeCache, fingerprint: &[DenyFingerprint]) -> bool {
        cache.fingerprint.len() != fingerprint.len()
            || cache
                .fingerprint
                .iter()
                .zip(fingerprint.iter())
                .any(|(a, b)| a != b)
    }

    /// Rebuild the inode cache from deny rules. Stats each deny rule path:
    /// concrete files are cached directly, directories are walked recursively
    /// so hardlinks to files inside a denied directory are caught by inode
    /// comparison regardless of the path the tracee used.
    fn rebuild_deny_inode_cache(fingerprint: Vec<DenyFingerprint>) -> DenyInodeCache {
        use std::os::unix::fs::MetadataExt;
        let mut inodes: HashMap<InodeIdentity, Vec<DenyCacheEntry>> = HashMap::new();
        for entry in &fingerprint {
            let Ok(meta) = std::fs::metadata(&entry.path) else {
                continue;
            };
            if meta.is_dir() {
                Self::walk_dir_inodes(&entry.path, entry.access, &mut inodes);
            } else {
                let identity = InodeIdentity {
                    inode: meta.ino(),
                    device: meta.dev(),
                };
                inodes.entry(identity).or_default().push(DenyCacheEntry {
                    path: entry.path.clone(),
                    access: entry.access,
                });
            }
        }
        DenyInodeCache {
            inodes,
            fingerprint,
        }
    }
    fn walk_dir_inodes(
        dir: &Path,
        access: FileAccess,
        inodes: &mut HashMap<InodeIdentity, Vec<DenyCacheEntry>>,
    ) {
        use std::os::unix::fs::MetadataExt;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                Self::walk_dir_inodes(&entry.path(), access, inodes);
            } else {
                let identity = InodeIdentity {
                    inode: meta.ino(),
                    device: meta.dev(),
                };
                inodes.entry(identity).or_default().push(DenyCacheEntry {
                    path: entry.path(),
                    access,
                });
            }
        }
    }

    /// Check if a request path is denied by inode comparison. Stats the
    /// requested path and checks if its `InodeIdentity` matches any deny
    /// rule target, including files inside denied directories. Only denies
    /// if the deny rule's access covers the requested access.
    fn is_denied_by_inode(path: &Path, access: FileAccess, cache: &DenyInodeCache) -> bool {
        InodeIdentity::from_path(path).is_some_and(|identity| {
            cache
                .inodes
                .get(&identity)
                .is_some_and(|entries| entries.iter().any(|e| e.access.covers(access)))
        })
    }
}
fn session_resource_matches(
    bucket: &HashSet<ResourceRuleKey>,
    kind: ResourceKind,
    path: &Path,
    access: ResourceAccess,
) -> bool {
    bucket.iter().any(|entry| {
        let rule = ResourceRule::new(entry.kind, entry.path.clone(), entry.access, "");
        rule.matches(kind, path, access, None)
    })
}

impl PolicyStore {
    pub(crate) async fn resource_policy_denied(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &MergeContext,
    ) -> bool {
        let project_root = ctx.paths.project_root();
        let merged = self.merged_for(ctx);
        let home = ctx.paths.home();
        let path_match = merged
            .resources
            .deny
            .iter()
            .any(|rule| rule.matches(kind, path, access, project_root));
        if path_match {
            return true;
        }
        // Hardlink defense: check if the request path's inode matches any
        // resource deny rule target.
        let fingerprint = Self::deny_fingerprint(&merged, home, project_root);
        let mut inner = self.inner.lock().await;
        if Self::fingerprint_changed(&inner.deny_inode_cache, &fingerprint) {
            inner.deny_inode_cache = Self::rebuild_deny_inode_cache(fingerprint);
        }
        Self::is_denied_by_inode(path, FileAccess::All, &inner.deny_inode_cache)
    }

    pub(crate) fn resource_policy_allowed(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &MergeContext,
    ) -> bool {
        let project_root = ctx.paths.project_root();
        let merged = self.merged_for(ctx);
        merged
            .resources
            .allow
            .iter()
            .any(|rule| rule.matches(kind, path, access, project_root))
    }

    pub(crate) async fn session_resource_denied(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &MergeContext,
    ) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.filesystem_session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_resource_deny
                .get(sid)
                .is_some_and(|bucket| session_resource_matches(bucket, kind, path, access))
        })
    }

    pub(crate) async fn session_resource_allowed(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &MergeContext,
    ) -> bool {
        let resolved = self.resolve_context(ctx);
        let route = UiRoute::new(
            resolved.paths.cwd_path(),
            resolved.paths.project_root_path(),
        )
        .with_sandbox_session(resolved.sandbox_session_id.clone());
        let session_ids = self.filesystem_session_ids_for_route(&route).await;
        let inner = self.inner.lock().await;
        session_ids.iter().any(|sid| {
            inner
                .session_resource_allow
                .get(sid)
                .is_some_and(|bucket| session_resource_matches(bucket, kind, path, access))
        })
    }

    pub(crate) async fn resource_allow_source(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &MergeContext,
    ) -> Option<String> {
        if self.resource_policy_denied(kind, path, access, ctx).await {
            return Some("deny".into());
        }
        if self.session_resource_denied(kind, path, access, ctx).await {
            return Some("deny".into());
        }
        if self.session_resource_allowed(kind, path, access, ctx).await {
            return Some("session".into());
        }
        if self.resource_policy_allowed(kind, path, access, ctx) {
            return Some("allow".into());
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{session_network_matches, session_sudo_matches};
    use agent_sandbox_core::NetworkRuleKey;

    #[test]
    fn session_network_matches_wildcard_hosts() {
        let bucket = HashSet::from([NetworkRuleKey::new("*.baz.com", 443)]);
        assert!(session_network_matches(&bucket, "foo.bar.baz.com", 443));
        assert!(!session_network_matches(&bucket, "foo.bar.baz.com", 80));
    }

    #[test]
    fn session_network_matches_ipv4_prefix_wildcard() {
        let bucket = HashSet::from([NetworkRuleKey::new("34.230.40.*", 443)]);
        // Exact match within the prefix range
        assert!(session_network_matches(&bucket, "34.230.40.69", 443));
        assert!(session_network_matches(&bucket, "34.230.40.1", 443));
        // Different subnet: must NOT match
        assert!(!session_network_matches(&bucket, "34.230.41.69", 443));
        // Wrong port
        assert!(!session_network_matches(&bucket, "34.230.40.69", 80));
        // Partial octet match rejected
        assert!(!session_network_matches(&bucket, "34.230.4.1", 443));
    }

    #[test]
    fn session_network_matches_ipv4_broader_prefix_wildcards() {
        let bucket = HashSet::from([NetworkRuleKey::new("34.*", 443)]);
        assert!(session_network_matches(&bucket, "34.230.40.69", 443));
        assert!(session_network_matches(&bucket, "34.0.0.1", 443));
        assert!(!session_network_matches(&bucket, "35.0.0.1", 443));
    }

    #[tokio::test]
    async fn trusted_project_policy_deny_applies() {
        // The trusted per-project policy file lives under
        // `<project_root>/.agent-sandbox/policy.json`. A deny
        // rule there is honored by the merged policy.
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox"))
            .expect("create .agent-sandbox dir");
        std::fs::create_dir_all(&project_root).expect("create project root dir");
        std::fs::create_dir_all(&home).expect("create home dir");
        let policy_path = agent_sandbox_core::trusted_project_policy_path(&project_root)
            .expect("trusted project policy path");

        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .network
            .deny
            .push(agent_sandbox_core::NetworkRule::new(
                "34.230.40.*",
                443,
                "test",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = super::super::types::PolicyStore::new(super::super::types::PolicydArgs {
            host_socket: dir.path().join("sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: std::time::Duration::from_mins(1),
            interactive_approval: false,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        });

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();
        let ctx = crate::wire::MergeContext {
            paths: agent_sandbox_core::SandboxPaths::new(&project_root, &home, &project_root),
            ids: agent_sandbox_core::ProcessIds::default(),
            sandbox_session_id: None,
        };

        assert!(store.policy_denied("34.230.40.69", 443, &ctx));
        assert!(!store.is_allowed("34.230.40.69", 443, &ctx, false).await);
    }

    #[test]
    fn session_network_matches_ipv6_prefix_wildcard() {
        let bucket = HashSet::from([NetworkRuleKey::new("2001:db8:*", 443)]);
        // Exact match within the prefix range
        assert!(session_network_matches(&bucket, "2001:db8::1", 443));
        assert!(session_network_matches(
            &bucket,
            "2001:db8:0:0:0:0:0:1",
            443
        ));
        // Different subnet: must NOT match
        assert!(!session_network_matches(&bucket, "2001:db9::1", 443));
        // Wrong port
        assert!(!session_network_matches(&bucket, "2001:db8::1", 80));
    }

    #[tokio::test]
    async fn trusted_project_policy_ipv6_deny_applies() {
        // IPv6 deny rules in the trusted per-project policy file apply.
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox"))
            .expect("create .agent-sandbox dir");
        std::fs::create_dir_all(&project_root).expect("create project root dir");
        std::fs::create_dir_all(&home).expect("create home dir");
        let policy_path = agent_sandbox_core::trusted_project_policy_path(&project_root)
            .expect("trusted project policy path");

        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .network
            .deny
            .push(agent_sandbox_core::NetworkRule::new(
                "2001:db8:*",
                443,
                "test",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = super::super::types::PolicyStore::new(super::super::types::PolicydArgs {
            host_socket: dir.path().join("sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: std::time::Duration::from_mins(1),
            interactive_approval: false,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        });

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();
        let ctx = crate::wire::MergeContext {
            paths: agent_sandbox_core::SandboxPaths::new(&project_root, &home, &project_root),
            ids: agent_sandbox_core::ProcessIds::default(),
            sandbox_session_id: None,
        };

        assert!(store.policy_denied("2001:db8::1", 443, &ctx));
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

    #[tokio::test]
    async fn trusted_project_policy_deny_persists_after_reload() {
        // Deny rules in the trusted per-project policy file are picked up on
        // every merge. Rewriting the file with an empty policy removes the
        // deny rule the next time the policy is merged.
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox"))
            .expect("create .agent-sandbox dir");
        std::fs::create_dir_all(&project_root).expect("create project root dir");
        std::fs::create_dir_all(&home).expect("create home dir");
        let policy_path = agent_sandbox_core::trusted_project_policy_path(&project_root)
            .expect("trusted project policy path");

        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .network
            .deny
            .push(agent_sandbox_core::NetworkRule::new(
                "example.com",
                443,
                "test",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = super::super::types::PolicyStore::new(super::super::types::PolicydArgs {
            host_socket: dir.path().join("sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: std::time::Duration::from_mins(1),
            interactive_approval: false,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        });

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();
        let ctx = crate::wire::MergeContext {
            paths: agent_sandbox_core::SandboxPaths::new(&project_root, &home, &project_root),
            ids: agent_sandbox_core::ProcessIds::default(),
            sandbox_session_id: None,
        };

        assert!(store.policy_denied("example.com", 443, &ctx));
        assert!(!store.is_allowed("example.com", 443, &ctx, false).await);

        let empty = agent_sandbox_core::Policy::default();
        agent_sandbox_core::atomic_write_policy(&policy_path, &empty, None, None, None)
            .expect("clear policy");

        // The merged policy is computed on every call, so removing the deny rule
        // from disk takes effect immediately.
        assert!(!store.policy_denied("example.com", 443, &ctx));
    }

    #[tokio::test]
    async fn repo_local_policy_deny_applies() {
        // The repo-local `.agent-sandbox/policy.json` file is loaded by the
        // policy daemon. A deny rule there is honored by the merged policy.
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox"))
            .expect("create .agent-sandbox dir");
        std::fs::create_dir_all(&home).expect("create home dir");
        let policy_path = agent_sandbox_core::trusted_project_policy_path(&project_root)
            .expect("trusted project policy path");

        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .network
            .deny
            .push(agent_sandbox_core::NetworkRule::new(
                "34.230.40.*",
                443,
                "test",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = super::super::types::PolicyStore::new(super::super::types::PolicydArgs {
            host_socket: dir.path().join("sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: std::time::Duration::from_mins(1),
            interactive_approval: false,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        });

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();
        let ctx = crate::wire::MergeContext {
            paths: agent_sandbox_core::SandboxPaths::new(&project_root, &home, &project_root),
            ids: agent_sandbox_core::ProcessIds::default(),
            sandbox_session_id: None,
        };

        // The repo-local deny rule is applied: policy_denied returns
        // true because the merged policy includes the deny rule.
        assert!(store.policy_denied("34.230.40.69", 443, &ctx));
    }

    #[tokio::test]
    async fn global_policy_is_re_read_after_manual_edit() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(&project_root).expect("create project root dir");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        let policy_path = policy_dir.join("policy.json");

        let mut policy = agent_sandbox_core::Policy::default();
        policy
            .network
            .allow
            .push(agent_sandbox_core::NetworkRule::new(
                "example.com",
                443,
                "test",
            ));
        agent_sandbox_core::atomic_write_policy(&policy_path, &policy, None, None, None)
            .expect("write policy");

        let store = super::super::types::PolicyStore::new(super::super::types::PolicydArgs {
            host_socket: dir.path().join("sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: std::time::Duration::from_mins(1),
            interactive_approval: false,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        });

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();
        let ctx = crate::wire::MergeContext {
            paths: agent_sandbox_core::SandboxPaths::new(&project_root, &home, &project_root),
            ids: agent_sandbox_core::ProcessIds::default(),
            sandbox_session_id: None,
        };

        assert!(store.is_allowed("example.com", 443, &ctx, false).await);

        let empty = agent_sandbox_core::Policy::default();
        agent_sandbox_core::atomic_write_policy(&policy_path, &empty, None, None, None)
            .expect("clear policy");

        assert!(!store.is_allowed("example.com", 443, &ctx, false).await);
    }
}
