use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use agent_sandbox_core::{
    DbusRule, DbusTarget, FileAccess, FilesystemRule, FilesystemRuleKey, InodeIdentity,
    NetworkRuleKey, Policy, ResolvedRequestContext, ResourceAccess, ResourceKind, ResourceRule,
    ResourceRuleKey, SocketAccess, Verdict, contains_glob_syntax, discover_git_project_root,
    expand_policy_path, host_pattern_matches, normalize_directory_traverse_access, normalize_host,
};

use super::types::{DenyCacheEntry, DenyFingerprint, DenyInodeCache, PolicyStore};

/// Upper bound on files indexed by the deny inode cache across all deny
/// rules. Keeps a deny rule on a huge tree (e.g. a btrfs snapshot dir with
/// millions of files) from consuming unbounded memory and blocking checks.
const MAX_DENY_INODE_ENTRIES: usize = 100_000;

fn session_network_matches(bucket: &HashSet<NetworkRuleKey>, host: &str, port: u16) -> bool {
    let keys = [NetworkRuleKey::new(host, port)];

    bucket.iter().any(|rule| {
        rule.port == port
            && keys
                .iter()
                .any(|key| host_pattern_matches(&rule.host, &key.host))
    })
}

fn session_sudo_matches(bucket: &HashSet<Vec<String>>, argv: &[String]) -> bool {
    bucket
        .iter()
        .any(|rule| !rule.is_empty() && argv.starts_with(rule))
}

fn session_dbus_matches(bucket: &HashSet<DbusTarget>, target: &DbusTarget) -> bool {
    bucket
        .iter()
        .any(|candidate| DbusRule::new(candidate.clone(), "").matches(target))
}

fn sandbox_filesystem_static_allow_key(ctx: &ResolvedRequestContext) -> String {
    if let Some(id) = &ctx.sandbox_session_id {
        return format!("sandbox:{id}");
    }

    let cwd = ctx
        .paths
        .cwd()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let project_root = ctx
        .paths
        .project_root()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    format!("ctx:{cwd}:{project_root}")
}

/// Host-managed runtime paths under `/run/agent-sandbox` are infrastructure,
/// not agent actions. Fanotify must allow them without loading merged policy.
pub(super) fn is_sandbox_infrastructure_path(path: &Path) -> bool {
    path.starts_with("/run/agent-sandbox")
}

impl PolicyStore {
    pub(crate) async fn once_allowed(&self, host: &str, port: u16, consume: bool) -> bool {
        let keys = [NetworkRuleKey::new(host, port)];
        let mut inner = self.inner.lock().await;
        let matched = keys.iter().any(|k| inner.session.once_allow.contains(k));

        if matched && consume {
            for key in keys {
                inner.session.once_allow.remove(&key);
            }
        }

        matched
    }

    pub(crate) async fn session_allowed(
        &self,
        host: &str,
        port: u16,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;

        if session_ids.is_empty() {
            return false;
        }

        let inner = self.inner.lock().await;

        session_ids.iter().any(|session_id| {
            inner
                .session
                .session_allow
                .get(session_id)
                .is_some_and(|bucket| session_network_matches(bucket, host, port))
        })
    }

    pub(crate) async fn session_denied(
        &self,
        host: &str,
        port: u16,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;

        if session_ids.is_empty() {
            return false;
        }

        let inner = self.inner.lock().await;

        session_ids.iter().any(|session_id| {
            inner
                .session
                .session_deny
                .get(session_id)
                .is_some_and(|bucket| session_network_matches(bucket, host, port))
        })
    }

    pub(crate) fn policy_denied(
        &self,
        host: &str,
        port: u16,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let host = normalize_host(host);
        let merged = self.merged_for(ctx);

        merged
            .network
            .direct
            .deny
            .iter()
            .any(|rule| host_pattern_matches(&rule.host, &host) && rule.port == port)
    }

    pub(crate) fn sudo_policy_denied(&self, argv: &[String], ctx: &ResolvedRequestContext) -> bool {
        let merged = self.merged_for(ctx);
        merged.sudo.deny.iter().any(|rule| rule.matches(argv))
    }

    pub(crate) fn sudo_policy_allowed(
        &self,
        argv: &[String],
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let merged = self.merged_for(ctx);
        merged.sudo.allow.iter().any(|rule| rule.matches(argv))
    }

    pub(crate) async fn session_sudo_denied(
        &self,
        argv: &[String],
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
                .session_sudo_deny
                .get(sid)
                .is_some_and(|bucket| session_sudo_matches(bucket, argv))
        })
    }

    pub(crate) async fn session_sudo_allowed(
        &self,
        argv: &[String],
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
                .session_sudo_allow
                .get(sid)
                .is_some_and(|bucket| session_sudo_matches(bucket, argv))
        })
    }

    pub async fn allow_verdict(
        &self,
        host: &str,
        port: u16,
        ctx: &ResolvedRequestContext,
    ) -> Option<Verdict> {
        self.network_verdict(host, port, ctx, false).await
    }
}

fn session_filesystem_matches(
    bucket: &HashSet<FilesystemRuleKey>,
    path: &Path,
    access: FileAccess,
    project_root: Option<&Path>,
) -> bool {
    bucket.iter().any(|entry| {
        let rule = FilesystemRule::new(entry.path.clone(), entry.access, "");
        rule.matches(path, access, project_root)
    })
}

/// Candidate project roots for matching project-relative allow rules.
///
/// Includes the resolved sandbox context root and, when the requested path lies
/// inside a Git work tree, that repository's root so `./.git` still matches
/// `.git/objects` after `cd` into another repo or a stale launcher root.
fn project_roots_for_allow(ctx_root: Option<&Path>, path: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    let mut push = |root: PathBuf| {
        if !root.as_os_str().is_empty() && !roots.iter().any(|r| r == &root) {
            roots.push(root);
        }
    };

    if let Some(pr) = ctx_root {
        push(pr.to_path_buf());
    }

    if let Some(git_root) = discover_git_project_root(path) {
        push(git_root);
    }

    roots
}

pub(super) fn filesystem_rules_match_allow(
    rules: &[FilesystemRule],
    path: &Path,
    access: FileAccess,
    ctx_root: Option<&Path>,
) -> bool {
    let roots = project_roots_for_allow(ctx_root, path);

    if roots.is_empty() {
        return rules.iter().any(|rule| rule.matches(path, access, None));
    }

    roots.iter().any(|root| {
        rules
            .iter()
            .any(|rule| rule.matches(path, access, Some(root)))
    })
}

fn session_filesystem_bucket_matches_allow(
    bucket: &HashSet<FilesystemRuleKey>,
    path: &Path,
    access: FileAccess,
    ctx_root: Option<&Path>,
) -> bool {
    let roots = project_roots_for_allow(ctx_root, path);

    if roots.is_empty() {
        return session_filesystem_matches(bucket, path, access, None);
    }

    roots
        .iter()
        .any(|root| session_filesystem_matches(bucket, path, access, Some(root)))
}

impl PolicyStore {
    pub(crate) async fn filesystem_policy_denied(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let access = normalize_directory_traverse_access(path, access);
        let project_root = ctx.paths.project_root();
        let ctx = ctx.clone();
        let merged = self.merged_for_worker(&ctx);
        let home = ctx.paths.home();

        let path_match = merged
            .filesystem
            .deny
            .iter()
            .any(|rule| rule.matches(path, access, project_root));

        if path_match {
            return true;
        }

        let fingerprint = Self::deny_fingerprint(&merged, home, project_root);
        self.deny_inode_denied(path, access, &fingerprint).await
    }

    pub(crate) async fn session_filesystem_denied(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let project_root = ctx.paths.project_root();
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
                .session_filesystem_deny
                .get(sid)
                .is_some_and(|bucket| {
                    session_filesystem_matches(bucket, path, access, project_root)
                })
        })
    }

    pub(crate) async fn session_filesystem_allowed(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let project_root = ctx.paths.project_root();
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
                .session_filesystem_allow
                .get(sid)
                .is_some_and(|bucket| {
                    session_filesystem_bucket_matches_allow(bucket, path, access, project_root)
                })
        })
    }

    /// Check if a request path is session-allowed by inode comparison.
    /// If a hardlink at a different path was already approved this session,
    /// skip the prompt. The inode is the same, so the approval covers it.
    pub(crate) async fn session_filesystem_allowed_by_inode(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let Some(identity) = InodeIdentity::from_path(path) else {
            return false;
        };

        let session_ids = self.session_ids_for_context(ctx).await;
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
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

    pub(crate) async fn static_filesystem_allowed(
        &self,
        path: &Path,
        access: FileAccess,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let key = sandbox_filesystem_static_allow_key(ctx);
        let project_root = ctx.paths.project_root();
        let inner = self.inner.lock().await;

        inner
            .sandbox_filesystem_static_allow
            .get(&key)
            .is_some_and(|rules| {
                rules
                    .iter()
                    .any(|rule| rule.matches(path, access, project_root))
            })
    }

    pub(crate) async fn store_sandbox_static_allow(
        &self,
        ctx: &ResolvedRequestContext,
        rules: Vec<FilesystemRule>,
    ) {
        if rules.is_empty() {
            return;
        }

        let key = sandbox_filesystem_static_allow_key(ctx);

        self.inner
            .lock()
            .await
            .sandbox_filesystem_static_allow
            .insert(key, rules);
    }

    pub(super) async fn deny_inode_denied(
        &self,
        path: &Path,
        access: FileAccess,
        fingerprint: &[DenyFingerprint],
    ) -> bool {
        let needs_rebuild = {
            let inner = self.inner.lock().await;
            Self::fingerprint_changed(&inner.deny_inode_cache, fingerprint)
        };

        if needs_rebuild {
            // Single-flight: concurrent checks wait here instead of each
            // launching a full recursive walk of every denied directory.
            let _rebuild_guard = self.deny_inode_rebuild.lock().await;

            let still_stale = {
                let inner = self.inner.lock().await;
                Self::fingerprint_changed(&inner.deny_inode_cache, fingerprint)
            };

            if still_stale {
                let fp = fingerprint.to_vec();

                // The walk can hit disk for a long time; keep it off the
                // async runtime so other requests stay responsive.
                match tokio::task::spawn_blocking(move || Self::rebuild_deny_inode_cache(fp)).await
                {
                    Ok(new_cache) => {
                        self.inner.lock().await.deny_inode_cache = new_cache;
                    }

                    Err(err) => {
                        tracing::error!(error = %err, "deny inode cache rebuild panicked");
                    }
                }
            }
        }

        let inner = self.inner.lock().await;
        Self::is_denied_by_inode(path, access, &inner.deny_inode_cache)
    }

    /// Compute a fingerprint for the deny rules: one `DenyFingerprint` per
    /// concrete (non-glob) deny rule path. When this changes the inode
    /// cache must be rebuilt.
    pub(super) fn deny_fingerprint(
        merged: &Policy,
        home: Option<&Path>,
        project_root: Option<&Path>,
    ) -> Vec<DenyFingerprint> {
        let mut fps = Vec::new();

        for rule in &merged.filesystem.deny {
            let expanded = expand_policy_path(&rule.path, home, project_root);

            if !contains_glob_syntax(&expanded.to_string_lossy()) {
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

            if !contains_glob_syntax(&expanded.to_string_lossy()) {
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
        let mut budget = MAX_DENY_INODE_ENTRIES;

        for entry in &fingerprint {
            let Ok(meta) = std::fs::metadata(&entry.path) else {
                continue;
            };

            if meta.is_dir() {
                // One visited set per rule: a directory reached through
                // another rule's symlink must still be walked when this rule
                // carries a different access level, or the narrower deny would
                // be lost. Cycles within one rule's reachable tree terminate
                // because the set is shared across that rule's recursion.
                let mut visited_dirs: HashSet<(u64, u64)> = HashSet::new();

                if !Self::walk_dir_inodes(
                    &entry.path,
                    entry.access,
                    &mut inodes,
                    &mut visited_dirs,
                    &mut budget,
                ) {
                    tracing::warn!(
                        path = %entry.path.display(),
                        limit = MAX_DENY_INODE_ENTRIES,
                        "deny directory too large for inode hardlink defense; walk truncated \
                         (path-based deny rules still apply)"
                    );
                }
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

    /// Recursively index files under a denied directory. Decrements `budget`
    /// per cached file; returns `false` when the budget is exhausted and the
    /// walk was abandoned (deny rules on huge trees, e.g. snapshot
    /// directories, would otherwise consume unbounded time and memory).
    ///
    /// Symlinks are followed: a member that is a symlink to a regular file is
    /// indexed by its resolved target inode, and a member that is a symlink to
    /// a directory recurses into that target. `visited_dirs` holds the inode
    /// identity of every followed directory so a symlink cycle (`link -> .` or
    /// `link -> ..`) terminates and aliases to the same real directory are
    /// walked once.
    fn walk_dir_inodes(
        dir: &Path,
        access: FileAccess,
        inodes: &mut HashMap<InodeIdentity, Vec<DenyCacheEntry>>,
        visited_dirs: &mut HashSet<(u64, u64)>,
        budget: &mut usize,
    ) -> bool {
        use std::os::unix::fs::MetadataExt;

        // The followed target of `dir`: `read_dir` and recursion below follow
        // a symlinked directory, so key the visit on the real directory's
        // inode. This both terminates cycles and dedups aliases.
        let Ok(dir_meta) = std::fs::metadata(dir) else {
            return true;
        };

        if !visited_dirs.insert((dir_meta.dev(), dir_meta.ino())) {
            return true;
        }

        let Ok(entries) = std::fs::read_dir(dir) else {
            return true;
        };

        for entry in entries.flatten() {
            if *budget == 0 {
                return false;
            }

            // `file_type` does not follow the link, so a real subdirectory is
            // recursed into directly. Symlinked members are resolved below.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };

            if file_type.is_dir() {
                if !Self::walk_dir_inodes(&entry.path(), access, inodes, visited_dirs, budget) {
                    return false;
                }
                continue;
            }

            // Follow the target: a regular file is indexed by its real inode
            // (matching `InodeIdentity::from_path` on the requested path), and
            // a symlinked directory recurses into its target.
            let Ok(meta) = std::fs::metadata(entry.path()) else {
                continue;
            };

            if meta.is_dir() {
                if !Self::walk_dir_inodes(&entry.path(), access, inodes, visited_dirs, budget) {
                    return false;
                }
                continue;
            }

            *budget -= 1;

            let identity = InodeIdentity {
                inode: meta.ino(),
                device: meta.dev(),
            };

            inodes.entry(identity).or_default().push(DenyCacheEntry {
                path: entry.path(),
                access,
            });
        }

        true
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

fn is_protected_abstract_socket(path: &str) -> bool {
    [
        "@abstract:/tmp/dbus-",
        "@abstract:/org/freedesktop/DBus",
        "@abstract:/org/freedesktop/systemd1",
        "@abstract:org.freedesktop.DBus",
        "@abstract:org.freedesktop.systemd1",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

fn is_protected_host_ipc_socket(kind: ResourceKind, path: &Path, access: ResourceAccess) -> bool {
    if kind != ResourceKind::UnixSocket
        || !matches!(
            access,
            ResourceAccess::Socket(SocketAccess::Connect | SocketAccess::Send | SocketAccess::All)
        )
    {
        return false;
    }

    let path_string = path.to_string_lossy();

    if is_protected_abstract_socket(&path_string) {
        return true;
    }

    if path == Path::new("/run/dbus")
        || path.starts_with("/run/dbus/")
        || path == Path::new("/run/systemd")
        || path.starts_with("/run/systemd/")
    {
        return true;
    }

    let mut components = path.components();

    matches!(
        (
            components.next(),
            components.next(),
            components.next(),
            components.next(),
            components.next(),
        ),
        (
            Some(std::path::Component::RootDir),
            Some(std::path::Component::Normal(run)),
            Some(std::path::Component::Normal(user)),
            Some(std::path::Component::Normal(uid)),
            Some(std::path::Component::Normal(area)),
        ) if run == "run"
            && user == "user"
            && uid.to_string_lossy().chars().all(|c| c.is_ascii_digit())
            && (area == "bus" || area == "systemd")
    )
}

impl PolicyStore {
    pub(crate) async fn resource_policy_denied(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let project_root = ctx.paths.project_root();
        let merged = self.merged_for(ctx);
        let home = ctx.paths.home();

        if is_protected_host_ipc_socket(kind, path, access) {
            return true;
        }

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

        self.deny_inode_denied(path, FileAccess::All, &fingerprint)
            .await
    }

    pub(crate) fn resource_policy_allowed(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        ctx: &ResolvedRequestContext,
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
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
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
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
                .session_resource_allow
                .get(sid)
                .is_some_and(|bucket| session_resource_matches(bucket, kind, path, access))
        })
    }

    pub(crate) async fn session_dbus_denied(
        &self,
        target: &DbusTarget,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
                .session_dbus_deny
                .get(sid)
                .is_some_and(|bucket| session_dbus_matches(bucket, target))
        })
    }

    pub(crate) async fn session_dbus_allowed(
        &self,
        target: &DbusTarget,
        ctx: &ResolvedRequestContext,
    ) -> bool {
        let session_ids = self.session_ids_for_context(ctx).await;
        let inner = self.inner.lock().await;

        session_ids.iter().any(|sid| {
            inner
                .session
                .session_dbus_allow
                .get(sid)
                .is_some_and(|bucket| session_dbus_matches(bucket, target))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::Path, sync::Arc};

    use agent_sandbox_core::{
        DbusMessageKind, DbusTarget, DeviceAccess, FileAccess, FilesystemRule, FilesystemRuleKey,
        NetworkRule, NetworkRuleKey, Policy, ProcessIds, ResolvedRequestContext, ResourceAccess,
        ResourceKind, SandboxPaths, SocketAccess, Verdict, VerdictSource, atomic_write_policy,
        trusted_project_policy_path,
    };
    use tokio::{net::UnixStream, sync::Mutex};

    use super::{
        is_protected_host_ipc_socket, session_filesystem_matches, session_network_matches,
        session_sudo_matches,
    };
    use crate::store::{UiSessionContext, types::UiClient};

    #[test]
    fn session_filesystem_matches_honors_project_relative_paths() {
        let bucket = HashSet::from([FilesystemRuleKey::new("./.git", FileAccess::ReadWrite)]);
        let project = Path::new("/home/user/dotfiles");
        let config = Path::new("/home/user/dotfiles/.git/config");

        assert!(session_filesystem_matches(
            &bucket,
            config,
            FileAccess::ReadWrite,
            Some(project),
        ));

        assert!(!session_filesystem_matches(
            &bucket,
            config,
            FileAccess::ReadWrite,
            None,
        ));
    }

    #[test]
    fn protected_host_ipc_socket_is_builtin_denied() {
        for path in [
            "/run/dbus/system_bus_socket",
            "/run/dbus/custom.sock",
            "/run/systemd/private",
            "/run/systemd/notify",
            "/run/user/1000/bus",
            "/run/user/1000/systemd/private",
            "@abstract:/tmp/dbus-1234",
            "@abstract:org.freedesktop.systemd1",
        ] {
            assert!(is_protected_host_ipc_socket(
                ResourceKind::UnixSocket,
                Path::new(path),
                ResourceAccess::Socket(SocketAccess::Connect)
            ));

            assert!(is_protected_host_ipc_socket(
                ResourceKind::UnixSocket,
                Path::new(path),
                ResourceAccess::Socket(SocketAccess::Send)
            ));
        }

        assert!(!is_protected_host_ipc_socket(
            ResourceKind::UnixSocket,
            Path::new("@abstract:nv_target_process_1234"),
            ResourceAccess::Socket(SocketAccess::Connect)
        ));

        assert!(!is_protected_host_ipc_socket(
            ResourceKind::UnixSocket,
            Path::new("/run/user/1000/portal-bus"),
            ResourceAccess::Socket(SocketAccess::Connect)
        ));

        assert!(!is_protected_host_ipc_socket(
            ResourceKind::Device,
            Path::new("/run/user/1000/bus"),
            ResourceAccess::Device(DeviceAccess::Read)
        ));
    }

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

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy
            .network
            .direct
            .deny
            .push(NetworkRule::new("34.230.40.*", 443, "test"));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root, &home, &project_root),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert!(store.policy_denied("34.230.40.69", 443, &ctx));

        assert!(
            !store
                .network_verdict("34.230.40.69", 443, &ctx, false)
                .await
                .is_some_and(|v| v.allowed)
        );
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

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy
            .network
            .direct
            .deny
            .push(NetworkRule::new("2001:db8:*", 443, "test"));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root, &home, &project_root),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
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

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy
            .network
            .direct
            .deny
            .push(NetworkRule::new("example.com", 443, "test"));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root, &home, &project_root),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert!(store.policy_denied("example.com", 443, &ctx));

        assert!(
            !store
                .network_verdict("example.com", 443, &ctx, false)
                .await
                .is_some_and(|v| v.allowed)
        );

        let empty = Policy::default();
        atomic_write_policy(&policy_path, &empty, None, None, None).expect("clear policy");

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

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy
            .network
            .direct
            .deny
            .push(NetworkRule::new("34.230.40.*", 443, "test"));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root, &home, &project_root),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
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
        let mut policy = Policy::default();

        policy
            .network
            .direct
            .allow
            .push(NetworkRule::new("example.com", 443, "test"));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root = project_root.to_string_lossy().into_owned();
        let home = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root, &home, &project_root),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert!(
            store
                .network_verdict("example.com", 443, &ctx, false)
                .await
                .is_some_and(|v| v.allowed)
        );

        let empty = Policy::default();
        atomic_write_policy(&policy_path, &empty, None, None, None).expect("clear policy");

        assert!(
            !store
                .network_verdict("example.com", 443, &ctx, false)
                .await
                .is_some_and(|v| v.allowed)
        );
    }

    #[tokio::test]
    async fn global_git_star_rule_needs_project_root_to_match() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("dotfiles");
        let home = dir.path().join("home");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(project_root.join(".git")).expect("create git dir");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        let policy_path = policy_dir.join("policy.json");
        let config_path = project_root.join(".git/config");
        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            "./.git",
            FileAccess::ReadWrite,
            "global",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let home_s = home.to_string_lossy().into_owned();
        let root_s = project_root.to_string_lossy().into_owned();

        let with_root = ResolvedRequestContext {
            paths: SandboxPaths::new(&root_s, &home_s, &root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        let without_root = ResolvedRequestContext {
            paths: SandboxPaths::new(&root_s, &home_s, ""),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert_eq!(
            store
                .filesystem_allow_source(&config_path, FileAccess::ReadWrite, &with_root,)
                .await,
            Some(Verdict::allowed(VerdictSource::policy())),
            "global ./.git should match .git/config when project_root is set"
        );

        assert_eq!(
            store
                .filesystem_allow_source(&config_path, FileAccess::ReadWrite, &without_root,)
                .await,
            Some(Verdict::allowed(VerdictSource::policy())),
            "global ./.git should still match via git-discovered project root when ctx \
             project_root is empty"
        );
    }

    #[tokio::test]
    async fn global_git_slash_prefix_matches_head_with_project_root() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("dotfiles");
        let home = dir.path().join("home");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(project_root.join(".git")).expect("create git dir");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        let policy_path = policy_dir.join("policy.json");
        let head_path = project_root.join(".git/HEAD");
        std::fs::write(&head_path, "ref: refs/heads/main\n").expect("write HEAD");
        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            "./.git/",
            FileAccess::ReadWrite,
            "global",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let home_s = home.to_string_lossy().into_owned();
        let root_s = project_root.to_string_lossy().into_owned();

        let with_root = ResolvedRequestContext {
            paths: SandboxPaths::new(&root_s, &home_s, &root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        let without_root = ResolvedRequestContext {
            paths: SandboxPaths::new(&root_s, &home_s, ""),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert_eq!(
            store
                .filesystem_allow_source(&head_path, FileAccess::Read, &with_root,)
                .await,
            Some(Verdict::allowed(VerdictSource::policy())),
            "./.git/ prefix should match .git/HEAD when project_root is set"
        );

        assert_eq!(
            store
                .filesystem_allow_source(&head_path, FileAccess::Read, &without_root,)
                .await,
            Some(Verdict::allowed(VerdictSource::policy())),
            "./.git/ prefix should match via git-discovered project root when ctx project_root is \
             empty"
        );
    }

    #[tokio::test]
    async fn global_git_star_matches_objects_when_ctx_project_root_is_stale() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("agent-sandbox");
        let home = dir.path().join("home");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(project_root.join(".git/objects/pack")).expect("git tree");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        let policy_path = policy_dir.join("policy.json");
        let objects_path = project_root.join(".git/objects/pack");
        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            "./.git",
            FileAccess::ReadWrite,
            "global",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let home_s = home.to_string_lossy().into_owned();

        let stale_root = ResolvedRequestContext {
            paths: SandboxPaths::new("/tmp", &home_s, "/tmp"),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert_eq!(
            store
                .filesystem_allow_source(&objects_path, FileAccess::ReadWrite, &stale_root,)
                .await,
            Some(Verdict::allowed(VerdictSource::policy())),
            "git root inferred from path should match ./.git even when launcher project_root is \
             stale"
        );
    }

    #[tokio::test]
    async fn global_git_star_matches_pack_directory_execute_traverse() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("agent-sandbox");
        let home = dir.path().join("home");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(project_root.join(".git/objects/pack")).expect("git tree");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        let policy_path = policy_dir.join("policy.json");
        let pack_dir = project_root.join(".git/objects/pack");
        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            "./.git",
            FileAccess::ReadWrite,
            "global",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&root_s, &home_s, &root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert_eq!(
            store
                .filesystem_allow_source(&pack_dir, FileAccess::Execute, &ctx,)
                .await,
            Some(Verdict::allowed(VerdictSource::policy())),
            "opendir on .git/objects/pack is directory traverse (Execute), not binary exec"
        );
    }

    #[tokio::test]
    async fn session_deny_overrides_global_allow_for_git_objects() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(project_root.join(".git/objects/pack")).expect("git tree");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        let policy_path = policy_dir.join("policy.json");
        let pack_dir = project_root.join(".git/objects/pack");
        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            "./.git",
            FileAccess::ReadWrite,
            "global",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let session_id = "sandbox-git-session";
        let ui_session_id = "ui-git-session";

        {
            let (a, b) = tokio::net::UnixStream::pair().expect("unix stream pair");
            drop(a);
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, super::super::types::UiClient {
                session_id: ui_session_id.into(),
                writer: std::sync::Arc::new(tokio::sync::Mutex::new(b.into_split().1)),
            });
            inner.ui_context_by_session.insert(
                ui_session_id.into(),
                super::super::types::UiSessionContext {
                    cwd: Some(project_root.clone()),
                    home: Some(home.clone()),
                    project_root: Some(project_root.clone()),
                    sandbox_session_id: Some(session_id.into()),
                    owner_uid: Some(1000),
                    client_id: 1,
                },
            );
        }

        {
            let mut inner = store.inner.lock().await;
            let key = FilesystemRuleKey::new("./.git", FileAccess::ReadWrite);
            inner.session.filesystem().apply(
                crate::store::decisions::DecisionAction::Deny,
                ui_session_id,
                &key,
            );
            drop(inner);
        }

        let home_s = home.to_string_lossy().into_owned();
        let root_s = project_root.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&root_s, &home_s, &root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some(session_id.into()),
            package: None,
        };

        assert_eq!(
            store
                .filesystem_allow_source(&pack_dir, FileAccess::Read, &ctx,)
                .await,
            Some(Verdict::denied(VerdictSource::policy())),
            "session deny on ./.git blocks the tree even when global ./.git allows"
        );
    }

    #[tokio::test]
    async fn static_allow_does_not_override_concrete_deny() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox")).expect("policy dir");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let license_path = project_root.join("LICENSE");
        std::fs::write(&license_path, "license").expect("write license");

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy.filesystem.deny.push(FilesystemRule::new(
            license_path.clone(),
            FileAccess::All,
            "deny license",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-test".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner
                .sandbox_filesystem_static_allow
                .insert("sandbox:sandbox-test".into(), vec![FilesystemRule::new(
                    license_path.clone(),
                    FileAccess::All,
                    "static allow license",
                )]);
        }

        assert_eq!(
            store
                .filesystem_allow_source(&license_path, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy()))
        );
    }

    #[tokio::test]
    async fn static_allow_does_not_override_inode_deny() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox")).expect("policy dir");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let secret_path = project_root.join("secret.txt");
        std::fs::write(&secret_path, "secret").expect("write secret");
        let alias_path = project_root.join("alias.txt");
        std::fs::hard_link(&secret_path, &alias_path).expect("hardlink alias");

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy.filesystem.deny.push(FilesystemRule::new(
            secret_path.clone(),
            FileAccess::All,
            "deny secret",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-inode".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner
                .sandbox_filesystem_static_allow
                .insert("sandbox:sandbox-inode".into(), vec![FilesystemRule::new(
                    alias_path.clone(),
                    FileAccess::All,
                    "static allow alias",
                )]);
        }

        assert_eq!(
            store
                .filesystem_allow_source(&alias_path, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy()))
        );
    }

    #[tokio::test]
    async fn infrastructure_paths_are_allowed_without_merged_policy() {
        let dir = tempfile::tempdir().expect("create tempdir");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let ctx = ResolvedRequestContext::default();

        assert_eq!(
            store
                .filesystem_allow_source(
                    Path::new("/run/agent-sandbox/sandbox-policy.sock"),
                    FileAccess::ReadWrite,
                    &ctx,
                )
                .await,
            Some(Verdict::allowed(VerdictSource::Infrastructure))
        );
    }

    #[tokio::test]
    async fn static_allow_allows_when_no_deny_matches() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let license_path = project_root.join("LICENSE");
        std::fs::write(&license_path, "license").expect("write license");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-allow".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner
                .sandbox_filesystem_static_allow
                .insert("sandbox:sandbox-allow".into(), vec![FilesystemRule::new(
                    license_path.clone(),
                    FileAccess::Read,
                    "static allow license",
                )]);
        }

        assert_eq!(
            store
                .filesystem_allow_source(&license_path, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::allowed(VerdictSource::Static))
        );
    }

    #[tokio::test]
    async fn static_allow_glob_does_not_override_inode_deny() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox")).expect("policy dir");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let secret_path = project_root.join("secret.txt");
        std::fs::write(&secret_path, "secret").expect("write secret");
        let alias_path = project_root.join("writable/alias.txt");
        std::fs::create_dir_all(alias_path.parent().unwrap()).expect("writable dir");
        std::fs::hard_link(&secret_path, &alias_path).expect("hardlink alias");

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy.filesystem.deny.push(FilesystemRule::new(
            secret_path.clone(),
            FileAccess::All,
            "deny secret",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-glob".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner
                .sandbox_filesystem_static_allow
                .insert("sandbox:sandbox-glob".into(), vec![FilesystemRule::new(
                    project_root.join("writable/**"),
                    FileAccess::All,
                    "static allow writable tree",
                )]);
        }

        assert_eq!(
            store
                .filesystem_allow_source(&alias_path, FileAccess::Write, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy())),
            "static allow globs must not bypass inode deny checks"
        );
    }

    #[tokio::test]
    async fn static_allow_glob_matches_broad_paths_when_not_denied() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join("vendor/pkg")).expect("vendor dir");
        std::fs::create_dir_all(&home).expect("home");
        let nested_path = project_root.join("vendor/pkg/LICENSE");
        std::fs::write(&nested_path, "license").expect("write license");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-glob-allow".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner.sandbox_filesystem_static_allow.insert(
                "sandbox:sandbox-glob-allow".into(),
                vec![FilesystemRule::new(
                    project_root.join("vendor/**"),
                    FileAccess::Read,
                    "static allow vendor tree",
                )],
            );
        }

        assert_eq!(
            store
                .filesystem_allow_source(&nested_path, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::allowed(VerdictSource::Static))
        );
    }

    #[tokio::test]
    async fn deny_directory_follows_symlink_to_real_target_inode() {
        // A denied directory whose members are symlinks to files elsewhere
        // must deny reads of the resolved target path. fsmon forwards the
        // path after the kernel resolves the symlink, so a symlink cache hit
        // on the link inode would miss the request for the real file.
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let real = dir
            .path()
            .join("home/dotfiles/home/dot_config/agent-sandbox/packages");
        std::fs::create_dir_all(&real).expect("real target dir");
        std::fs::create_dir_all(home.join(".config/agent-sandbox/packages")).expect("alias dir");
        let secret = real.join("codex.json");
        std::fs::write(&secret, "policy").expect("write real policy file");
        std::os::unix::fs::symlink(
            &secret,
            home.join(".config/agent-sandbox/packages/codex.json"),
        )
        .expect("symlink into denied dir");

        // The declarative layer denies ~/.config/agent-sandbox, exactly as the
        // host-wide policy declares.
        let mut policy = Policy::default();
        policy.filesystem.deny.push(FilesystemRule::new(
            "~/.config/agent-sandbox".to_string(),
            FileAccess::All,
            "deny policy tree",
        ));
        atomic_write_policy(
            &dir.path().join("declarative.json"),
            &policy,
            Some(&home),
            None,
            None,
        )
        .expect("write declarative policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = real.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-symlink".into()),
            package: None,
        };

        assert_eq!(
            store
                .filesystem_allow_source(&secret, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy())),
            "reading the symlink target under a denied directory must be denied"
        );
    }

    #[tokio::test]
    async fn deny_walk_follows_symlinked_directories_and_terminates_cycles() {
        // A file reachable only through a symlinked directory inside a denied
        // tree must be denied: the walk follows the link to its target, so the
        // real file's inode is indexed. A self-referential link (`.config/
        // agent-sandbox/loop -> .config/agent-sandbox`) must terminate instead
        // of looping the walk.
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let denied = home.join(".config/agent-sandbox");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&denied).expect("denied dir");
        std::fs::create_dir_all(&outside).expect("outside dir");
        let notes = outside.join("notes.txt");
        std::fs::write(&notes, "plain").expect("outside file");
        std::os::unix::fs::symlink(&outside, denied.join("escape")).expect("dir symlink");
        // A self-referential link would send a naive recursive walk into a
        // loop; the visited-directory guard must terminate it.
        std::os::unix::fs::symlink(&denied, denied.join("loop")).expect("cycle symlink");
        std::os::unix::fs::symlink(".", denied.join("dot")).expect("self-cycle symlink");

        let mut policy = Policy::default();
        policy.filesystem.deny.push(FilesystemRule::new(
            "~/.config/agent-sandbox".to_string(),
            FileAccess::All,
            "deny policy tree",
        ));
        atomic_write_policy(
            &dir.path().join("declarative.json"),
            &policy,
            Some(&home),
            None,
            None,
        )
        .expect("write declarative policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = dir.path().to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-symlink-dir".into()),
            package: None,
        };

        // The file outside the denied tree is reachable only through the
        // symlinked directory. The walk follows the link, indexes the real
        // inode, and denies the read.
        assert_eq!(
            store
                .filesystem_allow_source(&notes, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy())),
            "a file reached through a symlinked directory must be denied"
        );
    }

    #[tokio::test]
    async fn deny_walk_preserves_distinct_access_levels_across_rules() {
        // Two deny rules where one directory is reached through a different
        // rule's symlink must not collapse into the narrower access. Rule A
        // denies `~/.config/a` read-only; rule B denies `~/.config/b`, which
        // symlinks to the same real directory, read-write. The write deny
        // must survive even though the shared directory was already walked
        // for rule A's read.
        let dir = tempfile::tempdir().expect("create tempdir");
        let home = dir.path().join("home");
        let real = dir.path().join("real-shared");
        std::fs::create_dir_all(&real).expect("real shared dir");
        let secret = real.join("notes.txt");
        std::fs::write(&secret, "secret").expect("write shared file");
        std::fs::create_dir_all(home.join(".config/a")).expect("a dir");
        std::fs::create_dir_all(home.join(".config/b")).expect("b dir");
        std::os::unix::fs::symlink(&real, home.join(".config/a/shared")).expect("a link");
        std::os::unix::fs::symlink(&real, home.join(".config/b/shared")).expect("b link");

        let mut policy = Policy::default();
        policy.filesystem.deny.push(FilesystemRule::new(
            "~/.config/a".to_string(),
            FileAccess::Read,
            "deny a read-only",
        ));
        policy.filesystem.deny.push(FilesystemRule::new(
            "~/.config/b".to_string(),
            FileAccess::Write,
            "deny b write",
        ));
        atomic_write_policy(
            &dir.path().join("declarative.json"),
            &policy,
            Some(&home),
            None,
            None,
        )
        .expect("write declarative policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = real.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-symlink-access".into()),
            package: None,
        };

        // Rule A (Read) denies the read.
        assert_eq!(
            store
                .filesystem_allow_source(&secret, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy()))
        );

        // Rule B (Write) must also deny the write even though rule A already
        // indexed the same shared directory, otherwise write access leaks.
        assert_eq!(
            store
                .filesystem_allow_source(&secret, FileAccess::Write, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy())),
            "a narrower write deny through a symlinked dir must survive an earlier read deny"
        );
    }

    #[tokio::test]
    async fn static_allow_broad_glob_does_not_override_concrete_deny() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let project_root = dir.path().join("repo");
        let home = dir.path().join("home");
        std::fs::create_dir_all(project_root.join(".agent-sandbox")).expect("policy dir");
        std::fs::create_dir_all(&project_root).expect("project root");
        std::fs::create_dir_all(&home).expect("home");
        let license_path = project_root.join("LICENSE");
        std::fs::write(&license_path, "license").expect("write license");

        let policy_path =
            trusted_project_policy_path(&project_root).expect("trusted project policy path");

        let mut policy = Policy::default();

        policy.filesystem.deny.push(FilesystemRule::new(
            license_path.clone(),
            FileAccess::All,
            "deny license",
        ));

        atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let project_root_s = project_root.to_string_lossy().into_owned();
        let home_s = home.to_string_lossy().into_owned();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new(&project_root_s, &home_s, &project_root_s),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-broad-glob-deny".into()),
            package: None,
        };

        {
            let mut inner = store.inner.lock().await;
            inner.sandbox_filesystem_static_allow.insert(
                "sandbox:sandbox-broad-glob-deny".into(),
                vec![FilesystemRule::new(
                    project_root.join("**"),
                    FileAccess::All,
                    "broad static allow repo tree",
                )],
            );
        }

        assert_eq!(
            store
                .filesystem_allow_source(&license_path, FileAccess::Read, &ctx)
                .await,
            Some(Verdict::denied(VerdictSource::policy())),
            "broad user-defined globs must not bypass concrete policy deny"
        );
    }

    async fn dbus_session_store() -> (super::super::types::PolicyStore, ResolvedRequestContext) {
        let dir = tempfile::tempdir().expect("create tempdir");

        let store = super::super::types::PolicyStore::new(crate::store::test_args(
            dir.path().join("sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_mins(1),
            false,
        ));

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/repo", "/home/user", "/repo"),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("sandbox-dbus".into()),
            package: None,
        };

        let (stream, _) = UnixStream::pair().expect("unix stream pair");
        let (_, writer) = stream.into_split();

        {
            let mut inner = store.inner.lock().await;
            inner.ui_clients.insert(1, UiClient {
                session_id: "general-ui".into(),
                writer: Arc::new(Mutex::new(writer)),
            });
            inner
                .ui_context_by_session
                .insert("general-ui".into(), UiSessionContext {
                    cwd: Some("/repo".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/repo".into()),
                    sandbox_session_id: Some("sandbox-dbus".into()),
                    ..Default::default()
                });
        }

        (store, ctx)
    }

    #[tokio::test]
    async fn dbus_session_allow_matches_exact_and_wildcard_targets() {
        let (store, ctx) = dbus_session_store().await;

        let concrete = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );

        let other = DbusTarget::session(
            "org.example.Other",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );

        // Exact match: concrete target stored, concrete query allowed.
        {
            let mut inner = store.inner.lock().await;
            inner
                .session
                .session_dbus_allow
                .insert("general-ui".into(), HashSet::from([concrete.clone()]));
        }

        assert!(store.session_dbus_allowed(&concrete, &ctx).await);
        assert!(!store.session_dbus_allowed(&other, &ctx).await);
        let wildcard = DbusTarget::session(
            "org.example.Service",
            "**",
            "*",
            "*",
            DbusMessageKind::MethodCall,
            "*",
            Vec::new(),
        );

        // Wildcard match: broad pattern stored, concrete query allowed, other bus
        // rejected.
        {
            let mut inner = store.inner.lock().await;
            inner
                .session
                .session_dbus_allow
                .insert("general-ui".into(), HashSet::from([wildcard]));
        }

        assert!(store.session_dbus_allowed(&concrete, &ctx).await);
        assert!(!store.session_dbus_allowed(&other, &ctx).await);
    }
}
