//! Policy store: context.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    FileAccess, FilesystemRule, Policy, ProcessIds, ResolvedRequestContext, SandboxPaths,
    home_from_uid, is_descendant_of, load_policy, merge_layers, peer_context,
    resolve_policy_write_path, sandbox_session_id_from_pid, trusted_project_policy_path,
};

use super::types::PolicyStore;
use crate::{
    error::PolicydError,
    store::types::{SandboxSessionRegistration, TrustedPeer},
    wire::MergeContext,
};

fn atomic_write_text(path: &Path, content: &str) -> std::io::Result<()> {
    let target = resolve_policy_write_path(path, None)?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = target.with_file_name(format!(
        "{}.tmp",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("agent-sandbox-export")
    ));

    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

impl PolicyStore {
    pub(crate) fn note_sandbox_peer(&self, peer: TrustedPeer, sandbox_session_id: &str) {
        if peer.pid == 0 || peer.uid == 0 {
            return;
        }

        let mut sessions = self
            .sandbox_sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        sessions
            .entry(sandbox_session_id.to_string())
            .and_modify(|reg| {
                // A session pre-registered by the wrapper (RegisterSandbox)
                // has no observed root pid yet. Adopt the first sandbox peer
                // as root only when the peer descends from the recorded
                // launcher. A same-uid attacker in another sandbox descends
                // from a different launcher and must never claim the
                // registration. Unattributed sessions (launcher_pid == 0)
                // keep the plain first-peer-claims-root model.
                if reg.root_pid == 0
                    && (reg.launcher_pid == 0 || is_descendant_of(reg.launcher_pid, peer.pid))
                {
                    reg.root_pid = peer.pid;
                }
            })
            .or_insert(SandboxSessionRegistration {
                root_pid: peer.pid,
                owner_uid: peer.uid,
                package: None,
                launcher_pid: 0,
                launcher_start_time_ticks: 0,
            });
    }

    /// Register a sandbox session's package identity.
    ///
    /// Inserts the registration when the session is unknown, and otherwise
    /// updates the owner uid and package while keeping the observed root pid.
    /// The package is immutable per session:
    /// once a registration carries a package, a different package is
    /// rejected with [`PolicydError::PackageImmutable`] and the stored
    /// registration is left unchanged.
    ///
    /// The registration is bound to the launcher: `launcher_pid` (the
    /// wrapper script's `$$`) must equal the real parent of the RPC peer
    /// (`peer_pid`, read from `/proc/<peer_pid>/stat`). This stops a
    /// same-uid attacker in another sandbox from pre-registering a guessed
    /// session id and later being adopted as that session's root.
    ///
    /// # Errors
    ///
    /// Returns [`PolicydError::InvalidPackageName`] when the package name is
    /// empty, contains a `/`, contains a `..` component, or contains control
    /// characters; returns [`PolicydError::PackageImmutable`] when the
    /// session already has a different package; returns
    /// [`PolicydError::InvalidLauncherPid`] when `launcher_pid` is 0 or does
    /// not match the peer's real parent.
    pub(crate) fn register_sandbox(
        &self,
        session_id: &str,
        package: &str,
        owner_uid: u32,
        launcher_pid: u32,
        peer_pid: u32,
    ) -> Result<(), PolicydError> {
        validate_package_name(package)?;

        if launcher_pid == 0 {
            return Err(PolicydError::InvalidLauncherPid);
        }

        let parent_pid = read_proc_ppid(peer_pid).ok_or(PolicydError::InvalidLauncherPid)?;

        if parent_pid != launcher_pid {
            return Err(PolicydError::InvalidLauncherPid);
        }

        let launcher_start_time_ticks =
            read_proc_start_time_ticks(launcher_pid).ok_or(PolicydError::InvalidLauncherPid)?;

        let mut sessions = self
            .sandbox_sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match sessions.get_mut(session_id) {
            Some(reg) => {
                if let Some(existing) = &reg.package
                    && existing != package
                {
                    return Err(PolicydError::PackageImmutable);
                }
                reg.package = Some(package.to_string());
                reg.owner_uid = owner_uid;
                reg.launcher_pid = launcher_pid;
                reg.launcher_start_time_ticks = launcher_start_time_ticks;
            }

            None => {
                sessions.insert(session_id.to_string(), SandboxSessionRegistration {
                    root_pid: 0,
                    owner_uid,
                    package: Some(package.to_string()),
                    launcher_pid,
                    launcher_start_time_ticks,
                });
            }
        }

        drop(sessions);
        Ok(())
    }

    /// Resolve an incoming RPC [`MergeContext`] into a fully attributed
    /// [`ResolvedRequestContext`]. For a caller that has not been sanitized
    /// upstream this is the policy entry point: when a `peer` is present the
    /// context is re-resolved from the verified `peer` (see
    /// [`Self::resolve_from_peer`]); without a peer the incoming paths are
    /// treated as trusted and only missing fields are enriched from the wire
    /// ids and session id.
    pub fn resolve_context_with_peer(
        &self,
        ctx: &MergeContext,
        peer: Option<TrustedPeer>,
    ) -> ResolvedRequestContext {
        let Some(peer) = peer else {
            return self.resolve_trusted_context(&ResolvedRequestContext::new(
                ctx.paths.clone(),
                ctx.ids,
                ctx.sandbox_session_id.clone(),
            ));
        };

        self.resolve_from_peer(ctx, peer)
    }

    /// Resolve a gate context without allowing root peer credentials to trust
    /// caller-supplied paths or session identifiers.
    pub(crate) fn resolve_gate_context_with_peer(
        &self,
        ctx: &MergeContext,
        peer: TrustedPeer,
    ) -> ResolvedRequestContext {
        self.resolve_from_peer_strict(ctx, peer)
    }

    /// Re-resolve a context that was already sanitized upstream by
    /// [`Self::resolve_from_peer`]. Internal store methods invoke this without
    /// a peer. The incoming paths are trusted and only missing fields are
    /// enriched from the verified pid and uid. This must never be reached with
    /// attacker-supplied wire paths. Those are overwritten at the dispatch
    /// boundary before any handler runs.
    ///
    /// Callers are policyd-side or host-side trusted (root helpers, internal
    /// store methods), so the package is adopted from the session
    /// registration by session id alone.
    pub(crate) fn resolve_trusted_context(
        &self,
        ctx: &ResolvedRequestContext,
    ) -> ResolvedRequestContext {
        let uid = ctx.ids.uid();
        let pid = ctx.ids.pid();
        let mut sandbox_session_id = ctx.sandbox_session_id.clone();

        if sandbox_session_id.is_none()
            && let Some(pid) = pid
        {
            sandbox_session_id = sandbox_session_id_from_pid(pid);
        }

        let mut cwd = ctx.paths.cwd_path();
        let mut home = ctx.paths.home_path();

        if home.is_none() {
            home = uid.and_then(|u| home_from_uid(Some(u))).map(PathBuf::from);
        }

        if cwd.is_none()
            && let Some(pid) = pid
        {
            cwd = peer_context(pid, uid).cwd;
        }

        // Root and internal callers are policyd-side trusted: there is no
        // peer uid to check, so the package is adopted straight from the
        // session registration.
        let package = sandbox_session_id.as_ref().and_then(|id| {
            self.sandbox_sessions
                .read()
                .ok()
                .and_then(|sessions| sessions.get(id).cloned())
                .and_then(|reg| reg.package)
        });

        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(cwd, home, None),
            ids: ProcessIds::from_options(pid, uid),
            sandbox_session_id,
            package,
        }
    }

    fn resolve_from_peer(&self, ctx: &MergeContext, peer: TrustedPeer) -> ResolvedRequestContext {
        self.resolve_from_peer_inner(ctx, peer, true)
    }

    fn resolve_from_peer_strict(
        &self,
        ctx: &MergeContext,
        peer: TrustedPeer,
    ) -> ResolvedRequestContext {
        self.resolve_from_peer_inner(ctx, peer, false)
    }

    fn resolve_from_peer_inner(
        &self,
        ctx: &MergeContext,
        peer: TrustedPeer,
        allow_root_wire_context: bool,
    ) -> ResolvedRequestContext {
        // Host-side helpers (fsmon, syscall-broker) connect to the sandbox
        // socket as root. Their wire ctx was populated at spawn time (or carries
        // the tracee pid); peer-based home/cwd would be wrong and breaks UI spawn.
        if allow_root_wire_context && peer.uid == 0 {
            return self.resolve_trusted_context(&ResolvedRequestContext::new(
                ctx.paths.clone(),
                ctx.ids,
                ctx.sandbox_session_id.clone(),
            ));
        }

        let peer = Some(peer);
        let peer_pid = peer.map(|p| p.pid);
        let trusted_uid = peer.and_then(|p| (p.uid > 0).then_some(p.uid));

        let verified_pid = match (ctx.ids.pid().filter(|&p| p > 0), peer) {
            // syscall-arm: the broker parent connects on behalf of the tracee
            // during emulated connects; prefer the wire tracee pid when it is
            // the peer or a direct descendant (fs-arm after fork).
            (Some(wire_pid), Some(p)) if is_descendant_of(p.pid, wire_pid) => Some(wire_pid),
            (wire_pid, None) => wire_pid,
            (_, Some(p)) if p.pid > 0 => Some(p.pid),
            _ => None,
        };

        let trusted_uid = trusted_uid.or_else(|| ctx.ids.uid());
        let mut sandbox_session_id = if allow_root_wire_context {
            ctx.sandbox_session_id.clone()
        } else {
            None
        };

        if sandbox_session_id.is_none()
            && let Some(pid) = verified_pid
        {
            sandbox_session_id = sandbox_session_id_from_pid(pid);
        }

        // Never trust wire home/cwd/project_root from sandbox peers — a
        // compromised agent can forge them on the sandbox socket. Use the
        // peer uid's passwd home and launcher env vars from /proc instead.
        let home = trusted_uid
            .and_then(|u| home_from_uid(Some(u)))
            .map(PathBuf::from);

        let mut cwd = None;
        let mut package = None;

        if let Some(pid) = verified_pid {
            let registration = sandbox_session_id.as_ref().and_then(|id| {
                self.sandbox_sessions
                    .read()
                    .ok()
                    .and_then(|sessions| sessions.get(id).cloned())
            });

            let pid_allowed = registration.as_ref().is_none_or(|reg| {
                // Only a peer inside the sandbox's own process tree (a
                // strict descendant of the recorded launcher) may inherit
                // the package. The launcher itself and same-uid host
                // processes above it (the user's shell, the agent client
                // that spawned the sandbox) stay excluded, so a forged
                // session id cannot claim a foreign package.
                let peer_in_sandbox = reg.launcher_pid > 0
                    && peer_pid.is_some_and(|pp| {
                        pp != reg.launcher_pid && is_descendant_of(reg.launcher_pid, pp)
                    });

                peer_in_sandbox
                    && (reg.root_pid == pid
                        || is_descendant_of(reg.root_pid, pid)
                        // The syscall broker is the parent of the session
                        // root (the fs-arm entry process), never its
                        // descendant, and its CheckResource carries the
                        // tracee pid, which lives beside the root rather
                        // than under it, so neither root-based check can
                        // pass. The authenticated peer's host pid is the
                        // broker: accept it when it is an ancestor of the
                        // adopted root.
                        || peer_pid.is_some_and(|pp| is_descendant_of(pp, reg.root_pid)))
            });

            // Package attribution is unforgeable: the wire session id alone
            // is attacker-controlled, so the package is only adopted when
            // the requesting peer owns the registration (same uid) and is
            // the session root or one of its descendants.
            if pid_allowed
                && let Some(reg) = &registration
                && reg.owner_uid == trusted_uid.unwrap_or(0)
            {
                package.clone_from(&reg.package);
            }

            if pid_allowed {
                cwd = peer_context(pid, trusted_uid).cwd;
            }
        }

        let ids = ProcessIds::from_options(verified_pid, trusted_uid);

        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(cwd, home, None),
            ids,
            sandbox_session_id,
            package,
        }
    }

    /// Merge every policy layer visible to this request.
    ///
    /// Layer order, lowest priority first:
    /// 1. `self.args.declarative` (NixOS configuration).
    /// 2. The per-package base file (`--package-declarative NAME=PATH`) and the
    ///    home extension file `~/.config/agent-sandbox/packages/<name>.json`
    ///    for an attributed session.
    /// 3. `~/.config/agent-sandbox/policy.json` (trusted user policy).
    /// 4. The trusted per-project policy file under
    ///    `<project_root>/.agent-sandbox/policy.json`
    /// 5. The package-specific project file
    ///    `<project_root>/.agent-sandbox/packages/<name>.json`
    ///
    /// Layers are merged with deny-wins semantics: any non-empty `deny`
    /// rule shadows the corresponding `allow` rule across the merged set.
    pub fn merged_for(&self, ctx: &ResolvedRequestContext) -> Policy {
        let key = self.merged_cache_key(ctx);

        if let Ok(cache) = self.merged_cache.lock()
            && let Some(policy) = cache.get(&key)
        {
            return policy;
        }

        let policy = self.build_merged_for(ctx);

        if let Ok(mut cache) = self.merged_cache.lock() {
            cache.insert(key, policy.clone());
        }

        policy
    }

    fn merged_cache_key(&self, ctx: &ResolvedRequestContext) -> super::types::MergedCacheKey {
        let ctx = ctx.clone();
        let home_path = ctx.paths.home().map(Path::new);
        let project_root_path = ctx.paths.project_root().map(Path::new);

        let package = ctx
            .package
            .as_deref()
            .filter(|name| validate_package_name(name).is_ok());

        let home_policy = home_path.map(|home| {
            home.join(".config")
                .join("agent-sandbox")
                .join("policy.json")
        });

        let project_policy =
            project_root_path.and_then(|root| trusted_project_policy_path(root).ok());

        let (package_base, package_home, package_project) = package
            .map(|name| self.package_layer_paths(name, home_path, project_root_path))
            .unwrap_or_default();

        super::types::MergedCacheKey {
            home: home_path.map(Path::to_path_buf),
            project_root: project_root_path.map(Path::to_path_buf),
            declarative_mtime: policy_file_mtime(&self.args.declarative),
            home_policy_mtime: home_policy.as_deref().and_then(policy_file_mtime),
            project_policy_mtime: project_policy.as_deref().and_then(policy_file_mtime),
            package: ctx.package,
            package_base_mtime: package_base.as_deref().and_then(policy_file_mtime),
            package_home_mtime: package_home.as_deref().and_then(policy_file_mtime),
            package_project_mtime: package_project.as_deref().and_then(policy_file_mtime),
        }
    }

    fn build_merged_for(&self, ctx: &ResolvedRequestContext) -> Policy {
        let ctx = ctx.clone();
        let home_path = ctx.paths.home().map(Path::new);
        let project_root_path = ctx.paths.project_root().map(Path::new);

        let package = ctx
            .package
            .as_deref()
            .filter(|name| validate_package_name(name).is_ok());

        let mut layers: Vec<Policy> = Vec::new();
        layers.push(load_policy(&self.args.declarative, home_path, None));

        // Package layer: NixOS-declared base file, then the user-writable
        // home extension file. Merged between the global declarative layer
        // and the user policy, so a package rule cannot override a
        // NixOS-declared deny (deny-wins across all layers).
        let (package_base, package_home, package_project) = package
            .map(|name| self.package_layer_paths(name, home_path, project_root_path))
            .unwrap_or_default();

        if let Some(base) = &package_base {
            layers.push(load_policy(base, home_path, None));
        }

        if let Some(ext) = &package_home {
            layers.push(load_policy(ext, home_path, None));
        }

        if let Some(home) = home_path {
            let home_policy = home
                .join(".config")
                .join("agent-sandbox")
                .join("policy.json");

            layers.push(load_policy(&home_policy, home_path, None));

            if let Some(root) = project_root_path
                && let Ok(trusted) = trusted_project_policy_path(root)
            {
                layers.push(load_policy(&trusted, home_path, project_root_path));
            }
        }

        // The package-specific project file merges last, within the project
        // layer, and only for sessions attributed to this package in this
        // project.
        if let Some(pkg_project) = &package_project {
            layers.push(load_policy(pkg_project, home_path, project_root_path));
        }

        let mut merged = merge_layers(&layers);

        // Implicit deny-all for trusted policy files. Hides the policy from
        // the sandboxed agent so it cannot learn pre-approved paths and
        // craft bypasses. The DenyInodeCache fingerprints these by inode,
        // so hardlinks and symlink targets at any path are caught.
        for path in [
            Some(self.args.declarative.clone()),
            home_path.map(|home| {
                home.join(".config")
                    .join("agent-sandbox")
                    .join("policy.json")
            }),
            package_base,
            package_home,
            package_project,
        ]
        .into_iter()
        .flatten()
        {
            merged.filesystem.deny.push(FilesystemRule {
                path,
                access: FileAccess::All,
                comment: Some("trusted policy file".into()),
            });
        }

        if let Some(root) = project_root_path
            && let Ok(trusted) = trusted_project_policy_path(root)
        {
            merged.filesystem.deny.push(FilesystemRule {
                path: trusted,
                access: FileAccess::All,
                comment: Some("trusted policy file".into()),
            });
        }

        merged
    }

    /// Paths of the three per-package policy sources for `package`.
    ///
    /// Returns `(base, home_extension, package_project)`, where the base
    /// comes from the `--package-declarative` args map and the extension and
    /// project files are derived from the resolved home and project root.
    fn package_layer_paths(
        &self,
        package: &str,
        home_path: Option<&Path>,
        project_root_path: Option<&Path>,
    ) -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
        let base = self
            .args
            .package_declarative
            .iter()
            .find(|(name, _)| name == package)
            .map(|(_, path)| path.clone());

        let home_ext = home_path.map(|home| {
            home.join(".config")
                .join("agent-sandbox")
                .join("packages")
                .join(format!("{package}.json"))
        });

        let project = project_root_path.map(|root| {
            root.join(".agent-sandbox")
                .join("packages")
                .join(format!("{package}.json"))
        });

        (base, home_ext, project)
    }

    /// Load merged policy from async handlers without blocking the Tokio
    /// runtime.
    pub(crate) fn merged_for_worker(&self, ctx: &ResolvedRequestContext) -> Policy {
        let ctx = ctx.clone();

        if tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        {
            tokio::task::block_in_place(|| self.merged_for(&ctx))
        } else {
            self.merged_for(&ctx)
        }
    }

    pub(crate) fn invalidate_merged_policy_cache(&self) {
        if let Ok(mut cache) = self.merged_cache.lock() {
            cache.entries.clear();
        }
    }

    /// Export merged policy to JSON and optionally Nix-format files.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if policy files cannot be written (serialization,
    /// directory creation, or file write failures).
    pub fn export_policy_files(&self, paths: SandboxPaths) -> std::io::Result<()> {
        let ctx = ResolvedRequestContext {
            paths,
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        let merged = self.merged_for(&ctx);

        atomic_write_text(
            &self.args.export_json,
            &(serde_json::to_string_pretty(&merged)? + "\n"),
        )?;

        if let Some(nix_path) = &self.args.export_nix {
            let mut lines = vec![
                "# Generated by agent-sandbox-policyd.".to_string(),
                "{".to_string(),
                "  network.direct.allow = [".to_string(),
            ];

            for rule in &merged.network.direct.allow {
                let host = rule.host.replace('"', "\\\"");

                lines.push(format!(
                    "    {{ host = \"{host}\"; port = {}; }}",
                    rule.port
                ));
            }

            lines.push("  ];".to_string());
            lines.push("  network.direct.deny = [".to_string());

            for rule in &merged.network.direct.deny {
                let host = rule.host.replace('"', "\\\"");

                lines.push(format!(
                    "    {{ host = \"{host}\"; port = {}; }}",
                    rule.port
                ));
            }

            lines.extend(["  ];".to_string(), "}".to_string(), String::new()]);
            atomic_write_text(nix_path, &lines.join("\n"))?;
        }

        Ok(())
    }
}

impl PolicyStore {
    pub(crate) fn authenticates_context_adapter(
        &self,
        sandbox_session_id: &str,
        peer: TrustedPeer,
    ) -> bool {
        self.sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(sandbox_session_id)
            .is_some_and(|registration| {
                registration.owner_uid == peer.uid
                    && registration.launcher_pid == peer.pid
                    && registration.launcher_start_time_ticks != 0
                    && read_proc_start_time_ticks(peer.pid)
                        == Some(registration.launcher_start_time_ticks)
            })
    }
}

fn validate_package_name(package: &str) -> Result<(), PolicydError> {
    if package.is_empty() {
        return Err(PolicydError::InvalidPackageName(
            "package name must not be empty".into(),
        ));
    }

    if package.contains('/') {
        return Err(PolicydError::InvalidPackageName(format!(
            "{package:?} must not contain '/'"
        )));
    }

    if package.split('/').any(|component| component == "..") {
        return Err(PolicydError::InvalidPackageName(format!(
            "{package:?} must not contain a '..' component"
        )));
    }

    if package.chars().any(char::is_control) {
        return Err(PolicydError::InvalidPackageName(format!(
            "{package:?} must not contain control characters"
        )));
    }

    Ok(())
}

/// Read a process's real parent pid from `/proc/<pid>/stat`.
///
/// The comm field (parenthesised, may contain spaces) is skipped by taking
/// everything after the last `)`. The state field is then skipped, and the
/// next field is the parent pid.
fn read_proc_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    let mut fields = stat[end + 1..].split_whitespace();
    fields.next()?;
    fields.next()?.parse().ok()
}

fn read_proc_start_time_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    stat[end + 1..].split_whitespace().nth(19)?.parse().ok()
}

fn policy_file_mtime(path: &Path) -> Option<super::types::MtimeKey> {
    let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
    let duration = modified.duration_since(std::time::UNIX_EPOCH).ok()?;

    Some(super::types::MtimeKey {
        secs: duration.as_secs(),
        nanos: duration.subsec_nanos(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agent_sandbox_core::SudoRule;

    use super::*;

    fn test_store() -> PolicyStore {
        PolicyStore::new(crate::store::test_args(
            "/tmp/test.sock".into(),
            "/tmp/test-sandbox.sock".into(),
            "/tmp/declarative.json".into(),
            "/tmp/export.json".into(),
            Duration::from_secs(30),
            true,
        ))
    }

    /// `(launcher_pid, peer_pid)` that passes the launcher binding check:
    /// the test process is the peer and its real parent is the launcher.
    fn launcher_pair() -> (u32, u32) {
        let pid = std::process::id();
        let parent = read_proc_ppid(pid).expect("parent of the test process");
        (parent, pid)
    }

    #[test]
    fn atomic_write_text_preserves_symlink() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let real_dir = tmp.path().join("dotfiles/home/dot_config/agent-sandbox");
        let link_dir = tmp.path().join("home/.config/agent-sandbox");
        std::fs::create_dir_all(&real_dir).expect("create real dir");
        std::fs::create_dir_all(&link_dir).expect("create link dir");
        let real = real_dir.join("policy.json");
        let link = link_dir.join("policy.json");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink");

        atomic_write_text(
            &link, "{}
",
        )
        .expect("write policy via symlink");

        assert!(link.is_symlink());

        assert_eq!(
            std::fs::read_to_string(real).expect("read policy file"),
            "{}\n"
        );
    }

    #[test]
    fn sandbox_peer_ignores_forged_wire_paths() {
        let store = test_store();
        let uid = nix::unistd::getuid().as_raw();
        let real_home = home_from_uid(Some(uid)).map(PathBuf::from);

        let wire = MergeContext {
            paths: SandboxPaths::from_wire(
                Some(PathBuf::from("/attacker/cwd")),
                Some(PathBuf::from("/attacker/home")),
                Some(PathBuf::from("/attacker/project")),
            ),
            ids: ProcessIds::from_options(Some(0), Some(uid)),
            sandbox_session_id: None,
        };

        let resolved = store.resolve_context_with_peer(&wire, Some(TrustedPeer { pid: 0, uid }));
        assert_eq!(resolved.paths.home_path(), real_home);

        assert_ne!(
            resolved.paths.home_path(),
            Some(PathBuf::from("/attacker/home"))
        );

        assert_eq!(resolved.paths.project_root_path(), None);
    }

    #[test]
    fn root_helper_preserves_display_paths_but_not_project_root() {
        let store = test_store();

        let wire = MergeContext {
            paths: SandboxPaths::from_wire(
                Some(PathBuf::from("/home/user")),
                Some(PathBuf::from("/home/user")),
                Some(PathBuf::from("/home/user/project")),
            ),
            ids: ProcessIds::from_options(None, None),
            sandbox_session_id: Some("sandbox-session".into()),
        };

        let resolved = store.resolve_context_with_peer(
            &wire,
            Some(TrustedPeer {
                pid: 42_000,
                uid: 0,
            }),
        );

        assert_eq!(
            resolved.paths.home_path(),
            Some(PathBuf::from("/home/user"))
        );

        assert_eq!(resolved.paths.cwd_path(), Some(PathBuf::from("/home/user")));

        assert_eq!(resolved.paths.project_root_path(), None);

        assert_eq!(
            resolved.sandbox_session_id.as_deref(),
            Some("sandbox-session")
        );
    }

    #[test]
    fn wire_tracee_pid_preferred_over_broker_peer() {
        let store = test_store();
        let pid = std::process::id();

        let parent = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let end = stat.rfind(')')?;
                let mut fields = stat[end + 1..].split_whitespace();
                fields.next()?;
                fields.next()?.parse().ok()
            })
            .expect("parent pid");

        let wire = MergeContext {
            paths: SandboxPaths::default(),
            ids: ProcessIds::from_options(Some(pid), Some(1000)),
            sandbox_session_id: None,
        };

        let resolved = store.resolve_context_with_peer(
            &wire,
            Some(TrustedPeer {
                pid: parent,
                uid: 1000,
            }),
        );

        assert_eq!(resolved.ids.pid(), Some(pid));
    }

    #[test]
    fn broker_peer_above_adopted_root_is_attributed() {
        // The syscall broker is the parent of the session root (the fs-arm
        // entry process). Under a pid namespace the wire tracee pid is
        // jail-local, so the broker's host peer pid is used for
        // verification, and the descendant check alone would reject it.
        let store = test_store();
        let uid = nix::unistd::getuid().as_raw();
        let root_pid = std::process::id();
        let broker_pid = read_proc_ppid(root_pid).expect("parent of the test process");
        let launcher_pid = read_proc_ppid(broker_pid).expect("grandparent of the test process");

        {
            let mut sessions = store
                .sandbox_sessions
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sessions.insert("broker-session".into(), SandboxSessionRegistration {
                root_pid,
                owner_uid: uid,
                package: Some("codex".into()),
                launcher_pid,
                launcher_start_time_ticks: read_proc_start_time_ticks(launcher_pid).unwrap(),
            });
        }

        // The wire pid is a jail-local tracee pid (unresolvable from the
        // host); the peer is the broker, an ancestor of the adopted root
        // that descends from the recorded launcher.
        let wire = MergeContext {
            paths: SandboxPaths::default(),
            ids: ProcessIds::from_options(Some(2_147_483_647), None),
            sandbox_session_id: Some("broker-session".into()),
        };

        let resolved = store.resolve_context_with_peer(
            &wire,
            Some(TrustedPeer {
                pid: broker_pid,
                uid,
            }),
        );

        assert_eq!(
            resolved.package.as_deref(),
            Some("codex"),
            "the broker must be attributed to its session"
        );
    }

    #[test]
    fn broker_tracee_beside_root_is_attributed() {
        // The broker's CheckResource carries the tracee pid, which descends
        // from the broker but lives beside the adopted root (the fs-arm)
        // rather than under it. The verification must use the authenticated
        // peer's host pid, not the tracee pid.
        let store = test_store();
        let uid = nix::unistd::getuid().as_raw();
        let root_pid = std::process::id();
        let peer_pid = read_proc_ppid(root_pid).expect("parent of the test process");
        let launcher_pid = read_proc_ppid(peer_pid).expect("grandparent of the test process");

        {
            let mut sessions = store
                .sandbox_sessions
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sessions.insert("broker-tracee-session".into(), SandboxSessionRegistration {
                root_pid,
                owner_uid: uid,
                package: Some("codex".into()),
                launcher_pid,
                launcher_start_time_ticks: read_proc_start_time_ticks(launcher_pid).unwrap(),
            });
        }

        // The wire tracee pid is the peer itself (a descendant of the peer,
        // but not of the adopted root).
        let wire = MergeContext {
            paths: SandboxPaths::default(),
            ids: ProcessIds::from_options(Some(peer_pid), None),
            sandbox_session_id: Some("broker-tracee-session".into()),
        };

        let resolved =
            store.resolve_context_with_peer(&wire, Some(TrustedPeer { pid: peer_pid, uid }));

        assert_eq!(
            resolved.package.as_deref(),
            Some("codex"),
            "the broker's tracee must be attributed to its session"
        );
    }

    #[tokio::test]
    async fn declarative_policy_is_denied_to_sandbox_requests() {
        let store = test_store();

        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/home/user/project", "/home/user", "/home/user/project"),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
            package: None,
        };

        assert!(
            store
                .filesystem_policy_denied(
                    Path::new("/tmp/declarative.json"),
                    FileAccess::Read,
                    &ctx,
                )
                .await,
            "sandbox reads of declarative policy must be denied"
        );
    }

    #[test]
    fn forged_home_does_not_load_policy_from_attacker_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_home = tmp.path().join("home/user");
        let evil = tmp.path().join("evil");
        std::fs::create_dir_all(real_home.join(".config/agent-sandbox")).expect("real config");
        std::fs::create_dir_all(evil.join(".config/agent-sandbox")).expect("evil config");

        std::fs::write(
            real_home.join(".config/agent-sandbox/policy.json"),
            r#"{"network":{"direct":{"allow":[],"deny":[]},"http":{"allow":[],"deny":[]}},"sudo":{"allow":[],"deny":[]},"filesystem":{"allow":[],"deny":[]},"resources":{"allow":[],"deny":[]}}"#,
        )
        .expect("real policy");

        std::fs::write(
            evil.join(".config/agent-sandbox/policy.json"),
            serde_json::to_string(&Policy {
                sudo: agent_sandbox_core::SudoSection {
                    allow: vec![SudoRule::new(vec!["id".into()], "evil")],
                    deny: vec![],
                },
                ..Policy::default()
            })
            .expect("serialize"),
        )
        .expect("evil policy");

        let store = test_store();
        let uid = nix::unistd::getuid().as_raw();

        let forged = MergeContext {
            paths: SandboxPaths::from_wire(Some(evil.clone()), Some(evil.clone()), Some(evil)),
            ids: ProcessIds::from_options(Some(0), Some(uid)),
            sandbox_session_id: None,
        };

        let resolved = store.resolve_context_with_peer(&forged, Some(TrustedPeer { pid: 0, uid }));
        let merged = store.merged_for(&resolved);

        assert!(
            merged.sudo.allow.is_empty(),
            "forged home must not load attacker sudo allow rules"
        );
    }

    #[test]
    fn register_sandbox_stores_package_and_owner() {
        let store = test_store();
        let (launcher, peer) = launcher_pair();

        store
            .register_sandbox("sandbox-a", "omp", 1000, launcher, peer)
            .expect("register sandbox");

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions
            .get("sandbox-a")
            .expect("registration must exist after register_sandbox");

        assert_eq!(reg.package.as_deref(), Some("omp"));
        assert_eq!(reg.owner_uid, 1000);
        drop(sessions);
    }

    #[test]
    fn register_sandbox_stores_launcher_pid() {
        let store = test_store();
        let (launcher, peer) = launcher_pair();

        store
            .register_sandbox("sandbox-a", "omp", 1000, launcher, peer)
            .expect("register sandbox");

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions
            .get("sandbox-a")
            .expect("registration must exist after register_sandbox");

        assert_eq!(
            reg.launcher_pid, launcher,
            "registration must record the verified launcher pid"
        );

        drop(sessions);
    }

    #[test]
    fn register_sandbox_rejects_mismatched_launcher_pid() {
        let store = test_store();
        let (launcher, peer) = launcher_pair();
        let zero = store.register_sandbox("sandbox-a", "omp", 1000, 0, peer);

        assert!(
            matches!(zero, Err(PolicydError::InvalidLauncherPid)),
            "launcher pid 0 must be rejected, got: {zero:?}"
        );

        let wrong =
            store.register_sandbox("sandbox-a", "omp", 1000, launcher.wrapping_add(1), peer);

        assert!(
            matches!(wrong, Err(PolicydError::InvalidLauncherPid)),
            "a launcher pid that is not the peer's real parent must be rejected, got: {wrong:?}"
        );

        let missing_peer = store.register_sandbox("sandbox-a", "omp", 1000, launcher, u32::MAX);

        assert!(
            matches!(missing_peer, Err(PolicydError::InvalidLauncherPid)),
            "a peer pid without a /proc entry must be rejected, got: {missing_peer:?}"
        );

        assert!(
            store
                .sandbox_sessions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get("sandbox-a")
                .is_none(),
            "rejected registrations must not create a session"
        );
    }

    #[test]
    fn note_sandbox_peer_adopts_only_launcher_descendants() {
        let store = test_store();
        let (launcher, peer) = launcher_pair();

        store
            .register_sandbox("sandbox-a", "omp", 1000, launcher, peer)
            .expect("register sandbox");

        // A peer that is not a descendant of the launcher (init, pid 1)
        // must not be adopted as the root of a pre-registered session.
        store.note_sandbox_peer(TrustedPeer { pid: 1, uid: 1000 }, "sandbox-a");

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions.get("sandbox-a").expect("registration exists");

        assert_eq!(
            reg.root_pid, 0,
            "a non-descendant peer must not claim a pre-registered session's root"
        );

        drop(sessions);

        // A real descendant (a child of the launcher) is adopted as root.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a child of the test process");

        let child_pid = child.id();

        store.note_sandbox_peer(
            TrustedPeer {
                pid: child_pid,
                uid: 1000,
            },
            "sandbox-a",
        );

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions.get("sandbox-a").expect("registration exists");

        assert_eq!(
            reg.root_pid, child_pid,
            "a descendant of the launcher must be adopted as the session root"
        );

        drop(sessions);
        child.kill().expect("kill child");
        let _ = child.wait();
    }

    #[test]
    fn register_sandbox_rejects_different_package() {
        let store = test_store();
        let (launcher, peer) = launcher_pair();

        store
            .register_sandbox("sandbox-a", "omp", 1000, launcher, peer)
            .expect("first registration");

        let result = store.register_sandbox("sandbox-a", "other", 1000, launcher, peer);

        assert!(
            matches!(result, Err(PolicydError::PackageImmutable)),
            "second registration with a different package must be rejected, got: {result:?}"
        );

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions.get("sandbox-a").expect("registration exists");

        assert_eq!(
            reg.package.as_deref(),
            Some("omp"),
            "stored package must be unchanged after rejected re-registration"
        );

        drop(sessions);
    }

    #[test]
    fn register_sandbox_same_package_re_registers() {
        let store = test_store();
        let (launcher, peer) = launcher_pair();

        store
            .register_sandbox("sandbox-a", "omp", 1000, launcher, peer)
            .expect("first registration");

        store
            .register_sandbox("sandbox-a", "omp", 2000, launcher, peer)
            .expect("same-package re-registration must succeed");

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions.get("sandbox-a").expect("registration exists");
        assert_eq!(reg.package.as_deref(), Some("omp"));
        assert_eq!(reg.owner_uid, 2000);
        drop(sessions);
    }

    #[test]
    fn register_sandbox_rejects_invalid_package_names() {
        let store = test_store();
        let (launcher, peer) = launcher_pair();

        for package in ["", "a/b", "..", "a/../b", "bad\nname"] {
            let result = store.register_sandbox("sandbox-a", package, 1000, launcher, peer);

            assert!(
                matches!(result, Err(PolicydError::InvalidPackageName(_))),
                "package name {package:?} must be rejected, got: {result:?}"
            );
        }

        assert!(
            store
                .sandbox_sessions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get("sandbox-a")
                .is_none(),
            "rejected registrations must not create a session"
        );
    }

    #[test]
    fn note_sandbox_peer_preserves_package_and_adopts_root() {
        let store = test_store();
        let (launcher, pid) = launcher_pair();

        store
            .register_sandbox("sandbox-a", "omp", 1000, launcher, pid)
            .expect("register sandbox");

        store.note_sandbox_peer(TrustedPeer { pid, uid: 1000 }, "sandbox-a");

        let sessions = store
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let reg = sessions.get("sandbox-a").expect("registration exists");

        assert_eq!(
            reg.package.as_deref(),
            Some("omp"),
            "note_sandbox_peer must not clobber the registered package"
        );

        assert_eq!(
            reg.root_pid, pid,
            "note_sandbox_peer must adopt the first sandbox peer as the session root"
        );

        drop(sessions);
    }

    fn package_store(dir: &tempfile::TempDir, packages: &[(&str, PathBuf)]) -> PolicyStore {
        let mut args = crate::store::test_args(
            dir.path().join("test.sock"),
            dir.path().join("test-sandbox.sock"),
            dir.path().join("declarative.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        );

        args.package_declarative = packages
            .iter()
            .map(|(name, path)| (name.to_string(), path.clone()))
            .collect();

        PolicyStore::new(args)
    }

    fn write_fs_policy(path: &Path, allow: &[&str], deny: &[&str]) {
        let policy = Policy {
            filesystem: agent_sandbox_core::FilesystemSection {
                allow: allow
                    .iter()
                    .map(|p| FilesystemRule::new(p, FileAccess::Read, "test"))
                    .collect(),
                deny: deny
                    .iter()
                    .map(|p| FilesystemRule::new(p, FileAccess::Read, "test"))
                    .collect(),
            },
            ..Default::default()
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create policy dir");
        }

        std::fs::write(
            path,
            serde_json::to_string(&policy).expect("serialize policy"),
        )
        .expect("write policy");
    }

    fn omp_context(
        home: PathBuf,
        project: PathBuf,
        package: Option<&str>,
    ) -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(Some(project.clone()), Some(home), Some(project)),
            ids: ProcessIds::default(),
            sandbox_session_id: Some("s1".into()),
            package: package.map(str::to_string),
        }
    }

    fn fs_allowed(merged: &Policy, path: &str) -> bool {
        merged
            .filesystem
            .allow
            .iter()
            .any(|r| r.path == Path::new(path) && r.access == FileAccess::Read)
    }

    fn fs_denied(merged: &Policy, path: &str) -> bool {
        merged
            .filesystem
            .deny
            .iter()
            .any(|r| r.path == Path::new(path))
    }

    #[test]
    fn attributed_session_merges_home_extension_allow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let project = dir.path().join("repo");
        let base = dir.path().join("omp-base.json");
        write_fs_policy(&dir.path().join("declarative.json"), &[], &[]);
        write_fs_policy(&base, &["/granted/base"], &[]);

        write_fs_policy(
            &home.join(".config/agent-sandbox/packages/omp.json"),
            &["/granted/home-ext"],
            &[],
        );

        let store = package_store(&dir, &[("omp", base)]);
        let merged = store.merged_for(&omp_context(home, project, Some("omp")));

        assert!(
            fs_allowed(&merged, "/granted/base"),
            "package base file must load for an attributed session"
        );

        assert!(
            fs_allowed(&merged, "/granted/home-ext"),
            "home extension file must load for an attributed session"
        );
    }

    #[test]
    fn package_merge_order_and_deny_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let project = dir.path().join("repo");

        // Layer order, lowest priority first: declarative, package base,
        // package home extension, user, project shared, package project.
        // Deny-wins: any deny shadows the matching allow from any layer.
        write_fs_policy(&dir.path().join("declarative.json"), &[], &["/d-global"]);

        let base = dir.path().join("omp-base.json");
        write_fs_policy(&base, &["/d-global", "/granted/base"], &["/d-package"]);

        write_fs_policy(
            &home.join(".config/agent-sandbox/packages/omp.json"),
            &["/d-global", "/d-package", "/granted/ext"],
            &["/d-user"],
        );

        write_fs_policy(
            &home.join(".config/agent-sandbox/policy.json"),
            &["/d-user", "/granted/user"],
            &["/d-project"],
        );

        write_fs_policy(
            &project.join(".agent-sandbox/policy.json"),
            &["/d-project", "/granted/project"],
            &[],
        );

        write_fs_policy(
            &project.join(".agent-sandbox/packages/omp.json"),
            &["/granted/pkg-project"],
            &[],
        );

        let store = package_store(&dir, &[("omp", base)]);
        let merged = store.merged_for(&omp_context(home, project, Some("omp")));

        // Declarative deny shadows the package allow from the base and the
        // extension files: an extension file cannot override a NixOS-declared
        // deny.
        assert!(fs_denied(&merged, "/d-global"));

        assert!(!fs_allowed(&merged, "/d-global"));

        // Package deny shadows the user allow.
        assert!(fs_denied(&merged, "/d-package"));

        assert!(!fs_allowed(&merged, "/d-package"));

        // User deny shadows the project allow.
        assert!(fs_denied(&merged, "/d-user"));

        assert!(!fs_allowed(&merged, "/d-user"));
        assert!(fs_denied(&merged, "/d-project"));
        assert!(!fs_allowed(&merged, "/d-project"));

        // Non-conflicting allows from every layer survive in order.
        assert!(fs_allowed(&merged, "/granted/base"));

        assert!(fs_allowed(&merged, "/granted/ext"));
        assert!(fs_allowed(&merged, "/granted/user"));
        assert!(fs_allowed(&merged, "/granted/project"));
        assert!(fs_allowed(&merged, "/granted/pkg-project"));
    }

    #[test]
    fn package_project_file_applies_only_to_matching_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let project = dir.path().join("repo");
        write_fs_policy(&dir.path().join("declarative.json"), &[], &[]);

        write_fs_policy(
            &project.join(".agent-sandbox/packages/omp.json"),
            &["/omp-only"],
            &[],
        );

        write_fs_policy(
            &project.join(".agent-sandbox/packages/codex.json"),
            &["/codex-only"],
            &[],
        );

        let store = package_store(&dir, &[("omp", dir.path().join("omp-base.json"))]);
        let omp = store.merged_for(&omp_context(home.clone(), project.clone(), Some("omp")));
        assert!(fs_allowed(&omp, "/omp-only"));
        assert!(!fs_allowed(&omp, "/codex-only"));
        let codex = store.merged_for(&omp_context(home, project, Some("codex")));

        assert!(
            !fs_allowed(&codex, "/omp-only"),
            "a different package in the same project must not see the omp project file"
        );
    }

    #[test]
    fn unattributed_session_sees_no_package_layer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let project = dir.path().join("repo");
        let base = dir.path().join("omp-base.json");
        write_fs_policy(&dir.path().join("declarative.json"), &[], &[]);
        write_fs_policy(&base, &["/granted/base"], &[]);

        write_fs_policy(
            &home.join(".config/agent-sandbox/packages/omp.json"),
            &["/granted/home-ext"],
            &[],
        );

        let store = package_store(&dir, &[("omp", base.clone())]);
        let merged = store.merged_for(&omp_context(home, project, None));

        assert!(
            !fs_allowed(&merged, "/granted/base"),
            "unattributed session must not load the package base file"
        );

        assert!(
            !fs_allowed(&merged, "/granted/home-ext"),
            "unattributed session must not load the home extension file"
        );

        assert!(
            !merged
                .filesystem
                .deny
                .iter()
                .any(|r| r.path == base || r.path.ends_with("packages/omp.json")),
            "unattributed session must not inherit package policy file denies"
        );
    }

    #[tokio::test]
    async fn implicit_deny_list_covers_package_policy_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let project = dir.path().join("repo");
        let base = dir.path().join("omp-base.json");
        let ext = home.join(".config/agent-sandbox/packages/omp.json");
        let pkg_project = project.join(".agent-sandbox/packages/omp.json");
        write_fs_policy(&dir.path().join("declarative.json"), &[], &[]);
        write_fs_policy(&base, &[], &[]);
        write_fs_policy(&ext, &[], &[]);
        write_fs_policy(&pkg_project, &[], &[]);
        let store = package_store(&dir, &[("omp", base.clone())]);
        let ctx = omp_context(home, project, Some("omp"));
        let merged = store.merged_for(&ctx);

        let denied: Vec<&Path> = merged
            .filesystem
            .deny
            .iter()
            .filter(|r| r.comment.as_deref() == Some("trusted policy file"))
            .map(|r| r.path.as_path())
            .collect();

        for path in [base.as_path(), ext.as_path(), pkg_project.as_path()] {
            assert!(
                denied.contains(&path),
                "package policy file {path:?} must be implicitly denied"
            );
        }

        assert!(
            store
                .filesystem_policy_denied(&base, FileAccess::Read, &ctx)
                .await,
            "sandbox reads of the package base file must be denied"
        );
    }

    #[test]
    fn package_file_mtime_change_invalidates_merged_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let project = dir.path().join("repo");
        let ext = home.join(".config/agent-sandbox/packages/omp.json");
        write_fs_policy(&dir.path().join("declarative.json"), &[], &[]);
        write_fs_policy(&ext, &["/granted/v1"], &[]);
        let store = package_store(&dir, &[]);
        let ctx = omp_context(home, project, Some("omp"));
        assert!(fs_allowed(&store.merged_for(&ctx), "/granted/v1"));
        write_fs_policy(&ext, &["/granted/v2"], &[]);
        let file = std::fs::File::open(&ext).expect("open extension file");

        file.set_modified(std::time::SystemTime::now() + Duration::from_secs(2))
            .expect("bump extension mtime");

        drop(file);
        let merged = store.merged_for(&ctx);

        assert!(
            fs_allowed(&merged, "/granted/v2"),
            "merged policy must reflect the updated extension file"
        );

        assert!(!fs_allowed(&merged, "/granted/v1"));
    }

    #[test]
    fn forged_session_id_does_not_inherit_package_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("omp-base.json");
        write_fs_policy(&dir.path().join("declarative.json"), &[], &[]);
        write_fs_policy(&base, &["/granted/base"], &[]);
        let store = package_store(&dir, &[("omp", base)]);
        let (launcher, owner_pid) = launcher_pair();

        store
            .register_sandbox("s1", "omp", 1000, launcher, owner_pid)
            .expect("register sandbox");

        store.note_sandbox_peer(
            TrustedPeer {
                pid: owner_pid,
                uid: 1000,
            },
            "s1",
        );

        let parent_pid = std::fs::read_to_string(format!("/proc/{owner_pid}/stat"))
            .ok()
            .and_then(|stat| {
                let end = stat.rfind(')')?;
                let mut fields = stat[end + 1..].split_whitespace();
                fields.next()?;
                fields.next()?.parse().ok()
            })
            .expect("parent pid");

        // Positive control: the owner peer (session root, matching uid)
        // gets the package layer.
        let legit = store.resolve_context_with_peer(
            &MergeContext {
                paths: SandboxPaths::default(),
                ids: ProcessIds::from_options(Some(owner_pid), Some(1000)),
                sandbox_session_id: Some("s1".into()),
            },
            Some(TrustedPeer {
                pid: owner_pid,
                uid: 1000,
            }),
        );

        assert_eq!(legit.package.as_deref(), Some("omp"));
        assert!(fs_allowed(&store.merged_for(&legit), "/granted/base"));

        // Forged: a different uid claims session "s1" from a pid that is
        // not inside the session root's subtree. The wire session id alone
        // must not grant the package.
        let forged = store.resolve_context_with_peer(
            &MergeContext {
                paths: SandboxPaths::default(),
                ids: ProcessIds::from_options(Some(parent_pid), Some(2000)),
                sandbox_session_id: Some("s1".into()),
            },
            Some(TrustedPeer {
                pid: parent_pid,
                uid: 2000,
            }),
        );

        assert_eq!(
            forged.package, None,
            "a forged session id from a different uid must not inherit the package"
        );

        assert!(!fs_allowed(&store.merged_for(&forged), "/granted/base"));

        // Forged: the owning uid, but the pid is not the session root or a
        // descendant of it.
        let wrong_pid = store.resolve_context_with_peer(
            &MergeContext {
                paths: SandboxPaths::default(),
                ids: ProcessIds::from_options(Some(parent_pid), Some(1000)),
                sandbox_session_id: Some("s1".into()),
            },
            Some(TrustedPeer {
                pid: parent_pid,
                uid: 1000,
            }),
        );

        assert_eq!(
            wrong_pid.package, None,
            "a same-uid peer outside the session root subtree must not get the package"
        );

        assert!(!fs_allowed(&store.merged_for(&wrong_pid), "/granted/base"));

        // Forged: the owning uid with the root's pid echoed as the wire pid
        // by the launcher itself (a root ancestor outside the sandbox). The
        // launcher must not be able to claim the package either.
        let launcher_forged = store.resolve_context_with_peer(
            &MergeContext {
                paths: SandboxPaths::default(),
                ids: ProcessIds::from_options(Some(owner_pid), Some(1000)),
                sandbox_session_id: Some("s1".into()),
            },
            Some(TrustedPeer {
                pid: parent_pid,
                uid: 1000,
            }),
        );

        assert_eq!(
            launcher_forged.package, None,
            "the launcher echoing the root's pid must not get the package"
        );
    }
}
