//! Policy store: context.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    FileAccess, FilesystemRule, Policy, ProcessIds, ProjectPolicyContext, ResolvedRequestContext,
    SandboxPaths, home_from_uid, is_descendant_of, is_path_descendant, load_policy, merge_layers,
    migrate_policy, read_proc_environ, resolve_policy_write_path, sandbox_session_id_from_pid,
    trusted_context_from_pid, trusted_project_policy_path,
};

use crate::store::types::{SandboxSessionRegistration, TrustedPeer};
use crate::wire::MergeContext;

use super::types::PolicyStore;

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
        let trusted = trusted_context_from_pid(peer.pid, Some(peer.uid));
        let project_root = trusted
            .project_root
            .clone()
            .or_else(|| trusted.cwd.clone())
            .unwrap_or_default();
        let mut sessions = self
            .sandbox_sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions
            .entry(sandbox_session_id.to_string())
            .and_modify(|reg| {
                if is_descendant_of(reg.root_pid, peer.pid)
                    && !project_root.as_os_str().is_empty()
                    && (reg.project_root.as_os_str().is_empty()
                        || is_path_descendant(&project_root, &reg.project_root))
                {
                    reg.project_root.clone_from(&project_root);
                }
            })
            .or_insert(SandboxSessionRegistration {
                root_pid: peer.pid,
                owner_uid: peer.uid,
                project_root,
            });
    }

    pub fn resolve_context_with_peer(
        &self,
        ctx: &MergeContext,
        peer: Option<TrustedPeer>,
    ) -> ResolvedRequestContext {
        let Some(peer) = peer else {
            return Self::resolve_trusted_context(&ResolvedRequestContext::new(
                ctx.paths.clone(),
                ctx.ids,
                ctx.sandbox_session_id.clone(),
            ));
        };
        self.resolve_from_peer(ctx, peer)
    }

    /// Re-resolve a context that was already sanitized upstream by
    /// [`Self::resolve_from_peer`]. Internal store methods invoke this without
    /// a peer. The incoming paths are trusted and only missing fields are
    /// enriched from the verified pid and uid. This must never be reached with
    /// attacker-supplied wire paths. Those are overwritten at the dispatch
    /// boundary before any handler runs.
    pub(crate) fn resolve_trusted_context(ctx: &ResolvedRequestContext) -> ResolvedRequestContext {
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
        let mut project_root = ctx.paths.project_root_path();

        if home.is_none() {
            home = uid.and_then(|u| home_from_uid(Some(u))).map(PathBuf::from);
        }
        if (cwd.is_none() || project_root.is_none())
            && let Some(pid) = pid
        {
            let proc = trusted_context_from_pid(pid, uid);
            if cwd.is_none() {
                cwd = proc.cwd;
            }
            if project_root.is_none() {
                project_root = proc.project_root;
            }
        }
        if project_root.is_none()
            && let (Some(home), Some(cwd_path)) = (home.as_deref(), cwd.as_deref())
        {
            let project = ProjectPolicyContext::new(Some(home), Some(cwd_path), None);
            project_root = project.project_root().map(Path::to_path_buf);
        }

        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(cwd, home, project_root),
            ids: ProcessIds::from_options(pid, uid),
            sandbox_session_id,
        }
    }

    fn resolve_from_peer(&self, ctx: &MergeContext, peer: TrustedPeer) -> ResolvedRequestContext {
        // Host-side helpers (fsmon, syscall-broker) connect to the sandbox
        // socket as root. Their wire ctx was populated at spawn time (or carries
        // the tracee pid); peer-based home/cwd would be wrong and breaks UI spawn.
        if peer.uid == 0 {
            return Self::resolve_trusted_context(&ResolvedRequestContext::new(
                ctx.paths.clone(),
                ctx.ids,
                ctx.sandbox_session_id.clone(),
            ));
        }

        let peer = Some(peer);
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

        let mut sandbox_session_id = ctx.sandbox_session_id.clone();
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
        let mut project_root = None;

        if let Some(pid) = verified_pid {
            let registration = sandbox_session_id.as_ref().and_then(|id| {
                self.sandbox_sessions
                    .read()
                    .ok()
                    .and_then(|sessions| sessions.get(id).cloned())
            });
            let pid_allowed = registration
                .as_ref()
                .is_none_or(|reg| reg.root_pid == pid || is_descendant_of(reg.root_pid, pid));
            if pid_allowed {
                let env = read_proc_environ(pid);
                if cwd.is_none() {
                    cwd = env
                        .get("AGENT_SANDBOX_CWD")
                        .filter(|value| !value.is_empty())
                        .map(PathBuf::from);
                }
                if project_root.is_none() {
                    project_root = env
                        .get("AGENT_SANDBOX_PROJECT_ROOT")
                        .filter(|value| !value.is_empty())
                        .map(PathBuf::from);
                }

                let proc = trusted_context_from_pid(pid, trusted_uid);
                if cwd.is_none() {
                    cwd = proc.cwd;
                }
                if project_root.is_none() {
                    project_root = proc.project_root;
                }
                if let (Some(pr), Some(reg)) = (&project_root, &registration)
                    && !reg.project_root.as_os_str().is_empty()
                    && !is_path_descendant(pr, &reg.project_root)
                {
                    project_root = None;
                }
            }
        }

        if project_root.is_none()
            && let (Some(home), Some(cwd_path)) = (home.as_deref(), cwd.as_deref())
        {
            let project = ProjectPolicyContext::new(Some(home), Some(cwd_path), None);
            project_root = project.project_root().map(Path::to_path_buf);
        }

        let ids = ProcessIds::from_options(verified_pid, trusted_uid);

        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(cwd, home, project_root),
            ids,
            sandbox_session_id,
        }
    }

    /// Merge every policy layer visible to this request.
    ///
    /// Layer order, lowest priority first:
    /// 1. `self.args.declarative` (NixOS configuration).
    /// 2. `~/.config/agent-sandbox/policy.json` (trusted user policy).
    /// 3. The trusted per-project policy file under
    ///    `<project_root>/.agent-sandbox/policy.json`
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
        let home_policy = home_path.map(|home| {
            home.join(".config")
                .join("agent-sandbox")
                .join("policy.json")
        });
        let project_policy =
            project_root_path.and_then(|root| trusted_project_policy_path(root).ok());
        super::types::MergedCacheKey {
            home: home_path.map(Path::to_path_buf),
            project_root: project_root_path.map(Path::to_path_buf),
            declarative_mtime: policy_file_mtime(&self.args.declarative),
            home_policy_mtime: home_policy.as_deref().and_then(policy_file_mtime),
            project_policy_mtime: project_policy.as_deref().and_then(policy_file_mtime),
        }
    }

    fn build_merged_for(&self, ctx: &ResolvedRequestContext) -> Policy {
        let ctx = ctx.clone();
        let home_path = ctx.paths.home().map(Path::new);
        let project_root_path = ctx.paths.project_root().map(Path::new);
        let mut layers: Vec<Policy> = Vec::new();
        layers.push(load_policy(&self.args.declarative, home_path, None));
        if let Some(home) = home_path {
            let home_policy = home
                .join(".config")
                .join("agent-sandbox")
                .join("policy.json");
            if let Err(error) = migrate_policy(&home_policy, home_path, None) {
                tracing::warn!(
                    path = %home_policy.display(),
                    error = %error,
                    "failed to migrate legacy home policy"
                );
            }
            layers.push(load_policy(&home_policy, home_path, None));
            if let Some(root) = project_root_path
                && let Ok(trusted) = trusted_project_policy_path(root)
            {
                if let Err(error) = migrate_policy(&trusted, home_path, Some(root)) {
                    tracing::warn!(
                        path = %trusted.display(),
                        error = %error,
                        "failed to migrate legacy project policy"
                    );
                }
                layers.push(load_policy(&trusted, home_path, project_root_path));
            }
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

    /// Load merged policy from async handlers without blocking the Tokio runtime.
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
    use super::*;
    use crate::store::types::PolicydArgs;
    use agent_sandbox_core::SudoRule;
    use std::time::Duration;

    fn test_store() -> PolicyStore {
        PolicyStore::new(PolicydArgs {
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
        })
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
        assert_ne!(
            resolved.paths.project_root_path(),
            Some(PathBuf::from("/attacker/project"))
        );
    }

    #[test]
    fn root_helper_preserves_wire_paths_from_fsmon() {
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
        assert_eq!(
            resolved.paths.project_root_path(),
            Some(PathBuf::from("/home/user/project"))
        );
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

    #[tokio::test]
    async fn declarative_policy_is_denied_to_sandbox_requests() {
        let store = test_store();
        let ctx = ResolvedRequestContext {
            paths: SandboxPaths::new("/home/user/project", "/home/user", "/home/user/project"),
            ids: ProcessIds::default(),
            sandbox_session_id: None,
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
    fn merged_for_migrates_legacy_home_policy() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let project_root = tmp.path().join("project");
        let policy_dir = home.join(".config/agent-sandbox");
        std::fs::create_dir_all(&policy_dir).expect("create policy directory");
        std::fs::create_dir_all(&project_root).expect("create project root");
        let policy_path = policy_dir.join("policy.json");
        std::fs::write(
            &policy_path,
            r#"{"network":{"allow":[{"host":"example.com","port":443}],"deny":[]}}"#,
        )
        .expect("write legacy home policy");

        let store = test_store();
        let home_s = home.to_string_lossy().into_owned();
        let project_s = project_root.to_string_lossy().into_owned();
        let ctx = ResolvedRequestContext::new(
            SandboxPaths::new(&project_s, &home_s, &project_s),
            ProcessIds::default(),
            None,
        );
        let merged = store.merged_for(&ctx);
        assert_eq!(merged.network.direct.allow.len(), 1);
        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(policy_path).expect("read policy"))
                .expect("parse rewritten policy");
        assert!(rewritten["network"]["allow"].is_null());
        assert_eq!(
            rewritten["network"]["direct"]["allow"]
                .as_array()
                .map(Vec::len),
            Some(1)
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
}
