//! Project policy discovery and path resolution.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::ProjectPolicyError;

const EPHEMERAL_MARKERS: &[&str] = &["omp-python-runner", "nix-build-", "/tmp/tmp"];

#[derive(Debug, Clone, Default)]
pub struct ProjectPolicyContext {
    home: Option<PathBuf>,
    cwd: Option<PathBuf>,
    project_root: Option<PathBuf>,
    discovered_policy: Option<PathBuf>,
}

impl ProjectPolicyContext {
    #[must_use]
    pub fn new(home: Option<&Path>, cwd: Option<&Path>, project_root: Option<&Path>) -> Self {
        let home = home.and_then(canonicalize);
        let cwd = cwd.and_then(canonicalize);
        let project_root = project_root.and_then(canonicalize);
        let discovered_policy = cwd
            .as_deref()
            .filter(|path| is_valid_project_root(path) && !is_ephemeral_path(path))
            .and_then(discover_project_policy);
        Self {
            home,
            cwd,
            project_root,
            discovered_policy,
        }
    }

    pub fn home_hint(&self) -> Option<String> {
        self.home
            .as_deref()
            .map(path_to_string)
            .or_else(|| infer_home([self.project_root.as_deref(), self.cwd.as_deref()]))
    }

    pub fn project_root(&self) -> Option<&Path> {
        self.valid_project_root().or_else(|| {
            self.discovered_policy
                .as_deref()
                .and_then(|path| path.parent().and_then(Path::parent))
        })
    }

    pub fn resolve_policy_path(&self) -> Result<PathBuf, ProjectPolicyError> {
        if let Some(project_root) = self.project_root.as_deref() {
            if !is_valid_project_root(project_root) {
                return Err(ProjectPolicyError::InvalidProjectRoot {
                    path: project_root.to_path_buf(),
                });
            }
            return Ok(project_root.join(".agent-sandbox").join("policy.json"));
        }

        if let Some(cwd) = self.cwd.as_deref() {
            if !is_valid_project_root(cwd) {
                return Err(ProjectPolicyError::InvalidCwd {
                    path: cwd.to_path_buf(),
                });
            }
            if is_ephemeral_path(cwd) {
                return Err(ProjectPolicyError::EphemeralCwd {
                    path: cwd.to_path_buf(),
                });
            }
            if let Some(existing) = &self.discovered_policy {
                return Ok(existing.clone());
            }
            return Ok(cwd.join(".agent-sandbox").join("policy.json"));
        }

        Err(ProjectPolicyError::MissingContext)
    }

    pub fn layer_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = HashSet::new();
        let mut add = |path: Option<PathBuf>| {
            let Some(path) = path else {
                return;
            };
            if !path.is_file() {
                return;
            }
            let resolved = path.canonicalize().unwrap_or(path);
            if seen.insert(resolved.clone()) {
                paths.push(resolved);
            }
        };

        add(self.valid_project_root().map(project_policy_path));
        add(self.discovered_policy.clone());

        paths
    }

    fn valid_project_root(&self) -> Option<&Path> {
        self.project_root
            .as_deref()
            .filter(|path| is_valid_project_root(path))
    }
}

fn canonicalize(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

fn discover_project_policy(start: &Path) -> Option<PathBuf> {
    let mut parent = start;
    loop {
        let candidate = parent.join(".agent-sandbox").join("policy.json");
        if candidate.is_file() {
            return Some(candidate);
        }
        if parent == Path::new("/") {
            break;
        }
        parent = parent.parent()?;
    }
    None
}

fn infer_home<'a>(paths: impl IntoIterator<Item = Option<&'a Path>>) -> Option<String> {
    paths.into_iter().flatten().find_map(infer_home_from_path)
}

fn infer_home_from_path(path: &Path) -> Option<String> {
    let parts: Vec<_> = path
        .canonicalize()
        .ok()?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    for (idx, part) in parts.iter().enumerate().take(parts.len().saturating_sub(1)) {
        if part != "home" {
            continue;
        }
        let user = parts.get(idx + 1)?;
        if user.is_empty() {
            continue;
        }
        let candidate = parts.iter().take(idx + 2).collect::<PathBuf>();
        if candidate.is_dir() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn is_ephemeral_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    EPHEMERAL_MARKERS.iter().any(|marker| s.contains(marker))
}

fn is_valid_project_root(path: &Path) -> bool {
    path != Path::new("/") && path.file_name().is_some()
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn project_policy_path(root: &Path) -> PathBuf {
    root.join(".agent-sandbox").join("policy.json")
}

/// Build the path to the trusted per-project policy file under the user's
/// `~/.config/agent-sandbox/projects/<encoded-project-root>/policy.json`.
///
/// The encoded project root replaces every path separator with `-` so the
/// resulting path lives outside the writable project tree. The sandboxed
/// process cannot tamper with its own persistent approvals.
pub fn trusted_project_policy_path(
    home: &Path,
    project_root: &Path,
) -> Result<PathBuf, ProjectPolicyError> {
    let canonical =
        project_root
            .canonicalize()
            .map_err(|_| ProjectPolicyError::InvalidProjectRoot {
                path: project_root.to_path_buf(),
            })?;
    if !is_valid_project_root(&canonical) {
        return Err(ProjectPolicyError::InvalidProjectRoot { path: canonical });
    }
    let encoded = encode_project_root(&canonical);
    Ok(home
        .join(".config")
        .join("agent-sandbox")
        .join("projects")
        .join(encoded)
        .join("policy.json"))
}

fn encode_project_root(path: &Path) -> String {
    let mut out = String::with_capacity(path.as_os_str().len());
    let lossy = path.to_string_lossy();
    let bytes = lossy.as_bytes();
    // Skip a single leading separator so the encoded form never starts with "-".
    let start = usize::from(bytes.first() == Some(&b'/'));
    for &byte in &bytes[start..] {
        if byte == b'/' {
            out.push('-');
        } else {
            out.push(byte as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{ProjectPolicyContext, encode_project_root, trusted_project_policy_path};

    #[test]
    fn explicit_project_root_beats_ephemeral_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("dotfiles");
        fs::create_dir_all(repo.join(".agent-sandbox")).unwrap();
        let policy_file = repo.join(".agent-sandbox/policy.json");
        fs::write(
            &policy_file,
            r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
        )
        .unwrap();
        let ephemeral = tmp.path().join("omp-python-runner");
        fs::create_dir(&ephemeral).unwrap();

        let ctx = ProjectPolicyContext::new(None, Some(&ephemeral), Some(&repo));
        assert_eq!(ctx.resolve_policy_path().unwrap(), policy_file);
    }

    #[test]
    fn ephemeral_cwd_without_project_root_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let ephemeral = tmp.path().join("omp-python-runner");
        fs::create_dir(&ephemeral).unwrap();

        let ctx = ProjectPolicyContext::new(None, Some(&ephemeral), None);
        assert!(ctx.resolve_policy_path().is_err());
    }

    #[test]
    fn rejects_root_cwd() {
        let ctx = ProjectPolicyContext::new(None, Some(Path::new("/")), None);
        assert!(ctx.resolve_policy_path().is_err());
    }

    #[test]
    fn discovers_policy_from_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("proj");
        fs::create_dir_all(repo.join("src")).unwrap();
        let policy_file = repo.join(".agent-sandbox/policy.json");
        fs::create_dir_all(policy_file.parent().unwrap()).unwrap();
        fs::write(
            &policy_file,
            r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
        )
        .unwrap();

        let ctx = ProjectPolicyContext::new(None, Some(&repo.join("src")), None);
        assert_eq!(ctx.resolve_policy_path().unwrap(), policy_file);
        assert_eq!(ctx.project_root(), Some(repo.as_path()));
    }

    #[test]
    fn infers_home_from_project_root() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home/tim");
        let repo = home.join("dotfiles");
        fs::create_dir_all(&repo).unwrap();

        let ctx = ProjectPolicyContext::new(None, None, Some(&repo));
        assert_eq!(ctx.home_hint(), Some(home.to_string_lossy().into_owned()));
    }

    #[test]
    fn layer_paths_only_includes_repo_local_policies() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home/tim");
        let repo = home.join("dotfiles");
        fs::create_dir_all(repo.join(".agent-sandbox")).unwrap();
        fs::write(
            repo.join(".agent-sandbox/policy.json"),
            r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
        )
        .unwrap();
        fs::create_dir_all(home.join(".agent-sandbox")).unwrap();
        fs::write(
            home.join(".agent-sandbox/policy.json"),
            r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
        )
        .unwrap();

        let ctx = ProjectPolicyContext::new(Some(&home), Some(&repo), None);
        let paths = ctx.layer_paths();
        assert_eq!(paths.len(), 1);
        assert!(
            paths
                .iter()
                .any(|path| path.ends_with("home/tim/dotfiles/.agent-sandbox/policy.json"))
        );
    }

    #[test]
    fn trusted_project_policy_path_lives_outside_project_root() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home/tim");
        let repo = home.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let path = trusted_project_policy_path(&home, &repo).unwrap();
        let s = path.to_string_lossy();
        assert!(s.contains(".config/agent-sandbox/projects/"), "got: {s}");
        assert!(s.ends_with("/policy.json"), "got: {s}");
        assert!(!s.contains("/repo/policy.json"));
    }

    #[test]
    fn encode_project_root_replaces_separators_with_dash() {
        let encoded = encode_project_root(Path::new("/home/user/repo"));
        assert_eq!(encoded, "home-user-repo");
    }

    #[test]
    fn trusted_project_policy_path_rejects_invalid_project_root() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home/tim");
        std::fs::create_dir_all(&home).unwrap();
        let err =
            trusted_project_policy_path(&home, Path::new("/nonexistent/path/here")).unwrap_err();
        match err {
            crate::error::ProjectPolicyError::InvalidProjectRoot { .. } => {}
            other => panic!("expected InvalidProjectRoot, got {other:?}"),
        }
    }

    #[test]
    fn detects_ephemeral_runner() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("omp-python-runner");
        fs::create_dir(&path).unwrap();

        let ctx = ProjectPolicyContext::new(None, Some(&path), None);
        assert!(ctx.resolve_policy_path().is_err());
    }
}
