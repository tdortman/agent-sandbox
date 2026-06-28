//! Explicit `project_root` handling and home inference for policy resolution.

use std::path::{Path, PathBuf};

use crate::error::ProjectPolicyError;

/// Cached inputs for explicit valid `project_root` handling and home inference.
#[derive(Debug, Clone, Default)]
pub struct ProjectPolicyContext {
    home: Option<PathBuf>,
    cwd: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

impl ProjectPolicyContext {
    #[must_use]
    pub fn new(home: Option<&Path>, cwd: Option<&Path>, project_root: Option<&Path>) -> Self {
        Self {
            home: home.and_then(canonicalize),
            cwd: cwd.and_then(canonicalize),
            project_root: project_root.and_then(canonicalize),
        }
    }

    pub fn home_hint(&self) -> Option<String> {
        self.home
            .as_deref()
            .map(path_to_string)
            .or_else(|| infer_home([self.project_root.as_deref(), self.cwd.as_deref()]))
    }

    /// Return the validated project root, if any (not `/`, has a file name).
    #[must_use]
    pub fn project_root(&self) -> Option<&Path> {
        self.project_root
            .as_deref()
            .filter(|path| is_valid_project_root(path))
    }
}

fn canonicalize(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
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

fn is_valid_project_root(path: &Path) -> bool {
    path != Path::new("/") && path.file_name().is_some()
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Build the path to the trusted per-project policy file inside the project:
/// `<canonical project_root>/.agent-sandbox/policy.json`.
///
/// The returned path is canonicalised and verified to be a descendant of the
/// canonical project root, defeating symlink-escape attacks.
///
/// # Errors
///
/// Returns an error if `project_root` cannot be canonicalized, is not a valid
/// project root (`/` or lacking a file name), or the canonicalized policy path
/// escapes `project_root`.
pub fn trusted_project_policy_path(project_root: &Path) -> Result<PathBuf, ProjectPolicyError> {
    let canonical_root =
        project_root
            .canonicalize()
            .map_err(|_| ProjectPolicyError::InvalidProjectRoot {
                path: project_root.to_path_buf(),
            })?;
    if !is_valid_project_root(&canonical_root) {
        return Err(ProjectPolicyError::InvalidProjectRoot {
            path: canonical_root,
        });
    }
    let policy_path = canonical_root.join(".agent-sandbox").join("policy.json");
    // If the policy file exists, canonicalize and verify containment.
    if let Ok(canonical_policy) = policy_path.canonicalize() {
        if !canonical_policy.starts_with(&canonical_root) {
            return Err(ProjectPolicyError::InvalidProjectRoot {
                path: canonical_policy,
            });
        }
        return Ok(canonical_policy);
    }
    // File does not exist yet — the constructed path cannot be a symlink escape.
    Ok(policy_path)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{ProjectPolicyContext, trusted_project_policy_path};

    #[test]
    fn project_root_returns_explicit_value() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let repo = tmp.path().join("dotfiles");
        fs::create_dir_all(&repo).expect("create dirs");

        let ctx = ProjectPolicyContext::new(None, None, Some(&repo));
        assert_eq!(ctx.project_root(), Some(repo.as_path()));
    }

    #[test]
    fn invalid_explicit_project_root_is_ignored() {
        let ctx = ProjectPolicyContext::new(None, None, Some(Path::new("/")));
        assert_eq!(ctx.project_root(), None);
    }

    #[test]
    fn explicit_project_root_beats_ephemeral_cwd() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let repo = tmp.path().join("dotfiles");
        fs::create_dir_all(repo.join(".agent-sandbox")).expect("create dirs");
        let ephemeral = tmp.path().join("agent-python-runner");
        fs::create_dir(&ephemeral).expect("create dirs");

        let ctx = ProjectPolicyContext::new(None, Some(&ephemeral), Some(&repo));
        assert_eq!(ctx.project_root(), Some(repo.as_path()));
    }

    #[test]
    fn cwd_repo_local_policy_does_not_infer_project_root() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let repo = tmp.path().join("proj");
        fs::create_dir_all(repo.join(".agent-sandbox")).expect("create dirs");
        fs::write(
            repo.join(".agent-sandbox/policy.json"),
            r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
        )
        .expect("write file");

        let ctx = ProjectPolicyContext::new(None, Some(&repo), None);
        assert_eq!(ctx.project_root(), None);
    }

    #[test]
    fn infers_home_from_project_root() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let home = tmp.path().join("home/user");
        let repo = home.join("dotfiles");
        fs::create_dir_all(&repo).expect("create dirs");

        let ctx = ProjectPolicyContext::new(None, None, Some(&repo));
        assert_eq!(ctx.home_hint(), Some(home.to_string_lossy().into_owned()));
    }

    #[test]
    fn infers_home_from_cwd() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let home = tmp.path().join("home/user");
        let cwd = home.join("repo");
        fs::create_dir_all(&cwd).expect("create dirs");

        let ctx = ProjectPolicyContext::new(None, Some(&cwd), None);
        assert_eq!(ctx.home_hint(), Some(home.to_string_lossy().into_owned()));
    }

    #[test]
    fn explicit_home_beats_inference() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let explicit_home = tmp.path().join("explicit-home");
        fs::create_dir_all(&explicit_home).expect("create dirs");
        let cwd = tmp.path().join("repo");
        fs::create_dir_all(&cwd).expect("create dirs");

        let ctx = ProjectPolicyContext::new(Some(&explicit_home), Some(&cwd), None);
        assert_eq!(
            ctx.home_hint(),
            Some(explicit_home.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn trusted_project_policy_path_is_inside_project_root() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".agent-sandbox")).expect("create dirs");
        let path = trusted_project_policy_path(&repo).expect("trusted project policy path");
        let s = path.to_string_lossy();
        assert!(s.ends_with(".agent-sandbox/policy.json"), "got: {s}");
        assert!(
            path.starts_with(&repo),
            "path must be inside project root: {s}"
        );
    }

    #[test]
    fn trusted_project_policy_path_rejects_symlink_escape() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).expect("create dirs");
        // Create a symlink from .agent-sandbox/policy.json to /etc/passwd
        let sandbox_dir = repo.join(".agent-sandbox");
        fs::create_dir_all(&sandbox_dir).expect("create dirs");
        std::os::unix::fs::symlink("/etc/passwd", sandbox_dir.join("policy.json"))
            .expect("create symlink");
        let err = trusted_project_policy_path(&repo).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::ProjectPolicyError::InvalidProjectRoot { .. }
            ),
            "expected InvalidProjectRoot, got {err:?}"
        );
    }

    #[test]
    fn trusted_project_policy_path_rejects_nonexistent_project_root() {
        let err = trusted_project_policy_path(Path::new("/nonexistent/path/here")).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::ProjectPolicyError::InvalidProjectRoot { .. }
            ),
            "expected InvalidProjectRoot, got {err:?}"
        );
    }
}
