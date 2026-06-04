//! Project policy discovery and path resolution.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::ProjectPolicyError;

const EPHEMERAL_MARKERS: &[&str] = &["omp-python-runner", "nix-build-", "/tmp/tmp"];

pub fn is_ephemeral_cwd(path: &Path) -> bool {
    let s = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let s = s.to_string_lossy();
    EPHEMERAL_MARKERS.iter().any(|m| s.contains(m))
}

pub fn is_valid_project_root(path: &Path) -> bool {
    let root = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    root != Path::new("/") && root.file_name().is_some()
}

pub fn infer_home_from_paths(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Option<String> {
    for path_str in paths {
        let parts: Vec<_> = path_str
            .as_ref()
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
    }
    None
}

pub fn discover_project_policy(start: &Path) -> Option<PathBuf> {
    let cur = start.canonicalize().ok()?;
    if !is_valid_project_root(&cur) {
        return None;
    }
    let mut parent = cur.as_path();
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

pub fn project_policy_paths(
    home: Option<&Path>,
    cwd: Option<&Path>,
    project_root: Option<&Path>,
) -> Vec<PathBuf> {
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

    if let Some(project_root) = project_root
        && let Ok(p) = resolve_project_policy_path(None, Some(project_root))
    {
        add(Some(p));
    }
    if let Some(cwd) = cwd
        && let Ok(cwd_path) = cwd.canonicalize()
        && is_valid_project_root(&cwd_path)
        && !is_ephemeral_cwd(&cwd_path)
    {
        add(discover_project_policy(&cwd_path));
    }
    if let Some(home) = home
        && let Ok(home_path) = home.canonicalize()
    {
        add(Some(home_path.join(".agent-sandbox").join("policy.json")));
        if let Ok(entries) = std::fs::read_dir(&home_path) {
            for entry in entries.flatten() {
                let candidate = entry.path().join(".agent-sandbox").join("policy.json");
                add(Some(candidate));
            }
        }
    }
    paths
}

pub fn resolve_project_policy_path(
    cwd: Option<&Path>,
    project_root: Option<&Path>,
) -> Result<PathBuf, ProjectPolicyError> {
    if let Some(project_root) = project_root {
        let root = project_root.canonicalize()?;
        if !is_valid_project_root(&root) {
            return Err(ProjectPolicyError::InvalidProjectRoot { path: root });
        }
        return Ok(root.join(".agent-sandbox").join("policy.json"));
    }

    if let Some(cwd) = cwd {
        let cwd_path = cwd.canonicalize()?;
        if !is_valid_project_root(&cwd_path) {
            return Err(ProjectPolicyError::InvalidCwd { path: cwd_path });
        }
        if is_ephemeral_cwd(&cwd_path) {
            return Err(ProjectPolicyError::EphemeralCwd { path: cwd_path });
        }
        if let Some(existing) = discover_project_policy(&cwd_path) {
            return Ok(existing);
        }
        return Ok(cwd_path.join(".agent-sandbox").join("policy.json"));
    }

    Err(ProjectPolicyError::MissingContext)
}
