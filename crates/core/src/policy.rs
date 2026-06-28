//! On-disk policy document (`network` / `sudo` / `filesystem` allow and deny rules).
//!
//! Paths can be absolute (`/foo`), home-relative (`~/foo`), or project-relative (`./foo`).
//! Paths containing `*` or `?` are treated as glob patterns compiled with [`globset`].

use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::hosts::NetworkRuleKey;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess {
    #[default]
    Read,
    Write,
    ReadWrite,
    Execute,
    All,
}

impl FileAccess {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
            Self::Execute => "execute",
            Self::All => "all",
        }
    }

    /// Whether this access level covers the requested access.
    #[must_use]
    pub fn covers(self, requested: FileAccess) -> bool {
        match self {
            Self::All => true,
            Self::ReadWrite => matches!(requested, Self::Read | Self::Write | Self::ReadWrite),
            _ => self == requested,
        }
    }

    /// Smallest policy access that covers both access levels.
    #[must_use]
    pub fn union(self, other: FileAccess) -> Self {
        if self.covers(other) {
            self
        } else if other.covers(self) {
            other
        } else if matches!(
            (self, other),
            (Self::Read, Self::Write) | (Self::Write, Self::Read)
        ) {
            Self::ReadWrite
        } else {
            Self::All
        }
    }
}

impl std::fmt::Display for FileAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilesystemRuleKey {
    pub path: String,
    pub access: FileAccess,
}

impl FilesystemRuleKey {
    #[must_use]
    pub fn new(path: impl Into<String>, access: FileAccess) -> Self {
        Self {
            path: path.into(),
            access,
        }
    }

    #[must_use]
    pub fn from_rule(rule: &FilesystemRule) -> Self {
        Self::new(rule.path.trim_end_matches('/'), rule.access)
    }
}

/// Compiled path matching strategy: literal prefix or glob pattern.
enum CompiledPath {
    /// Literal path used for exact/descendant prefix matching.
    Prefix(String),
    /// Compiled glob matcher.
    Glob(GlobMatcher),
}

impl CompiledPath {
    /// Compile a policy path into a matcher.
    ///
    /// If the path (after `./` expansion) contains `*` or `?`, it becomes a `Glob`.
    /// Otherwise it is treated as a literal `Prefix` path.
    fn compile(path: &str, project_root: Option<&Path>) -> Result<Self, globset::Error> {
        let expanded = expand_policy_path(path, None, project_root);
        if expanded.contains('*') || expanded.contains('?') {
            let glob = Glob::new(&expanded)?.compile_matcher();
            Ok(Self::Glob(glob))
        } else {
            Ok(Self::Prefix(expanded))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FilesystemSortKey {
    pub path: String,
    pub access: FileAccess,
}

impl FilesystemSortKey {
    #[must_use]
    pub fn new(path: impl Into<String>, access: FileAccess) -> Self {
        Self {
            path: path.into(),
            access,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilesystemRule {
    pub path: String,
    pub access: FileAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl FilesystemRule {
    #[must_use]
    pub fn new(path: impl Into<String>, access: FileAccess, comment: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            access,
            comment: Some(comment.into()),
        }
    }

    /// Whether this rule's path matches the requested path (exact, descendant, or glob).
    pub fn path_matches(&self, requested: &Path, project_root: Option<&Path>) -> bool {
        // ponytail: recompile on every match. globset compile is ~10us; add a sidecar
        // cache if profiling shows the matcher is hot. Replaces the previous OnceLock
        // field, which forced manual PartialEq/Eq impls.
        let compiled = CompiledPath::compile(&self.path, project_root).expect("valid glob pattern");
        match compiled {
            CompiledPath::Prefix(rule_path) => {
                let requested = normalize_rule_path(&requested.to_string_lossy());
                if rule_path == "/" {
                    return requested.starts_with('/');
                }
                if rule_path == requested {
                    return true;
                }
                requested
                    .strip_prefix(rule_path.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            }
            CompiledPath::Glob(matcher) => matcher.is_match(requested),
        }
    }

    /// Whether this rule matches the given path and access request.
    #[must_use]
    pub fn matches(&self, path: &Path, access: FileAccess, project_root: Option<&Path>) -> bool {
        self.path_matches(path, project_root) && self.access.covers(access)
    }
}

fn normalize_rule_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        trimmed.into()
    }
}

/// Convert an absolute path under `home` to the `~/...` shorthand.
/// Paths outside `home` are returned unchanged.  `home` itself maps to `~`.
#[must_use]
pub fn contract_home_path(path: &str, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return path.to_string();
    };
    let trimmed = path.trim_end_matches('/');
    let home_trimmed = home.to_string_lossy().trim_end_matches('/').to_string();
    if trimmed.is_empty() || home_trimmed.is_empty() {
        return path.to_string();
    }
    if trimmed == home_trimmed {
        return "~".to_string();
    }
    if let Some(rest) = trimmed.strip_prefix(&home_trimmed)
        && let Some(stripped) = rest.strip_prefix('/')
    {
        return format!("~/{stripped}");
    }
    path.to_string()
}

/// Expand a `~/...` path to an absolute path under `home`.  Paths that do not
/// start with `~/` are returned unchanged.  When `home` is `None`, `~/` paths
/// are kept as-is (matching will then fail closed).
#[must_use]
pub fn expand_home_path(path: &str, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return path.to_string();
    };
    let home_str = home.to_string_lossy();
    if path == "~" {
        return home_str.trim_end_matches('/').to_string();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        let base = home_str.trim_end_matches('/');
        return format!("{base}/{rest}");
    }
    path.to_string()
}

/// Expand a `./...` path to an absolute path under `project_root`.
///
/// Paths that do not start with `./` are returned unchanged. When `project_root`
/// is `None`, `./` paths are kept as-is (matching will then fail closed).
#[must_use]
pub fn expand_project_relative(path: &str, project_root: &Path) -> String {
    let pr = project_root.to_string_lossy();
    if path == "." {
        return pr.trim_end_matches('/').to_string();
    }
    if let Some(rest) = path.strip_prefix("./") {
        let base = pr.trim_end_matches('/');
        return format!("{base}/{rest}");
    }
    path.to_string()
}

/// Apply home (`~/`) then project-relative (`./`) expansion in order.
#[must_use]
pub fn expand_policy_path(path: &str, home: Option<&Path>, project_root: Option<&Path>) -> String {
    let expanded = expand_home_path(path, home);
    if let Some(pr) = project_root {
        expand_project_relative(&expanded, pr)
    } else {
        expanded
    }
}

/// Build the ordered list of filesystem paths to present as approval targets.
///
/// Returns the exact path first, then parent directories walking upward.
/// For paths under `home`, stops after including the home directory itself.
/// For non-home paths, stops after including `/`.
/// No duplicates are returned.
#[must_use]
pub fn filesystem_approval_paths(path: &Path, home: Option<&Path>) -> Vec<String> {
    let path_str = path.to_string_lossy();
    let norm = path_str.trim_end_matches('/');
    if norm.is_empty() {
        return vec!["/".to_string()];
    }

    let home_trimmed = home.map(|h| h.to_string_lossy().trim_end_matches('/').to_string());
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut current = norm.to_string();
    loop {
        if seen.insert(current.clone()) {
            result.push(current.clone());
        }

        if home_trimmed.as_deref() == Some(current.as_str()) {
            break;
        }

        let parent = match std::path::Path::new(&current).parent() {
            Some(p) => p.to_string_lossy().to_string(),
            None => break,
        };

        if parent.is_empty() || seen.contains(&parent) {
            break;
        }

        // Include root when reached, then stop
        if parent == "/" {
            if seen.insert("/".to_string()) {
                result.push("/".to_string());
            }
            break;
        }

        // Stop at home (include it) when path is under home
        if let Some(h) = &home_trimmed
            && parent == *h
        {
            if seen.insert(parent.clone()) {
                result.push(parent);
            }
            break;
        }

        current = parent;
    }

    result
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemSection {
    #[serde(default)]
    pub allow: Vec<FilesystemRule>,
    #[serde(default)]
    pub deny: Vec<FilesystemRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub sudo: SudoSection,
    #[serde(default)]
    pub filesystem: FilesystemSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSection {
    #[serde(default)]
    pub allow: Vec<NetworkRule>,
    #[serde(default)]
    pub deny: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoSection {
    #[serde(default)]
    pub allow: Vec<SudoRule>,
    #[serde(default)]
    pub deny: Vec<SudoRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRule {
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoRule {
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl NetworkRule {
    pub fn new(host: impl Into<String>, port: u16, comment: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            comment: Some(comment.into()),
        }
    }

    pub fn key(&self) -> NetworkRuleKey {
        NetworkRuleKey::new(&self.host, self.port)
    }
}

impl SudoRule {
    pub fn new(argv: Vec<String>, comment: impl Into<String>) -> Self {
        Self {
            argv,
            comment: Some(comment.into()),
        }
    }

    pub fn key(&self) -> Option<Vec<String>> {
        if self.argv.is_empty() {
            None
        } else {
            Some(self.argv.clone())
        }
    }

    pub fn matches(&self, argv: &[String]) -> bool {
        !self.argv.is_empty() && argv.starts_with(&self.argv)
    }

    pub fn approval_prefixes(argv: &[String]) -> Vec<Vec<String>> {
        let mut prefixes = Vec::with_capacity(argv.len());
        for len in (1..=argv.len()).rev() {
            prefixes.push(argv[..len].to_vec());
        }
        prefixes
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FileAccess, FilesystemRule, SudoRule, contract_home_path, expand_home_path,
        filesystem_approval_paths,
    };
    use std::path::Path;

    #[test]
    fn sudo_rule_matches_prefix() {
        let rule = SudoRule::new(vec!["systemctl".into(), "restart".into()], "");
        let argv = ["systemctl".into(), "restart".into(), "nginx".into()];
        let wrong_argv = ["systemctl".into(), "stop".into()];
        assert!(rule.matches(&argv));
        assert!(!rule.matches(&wrong_argv));
    }

    #[test]
    fn sudo_rule_approval_prefixes_descend_from_most_specific() {
        let argv = vec!["systemctl".into(), "restart".into(), "nginx".into()];
        assert_eq!(
            SudoRule::approval_prefixes(&argv),
            vec![
                vec![
                    "systemctl".to_string(),
                    "restart".to_string(),
                    "nginx".to_string()
                ],
                vec!["systemctl".to_string(), "restart".to_string()],
                vec!["systemctl".to_string()],
            ]
        );
    }

    #[test]
    fn file_access_covers() {
        assert!(FileAccess::All.covers(FileAccess::Read));
        assert!(FileAccess::All.covers(FileAccess::Write));
        assert!(FileAccess::All.covers(FileAccess::Execute));
        assert!(FileAccess::All.covers(FileAccess::ReadWrite));
        assert!(FileAccess::ReadWrite.covers(FileAccess::Read));
        assert!(FileAccess::ReadWrite.covers(FileAccess::Write));
        assert!(!FileAccess::ReadWrite.covers(FileAccess::Execute));
        assert!(!FileAccess::Read.covers(FileAccess::Write));
        assert!(FileAccess::Read.covers(FileAccess::Read));
    }

    #[test]
    fn file_access_union_uses_smallest_covering_access() {
        assert_eq!(FileAccess::Read.union(FileAccess::Read), FileAccess::Read);
        assert_eq!(
            FileAccess::Read.union(FileAccess::Write),
            FileAccess::ReadWrite
        );
        assert_eq!(
            FileAccess::ReadWrite.union(FileAccess::Read),
            FileAccess::ReadWrite
        );
        assert_eq!(
            FileAccess::ReadWrite.union(FileAccess::Execute),
            FileAccess::All
        );
        assert_eq!(FileAccess::All.union(FileAccess::Read), FileAccess::All);
    }
    #[test]
    fn filesystem_rule_matches_exact_path() {
        let rule = FilesystemRule::new("/home/user", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/home/user"), None));
        assert!(!rule.path_matches(Path::new("/home/userx"), None));
    }

    #[test]
    fn filesystem_rule_matches_descendant() {
        let rule = FilesystemRule::new("/home", FileAccess::ReadWrite, "");
        assert!(rule.path_matches(Path::new("/home/user"), None));
        assert!(rule.path_matches(Path::new("/home/user/file.txt"), None));
        assert!(!rule.path_matches(Path::new("/var/log"), None));
    }

    #[test]
    fn filesystem_rule_respects_access_hierarchy() {
        let rule = FilesystemRule::new("/tmp", FileAccess::ReadWrite, "");
        assert!(rule.matches(Path::new("/tmp"), FileAccess::Read, None));
        assert!(rule.matches(Path::new("/tmp"), FileAccess::Write, None));
        assert!(!rule.matches(Path::new("/tmp"), FileAccess::Execute, None));

        let all_rule = FilesystemRule::new("/nix/store", FileAccess::All, "");
        assert!(all_rule.matches(Path::new("/nix/store/something"), FileAccess::Execute, None));
        assert!(all_rule.matches(Path::new("/nix/store"), FileAccess::Write, None));
    }

    #[test]
    fn glob_match_dot_slash_dot_env() {
        let rule = FilesystemRule::new("./**/.env", FileAccess::Read, "");
        // With project_root="/work", ./**/.env -> /work/**/.env
        assert!(rule.path_matches(Path::new("/work/.env"), Some(Path::new("/work"))));
        assert!(rule.path_matches(Path::new("/work/sub/.env"), Some(Path::new("/work"))));
        assert!(!rule.path_matches(Path::new("/etc/.env"), Some(Path::new("/work"))));
    }

    #[test]
    fn glob_match_double_star_dot_env() {
        let rule = FilesystemRule::new("**/.env", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/.env"), None));
        assert!(rule.path_matches(Path::new("/work/sub/.env"), None));
    }

    #[test]
    fn glob_match_dot_slash_double_star_dot_env_with_project_root() {
        let rule = FilesystemRule::new("./**/.env", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/.env"), Some(Path::new("/work"))));
        assert!(rule.path_matches(Path::new("/work/sub/.env"), Some(Path::new("/work"))));
        assert!(!rule.path_matches(Path::new("/etc/.env"), Some(Path::new("/work"))));
    }

    #[test]
    fn glob_does_not_match_non_matching_pattern() {
        let rule = FilesystemRule::new("**/secret", FileAccess::Read, "");
        assert!(!rule.path_matches(Path::new("/work/.env"), None));
        assert!(rule.path_matches(Path::new("/work/secret"), None));
    }

    #[test]
    fn glob_dot_slash_prefix_expands_correctly() {
        let rule = FilesystemRule::new("./foo", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/foo"), Some(Path::new("/work"))));
        assert!(rule.path_matches(Path::new("/work/foo/bar"), Some(Path::new("/work"))));
        assert!(!rule.path_matches(Path::new("/work/foobar"), Some(Path::new("/work"))));
    }

    #[test]
    fn filesystem_approval_paths_exact_path_first() {
        let paths = filesystem_approval_paths(
            Path::new("/home/user/.local/share/foo"),
            Some(Path::new("/home/user")),
        );
        assert_eq!(
            paths[0], "/home/user/.local/share/foo",
            "exact path must be first"
        );
    }

    #[test]
    fn filesystem_approval_paths_under_home_stops_at_home() {
        let paths = filesystem_approval_paths(
            Path::new("/home/user/.local/share/foo"),
            Some(Path::new("/home/user")),
        );
        assert_eq!(
            paths,
            vec![
                "/home/user/.local/share/foo",
                "/home/user/.local/share",
                "/home/user/.local",
                "/home/user",
            ]
        );
    }

    #[test]
    fn filesystem_approval_paths_non_home_includes_root() {
        let paths = filesystem_approval_paths(
            Path::new("/nix/store/abc123/bin/hello"),
            Some(Path::new("/home/user")),
        );
        assert_eq!(
            paths,
            vec![
                "/nix/store/abc123/bin/hello",
                "/nix/store/abc123/bin",
                "/nix/store/abc123",
                "/nix/store",
                "/nix",
                "/",
            ]
        );
    }

    #[test]
    fn filesystem_approval_paths_root_path_returns_just_root() {
        let paths = filesystem_approval_paths(Path::new("/"), Some(Path::new("/home/user")));
        assert_eq!(paths, vec!["/"]);
    }

    #[test]
    fn filesystem_approval_paths_home_exact_returns_just_home() {
        let paths =
            filesystem_approval_paths(Path::new("/home/user"), Some(Path::new("/home/user")));
        assert_eq!(paths, vec!["/home/user"]);
    }

    #[test]
    fn filesystem_approval_paths_no_duplicates() {
        let paths = filesystem_approval_paths(Path::new("/etc/passwd"), None);
        let mut dedup = paths.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(paths.len(), dedup.len(), "must not have duplicates");
    }

    #[test]
    fn contract_home_path_converts_under_home() {
        let home = Path::new("/home/user");
        assert_eq!(
            contract_home_path("/home/user/.local/share/foo", Some(home)),
            "~/.local/share/foo"
        );
        assert_eq!(contract_home_path("/home/user", Some(home)), "~");
        assert_eq!(contract_home_path("/home/user/", Some(home)), "~");
    }

    #[test]
    fn contract_home_path_leaves_non_home_paths_unchanged() {
        let home = Path::new("/home/user");
        assert_eq!(contract_home_path("/nix/store", Some(home)), "/nix/store");
        assert_eq!(contract_home_path("/", Some(home)), "/");
        assert_eq!(contract_home_path("/home", Some(home)), "/home");
        assert_eq!(
            contract_home_path("/home/user2/file", Some(home)),
            "/home/user2/file"
        );
    }

    #[test]
    fn contract_home_path_without_home_is_passthrough() {
        assert_eq!(
            contract_home_path("/home/user/.local/share/foo", None),
            "/home/user/.local/share/foo"
        );
    }

    #[test]
    fn expand_home_path_converts_tilde() {
        let home = Path::new("/home/user");
        assert_eq!(
            expand_home_path("~/.local/share/foo", Some(home)),
            "/home/user/.local/share/foo"
        );
        assert_eq!(expand_home_path("~", Some(home)), "/home/user");
    }

    #[test]
    fn expand_home_path_leaves_absolute_paths_unchanged() {
        let home = Path::new("/home/user");
        assert_eq!(expand_home_path("/nix/store", Some(home)), "/nix/store");
        assert_eq!(expand_home_path("/", Some(home)), "/");
    }

    #[test]
    fn expand_home_path_without_home_keeps_tilde() {
        assert_eq!(
            expand_home_path("~/.local/share/foo", None),
            "~/.local/share/foo"
        );
    }

    #[test]
    fn contract_expand_round_trip() {
        let home = Path::new("/home/user");
        let original = "/home/user/.local/share/foo/agent/models.db-wal";
        let contracted = contract_home_path(original, Some(home));
        assert_eq!(contracted, "~/.local/share/foo/agent/models.db-wal");
        let expanded = expand_home_path(&contracted, Some(home));
        assert_eq!(expanded, original);
    }
}
