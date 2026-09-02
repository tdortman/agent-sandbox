//! On-disk policy document (`network` / `sudo` / `filesystem` allow and deny
//! rules).
//!
//! Paths can be absolute (`/foo`), home-relative (`~/foo`), or project-relative
//! (`./foo`). Paths containing glob syntax are compiled with [`globset`].

use std::path::{Path, PathBuf};

use globset::GlobMatcher;
use serde::{Deserialize, Serialize};

use crate::{
    hosts::{NetworkRuleKey, build_glob},
    http::HttpRule,
};

/// Access mode for a filesystem path rule or request.
///
/// Level semantics follow Unix file access and are classified by fanotify /
/// `open(2)` flag bits (see [`open_flags_to_file_access`]).
///
/// [`open_flags_to_file_access`]: fn@open_flags_to_file_access
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess {
    #[default]
    /// Read access.
    ///
    /// When observed via fanotify, directory traversal is normalized to this
    /// by [`normalize_directory_traverse_access`].
    ///
    /// [`normalize_directory_traverse_access`]: fn@normalize_directory_traverse_access
    Read,

    /// Write access.
    ///
    /// Includes truncation and creation semantics, so `creat(2)` classifies
    /// as write-equivalent even when the passed access flags are read-only.
    Write,

    /// Read and write access.
    ReadWrite,

    /// Execute access.
    Execute,
    /// All access levels.
    All,
}

impl FileAccess {
    /// Return the stable wire / policy-file name of this access level.
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
    pub fn covers(self, requested: Self) -> bool {
        match self {
            Self::All => true,
            Self::ReadWrite => matches!(requested, Self::Read | Self::Write | Self::ReadWrite),
            Self::Write => matches!(requested, Self::Write | Self::ReadWrite),
            _ => self == requested,
        }
    }

    /// Whether `self` covers every access level that `other` covers.
    ///
    /// Used by merge to decide whether a deny rule fully shadows an allow
    /// rule. `Write` does NOT supersede `ReadWrite` because `ReadWrite`
    /// covers `Read` while `Write` does not.
    #[must_use]
    pub fn access_superset(self, other: Self) -> bool {
        [
            Self::Read,
            Self::Write,
            Self::ReadWrite,
            Self::Execute,
            Self::All,
        ]
        .iter()
        .all(|&v| !other.covers(v) || self.covers(v))
    }

    /// Smallest access that conservatively represents both observations.
    ///
    /// This is stricter than [`Self::union`]: combining an observed read with
    /// an observed `read_write` must stay `read_write`, not collapse to
    /// `write` through policy coverage semantics.
    #[must_use]
    pub fn combine_observed(self, other: Self) -> Self {
        if self == other {
            return self;
        }

        if self == Self::All || other == Self::All {
            return Self::All;
        }

        if self == Self::ReadWrite || other == Self::ReadWrite {
            return Self::ReadWrite;
        }

        if matches!(
            (self, other),
            (Self::Read, Self::Write) | (Self::Write, Self::Read)
        ) {
            Self::ReadWrite
        } else {
            Self::All
        }
    }

    /// Smallest policy access that covers both access levels.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
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

/// Map directory `FAN_OPEN_EXEC_PERM` (traverse) to [`FileAccess::Read`].
///
/// Fanotify reports search permission as execute; recursive glob rules (e.g.
/// `./.git/**`, `./crates`) must still cover `ls` / `opendir`.
#[must_use]
pub fn normalize_directory_traverse_access(path: &Path, access: FileAccess) -> FileAccess {
    if access == FileAccess::Execute && std::fs::metadata(path).is_ok_and(|meta| meta.is_dir()) {
        FileAccess::Read
    } else {
        access
    }
}

/// Map `open(2)`/`openat(2)` flag bits to [`FileAccess`].
///
/// Uses `O_ACCMODE` per `fcntl(2)`, but creation/truncation still count as
/// write semantics even when the access mode bits alone say read-only.
/// `creat(2)` is therefore naturally classified as write-equivalent.
#[must_use]
pub fn open_flags_to_file_access(flags: i32) -> FileAccess {
    let access = match flags & libc::O_ACCMODE {
        libc::O_RDONLY => FileAccess::Read,
        libc::O_WRONLY => FileAccess::Write,
        _ => FileAccess::ReadWrite,
    };

    if flags & (libc::O_CREAT | libc::O_TRUNC) != 0 {
        access.combine_observed(FileAccess::Write)
    } else {
        access
    }
}

/// Identity of a filesystem rule: a path plus the access level it applies to.
///
/// Used as the hash key that deduplicates and aggregates [`FilesystemRule`]s
/// (e.g. merging an observed access with a matching rule).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilesystemRuleKey {
    /// Path the rule applies to.
    pub path: PathBuf,
    /// Access level the rule grants or denies.
    pub access: FileAccess,
}

impl FilesystemRuleKey {
    /// Construct a new key from an explicit path and access level.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, access: FileAccess) -> Self {
        Self {
            path: path.into(),
            access,
        }
    }

    /// Derive the key from a [`FilesystemRule`], trimming trailing slashes from
    /// its path so equivalent path spellings share one key.
    #[must_use]
    pub fn from_rule(rule: &FilesystemRule) -> Self {
        Self::new(
            rule.path.to_string_lossy().trim_end_matches('/'),
            rule.access,
        )
    }
}

/// Compiled path matching strategy: literal prefix or glob pattern.
enum CompiledPath {
    /// Literal path used for exact/descendant prefix matching.
    Prefix(PathBuf),

    /// Compiled glob matcher.
    Glob(GlobMatcher),
}

fn expand_match_path(path: &Path, project_root: Option<&Path>, canonicalize: bool) -> PathBuf {
    if canonicalize {
        return expand_policy_path(path, None, project_root);
    }

    project_root.map_or_else(
        || expand_home_path(path, None),
        |root| expand_project_relative(&expand_home_path(path, None), root),
    )
}

impl CompiledPath {
    /// Compile a policy path into a matcher.
    ///
    /// Paths containing glob syntax become a `Glob`; otherwise they are
    /// treated as literal `Prefix` paths.
    fn compile(path: &Path, project_root: Option<&Path>) -> Result<Self, globset::Error> {
        Self::compile_with_aliases(path, project_root, true)
    }

    fn compile_raw(path: &Path, project_root: Option<&Path>) -> Result<Self, globset::Error> {
        Self::compile_with_aliases(path, project_root, false)
    }

    fn compile_with_aliases(
        path: &Path,
        project_root: Option<&Path>,
        canonicalize: bool,
    ) -> Result<Self, globset::Error> {
        let expanded = expand_match_path(path, project_root, canonicalize);
        let expanded_str = expanded.to_string_lossy();

        if contains_glob_syntax(&expanded_str) {
            let glob = build_glob(&expanded_str)?.compile_matcher();
            Ok(Self::Glob(glob))
        } else {
            Ok(Self::Prefix(normalize_rule_path(&expanded)))
        }
    }
}

/// Return whether a path contains glob syntax supported by policy matching.
#[must_use]
pub fn contains_glob_syntax(value: &str) -> bool {
    value.contains(['*', '?', '[', '{', '\\'])
}

fn prefix_matches(rule_path: &Path, requested: &Path, require_directory_boundary: bool) -> bool {
    if rule_path == Path::new("/") {
        return requested.starts_with("/");
    }

    if rule_path == requested {
        return true;
    }

    let Ok(rest) = requested.strip_prefix(rule_path) else {
        return false;
    };

    !require_directory_boundary || rest.starts_with("/")
}

fn compiled_matches(
    compiled: CompiledPath,
    requested: &Path,
    require_directory_boundary: bool,
) -> bool {
    match compiled {
        CompiledPath::Prefix(rule_path) => {
            prefix_matches(&rule_path, requested, require_directory_boundary)
        }

        CompiledPath::Glob(matcher) => matcher.is_match(requested),
    }
}

fn path_matches_rule(
    rule_path: &Path,
    requested: &Path,
    project_root: Option<&Path>,
    require_directory_boundary: bool,
) -> bool {
    let requested = normalize_rule_path(requested);
    let raw = CompiledPath::compile_raw(rule_path, project_root);

    if let Ok(compiled) = raw
        && compiled_matches(compiled, &requested, require_directory_boundary)
    {
        return true;
    }

    let Ok(compiled) = CompiledPath::compile(rule_path, project_root) else {
        // A malformed glob saved as a rule (user-typed, free-form) cannot match.
        // Previously a panic via .expect; now degrades gracefully.
        return false;
    };

    compiled_matches(compiled, &requested, require_directory_boundary)
}

/// One allow or deny rule for a filesystem path.
///
/// `path` may be absolute (`/foo`), home-relative (`~/foo`),
/// project-relative (`./foo`), or a glob pattern. The rule matches
/// when its path matches the requested path and its `access` covers the
/// requested access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilesystemRule {
    /// Path the rule applies to.
    ///
    /// May contain glob syntax; see [`contains_glob_syntax`].
    pub path: PathBuf,
    /// Access level the rule grants or denies.
    pub access: FileAccess,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional human-readable annotation attached to the rule.
    pub comment: Option<String>,
}

impl FilesystemRule {
    /// Construct a new rule from a path, access level, and comment.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, access: FileAccess, comment: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            access,
            comment: Some(comment.into()),
        }
    }

    /// Whether this rule's path matches the requested path (exact, descendant,
    /// or glob).
    ///
    /// A rule whose `self.path` is a malformed glob pattern (e.g. an unclosed
    /// `[`) is treated as non-matching rather than panicking. Such rules
    /// can arise when a user types a free-form path into the approval text
    /// field.
    #[must_use]
    pub fn path_matches(&self, requested: &Path, project_root: Option<&Path>) -> bool {
        if path_matches_rule(&self.path, requested, project_root, false) {
            return true;
        }

        // Symlink alias fallback: e.g. /var/run → /run. Only runs on a
        // miss, so the common case (exact path match) is O(1) with no
        // stat() syscall. Falls back to the raw path if canonicalization
        // fails (socket deleted between checks).
        let canonical = expand_policy_path(requested, None, project_root);

        canonical.as_path() != requested
            && path_matches_rule(&self.path, &canonical, project_root, false)
    }

    /// Whether this rule matches the given path and access request.
    #[must_use]
    pub fn matches(&self, path: &Path, access: FileAccess, project_root: Option<&Path>) -> bool {
        self.path_matches(path, project_root) && self.access.covers(access)
    }
}

fn normalize_rule_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    let trimmed = s.trim_end_matches('/');

    if trimmed.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(trimmed)
    }
}

/// Convert an absolute path under `home` to the `~/...` shorthand.
/// Paths outside `home` are returned unchanged.  `home` itself maps to `~`.
#[must_use]
pub fn contract_home_path(path: &Path, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return path.to_path_buf();
    };

    let s = path.to_string_lossy();
    let trimmed = s.trim_end_matches('/');
    let home_trimmed = home.to_string_lossy().trim_end_matches('/').to_string();

    if trimmed.is_empty() || home_trimmed.is_empty() {
        return path.to_path_buf();
    }

    if trimmed == home_trimmed {
        return PathBuf::from("~");
    }

    if let Some(rest) = trimmed.strip_prefix(&home_trimmed)
        && let Some(stripped) = rest.strip_prefix('/')
    {
        return PathBuf::from(format!("~/{stripped}"));
    }

    path.to_path_buf()
}

/// Convert an absolute path under `project_root` to the `./...` shorthand.
/// Paths outside `project_root` are returned unchanged.
#[must_use]
pub fn contract_project_path(path: &Path, project_root: Option<&Path>) -> PathBuf {
    let Some(project_root) = project_root.filter(|root| !root.as_os_str().is_empty()) else {
        return path.to_path_buf();
    };

    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    let canonical_root = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());

    let Some(relative) = canonical_path.strip_prefix(&canonical_root).ok() else {
        return path.to_path_buf();
    };

    if relative.as_os_str().is_empty() {
        return PathBuf::from(".");
    }

    PathBuf::from(".").join(relative)
}

/// Expand a `~/...` path to an absolute path under `home`.  Paths that do not
/// start with `~/` are returned unchanged.  When `home` is `None`, `~/` paths
/// are kept as-is (matching will then fail closed).
#[must_use]
pub fn expand_home_path(path: &Path, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return path.to_path_buf();
    };

    let s = path.to_string_lossy();
    let home_str = home.to_string_lossy();

    if s == "~" {
        return PathBuf::from(home_str.trim_end_matches('/'));
    }

    if let Some(rest) = s.strip_prefix("~/") {
        if rest.split('/').any(|part| part == "..") {
            return path.to_path_buf();
        }

        let base = home_str.trim_end_matches('/');
        let expanded = PathBuf::from(format!("{base}/{rest}"));

        if let Ok(home_canon) = home.canonicalize() {
            match expanded.canonicalize() {
                Ok(canonical) if canonical.starts_with(&home_canon) => return canonical,
                Ok(_) => return path.to_path_buf(),
                Err(_) if rest.split('/').any(|part| part == "..") => return path.to_path_buf(),
                Err(_) => return expanded,
            }
        }

        return expanded;
    }

    path.to_path_buf()
}

/// Expand a `./...` path to an absolute path under `project_root`.
///
/// Paths that do not start with `./` are returned unchanged. When
/// `project_root` is `None`, `./` paths are kept as-is (matching will then fail
/// closed).
#[must_use]
fn expand_project_relative(path: &Path, project_root: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    let pr = project_root.to_string_lossy();

    if s == "." {
        return PathBuf::from(pr.trim_end_matches('/'));
    }

    if let Some(rest) = s.strip_prefix("./") {
        let base = pr.trim_end_matches('/');
        return PathBuf::from(format!("{base}/{rest}"));
    }

    path.to_path_buf()
}

/// Apply home (`~/`), project-relative (`./`), then symlink canonicalization
/// in order.
///
/// Symlinks are resolved so that a rule stored as `/run/nscd/socket`
/// matches a request for `/var/run/nscd/socket`. Falls back to the expanded
/// path if canonicalization fails (e.g. the file does not exist yet).
#[must_use]
pub fn expand_policy_path(
    path: &Path,
    home: Option<&Path>,
    project_root: Option<&Path>,
) -> PathBuf {
    let expanded = expand_home_path(path, home);

    let expanded = if let Some(pr) = project_root {
        expand_project_relative(&expanded, pr)
    } else {
        expanded
    };

    let s = expanded.to_string_lossy();

    // Only canonicalize absolute literal paths. Glob patterns are left as-is
    // since canonicalize would fail on them.
    if s.starts_with('/') && !contains_glob_syntax(&s) {
        std::fs::canonicalize(&expanded).unwrap_or(expanded)
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
pub fn filesystem_approval_paths(path: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    let path_str = path.to_string_lossy();
    let norm = path_str.trim_end_matches('/');

    if norm.is_empty() {
        return vec![PathBuf::from("/")];
    }

    let home_trimmed = home.map(|h| h.to_string_lossy().trim_end_matches('/').to_string());
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = norm.to_string();

    loop {
        if seen.insert(current.clone()) {
            result.push(PathBuf::from(&current));
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
                result.push(PathBuf::from("/"));
            }

            break;
        }

        // Stop at home (include it) when path is under home
        if let Some(h) = &home_trimmed
            && parent == *h
        {
            if seen.insert(parent.clone()) {
                result.push(PathBuf::from(&parent));
            }

            break;
        }

        current = parent;
    }

    result
}

/// The `filesystem` policy section: ordered lists of allow and deny
/// [`FilesystemRule`]s.
///
/// When a request matches, rules are checked in order; a deny that matches
/// (after allow rules) is authoritative.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemSection {
    #[serde(default)]
    /// Allow rules.
    pub allow: Vec<FilesystemRule>,

    #[serde(default)]
    /// Deny rules.
    pub deny: Vec<FilesystemRule>,
}

/// Kind of capability-granting resource gated by the seccomp broker.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    #[default]
    /// A Unix-domain socket accessed by `connect(2)` / `sendto(2)`.
    UnixSocket,

    /// A device node opened by the broker.
    Device,
}
impl ResourceKind {
    /// Return the stable wire / policy-file name of this resource kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnixSocket => "unix_socket",
            Self::Device => "device",
        }
    }
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Access mode for a Unix-domain socket resource.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocketAccess {
    #[default]
    /// `connect(2)` to the socket.
    Connect,

    /// `sendto(2)`/`sendmsg(2)` on the socket.
    Send,

    /// Both connecting and sending.
    All,
}

/// Access mode for a broker-opened device resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceAccess {
    /// Open the device read-only.
    Read,

    /// Open the device write-only.
    Write,

    /// Open the device read-write.
    ReadWrite,
}

/// Access mode for a capability-granting resource.
///
/// Serialization remains flat for policy files and RPC compatibility:
/// `connect`, `send`, `all`, `open_read`, `open_write`, and `open_read_write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceAccess {
    /// Access to a Unix-domain socket resource.
    Socket(SocketAccess),

    /// Access to a device node opened by the broker.
    Device(DeviceAccess),
}

impl Default for ResourceAccess {
    fn default() -> Self {
        Self::Socket(SocketAccess::Connect)
    }
}

impl ResourceAccess {
    /// Return the flat wire / policy-file name of this access.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Socket(SocketAccess::Connect) => "connect",
            Self::Socket(SocketAccess::Send) => "send",
            Self::Socket(SocketAccess::All) => "all",
            Self::Device(DeviceAccess::Read) => "open_read",
            Self::Device(DeviceAccess::Write) => "open_write",
            Self::Device(DeviceAccess::ReadWrite) => "open_read_write",
        }
    }

    /// Return the [`ResourceKind`] this access applies to.
    #[must_use]
    pub const fn kind(self) -> ResourceKind {
        match self {
            Self::Socket(_) => ResourceKind::UnixSocket,
            Self::Device(_) => ResourceKind::Device,
        }
    }

    /// Whether this access level covers the requested access.
    #[must_use]
    pub const fn covers(self, requested: Self) -> bool {
        matches!(
            (self, requested),
            (Self::Socket(SocketAccess::All), Self::Socket(_))
                | (
                    Self::Socket(SocketAccess::Connect),
                    Self::Socket(SocketAccess::Connect)
                )
                | (
                    Self::Socket(SocketAccess::Send),
                    Self::Socket(SocketAccess::Send)
                )
                | (Self::Device(DeviceAccess::ReadWrite), Self::Device(_))
                | (
                    Self::Device(DeviceAccess::Read),
                    Self::Device(DeviceAccess::Read)
                )
                | (
                    Self::Device(DeviceAccess::Write),
                    Self::Device(DeviceAccess::Write)
                )
        )
    }

    /// Smallest policy access that covers both access levels, or `None` if
    /// the two accesses are incompatible.
    #[must_use]
    pub const fn union(self, other: Self) -> Option<Self> {
        if self.covers(other) {
            Some(self)
        } else if other.covers(self) {
            Some(other)
        } else {
            match (self, other) {
                (Self::Socket(SocketAccess::Connect), Self::Socket(SocketAccess::Send))
                | (Self::Socket(SocketAccess::Send), Self::Socket(SocketAccess::Connect)) => {
                    Some(Self::Socket(SocketAccess::All))
                }

                (Self::Device(DeviceAccess::Read), Self::Device(DeviceAccess::Write))
                | (Self::Device(DeviceAccess::Write), Self::Device(DeviceAccess::Read)) => {
                    Some(Self::Device(DeviceAccess::ReadWrite))
                }

                _ => None,
            }
        }
    }
}

impl Serialize for ResourceAccess {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ResourceAccess {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "connect" => Ok(Self::Socket(SocketAccess::Connect)),
            "send" => Ok(Self::Socket(SocketAccess::Send)),
            "all" => Ok(Self::Socket(SocketAccess::All)),
            "open_read" => Ok(Self::Device(DeviceAccess::Read)),
            "open_write" => Ok(Self::Device(DeviceAccess::Write)),
            "open_read_write" => Ok(Self::Device(DeviceAccess::ReadWrite)),

            value => Err(serde::de::Error::custom(format!(
                "invalid resource access {value:?}"
            ))),
        }
    }
}

impl std::fmt::Display for ResourceAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identity of a resource rule: the resource kind, path, and access level.
///
/// Acts as the hash key that deduplicates and aggregates [`ResourceRule`]s.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceRuleKey {
    /// Kind of resource the rule applies to.
    pub kind: ResourceKind,
    /// Path of the resource the rule applies to.
    pub path: PathBuf,
    /// Access level the rule grants or denies.
    pub access: ResourceAccess,
}

impl ResourceRuleKey {
    /// Construct a new key from an explicit kind, path, and access level.
    #[must_use]
    pub fn new(kind: ResourceKind, path: impl Into<PathBuf>, access: ResourceAccess) -> Self {
        Self {
            kind,
            path: path.into(),
            access,
        }
    }

    /// Derive the key from a [`ResourceRule`], trimming trailing slashes from
    /// its path so equivalent path spellings share one key.
    #[must_use]
    pub fn from_rule(rule: &ResourceRule) -> Self {
        Self::new(
            rule.kind,
            rule.path.to_string_lossy().trim_end_matches('/'),
            rule.access,
        )
    }
}

/// One allow or deny rule for a capability-granting resource.
///
/// `path` may be absolute, home-relative (`~/foo`), project-relative
/// (`./foo`), or a glob pattern. The rule matches when the resource kind and
/// path match and `access` covers the requested access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceRule {
    /// Kind of resource the rule applies to.
    pub kind: ResourceKind,
    /// Path of the resource the rule applies to.
    ///
    /// May contain glob syntax; see [`contains_glob_syntax`].
    pub path: PathBuf,
    /// Access level the rule grants or denies.
    pub access: ResourceAccess,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional human-readable annotation attached to the rule.
    pub comment: Option<String>,
}

impl ResourceRule {
    /// Construct a new rule from a kind, path, access level, and comment.
    #[must_use]
    pub fn new(
        kind: ResourceKind,
        path: impl Into<PathBuf>,
        access: ResourceAccess,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            access,
            comment: Some(comment.into()),
        }
    }

    /// Whether this rule's path matches the requested path (exact, descendant,
    /// or glob).
    ///
    /// A rule whose `self.path` is a malformed glob pattern (e.g. an unclosed
    /// `[`) is treated as non-matching rather than panicking. Such rules
    /// can arise when a user types a free-form path into the approval text
    /// field.
    #[must_use]
    pub fn path_matches(&self, requested: &Path, project_root: Option<&Path>) -> bool {
        if path_matches_rule(&self.path, requested, project_root, false) {
            return true;
        }

        // Symlink alias fallback: e.g. /var/run → /run. Only runs on a
        // miss, so the common case (exact path match) is O(1) with no
        // stat() syscall. Falls back to the raw path if canonicalization
        // fails (socket deleted between checks).
        let canonical = expand_policy_path(requested, None, project_root);

        canonical.as_path() != requested
            && path_matches_rule(&self.path, &canonical, project_root, false)
    }

    /// Whether this rule matches the given kind, path, and access request.
    #[must_use]
    pub fn matches(
        &self,
        kind: ResourceKind,
        path: &Path,
        access: ResourceAccess,
        project_root: Option<&Path>,
    ) -> bool {
        self.kind == kind
            && self.access.kind() == self.kind
            && self.path_matches(path, project_root)
            && self.access.covers(access)
    }
}

/// The `resources` policy section: ordered lists of allow and deny
/// [`ResourceRule`]s that gate Unix-domain-socket and device resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceSection {
    #[serde(default)]
    /// Allow rules.
    pub allow: Vec<ResourceRule>,

    #[serde(default)]
    /// Deny rules.
    pub deny: Vec<ResourceRule>,
}

/// D-Bus bus selected by a relay target.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum DbusBus {
    #[default]
    /// The per-user session bus.
    Session,

    /// The machine-wide system bus.
    System,
}

/// D-Bus message kind visible to the policy relay.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum DbusMessageKind {
    #[default]
    /// A method call from one peer to another.
    MethodCall,

    /// The reply to a method call.
    MethodReturn,

    /// An error reply to a method call.
    Error,

    /// A broadcast signal emitted by a peer.
    Signal,
}

/// Opaque metadata for one file descriptor carried by a D-Bus message.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DbusFdMetadata {
    #[serde(default)]
    /// Kind of file descriptor (e.g. an fd name) attached to the message.
    pub kind: String,

    #[serde(default)]
    /// Whether the descriptor grants read-only access.
    pub read_only: bool,
}

/// Structured identity of a D-Bus message.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DbusTarget {
    /// Bus the message traverses.
    pub bus: DbusBus,
    /// Destination service name of the message.
    pub destination: String,
    /// Object path addressed by the message.
    pub object_path: String,
    /// Interface the message targets.
    pub interface: String,
    /// Method or signal name of the message.
    pub member: String,
    /// Kind of D-Bus message.
    pub message_kind: DbusMessageKind,
    /// D-Bus signature (type encoding) of the message body.
    pub signature: String,

    #[serde(default)]
    /// Metadata for any file descriptors carried by the message.
    pub fd_metadata: Vec<DbusFdMetadata>,
}

impl DbusTarget {
    /// Construct a target for a message on the session bus.
    #[must_use]
    pub fn session(
        destination: impl Into<String>,
        object_path: impl Into<String>,
        interface: impl Into<String>,
        member: impl Into<String>,
        message_kind: DbusMessageKind,
        signature: impl Into<String>,
        fd_metadata: Vec<DbusFdMetadata>,
    ) -> Self {
        Self {
            bus: DbusBus::Session,
            destination: destination.into(),
            object_path: object_path.into(),
            interface: interface.into(),
            member: member.into(),
            message_kind,
            signature: signature.into(),
            fd_metadata,
        }
    }
}

/// Declarative D-Bus rule. Target string fields accept globset syntax.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DbusRule {
    /// The message target this rule matches.
    pub target: DbusTarget,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional human-readable annotation attached to the rule.
    pub comment: Option<String>,
}

impl DbusRule {
    /// Construct a new rule from a target and comment.
    #[must_use]
    pub fn new(target: DbusTarget, comment: impl Into<String>) -> Self {
        Self {
            target,
            comment: Some(comment.into()),
        }
    }

    /// Whether this rule matches the given message target.
    ///
    /// The bus, message kind, and fd metadata must match exactly; the other
    /// string fields match as globset patterns.
    #[must_use]
    pub fn matches(&self, target: &DbusTarget) -> bool {
        if self.target.bus != target.bus
            || self.target.message_kind != target.message_kind
            || self.target.fd_metadata != target.fd_metadata
        {
            return false;
        }

        glob_matches(&self.target.destination, &target.destination)
            && glob_matches(&self.target.object_path, &target.object_path)
            && glob_matches(&self.target.interface, &target.interface)
            && glob_matches(&self.target.member, &target.member)
            // D-Bus signatures use braces that globset treats as alternation syntax.
            && (self.target.signature == target.signature
                || glob_matches(&self.target.signature, &target.signature))
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    build_glob(pattern).is_ok_and(|glob| glob.compile_matcher().is_match(value))
}

/// The `dbus` policy section: ordered lists of allow and deny [`DbusRule`]s
/// that gate messages relayed over D-Bus.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbusSection {
    #[serde(default)]
    /// Allow rules.
    pub allow: Vec<DbusRule>,

    #[serde(default)]
    /// Deny rules.
    pub deny: Vec<DbusRule>,
}

/// The complete on-disk policy document, organized into per-resource sections.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    #[serde(default)]
    /// Network section: direct and HTTP allow/deny rules.
    pub network: NetworkSection,

    #[serde(default)]
    /// Sudo section: argv allow/deny rules.
    pub sudo: SudoSection,

    #[serde(default)]
    /// Filesystem section: path allow/deny rules.
    pub filesystem: FilesystemSection,

    #[serde(default)]
    /// Resources section: capability-granting resource allow/deny rules.
    pub resources: ResourceSection,

    #[serde(default)]
    /// D-Bus section: message allow/deny rules.
    pub dbus: DbusSection,
}

/// Network rules for direct (host/port) connections.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectNetworkSection {
    #[serde(default)]
    /// Allow rules.
    pub allow: Vec<NetworkRule>,

    #[serde(default)]
    /// Deny rules.
    pub deny: Vec<NetworkRule>,
}

/// The `network` policy section, split into direct and HTTP rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSection {
    #[serde(default)]
    /// Direct host/port connection rules.
    pub direct: DirectNetworkSection,

    #[serde(default)]
    /// HTTP request rules.
    pub http: HttpSection,
}

/// HTTP allow and deny rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpSection {
    #[serde(default)]
    /// Allow rules.
    pub allow: Vec<HttpRule>,

    #[serde(default)]
    /// Deny rules.
    pub deny: Vec<HttpRule>,
}

/// The `sudo` policy section: argv allow and deny rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoSection {
    #[serde(default)]
    /// Allow rules.
    pub allow: Vec<SudoRule>,

    #[serde(default)]
    /// Deny rules.
    pub deny: Vec<SudoRule>,
}

/// One allow or deny rule for a direct (host/port) connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRule {
    /// Host name or IP the rule applies to.
    pub host: String,
    /// Port the rule applies to.
    pub port: u16,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional human-readable annotation attached to the rule.
    pub comment: Option<String>,
}

/// One allow or deny rule for a `sudo` command.
///
/// The rule matches when the requested argv begins with `argv`, permitting
/// deny/allow of a command with any arguments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoRule {
    /// Command and (optionally) argument prefix to match against.
    pub argv: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional human-readable annotation attached to the rule.
    pub comment: Option<String>,
}

impl NetworkRule {
    /// Construct a new rule from a host, port, and comment.
    pub fn new(host: impl Into<String>, port: u16, comment: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            comment: Some(comment.into()),
        }
    }

    /// Return the identity of this rule: host and port pair.
    #[must_use]
    pub fn key(&self) -> NetworkRuleKey {
        NetworkRuleKey::new(&self.host, self.port)
    }
}

impl SudoRule {
    /// Construct a new rule from an argv and comment.
    pub fn new(argv: Vec<String>, comment: impl Into<String>) -> Self {
        Self {
            argv,
            comment: Some(comment.into()),
        }
    }

    /// Return the argv as a stable key, or `None` when the argv is empty.
    #[must_use]
    pub fn key(&self) -> Option<Vec<String>> {
        if self.argv.is_empty() {
            None
        } else {
            Some(self.argv.clone())
        }
    }

    /// Whether this rule matches the given argv (as a prefix).
    #[must_use]
    pub fn matches(&self, argv: &[String]) -> bool {
        !self.argv.is_empty() && argv.starts_with(&self.argv)
    }

    /// Return every non-empty prefix of the given argv, longest first.
    ///
    /// Used to enumerate candidate `sudo` approval targets.
    #[must_use]
    pub fn approval_prefixes(argv: &[String]) -> Vec<Vec<String>> {
        let mut prefixes = Vec::with_capacity(argv.len());

        for len in (1..=argv.len()).rev() {
            prefixes.push(argv[..len].to_vec());
        }

        prefixes
    }
}

/// Identity of a filesystem object by inode and device number.
/// Two paths with the same `InodeIdentity` refer to the same on-disk
/// object, which means one is a hardlink of the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InodeIdentity {
    /// Inode number of the filesystem object.
    pub inode: u64,
    /// Device number of the filesystem containing the object.
    pub device: u64,
}

impl InodeIdentity {
    /// Stat a path and return its inode identity.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;

        std::fs::metadata(path)
            .map(|m| Self {
                inode: m.ino(),
                device: m.dev(),
            })
            .ok()
    }
}

#[cfg(test)]
mod dbus_tests {
    use super::{DbusBus, DbusFdMetadata, DbusMessageKind, DbusRule, DbusTarget};

    fn target(member: &str) -> DbusTarget {
        DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            member,
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        )
    }

    #[test]
    fn dbus_rules_accept_globs_by_default() {
        let rule = DbusRule::new(target("Read*"), "glob");
        assert!(rule.matches(&target("Read")));
        assert!(rule.matches(&target("ReadAll")));
        assert!(!rule.matches(&target("Write")));
    }

    #[test]
    fn dbus_globset_supports_question_mark_and_character_classes() {
        let question = DbusRule::new(target("Read?"), "");
        assert!(question.matches(&target("Read1")));
        assert!(!question.matches(&target("Read12")));
        let class = DbusRule::new(target("[RW]ead"), "");
        assert!(class.matches(&target("Read")));
        assert!(class.matches(&target("Wead")));
        assert!(!class.matches(&target("Xead")));
    }

    #[test]
    fn dbus_globset_supports_alternates_and_escapes() {
        let alternate = DbusRule::new(target("{Read,Write}"), "");
        assert!(alternate.matches(&target("Read")));
        assert!(alternate.matches(&target("Write")));
        assert!(!alternate.matches(&target("Close")));
        let escaped = DbusRule::new(target(r"Read\*"), "");
        assert!(escaped.matches(&target("Read*")));
        assert!(!escaped.matches(&target("ReadAll")));
    }

    #[test]
    fn dbus_rules_match_literal_signatures_with_braces() {
        let base_target = target("SearchItems");

        let rule = DbusRule::new(
            DbusTarget {
                signature: "a{ss}".into(),
                ..base_target
            },
            "",
        );

        let requested = DbusTarget {
            signature: "a{ss}".into(),
            ..target("SearchItems")
        };

        assert!(rule.matches(&requested));
    }

    #[test]
    fn dbus_globset_literal_separator_requires_double_star_for_paths() {
        let single = DbusRule::new(
            DbusTarget {
                object_path: "/org/*/Object".into(),
                ..target("Read")
            },
            "",
        );

        let star = DbusRule::new(
            DbusTarget {
                object_path: "*".into(),
                ..target("Read")
            },
            "",
        );

        let double = DbusRule::new(
            DbusTarget {
                object_path: "/org/**/Object".into(),
                ..target("Read")
            },
            "",
        );

        let nested = DbusTarget {
            object_path: "/org/example/team/Object".into(),
            ..target("Read")
        };

        assert!(!single.matches(&nested));
        assert!(!star.matches(&nested));
        assert!(double.matches(&nested));
    }

    #[test]
    fn dbus_bus_is_structured() {
        let mut system = target("Read");
        system.bus = DbusBus::System;
        assert!(!DbusRule::new(target("Read"), "").matches(&system));
    }

    #[test]
    fn dbus_rules_match_all_structured_fields() {
        let mut rule_target = target("Read");
        rule_target.object_path = "/org/example/*".into();
        rule_target.interface = "org.example.*".into();
        rule_target.signature = "s*".into();

        rule_target.fd_metadata = vec![DbusFdMetadata {
            kind: "memfd".into(),
            read_only: true,
        }];

        let fd_metadata = rule_target.fd_metadata.clone();
        let rule = DbusRule::new(rule_target, "structured");

        let matching = DbusTarget {
            fd_metadata,
            ..target("Read")
        };

        assert!(rule.matches(&matching));

        let mutations: [fn(&mut DbusTarget); 4] = [
            |target| target.object_path = "/other".into(),
            |target| target.interface = "org.other.Interface".into(),
            |target| target.signature = "a{sv}".into(),
            |target| target.fd_metadata.clear(),
        ];

        for mutate in mutations {
            let mut non_matching = matching.clone();
            mutate(&mut non_matching);
            assert!(!rule.matches(&non_matching));
        }
    }
}

/// Default path of the merged policy JSON policyd exports at startup.
pub const EXPORTED_POLICY_PATH: &str = "/var/lib/agent-sandbox/exported-policy.json";

/// Static filesystem allow rules loaded from policyd's exported merged
/// policy snapshot.
///
/// Enforcement components (fsmon, the syscall broker) answer events whose
/// (path, access) matches one of these rules locally: policyd would reach
/// the same verdict from its static policy layers, and the matching code is
/// the same [`FilesystemRule::matches`] the store uses. Deny rules and every
/// live verdict (session buckets, approvals, deny-inode cache) are never
/// replayed locally: anything that does not match is forwarded to policyd, so
/// runtime approvals keep working and no deny can be bypassed. The snapshot
/// is loaded once; editing policy files mid-session is out of scope by
/// design.
pub struct StaticPolicyAllow {
    rules: Vec<FilesystemRule>,
    project_root: Option<PathBuf>,
}

impl StaticPolicyAllow {
    /// Load the filesystem allow rules from a policyd policy export.
    ///
    /// Returns an empty evaluator when the file is missing or unparseable;
    /// callers then round-trip every event through policyd.
    #[must_use]
    pub fn load(path: &Path, project_root: Option<PathBuf>) -> Self {
        let rules = std::fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str::<Policy>(&content).ok())
            .map_or_else(
                || {
                    tracing::warn!(
                        path = %path.display(),
                        "cannot load static policy export; all events will round-trip policyd"
                    );

                    Vec::new()
                },
                |policy| policy.filesystem.allow,
            );

        Self {
            rules,
            project_root,
        }
    }

    /// Whether the static snapshot allows the given path and access mode.
    #[must_use]
    pub fn allows(&self, path: &Path, access: FileAccess) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.matches(path, access, self.project_root.as_deref()))
    }

    /// Whether the static snapshot allows every path/access pair.
    #[must_use]
    pub fn allows_all(&self, checks: &[(PathBuf, FileAccess)]) -> bool {
        checks
            .iter()
            .all(|(path, access)| self.allows(path, *access))
    }

    /// Whether the snapshot holds no usable rules (load failed or empty
    /// policy), so every event must round-trip policyd.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        DeviceAccess, FileAccess, FilesystemRule, Policy, ResourceAccess, ResourceKind,
        ResourceRule, SocketAccess, StaticPolicyAllow, SudoRule, contract_home_path,
        contract_project_path, expand_home_path, filesystem_approval_paths,
        open_flags_to_file_access,
    };

    #[test]
    fn expand_home_path_blocks_parent_traversal() {
        let home = Path::new("/home/user");
        let tmp = tempfile::tempdir().expect("tempdir");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).expect("outside dir");
        let escaped = expand_home_path(Path::new("~/../outside"), Some(home));

        assert_eq!(
            escaped,
            Path::new("~/../outside"),
            "traversal outside home must not expand"
        );
    }

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

        assert_eq!(SudoRule::approval_prefixes(&argv), vec![
            vec![
                "systemctl".to_string(),
                "restart".to_string(),
                "nginx".to_string()
            ],
            vec!["systemctl".to_string(), "restart".to_string()],
            vec!["systemctl".to_string()],
        ]);
    }

    #[test]
    fn normalize_directory_traverse_maps_execute_to_read_on_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pack = dir.path().join(".git/objects/pack");
        std::fs::create_dir_all(&pack).expect("pack dir");

        assert_eq!(
            super::normalize_directory_traverse_access(&pack, FileAccess::Execute),
            FileAccess::Read
        );

        let pack_file = pack.join("pack-abc.pack");
        std::fs::write(&pack_file, b"x").expect("pack file");

        assert_eq!(
            super::normalize_directory_traverse_access(&pack_file, FileAccess::Execute),
            FileAccess::Execute
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
    fn file_access_combine_observed_keeps_conservative_runtime_access() {
        assert_eq!(
            FileAccess::Read.combine_observed(FileAccess::Write),
            FileAccess::ReadWrite
        );

        assert_eq!(
            FileAccess::Read.combine_observed(FileAccess::Execute),
            FileAccess::All
        );

        assert_eq!(
            FileAccess::Read.combine_observed(FileAccess::ReadWrite),
            FileAccess::ReadWrite
        );
    }

    #[test]
    fn open_flags_classify_to_file_access() {
        assert_eq!(open_flags_to_file_access(libc::O_RDONLY), FileAccess::Read);
        assert_eq!(open_flags_to_file_access(libc::O_WRONLY), FileAccess::Write);

        assert_eq!(
            open_flags_to_file_access(libc::O_RDWR),
            FileAccess::ReadWrite
        );

        assert_eq!(
            open_flags_to_file_access(libc::O_RDWR | libc::O_APPEND),
            FileAccess::ReadWrite
        );

        assert_eq!(
            open_flags_to_file_access(libc::O_RDONLY | libc::O_CREAT),
            FileAccess::ReadWrite
        );

        assert_eq!(
            open_flags_to_file_access(libc::O_RDONLY | libc::O_TRUNC),
            FileAccess::ReadWrite
        );
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
    fn filesystem_rule_trailing_slash_matches_descendants() {
        // Regression: a rule path ending in '/' (e.g. from a Nix readwriteDirs
        // entry like "~/.local/state/opencode/") must still match its own
        // directory and its children. The matcher normalizes the requested path
        // but previously not the rule path, so the descendant prefix check
        // failed ("model.json" has no leading '/').
        let rule = FilesystemRule::new("/home/user/state/opencode/", FileAccess::ReadWrite, "");

        assert!(rule.path_matches(Path::new("/home/user/state/opencode"), None));
        assert!(rule.path_matches(Path::new("/home/user/state/opencode/model.json"), None));

        // Prefix boundary: a longer name sharing the prefix stem must not match.
        assert!(!rule.path_matches(Path::new("/home/user/state/opencode-other"), None));

        assert!(!rule.path_matches(Path::new("/home/user/elsewhere"), None));
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
    fn filesystem_globset_question_mark_matches_one_character() {
        let rule = FilesystemRule::new("/work/file?.txt", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/file1.txt"), None));
        assert!(!rule.path_matches(Path::new("/work/file12.txt"), None));
    }

    #[test]
    fn filesystem_globset_star_respects_literal_separator() {
        let rule = FilesystemRule::new("/work/*.txt", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/file.txt"), None));
        assert!(!rule.path_matches(Path::new("/work/sub/file.txt"), None));
    }

    #[test]
    fn filesystem_globset_double_star_matches_nested_paths() {
        let rule = FilesystemRule::new("/work/**/file.txt", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/file.txt"), None));
        assert!(rule.path_matches(Path::new("/work/sub/file.txt"), None));
        assert!(!rule.path_matches(Path::new("/work/file.bin"), None));
    }

    #[test]
    fn filesystem_globset_alternates_and_character_classes_match() {
        let rule = FilesystemRule::new("/work/{src,test}/[a-c][!x].rs", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/src/ab.rs"), None));
        assert!(rule.path_matches(Path::new("/work/test/cd.rs"), None));
        assert!(!rule.path_matches(Path::new("/work/doc/ab.rs"), None));
        assert!(!rule.path_matches(Path::new("/work/src/ax.rs"), None));
    }

    #[test]
    fn filesystem_globset_escapes_match_literal_metacharacters() {
        let rule = FilesystemRule::new(r"/work/\*.txt", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/*.txt"), None));
        assert!(!rule.path_matches(Path::new("/work/file.txt"), None));
    }

    #[test]
    fn glob_dot_slash_prefix_expands_correctly() {
        let rule = FilesystemRule::new("./foo", FileAccess::Read, "");
        assert!(rule.path_matches(Path::new("/work/foo"), Some(Path::new("/work"))));
        assert!(rule.path_matches(Path::new("/work/foo/bar"), Some(Path::new("/work"))));
        assert!(!rule.path_matches(Path::new("/work/foobar"), Some(Path::new("/work"))));
    }

    #[test]
    fn git_directory_prefix_matches_inside_git_directory_with_project_root() {
        let rule = FilesystemRule::new("./.git", FileAccess::ReadWrite, "");
        let root = Path::new("/home/user/dotfiles");
        assert!(rule.matches(&root.join(".git"), FileAccess::ReadWrite, Some(root)));
        assert!(rule.matches(&root.join(".git/config"), FileAccess::ReadWrite, Some(root)));

        assert!(rule.matches(
            &root.join(".git/objects/pack"),
            FileAccess::Read,
            Some(root)
        ));

        assert!(rule.matches(
            &root.join(".git/objects/39/2aff17307d2091111c7a71e95580c632d90421"),
            FileAccess::ReadWrite,
            Some(root)
        ));
    }

    #[test]
    fn git_directory_prefix_without_project_root_does_not_match_absolute_git_paths() {
        let rule = FilesystemRule::new("./.git", FileAccess::ReadWrite, "");
        let root = Path::new("/home/user/dotfiles");
        assert!(!rule.matches(&root.join(".git/config"), FileAccess::ReadWrite, None));
    }

    #[test]
    fn globset_star_matches_across_slashes_by_default() {
        use globset::{Glob, GlobBuilder};

        let default = Glob::new("/home/user/dotfiles/.git*")
            .expect("glob")
            .compile_matcher();

        assert!(default.is_match("/home/user/dotfiles/.git/config"));

        let literal = GlobBuilder::new("/home/user/dotfiles/.git*")
            .literal_separator(true)
            .build()
            .expect("glob")
            .compile_matcher();

        assert!(!literal.is_match("/home/user/dotfiles/.git/config"));
    }

    #[test]
    fn git_directory_prefix_matches_files_inside() {
        let rule = FilesystemRule::new("./.git", FileAccess::ReadWrite, "");
        let root = Path::new("/home/user/dotfiles");
        assert!(rule.matches(&root.join(".git/config"), FileAccess::ReadWrite, Some(root)));
    }

    #[test]
    fn filesystem_approval_paths_exact_path_first() {
        let paths = filesystem_approval_paths(
            Path::new("/home/user/.local/share/foo"),
            Some(Path::new("/home/user")),
        );

        assert_eq!(
            paths[0],
            PathBuf::from("/home/user/.local/share/foo"),
            "exact path must be first"
        );
    }

    #[test]
    fn filesystem_approval_paths_under_home_stops_at_home() {
        let paths = filesystem_approval_paths(
            Path::new("/home/user/.local/share/foo"),
            Some(Path::new("/home/user")),
        );

        assert_eq!(paths, vec![
            PathBuf::from("/home/user/.local/share/foo"),
            PathBuf::from("/home/user/.local/share"),
            PathBuf::from("/home/user/.local"),
            PathBuf::from("/home/user"),
        ]);
    }

    #[test]
    fn filesystem_approval_paths_non_home_includes_root() {
        let paths = filesystem_approval_paths(
            Path::new("/nix/store/abc123/bin/hello"),
            Some(Path::new("/home/user")),
        );

        assert_eq!(paths, vec![
            PathBuf::from("/nix/store/abc123/bin/hello"),
            PathBuf::from("/nix/store/abc123/bin"),
            PathBuf::from("/nix/store/abc123"),
            PathBuf::from("/nix/store"),
            PathBuf::from("/nix"),
            PathBuf::from("/"),
        ]);
    }

    #[test]
    fn filesystem_approval_paths_root_path_returns_just_root() {
        let paths = filesystem_approval_paths(Path::new("/"), Some(Path::new("/home/user")));
        assert_eq!(paths, vec![PathBuf::from("/")]);
    }

    #[test]
    fn filesystem_approval_paths_home_exact_returns_just_home() {
        let paths =
            filesystem_approval_paths(Path::new("/home/user"), Some(Path::new("/home/user")));

        assert_eq!(paths, vec![PathBuf::from("/home/user")]);
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
            contract_home_path(Path::new("/home/user/.local/share/foo"), Some(home)),
            PathBuf::from("~/.local/share/foo")
        );

        assert_eq!(
            contract_home_path(Path::new("/home/user"), Some(home)),
            PathBuf::from("~")
        );

        assert_eq!(
            contract_home_path(Path::new("/home/user/"), Some(home)),
            PathBuf::from("~")
        );
    }

    #[test]
    fn contract_project_path_converts_unix_socket_under_project() {
        let project = Path::new("/home/user/repo");

        assert_eq!(
            contract_project_path(Path::new("/home/user/repo/.agent.sock"), Some(project)),
            PathBuf::from("./.agent.sock")
        );

        assert_eq!(
            contract_project_path(Path::new("/tmp/agent.sock"), Some(project)),
            PathBuf::from("/tmp/agent.sock")
        );
    }

    #[test]
    fn contract_home_path_leaves_non_home_paths_unchanged() {
        let home = Path::new("/home/user");

        assert_eq!(
            contract_home_path(Path::new("/nix/store"), Some(home)),
            PathBuf::from("/nix/store")
        );

        assert_eq!(
            contract_home_path(Path::new("/"), Some(home)),
            PathBuf::from("/")
        );

        assert_eq!(
            contract_home_path(Path::new("/home"), Some(home)),
            PathBuf::from("/home")
        );

        assert_eq!(
            contract_home_path(Path::new("/home/user2/file"), Some(home)),
            PathBuf::from("/home/user2/file")
        );
    }

    #[test]
    fn contract_home_path_without_home_is_passthrough() {
        assert_eq!(
            contract_home_path(Path::new("/home/user/.local/share/foo"), None),
            PathBuf::from("/home/user/.local/share/foo")
        );
    }

    #[test]
    fn expand_home_path_converts_tilde() {
        let home = Path::new("/home/user");

        assert_eq!(
            expand_home_path(Path::new("~/.local/share/foo"), Some(home)),
            PathBuf::from("/home/user/.local/share/foo")
        );

        assert_eq!(
            expand_home_path(Path::new("~"), Some(home)),
            PathBuf::from("/home/user")
        );
    }

    #[test]
    fn expand_home_path_leaves_absolute_paths_unchanged() {
        let home = Path::new("/home/user");

        assert_eq!(
            expand_home_path(Path::new("/nix/store"), Some(home)),
            PathBuf::from("/nix/store")
        );

        assert_eq!(
            expand_home_path(Path::new("/"), Some(home)),
            PathBuf::from("/")
        );
    }

    #[test]
    fn expand_home_path_without_home_keeps_tilde() {
        assert_eq!(
            expand_home_path(Path::new("~/.local/share/foo"), None),
            PathBuf::from("~/.local/share/foo")
        );
    }

    #[test]
    fn contract_expand_round_trip() {
        let home = Path::new("/home/user");
        let original = Path::new("/home/user/.local/share/foo/agent/models.db-wal");
        let contracted = contract_home_path(original, Some(home));

        assert_eq!(
            contracted,
            PathBuf::from("~/.local/share/foo/agent/models.db-wal")
        );

        let expanded = expand_home_path(&contracted, Some(home));
        assert_eq!(expanded, original);
    }

    #[test]
    fn resource_rule_matches_descendants_with_access_hierarchy() {
        let rule = ResourceRule::new(
            ResourceKind::Device,
            "/dev/fd",
            ResourceAccess::Device(DeviceAccess::ReadWrite),
            "",
        );

        assert!(rule.matches(
            ResourceKind::Device,
            Path::new("/dev/fd/3"),
            ResourceAccess::Device(DeviceAccess::Read),
            None
        ));

        assert!(rule.matches(
            ResourceKind::Device,
            Path::new("/dev/fd/3"),
            ResourceAccess::Device(DeviceAccess::Write),
            None
        ));

        assert!(!rule.matches(
            ResourceKind::Device,
            Path::new("/dev/fd/3"),
            ResourceAccess::Socket(SocketAccess::Connect),
            None
        ));

        assert!(!rule.matches(
            ResourceKind::UnixSocket,
            Path::new("/dev/fd/3"),
            ResourceAccess::Device(DeviceAccess::Read),
            None
        ));
    }

    #[test]
    fn resource_socket_connect_and_send_are_distinct() {
        let connect_rule = ResourceRule::new(
            ResourceKind::UnixSocket,
            "/tmp/example.sock",
            ResourceAccess::Socket(SocketAccess::Connect),
            "",
        );

        assert!(connect_rule.matches(
            ResourceKind::UnixSocket,
            Path::new("/tmp/example.sock"),
            ResourceAccess::Socket(SocketAccess::Connect),
            None
        ));

        assert!(!connect_rule.matches(
            ResourceKind::UnixSocket,
            Path::new("/tmp/example.sock"),
            ResourceAccess::Socket(SocketAccess::Send),
            None
        ));

        let send_rule = ResourceRule::new(
            ResourceKind::UnixSocket,
            "/tmp/example.sock",
            ResourceAccess::Socket(SocketAccess::Send),
            "",
        );

        assert!(send_rule.matches(
            ResourceKind::UnixSocket,
            Path::new("/tmp/example.sock"),
            ResourceAccess::Socket(SocketAccess::Send),
            None
        ));

        assert!(!send_rule.matches(
            ResourceKind::UnixSocket,
            Path::new("/tmp/example.sock"),
            ResourceAccess::Socket(SocketAccess::Connect),
            None
        ));

        let all = ResourceAccess::Socket(SocketAccess::All);
        assert!(all.covers(ResourceAccess::Socket(SocketAccess::Connect)));
        assert!(all.covers(ResourceAccess::Socket(SocketAccess::Send)));

        assert_eq!(
            ResourceAccess::Socket(SocketAccess::Connect)
                .union(ResourceAccess::Socket(SocketAccess::Send)),
            Some(all)
        );

        assert_eq!(
            serde_json::to_string(&all).expect("serialize socket all"),
            "\"all\""
        );

        assert_eq!(
            serde_json::from_str::<ResourceAccess>("\"all\"").expect("deserialize socket all"),
            all
        );
    }

    #[test]
    fn resource_rule_trailing_slash_matches_descendants() {
        let rule = ResourceRule::new(
            ResourceKind::UnixSocket,
            "/run/user/1000/bus/",
            ResourceAccess::Socket(SocketAccess::Connect),
            "",
        );

        assert!(rule.path_matches(Path::new("/run/user/1000/bus"), None));
        assert!(rule.path_matches(Path::new("/run/user/1000/bus/socket"), None));
        assert!(!rule.path_matches(Path::new("/run/user/1000/bus-other"), None));
    }

    #[test]
    fn static_policy_allow_matches_allow_rules_only() {
        let mut policy = Policy::default();

        policy.filesystem.allow.push(FilesystemRule::new(
            "/home/user/bench",
            FileAccess::All,
            "test",
        ));
        policy
            .filesystem
            .allow
            .push(FilesystemRule::new("/readonly", FileAccess::Read, "test"));

        let eval = StaticPolicyAllow {
            rules: policy.filesystem.allow,
            project_root: None,
        };

        assert!(eval.allows(Path::new("/home/user/bench/run/f0"), FileAccess::ReadWrite));
        assert!(eval.allows(Path::new("/readonly"), FileAccess::Read));
        assert!(
            !eval.allows(Path::new("/readonly"), FileAccess::Write),
            "access mode must match"
        );
        assert!(!eval.allows(Path::new("/denied"), FileAccess::Read));
        assert!(
            !eval.allows(Path::new("/home/user/benchmark"), FileAccess::Read),
            "prefix must not match"
        );
        assert!(eval.allows_all(&[
            (PathBuf::from("/home/user/bench/a"), FileAccess::Read),
            (PathBuf::from("/readonly"), FileAccess::Read),
        ]));
        assert!(!eval.allows_all(&[
            (PathBuf::from("/home/user/bench/a"), FileAccess::Read),
            (PathBuf::from("/denied"), FileAccess::Read),
        ]));
    }

    #[test]
    fn static_policy_load_falls_back_to_empty_on_missing_file() {
        let eval = StaticPolicyAllow::load(
            Path::new("/nonexistent/agent-sandbox-exported-policy.json"),
            None,
        );

        assert!(eval.is_empty());
        assert!(!eval.allows(Path::new("/anything"), FileAccess::Read));
    }
}
