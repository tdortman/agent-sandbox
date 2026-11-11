use std::path::{Path, PathBuf};

use super::{
    CompiledPath, FileAccess, FilesystemCheck, FilesystemRule, PathResolution, Policy,
    compiled_matches, expand_policy_path, normalize_rule_path,
};

/// Static filesystem allow rules from a merged policy snapshot.
///
/// Matches path and access against immutable allow and deny rules. Every
/// alias-derived grant is confirmed by [`FilesystemRule::matches`]. A matching
/// deny always wins over an allow in this snapshot; deny rule aliases are
/// resolved when the snapshot is built.
///
/// Callers own snapshot refresh and any checks outside these rules, including
/// policyd's deny-inode defense; `policy_replica` keeps a copy fresh and
/// carries the inode defense. Session approvals and other live verdicts are
/// not cached here.
pub struct StaticPolicyAllow {
    rules: Vec<StaticRule>,

    deny: Vec<StaticRule>,

    project_root: Option<PathBuf>,
}

struct StaticRule {
    rule: FilesystemRule,

    // The rule path compiled as written.
    literal: Option<CompiledPath>,

    // The rule path compiled with its symlink aliases resolved at load. For
    // allows only a prefilter: hits are confirmed by `FilesystemRule::matches`,
    // whose aliases are at most `RULE_PATH_CACHE_TTL` old, so a retargeted
    // alias soon grants nothing locally (policyd decides it). For denies it is
    // the alias as of load; callers rebuild the snapshot to follow a
    // retargeted alias.
    alias: Option<CompiledPath>,
}

impl StaticRule {
    fn compile(rule: FilesystemRule, project_root: Option<&Path>) -> Self {
        Self {
            literal: CompiledPath::compile_raw(&rule.path, project_root).ok(),
            alias: CompiledPath::compile(&rule.path, project_root).ok(),
            rule,
        }
    }

    fn hits(&self, requested: &Path) -> bool {
        [&self.literal, &self.alias].into_iter().any(|compiled| {
            compiled
                .as_ref()
                .is_some_and(|compiled| compiled_matches(compiled, requested, false))
        })
    }
}

impl StaticPolicyAllow {
    /// Build the evaluator from an already merged policy.
    #[must_use]
    pub fn from_policy(policy: Policy, project_root: Option<PathBuf>) -> Self {
        let compile = |rules: Vec<FilesystemRule>| {
            rules
                .into_iter()
                .map(|rule| StaticRule::compile(rule, project_root.as_deref()))
                .collect()
        };

        Self {
            rules: compile(policy.filesystem.allow),
            deny: compile(policy.filesystem.deny),
            project_root,
        }
    }

    /// Whether a deny rule matches, so the request must go to policyd. Deny
    /// rule aliases are those resolved at load; an unresolved request is
    /// canonicalized live.
    fn denied(&self, path: &Path, access: FileAccess, resolution: PathResolution) -> bool {
        let mut rules = self
            .deny
            .iter()
            .filter(|deny| deny.rule.access.covers(access))
            .peekable();
        if rules.peek().is_none() {
            return false;
        }

        let requested = normalize_rule_path(path);
        let canonical = self.canonical_request(path, resolution);
        rules.any(|deny| {
            deny.hits(&requested) || canonical.as_ref().is_some_and(|path| deny.hits(path))
        })
    }

    /// The request with its symlinks resolved, when that differs from the
    /// path as given.
    fn canonical_request(&self, path: &Path, resolution: PathResolution) -> Option<PathBuf> {
        match resolution {
            PathResolution::Canonical => None,
            PathResolution::Unresolved => Some(normalize_rule_path(&expand_policy_path(
                path,
                None,
                self.project_root.as_deref(),
            ))),
        }
    }

    /// Whether the static snapshot allows the given path and access mode.
    #[must_use]
    pub fn allows(&self, path: &Path, access: FileAccess, resolution: PathResolution) -> bool {
        if self.denied(path, access, resolution) {
            return false;
        }

        if self.literal_grant(path, access) {
            return true;
        }

        let project_root = self.project_root.as_deref();
        let requested = normalize_rule_path(path);
        let canonical = self.canonical_request(path, resolution);

        self.rules.iter().any(|static_rule| {
            static_rule.rule.access.covers(access)
                && (static_rule.hits(&requested)
                    || canonical
                        .as_ref()
                        .is_some_and(|path| static_rule.hits(path)))
                && static_rule.rule.matches(path, access, project_root)
        })
    }

    /// Whether a rule grants access without resolving filesystem aliases in
    /// the allow rules. A miss does not exclude a grant through a live
    /// symlink alias.
    #[must_use]
    pub fn allows_literal(
        &self,
        path: &Path,
        access: FileAccess,
        resolution: PathResolution,
    ) -> bool {
        self.literal_grant(path, access) && !self.denied(path, access, resolution)
    }

    fn literal_grant(&self, path: &Path, access: FileAccess) -> bool {
        let requested = normalize_rule_path(path);

        self.rules.iter().any(|static_rule| {
            static_rule.rule.access.covers(access)
                && static_rule
                    .literal
                    .as_ref()
                    .is_some_and(|compiled| compiled_matches(compiled, &requested, false))
        })
    }

    /// Whether the static snapshot allows every path/access pair.
    #[must_use]
    pub fn allows_all(&self, checks: &[FilesystemCheck]) -> bool {
        checks
            .iter()
            .all(|check| self.allows(&check.path, check.access, PathResolution::Unresolved))
    }

    /// Whether the snapshot holds no usable rules (load failed or empty
    /// policy), so every event must round-trip policyd.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
