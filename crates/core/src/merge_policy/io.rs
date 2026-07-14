//! Load and atomically write policy JSON on disk.

use std::path::{Path, PathBuf};

use crate::hosts::NetworkSortKey;
use crate::http::HttpRule;
use crate::policy::{
    FilesystemRule, FilesystemSortKey, NetworkRule, Policy, ResourceRule, ResourceSortKey,
    SudoRule, contract_home_path, expand_policy_path,
};

/// Maximum on-disk policy JSON size policyd/core will load.
pub const MAX_POLICY_JSON_BYTES: usize = 1 << 20;

/// Maximum total allow+deny rules per policy section aggregate.
pub const MAX_POLICY_RULES: usize = 8192;
const fn policy_rule_count(policy: &Policy) -> usize {
    policy.network.direct.allow.len()
        + policy.network.direct.deny.len()
        + policy.network.http.allow.len()
        + policy.network.http.deny.len()
        + policy.sudo.allow.len()
        + policy.sudo.deny.len()
        + policy.filesystem.allow.len()
        + policy.filesystem.deny.len()
        + policy.resources.allow.len()
        + policy.resources.deny.len()
}

#[must_use]
pub fn load_policy(path: &Path, home: Option<&Path>, project_root: Option<&Path>) -> Policy {
    let Ok(Some((mut policy, _))) = load_policy_inner(path, project_root, false) else {
        return Policy::default();
    };
    expand_policy_paths(&mut policy, home, project_root);
    policy
}

/// Rewrite legacy direct network fields into the canonical
/// `network.direct` section.
///
/// # Errors
///
/// Returns an error when the policy cannot be read, parsed, validated, or
/// atomically rewritten.
pub fn migrate_policy(
    path: &Path,
    home: Option<&Path>,
    project_root: Option<&Path>,
) -> std::io::Result<bool> {
    let Some((policy, needs_migration)) = load_policy_inner(path, project_root, true)? else {
        return Ok(false);
    };
    if needs_migration {
        atomic_write_policy(path, &policy, home, None, project_root)?;
    }
    Ok(needs_migration)
}

fn validate_http_rules(policy: &Policy) -> std::io::Result<()> {
    for rule in policy
        .network
        .http
        .allow
        .iter()
        .chain(policy.network.http.deny.iter())
    {
        rule.target().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid HTTP rule: {error}"),
            )
        })?;
    }
    Ok(())
}

fn load_policy_inner(
    path: &Path,
    project_root: Option<&Path>,
    strict_http: bool,
) -> std::io::Result<Option<(Policy, bool)>> {
    if let Some(root) = project_root
        && let Ok(canonical_path) = path.canonicalize()
        && let Ok(canonical_root) = root.canonicalize()
        && !canonical_path.starts_with(&canonical_root)
    {
        return Ok(None);
    }
    let read_path = resolve_policy_write_path(path, project_root)?;
    if !read_path.is_file() {
        return Ok(None);
    }
    let meta = std::fs::metadata(&read_path)?;
    if meta.len() > MAX_POLICY_JSON_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "policy JSON exceeds the maximum size",
        ));
    }
    let data = std::fs::read_to_string(&read_path)?;
    let value = serde_json::from_str::<serde_json::Value>(&data).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid policy JSON: {error}"),
        )
    })?;
    let legacy_direct = value
        .get("network")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|network| network.contains_key("allow") || network.contains_key("deny"));
    let legacy_http_methods = value
        .get("network")
        .and_then(serde_json::Value::as_object)
        .and_then(|network| network.get("http"))
        .and_then(serde_json::Value::as_object)
        .is_some_and(|http| {
            ["allow", "deny"].into_iter().any(|name| {
                http.get(name)
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|rules| {
                        rules.iter().any(|rule| {
                            rule.as_object()
                                .is_some_and(|rule| rule.contains_key("method"))
                        })
                    })
            })
        });
    let needs_migration = legacy_direct || legacy_http_methods;
    let mut policy = serde_json::from_value::<Policy>(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid policy fields: {error}"),
        )
    })?;
    if policy_rule_count(&policy) > MAX_POLICY_RULES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "policy contains too many rules",
        ));
    }
    if strict_http {
        validate_http_rules(&policy)?;
    } else {
        policy
            .network
            .http
            .allow
            .retain(|rule| rule.target().is_ok());
        policy
            .network
            .http
            .deny
            .retain(|rule| rule.target().is_ok());
    }
    Ok(Some((policy, needs_migration)))
}

fn network_rule_sort_key(rule: &NetworkRule) -> NetworkSortKey {
    NetworkSortKey::new(&rule.host, rule.port)
}

fn http_rule_sort_key(rule: &HttpRule) -> (String, Vec<String>) {
    let url = rule
        .target()
        .map_or_else(|_| rule.url.clone(), |target| target.url.to_string());
    (url, rule.methods.clone())
}

fn sudo_rule_sort_key(rule: &SudoRule) -> Vec<String> {
    rule.argv.clone()
}

fn filesystem_rule_sort_key(rule: &FilesystemRule, home: Option<&Path>) -> FilesystemSortKey {
    FilesystemSortKey::new(contract_home_path(&rule.path, home), rule.access)
}
fn resource_rule_sort_key(rule: &ResourceRule, home: Option<&Path>) -> ResourceSortKey {
    ResourceSortKey::new(rule.kind, contract_home_path(&rule.path, home), rule.access)
}
fn sorted_policy(policy: &Policy, home: Option<&Path>) -> Policy {
    let mut out = policy.clone();
    out.network.direct.allow.sort_by_key(network_rule_sort_key);
    out.network.direct.deny.sort_by_key(network_rule_sort_key);
    out.network.http.allow.sort_by_key(http_rule_sort_key);
    out.network.http.deny.sort_by_key(http_rule_sort_key);
    out.sudo.allow.sort_by_key(sudo_rule_sort_key);
    out.sudo.deny.sort_by_key(sudo_rule_sort_key);
    out.filesystem
        .allow
        .sort_by_key(|rule| filesystem_rule_sort_key(rule, home));
    out.filesystem
        .deny
        .sort_by_key(|rule| filesystem_rule_sort_key(rule, home));
    out.resources
        .allow
        .sort_by_key(|rule| resource_rule_sort_key(rule, home));
    out.resources
        .deny
        .sort_by_key(|rule| resource_rule_sort_key(rule, home));
    out
}
fn expand_policy_paths(policy: &mut Policy, home: Option<&Path>, project_root: Option<&Path>) {
    for rule in &mut policy.filesystem.allow {
        rule.path = expand_policy_path(&rule.path, home, project_root);
    }
    for rule in &mut policy.filesystem.deny {
        rule.path = expand_policy_path(&rule.path, home, project_root);
    }
    for rule in &mut policy.resources.allow {
        rule.path = expand_policy_path(&rule.path, home, project_root);
    }
    for rule in &mut policy.resources.deny {
        rule.path = expand_policy_path(&rule.path, home, project_root);
    }
}
/// Resolve the policy write path, verifying symlink containment.
///
/// # Errors
///
/// Returns an error if canonicalization or stat operations fail, or if the
/// resolved path (or symlink target) escapes `expected_root`.
pub fn resolve_policy_write_path(
    path: &Path,
    expected_root: Option<&Path>,
) -> std::io::Result<PathBuf> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(path.to_path_buf());
    };
    if !meta.file_type().is_symlink() {
        // Not a symlink: verify containment if expected_root is given.
        if let Some(root) = expected_root {
            let canonical_path = path.canonicalize()?;
            let canonical_root = root.canonicalize()?;
            if !canonical_path.starts_with(&canonical_root) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "policy path escapes expected root",
                ));
            }
            return Ok(canonical_path);
        }
        return Ok(path.to_path_buf());
    }
    let link_target = std::fs::read_link(path)?;
    let resolved = if link_target.is_absolute() {
        link_target
    } else {
        path.parent()
            .unwrap_or_else(|| Path::new(""))
            .join(link_target)
    };
    let canonical = resolved.canonicalize().unwrap_or(resolved);
    // Verify symlink target containment.
    if let Some(root) = expected_root {
        let canonical_root = root.canonicalize()?;
        if !canonical.starts_with(&canonical_root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "policy symlink target escapes expected root",
            ));
        }
    }
    Ok(canonical)
}

#[must_use]
pub fn resolve_owner_uid(path: &Path, home: Option<&Path>, uid: Option<u32>) -> Option<u32> {
    if let Some(uid) = uid.filter(|u| *u > 0) {
        return Some(uid);
    }
    if let Some(home) = home
        && let Ok(meta) = std::fs::metadata(home)
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let u = meta.uid();
            if u > 0 {
                return Some(u);
            }
        }
    }
    if let Ok(resolved) = path.canonicalize() {
        let parts: Vec<_> = resolved
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if parts.len() >= 3
            && parts[1] == "home"
            && let Ok(Some(pw)) = nix::unistd::User::from_name(&parts[2])
        {
            return Some(pw.uid.as_raw());
        }
    }
    None
}

fn policy_chown_paths(target: &Path) -> Vec<PathBuf> {
    let Ok(target) = resolve_policy_write_path(target, None) else {
        return Vec::new();
    };
    let mut paths = Vec::with_capacity(2);
    if let Some(parent) = target.parent() {
        paths.push(parent.to_path_buf());
    }
    paths.push(target);
    paths
}

pub fn chown_policy_path(path: &Path, uid: u32) {
    if uid == 0 {
        return;
    }
    let Ok(Some(pw)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) else {
        return;
    };
    let gid = pw.gid;
    for entry in policy_chown_paths(path) {
        if !entry.exists() {
            continue;
        }
        let _ = nix::unistd::chown(&entry, Some(nix::unistd::Uid::from_raw(uid)), Some(gid));
    }
}

/// Atomically write policy data to disk.
///
/// # Errors
///
/// Returns an error if the policy path cannot be resolved, directory creation
/// fails, JSON serialization fails, the temporary file cannot be written or
/// renamed into place, or filesystem metadata operations fail.
pub fn atomic_write_policy(
    path: &Path,
    data: &Policy,
    home: Option<&Path>,
    owner_uid: Option<u32>,
    project_root: Option<&Path>,
) -> std::io::Result<()> {
    let target = resolve_policy_write_path(path, project_root)?;
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = target.with_file_name(format!(
        "{}.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("policy.json")
    ));
    let json = policy_json(&sorted_policy(&contracted_policy(data, home), home))? + "\n";
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &target)?;
    if let Some(uid) = resolve_owner_uid(path, home, owner_uid) {
        chown_policy_path(path, uid);
    }
    Ok(())
}

pub fn policy_json(policy: &Policy) -> serde_json::Result<String> {
    let mut json = String::new();
    json.push_str("{\n    \"network\": {\n        \"direct\": {\n");
    push_nested_rules(&mut json, "allow", &policy.network.direct.allow)?;
    json.push_str(",\n");
    push_nested_rules(&mut json, "deny", &policy.network.direct.deny)?;
    json.push_str("\n        },\n        \"http\": {\n");
    push_nested_rules(&mut json, "allow", &policy.network.http.allow)?;
    json.push_str(",\n");
    push_nested_rules(&mut json, "deny", &policy.network.http.deny)?;
    json.push_str("\n        }\n    },\n    \"sudo\": {\n");
    push_rules(&mut json, "allow", &policy.sudo.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.sudo.deny)?;
    json.push_str("\n    },\n    \"filesystem\": {\n");
    push_rules(&mut json, "allow", &policy.filesystem.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.filesystem.deny)?;
    json.push_str("\n    },\n    \"resources\": {\n");
    push_rules(&mut json, "allow", &policy.resources.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.resources.deny)?;
    json.push_str("\n    }\n}");
    Ok(json)
}
/// Return a copy of `policy` with filesystem and resource allow/deny paths
/// under `home` contracted to the `~/...` shorthand for on-disk serialization.
fn contracted_policy(policy: &Policy, home: Option<&Path>) -> Policy {
    let mut out = policy.clone();
    for rule in &mut out.filesystem.allow {
        rule.path = contract_home_path(&rule.path, home);
    }
    for rule in &mut out.filesystem.deny {
        rule.path = contract_home_path(&rule.path, home);
    }
    for rule in &mut out.resources.allow {
        rule.path = contract_home_path(&rule.path, home);
    }
    for rule in &mut out.resources.deny {
        rule.path = contract_home_path(&rule.path, home);
    }
    out
}

fn push_rules<T: serde::Serialize>(
    out: &mut String,
    name: &str,
    rules: &[T],
) -> serde_json::Result<()> {
    out.push_str("        \"");
    out.push_str(name);
    out.push_str("\": ");
    if rules.is_empty() {
        out.push_str("[]");
        return Ok(());
    }
    out.push_str("[\n");
    for (index, rule) in rules.iter().enumerate() {
        out.push_str("            ");
        push_spaced_json(out, &serde_json::to_string(rule)?);
        if index + 1 != rules.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("        ]");
    Ok(())
}

fn push_nested_rules<T: serde::Serialize>(
    out: &mut String,
    name: &str,
    rules: &[T],
) -> serde_json::Result<()> {
    out.push_str("            \"");
    out.push_str(name);
    out.push_str("\": ");
    if rules.is_empty() {
        out.push_str("[]");
        return Ok(());
    }
    out.push_str("[\n");
    for (index, rule) in rules.iter().enumerate() {
        out.push_str("                ");
        push_spaced_json(out, &serde_json::to_string(rule)?);
        if index + 1 != rules.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("            ]");
    Ok(())
}

fn push_spaced_json(out: &mut String, compact: &str) {
    let mut in_string = false;
    let mut escaped = false;
    for c in compact.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '{' => out.push_str("{ "),
            '}' => out.push_str(" }"),
            ':' => out.push_str(": "),
            ',' => out.push_str(", "),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FilesystemRule, NetworkRule};

    #[test]
    fn project_policy_chown_includes_parent_directory() {
        let path =
            Path::new("/home/user/.config/agent-sandbox/projects/home-user-repo/policy.json");
        let paths = policy_chown_paths(path);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/home/user/.config/agent-sandbox/projects/home-user-repo"),
                PathBuf::from(
                    "/home/user/.config/agent-sandbox/projects/home-user-repo/policy.json",
                ),
            ]
        );
    }

    #[test]
    fn policy_json_writes_home_paths_as_tilde() {
        let mut policy = crate::policy::Policy::default();
        policy.filesystem.allow = vec![FilesystemRule::new(
            "/home/user/.local/share/foo",
            FileAccess::All,
            "",
        )];
        let path = std::env::temp_dir().join("agent-sandbox-write-home.json");
        let _ = std::fs::remove_file(&path);
        atomic_write_policy(&path, &policy, Some(Path::new("/home/user")), None, None)
            .expect("write policy");
        let raw = std::fs::read_to_string(&path).expect("read file");
        assert!(
            raw.contains("\"~/.local/share/foo\""),
            "home path must serialize as ~/...: {raw}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_json_leaves_non_home_paths_absolute() {
        let mut policy = crate::policy::Policy::default();
        policy.filesystem.allow = vec![FilesystemRule::new("/nix/store", FileAccess::All, "")];
        let path = std::env::temp_dir().join("agent-sandbox-write-nonhome.json");
        let _ = std::fs::remove_file(&path);
        atomic_write_policy(&path, &policy, Some(Path::new("/home/user")), None, None)
            .expect("write policy");
        let raw = std::fs::read_to_string(&path).expect("read file");
        assert!(
            raw.contains("\"/nix/store\""),
            "non-home path must stay absolute: {raw}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_json_sorts_network_by_domain_hierarchy() {
        let mut policy = crate::policy::Policy::default();
        policy.network.direct.allow = vec![
            NetworkRule::new("docs.developer.apple.com", 443, "global"),
            NetworkRule::new("api.z.ai", 443, "global"),
            NetworkRule::new("developer.apple.com", 443, "global"),
            NetworkRule::new("example.com", 443, "global"),
            NetworkRule::new("r.jina.ai", 443, "global"),
            NetworkRule::new("api.example.com", 443, "global"),
        ];
        let path = std::env::temp_dir().join("agent-sandbox-write-network-order.json");
        let _ = std::fs::remove_file(&path);
        atomic_write_policy(&path, &policy, Some(Path::new("/home/user")), None, None)
            .expect("write policy");
        let loaded = load_policy(&path, Some(Path::new("/home/user")), None);
        let hosts: Vec<&str> = loaded
            .network
            .direct
            .allow
            .iter()
            .map(|rule| rule.host.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec![
                "developer.apple.com",
                "docs.developer.apple.com",
                "example.com",
                "api.example.com",
                "r.jina.ai",
                "api.z.ai",
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_policy_expands_tilde_to_home() {
        let home = Path::new("/home/user");
        let raw = r#"{
            "network": { "allow": [], "deny": [] },
            "sudo": { "allow": [], "deny": [] },
            "filesystem": {
                "allow": [ { "path": "~/.local/share/foo", "access": "all" } ],
                "deny": [ { "path": "~/.cache/secret", "access": "read" } ]
            }
        }"#;
        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("policy.json");
        std::fs::write(&path, raw).expect("write file");
        let loaded = load_policy(&path, Some(home), None);
        assert_eq!(
            loaded.filesystem.allow[0].path,
            Path::new("/home/user/.local/share/foo")
        );
        assert_eq!(
            loaded.filesystem.deny[0].path,
            Path::new("/home/user/.cache/secret")
        );
    }

    #[test]
    fn load_policy_leaves_other_user_paths_absolute() {
        let home = Path::new("/home/user");
        let raw = r#"{
            "network": { "allow": [], "deny": [] },
            "sudo": { "allow": [], "deny": [] },
            "filesystem": {
                "allow": [ { "path": "/home/user2/.cache", "access": "all" } ],
                "deny": []
            }
        }"#;
        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("policy.json");
        std::fs::write(&path, raw).expect("write file");
        let loaded = load_policy(&path, Some(home), None);
        assert_eq!(
            loaded.filesystem.allow[0].path,
            Path::new("/home/user2/.cache")
        );
    }

    #[test]
    fn load_policy_round_trip_through_disk() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("policy.json");
        let mut policy = crate::policy::Policy::default();
        policy.filesystem.allow = vec![
            FilesystemRule::new("/home/user/.local/share/foo", FileAccess::All, ""),
            FilesystemRule::new("/nix/store", FileAccess::Read, ""),
        ];
        atomic_write_policy(&path, &policy, Some(Path::new("/home/user")), None, None)
            .expect("write policy");
        let raw = std::fs::read_to_string(&path).expect("read file");
        assert!(raw.contains("\"~/.local/share/foo\""), "raw: {raw}");
        assert!(raw.contains("\"/nix/store\""), "raw: {raw}");
        let loaded = load_policy(&path, Some(Path::new("/home/user")), None);
        assert_eq!(loaded.filesystem.allow[0].path, Path::new("/nix/store"));
        assert_eq!(
            loaded.filesystem.allow[1].path,
            Path::new("/home/user/.local/share/foo")
        );
    }
}
