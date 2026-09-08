//! Load and atomically write policy JSON on disk.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use crate::{
    hosts::NetworkSortKey,
    http::HttpRule,
    policy::{
        FilesystemRule, FilesystemRuleKey, NetworkRule, Policy, ResourceRule, ResourceRuleKey,
        SudoRule, contract_home_path, expand_policy_path,
    },
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
/// Load the merged policy for a path, applying all layered policy files.
///
/// Reads the default system policy and any per-user/per-project policy under
/// `home`/`project_root`, merges them with deny-wins semantics, and expands
/// `~` paths against `home`. Returns the default empty policy on error.
pub fn load_policy(path: &Path, home: Option<&Path>, project_root: Option<&Path>) -> Policy {
    let Ok(Some(mut policy)) = load_policy_inner(path, project_root) else {
        return Policy::default();
    };

    expand_policy_paths(&mut policy, home, project_root);
    policy
}
fn load_policy_inner(path: &Path, project_root: Option<&Path>) -> std::io::Result<Option<Policy>> {
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

    let mut data = String::new();

    std::fs::File::open(&read_path)?
        .take((MAX_POLICY_JSON_BYTES + 1) as u64)
        .read_to_string(&mut data)?;

    let policy = parse_policy(&data).map(Some)?;
    maybe_migrate_policy_file(&read_path, &data);
    Ok(policy)
}

fn is_nix_store_path(path: &Path) -> bool {
    path.starts_with("/nix/store")
}

/// Best-effort on-load upgrade of legacy HTTP rules to `{url, port}` form.
///
/// Never alters the returned in-memory policy: failures only skip the rewrite
/// and emit a warning. Skips immutable `/nix/store` files, invalid documents,
/// files with any malformed HTTP rule, and files needing no change. The target
/// is re-read just before `rename`; a mismatch with the observed bytes skips
/// the write. A concurrent writer can still slip between that recheck and
/// `rename`, so the check narrows but does not eliminate the race.
fn maybe_migrate_policy_file(read_path: &Path, original_data: &str) {
    if is_nix_store_path(read_path) {
        return;
    }

    let Some(migrated) = compute_migrated_policy_bytes(original_data) else {
        return;
    };

    if migrated.len() > MAX_POLICY_JSON_BYTES {
        return;
    }

    match write_bytes_atomically_if_unchanged(read_path, &migrated, original_data.as_bytes()) {
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(path = %read_path.display(), %error, "policy HTTP migration write failed");
        }
    }
}

/// Insert missing HTTP ports without changing any existing JSON bytes.
/// Invalid rules prevent the entire rewrite. Borrowed raw values identify
/// insertion points without reserializing strings, numbers, or object keys.
fn compute_migrated_policy_bytes(data: &str) -> Option<Vec<u8>> {
    type Object<'a> = HashMap<String, &'a serde_json::value::RawValue>;
    let root: Object<'_> = serde_json::from_str(data).ok()?;
    let network: Object<'_> = serde_json::from_str(root.get("network")?.get()).ok()?;
    let http: Object<'_> = serde_json::from_str(network.get("http")?.get()).ok()?;
    let mut insertions = Vec::new();

    for section in ["allow", "deny"] {
        let Some(rules) = http.get(section) else {
            continue;
        };
        if rules.get() == "null" {
            continue;
        }
        let rules: Vec<&serde_json::value::RawValue> = serde_json::from_str(rules.get()).ok()?;
        for rule in rules {
            let parsed: HttpRule = serde_json::from_str(rule.get()).ok()?;
            parsed.target().ok()?;
            let fields: Object<'_> = serde_json::from_str(rule.get()).ok()?;
            if fields.contains_key("port") {
                continue;
            }
            let url = fields.get("url")?.get();
            let url_start = url.as_ptr() as usize - rule.get().as_ptr() as usize;
            let prefix = &rule.get()[..url_start];
            // Copy the URL member's colon spacing and the object's indentation.
            let colon = &prefix[prefix.rfind('"')? + 1..];
            let first_key = rule.get().find('"')?;
            let spacing = &rule.get()[1..first_key];
            let insertion = format!(",{spacing}\"port\"{colon}{}", parsed.port);
            let offset = url.as_ptr() as usize - data.as_ptr() as usize + url.len();
            insertions.push((offset, insertion));
        }
    }
    if insertions.is_empty() {
        return None;
    }
    insertions.sort_unstable_by_key(|(offset, _)| *offset);
    let added_bytes: usize = insertions.iter().map(|(_, text)| text.len()).sum();
    let mut migrated = Vec::with_capacity(data.len() + added_bytes);
    let mut start = 0;
    for (offset, text) in insertions {
        migrated.extend_from_slice(&data.as_bytes()[start..offset]);
        migrated.extend_from_slice(text.as_bytes());
        start = offset;
    }
    migrated.extend_from_slice(&data.as_bytes()[start..]);
    Some(migrated)
}

/// Atomically replace `target` with `bytes` via a unique temp file.
///
/// The temp name is unique (`O_CREAT|O_EXCL`) so a predictable
/// `<name>.tmp` symlink planted in an untrusted directory cannot redirect a
/// privileged write. Original mode and ownership are applied before `rename`;
/// the parent directory must already exist.
fn write_bytes_atomically(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = stage_bytes_atomically(target, bytes)?;
    tmp.persist(target).map(|_| ()).map_err(|error| error.error)
}

/// Stage `bytes` in a unique temp file, then replace `target` only when its
/// current bytes still equal `expected`.
///
/// The recheck happens after staging (metadata applied, bytes synced) and just
/// before `rename`, minimizing the window in which an external edit could be
/// clobbered. Returns `Ok(false)` without renaming on mismatch. A concurrent
/// writer can still slip between the recheck and `rename`.
fn write_bytes_atomically_if_unchanged(
    target: &Path,
    bytes: &[u8],
    expected: &[u8],
) -> std::io::Result<bool> {
    let tmp = stage_bytes_atomically(target, bytes)?;
    let current = std::fs::read(target)?;
    if current != expected {
        return Ok(false);
    }
    tmp.persist(target)
        .map(|_| true)
        .map_err(|error| error.error)
}

fn stage_bytes_atomically(target: &Path, bytes: &[u8]) -> std::io::Result<tempfile::NamedTempFile> {
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy path has no parent directory",
        )
    })?;
    let original = std::fs::metadata(target).ok();
    let original_mode = original.as_ref().map(|meta| meta.mode() & 0o7777);
    let original_owner = original.as_ref().map(|meta| (meta.uid(), meta.gid()));

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    if let Some((uid, gid)) = original_owner {
        let staged = tmp.as_file().metadata()?;
        if (staged.uid(), staged.gid()) != (uid, gid) {
            nix::unistd::fchown(
                tmp.as_file(),
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(gid)),
            )
            .map_err(std::io::Error::from)?;
        }
    }
    if let Some(mode) = original_mode {
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file().sync_all()?;
    Ok(tmp)
}

/// Parse a policy snapshot using the same size, schema, and rule limits as file
/// loading. Path expansion is left to the caller's policy context.
///
/// # Errors
/// Returns an error for oversized input, invalid fields, or excessive rule
/// counts.
pub fn parse_policy(data: &str) -> std::io::Result<Policy> {
    if data.len() > MAX_POLICY_JSON_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "policy JSON exceeds the maximum size",
        ));
    }

    // Cache syntax by complete content. Callers establish freshness; path
    // expansion remains specific to the caller's context.
    static PARSED: OnceLock<Mutex<HashMap<String, Policy>>> = OnceLock::new();

    let parsed = PARSED.get_or_init(Mutex::default);

    if let Ok(cache) = parsed.lock()
        && let Some(policy) = cache.get(data)
    {
        return Ok(policy.clone());
    }

    let mut policy = serde_json::from_str::<Policy>(data).map_err(|error| {
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

    if let Ok(mut cache) = parsed.lock() {
        // ponytail: clear at 32 documents; use LRU eviction if varied policy
        // contents cause measurable churn. The file-size limit bounds memory.
        if cache.len() >= 32 {
            cache.clear();
        }

        cache.insert(data.to_owned(), policy.clone());
    }

    Ok(policy)
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

fn filesystem_rule_sort_key(rule: &FilesystemRule, home: Option<&Path>) -> FilesystemRuleKey {
    FilesystemRuleKey::new(contract_home_path(&rule.path, home), rule.access)
}

fn resource_rule_sort_key(rule: &ResourceRule, home: Option<&Path>) -> ResourceRuleKey {
    ResourceRuleKey::new(rule.kind, contract_home_path(&rule.path, home), rule.access)
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
fn resolve_owner_uid(path: &Path, home: Option<&Path>, uid: Option<u32>) -> Option<u32> {
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

/// Recursively change ownership of a policy path's files to `uid`.
///
/// Best-effort: ownership errors are ignored.
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
    let json = policy_json(&sorted_policy(&contracted_policy(data, home), home))? + "\n";
    write_bytes_atomically(&target, json.as_bytes())?;

    if let Some(uid) = resolve_owner_uid(path, home, owner_uid) {
        chown_policy_path(path, uid);
    }

    Ok(())
}

/// Serialize `policy` to compact JSON.
///
/// # Errors
///
/// Returns an error if the policy cannot be serialized.
pub fn policy_json(policy: &Policy) -> serde_json::Result<String> {
    let mut json = String::new();
    json.push_str("{\n  \"network\": {\n    \"direct\": {\n");
    push_nested_rules(&mut json, "allow", &policy.network.direct.allow)?;
    json.push_str(",\n");
    push_nested_rules(&mut json, "deny", &policy.network.direct.deny)?;
    json.push_str("\n    },\n    \"http\": {\n");
    push_nested_rules(&mut json, "allow", &policy.network.http.allow)?;
    json.push_str(",\n");
    push_nested_rules(&mut json, "deny", &policy.network.http.deny)?;
    json.push_str("\n    }\n  },\n  \"sudo\": {\n");
    push_rules(&mut json, "allow", &policy.sudo.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.sudo.deny)?;
    json.push_str("\n  },\n  \"filesystem\": {\n");
    push_rules(&mut json, "allow", &policy.filesystem.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.filesystem.deny)?;
    json.push_str("\n  },\n  \"resources\": {\n");
    push_rules(&mut json, "allow", &policy.resources.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.resources.deny)?;

    if policy.dbus.allow.is_empty() && policy.dbus.deny.is_empty() {
        json.push_str("\n  }\n}");
        return Ok(json);
    }

    json.push_str("\n  },\n  \"dbus\": {\n");
    push_pretty_rules(&mut json, "allow", &policy.dbus.allow)?;
    json.push_str(",\n");
    push_pretty_rules(&mut json, "deny", &policy.dbus.deny)?;
    json.push_str("\n  }\n}");
    Ok(json)
}

/// Return a copy of `policy` with filesystem and resource allow/deny paths
/// under `home` contracted to the `~/...` shorthand for on-disk serialization.
fn contracted_policy(policy: &Policy, home: Option<&Path>) -> Policy {
    let mut out = policy.clone();

    for rule in out
        .filesystem
        .allow
        .iter_mut()
        .chain(out.filesystem.deny.iter_mut())
    {
        rule.path = contract_home_path(&rule.path, home);
    }

    for rule in out
        .resources
        .allow
        .iter_mut()
        .chain(out.resources.deny.iter_mut())
    {
        rule.path = contract_home_path(&rule.path, home);
    }

    out
}

fn push_rules<T: serde::Serialize>(
    out: &mut String,
    name: &str,
    rules: &[T],
) -> serde_json::Result<()> {
    out.push_str("    \"");
    out.push_str(name);
    out.push_str("\": ");

    if rules.is_empty() {
        out.push_str("[]");
        return Ok(());
    }

    out.push_str("[\n");

    for (index, rule) in rules.iter().enumerate() {
        out.push_str("      ");
        push_spaced_json(out, &serde_json::to_string(rule)?);

        if index + 1 != rules.len() {
            out.push(',');
        }

        out.push('\n');
    }

    out.push_str("    ]");
    Ok(())
}

fn push_pretty_rules<T: serde::Serialize>(
    out: &mut String,
    name: &str,
    rules: &[T],
) -> serde_json::Result<()> {
    out.push_str("    \"");
    out.push_str(name);
    out.push_str("\": ");

    if rules.is_empty() {
        out.push_str("[]");
        return Ok(());
    }

    out.push_str("[\n");

    for (index, rule) in rules.iter().enumerate() {
        push_indented_pretty_json(out, &serde_json::to_string_pretty(rule)?, 6);

        if index + 1 != rules.len() {
            out.push(',');
        }

        out.push('\n');
    }

    out.push_str("    ]");
    Ok(())
}

fn push_indented_pretty_json(out: &mut String, json: &str, base_indent: usize) {
    for (index, line) in json.lines().enumerate() {
        if index != 0 {
            out.push('\n');
        }

        for _ in 0..base_indent {
            out.push(' ');
        }

        let leading_spaces = line.len() - line.trim_start().len();

        for _ in 0..leading_spaces {
            out.push(' ');
        }

        out.push_str(line.trim_start());
    }
}

fn push_nested_rules<T: serde::Serialize>(
    out: &mut String,
    name: &str,
    rules: &[T],
) -> serde_json::Result<()> {
    out.push_str("      \"");
    out.push_str(name);
    out.push_str("\": ");

    if rules.is_empty() {
        out.push_str("[]");
        return Ok(());
    }

    out.push_str("[\n");

    for (index, rule) in rules.iter().enumerate() {
        out.push_str("        ");
        push_spaced_json(out, &serde_json::to_string(rule)?);

        if index + 1 != rules.len() {
            out.push(',');
        }

        out.push('\n');
    }

    out.push_str("      ]");
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
    use crate::policy::{
        DbusMessageKind, DbusRule, DbusTarget, FileAccess, FilesystemRule, NetworkRule, Policy,
    };

    #[test]
    fn policy_json_formats_dbus_rules_multiline() {
        let mut policy = Policy::default();

        policy.dbus.allow = vec![DbusRule::new(
            DbusTarget::session(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.Introspectable",
                "Introspect",
                DbusMessageKind::MethodCall,
                "",
                Vec::new(),
            ),
            "global",
        )];

        let json = policy_json(&policy).expect("serialize policy");
        serde_json::from_str::<serde_json::Value>(&json).expect("valid policy JSON");

        assert!(json.contains(
            r#"      {
        "target": {
          "bus": "session""#
        ));

        assert!(!json.contains(r#""target": { "bus":"#));
    }

    #[test]
    fn project_policy_chown_includes_parent_directory() {
        let path =
            Path::new("/home/user/.config/agent-sandbox/projects/home-user-repo/policy.json");

        let paths = policy_chown_paths(path);

        assert_eq!(paths, vec![
            PathBuf::from("/home/user/.config/agent-sandbox/projects/home-user-repo"),
            PathBuf::from("/home/user/.config/agent-sandbox/projects/home-user-repo/policy.json",),
        ]);
    }

    #[test]
    fn policy_json_writes_home_paths_as_tilde() {
        let mut policy = Policy::default();

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
        let mut policy = Policy::default();
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
        let mut policy = Policy::default();

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

        assert_eq!(hosts, vec![
            "developer.apple.com",
            "docs.developer.apple.com",
            "example.com",
            "api.example.com",
            "r.jina.ai",
            "api.z.ai",
        ]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_policy_expands_tilde_to_home() {
        let home = Path::new("/home/user");

        let raw = r#"{
            "network": { "direct": { "allow": [], "deny": [] } },
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

        let other = load_policy(&path, Some(Path::new("/home/other")), None);

        assert_eq!(
            other.filesystem.allow[0].path,
            Path::new("/home/other/.local/share/foo")
        );

        assert_eq!(
            other.filesystem.deny[0].path,
            Path::new("/home/other/.cache/secret")
        );
    }

    #[test]
    fn load_policy_leaves_other_user_paths_absolute() {
        let home = Path::new("/home/user");

        let raw = r#"{
            "network": { "direct": { "allow": [], "deny": [] } },
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
        let mut policy = Policy::default();

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

    #[test]
    fn http_migration_preserves_inline_json_bytes() {
        let tmp = tempfile::tempdir().expect("create policy directory");
        let path = tmp.path().join("policy.json");
        let raw = r#" {"extra":{"z":1e+02,"a":"λ"},"network":{"http":{"deny":[{"url":"http://example.com:8080/*","methods":[]}],"allow":[{ "comment":"keep \"quoted\"", "methods":["GET"], "url" : "https:\/\/example.com\/api" }]}}} "#;
        let expected = r#" {"extra":{"z":1e+02,"a":"λ"},"network":{"http":{"deny":[{"url":"http://example.com:8080/*","port":8080,"methods":[]}],"allow":[{ "comment":"keep \"quoted\"", "methods":["GET"], "url" : "https:\/\/example.com\/api", "port" : 443 }]}}} "#;
        std::fs::write(&path, raw).expect("write legacy policy");
        let loaded = load_policy(&path, None, None);
        assert_eq!(loaded.network.http.deny[0].port.get(), 8080);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read migrated policy"),
            expected
        );
        let reloaded = load_policy(&path, None, None);
        assert_eq!(reloaded.network.http.allow[0].port.get(), 443);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read unchanged policy"),
            expected
        );
    }

    #[test]
    fn http_migration_preserves_crlf_tabs_and_escaped_keys() {
        let tmp = tempfile::tempdir().expect("create policy directory");
        let path = tmp.path().join("policy.json");
        let raw = "{\r\n\t\"network\": {\"http\": {\"allow\": [{\r\n\t\t\"u\\u0072l\": \"https://[::1]:8443/*\",\r\n\t\t\"methods\": []\r\n\t}]}}\r\n}\r\n";
        let expected = "{\r\n\t\"network\": {\"http\": {\"allow\": [{\r\n\t\t\"u\\u0072l\": \"https://[::1]:8443/*\",\r\n\t\t\"port\": 8443,\r\n\t\t\"methods\": []\r\n\t}]}}\r\n}\r\n";
        std::fs::write(&path, raw).expect("write legacy policy");
        let loaded = load_policy(&path, None, None);
        assert_eq!(loaded.network.http.allow[0].port.get(), 8443);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read migrated policy"),
            expected
        );
    }

    #[test]
    fn http_migration_adds_default_and_custom_ports() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("policy.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [ { "methods": [], "url": "https://example.com/api" } ],
            "deny": [ { "methods": ["GET"], "url": "https://example.com:8443/api" } ]
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] },
          "resources": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&path, raw).expect("write file");

        let loaded = load_policy(&path, None, None);
        assert_eq!(loaded.network.http.allow.len(), 1);
        assert_eq!(loaded.network.http.allow[0].url, "https://example.com/api");
        assert_eq!(loaded.network.http.allow[0].port.get(), 443);
        assert_eq!(loaded.network.http.deny.len(), 1);
        assert_eq!(loaded.network.http.deny[0].url, "https://example.com/api");
        assert_eq!(loaded.network.http.deny[0].port.get(), 8443);

        let migrated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read file"))
                .expect("valid JSON");
        let allow = &migrated["network"]["http"]["allow"][0];
        assert_eq!(allow["url"], "https://example.com/api");
        assert_eq!(allow["port"], 443);
        let deny = &migrated["network"]["http"]["deny"][0];
        assert_eq!(deny["url"], "https://example.com:8443/api");
        assert_eq!(deny["port"], 8443);
    }

    #[test]
    fn http_migration_handles_ipv6_and_globs() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("policy.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [
              { "methods": [], "url": "https://[::1]/file?.txt" },
              { "methods": [], "url": "http://[::1]:8080/path" },
              { "methods": [], "url": "https://*.github.com/repos/*/*" },
              { "methods": [], "url": "https://example.com:443/api" }
            ],
            "deny": []
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] },
          "resources": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&path, raw).expect("write file");

        let loaded = load_policy(&path, None, None);
        assert_eq!(loaded.network.http.allow.len(), 4);
        assert_eq!(loaded.network.http.allow[0].port.get(), 443);
        assert_eq!(loaded.network.http.allow[1].port.get(), 8080);
        assert_eq!(loaded.network.http.allow[1].url, "http://[::1]/path");
        assert_eq!(loaded.network.http.allow[2].port.get(), 443);
        assert_eq!(loaded.network.http.allow[3].port.get(), 443);
        assert_eq!(loaded.network.http.allow[3].url, "https://example.com/api");

        let migrated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read file"))
                .expect("valid JSON");
        assert_eq!(migrated["network"]["http"]["allow"][1]["port"], 8080);
        assert_eq!(
            migrated["network"]["http"]["allow"][1]["url"],
            "http://[::1]:8080/path"
        );
    }

    #[test]
    fn http_migration_is_idempotent() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("policy.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [ { "methods": [], "url": "https://example.com/api" } ],
            "deny": []
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] },
          "resources": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&path, raw).expect("write file");

        let _ = load_policy(&path, None, None);
        let after_first = std::fs::read(&path).expect("read file");
        assert!(compute_migrated_policy_bytes(&String::from_utf8_lossy(&after_first)).is_none());

        let _ = load_policy(&path, None, None);
        let after_second = std::fs::read(&path).expect("read file");
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn http_migration_preserves_non_http_fields() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("policy.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [ { "methods": [], "url": "https://example.com:8443/api", "comment": "keep me" } ],
            "deny": []
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [ { "path": "/srv/data", "access": "read" } ], "deny": [] },
          "resources": { "allow": [], "deny": [] },
          "extra_top": { "note": "preserve" }
        }"#;
        std::fs::write(&path, raw).expect("write file");

        let loaded = load_policy(&path, None, None);
        assert_eq!(loaded.network.http.allow.len(), 1);
        assert_eq!(loaded.filesystem.allow.len(), 1);

        let migrated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read file"))
                .expect("valid JSON");
        let rule = &migrated["network"]["http"]["allow"][0];
        assert_eq!(rule["url"], "https://example.com:8443/api");
        assert_eq!(rule["port"], 8443);
        assert_eq!(rule["comment"], "keep me");
        assert_eq!(migrated["extra_top"]["note"], "preserve");
        assert_eq!(migrated["filesystem"]["allow"][0]["path"], "/srv/data");
    }

    #[test]
    fn http_migration_preserves_symlink_and_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let tmp = tempfile::tempdir().expect("create tempdir");
        let real = tmp.path().join("real.json");
        let link = tmp.path().join("link.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [ { "methods": [], "url": "https://example.com:8443/api" } ],
            "deny": []
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] },
          "resources": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&real, raw).expect("write file");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        symlink(&real, &link).expect("symlink");

        let loaded = load_policy(&link, None, None);
        assert_eq!(loaded.network.http.allow.len(), 1);
        assert_eq!(loaded.network.http.allow[0].port.get(), 8443);

        assert!(
            std::fs::symlink_metadata(&link)
                .expect("metadata")
                .file_type()
                .is_symlink()
        );
        let mode = std::fs::metadata(&real)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let migrated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&real).expect("read file"))
                .expect("valid JSON");
        assert_eq!(migrated["network"]["http"]["allow"][0]["port"], 8443);
    }

    #[test]
    fn http_migration_leaves_invalid_policy_untouched() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let bad_url = tmp.path().join("bad-url.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [ { "methods": [], "url": "not-a-url" } ],
            "deny": [ { "methods": [], "url": "https://example.com/api" } ]
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] },
          "resources": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&bad_url, raw).expect("write file");
        let _ = load_policy(&bad_url, None, None);
        assert_eq!(std::fs::read_to_string(&bad_url).expect("read"), raw);

        let conflict = tmp.path().join("conflict.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [ { "methods": [], "url": "https://example.com:8443/api", "port": 9443 } ],
            "deny": []
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] },
          "resources": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&conflict, raw).expect("write file");
        let _ = load_policy(&conflict, None, None);
        assert_eq!(std::fs::read_to_string(&conflict).expect("read"), raw);

        let unknown = tmp.path().join("unknown-field.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] }, "http": {
            "allow": [ { "methods": [], "url": "https://example.com/api", "priority": 5 } ],
            "deny": []
          } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] },
          "resources": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&unknown, raw).expect("write file");
        let _ = load_policy(&unknown, None, None);
        assert_eq!(std::fs::read_to_string(&unknown).expect("read"), raw);

        let no_http = tmp.path().join("no-http.json");
        let raw = r#"{
          "network": { "direct": { "allow": [], "deny": [] } },
          "sudo": { "allow": [], "deny": [] },
          "filesystem": { "allow": [], "deny": [] }
        }"#;
        std::fs::write(&no_http, raw).expect("write file");
        let _ = load_policy(&no_http, None, None);
        assert_eq!(std::fs::read_to_string(&no_http).expect("read"), raw);
    }
}
