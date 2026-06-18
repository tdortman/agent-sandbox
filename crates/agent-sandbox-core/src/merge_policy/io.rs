//! Load and atomically write policy JSON on disk.

use std::path::{Path, PathBuf};

use crate::policy::Policy;

pub fn load_policy(path: &Path) -> Policy {
    let read_path = resolve_policy_write_path(path);
    if !read_path.is_file() {
        return Policy::default();
    }
    let Ok(data) = std::fs::read_to_string(&read_path) else {
        return Policy::default();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

pub fn resolve_policy_write_path(path: &Path) -> PathBuf {
    if path.is_symlink() {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}

pub fn resolve_owner_uid(path: &Path, home: Option<&str>, uid: Option<u32>) -> Option<u32> {
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

pub fn chown_policy_path(path: &Path, uid: u32) {
    if uid == 0 {
        return;
    }
    let Ok(Some(pw)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) else {
        return;
    };
    let gid = pw.gid;
    let target = resolve_policy_write_path(path);
    for entry in [
        target.parent().map(std::path::Path::to_path_buf),
        Some(target),
    ] {
        let Some(entry) = entry.filter(|e| e.exists()) else {
            continue;
        };
        let _ = nix::unistd::chown(&entry, Some(nix::unistd::Uid::from_raw(uid)), Some(gid));
    }
}

pub fn atomic_write_policy(
    path: &Path,
    data: &Policy,
    home: Option<&str>,
    owner_uid: Option<u32>,
) -> std::io::Result<()> {
    let target = resolve_policy_write_path(path);
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
    let json = policy_json(data)? + "\n";
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &target)?;
    if let Some(uid) = resolve_owner_uid(path, home, owner_uid) {
        chown_policy_path(path, uid);
    }
    Ok(())
}

pub(crate) fn policy_json(policy: &Policy) -> serde_json::Result<String> {
    let mut json = String::new();
    json.push_str("{\n    \"network\": {\n");
    push_rules(&mut json, "allow", &policy.network.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.network.deny)?;
    json.push_str("\n    },\n    \"sudo\": {\n");
    push_rules(&mut json, "allow", &policy.sudo.allow)?;
    json.push_str(",\n");
    push_rules(&mut json, "deny", &policy.sudo.deny)?;
    json.push_str("\n    }\n}");
    Ok(json)
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
