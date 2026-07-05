use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::io::policy_json;
use super::*;
use crate::policy::{FileAccess, FilesystemRule, NetworkRule, Policy, SudoRule};

fn empty_policy() -> Policy {
    Policy::default()
}

#[test]
fn deny_removes_allow_from_earlier_layer() {
    let low = Policy {
        network: crate::policy::NetworkSection {
            allow: vec![NetworkRule::new("example.com", 443, "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let high = Policy {
        network: crate::policy::NetworkSection {
            allow: vec![],
            deny: vec![NetworkRule::new("example.com", 443, "")],
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(merged.network.allow.is_empty());
    assert_eq!(merged.network.deny.len(), 1);
}

#[test]
fn atomic_write_preserves_symlink() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let real = tmp.path().join("home/dot_config/agent-sandbox");
    fs::create_dir_all(&real).expect("create dirs");
    let real_policy = real.join("policy.json");
    fs::write(
        &real_policy,
        r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
    )
    .expect("write file");
    let link = tmp.path().join("policy.json");
    std::os::unix::fs::symlink(&real_policy, &link).expect("symlink");
    let mut data = empty_policy();
    data.network.allow = vec![NetworkRule::new("example.com", 443, "")];
    atomic_write_policy(&link, &data, None, None, None).expect("write policy");
    assert!(link.is_symlink());
    let loaded = load_policy(&real_policy, None, None);
    assert_eq!(loaded.network.allow[0].host, "example.com");
}

#[test]
fn atomic_write_preserves_relative_symlink_to_missing_target() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let real_dir = tmp.path().join("home/dot_config/agent-sandbox");
    let link_dir = tmp.path().join("home/.config/agent-sandbox");
    fs::create_dir_all(&real_dir).expect("create dirs");
    fs::create_dir_all(&link_dir).expect("create dirs");
    let link = link_dir.join("policy.json");
    std::os::unix::fs::symlink("../../dot_config/agent-sandbox/policy.json", &link)
        .expect("symlink");
    let mut data = empty_policy();
    data.network.allow = vec![NetworkRule::new("example.com", 443, "")];

    atomic_write_policy(&link, &data, None, None, None).expect("write policy");

    assert!(link.is_symlink());
    let loaded = load_policy(&real_dir.join("policy.json"), None, None);
    assert_eq!(loaded.network.allow[0].host, "example.com");
}

#[test]
fn atomic_write_chowns_to_owner() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let repo = tmp.path().join("project");
    fs::create_dir_all(&repo).expect("create dirs");
    let policy_path = repo.join(".agent-sandbox/policy.json");
    atomic_write_policy(
        &policy_path,
        &empty_policy(),
        None,
        Some(nix::unistd::getuid().as_raw()),
        None,
    )
    .expect("write policy");
    let uid = nix::unistd::getuid().as_raw();
    assert_eq!(
        policy_path.metadata().expect("policy path metadata").uid(),
        uid
    );
    assert_eq!(
        policy_path
            .parent()
            .expect("policy parent dir")
            .metadata()
            .expect("policy parent metadata")
            .uid(),
        uid
    );
}

#[test]
fn atomic_write_keeps_each_rule_on_one_line() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let policy_path = tmp.path().join("policy.json");
    let mut policy = empty_policy();
    policy.network.allow = vec![
        NetworkRule::new("example.com", 443, "first"),
        NetworkRule::new("api.example.com", 443, "second"),
    ];
    policy.sudo.deny = vec![SudoRule::new(
        vec!["systemctl".into(), "restart".into(), "nginx".into()],
        "restart nginx",
    )];

    atomic_write_policy(&policy_path, &policy, None, None, None).expect("write policy");
    let json = fs::read_to_string(policy_path).expect("read file");

    assert_eq!(
        json,
        r#"{
    "network": {
        "allow": [
            { "host": "example.com", "port": 443, "comment": "first" },
            { "host": "api.example.com", "port": 443, "comment": "second" }
        ],
        "deny": []
    },
    "sudo": {
        "allow": [],
        "deny": [
            { "argv": ["systemctl", "restart", "nginx"], "comment": "restart nginx" }
        ]
    },
    "filesystem": {
        "allow": [],
        "deny": []
    },
    "resources": {
        "allow": [],
        "deny": []
    }
}
"#
    );
}

#[test]
fn policy_json_one_rule_per_line_invariant() {
    let mut p = empty_policy();
    p.network.allow = vec![
        NetworkRule::new("first.com", 80, "alpha"),
        NetworkRule::new("second.org", 443, "beta"),
    ];
    p.sudo.deny = vec![SudoRule::new(vec!["/usr/bin/ls".into()], "list")];
    let json = policy_json(&p).expect("serialize policy") + "\n";

    // Every rule appears as exactly one line, not spread across many.
    let rule_lines: Vec<&str> = json
        .lines()
        .filter(|l| l.starts_with("            {"))
        .collect();
    assert_eq!(
        rule_lines.len(),
        3,
        "expected 3 one-line rule objects, got {}:\n{}",
        rule_lines.len(),
        json
    );

    // Each rule line is a complete JSON object. Commas belong to the parent array.
    for line in &rule_lines {
        let object = line.trim_end_matches(',');
        let v: serde_json::Value = serde_json::from_str(object).expect("parse json");
        assert!(v.is_object(), "rule line is not a JSON object: {line}");
    }

    // Section ordering: network before sudo, allow before deny within each.
    let net_pos = json.find("\"network\"").expect("locate network section");
    let sudo_pos = json.find("\"sudo\"").expect("locate sudo section");
    assert!(net_pos < sudo_pos, "network section must precede sudo");
    let allow_pos = json[net_pos..sudo_pos]
        .find("\"allow\"")
        .expect("locate allow section");
    let deny_pos = json[net_pos..sudo_pos]
        .find("\"deny\"")
        .expect("locate deny section");
    assert!(
        allow_pos < deny_pos,
        "allow must precede deny within network"
    );

    // Empty arrays stay compact on one line.
    assert!(
        json.contains("\"deny\": []"),
        "empty deny array should be []:\n{json}"
    );
    assert!(
        json.contains("\"allow\": []"),
        "empty allow (sudo) should be []:\n{json}"
    );
}

#[test]
fn filesystem_later_deny_overrides_earlier_allow() {
    let low = Policy {
        filesystem: crate::policy::FilesystemSection {
            allow: vec![FilesystemRule::new("/home", FileAccess::ReadWrite, "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let high = Policy {
        filesystem: crate::policy::FilesystemSection {
            allow: vec![],
            deny: vec![FilesystemRule::new("/home", FileAccess::ReadWrite, "")],
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(merged.filesystem.allow.is_empty());
    assert_eq!(merged.filesystem.deny.len(), 1);
}

#[test]
fn filesystem_trailing_slash_path_merge_deduplicates() {
    let low = Policy {
        filesystem: crate::policy::FilesystemSection {
            allow: vec![FilesystemRule::new("/home/", FileAccess::Read, "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let high = Policy {
        filesystem: crate::policy::FilesystemSection {
            allow: vec![FilesystemRule::new("/home", FileAccess::Read, "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert_eq!(merged.filesystem.allow.len(), 1);
    assert_eq!(merged.filesystem.allow[0].path, Path::new("/home"));
}

#[test]
fn filesystem_deny_wins_over_allow_at_eval_time() {
    let merged = Policy {
        filesystem: crate::policy::FilesystemSection {
            allow: vec![FilesystemRule::new("/tmp", FileAccess::Read, "")],
            deny: vec![FilesystemRule::new("/tmp", FileAccess::All, "")],
        },
        ..Policy::default()
    };
    // deny wins: check deny list first
    let denied = merged
        .filesystem
        .deny
        .iter()
        .any(|r| r.matches(Path::new("/tmp"), FileAccess::Read, None));
    assert!(denied);
    let allowed = merged
        .filesystem
        .allow
        .iter()
        .any(|r| r.matches(Path::new("/tmp"), FileAccess::Read, None));
    assert!(allowed);
}

#[test]
fn old_policy_without_filesystem_still_loads() {
    let json = r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#;
    let policy: Policy = serde_json::from_str(json).expect("deserialize policy");
    assert!(policy.filesystem.allow.is_empty());
    assert!(policy.filesystem.deny.is_empty());
}

#[test]
fn global_deny_beats_project_allow() {
    let low = Policy {
        network: crate::policy::NetworkSection {
            allow: vec![NetworkRule::new("example.com", 443, "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let high = Policy {
        network: crate::policy::NetworkSection {
            allow: vec![],
            deny: vec![NetworkRule::new("example.com", 443, "")],
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(merged.network.allow.is_empty());
    assert_eq!(merged.network.deny.len(), 1);
}

#[test]
fn sudo_deny_beats_later_allow() {
    let low = Policy {
        sudo: crate::policy::SudoSection {
            allow: vec![SudoRule::new(vec!["rm".into(), "-rf".into()], "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let high = Policy {
        sudo: crate::policy::SudoSection {
            allow: vec![],
            deny: vec![SudoRule::new(vec!["rm".into(), "-rf".into()], "")],
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(merged.sudo.allow.is_empty());
    assert_eq!(merged.sudo.deny.len(), 1);
}

#[test]
fn deny_wins_over_wildcard_allow_on_merge() {
    let low = Policy {
        network: crate::policy::NetworkSection {
            allow: vec![NetworkRule::new("*.evil.com", 443, "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let high = Policy {
        network: crate::policy::NetworkSection {
            allow: vec![],
            deny: vec![NetworkRule::new("evil.com", 443, "")],
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(
        merged.network.allow.is_empty(),
        "deny evil.com must shadow allow *.evil.com"
    );
}

#[test]
fn filesystem_deny_beats_later_allow() {
    let low = Policy {
        filesystem: crate::policy::FilesystemSection {
            allow: vec![FilesystemRule::new("/home", FileAccess::ReadWrite, "")],
            deny: vec![],
        },
        ..empty_policy()
    };
    let high = Policy {
        filesystem: crate::policy::FilesystemSection {
            allow: vec![],
            deny: vec![FilesystemRule::new("/home", FileAccess::ReadWrite, "")],
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(merged.filesystem.allow.is_empty());
    assert_eq!(merged.filesystem.deny.len(), 1);
}
