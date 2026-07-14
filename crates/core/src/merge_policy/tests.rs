use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::io::policy_json;
use super::*;
use crate::HttpRule;
use crate::policy::{FileAccess, FilesystemRule, HttpSection, NetworkRule, Policy, SudoRule};

fn empty_policy() -> Policy {
    Policy::default()
}

#[test]
fn deny_removes_allow_from_earlier_layer() {
    let low = Policy {
        network: crate::policy::NetworkSection {
            direct: crate::policy::DirectNetworkSection {
                allow: vec![NetworkRule::new("example.com", 443, "")],
                deny: vec![],
            },
            http: HttpSection::default(),
        },
        ..empty_policy()
    };
    let high = Policy {
        network: crate::policy::NetworkSection {
            direct: crate::policy::DirectNetworkSection {
                allow: vec![],
                deny: vec![NetworkRule::new("example.com", 443, "")],
            },
            http: HttpSection::default(),
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(merged.network.direct.allow.is_empty());
    assert_eq!(merged.network.direct.deny.len(), 1);
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
    data.network.direct.allow = vec![NetworkRule::new("example.com", 443, "")];
    atomic_write_policy(&link, &data, None, None, None).expect("write policy");
    assert!(link.is_symlink());
    let loaded = load_policy(&real_policy, None, None);
    assert_eq!(loaded.network.direct.allow[0].host, "example.com");
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
    data.network.direct.allow = vec![NetworkRule::new("example.com", 443, "")];

    atomic_write_policy(&link, &data, None, None, None).expect("write policy");

    assert!(link.is_symlink());
    let loaded = load_policy(&real_dir.join("policy.json"), None, None);
    assert_eq!(loaded.network.direct.allow[0].host, "example.com");
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
    policy.network.direct.allow = vec![
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
        "direct": {
            "allow": [
                { "host": "example.com", "port": 443, "comment": "first" },
                { "host": "api.example.com", "port": 443, "comment": "second" }
            ],
            "deny": []
        },
        "http": {
            "allow": [],
            "deny": []
        }
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
fn load_policy_ignores_top_level_http_rules() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().join("policy.json");
    fs::write(
        &path,
        r#"{
    "network": { "allow": [], "deny": [] },
    "http": {
        "allow": [{ "method": "GET", "url": "https://api.example.com/v1" }],
        "deny": [{ "url": "https://api.example.com/v1/telemetry" }]
    },
    "sudo": { "allow": [], "deny": [] },
    "filesystem": { "allow": [], "deny": [] },
    "resources": { "allow": [], "deny": [] }
}"#,
    )
    .expect("write file");

    let policy = load_policy(&path, None, None);
    assert!(policy.network.http.allow.is_empty());
    assert!(policy.network.http.deny.is_empty());
}

#[test]
fn legacy_direct_network_fields_deserialize_to_canonical_direct() {
    let policy: Policy = serde_json::from_str(
        r#"{
    "network": {
        "allow": [{ "host": "example.com", "port": 443 }],
        "deny": []
    }
}"#,
    )
    .expect("legacy direct policy");
    assert_eq!(policy.network.direct.allow.len(), 1);
    assert!(policy.network.direct.deny.is_empty());
    let json = serde_json::to_value(policy).expect("serialize canonical policy");
    let network = json
        .get("network")
        .and_then(serde_json::Value::as_object)
        .expect("network object");
    assert!(network.contains_key("direct"));
    assert!(!network.contains_key("allow"));
    assert!(!network.contains_key("deny"));
}

#[test]
fn migrate_policy_rewrites_legacy_network_fields_on_disk() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().join("policy.json");
    fs::write(
        &path,
        r#"{
    "network": {
        "allow": [{ "host": "example.com", "port": 443 }],
        "deny": []
    }
}"#,
    )
    .expect("write legacy policy");

    assert!(migrate_policy(&path, None, None).expect("migrate policy"));
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read migrated policy"))
            .expect("parse migrated policy");
    let network = value
        .get("network")
        .and_then(serde_json::Value::as_object)
        .expect("network object");
    assert!(network.contains_key("direct"));
    assert!(!network.contains_key("allow"));
    assert!(!network.contains_key("deny"));
    assert_eq!(
        network["direct"]["allow"][0]["host"],
        serde_json::Value::String("example.com".into())
    );
}

#[test]
fn migrate_policy_reports_invalid_http_without_rewriting() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = tmp.path().join("policy.json");
    let legacy = r#"{
    "network": {
        "allow": [{ "host": "example.com", "port": 443 }],
        "http": {
            "allow": [{ "method": "GET", "url": "not a URL" }]
        }
    }
}"#;
    fs::write(&path, legacy).expect("write legacy policy");
    let before = fs::read(&path).expect("read original policy");

    let loaded = load_policy(&path, None, None);
    assert_eq!(loaded.network.direct.allow.len(), 1);
    assert!(loaded.network.http.allow.is_empty());

    let error = migrate_policy(&path, None, None).expect_err("invalid HTTP rule must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(fs::read(&path).expect("read unchanged policy"), before);
}

#[test]
fn policy_json_one_rule_per_line_invariant() {
    let mut p = empty_policy();
    p.network.direct.allow = vec![
        NetworkRule::new("first.com", 80, "alpha"),
        NetworkRule::new("second.org", 443, "beta"),
    ];
    p.sudo.deny = vec![SudoRule::new(vec!["/usr/bin/ls".into()], "list")];
    let json = policy_json(&p).expect("serialize policy") + "\n";

    // Every rule appears as exactly one line, not spread across many.
    let rule_lines: Vec<&str> = json
        .lines()
        .filter(|line| line.trim_start().starts_with("{ "))
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
            direct: crate::policy::DirectNetworkSection {
                allow: vec![NetworkRule::new("example.com", 443, "")],
                deny: vec![],
            },
            http: HttpSection::default(),
        },
        ..empty_policy()
    };
    let high = Policy {
        network: crate::policy::NetworkSection {
            direct: crate::policy::DirectNetworkSection {
                allow: vec![],
                deny: vec![NetworkRule::new("example.com", 443, "")],
            },
            http: HttpSection::default(),
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(merged.network.direct.allow.is_empty());
    assert_eq!(merged.network.direct.deny.len(), 1);
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
            direct: crate::policy::DirectNetworkSection {
                allow: vec![NetworkRule::new("*.evil.com", 443, "")],
                deny: vec![],
            },
            http: HttpSection::default(),
        },
        ..empty_policy()
    };
    let high = Policy {
        network: crate::policy::NetworkSection {
            direct: crate::policy::DirectNetworkSection {
                allow: vec![],
                deny: vec![NetworkRule::new("evil.com", 443, "")],
            },
            http: HttpSection::default(),
        },
        ..empty_policy()
    };
    let merged = merge_layers(&[low, high]);
    assert!(
        merged.network.direct.allow.is_empty(),
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

#[test]
fn http_merge_removes_only_exact_opposite_target() {
    let mut allow = empty_policy();
    allow.network.http = HttpSection {
        allow: vec![HttpRule::new(
            vec![],
            "https://example.com/api",
            "all methods",
        )],
        deny: vec![],
    };
    let mut deny = empty_policy();
    deny.network.http = HttpSection {
        allow: vec![],
        deny: vec![HttpRule::new(
            vec!["GET".into()],
            "https://example.com/api",
            "GET only",
        )],
    };
    let merged = merge_layers(&[allow, deny]);
    assert_eq!(merged.network.http.allow.len(), 1);
    assert_eq!(merged.network.http.deny.len(), 1);
}

#[test]
fn http_merge_removes_an_exact_equal_target() {
    let mut allow = empty_policy();
    allow.network.http.allow = vec![HttpRule::new(
        vec!["GET".into()],
        "https://example.com/api",
        "allow",
    )];
    let mut deny = empty_policy();
    deny.network.http.deny = vec![HttpRule::new(
        vec!["GET".into()],
        "https://example.com/api",
        "deny",
    )];
    let merged = merge_layers(&[allow, deny]);
    assert!(merged.network.http.allow.is_empty());
    assert_eq!(merged.network.http.deny.len(), 1);
}

#[test]
fn http_merge_unions_methods_for_same_url() {
    let mut first = empty_policy();
    first.network.http.allow = vec![HttpRule::new(
        vec!["GET".into()],
        "https://example.com/api",
        "GET",
    )];
    let mut second = empty_policy();
    second.network.http.allow = vec![HttpRule::new(
        vec!["POST".into()],
        "https://example.com/api",
        "POST",
    )];

    let merged = merge_layers(&[first, second]);
    assert_eq!(merged.network.http.allow.len(), 1);
    assert_eq!(
        merged.network.http.allow[0].methods,
        vec!["GET".to_string(), "POST".to_string()]
    );
}

#[test]
fn http_merge_deny_covers_allow_path_and_methods() {
    let mut allow = empty_policy();
    allow.network.http.allow = vec![HttpRule::new(
        vec!["GET".into()],
        "https://example.com/api/v1",
        "allow",
    )];
    let mut deny = empty_policy();
    deny.network.http.deny = vec![HttpRule::new(
        vec!["GET".into()],
        "https://example.com/api",
        "deny",
    )];

    let merged = merge_layers(&[allow, deny]);
    assert!(merged.network.http.allow.is_empty());
}

#[test]
fn http_merge_partial_method_deny_keeps_allow() {
    let mut allow = empty_policy();
    allow.network.http.allow = vec![HttpRule::new(
        vec!["GET".into(), "POST".into()],
        "https://example.com/api",
        "allow",
    )];
    let mut deny = empty_policy();
    deny.network.http.deny = vec![HttpRule::new(
        vec!["GET".into()],
        "https://example.com/api",
        "deny",
    )];

    let merged = merge_layers(&[allow, deny]);
    assert_eq!(merged.network.http.allow.len(), 1);
    assert_eq!(
        merged.network.http.allow[0].methods,
        vec!["GET".to_string(), "POST".to_string()]
    );
}
#[test]
fn direct_merge_keeps_partially_overlapping_globs() {
    let mut allow = empty_policy();
    allow.network.direct.allow = vec![NetworkRule::new("api.*.example.com", 443, "allow")];
    let mut deny = empty_policy();
    deny.network.direct.deny = vec![NetworkRule::new("api.?.example.com", 443, "deny")];

    let merged = merge_layers(&[allow, deny]);
    assert_eq!(merged.network.direct.allow.len(), 1);
    assert_eq!(merged.network.direct.deny.len(), 1);
}

#[test]
fn http_glob_deny_covers_concrete_allow() {
    let mut allow = empty_policy();
    allow.network.http.allow = vec![HttpRule::new(
        vec!["GET".into()],
        "https://api.github.com/repos/owner/repo",
        "allow",
    )];
    let mut deny = empty_policy();
    deny.network.http.deny = vec![HttpRule::new(
        vec!["GET".into()],
        "https://api.github.com/repos/*/*",
        "deny",
    )];

    let merged = merge_layers(&[allow, deny]);
    assert!(merged.network.http.allow.is_empty());
    assert_eq!(merged.network.http.deny.len(), 1);
}
