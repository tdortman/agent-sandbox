use std::fs;
use std::os::unix::fs::MetadataExt;

use super::io::policy_json;
use super::*;
use crate::policy::{NetworkRule, Policy, SudoRule};

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
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("home/dot_config/agent-sandbox");
    fs::create_dir_all(&real).unwrap();
    let real_policy = real.join("policy.json");
    fs::write(
        &real_policy,
        r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
    )
    .unwrap();
    let link = tmp.path().join("policy.json");
    std::os::unix::fs::symlink(&real_policy, &link).unwrap();
    let mut data = empty_policy();
    data.network.allow = vec![NetworkRule::new("example.com", 443, "")];
    atomic_write_policy(&link, &data, None, None).unwrap();
    assert!(link.is_symlink());
    let loaded = load_policy(&real_policy);
    assert_eq!(loaded.network.allow[0].host, "example.com");
}

#[test]
fn atomic_write_chowns_to_owner() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    fs::create_dir_all(&repo).unwrap();
    let policy_path = repo.join(".agent-sandbox/policy.json");
    atomic_write_policy(
        &policy_path,
        &empty_policy(),
        None,
        Some(nix::unistd::getuid().as_raw()),
    )
    .unwrap();
    let uid = nix::unistd::getuid().as_raw();
    assert_eq!(policy_path.metadata().unwrap().uid(), uid);
    assert_eq!(policy_path.parent().unwrap().metadata().unwrap().uid(), uid);
}

#[test]
fn project_deny_beats_global_allow() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home/tim");
    let repo = home.join("dotfiles");
    fs::create_dir_all(repo.join(".agent-sandbox")).unwrap();
    fs::write(
        repo.join(".agent-sandbox/policy.json"),
        r#"{"network":{"allow":[],"deny":[{"host":"chatgpt.com","port":443}]},"sudo":{"allow":[],"deny":[]}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".config/agent-sandbox")).unwrap();
    fs::write(
        home.join(".config/agent-sandbox/policy.json"),
        r#"{"network":{"allow":[{"host":"chatgpt.com","port":443}],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
    )
    .unwrap();

    let mut layers = vec![
        Policy {
            network: crate::policy::NetworkSection {
                allow: vec![NetworkRule::new("chatgpt.com", 443, "")],
                deny: vec![],
            },
            ..empty_policy()
        },
        load_policy(&home.join(".config/agent-sandbox/policy.json")),
    ];
    for path in ProjectPolicyContext::new(Some(&home), None, None).layer_paths() {
        layers.push(load_policy(&path));
    }
    let merged = merge_layers(&layers);
    assert_eq!(merged.network.deny[0].host, "chatgpt.com");
    assert!(merged.network.allow.is_empty());
}

#[test]
fn atomic_write_keeps_each_rule_on_one_line() {
    let tmp = tempfile::tempdir().unwrap();
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

    atomic_write_policy(&policy_path, &policy, None, None).unwrap();
    let json = fs::read_to_string(policy_path).unwrap();

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
    let json = policy_json(&p).unwrap() + "\n";

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

    // Each rule line is a complete JSON object; commas belong to the parent array.
    for line in &rule_lines {
        let object = line.trim_end_matches(',');
        let v: serde_json::Value = serde_json::from_str(object).unwrap();
        assert!(v.is_object(), "rule line is not a JSON object: {line}");
    }

    // Section ordering: network before sudo, allow before deny within each.
    let net_pos = json.find("\"network\"").unwrap();
    let sudo_pos = json.find("\"sudo\"").unwrap();
    assert!(net_pos < sudo_pos, "network section must precede sudo");
    let allow_pos = json[net_pos..sudo_pos].find("\"allow\"").unwrap();
    let deny_pos = json[net_pos..sudo_pos].find("\"deny\"").unwrap();
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
