use std::fs;
use std::os::unix::fs::MetadataExt;

use super::*;
use crate::policy::{NetworkRule, Policy};

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
