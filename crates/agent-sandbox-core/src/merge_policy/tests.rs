use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::*;
use crate::policy::{NetworkRule, Policy, SudoRule};

fn empty_policy() -> Policy {
    Policy::default()
}

#[test]
fn prefers_project_root_over_ephemeral_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("dotfiles");
    fs::create_dir_all(repo.join(".agent-sandbox")).unwrap();
    let policy_file = repo.join(".agent-sandbox/policy.json");
    fs::write(
        &policy_file,
        r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
    )
    .unwrap();
    let ephemeral = tmp.path().join("omp-python-runner");
    fs::create_dir(&ephemeral).unwrap();
    let resolved = resolve_project_policy_path(Some(&ephemeral), Some(&repo)).unwrap();
    assert_eq!(resolved, policy_file);
}

#[test]
fn ephemeral_cwd_without_project_root_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let ephemeral = tmp.path().join("omp-python-runner");
    fs::create_dir(&ephemeral).unwrap();
    assert!(resolve_project_policy_path(Some(&ephemeral), None).is_err());
}

#[test]
fn rejects_root_cwd() {
    assert!(resolve_project_policy_path(Some(Path::new("/")), None).is_err());
}

#[test]
fn discovers_policy_from_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("proj");
    fs::create_dir_all(repo.join("src")).unwrap();
    let policy_file = repo.join(".agent-sandbox/policy.json");
    fs::create_dir_all(policy_file.parent().unwrap()).unwrap();
    fs::write(
        &policy_file,
        r#"{"network":{"allow":[],"deny":[]},"sudo":{"allow":[],"deny":[]}}"#,
    )
    .unwrap();
    let resolved = resolve_project_policy_path(Some(&repo.join("src")), None).unwrap();
    assert_eq!(resolved, policy_file);
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
fn sudo_argv_prefix_match() {
    let rule = SudoRule::new(vec!["systemctl".into(), "restart".into()], "");
    assert!(crate::policy::sudo_argv_matches(
        &rule,
        &["systemctl".into(), "restart".into(), "nginx".into()]
    ));
    assert!(!crate::policy::sudo_argv_matches(
        &rule,
        &["systemctl".into(), "stop".into()]
    ));
}

#[test]
fn infer_home_from_project_root() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home/tim");
    let repo = home.join("dotfiles");
    fs::create_dir_all(&repo).unwrap();
    assert_eq!(
        infer_home_from_paths([&repo]),
        Some(home.to_string_lossy().into_owned())
    );
    assert!(infer_home_from_paths([Path::new("/var/tmp/runner")]).is_none());
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
    let layers = vec![
        Policy {
            network: crate::policy::NetworkSection {
                allow: vec![NetworkRule::new("chatgpt.com", 443, "")],
                deny: vec![],
            },
            ..empty_policy()
        },
        load_policy(&home.join(".config/agent-sandbox/policy.json")),
    ];
    let mut all_layers = layers;
    for path in project_policy_paths(Some(&home), None, None) {
        all_layers.push(load_policy(&path));
    }
    let merged = merge_layers(&all_layers);
    assert_eq!(merged.network.deny[0].host, "chatgpt.com");
    assert!(merged.network.allow.is_empty());
}

#[test]
fn is_ephemeral_cwd_detects_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("omp-python-runner");
    fs::create_dir(&p).unwrap();
    assert!(is_ephemeral_cwd(&p));
}
