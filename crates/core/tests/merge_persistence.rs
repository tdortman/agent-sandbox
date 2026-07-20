use std::path::PathBuf;

use agent_sandbox_core::{
    FileAccess, FilesystemRule, NetworkRule, Policy, atomic_write_policy, load_policy, merge_layers,
};

#[test]
fn merged_policy_persists_normalized_layers_and_home_paths() {
    let temp = tempfile::tempdir().expect("temporary policy directory");
    let home = temp.path().join("home");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&project).expect("create project");

    let shared = home.join("shared");
    let private = shared.join("private");

    let mut base = Policy::default();
    base.network.direct.allow = vec![NetworkRule::new("api.example.com", 443, "base")];
    base.filesystem.allow = vec![FilesystemRule::new(
        shared.clone(),
        FileAccess::ReadWrite,
        "shared workspace",
    )];

    let mut project_layer = Policy::default();
    project_layer.network.direct.deny = vec![NetworkRule::new("*.example.com", 443, "blocked")];
    project_layer.filesystem.deny = vec![FilesystemRule::new(
        private,
        FileAccess::Write,
        "private writes",
    )];

    let merged = merge_layers(&[base, project_layer]);
    assert!(merged.network.direct.allow.is_empty());
    assert_eq!(merged.network.direct.deny.len(), 1);
    assert_eq!(merged.filesystem.allow.len(), 1);
    assert_eq!(merged.filesystem.deny.len(), 1);
    assert!(merged.filesystem.allow[0].matches(
        &home.join("shared/readme.txt"),
        FileAccess::Read,
        None,
    ));
    assert!(merged.filesystem.deny[0].matches(
        &home.join("shared/private/secret.txt"),
        FileAccess::Write,
        None,
    ));

    let policy_path = project.join(".config/agent-sandbox/policy.json");
    atomic_write_policy(&policy_path, &merged, Some(&home), None, Some(&project))
        .expect("write merged policy");
    let disk = std::fs::read_to_string(&policy_path).expect("read policy");
    assert!(disk.contains("~/shared"));
    assert!(disk.contains("~/shared/private"));

    let loaded = load_policy(&policy_path, Some(&home), Some(&project));
    assert_eq!(loaded.network.direct.allow, merged.network.direct.allow);
    assert_eq!(loaded.network.direct.deny, merged.network.direct.deny);
    assert_eq!(loaded.filesystem.allow, merged.filesystem.allow);
    assert_eq!(loaded.filesystem.deny, merged.filesystem.deny);
    assert_eq!(loaded.filesystem.allow[0].path, PathBuf::from(&shared));
    assert_eq!(loaded.filesystem.deny[0].path, home.join("shared/private"));
}
