use std::path::{Path, PathBuf};

use super::{
    DeviceAccess, FileAccess, FilesystemCheck, FilesystemRule, PathResolution, Policy,
    ResourceAccess, ResourceKind, ResourceRule, SocketAccess, StaticPolicyAllow, SudoRule,
    contract_home_path, contract_project_path, expand_home_path, expire_rule_path_cache,
    filesystem_approval_paths, open_flags_to_file_access,
};

#[test]
fn expand_home_path_blocks_parent_traversal() {
    let home = Path::new("/home/user");
    let tmp = tempfile::tempdir().expect("tempdir");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).expect("outside dir");
    let escaped = expand_home_path(Path::new("~/../outside"), Some(home));

    assert_eq!(
        escaped,
        Path::new("~/../outside"),
        "traversal outside home must not expand"
    );
}

#[test]
fn sudo_rule_matches_prefix_and_globs() {
    let rule = SudoRule::new(
        vec!["systemctl".into(), "restart".into(), "nginx*".into()],
        "",
    );
    let argv = [
        "systemctl".into(),
        "restart".into(),
        "nginx-staging".into(),
        "--now".into(),
    ];
    let wrong_argv = ["systemctl".into(), "stop".into(), "nginx-staging".into()];
    let path_rule = SudoRule::new(vec!["/run/current-system/sw/bin/*".into()], "");
    let path_argv = [
        "/run/current-system/sw/bin/systemctl".into(),
        "status".into(),
    ];
    assert!(rule.matches(&argv));
    assert!(!rule.matches(&wrong_argv));
    assert!(path_rule.matches(&path_argv));
}
#[test]
fn normalize_directory_traverse_maps_execute_to_read_on_directories() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pack = dir.path().join(".git/objects/pack");
    std::fs::create_dir_all(&pack).expect("pack dir");

    assert_eq!(
        super::normalize_directory_traverse_access(&pack, FileAccess::Execute),
        FileAccess::Read
    );

    let pack_file = pack.join("pack-abc.pack");
    std::fs::write(&pack_file, b"x").expect("pack file");

    assert_eq!(
        super::normalize_directory_traverse_access(&pack_file, FileAccess::Execute),
        FileAccess::Execute
    );
}

#[test]
fn file_access_covers() {
    assert!(FileAccess::All.covers(FileAccess::Read));
    assert!(FileAccess::All.covers(FileAccess::Write));
    assert!(FileAccess::All.covers(FileAccess::Execute));
    assert!(FileAccess::All.covers(FileAccess::ReadWrite));
    assert!(FileAccess::ReadWrite.covers(FileAccess::Read));
    assert!(FileAccess::ReadWrite.covers(FileAccess::Write));
    assert!(!FileAccess::ReadWrite.covers(FileAccess::Execute));
    assert!(!FileAccess::Read.covers(FileAccess::Write));
    assert!(FileAccess::Read.covers(FileAccess::Read));
}

#[test]
fn file_access_union_uses_smallest_covering_access() {
    assert_eq!(FileAccess::Read.union(FileAccess::Read), FileAccess::Read);

    assert_eq!(
        FileAccess::Read.union(FileAccess::Write),
        FileAccess::ReadWrite
    );

    assert_eq!(
        FileAccess::ReadWrite.union(FileAccess::Read),
        FileAccess::ReadWrite
    );

    assert_eq!(
        FileAccess::ReadWrite.union(FileAccess::Execute),
        FileAccess::All
    );

    assert_eq!(FileAccess::All.union(FileAccess::Read), FileAccess::All);
}

#[test]
fn file_access_combine_observed_keeps_conservative_runtime_access() {
    assert_eq!(
        FileAccess::Read.combine_observed(FileAccess::Write),
        FileAccess::ReadWrite
    );

    assert_eq!(
        FileAccess::Read.combine_observed(FileAccess::Execute),
        FileAccess::All
    );

    assert_eq!(
        FileAccess::Read.combine_observed(FileAccess::ReadWrite),
        FileAccess::ReadWrite
    );
}

#[test]
fn open_flags_classify_to_file_access() {
    assert_eq!(open_flags_to_file_access(libc::O_RDONLY), FileAccess::Read);
    assert_eq!(open_flags_to_file_access(libc::O_WRONLY), FileAccess::Write);

    assert_eq!(
        open_flags_to_file_access(libc::O_RDWR),
        FileAccess::ReadWrite
    );

    assert_eq!(
        open_flags_to_file_access(libc::O_RDWR | libc::O_APPEND),
        FileAccess::ReadWrite
    );

    assert_eq!(
        open_flags_to_file_access(libc::O_RDONLY | libc::O_CREAT),
        FileAccess::ReadWrite
    );

    assert_eq!(
        open_flags_to_file_access(libc::O_RDONLY | libc::O_TRUNC),
        FileAccess::ReadWrite
    );
}

#[test]
fn filesystem_rule_matches_exact_path() {
    let rule = FilesystemRule::new("/home/user", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/home/user"), None));
    assert!(!rule.path_matches(Path::new("/home/userx"), None));
}

#[test]
fn filesystem_rule_matches_descendant() {
    let rule = FilesystemRule::new("/home", FileAccess::ReadWrite, "");
    assert!(rule.path_matches(Path::new("/home/user"), None));
    assert!(rule.path_matches(Path::new("/home/user/file.txt"), None));
    assert!(!rule.path_matches(Path::new("/var/log"), None));
}

#[test]
fn filesystem_rule_trailing_slash_matches_descendants() {
    // Regression: a rule path ending in '/' (e.g. from a Nix readwriteDirs
    // entry like "~/.local/state/opencode/") must still match its own
    // directory and its children. The matcher normalizes the requested path
    // but previously not the rule path, so the descendant prefix check
    // failed ("model.json" has no leading '/').
    let rule = FilesystemRule::new("/home/user/state/opencode/", FileAccess::ReadWrite, "");

    assert!(rule.path_matches(Path::new("/home/user/state/opencode"), None));
    assert!(rule.path_matches(Path::new("/home/user/state/opencode/model.json"), None));

    // Prefix boundary: a longer name sharing the prefix stem must not
    // match.
    assert!(!rule.path_matches(Path::new("/home/user/state/opencode-other"), None));

    assert!(!rule.path_matches(Path::new("/home/user/elsewhere"), None));
}

#[test]
fn filesystem_rule_respects_access_hierarchy() {
    let rule = FilesystemRule::new("/tmp", FileAccess::ReadWrite, "");
    assert!(rule.matches(Path::new("/tmp"), FileAccess::Read, None));
    assert!(rule.matches(Path::new("/tmp"), FileAccess::Write, None));
    assert!(!rule.matches(Path::new("/tmp"), FileAccess::Execute, None));
    let all_rule = FilesystemRule::new("/nix/store", FileAccess::All, "");
    assert!(all_rule.matches(Path::new("/nix/store/something"), FileAccess::Execute, None));
    assert!(all_rule.matches(Path::new("/nix/store"), FileAccess::Write, None));
}

#[test]
fn glob_match_dot_slash_dot_env() {
    let rule = FilesystemRule::new("./**/.env", FileAccess::Read, "");

    // With project_root="/work", ./**/.env -> /work/**/.env
    assert!(rule.path_matches(Path::new("/work/.env"), Some(Path::new("/work"))));

    assert!(rule.path_matches(Path::new("/work/sub/.env"), Some(Path::new("/work"))));
    assert!(!rule.path_matches(Path::new("/etc/.env"), Some(Path::new("/work"))));
}

#[test]
fn glob_match_double_star_dot_env() {
    let rule = FilesystemRule::new("**/.env", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/.env"), None));
    assert!(rule.path_matches(Path::new("/work/sub/.env"), None));
}

#[test]
fn glob_match_dot_slash_double_star_dot_env_with_project_root() {
    let rule = FilesystemRule::new("./**/.env", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/.env"), Some(Path::new("/work"))));
    assert!(rule.path_matches(Path::new("/work/sub/.env"), Some(Path::new("/work"))));
    assert!(!rule.path_matches(Path::new("/etc/.env"), Some(Path::new("/work"))));
}

#[test]
fn glob_does_not_match_non_matching_pattern() {
    let rule = FilesystemRule::new("**/secret", FileAccess::Read, "");
    assert!(!rule.path_matches(Path::new("/work/.env"), None));
    assert!(rule.path_matches(Path::new("/work/secret"), None));
}

#[test]
fn filesystem_globset_question_mark_matches_one_character() {
    let rule = FilesystemRule::new("/work/file?.txt", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/file1.txt"), None));
    assert!(!rule.path_matches(Path::new("/work/file12.txt"), None));
}

#[test]
fn filesystem_globset_star_respects_literal_separator() {
    let rule = FilesystemRule::new("/work/*.txt", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/file.txt"), None));
    assert!(!rule.path_matches(Path::new("/work/sub/file.txt"), None));
}

#[test]
fn filesystem_globset_double_star_matches_nested_paths() {
    let rule = FilesystemRule::new("/work/**/file.txt", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/file.txt"), None));
    assert!(rule.path_matches(Path::new("/work/sub/file.txt"), None));
    assert!(!rule.path_matches(Path::new("/work/file.bin"), None));
}

#[test]
fn filesystem_globset_alternates_and_character_classes_match() {
    let rule = FilesystemRule::new("/work/{src,test}/[a-c][!x].rs", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/src/ab.rs"), None));
    assert!(rule.path_matches(Path::new("/work/test/cd.rs"), None));
    assert!(!rule.path_matches(Path::new("/work/doc/ab.rs"), None));
    assert!(!rule.path_matches(Path::new("/work/src/ax.rs"), None));
}

#[test]
fn filesystem_globset_escapes_match_literal_metacharacters() {
    let rule = FilesystemRule::new(r"/work/\*.txt", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/*.txt"), None));
    assert!(!rule.path_matches(Path::new("/work/file.txt"), None));
}

#[test]
fn glob_dot_slash_prefix_expands_correctly() {
    let rule = FilesystemRule::new("./foo", FileAccess::Read, "");
    assert!(rule.path_matches(Path::new("/work/foo"), Some(Path::new("/work"))));
    assert!(rule.path_matches(Path::new("/work/foo/bar"), Some(Path::new("/work"))));
    assert!(!rule.path_matches(Path::new("/work/foobar"), Some(Path::new("/work"))));
}

#[test]
fn git_directory_prefix_matches_inside_git_directory_with_project_root() {
    let rule = FilesystemRule::new("./.git", FileAccess::ReadWrite, "");
    let root = Path::new("/home/user/dotfiles");
    assert!(rule.matches(&root.join(".git"), FileAccess::ReadWrite, Some(root)));
    assert!(rule.matches(&root.join(".git/config"), FileAccess::ReadWrite, Some(root)));

    assert!(rule.matches(
        &root.join(".git/objects/pack"),
        FileAccess::Read,
        Some(root)
    ));

    assert!(rule.matches(
        &root.join(".git/objects/39/2aff17307d2091111c7a71e95580c632d90421"),
        FileAccess::ReadWrite,
        Some(root)
    ));
}

#[test]
fn git_directory_prefix_without_project_root_does_not_match_absolute_git_paths() {
    let rule = FilesystemRule::new("./.git", FileAccess::ReadWrite, "");
    let root = Path::new("/home/user/dotfiles");
    assert!(!rule.matches(&root.join(".git/config"), FileAccess::ReadWrite, None));
}

#[test]
fn globset_star_matches_across_slashes_by_default() {
    use globset::{Glob, GlobBuilder};

    let default = Glob::new("/home/user/dotfiles/.git*")
        .expect("glob")
        .compile_matcher();

    assert!(default.is_match("/home/user/dotfiles/.git/config"));

    let literal = GlobBuilder::new("/home/user/dotfiles/.git*")
        .literal_separator(true)
        .build()
        .expect("glob")
        .compile_matcher();

    assert!(!literal.is_match("/home/user/dotfiles/.git/config"));
}

#[test]
fn git_directory_prefix_matches_files_inside() {
    let rule = FilesystemRule::new("./.git", FileAccess::ReadWrite, "");
    let root = Path::new("/home/user/dotfiles");
    assert!(rule.matches(&root.join(".git/config"), FileAccess::ReadWrite, Some(root)));
}

#[test]
fn filesystem_approval_paths_exact_path_first() {
    let paths = filesystem_approval_paths(
        Path::new("/home/user/.local/share/foo"),
        Some(Path::new("/home/user")),
    );

    assert_eq!(
        paths[0],
        PathBuf::from("/home/user/.local/share/foo"),
        "exact path must be first"
    );
}

#[test]
fn filesystem_approval_paths_under_home_stops_at_home() {
    let paths = filesystem_approval_paths(
        Path::new("/home/user/.local/share/foo"),
        Some(Path::new("/home/user")),
    );

    assert_eq!(paths, vec![
        PathBuf::from("/home/user/.local/share/foo"),
        PathBuf::from("/home/user/.local/share"),
        PathBuf::from("/home/user/.local"),
        PathBuf::from("/home/user"),
    ]);
}

#[test]
fn filesystem_approval_paths_non_home_includes_root() {
    let paths = filesystem_approval_paths(
        Path::new("/nix/store/abc123/bin/hello"),
        Some(Path::new("/home/user")),
    );

    assert_eq!(paths, vec![
        PathBuf::from("/nix/store/abc123/bin/hello"),
        PathBuf::from("/nix/store/abc123/bin"),
        PathBuf::from("/nix/store/abc123"),
        PathBuf::from("/nix/store"),
        PathBuf::from("/nix"),
        PathBuf::from("/"),
    ]);
}

#[test]
fn filesystem_approval_paths_root_path_returns_just_root() {
    let paths = filesystem_approval_paths(Path::new("/"), Some(Path::new("/home/user")));
    assert_eq!(paths, vec![PathBuf::from("/")]);
}

#[test]
fn filesystem_approval_paths_home_exact_returns_just_home() {
    let paths = filesystem_approval_paths(Path::new("/home/user"), Some(Path::new("/home/user")));

    assert_eq!(paths, vec![PathBuf::from("/home/user")]);
}

#[test]
fn filesystem_approval_paths_no_duplicates() {
    let paths = filesystem_approval_paths(Path::new("/etc/passwd"), None);
    let mut dedup = paths.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(paths.len(), dedup.len(), "must not have duplicates");
}

#[test]
fn contract_home_path_converts_under_home() {
    let home = Path::new("/home/user");

    assert_eq!(
        contract_home_path(Path::new("/home/user/.local/share/foo"), Some(home)),
        PathBuf::from("~/.local/share/foo")
    );

    assert_eq!(
        contract_home_path(Path::new("/home/user"), Some(home)),
        PathBuf::from("~")
    );

    assert_eq!(
        contract_home_path(Path::new("/home/user/"), Some(home)),
        PathBuf::from("~")
    );
}

#[test]
fn contract_project_path_converts_unix_socket_under_project() {
    let project = Path::new("/home/user/repo");

    assert_eq!(
        contract_project_path(Path::new("/home/user/repo/.agent.sock"), Some(project)),
        PathBuf::from("./.agent.sock")
    );

    assert_eq!(
        contract_project_path(Path::new("/tmp/agent.sock"), Some(project)),
        PathBuf::from("/tmp/agent.sock")
    );
}

#[test]
fn contract_home_path_leaves_non_home_paths_unchanged() {
    let home = Path::new("/home/user");

    assert_eq!(
        contract_home_path(Path::new("/nix/store"), Some(home)),
        PathBuf::from("/nix/store")
    );

    assert_eq!(
        contract_home_path(Path::new("/"), Some(home)),
        PathBuf::from("/")
    );

    assert_eq!(
        contract_home_path(Path::new("/home"), Some(home)),
        PathBuf::from("/home")
    );

    assert_eq!(
        contract_home_path(Path::new("/home/user2/file"), Some(home)),
        PathBuf::from("/home/user2/file")
    );
}

#[test]
fn contract_home_path_without_home_is_passthrough() {
    assert_eq!(
        contract_home_path(Path::new("/home/user/.local/share/foo"), None),
        PathBuf::from("/home/user/.local/share/foo")
    );
}

#[test]
fn expand_home_path_converts_tilde() {
    let home = Path::new("/home/user");

    assert_eq!(
        expand_home_path(Path::new("~/.local/share/foo"), Some(home)),
        PathBuf::from("/home/user/.local/share/foo")
    );

    assert_eq!(
        expand_home_path(Path::new("~"), Some(home)),
        PathBuf::from("/home/user")
    );
}

#[test]
fn expand_home_path_leaves_absolute_paths_unchanged() {
    let home = Path::new("/home/user");

    assert_eq!(
        expand_home_path(Path::new("/nix/store"), Some(home)),
        PathBuf::from("/nix/store")
    );

    assert_eq!(
        expand_home_path(Path::new("/"), Some(home)),
        PathBuf::from("/")
    );
}

#[test]
fn expand_home_path_without_home_keeps_tilde() {
    assert_eq!(
        expand_home_path(Path::new("~/.local/share/foo"), None),
        PathBuf::from("~/.local/share/foo")
    );
}

#[test]
fn contract_expand_round_trip() {
    let home = Path::new("/home/user");
    let original = Path::new("/home/user/.local/share/foo/agent/models.db-wal");
    let contracted = contract_home_path(original, Some(home));

    assert_eq!(
        contracted,
        PathBuf::from("~/.local/share/foo/agent/models.db-wal")
    );

    let expanded = expand_home_path(&contracted, Some(home));
    assert_eq!(expanded, original);
}

#[test]
fn resource_rule_matches_descendants_with_access_hierarchy() {
    let rule = ResourceRule::new(
        ResourceKind::Device,
        "/dev/fd",
        ResourceAccess::Device(DeviceAccess::ReadWrite),
        "",
    );

    assert!(rule.matches(
        ResourceKind::Device,
        Path::new("/dev/fd/3"),
        ResourceAccess::Device(DeviceAccess::Read),
        None
    ));

    assert!(rule.matches(
        ResourceKind::Device,
        Path::new("/dev/fd/3"),
        ResourceAccess::Device(DeviceAccess::Write),
        None
    ));

    assert!(!rule.matches(
        ResourceKind::Device,
        Path::new("/dev/fd/3"),
        ResourceAccess::Socket(SocketAccess::Connect),
        None
    ));

    assert!(!rule.matches(
        ResourceKind::UnixSocket,
        Path::new("/dev/fd/3"),
        ResourceAccess::Device(DeviceAccess::Read),
        None
    ));
}

#[test]
fn resource_socket_connect_and_send_are_distinct() {
    let connect_rule = ResourceRule::new(
        ResourceKind::UnixSocket,
        "/tmp/example.sock",
        ResourceAccess::Socket(SocketAccess::Connect),
        "",
    );

    assert!(connect_rule.matches(
        ResourceKind::UnixSocket,
        Path::new("/tmp/example.sock"),
        ResourceAccess::Socket(SocketAccess::Connect),
        None
    ));

    assert!(!connect_rule.matches(
        ResourceKind::UnixSocket,
        Path::new("/tmp/example.sock"),
        ResourceAccess::Socket(SocketAccess::Send),
        None
    ));

    let send_rule = ResourceRule::new(
        ResourceKind::UnixSocket,
        "/tmp/example.sock",
        ResourceAccess::Socket(SocketAccess::Send),
        "",
    );

    assert!(send_rule.matches(
        ResourceKind::UnixSocket,
        Path::new("/tmp/example.sock"),
        ResourceAccess::Socket(SocketAccess::Send),
        None
    ));

    assert!(!send_rule.matches(
        ResourceKind::UnixSocket,
        Path::new("/tmp/example.sock"),
        ResourceAccess::Socket(SocketAccess::Connect),
        None
    ));

    let all = ResourceAccess::Socket(SocketAccess::All);
    assert!(all.covers(ResourceAccess::Socket(SocketAccess::Connect)));
    assert!(all.covers(ResourceAccess::Socket(SocketAccess::Send)));

    assert_eq!(
        ResourceAccess::Socket(SocketAccess::Connect)
            .union(ResourceAccess::Socket(SocketAccess::Send)),
        Some(all)
    );

    assert_eq!(
        serde_json::to_string(&all).expect("serialize socket all"),
        "\"all\""
    );

    assert_eq!(
        serde_json::from_str::<ResourceAccess>("\"all\"").expect("deserialize socket all"),
        all
    );
}

#[test]
fn resource_rule_trailing_slash_matches_descendants() {
    let rule = ResourceRule::new(
        ResourceKind::UnixSocket,
        "/run/user/1000/bus/",
        ResourceAccess::Socket(SocketAccess::Connect),
        "",
    );

    assert!(rule.path_matches(Path::new("/run/user/1000/bus"), None));
    assert!(rule.path_matches(Path::new("/run/user/1000/bus/socket"), None));
    assert!(!rule.path_matches(Path::new("/run/user/1000/bus-other"), None));
}

#[test]
fn static_policy_allow_never_grants_what_a_deny_rule_covers() {
    let project = tempfile::tempdir().expect("project root");
    std::fs::create_dir_all(project.path().join(".git/hooks")).expect("create hooks");
    let mut policy = Policy::default();

    policy
        .filesystem
        .allow
        .push(FilesystemRule::new("./.git", FileAccess::ReadWrite, "test"));

    policy.filesystem.deny.push(FilesystemRule::new(
        "./.git/hooks",
        FileAccess::Write,
        "test",
    ));

    let eval = StaticPolicyAllow::from_policy(policy, Some(project.path().to_path_buf()));
    let hook = project.path().join(".git/hooks/pre-commit");
    let config = project.path().join(".git/config");

    assert!(!eval.allows(&hook, FileAccess::Write, PathResolution::Unresolved));
    assert!(!eval.allows(&hook, FileAccess::ReadWrite, PathResolution::Unresolved));
    assert!(!eval.allows_literal(&hook, FileAccess::ReadWrite, PathResolution::Unresolved));
    assert!(
        eval.allows(&hook, FileAccess::Read, PathResolution::Unresolved),
        "deny covers writes only"
    );
    assert!(eval.allows_literal(&config, FileAccess::ReadWrite, PathResolution::Unresolved));
}

#[test]
fn static_policy_allow_matches_allow_rules_only() {
    let mut policy = Policy::default();

    policy.filesystem.allow.push(FilesystemRule::new(
        "/home/user/bench",
        FileAccess::All,
        "test",
    ));

    policy
        .filesystem
        .allow
        .push(FilesystemRule::new("/readonly", FileAccess::Read, "test"));

    let eval = StaticPolicyAllow::from_policy(policy, None);
    assert!(eval.allows(
        Path::new("/home/user/bench/run/f0"),
        FileAccess::ReadWrite,
        PathResolution::Unresolved
    ));
    assert!(eval.allows(
        Path::new("/readonly"),
        FileAccess::Read,
        PathResolution::Unresolved
    ));

    assert!(
        !eval.allows(
            Path::new("/readonly"),
            FileAccess::Write,
            PathResolution::Unresolved
        ),
        "access mode must match"
    );

    assert!(!eval.allows(
        Path::new("/denied"),
        FileAccess::Read,
        PathResolution::Unresolved
    ));

    assert!(
        !eval.allows(
            Path::new("/home/user/benchmark"),
            FileAccess::Read,
            PathResolution::Unresolved
        ),
        "prefix must not match"
    );

    assert!(eval.allows_all(&[
        FilesystemCheck {
            path: PathBuf::from("/home/user/bench/a"),
            access: FileAccess::Read
        },
        FilesystemCheck {
            path: PathBuf::from("/readonly"),
            access: FileAccess::Read
        },
    ]));

    assert!(!eval.allows_all(&[
        FilesystemCheck {
            path: PathBuf::from("/home/user/bench/a"),
            access: FileAccess::Read
        },
        FilesystemCheck {
            path: PathBuf::from("/denied"),
            access: FileAccess::Read
        },
    ]));
}

#[test]
fn static_policy_allow_resolves_current_rule_and_request_aliases() {
    let temporary = tempfile::tempdir().expect("temporary policy directory");
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    let alias = temporary.path().join("alias");
    std::fs::create_dir(&first).expect("create first target");
    std::fs::create_dir(&second).expect("create second target");
    std::os::unix::fs::symlink(&first, &alias).expect("create alias");

    let mut policy = Policy::default();

    policy
        .filesystem
        .allow
        .push(FilesystemRule::new(&alias, FileAccess::Read, "test"));

    let rule_alias = StaticPolicyAllow::from_policy(policy.clone(), None);
    policy.filesystem.allow[0].path.clone_from(&first);

    let request_alias = StaticPolicyAllow::from_policy(policy, None);
    assert!(rule_alias.allows(&first, FileAccess::Read, PathResolution::Unresolved));
    assert!(request_alias.allows(&alias, FileAccess::Read, PathResolution::Unresolved));
    assert!(!request_alias.allows(&alias, FileAccess::Write, PathResolution::Unresolved));
    std::fs::remove_file(&alias).expect("remove alias");
    std::os::unix::fs::symlink(&second, &alias).expect("retarget alias");
    expire_rule_path_cache();
    assert!(!rule_alias.allows(&first, FileAccess::Read, PathResolution::Unresolved));
    assert!(
        !rule_alias.allows(&second, FileAccess::Read, PathResolution::Unresolved),
        "a retargeted rule alias is left to policyd"
    );
    assert!(!request_alias.allows(&alias, FileAccess::Read, PathResolution::Unresolved));
}

#[test]
fn memoized_expansion_resolves_aliases_like_realpath() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let real = root.join("real");
    std::fs::create_dir_all(real.join("sub")).expect("create tree");
    std::fs::write(real.join("sub/file"), "").expect("create file");
    std::os::unix::fs::symlink(&real, root.join("dir-link")).expect("dir link");
    std::os::unix::fs::symlink("real/sub/file", root.join("file-link")).expect("file link");
    std::os::unix::fs::symlink("dir-link/sub", root.join("chain")).expect("chained link");

    let cases = [
        root.join("dir-link/sub/file"),
        root.join("file-link"),
        root.join("chain/file"),
        root.join("dir-link/../real/sub"),
        root.join("dir-link/missing"),
        root.join("real/sub/file/beneath-a-file"),
    ];

    let plain: Vec<_> = cases
        .iter()
        .map(|path| super::expand_policy_path(path, None, None))
        .collect();

    let memoized: Vec<_> = super::with_canonical_memo(|| {
        cases
            .iter()
            .chain(&cases)
            .map(|path| super::expand_policy_path(path, None, None))
            .collect()
    });

    assert_eq!(memoized[..cases.len()], plain[..]);
    assert_eq!(memoized[cases.len()..], plain[..]);
    assert_eq!(
        plain[0],
        real.canonicalize().expect("real").join("sub/file")
    );
}
