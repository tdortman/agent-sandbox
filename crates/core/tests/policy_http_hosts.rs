use std::path::Path;

use agent_sandbox_core::{
    FileAccess, FilesystemRule, HttpRequest, HttpRule, NetworkRule, SudoRule, normalize_dns_name,
    policy_host_for_connect,
};

#[test]
fn host_normalization_flows_into_http_and_direct_policy_keys() {
    assert_eq!(
        normalize_dns_name(" BÜCHER.Example. ").expect("IDNA hostname"),
        "xn--bcher-kva.example"
    );

    let resolution = policy_host_for_connect(" Example.COM. ", None);
    assert_eq!(resolution.policy_host, "example.com");
    assert_eq!(resolution.connect_host, "Example.COM.");

    let direct = NetworkRule::new(" EXAMPLE.com. ", 443, "direct");
    assert_eq!(direct.key().host, "example.com");
    assert_eq!(direct.key().port, 443);

    let http_rule = HttpRule::new(
        vec!["GET".into()],
        "https://BÜCHER.Example.:443/api/*",
        "IDNA HTTP rule",
    );
    let target = http_rule.target().expect("valid HTTP policy rule");
    let request = HttpRequest::parse_absolute(
        "GET",
        "https://xn--bcher-kva.example/api/v1?ignored=by-policy",
    )
    .expect("valid HTTP request");
    assert!(target.matches(&request));

    let other_method = HttpRequest::parse_absolute("POST", "https://xn--bcher-kva.example/api/v1")
        .expect("valid HTTP request");
    assert!(!target.matches(&other_method));
}

#[test]
fn public_policy_rules_match_access_and_command_boundaries() {
    let filesystem = FilesystemRule::new("/srv/project", FileAccess::ReadWrite, "workspace");
    assert!(filesystem.matches(
        Path::new("/srv/project/src/main.rs"),
        FileAccess::Read,
        None
    ));
    assert!(filesystem.matches(
        Path::new("/srv/project/src/main.rs"),
        FileAccess::Write,
        None
    ));
    assert!(!filesystem.matches(Path::new("/srv/projector/file"), FileAccess::Read, None));

    let sudo = SudoRule::new(vec!["git".into(), "status".into()], "safe status");
    assert!(sudo.matches(&["git".into(), "status".into(), "--short".into()]));
    assert!(!sudo.matches(&["git".into(), "push".into()]));
}
