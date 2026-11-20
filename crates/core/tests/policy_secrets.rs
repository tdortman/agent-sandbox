//! Public API tests for `secrets` policy schema, matching, validation,
//! serialization, and layer merging.

use std::collections::BTreeMap;

use agent_sandbox_core::{
    Policy, SecretAccess, SecretOperation, SecretPartition, SecretRequest, SecretRule,
    SecretSection, SecretTarget, atomic_write_policy, load_policy, merge_layers,
};

struct Attr<'a> {
    key: &'a str,
    value: &'a str,
}

const fn attr<'a>(key: &'a str, value: &'a str) -> Attr<'a> {
    Attr { key, value }
}

fn attrs(pairs: &[Attr<'_>]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|pair| (pair.key.to_owned(), pair.value.to_owned()))
        .collect()
}

fn host_read_request(
    collection: &str,
    is_default_collection: bool,
    attributes: BTreeMap<String, String>,
    label: &str,
) -> SecretRequest {
    SecretRequest {
        partition: SecretPartition::Host,
        collection: collection.to_owned(),
        is_default_collection,
        attributes,
        label: label.to_owned(),
        access: SecretAccess::Read,
        operation: SecretOperation::GetSecret,
        replace: false,
        batch: None,
    }
}

#[test]
fn secret_access_lattice_covers_superset_and_union() {
    use SecretAccess::{All, Delete, Read, ReadWrite, Write};

    assert!(All.covers(Read));
    assert!(All.covers(Write));
    assert!(All.covers(ReadWrite));
    assert!(All.covers(Delete));
    assert!(All.covers(All));

    assert!(ReadWrite.covers(Read));
    assert!(ReadWrite.covers(Write));
    assert!(ReadWrite.covers(ReadWrite));
    assert!(!ReadWrite.covers(Delete));
    assert!(!ReadWrite.covers(All));

    assert!(Read.covers(Read));
    assert!(!Read.covers(Write));
    assert!(!Read.covers(ReadWrite));
    assert!(!Read.covers(Delete));

    assert!(Write.covers(Write));
    assert!(!Write.covers(Read));
    assert!(!Write.covers(ReadWrite));
    assert!(!Write.covers(Delete));

    assert!(Delete.covers(Delete));
    assert!(!Delete.covers(Read));
    assert!(!Delete.covers(Write));

    assert!(All.access_superset(ReadWrite));
    assert!(ReadWrite.access_superset(Read));
    assert!(ReadWrite.access_superset(Write));
    assert!(!Write.access_superset(ReadWrite));
    assert!(!Delete.access_superset(ReadWrite));

    assert_eq!(Read.union(Write), ReadWrite);
    assert_eq!(Write.union(Read), ReadWrite);
    assert_eq!(Read.union(ReadWrite), ReadWrite);
    assert_eq!(Write.union(ReadWrite), ReadWrite);
    assert_eq!(Read.union(Delete), All);
    assert_eq!(Write.union(Delete), All);
    assert_eq!(ReadWrite.union(Delete), All);
    assert_eq!(Delete.union(Delete), Delete);
    assert_eq!(All.union(Read), All);
}

#[test]
fn secret_target_matches_collections_subset_attributes_label_and_attribution() {
    let req = host_read_request(
        "kdewallet",
        true,
        attrs(&[
            attr("service", "gh:github.com"),
            attr("username", "octocat"),
            attr("extra", "ignored"),
        ]),
        "GitHub CLI {prod}",
    );

    let default_target = SecretTarget {
        partition: SecretPartition::Host,
        collection: "default".into(),
        attributes: attrs(&[attr("service", "gh:*")]),
        label: Some("GitHub CLI {prod}".into()),
        access: SecretAccess::ReadWrite,
    };
    assert!(default_target.matches(&req, true));

    let concrete_target = SecretTarget {
        collection: "kde*".into(),
        ..default_target.clone()
    };
    assert!(concrete_target.matches(&req, true));

    let wildcard_target = SecretTarget {
        collection: "*".into(),
        ..default_target.clone()
    };
    assert!(wildcard_target.matches(&req, true));

    let mut non_default_req = req.clone();
    non_default_req.is_default_collection = false;
    assert!(!default_target.matches(&non_default_req, true));
    assert!(concrete_target.matches(&non_default_req, true));

    // Missing required attribute must fail.
    let missing_attr_target = SecretTarget {
        attributes: attrs(&[attr("service", "gh:*"), attr("scope", "repo")]),
        ..default_target.clone()
    };
    assert!(!missing_attr_target.matches(&req, true));

    // Access must cover request access.
    let write_only = SecretTarget {
        access: SecretAccess::Write,
        ..default_target
    };
    assert!(!write_only.matches(&req, true));

    // OwnPackage rules never match an unattributed sandbox instance.
    let own_req = SecretRequest {
        partition: SecretPartition::OwnPackage,
        ..req
    };
    let own_target = SecretTarget {
        partition: SecretPartition::OwnPackage,
        collection: "default".into(),
        attributes: BTreeMap::new(),
        label: None,
        access: SecretAccess::All,
    };
    assert!(own_target.matches(&own_req, true));
    assert!(!own_target.matches(&own_req, false));
}

#[test]
fn secret_target_validation_enforces_reserved_keys_collection_and_host_allow_guardrail() {
    let empty_host = SecretTarget {
        partition: SecretPartition::Host,
        collection: "default".into(),
        attributes: BTreeMap::new(),
        label: None,
        access: SecretAccess::Read,
    };
    assert!(empty_host.validate().is_ok());
    assert!(empty_host.validate_for_allow().is_err());

    let label_only_host = SecretTarget {
        label: Some("GitHub token".into()),
        ..empty_host.clone()
    };
    assert!(label_only_host.validate_for_allow().is_ok());

    let empty_own_pkg = SecretTarget {
        partition: SecretPartition::OwnPackage,
        ..empty_host.clone()
    };
    assert!(empty_own_pkg.validate_for_allow().is_ok());

    let reserved_key = SecretTarget {
        attributes: attrs(&[attr("agent-sandbox:package", "other")]),
        ..empty_host.clone()
    };
    assert!(reserved_key.validate().is_err());
    assert!(reserved_key.validate_for_allow().is_err());

    let empty_collection = SecretTarget {
        collection: String::new(),
        label: Some("token".into()),
        ..empty_host
    };
    assert!(empty_collection.validate().is_err());
    assert!(empty_collection.validate_for_allow().is_err());
}

#[test]
fn policy_json_is_backwards_compatible_and_drops_invalid_secret_rules_on_load() {
    // Legacy policy JSON without a `secrets` section still parses.
    let legacy: Policy = serde_json::from_str(r#"{"network":{"direct":{"allow":[],"deny":[]}}}"#)
        .expect("legacy policy without secrets section must deserialize");
    assert_eq!(legacy.secrets.allow, Vec::new());
    assert_eq!(legacy.secrets.deny, Vec::new());

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("policy.json");

    // Write policy containing valid rules plus invalid rules on disk.
    std::fs::write(
        &path,
        r#"{
            "secrets": {
                "allow": [
                    { "partition": "host", "access": "read" },
                    { "partition": "host", "attributes": { "agent-sandbox:package": "codex" }, "access": "read" },
                    { "partition": "host", "collection": "", "label": "tok", "access": "read" },
                    { "partition": "host", "attributes": { "service": "gh" }, "access": "read", "comment": "valid host" },
                    { "partition": "own_package", "access": "all", "comment": "valid own" }
                ],
                "deny": [
                    { "partition": "host", "access": "delete", "comment": "valid host deny" },
                    { "partition": "host", "attributes": { "agent-sandbox:owner": "x" }, "access": "read" }
                ]
            }
        }"#,
    )
    .expect("write policy");

    let loaded = load_policy(&path, None, None);
    assert_eq!(loaded.secrets.allow.len(), 2);
    assert_eq!(loaded.secrets.deny.len(), 1);
    assert_eq!(loaded.secrets.allow[0].target.collection, "default");
    assert_eq!(
        loaded.secrets.deny[0].comment.as_deref(),
        Some("valid host deny")
    );

    // Round-trip through atomic_write_policy preserves secrets in canonical
    // sorted order.
    let persisted_path = dir.path().join("persisted.json");
    atomic_write_policy(&persisted_path, &loaded, None, None, None)
        .expect("atomic_write_policy should persist secrets");
    let reloaded = load_policy(&persisted_path, None, None);
    let mut expected = loaded.secrets;
    expected.allow.sort();
    expected.deny.sort();
    assert_eq!(reloaded.secrets, expected);
}

#[test]
fn merge_layers_preserves_narrow_deny_and_strips_shadowed_secret_allows() {
    let own_all = SecretRule::new(
        SecretTarget {
            partition: SecretPartition::OwnPackage,
            collection: "default".into(),
            attributes: BTreeMap::new(),
            label: None,
            access: SecretAccess::All,
        },
        "allow own package",
    );
    let own_delete_deny = SecretRule::new(
        SecretTarget {
            partition: SecretPartition::OwnPackage,
            collection: "default".into(),
            attributes: BTreeMap::new(),
            label: None,
            access: SecretAccess::Delete,
        },
        "deny delete",
    );

    // Narrow delete deny keeps broad own_package all allow.
    let merged_narrow = merge_layers(&[
        Policy {
            secrets: SecretSection {
                allow: vec![own_all],
                deny: vec![],
            },
            ..Policy::default()
        },
        Policy {
            secrets: SecretSection {
                allow: vec![],
                deny: vec![own_delete_deny.clone()],
            },
            ..Policy::default()
        },
    ]);
    assert_eq!(merged_narrow.secrets.allow.len(), 1);
    assert_eq!(merged_narrow.secrets.deny.len(), 1);

    // "default" vs concrete "kdewallet" stays conservative in merged.
    let default_deny = SecretRule::new(
        SecretTarget {
            partition: SecretPartition::Host,
            collection: "default".into(),
            attributes: attrs(&[attr("service", "gh")]),
            label: None,
            access: SecretAccess::All,
        },
        "deny default",
    );
    let kdewallet_allow = SecretRule::new(
        SecretTarget {
            partition: SecretPartition::Host,
            collection: "kdewallet".into(),
            attributes: attrs(&[attr("service", "gh")]),
            label: None,
            access: SecretAccess::Read,
        },
        "allow kdewallet",
    );
    let merged_conservative = merge_layers(&[
        Policy {
            secrets: SecretSection {
                allow: vec![kdewallet_allow.clone()],
                deny: vec![],
            },
            ..Policy::default()
        },
        Policy {
            secrets: SecretSection {
                allow: vec![],
                deny: vec![default_deny],
            },
            ..Policy::default()
        },
    ]);
    assert_eq!(merged_conservative.secrets.allow.len(), 1);
    assert_eq!(merged_conservative.secrets.deny.len(), 1);

    // Full-coverage deny strips shadowed allow across wildcard collection and
    // subset attributes.
    let broad_host_deny = SecretRule::new(
        SecretTarget {
            partition: SecretPartition::Host,
            collection: "*".into(),
            attributes: attrs(&[attr("service", "gh*")]),
            label: None,
            access: SecretAccess::ReadWrite,
        },
        "deny gh*",
    );
    let merged_shadowed = merge_layers(&[
        Policy {
            secrets: SecretSection {
                allow: vec![kdewallet_allow],
                deny: vec![],
            },
            ..Policy::default()
        },
        Policy {
            secrets: SecretSection {
                allow: vec![],
                deny: vec![broad_host_deny],
            },
            ..Policy::default()
        },
    ]);
    assert_eq!(merged_shadowed.secrets.allow, Vec::new());
    assert_eq!(merged_shadowed.secrets.deny.len(), 1);

    // Distinct access denies on the same SecretRuleKey across layers both
    // survive.
    let own_write_deny = SecretRule::new(
        SecretTarget {
            partition: SecretPartition::OwnPackage,
            collection: "default".into(),
            attributes: BTreeMap::new(),
            label: None,
            access: SecretAccess::Write,
        },
        "deny write",
    );
    let merged_distinct_denies = merge_layers(&[
        Policy {
            secrets: SecretSection {
                allow: vec![],
                deny: vec![own_delete_deny],
            },
            ..Policy::default()
        },
        Policy {
            secrets: SecretSection {
                allow: vec![],
                deny: vec![own_write_deny],
            },
            ..Policy::default()
        },
    ]);
    assert_eq!(merged_distinct_denies.secrets.deny.len(), 2);
}
