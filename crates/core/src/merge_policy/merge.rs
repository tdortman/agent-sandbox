//! Merge policy layers with deny-wins semantics. A deny rule for a key is final even if a later layer allowed it.

use std::collections::BTreeMap;

use crate::hosts::host_pattern_matches;
use crate::policy::{
    FilesystemRule, FilesystemRuleKey, FilesystemSection, NetworkRule, NetworkSection, Policy,
    ResourceRule, ResourceRuleKey, ResourceSection, SudoRule, SudoSection,
};

#[must_use]
pub fn merge_layers(layers: &[Policy]) -> Policy {
    if layers.is_empty() {
        return Policy::default();
    }
    Policy {
        network: merge_network(layers),
        sudo: merge_sudo(layers),
        filesystem: merge_filesystem(layers),
        resources: merge_resources(layers),
    }
}

fn network_rules_overlap(deny: &NetworkRule, allow: &NetworkRule) -> bool {
    if deny.port != allow.port {
        return false;
    }
    host_pattern_matches(&deny.host, &allow.host) || host_pattern_matches(&allow.host, &deny.host)
}

fn merge_rules<R, K, Allow, Deny, Key, Overlap>(
    layers: &[Policy],
    allow_rules: Allow,
    deny_rules: Deny,
    key: Key,
    overlaps: Overlap,
) -> (Vec<R>, Vec<R>)
where
    R: Clone,
    K: Ord,
    Allow: Fn(&Policy) -> &[R],
    Deny: Fn(&Policy) -> &[R],
    Key: Fn(&R) -> Option<K>,
    Overlap: Fn(&R, &R) -> bool,
{
    let mut allow: BTreeMap<K, R> = BTreeMap::new();
    let mut deny: BTreeMap<K, R> = BTreeMap::new();
    for layer in layers {
        for rule in allow_rules(layer) {
            if let Some(key) = key(rule) {
                allow.insert(key, rule.clone());
            }
        }
        for rule in deny_rules(layer) {
            if let Some(key) = key(rule) {
                deny.insert(key, rule.clone());
            }
        }
    }
    allow.retain(|_, allow_rule| {
        !deny
            .values()
            .any(|deny_rule| overlaps(deny_rule, allow_rule))
    });
    (allow.into_values().collect(), deny.into_values().collect())
}

fn merge_network(layers: &[Policy]) -> NetworkSection {
    let (allow, deny) = merge_rules(
        layers,
        |policy| &policy.network.allow,
        |policy| &policy.network.deny,
        |rule| Some(rule.key()),
        network_rules_overlap,
    );
    NetworkSection { allow, deny }
}

fn sudo_rules_overlap(deny: &SudoRule, allow: &SudoRule) -> bool {
    deny.matches(&allow.argv) || allow.matches(&deny.argv)
}

fn merge_sudo(layers: &[Policy]) -> SudoSection {
    let (allow, deny) = merge_rules(
        layers,
        |policy| &policy.sudo.allow,
        |policy| &policy.sudo.deny,
        SudoRule::key,
        sudo_rules_overlap,
    );
    SudoSection { allow, deny }
}

fn filesystem_rule_key(rule: &FilesystemRule) -> FilesystemRuleKey {
    FilesystemRuleKey::from_rule(rule)
}

fn filesystem_rules_overlap(deny: &FilesystemRule, allow: &FilesystemRule) -> bool {
    deny.matches(&allow.path, allow.access, None) || allow.matches(&deny.path, deny.access, None)
}

fn merge_filesystem(layers: &[Policy]) -> FilesystemSection {
    let (allow, deny) = merge_rules(
        layers,
        |policy| &policy.filesystem.allow,
        |policy| &policy.filesystem.deny,
        |rule| Some(filesystem_rule_key(rule)),
        filesystem_rules_overlap,
    );
    FilesystemSection { allow, deny }
}

fn resource_rule_key(rule: &ResourceRule) -> ResourceRuleKey {
    ResourceRuleKey::from_rule(rule)
}

fn resource_rules_overlap(deny: &ResourceRule, allow: &ResourceRule) -> bool {
    deny.matches(allow.kind, &allow.path, allow.access, None)
        || allow.matches(deny.kind, &deny.path, deny.access, None)
}

fn merge_resources(layers: &[Policy]) -> ResourceSection {
    let (allow, deny) = merge_rules(
        layers,
        |policy| &policy.resources.allow,
        |policy| &policy.resources.deny,
        |rule| Some(resource_rule_key(rule)),
        resource_rules_overlap,
    );
    ResourceSection { allow, deny }
}

#[cfg(test)]
mod tests {
    use super::merge_layers;
    use crate::policy::{Policy, ResourceAccess, ResourceKind, ResourceRule, ResourceSection};

    fn empty_policy() -> Policy {
        Policy::default()
    }

    #[test]
    fn resource_deny_shadows_overlapping_allow_on_merge() {
        let low = Policy {
            resources: ResourceSection {
                allow: vec![ResourceRule::new(
                    ResourceKind::Device,
                    "/dev/fd",
                    ResourceAccess::OpenReadWrite,
                    "",
                )],
                deny: vec![],
            },
            ..empty_policy()
        };
        let high = Policy {
            resources: ResourceSection {
                allow: vec![],
                deny: vec![ResourceRule::new(
                    ResourceKind::Device,
                    "/dev/fd/3",
                    ResourceAccess::OpenRead,
                    "",
                )],
            },
            ..empty_policy()
        };

        let merged = merge_layers(&[low, high]);

        assert!(
            merged.resources.allow.is_empty(),
            "deny on /dev/fd/3 must shadow broader /dev/fd allow"
        );
        assert_eq!(merged.resources.deny.len(), 1);
    }

    #[test]
    fn resource_trailing_slash_paths_merge_as_one_rule() {
        let low = Policy {
            resources: ResourceSection {
                allow: vec![ResourceRule::new(
                    ResourceKind::Device,
                    "/dev/fd/",
                    ResourceAccess::OpenRead,
                    "",
                )],
                deny: vec![],
            },
            ..empty_policy()
        };
        let high = Policy {
            resources: ResourceSection {
                allow: vec![ResourceRule::new(
                    ResourceKind::Device,
                    "/dev/fd",
                    ResourceAccess::OpenRead,
                    "",
                )],
                deny: vec![],
            },
            ..empty_policy()
        };

        let merged = merge_layers(&[low, high]);

        assert_eq!(merged.resources.allow.len(), 1);
        assert_eq!(
            merged.resources.allow[0].path.as_path(),
            std::path::Path::new("/dev/fd")
        );
    }
}
