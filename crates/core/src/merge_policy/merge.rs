//! Merge policy layers with deny-wins semantics. A deny rule for a key is final even if a later layer allowed it.

use std::collections::BTreeMap;

use crate::hosts::{host_pattern_has_glob, host_pattern_matches};
use crate::http::{HttpMethodMatcher, HttpRule, HttpRuleTarget, HttpUrl};
use crate::policy::{
    DbusRule, DbusSection, DirectNetworkSection, FilesystemRule, FilesystemRuleKey,
    FilesystemSection, HttpSection, NetworkRule, NetworkSection, Policy, ResourceRule,
    ResourceRuleKey, ResourceSection, SudoRule, SudoSection,
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
        dbus: merge_dbus(layers),
    }
}

fn dbus_rules_overlap(deny: &DbusRule, allow: &DbusRule) -> bool {
    deny.matches(&allow.target) && allow.matches(&deny.target)
}

fn merge_dbus(layers: &[Policy]) -> DbusSection {
    let (allow, deny) = merge_rules(
        layers,
        |policy| &policy.dbus.allow,
        |policy| &policy.dbus.deny,
        |rule| Some(rule.clone()),
        dbus_rules_overlap,
    );
    DbusSection { allow, deny }
}

fn network_rules_overlap(deny: &NetworkRule, allow: &NetworkRule) -> bool {
    if deny.port != allow.port {
        return false;
    }
    if host_pattern_has_glob(&deny.host) && host_pattern_has_glob(&allow.host) {
        return deny.host.eq_ignore_ascii_case(&allow.host);
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

fn merge_http_rules(layers: &[Policy], allow_rules: bool) -> Vec<HttpRule> {
    let mut merged: BTreeMap<HttpUrl, (HttpMethodMatcher, Option<String>)> = BTreeMap::new();
    for layer in layers {
        let rules = if allow_rules {
            &layer.network.http.allow
        } else {
            &layer.network.http.deny
        };
        for rule in rules {
            let Ok(target) = rule.target() else {
                continue;
            };
            let url = target.url;
            if let Some((methods, comment)) = merged.get_mut(&url) {
                *methods = methods.union(&target.method);
                comment.clone_from(&rule.comment);
            } else {
                merged.insert(url, (target.method, rule.comment.clone()));
            }
        }
    }
    merged
        .into_iter()
        .map(|(url, (methods, comment))| HttpRule {
            methods: methods
                .to_methods()
                .into_iter()
                .map(|method| method.as_str().to_owned())
                .collect(),
            url: url.to_string(),
            comment,
        })
        .collect()
}

fn http_rule_target(rule: &HttpRule) -> Option<HttpRuleTarget> {
    rule.target().ok()
}

fn merge_network(layers: &[Policy]) -> NetworkSection {
    let (direct_allow, direct_deny) = merge_rules(
        layers,
        |policy| &policy.network.direct.allow,
        |policy| &policy.network.direct.deny,
        |rule| Some(rule.key()),
        network_rules_overlap,
    );
    let http_allow = merge_http_rules(layers, true);
    let http_deny = merge_http_rules(layers, false);
    let http_deny_targets: Vec<_> = http_deny.iter().filter_map(http_rule_target).collect();
    let http_allow = http_allow
        .into_iter()
        .filter(|allow| {
            let Some(allow_target) = http_rule_target(allow) else {
                return true;
            };
            !http_deny_targets
                .iter()
                .any(|deny_target| deny_target.covers(&allow_target))
        })
        .collect();
    NetworkSection {
        direct: DirectNetworkSection {
            allow: direct_allow,
            deny: direct_deny,
        },
        http: HttpSection {
            allow: http_allow,
            deny: http_deny,
        },
    }
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

/// Only strip an allow rule when the deny makes it **fully** redundant.
///
/// The deny path must cover the allow path (deny is same or broader) and the
/// deny access must cover every access level the allow grants. A narrower deny
/// (e.g. deny `write` to `./.git/hooks/*` within allow `read_write`
/// `./.git/`)
/// must not strip the broader allow. The evaluator checks deny before allow,
/// so the narrow deny still wins for its specific scope without removing the
/// allow for everything else.
fn filesystem_rules_overlap(deny: &FilesystemRule, allow: &FilesystemRule) -> bool {
    deny.path_matches(&allow.path, None) && deny.access.access_superset(allow.access)
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

/// Same conservative semantics as [`filesystem_rules_overlap`]: only strip the
/// allow when the deny path covers it and the deny access is a superset.
fn resource_rules_overlap(deny: &ResourceRule, allow: &ResourceRule) -> bool {
    deny.kind == allow.kind
        && deny.path_matches(&allow.path, None)
        && deny.access.access_superset(allow.access)
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
    use crate::policy::{
        DeviceAccess, FileAccess, FilesystemRule, FilesystemSection, Policy, ResourceAccess,
        ResourceKind, ResourceRule, ResourceSection,
    };

    fn empty_policy() -> Policy {
        Policy::default()
    }

    #[test]
    fn resource_narrow_deny_keeps_broad_allow() {
        // A narrow deny (/dev/fd/3 OpenRead) must NOT strip a broad allow
        // (/dev/fd OpenReadWrite). The evaluator checks deny before allow,
        // so the deny still wins for its scope. Stripping the allow would
        // block legitimate accesses outside the deny scope.
        let low = Policy {
            resources: ResourceSection {
                allow: vec![ResourceRule::new(
                    ResourceKind::Device,
                    "/dev/fd",
                    ResourceAccess::Device(DeviceAccess::ReadWrite),
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
                    ResourceAccess::Device(DeviceAccess::Read),
                    "",
                )],
            },
            ..empty_policy()
        };

        let merged = merge_layers(&[low, high]);

        assert_eq!(
            merged.resources.allow.len(),
            1,
            "broad /dev/fd allow must survive narrow /dev/fd/3 deny"
        );
        assert_eq!(merged.resources.deny.len(), 1);
    }

    #[test]
    fn resource_exact_deny_shadows_allow_on_merge() {
        // Same path, deny access is a superset of allow access: strip the allow.
        let low = Policy {
            resources: ResourceSection {
                allow: vec![ResourceRule::new(
                    ResourceKind::Device,
                    "/dev/fd/3",
                    ResourceAccess::Device(DeviceAccess::Read),
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
                    ResourceAccess::Device(DeviceAccess::ReadWrite),
                    "",
                )],
            },
            ..empty_policy()
        };

        let merged = merge_layers(&[low, high]);

        assert!(
            merged.resources.allow.is_empty(),
            "deny OpenReadWrite on /dev/fd/3 fully shadows allow OpenRead"
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
                    ResourceAccess::Device(DeviceAccess::Read),
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
                    ResourceAccess::Device(DeviceAccess::Read),
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

    #[test]
    fn filesystem_narrow_deny_keeps_broad_allow() {
        // The bug: deny write to ./.git/hooks/* stripped the entire allow
        // read_write ./.git/ during merge, causing prompts for every file
        // under .git/ (HEAD, config, etc.) even though they are not denied.
        let low = Policy {
            filesystem: FilesystemSection {
                allow: vec![FilesystemRule::new(
                    "./.git/",
                    FileAccess::ReadWrite,
                    "global",
                )],
                deny: vec![],
            },
            ..empty_policy()
        };
        let high = Policy {
            filesystem: FilesystemSection {
                allow: vec![],
                deny: vec![FilesystemRule::new(
                    "./.git/hooks/*",
                    FileAccess::Write,
                    "global",
                )],
            },
            ..empty_policy()
        };

        let merged = merge_layers(&[low, high]);

        assert_eq!(
            merged.filesystem.allow.len(),
            1,
            "broad ./.git/ allow must survive narrow ./.git/hooks/* deny"
        );
        assert_eq!(merged.filesystem.deny.len(), 1);
    }

    #[test]
    fn filesystem_exact_deny_shadows_allow_on_merge() {
        // Same path and deny access is a superset: strip the allow.
        let low = Policy {
            filesystem: FilesystemSection {
                allow: vec![FilesystemRule::new("./.git/", FileAccess::ReadWrite, "")],
                deny: vec![],
            },
            ..empty_policy()
        };
        let high = Policy {
            filesystem: FilesystemSection {
                allow: vec![],
                deny: vec![FilesystemRule::new("./.git/", FileAccess::All, "")],
            },
            ..empty_policy()
        };

        let merged = merge_layers(&[low, high]);

        assert!(
            merged.filesystem.allow.is_empty(),
            "deny All on ./.git/ fully shadows allow ReadWrite"
        );
    }
}
