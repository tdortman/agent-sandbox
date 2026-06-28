//! Merge policy layers with deny-wins semantics. A deny rule for a key is final even if a later layer allowed it.

use std::collections::BTreeMap;

use crate::hosts::NetworkRuleKey;
use crate::policy::{
    FilesystemRule, FilesystemRuleKey, FilesystemSection, NetworkRule, NetworkSection, Policy,
    SudoRule, SudoSection,
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
    }
}

fn merge_network(layers: &[Policy]) -> NetworkSection {
    let mut allow: BTreeMap<NetworkRuleKey, NetworkRule> = BTreeMap::new();
    let mut deny: BTreeMap<NetworkRuleKey, NetworkRule> = BTreeMap::new();
    for layer in layers {
        for rule in &layer.network.allow {
            allow.insert(rule.key(), rule.clone());
        }
        for rule in &layer.network.deny {
            deny.insert(rule.key(), rule.clone());
        }
    }
    // Deny-wins: a deny for a key is final even if a later layer allowed it.
    for key in deny.keys() {
        allow.remove(key);
    }
    NetworkSection {
        allow: allow.into_values().collect(),
        deny: deny.into_values().collect(),
    }
}

fn merge_sudo(layers: &[Policy]) -> SudoSection {
    let mut allow: BTreeMap<Vec<String>, SudoRule> = BTreeMap::new();
    let mut deny: BTreeMap<Vec<String>, SudoRule> = BTreeMap::new();
    for layer in layers {
        for rule in &layer.sudo.allow {
            if let Some(key) = rule.key() {
                allow.insert(key, rule.clone());
            }
        }
        for rule in &layer.sudo.deny {
            if let Some(key) = rule.key() {
                deny.insert(key, rule.clone());
            }
        }
    }
    for key in deny.keys() {
        allow.remove(key);
    }
    SudoSection {
        allow: allow.into_values().collect(),
        deny: deny.into_values().collect(),
    }
}

fn filesystem_rule_key(rule: &FilesystemRule) -> FilesystemRuleKey {
    FilesystemRuleKey::from_rule(rule)
}

fn merge_filesystem(layers: &[Policy]) -> FilesystemSection {
    let mut allow: BTreeMap<FilesystemRuleKey, FilesystemRule> = BTreeMap::new();
    let mut deny: BTreeMap<FilesystemRuleKey, FilesystemRule> = BTreeMap::new();
    for layer in layers {
        for rule in &layer.filesystem.allow {
            allow.insert(filesystem_rule_key(rule), rule.clone());
        }
        for rule in &layer.filesystem.deny {
            deny.insert(filesystem_rule_key(rule), rule.clone());
        }
    }
    for key in deny.keys() {
        allow.remove(key);
    }
    FilesystemSection {
        allow: allow.into_values().collect(),
        deny: deny.into_values().collect(),
    }
}
