//! Merge policy layers (later layers win on duplicate keys).

use std::collections::BTreeMap;

use crate::policy::{
    FileAccess, FilesystemRule, FilesystemSection, NetworkRule, NetworkSection, Policy, SudoRule,
    SudoSection,
};

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
    let mut allow: BTreeMap<(String, u16), NetworkRule> = BTreeMap::new();
    let mut deny: BTreeMap<(String, u16), NetworkRule> = BTreeMap::new();
    for layer in layers {
        for rule in &layer.network.deny {
            let key = rule.key();
            allow.remove(&key);
            deny.insert(key, rule.clone());
        }
        for rule in &layer.network.allow {
            let key = rule.key();
            deny.remove(&key);
            allow.insert(key, rule.clone());
        }
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
        for rule in &layer.sudo.deny {
            let Some(key) = rule.key() else {
                continue;
            };
            allow.remove(&key);
            deny.insert(key, rule.clone());
        }
        for rule in &layer.sudo.allow {
            let Some(key) = rule.key() else {
                continue;
            };
            deny.remove(&key);
            allow.insert(key, rule.clone());
        }
    }
    SudoSection {
        allow: allow.into_values().collect(),
        deny: deny.into_values().collect(),
    }
}

fn filesystem_rule_key(rule: &FilesystemRule) -> (String, FileAccess) {
    (rule.path.trim_end_matches('/').to_owned(), rule.access)
}

fn merge_filesystem(layers: &[Policy]) -> FilesystemSection {
    let mut allow: BTreeMap<(String, FileAccess), FilesystemRule> = BTreeMap::new();
    let mut deny: BTreeMap<(String, FileAccess), FilesystemRule> = BTreeMap::new();
    for layer in layers {
        for rule in &layer.filesystem.deny {
            let key = filesystem_rule_key(rule);
            allow.remove(&key);
            deny.insert(key, rule.clone());
        }
        for rule in &layer.filesystem.allow {
            let key = filesystem_rule_key(rule);
            deny.remove(&key);
            allow.insert(key, rule.clone());
        }
    }
    FilesystemSection {
        allow: allow.into_values().collect(),
        deny: deny.into_values().collect(),
    }
}
