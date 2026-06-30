//! Policy store persistence.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use agent_sandbox_core::{
    FileAccess, FilesystemRule, FilesystemSortKey, NetworkRule, NetworkSortKey, ResourceAccess,
    ResourceKind, ResourceRule, ResourceSortKey, SudoRule, atomic_write_policy, contract_home_path,
    load_policy, normalize_host, trusted_project_policy_path,
};

use super::types::PolicyStore;

/// Arguments for [`PolicyStore::persist_resource_rule`], grouped to keep the
/// function signature under clippy's argument-count threshold.
pub struct PersistResourceRuleArgs<'a> {
    pub path: &'a Path,
    pub kind: ResourceKind,
    pub rule_path: &'a Path,
    pub access: ResourceAccess,
    pub label: &'a str,
    pub allow_rule: bool,
    pub home: Option<&'a Path>,
    pub owner_uid: Option<u32>,
}

fn network_rule_sort_key(rule: &NetworkRule) -> NetworkSortKey {
    NetworkSortKey::new(&rule.host, rule.port)
}

fn network_sort_key(host: &str, port: u16) -> NetworkSortKey {
    NetworkSortKey::new(host, port)
}

fn filesystem_path_key(path: &Path) -> String {
    let s = path.to_string_lossy();
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() && s.starts_with('/') {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn upsert_filesystem_rule(
    rules: &mut Vec<FilesystemRule>,
    rule_path: &Path,
    access: FileAccess,
    label: &str,
) {
    let key = filesystem_path_key(rule_path);
    let mut merged_access = access;
    let mut insert_index = None;
    let mut retained = Vec::with_capacity(rules.len() + 1);

    for rule in rules.drain(..) {
        if filesystem_path_key(&rule.path) == key {
            merged_access = merged_access.union(rule.access);
            insert_index.get_or_insert(retained.len());
        } else {
            retained.push(rule);
        }
    }

    let rule = FilesystemRule::new(rule_path, merged_access, label);
    if let Some(index) = insert_index {
        retained.insert(index, rule);
    } else {
        retained.push(rule);
    }
    *rules = retained;
}

fn remove_filesystem_rule(rules: &mut Vec<FilesystemRule>, rule_path: &Path, access: FileAccess) {
    let key = filesystem_path_key(rule_path);
    rules.retain(|rule| filesystem_path_key(&rule.path) != key || rule.access != access);
}

fn filesystem_rule_sort_key(rule: &FilesystemRule, home: Option<&Path>) -> FilesystemSortKey {
    FilesystemSortKey::new(
        contract_home_path(Path::new(&filesystem_path_key(&rule.path)), home),
        rule.access,
    )
}

fn sort_filesystem_rules(rules: &mut [FilesystemRule], home: Option<&Path>) {
    rules.sort_by_key(|rule| filesystem_rule_sort_key(rule, home));
}
fn resource_path_key(path: &Path) -> String {
    let s = path.to_string_lossy();
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() && s.starts_with('/') {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn upsert_resource_rule(
    rules: &mut Vec<ResourceRule>,
    kind: ResourceKind,
    rule_path: &Path,
    access: ResourceAccess,
    label: &str,
) {
    let key = resource_path_key(rule_path);
    let mut merged_access = access;
    let mut insert_index = None;
    let mut retained = Vec::with_capacity(rules.len() + 1);

    for rule in rules.drain(..) {
        if rule.kind == kind && resource_path_key(&rule.path) == key {
            merged_access = merged_access.union(rule.access).unwrap_or(merged_access);
            insert_index.get_or_insert(retained.len());
        } else {
            retained.push(rule);
        }
    }

    let rule = ResourceRule::new(kind, rule_path, merged_access, label);
    if let Some(index) = insert_index {
        retained.insert(index, rule);
    } else {
        retained.push(rule);
    }
    *rules = retained;
}

fn remove_resource_rule(
    rules: &mut Vec<ResourceRule>,
    kind: ResourceKind,
    rule_path: &Path,
    access: ResourceAccess,
) {
    let key = resource_path_key(rule_path);
    rules.retain(|rule| {
        rule.kind != kind || resource_path_key(&rule.path) != key || rule.access != access
    });
}

fn resource_rule_sort_key(rule: &ResourceRule, home: Option<&Path>) -> ResourceSortKey {
    ResourceSortKey::new(
        rule.kind,
        contract_home_path(Path::new(&resource_path_key(&rule.path)), home),
        rule.access,
    )
}

fn sort_resource_rules(rules: &mut [ResourceRule], home: Option<&Path>) {
    rules.sort_by_key(|rule| resource_rule_sort_key(rule, home));
}

impl PolicyStore {
    fn persist_network_rule(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        allow_rule: bool,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path, home, None);
        let host_norm = normalize_host(host);
        let key = network_sort_key(&host_norm, port);
        let mut allow: BTreeMap<NetworkSortKey, NetworkRule> = current
            .network
            .allow
            .iter()
            .map(|r| (network_rule_sort_key(r), r.clone()))
            .collect();
        let mut deny: BTreeMap<NetworkSortKey, NetworkRule> = current
            .network
            .deny
            .iter()
            .map(|r| (network_rule_sort_key(r), r.clone()))
            .collect();

        if allow_rule {
            allow.insert(key.clone(), NetworkRule::new(host_norm, port, label));
            deny.remove(&key);
        } else {
            deny.insert(key.clone(), NetworkRule::new(host_norm, port, label));
            allow.remove(&key);
        }

        current.network.allow = allow.into_values().collect();
        current.network.deny = deny.into_values().collect();
        atomic_write_policy(path, &current, home, owner_uid, None)
    }

    pub(crate) fn persist_network_allow(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_network_rule(path, host, port, label, true, home, owner_uid)
    }

    pub(crate) fn persist_network_deny(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_network_rule(path, host, port, label, false, home, owner_uid)
    }

    fn persist_sudo_rule(
        path: &Path,
        argv: &[String],
        label: &str,
        allow_rule: bool,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path, home, None);
        let key: Vec<String> = argv.to_vec();
        let mut allow: BTreeMap<Vec<String>, SudoRule> = current
            .sudo
            .allow
            .iter()
            .filter_map(|r| r.key().map(|k| (k, r.clone())))
            .collect();
        let mut deny: BTreeMap<Vec<String>, SudoRule> = current
            .sudo
            .deny
            .iter()
            .filter_map(|r| r.key().map(|k| (k, r.clone())))
            .collect();

        if allow_rule {
            allow.insert(key.clone(), SudoRule::new(argv.to_vec(), label));
            deny.remove(&key);
        } else {
            deny.insert(key.clone(), SudoRule::new(argv.to_vec(), label));
            allow.remove(&key);
        }

        current.sudo.allow = allow.into_values().collect();
        current.sudo.deny = deny.into_values().collect();
        atomic_write_policy(path, &current, home, owner_uid, None)
    }

    pub(crate) fn persist_sudo_allow(
        path: &Path,
        argv: &[String],
        label: &str,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_sudo_rule(path, argv, label, true, home, owner_uid)
    }

    pub(crate) fn persist_sudo_deny(
        path: &Path,
        argv: &[String],
        label: &str,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_sudo_rule(path, argv, label, false, home, owner_uid)
    }

    pub(crate) fn persist_filesystem_rule(
        path: &Path,
        rule_path: &Path,
        access: FileAccess,
        label: &str,
        allow_rule: bool,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut policy = load_policy(path, home, None);
        if allow_rule {
            upsert_filesystem_rule(&mut policy.filesystem.allow, rule_path, access, label);
            remove_filesystem_rule(&mut policy.filesystem.deny, rule_path, access);
        } else {
            upsert_filesystem_rule(&mut policy.filesystem.deny, rule_path, access, label);
            remove_filesystem_rule(&mut policy.filesystem.allow, rule_path, access);
        }
        sort_filesystem_rules(&mut policy.filesystem.allow, home);
        sort_filesystem_rules(&mut policy.filesystem.deny, home);
        atomic_write_policy(path, &policy, home, owner_uid, None)
    }

    pub(crate) fn persist_resource_rule(args: &PersistResourceRuleArgs<'_>) -> std::io::Result<()> {
        let &PersistResourceRuleArgs {
            path,
            kind,
            rule_path,
            access,
            label,
            allow_rule,
            home,
            owner_uid,
        } = args;
        let mut policy = load_policy(path, home, None);
        if allow_rule {
            upsert_resource_rule(&mut policy.resources.allow, kind, rule_path, access, label);
            remove_resource_rule(&mut policy.resources.deny, kind, rule_path, access);
        } else {
            upsert_resource_rule(&mut policy.resources.deny, kind, rule_path, access, label);
            remove_resource_rule(&mut policy.resources.allow, kind, rule_path, access);
        }
        sort_resource_rules(&mut policy.resources.allow, home);
        sort_resource_rules(&mut policy.resources.deny, home);
        atomic_write_policy(path, &policy, home, owner_uid, None)
    }

    /// Return the on-disk path the project scope writes to. The path lives
    /// under `<project_root>/.agent-sandbox/policy.json` so
    /// the sandboxed process cannot tamper with its own persistent approvals.
    pub(crate) fn project_policy_path_display(project_root: &Path) -> Option<String> {
        trusted_project_policy_path(project_root)
            .ok()
            .map(|path| path.display().to_string())
    }

    pub(crate) async fn active_session_ids(&self) -> HashSet<String> {
        self.inner
            .lock()
            .await
            .ui_clients
            .values()
            .map(|c| c.session_id.clone())
            .collect()
    }
}
