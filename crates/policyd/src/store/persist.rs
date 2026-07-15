//! Policy store persistence.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use agent_sandbox_core::{
    FileAccess, FilesystemRule, FilesystemSortKey, HttpRule, HttpRuleTarget, NetworkRule,
    NetworkSortKey, ResourceAccess, ResourceKind, ResourceRule, ResourceSortKey, SudoRule,
    atomic_write_policy, contract_home_path, load_policy, normalize_host,
    trusted_project_policy_path,
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
            if let Some(union) = merged_access.union(rule.access) {
                merged_access = union;
                insert_index.get_or_insert(retained.len());
            } else {
                retained.push(rule);
            }
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum HttpMethods {
    All,
    Some(BTreeSet<String>),
}

impl HttpMethods {
    fn from_target(target: &HttpRuleTarget) -> Self {
        match &target.method {
            agent_sandbox_core::HttpMethodMatcher::All => Self::All,
            agent_sandbox_core::HttpMethodMatcher::Exact(method) => {
                Self::Some(BTreeSet::from([method.as_str().to_owned()]))
            }
            agent_sandbox_core::HttpMethodMatcher::AnyOf(methods) => Self::Some(
                methods
                    .iter()
                    .map(|method| method.as_str().to_owned())
                    .collect(),
            ),
        }
    }

    fn from_rule(rule: &HttpRule) -> Self {
        if rule.methods.is_empty() {
            Self::All
        } else {
            Self::Some(rule.methods.iter().cloned().collect())
        }
    }

    fn union_with(&mut self, other: &Self) {
        if matches!(self, Self::All) || matches!(other, Self::All) {
            *self = Self::All;
        } else if let (Self::Some(current), Self::Some(other)) = (self, other) {
            current.extend(other.iter().cloned());
        }
    }

    fn subtract(&self, selected: &Self) -> Option<Self> {
        match (self, selected) {
            (Self::All, Self::Some(_)) => Some(Self::All),
            (Self::All | Self::Some(_), Self::All) => None,
            (Self::Some(current), Self::Some(selected)) => {
                let remaining = current
                    .iter()
                    .filter(|method| !selected.contains(*method))
                    .cloned()
                    .collect::<BTreeSet<String>>();
                (!remaining.is_empty()).then_some(Self::Some(remaining))
            }
        }
    }

    fn into_methods(self) -> Vec<String> {
        match self {
            Self::All => Vec::new(),
            Self::Some(methods) => methods.into_iter().collect(),
        }
    }
}

fn same_http_url(rule: &HttpRule, target: &HttpRuleTarget) -> bool {
    rule.target().is_ok_and(|value| value.url == target.url)
}

fn subtract_http_methods(
    rules: &mut Vec<HttpRule>,
    target: &HttpRuleTarget,
    selected: &HttpMethods,
) {
    let mut retained = Vec::with_capacity(rules.len());
    for mut rule in rules.drain(..) {
        if !same_http_url(&rule, target) {
            retained.push(rule);
            continue;
        }
        let Some(methods) = HttpMethods::from_rule(&rule).subtract(selected) else {
            continue;
        };
        rule.methods = methods.into_methods();
        retained.push(rule);
    }
    *rules = retained;
}

fn union_http_methods(
    rules: &mut Vec<HttpRule>,
    target: &HttpRuleTarget,
    selected: &HttpMethods,
    label: &str,
) {
    let mut merged = selected.clone();
    let mut insert_index = None;
    let mut retained = Vec::with_capacity(rules.len() + 1);
    for rule in rules.drain(..) {
        if same_http_url(&rule, target) {
            merged.union_with(&HttpMethods::from_rule(&rule));
            insert_index.get_or_insert(retained.len());
        } else {
            retained.push(rule);
        }
    }
    let rule = HttpRule::new(merged.into_methods(), target.url.to_string(), label);
    if let Some(index) = insert_index {
        retained.insert(index, rule);
    } else {
        retained.push(rule);
    }
    *rules = retained;
}

impl PolicyStore {
    pub(crate) fn persist_http_rule(
        path: &Path,
        target: &HttpRuleTarget,
        label: &str,
        allow_rule: bool,
        home: Option<&Path>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path, home, None);
        let selected = HttpMethods::from_target(target);
        if allow_rule {
            subtract_http_methods(&mut current.network.http.deny, target, &selected);
            union_http_methods(&mut current.network.http.allow, target, &selected, label);
        } else {
            subtract_http_methods(&mut current.network.http.allow, target, &selected);
            union_http_methods(&mut current.network.http.deny, target, &selected, label);
        }
        atomic_write_policy(path, &current, home, owner_uid, None)
    }

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
            .direct
            .allow
            .iter()
            .map(|r| (network_rule_sort_key(r), r.clone()))
            .collect();
        let mut deny: BTreeMap<NetworkSortKey, NetworkRule> = current
            .network
            .direct
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

        current.network.direct.allow = allow.into_values().collect();
        current.network.direct.deny = deny.into_values().collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use agent_sandbox_core::{
        HttpMethod, HttpMethodMatcher, HttpRuleTarget, HttpUrl, Policy, ResourceAccess,
        ResourceKind, SocketAccess, atomic_write_policy,
    };

    fn target(method: &str) -> HttpRuleTarget {
        HttpRuleTarget::new(
            HttpMethodMatcher::Exact(HttpMethod::parse(method).expect("valid method")),
            HttpUrl::parse("https://example.com/api").expect("valid URL"),
        )
        .expect("valid target")
    }

    #[test]
    fn persist_http_rules_unions_methods_and_subtracts_denies() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("policy.json");
        atomic_write_policy(&path, &Policy::default(), None, None, None).expect("write policy");

        PolicyStore::persist_http_rule(&path, &target("GET"), "get", true, None, None)
            .expect("persist GET allow");
        PolicyStore::persist_http_rule(&path, &target("POST"), "post", true, None, None)
            .expect("persist POST allow");

        let policy = load_policy(&path, None, None);
        assert_eq!(policy.network.http.allow.len(), 1);
        assert_eq!(
            policy.network.http.allow[0].methods,
            vec!["GET".to_owned(), "POST".to_owned()]
        );

        PolicyStore::persist_http_rule(&path, &target("POST"), "deny post", false, None, None)
            .expect("persist POST deny");
        let policy = load_policy(&path, None, None);
        assert_eq!(policy.network.http.allow.len(), 1);
        assert_eq!(policy.network.http.allow[0].methods, vec!["GET".to_owned()]);
        assert_eq!(policy.network.http.deny.len(), 1);
        assert_eq!(policy.network.http.deny[0].methods, vec!["POST".to_owned()]);
    }
    #[test]
    fn persist_resource_rules_merges_connect_and_send_into_all() {
        let mut rules = Vec::new();
        let path = Path::new("/tmp/example.sock");

        upsert_resource_rule(
            &mut rules,
            ResourceKind::UnixSocket,
            path,
            ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Connect),
            "connect",
        );
        upsert_resource_rule(
            &mut rules,
            ResourceKind::UnixSocket,
            path,
            ResourceAccess::Socket(agent_sandbox_core::SocketAccess::Send),
            "send",
        );

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].access, ResourceAccess::Socket(SocketAccess::All));
    }
}
