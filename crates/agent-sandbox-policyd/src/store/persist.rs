//! Policy store persistence.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use agent_sandbox_core::{
    FileAccess, FilesystemRule, FilesystemSortKey, NetworkRule, NetworkSortKey,
    ProjectPolicyContext, SudoRule, atomic_write_policy, contract_home_path, load_policy,
    normalize_host,
};

use super::types::PolicyStore;

fn network_rule_sort_key(rule: &NetworkRule) -> NetworkSortKey {
    NetworkSortKey::new(&rule.host, rule.port)
}

fn network_sort_key(host: &str, port: u16) -> NetworkSortKey {
    NetworkSortKey::new(host, port)
}

fn filesystem_path_key(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() && path.starts_with('/') {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn upsert_filesystem_rule(
    rules: &mut Vec<FilesystemRule>,
    rule_path: &str,
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

fn remove_filesystem_rule(rules: &mut Vec<FilesystemRule>, rule_path: &str, access: FileAccess) {
    let key = filesystem_path_key(rule_path);
    rules.retain(|rule| filesystem_path_key(&rule.path) != key || rule.access != access);
}

fn filesystem_rule_sort_key(rule: &FilesystemRule, home: Option<&str>) -> FilesystemSortKey {
    FilesystemSortKey::new(
        contract_home_path(&filesystem_path_key(&rule.path), home),
        rule.access,
    )
}

fn sort_filesystem_rules(rules: &mut [FilesystemRule], home: Option<&str>) {
    rules.sort_by_key(|rule| filesystem_rule_sort_key(rule, home));
}

impl PolicyStore {
    fn persist_network_rule(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        allow_rule: bool,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path, home);
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
        atomic_write_policy(path, &current, home, owner_uid)
    }

    pub(crate) fn persist_network_allow(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_network_rule(path, host, port, label, true, home, owner_uid)
    }

    pub(crate) fn persist_network_deny(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_network_rule(path, host, port, label, false, home, owner_uid)
    }

    fn persist_sudo_rule(
        path: &Path,
        argv: &[String],
        label: &str,
        allow_rule: bool,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path, home);
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
        atomic_write_policy(path, &current, home, owner_uid)
    }

    pub(crate) fn persist_sudo_allow(
        path: &Path,
        argv: &[String],
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_sudo_rule(path, argv, label, true, home, owner_uid)
    }

    pub(crate) fn persist_sudo_deny(
        path: &Path,
        argv: &[String],
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        Self::persist_sudo_rule(path, argv, label, false, home, owner_uid)
    }

    pub(crate) fn persist_filesystem_rule(
        path: &Path,
        rule_path: &str,
        access: FileAccess,
        label: &str,
        allow_rule: bool,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut policy = load_policy(path, home);
        if allow_rule {
            upsert_filesystem_rule(&mut policy.filesystem.allow, rule_path, access, label);
            remove_filesystem_rule(&mut policy.filesystem.deny, rule_path, access);
        } else {
            upsert_filesystem_rule(&mut policy.filesystem.deny, rule_path, access, label);
            remove_filesystem_rule(&mut policy.filesystem.allow, rule_path, access);
        }
        sort_filesystem_rules(&mut policy.filesystem.allow, home);
        sort_filesystem_rules(&mut policy.filesystem.deny, home);
        atomic_write_policy(path, &policy, home, owner_uid)
    }

    pub(crate) fn project_policy_path_display(project_root: &str) -> Option<String> {
        ProjectPolicyContext::new(None, None, Some(Path::new(project_root)))
            .resolve_policy_path()
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
    use super::PolicyStore;
    use agent_sandbox_core::{FileAccess, load_policy};

    #[test]
    fn persisted_network_rules_are_sorted_by_domain_hierarchy() {
        let dir =
            std::env::temp_dir().join(format!("agent-sandbox-policy-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.json");

        PolicyStore::persist_network_allow(
            &policy_path,
            "www.twitch.tv",
            443,
            "project",
            None,
            None,
        )
        .unwrap();
        PolicyStore::persist_network_allow(&policy_path, "example.com", 443, "project", None, None)
            .unwrap();
        PolicyStore::persist_network_allow(
            &policy_path,
            "foo.bar.bazz",
            443,
            "project",
            None,
            None,
        )
        .unwrap();
        PolicyStore::persist_network_allow(
            &policy_path,
            "help.twitch.tv",
            443,
            "project",
            None,
            None,
        )
        .unwrap();
        PolicyStore::persist_network_allow(
            &policy_path,
            "api.twitch.tv",
            443,
            "project",
            None,
            None,
        )
        .unwrap();

        let policy = load_policy(&policy_path, None);
        let hosts: Vec<&str> = policy
            .network
            .allow
            .iter()
            .map(|rule| rule.host.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec![
                "foo.bar.bazz",
                "example.com",
                "api.twitch.tv",
                "help.twitch.tv",
                "www.twitch.tv"
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persisted_sudo_rules_are_sorted_by_command_hierarchy() {
        let dir =
            std::env::temp_dir().join(format!("agent-sandbox-sudo-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.json");

        PolicyStore::persist_sudo_allow(
            &policy_path,
            &["systemctl".into(), "restart".into(), "nginx".into()],
            "project",
            None,
            None,
        )
        .unwrap();
        PolicyStore::persist_sudo_allow(
            &policy_path,
            &["cargo".into(), "test".into()],
            "project",
            None,
            None,
        )
        .unwrap();
        PolicyStore::persist_sudo_allow(
            &policy_path,
            &["systemctl".into(), "reload".into(), "nginx".into()],
            "project",
            None,
            None,
        )
        .unwrap();

        let policy = load_policy(&policy_path, None);
        let argv: Vec<&[String]> = policy
            .sudo
            .allow
            .iter()
            .map(|rule| rule.argv.as_slice())
            .collect();
        assert_eq!(
            argv,
            vec![
                &["cargo".to_string(), "test".to_string()][..],
                &[
                    "systemctl".to_string(),
                    "reload".to_string(),
                    "nginx".to_string()
                ][..],
                &[
                    "systemctl".to_string(),
                    "restart".to_string(),
                    "nginx".to_string()
                ][..]
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn filesystem_allow_upgrades_existing_path_access_in_place() {
        let dir =
            std::env::temp_dir().join(format!("agent-sandbox-fs-upgrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.json");

        PolicyStore::persist_filesystem_rule(
            &policy_path,
            "/home/user/.gtkrc-2.0",
            FileAccess::Read,
            "project",
            true,
            Some("/home/user"),
            None,
        )
        .unwrap();
        PolicyStore::persist_filesystem_rule(
            &policy_path,
            "/home/user/.gtkrc-2.0",
            FileAccess::Write,
            "project",
            true,
            Some("/home/user"),
            None,
        )
        .unwrap();

        let policy = load_policy(&policy_path, Some("/home/user"));
        assert_eq!(policy.filesystem.allow.len(), 1);
        assert_eq!(policy.filesystem.allow[0].path, "/home/user/.gtkrc-2.0");
        assert_eq!(policy.filesystem.allow[0].access, FileAccess::ReadWrite);
        let raw = std::fs::read_to_string(&policy_path).unwrap();
        assert_eq!(raw.matches("\"path\"").count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn filesystem_allow_upgrades_read_write_and_execute_to_all() {
        let dir = std::env::temp_dir().join(format!("agent-sandbox-fs-all-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.json");

        PolicyStore::persist_filesystem_rule(
            &policy_path,
            "/home/user/bin/tool",
            FileAccess::ReadWrite,
            "project",
            true,
            Some("/home/user"),
            None,
        )
        .unwrap();
        PolicyStore::persist_filesystem_rule(
            &policy_path,
            "/home/user/bin/tool",
            FileAccess::Execute,
            "project",
            true,
            Some("/home/user"),
            None,
        )
        .unwrap();

        let policy = load_policy(&policy_path, Some("/home/user"));
        assert_eq!(policy.filesystem.allow.len(), 1);
        assert_eq!(policy.filesystem.allow[0].access, FileAccess::All);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn filesystem_deny_upgrades_existing_path_access_in_place() {
        let dir =
            std::env::temp_dir().join(format!("agent-sandbox-fs-deny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.json");

        PolicyStore::persist_filesystem_rule(
            &policy_path,
            "/home/user/secrets.txt",
            FileAccess::Read,
            "project",
            false,
            Some("/home/user"),
            None,
        )
        .unwrap();
        PolicyStore::persist_filesystem_rule(
            &policy_path,
            "/home/user/secrets.txt",
            FileAccess::Write,
            "project",
            false,
            Some("/home/user"),
            None,
        )
        .unwrap();

        let policy = load_policy(&policy_path, Some("/home/user"));
        assert_eq!(policy.filesystem.deny.len(), 1);
        assert_eq!(policy.filesystem.deny[0].path, "/home/user/secrets.txt");
        assert_eq!(policy.filesystem.deny[0].access, FileAccess::ReadWrite);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persisted_filesystem_rules_are_sorted_by_home_relative_path() {
        let dir =
            std::env::temp_dir().join(format!("agent-sandbox-fs-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.json");

        for path in [
            "/home/user/dotfiles/home/dot_omp/private_agent/config.yml",
            "/home/user/.codex/config.toml",
            "/home/user/dotfiles/home/dot_config/opencode/opencode.json",
            "/home/user/dotfiles/.gitignore",
            "/home/user/.cache/bun",
        ] {
            PolicyStore::persist_filesystem_rule(
                &policy_path,
                path,
                FileAccess::Read,
                "global",
                true,
                Some("/home/user"),
                None,
            )
            .unwrap();
        }

        let policy = load_policy(&policy_path, Some("/home/user"));
        let paths: Vec<&str> = policy
            .filesystem
            .allow
            .iter()
            .map(|rule| rule.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                "/home/user/.cache/bun",
                "/home/user/.codex/config.toml",
                "/home/user/dotfiles/.gitignore",
                "/home/user/dotfiles/home/dot_config/opencode/opencode.json",
                "/home/user/dotfiles/home/dot_omp/private_agent/config.yml",
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
