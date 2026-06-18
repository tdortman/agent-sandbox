//! Policy store persistence.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use agent_sandbox_core::{
    NetworkRule, ProjectPolicyContext, SudoRule, atomic_write_policy, load_policy, normalize_host,
};

use super::types::PolicyStore;

fn network_rule_sort_key(rule: &NetworkRule) -> (Vec<String>, u16) {
    network_sort_key(&rule.host, rule.port)
}

fn network_sort_key(host: &str, port: u16) -> (Vec<String>, u16) {
    let mut labels: Vec<String> = host.split('.').map(str::to_lowercase).collect();
    labels.reverse();
    (labels, port)
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
        let mut current = load_policy(path);
        let host_norm = normalize_host(host);
        let key = network_sort_key(&host_norm, port);
        let mut allow: BTreeMap<(Vec<String>, u16), NetworkRule> = current
            .network
            .allow
            .iter()
            .map(|r| (network_rule_sort_key(r), r.clone()))
            .collect();
        let mut deny: BTreeMap<(Vec<String>, u16), NetworkRule> = current
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
        let mut current = load_policy(path);
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
    use agent_sandbox_core::load_policy;

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

        let policy = load_policy(&policy_path);
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

        let policy = load_policy(&policy_path);
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
}
