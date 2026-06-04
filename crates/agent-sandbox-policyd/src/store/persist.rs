//! Policy store — persist.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use agent_sandbox_core::{
    ApprovalScope, NetworkRule, SudoRule, atomic_write_policy, load_policy, normalize_host,
    resolve_project_policy_path,
};

use super::types::PolicyStore;

impl PolicyStore {
    pub(crate) fn persist_network_allow(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path);
        let host_norm = normalize_host(host);
        let key = (host_norm.to_lowercase(), port);
        let mut allow: HashMap<(String, u16), NetworkRule> = current
            .network
            .allow
            .iter()
            .map(|r| (r.key(), r.clone()))
            .collect();
        allow.insert(key.clone(), NetworkRule::new(host_norm, port, label));
        let mut deny: HashMap<(String, u16), NetworkRule> = current
            .network
            .deny
            .iter()
            .map(|r| (r.key(), r.clone()))
            .collect();
        deny.remove(&key);
        current.network.allow = allow.into_values().collect();
        current.network.deny = deny.into_values().collect();
        atomic_write_policy(path, &current, home, owner_uid)
    }

    pub(crate) fn persist_network_deny(
        path: &Path,
        host: &str,
        port: u16,
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path);
        let host_norm = normalize_host(host);
        let key = (host_norm.to_lowercase(), port);
        let mut deny: HashMap<(String, u16), NetworkRule> = current
            .network
            .deny
            .iter()
            .map(|r| (r.key(), r.clone()))
            .collect();
        deny.insert(key.clone(), NetworkRule::new(host_norm, port, label));
        let mut allow: HashMap<(String, u16), NetworkRule> = current
            .network
            .allow
            .iter()
            .map(|r| (r.key(), r.clone()))
            .collect();
        allow.remove(&key);
        current.network.deny = deny.into_values().collect();
        current.network.allow = allow.into_values().collect();
        atomic_write_policy(path, &current, home, owner_uid)
    }

    pub(crate) fn persist_sudo_allow(
        path: &Path,
        argv: &[String],
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path);
        let key: Vec<String> = argv.to_vec();
        let mut allow: HashMap<Vec<String>, SudoRule> = current
            .sudo
            .allow
            .iter()
            .filter_map(|r| r.key().map(|k| (k, r.clone())))
            .collect();
        allow.insert(key.clone(), SudoRule::new(argv.to_vec(), label));
        let mut deny: HashMap<Vec<String>, SudoRule> = current
            .sudo
            .deny
            .iter()
            .filter_map(|r| r.key().map(|k| (k, r.clone())))
            .collect();
        deny.remove(&key);
        current.sudo.allow = allow.into_values().collect();
        current.sudo.deny = deny.into_values().collect();
        atomic_write_policy(path, &current, home, owner_uid)
    }

    pub(crate) fn persist_sudo_deny(
        path: &Path,
        argv: &[String],
        label: &str,
        home: Option<&str>,
        owner_uid: Option<u32>,
    ) -> std::io::Result<()> {
        let mut current = load_policy(path);
        let key: Vec<String> = argv.to_vec();
        let mut deny: HashMap<Vec<String>, SudoRule> = current
            .sudo
            .deny
            .iter()
            .filter_map(|r| r.key().map(|k| (k, r.clone())))
            .collect();
        deny.insert(key.clone(), SudoRule::new(argv.to_vec(), label));
        let mut allow: HashMap<Vec<String>, SudoRule> = current
            .sudo
            .allow
            .iter()
            .filter_map(|r| r.key().map(|k| (k, r.clone())))
            .collect();
        allow.remove(&key);
        current.sudo.deny = deny.into_values().collect();
        current.sudo.allow = allow.into_values().collect();
        atomic_write_policy(path, &current, home, owner_uid)
    }

    pub(crate) fn project_policy_path_display(project_root: &str) -> Option<String> {
        resolve_project_policy_path(None, Some(Path::new(project_root)))
            .ok()
            .map(|p| p.display().to_string())
    }

    pub(crate) fn parse_scope(
        scope: &str,
    ) -> Result<ApprovalScope, agent_sandbox_core::InvalidScopeError> {
        ApprovalScope::parse(scope)
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
