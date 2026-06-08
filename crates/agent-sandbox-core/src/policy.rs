//! On-disk policy document (`network` / `sudo` allow and deny rules).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub sudo: SudoSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSection {
    #[serde(default)]
    pub allow: Vec<NetworkRule>,
    #[serde(default)]
    pub deny: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoSection {
    #[serde(default)]
    pub allow: Vec<SudoRule>,
    #[serde(default)]
    pub deny: Vec<SudoRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRule {
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoRule {
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl NetworkRule {
    pub fn new(host: impl Into<String>, port: u16, comment: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            comment: Some(comment.into()),
        }
    }

    pub fn key(&self) -> (String, u16) {
        (self.host.to_lowercase(), self.port)
    }
}

impl SudoRule {
    pub fn new(argv: Vec<String>, comment: impl Into<String>) -> Self {
        Self {
            argv,
            comment: Some(comment.into()),
        }
    }

    pub fn key(&self) -> Option<Vec<String>> {
        if self.argv.is_empty() {
            None
        } else {
            Some(self.argv.clone())
        }
    }

    pub fn matches(&self, argv: &[String]) -> bool {
        !self.argv.is_empty() && argv.starts_with(&self.argv)
    }

    pub fn approval_prefixes(argv: &[String]) -> Vec<Vec<String>> {
        let mut prefixes = Vec::with_capacity(argv.len());
        for len in (1..=argv.len()).rev() {
            prefixes.push(argv[..len].to_vec());
        }
        prefixes
    }
}

#[cfg(test)]
mod tests {
    use super::SudoRule;

    #[test]
    fn sudo_rule_matches_prefix() {
        let rule = SudoRule::new(vec!["systemctl".into(), "restart".into()], "");
        let argv = ["systemctl".into(), "restart".into(), "nginx".into()];
        let wrong_argv = ["systemctl".into(), "stop".into()];
        assert!(rule.matches(&argv));
        assert!(!rule.matches(&wrong_argv));
    }

    #[test]
    fn sudo_rule_approval_prefixes_descend_from_most_specific() {
        let argv = vec!["systemctl".into(), "restart".into(), "nginx".into()];
        assert_eq!(
            SudoRule::approval_prefixes(&argv),
            vec![
                vec![
                    "systemctl".to_string(),
                    "restart".to_string(),
                    "nginx".to_string()
                ],
                vec!["systemctl".to_string(), "restart".to_string()],
                vec!["systemctl".to_string()],
            ]
        );
    }
}
