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
}

pub fn sudo_argv_matches(rule: &SudoRule, argv: &[String]) -> bool {
    if rule.argv.is_empty() {
        return false;
    }
    if rule.argv.len() > argv.len() {
        return false;
    }
    if rule.argv.len() == argv.len() {
        return rule.argv == argv;
    }
    argv.starts_with(&rule.argv)
}
