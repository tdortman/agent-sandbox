//! Approval scope for network and sudo rules.

use serde::{Deserialize, Serialize};

/// Approval scope for network and sudo rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Once,
    Session,
    Project,
    Global,
}

impl std::str::FromStr for ApprovalScope {
    type Err = crate::error::InvalidScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl ApprovalScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Project => "project",
            Self::Global => "global",
        }
    }

    pub fn parse(scope: &str) -> Result<Self, crate::error::InvalidScopeError> {
        match scope {
            "once" => Ok(Self::Once),
            "session" => Ok(Self::Session),
            "project" => Ok(Self::Project),
            "global" => Ok(Self::Global),
            other => Err(crate::error::InvalidScopeError::new(other)),
        }
    }
}
