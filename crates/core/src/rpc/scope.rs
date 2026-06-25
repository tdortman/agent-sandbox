//! Approval scope for network and sudo rules.

use std::fmt;

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

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        match scope {
            "once" => Ok(Self::Once),
            "session" => Ok(Self::Session),
            "project" => Ok(Self::Project),
            "global" => Ok(Self::Global),
            other => Err(crate::error::InvalidScopeError::new(other)),
        }
    }
}

impl fmt::Display for ApprovalScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
}

#[cfg(test)]
mod tests {
    use super::ApprovalScope;

    #[test]
    fn display_uses_wire_label() {
        assert_eq!(ApprovalScope::Project.to_string(), "project");
    }
}
