//! Approval scope for network and sudo rules.

use crate::error::InvalidScopeError;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Approval scope for network and sudo rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Once,
    Session,
    ProjectPackage,
    Project,
    GlobalPackage,
    Global,
}

impl std::str::FromStr for ApprovalScope {
    type Err = InvalidScopeError;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        match scope {
            "once" => Ok(Self::Once),
            "session" => Ok(Self::Session),
            "project_package" => Ok(Self::ProjectPackage),
            "project" => Ok(Self::Project),
            "global_package" => Ok(Self::GlobalPackage),
            "global" => Ok(Self::Global),
            other => Err(InvalidScopeError::new(other)),
        }
    }
}

impl fmt::Display for ApprovalScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ApprovalScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::ProjectPackage => "project_package",
            Self::Project => "project",
            Self::GlobalPackage => "global_package",
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
        assert_eq!(ApprovalScope::ProjectPackage.to_string(), "project_package");
        assert_eq!(ApprovalScope::GlobalPackage.to_string(), "global_package");
    }

    #[test]
    fn parses_every_wire_label() {
        for scope in [
            ApprovalScope::Once,
            ApprovalScope::Session,
            ApprovalScope::ProjectPackage,
            ApprovalScope::Project,
            ApprovalScope::GlobalPackage,
            ApprovalScope::Global,
        ] {
            assert_eq!(scope.to_string().parse(), Ok(scope));
        }

        assert!("nonsense".parse::<ApprovalScope>().is_err());
    }
}
