//! Approval scope for network and sudo rules.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::InvalidScopeError;

/// Approval scope for network and sudo rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Require approval once for this invocation.
    Once,

    /// Require approval for the duration of the current session.
    Session,

    /// Require approval for the current project's package.
    ProjectPackage,

    /// Require approval for the current project.
    Project,

    /// Require approval for any package of the current platform user.
    GlobalPackage,

    /// Require approval globally for the current platform user.
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
    /// Every scope, most specific first.
    pub const LADDER: [Self; 6] = [
        Self::Once,
        Self::Session,
        Self::ProjectPackage,
        Self::Project,
        Self::GlobalPackage,
        Self::Global,
    ];

    /// Returns the `snake_case` wire label for this scope.
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

    /// Whether the scope is only valid for a registered sandbox session.
    #[must_use]
    pub const fn needs_session(self) -> bool {
        matches!(self, Self::Session)
    }

    /// Whether the scope is only valid for an attributed package.
    #[must_use]
    pub const fn needs_package(self) -> bool {
        matches!(self, Self::ProjectPackage | Self::GlobalPackage)
    }

    /// Whether the scope is stored in a policy file rather than held in memory.
    #[must_use]
    pub const fn is_persistent(self) -> bool {
        !matches!(self, Self::Once | Self::Session)
    }

    /// Whether the scope can be chosen given session and package availability.
    #[must_use]
    pub const fn is_available(self, session_available: bool, package_available: bool) -> bool {
        (session_available || !self.needs_session()) && (package_available || !self.needs_package())
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
    fn ladder_round_trips_wire_labels_and_states_each_rung_facts() {
        struct Rung {
            label: &'static str,
            needs_session: bool,
            needs_package: bool,
            persistent: bool,
        }

        let rung = |label, needs_session, needs_package, persistent| Rung {
            label,
            needs_session,
            needs_package,
            persistent,
        };

        let expected = [
            rung("once", false, false, false),
            rung("session", true, false, false),
            rung("project_package", false, true, true),
            rung("project", false, false, true),
            rung("global_package", false, true, true),
            rung("global", false, false, true),
        ];

        assert_eq!(ApprovalScope::LADDER.len(), expected.len());

        for (scope, rung) in ApprovalScope::LADDER.into_iter().zip(&expected) {
            assert_eq!(scope.as_str(), rung.label);
            assert_eq!(rung.label.parse(), Ok(scope));
            assert_eq!(scope.needs_session(), rung.needs_session);
            assert_eq!(scope.needs_package(), rung.needs_package);
            assert_eq!(scope.is_persistent(), rung.persistent);
        }

        assert!("nonsense".parse::<ApprovalScope>().is_err());
    }
}
