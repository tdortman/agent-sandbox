//! Shared error types for policy paths and I/O.

use std::path::PathBuf;

use thiserror::Error;

/// Errors produced while resolving or validating a project's trusted policy
/// path.
#[derive(Debug, Error)]
pub enum ProjectPolicyError {
    /// `project_root` is not the root of a trusted project.
    #[error("invalid project_root ({path:?}); set AGENT_SANDBOX_PROJECT_ROOT to the git root")]
    InvalidProjectRoot {
        /// The offending project root path.
        path: PathBuf,
    },

    /// Underlying filesystem error while accessing the policy path.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// The requested approval scope string does not match a known scope variant.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid approval scope: {scope}")]
pub struct InvalidScopeError {
    /// The invalid scope string as received.
    pub scope: String,
}

impl InvalidScopeError {
    /// Build an error from the offending scope string.
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
        }
    }
}

/// Failed to resolve `scope` + RPC context into a concrete persistence target.
#[derive(Debug, Error)]
pub enum ScopeResolveError {
    /// The scope string is not a recognised approval scope.
    #[error(transparent)]
    InvalidScope(#[from] InvalidScopeError),

    /// A session scope was used without a currently active session id.
    #[error("session_id required")]
    SessionRequired,

    /// A global scope was used without a home directory.
    #[error("home required for global scope")]
    HomeRequired,

    /// A project scope was used without a project root.
    #[error("project_root required (set AGENT_SANDBOX_PROJECT_ROOT)")]
    ProjectRootRequired,

    /// A package scope was used without an attributed package name.
    #[error("package required for global_package scope")]
    PackageRequired,

    /// The project policy path could not be resolved.
    #[error(transparent)]
    ProjectPolicy(#[from] ProjectPolicyError),
}
