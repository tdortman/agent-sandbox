//! Shared error types for policy paths and I/O.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProjectPolicyError {
    #[error("invalid project_root ({path:?}); set AGENT_SANDBOX_PROJECT_ROOT to the git root")]
    InvalidProjectRoot { path: PathBuf },
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
#[error("invalid approval scope: {scope}")]
pub struct InvalidScopeError {
    pub scope: String,
}

impl InvalidScopeError {
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
        }
    }
}

/// Failed to resolve `scope` + RPC context into a concrete persistence target.
#[derive(Debug, Error)]
pub enum ScopeResolveError {
    #[error(transparent)]
    InvalidScope(#[from] InvalidScopeError),
    #[error("session_id required")]
    SessionRequired,
    #[error("home required for global scope")]
    HomeRequired,
    #[error("project_root required (set AGENT_SANDBOX_PROJECT_ROOT)")]
    ProjectRootRequired,
    #[error(transparent)]
    ProjectPolicy(#[from] ProjectPolicyError),
}
