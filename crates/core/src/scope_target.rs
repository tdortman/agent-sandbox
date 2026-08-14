//! Resolved approval scope: typestate after validating RPC context.
//!
//! Wire format uses [`ApprovalScope`] directly on requests. Call
//! [`ScopeTarget::resolve`] so session/global/project requirements are enforced
//! once, in one place.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use crate::{
    error::ScopeResolveError, merge_policy::trusted_project_policy_path, rpc::ApprovalScope,
};

/// Where an approved/denied rule is stored after scope + context validation.
#[derive(Debug, Clone)]
pub enum ScopeTarget {
    /// `once`: in-memory only for this policyd process.
    Ephemeral,

    Session {
        session_id: String,
    },

    Project {
        policy_path: PathBuf,
        project_root: PathBuf,
    },

    ProjectPackage {
        policy_path: PathBuf,
        project_root: PathBuf,
        package: String,
    },

    Global {
        policy_path: PathBuf,
        home: PathBuf,
    },

    GlobalPackage {
        policy_path: PathBuf,
        home: PathBuf,
        package: String,
    },
}

/// Inputs required to turn a wire-level scope into a [`ScopeTarget`].
pub struct ScopeContext<'a> {
    pub scope: ApprovalScope,
    pub session_id: Option<&'a str>,
    pub home: Option<&'a str>,
    pub project_root: Option<&'a str>,
    pub package: Option<&'a str>,
    pub active_session_ids: &'a HashSet<String>,
}

impl ScopeTarget {
    /// Validate a wire-level scope against the provided context and produce a
    /// [`ScopeTarget`].
    ///
    /// # Errors
    /// Returns [`ScopeResolveError::SessionRequired`] if the session scope is
    /// used but no valid session is provided,
    /// [`ScopeResolveError::ProjectRootRequired`] if the project scope is
    /// used without a project root, [`ScopeResolveError::HomeRequired`] if
    /// the global scope is used without a home directory,
    /// [`ScopeResolveError::PackageRequired`] if a package scope is used
    /// without an attributed package, or
    /// [`ScopeResolveError::ProjectPolicy`] if the project policy path
    /// cannot be resolved.
    pub fn resolve(ctx: &ScopeContext<'_>) -> Result<Self, ScopeResolveError> {
        match ctx.scope {
            ApprovalScope::Once => Ok(Self::Ephemeral),

            ApprovalScope::Session => {
                let session_id = ctx.session_id.ok_or(ScopeResolveError::SessionRequired)?;
                if !ctx.active_session_ids.contains(session_id) {
                    return Err(ScopeResolveError::SessionRequired);
                }
                Ok(Self::Session {
                    session_id: session_id.to_string(),
                })
            }

            ApprovalScope::Project => {
                let project_root = ctx
                    .project_root
                    .ok_or(ScopeResolveError::ProjectRootRequired)?;
                let policy_path = trusted_project_policy_path(Path::new(project_root))?;
                Ok(Self::Project {
                    policy_path,
                    project_root: PathBuf::from(project_root),
                })
            }

            ApprovalScope::ProjectPackage => {
                let project_root = ctx
                    .project_root
                    .ok_or(ScopeResolveError::ProjectRootRequired)?;
                let package = ctx.package.ok_or(ScopeResolveError::PackageRequired)?;
                let policy_path = project_package_policy_path(Path::new(project_root), package);
                Ok(Self::ProjectPackage {
                    policy_path,
                    project_root: PathBuf::from(project_root),
                    package: package.to_string(),
                })
            }

            ApprovalScope::Global => {
                let home = ctx.home.ok_or(ScopeResolveError::HomeRequired)?;
                let policy_path = global_policy_path(Path::new(home));
                Ok(Self::Global {
                    policy_path,
                    home: PathBuf::from(home),
                })
            }

            ApprovalScope::GlobalPackage => {
                let home = ctx.home.ok_or(ScopeResolveError::HomeRequired)?;
                let package = ctx.package.ok_or(ScopeResolveError::PackageRequired)?;
                let policy_path = global_package_policy_path(Path::new(home), package);
                Ok(Self::GlobalPackage {
                    policy_path,
                    home: PathBuf::from(home),
                    package: package.to_string(),
                })
            }
        }
    }

    #[must_use]
    pub fn project_root(&self) -> Option<&Path> {
        match self {
            Self::Project { project_root, .. } => Some(project_root.as_path()),
            _ => None,
        }
    }
}

fn global_policy_path(home: &Path) -> PathBuf {
    let canonical_home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    canonical_home.join(".config/agent-sandbox/policy.json")
}

fn global_package_policy_path(home: &Path, package: &str) -> PathBuf {
    let canonical_home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());

    canonical_home
        .join(".config")
        .join("agent-sandbox")
        .join("packages")
        .join(format!("{package}.json"))
}

fn project_package_policy_path(project_root: &Path, package: &str) -> PathBuf {
    project_root
        .join(".agent-sandbox")
        .join("packages")
        .join(format!("{package}.json"))
}
