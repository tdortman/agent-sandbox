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

    /// `session`: persisted per-session in the session-scoped policy store.
    ///
    /// Validated against the active session id in the request context.
    Session {
        /// The session to scope the target against.
        session_id: String,
    },

    /// `project`: persisted in the project's trusted policy file.
    ///
    /// Stores the resolved policy file path and the project root it belongs to.
    Project {
        /// Resolved policy file path.
        policy_path: PathBuf,
        /// Project root the policy file belongs to.
        project_root: PathBuf,
    },

    /// `project_package`: persisted in a package-scoped project policy file.
    ///
    /// Stores the policy file path, project root, and attributed package name.
    ProjectPackage {
        /// Resolved policy file path.
        policy_path: PathBuf,
        /// Project root the policy file belongs to.
        project_root: PathBuf,
        /// Attributed package name.
        package: String,
    },

    /// `global`: persisted in the user's global policy file under
    /// `~/.config/agent-sandbox/policy.json`.
    ///
    /// Requires a known home directory.
    Global {
        /// Resolved policy file path.
        policy_path: PathBuf,
        /// Home directory the policy file lives under.
        home: PathBuf,
    },

    /// `global_package`: persisted in a package-scoped global policy file,
    /// e.g. `~/.config/agent-sandbox/packages/<package>.json`.
    ///
    /// Requires a known home directory and attributed package name.
    GlobalPackage {
        /// Resolved policy file path.
        policy_path: PathBuf,
        /// Home directory the policy file lives under.
        home: PathBuf,
        /// Attributed package name.
        package: String,
    },
}

/// Inputs required to turn a wire-level scope into a [`ScopeTarget`].
pub struct ScopeContext<'a> {
    /// The wire-level scope being resolved.
    pub scope: ApprovalScope,
    /// Requested session id, required for session scope.
    pub session_id: Option<&'a str>,
    /// Home directory, required for global scopes.
    pub home: Option<&'a str>,
    /// Project root, required for project scopes.
    pub project_root: Option<&'a str>,
    /// Attributed package name, required for package scopes.
    pub package: Option<&'a str>,
    /// Currently active session ids against which a session scope is validated.
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

    /// Project root for a [`ScopeTarget::Project`]; `None` for all other
    /// variants.
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
