//! Policy store: the shared scope ladder lifecycle.
//!
//! Every capability scope decision runs the same ladder: resolve the
//! [`ScopeTarget`] from the [`ApprovalScope`], apply the in-memory session
//! arms under the state lock, then run the four persistent arms through the
//! capability's rule writer. Merged-policy cache invalidation follows the
//! ladder's flags after each persistent write, and project-scope writes emit
//! the ladder's log lines.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths, ScopeContext, ScopeTarget};

use super::types::{PolicyDecisionState, PolicyStore};
use crate::error::PolicydError;

/// Whether a persistent scope write invalidates the merged-policy cache.
///
/// `global` covers the `Global` and `Project` arms; `package` covers the
/// `GlobalPackage` and `ProjectPackage` arms. Values preserve the per
/// capability behaviour of the former copy-pasted `match` blocks.
#[derive(Clone, Copy)]
pub struct ScopePersistFlags {
    /// `invalidate` for `Global` and `Project`.
    pub global: bool,
    /// `invalidate` for `GlobalPackage` and `ProjectPackage`.
    pub package: bool,
}

impl ScopePersistFlags {
    pub const fn new(global: bool, package: bool) -> Self {
        Self { global, package }
    }
}

/// The capability-independent inputs of one scope decision.
pub struct ScopeLadder<'a> {
    pub scope: ApprovalScope,
    pub session_id: Option<&'a str>,
    pub package: Option<&'a str>,
    pub paths: &'a SandboxPaths,
    pub flags: ScopePersistFlags,
    /// Log line emitted after a `Project` write; `None` suppresses it.
    pub project_log: Option<&'a str>,
    /// Log line emitted after a `ProjectPackage` write; `None` suppresses it.
    pub project_package_log: Option<&'a str>,
}

/// What one ladder run changed, for the capability's reply tail.
pub struct ScopeApplied {
    pub target: ScopeTarget,
    /// Policy file written by a persistent arm, if any.
    pub policy_path: Option<PathBuf>,
}

/// Why a ladder run stopped early.
pub enum ScopeApplyError {
    /// The approval scope could not be resolved for this request.
    Resolve(Box<RpcReply>),
    /// The capability's memory step rejected the decision.
    Memory(PolicydError),
    /// A persistent rule write failed.
    Persist(PolicydError),
}

impl From<ScopeApplyError> for RpcReply {
    fn from(err: ScopeApplyError) -> Self {
        match err {
            ScopeApplyError::Resolve(reply) => *reply,
            ScopeApplyError::Memory(err) | ScopeApplyError::Persist(err) => err.into(),
        }
    }
}

impl PolicyStore {
    /// Run the full scope ladder for one capability decision.
    ///
    /// `memory` runs under the state lock for every resolved target and owns
    /// the in-memory arms (`Ephemeral`, `Session`); it ignores the persistent
    /// targets. `persist` is the capability's rule writer, invoked once per
    /// persistent arm with the policy path and the home the rule belongs to.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeApplyError::Resolve`] when the approval scope is not
    /// valid for this request, [`ScopeApplyError::Memory`] when the
    /// capability's memory step rejects the decision, and
    /// [`ScopeApplyError::Persist`] when a persistent rule write fails.
    pub async fn apply_scope_ladder(
        &self,
        ladder: ScopeLadder<'_>,
        memory: impl FnOnce(&mut PolicyDecisionState, &ScopeTarget) -> Result<(), PolicydError>,
        persist: &mut impl FnMut(&Path, Option<&Path>) -> std::io::Result<()>,
    ) -> Result<ScopeApplied, ScopeApplyError> {
        let home = ladder.paths.home();
        let project_root = ladder.paths.project_root();

        let target = self
            .resolve_scope_target(
                ladder.scope,
                ladder.session_id,
                home,
                project_root,
                ladder.package,
            )
            .await
            .map_err(ScopeApplyError::Resolve)?;

        {
            let mut inner = self.inner.lock().await;
            memory(&mut inner, &target).map_err(ScopeApplyError::Memory)?;
        }

        let policy_path = match &target {
            ScopeTarget::Ephemeral | ScopeTarget::Session { .. } => None,

            ScopeTarget::Global { policy_path, home } => {
                persist(policy_path, Some(home.as_path()))
                    .map_err(|err| ScopeApplyError::Persist(err.into()))?;

                if ladder.flags.global {
                    self.invalidate_merged_policy_cache();
                }

                Some(policy_path.clone())
            }

            ScopeTarget::GlobalPackage {
                policy_path, home, ..
            } => {
                persist(policy_path, Some(home.as_path()))
                    .map_err(|err| ScopeApplyError::Persist(err.into()))?;

                if ladder.flags.package {
                    self.invalidate_merged_policy_cache();
                }

                Some(policy_path.clone())
            }

            ScopeTarget::Project { policy_path, .. } => {
                persist(policy_path, home).map_err(|err| ScopeApplyError::Persist(err.into()))?;

                if ladder.flags.global {
                    self.invalidate_merged_policy_cache();
                }

                if let Some(log) = ladder.project_log {
                    tracing::info!(path = ?policy_path, "{log}");
                }

                Some(policy_path.clone())
            }

            ScopeTarget::ProjectPackage { policy_path, .. } => {
                persist(policy_path, home).map_err(|err| ScopeApplyError::Persist(err.into()))?;

                if ladder.flags.package {
                    self.invalidate_merged_policy_cache();
                }

                if let Some(log) = ladder.project_package_log {
                    tracing::info!(path = ?policy_path, "{log}");
                }

                Some(policy_path.clone())
            }
        };

        Ok(ScopeApplied {
            target,
            policy_path,
        })
    }

    /// Resolve the scope target for one request against the active sessions.
    ///
    /// # Errors
    ///
    /// Returns the RPC reply describing why the scope is invalid, matching
    /// the wire error shape callers forward unchanged.
    pub async fn resolve_scope_target(
        &self,
        scope: ApprovalScope,
        session_id: Option<&str>,
        home: Option<&Path>,
        project_root: Option<&Path>,
        package: Option<&str>,
    ) -> Result<ScopeTarget, Box<RpcReply>> {
        let active = self.active_session_ids().await;
        let home_str = home.and_then(Path::to_str);
        let project_root_str = project_root.and_then(Path::to_str);

        let ctx = ScopeContext {
            scope,
            session_id,
            home: home_str,
            project_root: project_root_str,
            package,
            active_session_ids: &active,
        };

        ScopeTarget::resolve(&ctx).map_err(|err| Box::new(RpcReply::from(err)))
    }
}
