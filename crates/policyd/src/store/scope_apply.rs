//! Policy store: the shared scope ladder lifecycle.
//!
//! Every capability scope decision runs the same ladder: resolve the
//! [`ScopeTarget`] from the [`ApprovalScope`], apply the in-memory arms under
//! the state lock (the ladder owns the `Session` arm; the `Ephemeral` arm and
//! pre-memory invalidation are the capability's [`ScopeEffects`]), then run
//! the four persistent arms through the capability's rule writer.
//! Project-scope writes emit the ladder's log lines.

use std::{
    hash::Hash,
    path::{Path, PathBuf},
};

use agent_sandbox_core::{ApprovalScope, RpcReply, SandboxPaths, ScopeContext, ScopeTarget};

use super::{
    decisions::DecisionAction,
    state::{SessionBuckets, SessionState},
    types::{PolicyDecisionState, PolicyStore},
};
use crate::error::PolicydError;

/// Capability-specific in-memory work around the ladder's session arm.
pub trait ScopeEffects {
    /// Runs under the state lock for every resolved target, before the
    /// in-memory arms.
    ///
    /// # Errors
    ///
    /// Returns the error that rejects the decision before any memory write.
    fn before(
        &self,
        _inner: &mut PolicyDecisionState,
        _target: &ScopeTarget,
    ) -> Result<(), PolicydError> {
        Ok(())
    }

    /// The `Ephemeral` arm: record a once decision.
    ///
    /// # Errors
    ///
    /// Returns the error that rejects the once decision.
    fn once(
        &self,
        _session: &mut SessionState,
        _action: DecisionAction,
    ) -> Result<(), PolicydError> {
        Ok(())
    }
}

/// Capabilities with no once set and no invalidation: `Ephemeral` writes
/// nothing.
pub struct NoEffects;

impl ScopeEffects for NoEffects {}

/// The inputs of one scope decision: the request, the decision, the rule
/// key, and the session bucket the key belongs to.
pub struct ScopeLadder<'a, K, E> {
    pub action: DecisionAction,
    pub key: &'a K,

    /// Selects the capability's session bucket, e.g.
    /// `SessionState::sudo_buckets`.
    pub bucket: fn(&mut SessionState) -> SessionBuckets<'_, K>,
    pub effects: E,
    pub scope: ApprovalScope,
    pub session_id: Option<&'a str>,
    pub package: Option<&'a str>,
    pub paths: &'a SandboxPaths,

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
    /// The in-memory arms run under the state lock: `Session` writes the
    /// key into the capability's bucket, `Ephemeral` defers to
    /// [`ScopeEffects::once`]. `persist` is the capability's rule writer,
    /// invoked once per persistent arm with the policy path and the home the
    /// rule belongs to.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeApplyError::Resolve`] when the approval scope is not
    /// valid for this request, [`ScopeApplyError::Memory`] when the
    /// capability's effects reject the decision, and
    /// [`ScopeApplyError::Persist`] when a persistent rule write fails.
    pub async fn apply_scope_ladder<K: Clone + Eq + Hash + Sync, E: ScopeEffects + Send>(
        &self,
        ladder: ScopeLadder<'_, K, E>,
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
            ladder
                .effects
                .before(&mut inner, &target)
                .map_err(ScopeApplyError::Memory)?;

            match &target {
                ScopeTarget::Ephemeral => ladder
                    .effects
                    .once(&mut inner.session, ladder.action)
                    .map_err(ScopeApplyError::Memory)?,

                ScopeTarget::Session { session_id } => {
                    (ladder.bucket)(&mut inner.session).apply(
                        ladder.action,
                        session_id,
                        ladder.key,
                    );
                }

                ScopeTarget::Global { .. }
                | ScopeTarget::GlobalPackage { .. }
                | ScopeTarget::Project { .. }
                | ScopeTarget::ProjectPackage { .. } => {}
            }
        }

        let policy_path = match &target {
            ScopeTarget::Ephemeral | ScopeTarget::Session { .. } => None,

            ScopeTarget::Global { policy_path, home } => {
                persist(policy_path, Some(home.as_path()))
                    .map_err(|err| ScopeApplyError::Persist(err.into()))?;

                Some(policy_path.clone())
            }

            ScopeTarget::GlobalPackage {
                policy_path, home, ..
            } => {
                persist(policy_path, Some(home.as_path()))
                    .map_err(|err| ScopeApplyError::Persist(err.into()))?;

                Some(policy_path.clone())
            }

            ScopeTarget::Project { policy_path, .. } => {
                persist(policy_path, home).map_err(|err| ScopeApplyError::Persist(err.into()))?;

                if let Some(log) = ladder.project_log {
                    tracing::info!(path = ?policy_path, "{log}");
                }

                Some(policy_path.clone())
            }

            ScopeTarget::ProjectPackage { policy_path, .. } => {
                persist(policy_path, home).map_err(|err| ScopeApplyError::Persist(err.into()))?;

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
