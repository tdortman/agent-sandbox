//! The context a decided verdict belongs to.
//!
//! Every sandbox of one user shares one policyd, so a verdict recorded for
//! one request must only answer requests that would be judged the same way.
//! What a verdict depends on is the merged policy (home, project root,
//! package) and the session decisions routed to the request (session id, and
//! for a request without a session the working directory). The short
//! verdict caches, and the coalescing of identical prompts, key on that
//! context together with the request.

use std::path::PathBuf;

use agent_sandbox_core::{HttpContextKey, ResolvedRequestContext};

use crate::wire::ScopeWire;

/// The decision context of a request. Two requests with equal contexts are
/// judged by the same policy layers and session decisions; a request without
/// a session never equals one with a session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct DecisionContext {
    /// Sandbox session the request belongs to.
    pub sandbox_session_id: Option<String>,

    /// Package attributed to the request after policyd verified it against
    /// the session. Unverified claims leave it empty, which is what keeps a
    /// process that merely names another sandbox's session id apart from it.
    pub package: Option<String>,

    /// Project root policy layers are loaded from.
    pub project_root: Option<PathBuf>,

    /// Home directory user policy is loaded from.
    pub home: Option<PathBuf>,

    /// Working directory, for a request without a session only: session
    /// decisions of such a request route by project root or working
    /// directory.
    pub cwd: Option<PathBuf>,
}

impl From<&ResolvedRequestContext> for DecisionContext {
    fn from(ctx: &ResolvedRequestContext) -> Self {
        Self {
            sandbox_session_id: ctx.sandbox_session_id.clone(),
            package: ctx.package.clone(),
            project_root: ctx.paths.project_root_path(),
            home: ctx.paths.home_path(),
            cwd: ctx
                .sandbox_session_id
                .is_none()
                .then(|| ctx.paths.cwd_path())
                .flatten(),
        }
    }
}

impl DecisionContext {
    /// The context of an HTTP request, from the parts a pending HTTP
    /// approval keeps.
    #[must_use]
    pub fn from_http(context: &HttpContextKey, package: Option<&str>) -> Self {
        Self {
            sandbox_session_id: context.sandbox_session_id.clone(),
            package: package.map(str::to_owned),
            project_root: context.project_root.clone(),
            home: context.home.clone(),
            cwd: context
                .sandbox_session_id
                .is_none()
                .then(|| context.cwd.clone())
                .flatten(),
        }
    }
}

impl From<&ScopeWire> for DecisionContext {
    /// The context a scope decision on a request of `wire` applies to.
    fn from(wire: &ScopeWire) -> Self {
        Self {
            sandbox_session_id: wire.sandbox_session_id.clone(),
            package: wire.package.clone(),
            project_root: wire.paths.project_root_path(),
            home: wire.paths.home_path(),
            cwd: wire
                .sandbox_session_id
                .is_none()
                .then(|| wire.paths.cwd_path())
                .flatten(),
        }
    }
}

/// A request key qualified by the context it was decided under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContextKey<K> {
    /// Context the verdict was decided under.
    pub context: DecisionContext,

    /// The request.
    pub key: K,
}

impl<K> ContextKey<K> {
    /// Qualify `key` with the context of `ctx`.
    #[must_use]
    pub fn new(ctx: &ResolvedRequestContext, key: K) -> Self {
        Self {
            context: DecisionContext::from(ctx),
            key,
        }
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{ProcessIds, ResolvedRequestContext, SandboxPaths};

    use super::DecisionContext;

    fn ctx(session: Option<&str>, package: Option<&str>, root: &str) -> ResolvedRequestContext {
        ResolvedRequestContext {
            paths: SandboxPaths::from_wire(
                Some("/work/cwd".into()),
                Some("/home/user".into()),
                Some(root.into()),
            ),
            ids: ProcessIds::from_options(Some(10), Some(1000)),
            sandbox_session_id: session.map(Into::into),
            package: package.map(Into::into),
        }
    }

    #[test]
    fn contexts_differ_by_session_package_and_project() {
        let base = DecisionContext::from(&ctx(Some("a"), Some("pkg"), "/p"));

        assert_eq!(
            base,
            DecisionContext::from(&ctx(Some("a"), Some("pkg"), "/p"))
        );
        assert_ne!(
            base,
            DecisionContext::from(&ctx(Some("b"), Some("pkg"), "/p"))
        );
        assert_ne!(base, DecisionContext::from(&ctx(Some("a"), None, "/p")));
        assert_ne!(
            base,
            DecisionContext::from(&ctx(Some("a"), Some("pkg"), "/q"))
        );
        assert_ne!(base, DecisionContext::from(&ctx(None, Some("pkg"), "/p")));
    }

    #[test]
    fn processes_of_one_session_share_a_context_whatever_their_cwd() {
        let mut other = ctx(Some("a"), Some("pkg"), "/p");
        other.paths = SandboxPaths::from_wire(
            Some("/elsewhere".into()),
            Some("/home/user".into()),
            Some("/p".into()),
        );

        assert_eq!(
            DecisionContext::from(&ctx(Some("a"), Some("pkg"), "/p")),
            DecisionContext::from(&other)
        );
    }

    #[test]
    fn sessionless_requests_are_told_apart_by_cwd() {
        let mut other = ctx(None, None, "/p");
        other.paths = SandboxPaths::from_wire(
            Some("/elsewhere".into()),
            Some("/home/user".into()),
            Some("/p".into()),
        );

        assert_ne!(
            DecisionContext::from(&ctx(None, None, "/p")),
            DecisionContext::from(&other)
        );
    }
}
