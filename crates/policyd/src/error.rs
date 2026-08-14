//! Policy daemon errors (RPC-facing and startup).

use agent_sandbox_core::{ErrorReply, ProjectPolicyError, RpcReply, ScopeResolveError};
use thiserror::Error;

/// Errors returned by the policy daemon across RPC dispatch and startup.
#[derive(Debug, Error)]
pub enum PolicydError {
    #[error(transparent)]
    /// Failure to resolve a request's scope targets.
    Scope(#[from] ScopeResolveError),

    #[error(transparent)]
    /// A project-level policy error propagated from the core crate.
    ProjectPolicy(#[from] ProjectPolicyError),

    #[error(transparent)]
    /// An underlying I/O error.
    Io(#[from] std::io::Error),

    #[error("invalid JSON")]
    /// The request body was not valid JSON.
    InvalidJson,

    #[error("argv required (non-empty list of strings)")]
    /// The request was missing a non-empty `argv` list.
    ArgvRequired,

    #[error("host required")]
    /// The request was missing a required `host`.
    HostRequired,

    #[error("invalid port")]
    /// The request carried an invalid `port` value.
    InvalidPort,

    #[error("invalid package name: {0}")]
    /// The package name given was not a valid package name.
    InvalidPackageName(String),

    #[error("launcher pid does not match the registering peer's parent")]
    /// The launcher pid did not match the registering peer's parent process.
    InvalidLauncherPid,

    #[error("package is immutable for this session after first registration")]
    /// The package is immutable for this session after its first registration.
    PackageImmutable,

    #[error("unknown pending id")]
    /// The referenced pending approval id is not known.
    UnknownPendingId,

    #[error("host denied by policy deny rules")]
    /// The requested host is denied by policy deny rules.
    HostDeniedByPolicy,

    #[error("invalid approval target")]
    /// The approval target given was invalid.
    InvalidDecisionTarget,

    #[error("request not allowed on sandbox policy socket")]
    /// The request is not allowed on the sandbox policy socket.
    UnauthorizedRequest,

    #[error("request not allowed on inherited UI policy fd")]
    /// The request is not allowed on an inherited UI policy fd.
    UnauthorizedUiFdRequest,

    #[error("approval session does not match pending sandbox session")]
    /// The approval session does not match the pending sandbox session.
    UnauthorizedApprovalSession,

    #[error("approval not authorized for this connection")]
    /// The approval is not authorized for this connection.
    UnauthorizedApprovalClient,

    #[error("UI registration uid does not match sandbox owner")]
    /// The UI registration uid does not match the sandbox owner.
    UnauthorizedUiRegistration,

    #[error("too many connections for this uid")]
    /// Too many concurrent connections exist for this uid.
    TooManyConnections,

    #[error("proxy request failed: {0}")]
    /// The proxy request failed with the underlying error.
    Proxy(String),

    #[error("RPC line too large")]
    /// An RPC line exceeded the maximum allowed size.
    RpcLineTooLarge,

    #[error(
        "elevation argv[0] must be a bare command resolved via /run/current-system/sw/bin or an \
         absolute path under /run/current-system, with a regular canonical target under /nix/store"
    )]
    /// Elevation `argv[0]` is not a bare command or absolute path under
    /// `/run/current-system` with a regular canonical target under
    /// `/nix/store`.
    ElevationArgvNotAbsolute,
}

impl From<PolicydError> for RpcReply {
    fn from(err: PolicydError) -> Self {
        Self::Error(ErrorReply::new(err.to_string()))
    }
}
