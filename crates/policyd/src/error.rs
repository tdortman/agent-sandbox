//! Policy daemon errors (RPC-facing and startup).

use agent_sandbox_core::{ErrorReply, ProjectPolicyError, RpcReply, ScopeResolveError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicydError {
    #[error(transparent)]
    Scope(#[from] ScopeResolveError),
    #[error(transparent)]
    ProjectPolicy(#[from] ProjectPolicyError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid JSON")]
    InvalidJson,
    #[error("argv required (non-empty list of strings)")]
    ArgvRequired,
    #[error("host required")]
    HostRequired,
    #[error("invalid port")]
    InvalidPort,
    #[error("port required (1-65535)")]
    PortRequired,
    #[error("unknown pending id")]
    UnknownPendingId,
    #[error("host denied by policy deny rules")]
    HostDeniedByPolicy,
    #[error("invalid approval target")]
    InvalidDecisionTarget,
    #[error("request not allowed on sandbox policy socket")]
    UnauthorizedRequest,
    #[error("request not allowed on inherited UI policy fd")]
    UnauthorizedUiFdRequest,
    #[error("approval session does not match pending sandbox session")]
    UnauthorizedApprovalSession,
}

impl From<PolicydError> for RpcReply {
    fn from(err: PolicydError) -> Self {
        Self::Error(ErrorReply::new(err.to_string()))
    }
}
