//! Grouped wire/context fields for policyd.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, ResolvedRequestContext, ResourceAccess,
    ResourceKind, SandboxPaths,
};

/// Resolved scope context along with the wire-supplied session and package
/// data.
#[derive(Debug, Clone)]
pub struct ScopeWire {
    /// Sandbox paths for the scope.
    pub paths: SandboxPaths,
    /// Optional session id.
    pub session_id: Option<String>,
    /// Owner uid deduced from the resolved context.
    pub owner_uid: Option<u32>,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<String>,
    /// Optional free-text comment supplied on the wire.
    pub comment: Option<String>,
    /// Optional package name associated with the scope.
    pub package: Option<String>,
}

impl ScopeWire {
    #[must_use]
    /// Build a [`ScopeWire`] from a resolved request context and session id.
    pub fn from_resolved(ctx: &ResolvedRequestContext, session_id: Option<String>) -> Self {
        let owner_uid = ctx.ids.uid();

        Self {
            paths: ctx.paths.clone(),
            session_id,
            owner_uid,
            sandbox_session_id: ctx.sandbox_session_id.clone(),
            comment: None,
            package: ctx.package.clone(),
        }
    }
}

/// Network scope operation awaiting approval.
#[derive(Debug, Clone)]
pub struct NetworkScopeOp {
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Approval scope for the operation.
    pub scope: ApprovalScope,
    /// Wire-supplied scope context.
    pub wire: ScopeWire,
}

/// Sudo scope operation awaiting approval.
#[derive(Debug, Clone)]
pub struct SudoScopeOp {
    /// Commandline arguments to elevate.
    pub argv: Vec<String>,
    /// Approval scope for the operation.
    pub scope: ApprovalScope,
    /// Wire-supplied scope context.
    pub wire: ScopeWire,
}

/// Filesystem scope operation awaiting approval.
#[derive(Debug, Clone)]
pub struct FilesystemScopeOp {
    /// Filesystem path being accessed.
    pub path: PathBuf,
    /// Access mode requested.
    pub access: FileAccess,
    /// Approval scope for the operation.
    pub scope: ApprovalScope,
    /// Wire-supplied scope context.
    pub wire: ScopeWire,
}

/// Resource scope operation awaiting approval.
#[derive(Debug, Clone)]
pub struct ResourceScopeOp {
    /// Type of resource being accessed.
    pub kind: ResourceKind,
    /// Resource path.
    pub path: PathBuf,
    /// Access mode requested.
    pub access: ResourceAccess,
    /// Approval scope for the operation.
    pub scope: ApprovalScope,
    /// Wire-supplied scope context.
    pub wire: ScopeWire,
}

/// UI spawn context describing an inherited UI policy fd registration.
pub struct UiSpawnContext<'a> {
    /// Whether a matching UI session exists.
    pub has_matching_ui: bool,
    /// Optional sandbox session id.
    pub sandbox_session_id: Option<&'a str>,
    /// Optional uid of the registering process.
    pub uid: Option<u32>,
    /// Optional home directory.
    pub home: Option<&'a Path>,
    /// Optional current working directory.
    pub cwd: Option<&'a Path>,
    /// Optional project root directory.
    pub project_root: Option<&'a Path>,
}

/// A decision awaiting approval, keyed by its pending id.
#[derive(Debug, Clone)]
pub struct PendingDecision {
    /// Id identifying this pending decision.
    pub pending_id: String,
    /// Approval scope of the pending decision.
    pub scope: ApprovalScope,
    /// Optional approval target.
    pub target: Option<ApprovalTarget>,
    /// Wire-supplied scope context.
    pub wire: ScopeWire,
    /// Client id that issued the request.
    pub client_id: u64,

    /// `SO_PEERCRED` uid of the connection issuing Approve/Deny.
    pub approver_uid: Option<u32>,
}
