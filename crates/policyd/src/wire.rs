//! Grouped wire/context fields for policyd.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, DbusTarget, FileAccess, FilesystemRule, ProcessIds,
    RequestContext, ResolvedRequestContext, ResourceAccess, ResourceKind, SandboxPaths,
};

/// Attacker-controlled request context as received on the wire.
///
/// This stays distinct from [`ResolvedRequestContext`] until dispatch applies
/// `SO_PEERCRED` and store-side enrichment.
#[derive(Debug, Clone, Default)]
pub struct MergeContext {
    /// Sandbox paths carried by the request.
    pub paths: SandboxPaths,
    /// Process identifiers attesting the requesting process.
    pub ids: ProcessIds,
    /// Optional sandbox session id associated with the request.
    pub sandbox_session_id: Option<String>,
}

impl From<&RequestContext> for MergeContext {
    fn from(ctx: &RequestContext) -> Self {
        Self {
            paths: ctx.sandbox_paths(),
            ids: ctx.ids(),
            sandbox_session_id: ctx.sandbox_session_id.clone(),
        }
    }
}

impl From<MergeContext> for RequestContext {
    fn from(ctx: MergeContext) -> Self {
        Self {
            cwd: ctx.paths.cwd_path(),
            home: ctx.paths.home_path(),
            project_root: ctx.paths.project_root_path(),
            pid: ctx.ids.pid(),
            uid: ctx.ids.uid(),
            sandbox_session_id: ctx.sandbox_session_id,
        }
    }
}

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

/// Network check payload for policyd approval.
///
/// Attribution hints travel via `request_network_approval_with_aliases`.
#[derive(Debug, Clone)]
pub struct NetworkCheckRequest {
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// URL scheme.
    pub scheme: String,
    /// Full request URL.
    pub url: String,
    /// Resolved request context for attribution.
    pub ctx: ResolvedRequestContext,
}

/// Filesystem check payload for policyd approval.
#[derive(Debug, Clone)]
pub struct FilesystemCheckRequest {
    /// Filesystem path being checked.
    pub path: PathBuf,
    /// Access mode requested.
    pub access: FileAccess,
    /// Resolved request context for attribution.
    pub ctx: ResolvedRequestContext,
}

/// Resource check payload for policyd approval.
#[derive(Debug, Clone)]
pub struct ResourceCheckRequest {
    /// Type of resource being checked.
    pub kind: ResourceKind,
    /// Resource path.
    pub path: PathBuf,
    /// Access mode requested.
    pub access: ResourceAccess,
    /// Resolved request context for attribution.
    pub ctx: ResolvedRequestContext,
}

/// D-Bus check payload for policyd approval.
#[derive(Debug, Clone)]
pub struct DbusCheckRequest {
    /// D-Bus target being addressed.
    pub target: DbusTarget,
    /// Resolved request context for attribution.
    pub ctx: ResolvedRequestContext,
}

/// Filesystem monitor registration payload for policyd.
#[derive(Debug, Clone)]
pub struct FilesystemMonitorRequest {
    /// Pid of the peer to monitor.
    pub peer_pid: u32,
    /// Resolved request context for attribution.
    pub ctx: ResolvedRequestContext,
    /// Statically allowed filesystem rules for the monitor.
    pub static_allow: Vec<FilesystemRule>,
}

/// Host approval payload for policyd.
#[derive(Debug, Clone)]
pub struct HostApproveRequest {
    /// Host to approve.
    pub host: String,
    /// Port to approve.
    pub port: u16,
    /// Approval scope being granted.
    pub scope: ApprovalScope,
    /// Optional session id.
    pub session_id: Option<String>,
    /// Resolved request context for attribution.
    pub ctx: ResolvedRequestContext,
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

/// Elevation request payload for policyd.
#[derive(Debug, Clone)]
pub struct ElevationRequest {
    /// Commandline to run elevated.
    pub argv: Vec<String>,
    /// Resolved request context for attribution.
    pub ctx: ResolvedRequestContext,
}
