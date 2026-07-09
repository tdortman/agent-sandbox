//! Grouped wire/context fields for policyd.

use std::path::{Path, PathBuf};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, FilesystemRule, ProcessIds, RequestContext,
    ResolvedRequestContext, ResourceAccess, ResourceKind, SandboxPaths,
};

/// Attacker-controlled request context as received on the wire.
///
/// This stays distinct from [`ResolvedRequestContext`] until dispatch applies
/// `SO_PEERCRED` and store-side enrichment.
#[derive(Debug, Clone, Default)]
pub struct MergeContext {
    pub paths: SandboxPaths,
    pub ids: ProcessIds,
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

#[derive(Debug, Clone)]
pub struct ScopeWire {
    pub paths: SandboxPaths,
    pub session_id: Option<String>,
    pub owner_uid: Option<u32>,
    pub sandbox_session_id: Option<String>,
}

impl ScopeWire {
    #[must_use]
    pub fn from_resolved(ctx: &ResolvedRequestContext, session_id: Option<String>) -> Self {
        let owner_uid = ctx.ids.uid();
        Self {
            paths: ctx.paths.clone(),
            session_id,
            owner_uid,
            sandbox_session_id: ctx.sandbox_session_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkScopeOp {
    pub host: String,
    pub port: u16,
    pub scope: ApprovalScope,
    pub wire: ScopeWire,
}

#[derive(Debug, Clone)]
pub struct SudoScopeOp {
    pub argv: Vec<String>,
    pub scope: ApprovalScope,
    pub wire: ScopeWire,
}

#[derive(Debug, Clone)]
pub struct FilesystemScopeOp {
    pub path: PathBuf,
    pub access: FileAccess,
    pub scope: ApprovalScope,
    pub wire: ScopeWire,
}

#[derive(Debug, Clone)]
pub struct ResourceScopeOp {
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
    pub scope: ApprovalScope,
    pub wire: ScopeWire,
}

#[derive(Debug, Clone, Copy)]
pub struct UiSpawnGate {
    pub has_matching_ui: bool,
}

pub struct UiSpawnContext<'a> {
    pub gate: UiSpawnGate,
    pub sandbox_session_id: Option<&'a str>,
    pub uid: Option<u32>,
    pub home: Option<&'a Path>,
    pub cwd: Option<&'a Path>,
    pub project_root: Option<&'a Path>,
}

/// Network check payload for policyd approval.
///
/// Attribution hints travel via `request_network_approval_with_aliases`.
#[derive(Debug, Clone)]
pub struct NetworkCheckRequest {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub url: String,
    pub ctx: ResolvedRequestContext,
}

#[derive(Debug, Clone)]
pub struct FilesystemCheckRequest {
    pub path: PathBuf,
    pub access: FileAccess,
    pub ctx: ResolvedRequestContext,
}

#[derive(Debug, Clone)]
pub struct ResourceCheckRequest {
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
    pub ctx: ResolvedRequestContext,
}

#[derive(Debug, Clone)]
pub struct FilesystemMonitorRequest {
    pub peer_pid: u32,
    pub ctx: ResolvedRequestContext,
    pub static_allow: Vec<FilesystemRule>,
}

#[derive(Debug, Clone)]
pub struct HostApproveRequest {
    pub host: String,
    pub port: u16,
    pub scope: ApprovalScope,
    pub session_id: Option<String>,
    pub ctx: ResolvedRequestContext,
}

#[derive(Debug, Clone)]
pub struct PendingDecision {
    pub pending_id: String,
    pub scope: ApprovalScope,
    pub target: Option<ApprovalTarget>,
    pub wire: ScopeWire,
    pub client_id: u64,
    /// `SO_PEERCRED` uid of the connection issuing Approve/Deny.
    pub approver_uid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ElevationRequest {
    pub argv: Vec<String>,
    pub ctx: ResolvedRequestContext,
}
