//! Grouped wire/context fields for policyd.

use agent_sandbox_core::{ApprovalScope, ProcessIds, RequestContext, SandboxPaths};

#[derive(Debug, Clone, Default)]
pub struct MergeContext {
    pub paths: SandboxPaths,
    pub ids: ProcessIds,
}

impl From<&RequestContext> for MergeContext {
    fn from(ctx: &RequestContext) -> Self {
        Self {
            paths: ctx.sandbox_paths(),
            ids: ctx.ids(),
        }
    }
}

impl From<MergeContext> for RequestContext {
    fn from(ctx: MergeContext) -> Self {
        Self {
            cwd: ctx.paths.cwd_string(),
            home: ctx.paths.home_string(),
            project_root: ctx.paths.project_root_string(),
            pid: ctx.ids.pid(),
            uid: ctx.ids.uid(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopeWire {
    pub paths: SandboxPaths,
    pub session_id: Option<String>,
    pub owner_uid: Option<u32>,
}

impl ScopeWire {
    #[must_use]
    pub fn from_request(ctx: &RequestContext, session_id: Option<String>) -> Self {
        let owner_uid = ctx.uid;
        Self {
            paths: ctx.sandbox_paths(),
            session_id,
            owner_uid,
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

#[derive(Debug, Clone, Copy)]
pub struct UiSpawnGate {
    pub has_ui_clients: bool,
    pub has_omp_ui: bool,
}

pub struct UiSpawnContext<'a> {
    pub gate: UiSpawnGate,
    pub uid: Option<u32>,
    pub home: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub project_root: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct NetworkCheckRequest {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub url: String,
    pub ctx: MergeContext,
}

#[derive(Debug, Clone)]
pub struct HostApproveRequest {
    pub host: String,
    pub port: u16,
    pub scope: ApprovalScope,
    pub session_id: Option<String>,
    pub ctx: MergeContext,
}

#[derive(Debug, Clone)]
pub struct PendingDecision {
    pub pending_id: String,
    pub scope: ApprovalScope,
    pub wire: ScopeWire,
}

#[derive(Debug, Clone)]
pub struct ElevationRequest {
    pub argv: Vec<String>,
    pub ctx: MergeContext,
}
