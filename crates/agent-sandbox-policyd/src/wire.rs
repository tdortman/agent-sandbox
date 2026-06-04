//! Grouped wire/context fields for policyd (keeps function arity down).

use agent_sandbox_core::{ApprovalScope, ProcessIds, SandboxPaths};

#[derive(Debug, Clone, Default)]
pub struct MergeContext {
    pub paths: SandboxPaths,
    pub ids: ProcessIds,
}

impl MergeContext {
    #[must_use]
    pub fn from_options(
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
        pid: Option<u32>,
        uid: Option<u32>,
    ) -> Self {
        Self {
            paths: SandboxPaths::from_wire(cwd, home, project_root),
            ids: ProcessIds::from_wire(pid, uid),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopeWire {
    pub paths: SandboxPaths,
    pub session_id: Option<String>,
    pub owner_uid: Option<u32>,
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
    pub scope: String,
    pub session_id: Option<String>,
    pub ctx: MergeContext,
}

#[derive(Debug, Clone)]
pub struct PendingDecision {
    pub pending_id: String,
    pub scope: String,
    pub wire: ScopeWire,
}

#[derive(Debug, Clone)]
pub struct ElevationRequest {
    pub argv: Vec<String>,
    pub ctx: MergeContext,
}
