//! Agent sandbox policy daemon (JSON-line RPC over Unix socket).

pub mod error;
pub mod server;
pub mod spawn;
pub mod store;
pub mod wire;

pub use error::PolicydError;
pub use server::PolicyServer;
pub use store::{PolicyStore, PolicydArgs, cleanup_cgroup_freeze};
pub use wire::{
    FilesystemCheckRequest, FilesystemMonitorRequest, FilesystemScopeOp, HostApproveRequest,
    MergeContext, NetworkCheckRequest, NetworkScopeOp, PendingDecision, ResourceCheckRequest,
    ResourceScopeOp, SudoScopeOp, UiSpawnContext, UiSpawnGate,
};
