//! Agent sandbox policy daemon (JSON-line RPC over Unix socket).

pub mod error;
pub mod server;
pub mod spawn;
pub mod store;
pub mod wire;

pub use error::PolicydError;
pub use server::PolicyServer;
pub use store::{PolicyStore, PolicydArgs};
pub use wire::{
    HostApproveRequest, MergeContext, NetworkCheckRequest, NetworkScopeOp, PendingDecision,
    SudoScopeOp, UiSpawnContext, UiSpawnGate,
};
