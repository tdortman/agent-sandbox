//! Agent sandbox policy daemon (JSON-line RPC over Unix socket).

pub mod error;
mod fuse_mount;
mod loopback_bridge;
mod shutdown;

pub mod server;
pub mod spawn;
mod stall;
pub mod store;
pub mod wire;
pub use error::PolicydError;
pub use server::PolicyServer;
pub use shutdown::handoff_or_abort;
pub use store::{
    ObservedNetworkGrants, PackageDeclarative, PolicyStore, PolicydArgs, cleanup_cgroup_freeze,
};
