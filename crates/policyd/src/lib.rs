//! Agent sandbox policy daemon (JSON-line RPC over Unix socket).

pub mod error;
mod loopback_bridge;
mod shutdown;

pub mod server;
pub mod spawn;
pub mod store;
pub mod wire;
pub use error::PolicydError;
pub use server::PolicyServer;
pub use shutdown::handoff_or_abort;
pub use store::{
    ObservedNetworkGrants, PackageDeclarative, PolicyStore, PolicydArgs, cleanup_cgroup_freeze,
};
