//! Policy merge, pending approvals, and UI session state.

mod access;
mod context;
mod decisions;
mod elevation;
mod network;
mod persist;
mod scope_network;
mod scope_sudo;
mod status;
mod types;
mod ui;
mod ui_route;
mod util;

pub(crate) use types::UiSessionOwner;
pub use types::{
    Pending, PendingElevation, PendingKind, PendingNetwork, PolicyStore, PolicydArgs,
    UiClientHandle,
};

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use types::StoreInner;

impl PolicyStore {
    pub fn new(args: PolicydArgs) -> Self {
        Self {
            args,
            inner: tokio::sync::Mutex::new(StoreInner {
                session_allow: HashMap::new(),
                once_allow: HashSet::new(),
                pending: HashMap::new(),
                elevation_futures: HashMap::new(),
                network_futures: HashMap::new(),
                ui_clients: HashMap::new(),
                ui_context_by_session: HashMap::new(),
                ui_spawn_last: HashMap::<String, Instant>::new(),
                session_deny: HashMap::new(),
                session_sudo_allow: HashMap::new(),
                session_sudo_deny: HashMap::new(),
            }),
        }
    }

    pub const fn args(&self) -> &PolicydArgs {
        &self.args
    }
}
