//! Policy merge, pending approvals, and UI session state.

mod access;
mod context;
mod decisions;
mod elevation;
mod filesystem;
mod network;
mod persist;
mod scope_filesystem;
mod scope_network;
mod scope_sudo;
mod status;
mod types;
mod ui;
mod ui_route;
mod util;

pub(crate) use types::UiSessionContext;
pub use types::{
    Pending, PendingElevation, PendingFilesystem, PendingKind, PendingNetwork, PolicyStore,
    PolicydArgs, UiClientHandle,
};

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use types::StoreInner;

impl PolicyStore {
    #[must_use]
    pub fn new(args: PolicydArgs) -> Self {
        Self {
            args,
            inner: tokio::sync::Mutex::new(StoreInner {
                session_allow: HashMap::new(),
                once_allow: HashSet::new(),
                pending: HashMap::new(),
                elevation_futures: HashMap::new(),
                network_futures: HashMap::new(),
                filesystem_futures: HashMap::new(),
                ui_clients: HashMap::new(),
                ui_context_by_session: HashMap::new(),
                ui_spawn_last: HashMap::<String, Instant>::new(),
                session_deny: HashMap::new(),
                session_sudo_allow: HashMap::new(),
                session_sudo_deny: HashMap::new(),
                session_filesystem_allow: HashMap::new(),
                session_filesystem_deny: HashMap::new(),
                network_verdict_cache: HashMap::new(),
                filesystem_verdict_cache: HashMap::new(),
            }),
        }
    }

    pub const fn args(&self) -> &PolicydArgs {
        &self.args
    }
}
