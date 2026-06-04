//! Scope wire resolution for pending decisions.

use agent_sandbox_core::SandboxPaths;

use crate::wire::ScopeWire;

use super::super::types::{Pending, PolicyStore};

impl PolicyStore {
    pub(crate) fn scope_wire_for_pending(wire: ScopeWire, pending: &Pending) -> ScopeWire {
        ScopeWire {
            paths: SandboxPaths::from_wire(
                pending.cwd.clone().or(wire.paths.cwd_string()),
                pending.home.clone().or(wire.paths.home_string()),
                pending
                    .project_root
                    .clone()
                    .or(wire.paths.project_root_string()),
            ),
            session_id: wire.session_id,
            owner_uid: wire.owner_uid,
        }
    }
}
