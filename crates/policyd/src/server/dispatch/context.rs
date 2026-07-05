//! Resolve request context from an incoming RPC.

use std::sync::Arc;

use agent_sandbox_core::{RequestContext, RpcRequest};

use crate::server::dispatch::SocketRole;
use crate::server::peer::ClientPeer;
use crate::store::{PolicyStore, TrustedPeer};
use crate::wire::MergeContext;

pub fn resolve(store: &Arc<PolicyStore>, peer: ClientPeer, role: SocketRole, req: &mut RpcRequest) {
    let Some(ctx) = req.context_mut() else {
        return;
    };
    if role == SocketRole::Sandbox
        && let Some(sandbox_session_id) = ctx.sandbox_session_id.clone()
    {
        store.note_sandbox_peer(
            TrustedPeer {
                pid: peer.pid,
                uid: peer.uid,
            },
            &sandbox_session_id,
        );
    }
    let mc = MergeContext::from(&*ctx);
    let resolved = store.resolve_context_with_peer(
        &mc,
        Some(TrustedPeer {
            pid: peer.pid,
            uid: peer.uid,
        }),
    );
    *ctx = RequestContext::from(resolved);
}
