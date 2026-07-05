//! Route incoming RPC requests to store methods.

mod auth;
pub use auth::SocketRole;
mod check;
mod context;
mod handlers;

use std::sync::Arc;

use agent_sandbox_core::{RpcReply, RpcRequest};

use crate::error::PolicydError;
use crate::server::peer::ClientPeer;
use crate::store::PolicyStore;

pub async fn dispatch(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    mut req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    auth::ensure_allowed(role, &req)?;
    context::resolve(store, peer, role, &mut req);
    handlers::handle(store, client, peer, req).await
}
