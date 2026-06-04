//! Route incoming RPC requests to store methods.

mod check;
mod context;
mod handlers;

use std::sync::Arc;

use agent_sandbox_core::{RpcReply, RpcRequest};

use crate::error::PolicydError;
use crate::store::PolicyStore;

pub async fn dispatch(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    let ctx = context::resolve(store, &req).await;
    handlers::handle(store, client, req, ctx).await
}
