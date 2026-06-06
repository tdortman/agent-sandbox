//! Resolve request context from an incoming RPC.

use std::sync::Arc;

use agent_sandbox_core::{RequestContext, RpcRequest};

use crate::store::PolicyStore;
use crate::wire::MergeContext;

pub(crate) async fn resolve(store: &Arc<PolicyStore>, req: &mut RpcRequest) {
    let Some(ctx) = req.context_mut() else {
        return;
    };
    let resolved = store.resolve_context(MergeContext::from(&*ctx)).await;
    *ctx = RequestContext::from(resolved);
}
