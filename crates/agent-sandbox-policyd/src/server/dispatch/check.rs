//! Network `Check` RPC handling.

use std::sync::Arc;

use agent_sandbox_core::{
    CheckReply, RequestContext, RpcReply, is_ipv4_literal, normalize_host, policy_host_for_connect,
};

use crate::error::PolicydError;
use crate::store::PolicyStore;
use crate::wire::{MergeContext, NetworkCheckRequest};

pub(crate) async fn handle_check(
    store: &Arc<PolicyStore>,
    host: Option<String>,
    connect_host: Option<String>,
    port: Option<u16>,
    scheme: String,
    url: Option<String>,
    ctx: RequestContext,
) -> Result<RpcReply, PolicydError> {
    let connect_host = connect_host.or_else(|| host.clone()).unwrap_or_default();
    let port = port.unwrap_or(0);
    let mut policy_host = normalize_host(host.as_deref().unwrap_or(""));
    if policy_host.is_empty() || is_ipv4_literal(&policy_host) {
        policy_host = policy_host_for_connect(&connect_host, None, None).0;
    }
    let url = url.unwrap_or_else(|| format!("{scheme}://{policy_host}:{port}"));
    let merge = MergeContext::from(&ctx);
    if let Some(source) = store.allow_source(&policy_host, port, merge.clone()).await {
        if source == "deny" {
            tracing::info!(%policy_host, port, "check deny (project policy)");
            return Ok(RpcReply::Check(CheckReply::denied("deny")));
        }
        if source == "once" {
            let allowed = store.is_allowed(&policy_host, port, merge, true).await;
            if allowed {
                tracing::info!(%policy_host, port, %source, "check allow");
            } else {
                tracing::info!(%policy_host, port, %source, "check deny (once grant consumed)");
            }
            return Ok(RpcReply::Check(if allowed {
                CheckReply::allowed(source)
            } else {
                CheckReply::denied(source)
            }));
        }
        tracing::info!(%policy_host, port, %source, "check allow");
        return Ok(RpcReply::Check(CheckReply::allowed(source)));
    }
    Ok(RpcReply::Check(
        store
            .request_network_approval(NetworkCheckRequest {
                host: policy_host,
                port,
                scheme,
                url,
                ctx: merge,
            })
            .await,
    ))
}
