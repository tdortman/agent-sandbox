//! Network `Check` RPC handling.

use std::sync::Arc;

use agent_sandbox_core::{
    CheckReply, RpcReply, SessionContext, is_ipv4_literal, normalize_host, policy_host_for_connect,
    write_session_context,
};

use crate::error::PolicydError;
use crate::store::PolicyStore;
use crate::wire::{MergeContext, NetworkCheckRequest};

use super::context::Resolved;

pub(crate) struct CheckParams {
    pub host: Option<String>,
    pub connect_host: Option<String>,
    pub port: Option<u16>,
    pub scheme: String,
    pub url: Option<String>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
}

pub(crate) async fn handle_check(
    store: &Arc<PolicyStore>,
    params: CheckParams,
    ctx: Resolved,
) -> Result<RpcReply, PolicydError> {
    let CheckParams {
        host,
        connect_host,
        port,
        scheme,
        url,
        pid,
        uid,
    } = params;
    let Resolved {
        cwd,
        home,
        project_root,
    } = ctx;

    let connect_host = connect_host.or_else(|| host.clone()).unwrap_or_default();
    let port = port.unwrap_or(0);
    let mut policy_host = normalize_host(host.as_deref().unwrap_or(""));
    if policy_host.is_empty() || is_ipv4_literal(&policy_host) {
        policy_host = policy_host_for_connect(&connect_host, None, None).0;
    }
    let url = url.unwrap_or_else(|| format!("{scheme}://{policy_host}:{port}"));
    if home.is_some() {
        write_session_context(&SessionContext {
            cwd: cwd.clone(),
            home: home.clone(),
            project_root: project_root.clone(),
        });
    }
    let merge =
        MergeContext::from_options(cwd.clone(), home.clone(), project_root.clone(), pid, uid);
    if let Some(source) = store.allow_source(&policy_host, port, merge.clone()).await {
        if source == "deny" {
            tracing::info!(%policy_host, port, "check deny (project policy)");
            return Ok(RpcReply::Check(CheckReply::denied("deny")));
        }
        let allowed = store
            .is_allowed(&policy_host, port, merge, source == "once")
            .await;
        if allowed {
            tracing::info!(%policy_host, port, %source, "check allow");
        }
        return Ok(RpcReply::Check(if allowed {
            CheckReply::allowed(source)
        } else {
            CheckReply::denied(source)
        }));
    }
    Ok(RpcReply::Check(
        store
            .request_network_approval(NetworkCheckRequest {
                host: policy_host,
                port,
                scheme,
                url,
                ctx: MergeContext::from_options(cwd, home, project_root, pid, uid),
            })
            .await,
    ))
}
