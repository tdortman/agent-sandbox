use std::time::Duration;

use agent_sandbox_core::{
    ProcessIds, RpcReply, RpcRequest, persist_session_paths, policy_rpc, resolve_proxy_paths,
};
use tracing::{info, warn};

use crate::error::ProxyClientError;
use crate::state::ProxyState;

pub(crate) async fn check_destination(
    state: &ProxyState,
    policy_host: &str,
    connect_host: &str,
    port: u16,
    scheme: &str,
    ids: ProcessIds,
) -> Result<bool, ProxyClientError> {
    let paths = resolve_proxy_paths(ids);
    persist_session_paths(&paths);
    let url = format!("{scheme}://{policy_host}:{port}");
    let req = RpcRequest::Check {
        host: Some(policy_host.to_string()),
        connect_host: Some(connect_host.to_string()),
        port: Some(port),
        scheme: scheme.to_string(),
        url: Some(url),
        cwd: paths.cwd_string(),
        home: paths.home_string(),
        project_root: paths.project_root_string(),
        pid: ids.pid(),
        uid: ids.uid(),
    };
    let timeout = Duration::from_secs_f64(state.args.policy_timeout.max(1.0));
    let resp = policy_rpc(&state.args.policy_socket, req, timeout).await?;
    log_check(policy_host, port, &resp);
    Ok(matches!(resp, RpcReply::Check(c) if c.allowed))
}

fn log_check(host: &str, port: u16, resp: &RpcReply) {
    match resp {
        RpcReply::Check(c) if c.allowed => {
            if c.source.is_empty() {
                info!(%host, port, "policy allow");
            } else {
                info!(%host, port, source = %c.source, "policy allow");
            }
        }
        RpcReply::Check(c) if c.source == "deny" => {
            info!(%host, port, "policy deny (project policy)");
        }
        RpcReply::Check(c) => {
            if let Some(err) = &c.error {
                info!(%host, port, source = %c.source, error = %err, "policy blocked");
            } else {
                info!(%host, port, source = %c.source, "policy blocked");
            }
        }
        RpcReply::Error(e) => {
            warn!(%host, port, error = %e.error, "policy check error");
        }
        _ => {}
    }
}
