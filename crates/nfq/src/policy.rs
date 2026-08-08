//! Policy RPC client for NFQUEUE, calls policyd's `Check` endpoint.

use crate::packet::TransportProtocol;

use agent_sandbox_core::{
    FlowRegistration, RequestContext, RpcReply, RpcRequest, attach_check_aliases, daemon_context,
    persist_session_paths, policy_rpc,
};

use std::time::Duration;

/// Inputs for a single policy check, grouped to keep the call signature small.
pub struct CheckDestinationArgs<'a> {
    pub hostname: &'a str,
    pub dst_ip: &'a str,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    pub src_pid: Option<u32>,
    pub aliases: &'a [String],
}

/// Check whether a destination is allowed by policy.
///
/// `hostname` should be pre-resolved by the caller (DNS cache or PTR).
/// Blocks until policyd responds (which may wait for user approval).
pub async fn check_destination(
    socket: &str,
    args: CheckDestinationArgs<'_>,
    timeout: Duration,
) -> std::io::Result<bool> {
    let ctx = daemon_context(args.src_pid);
    persist_session_paths(&ctx.paths);
    let scheme = args.protocol.as_str();
    let url = format!("{scheme}://{}:{}", args.hostname, args.dst_port);

    let req = RpcRequest::Check {
        host: Some(args.hostname.to_string()),
        connect_host: Some(args.dst_ip.to_string()),
        port: Some(args.dst_port),
        scheme: scheme.to_string(),
        url: attach_check_aliases(Some(url), args.aliases),
        ctx: RequestContext::from(&ctx),
    };

    let resp = policy_rpc(socket, req, timeout)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;

    let allowed = matches!(resp, RpcReply::Check(check) if check.allowed);
    Ok(allowed)
}

/// Register one owner-identified flow with policyd before proxy forwarding.
///
/// Asks policyd to validate the typed owner snapshot and stores the flow for
/// the transparent proxy to claim later. Any malformed reply is an RPC failure
/// and must be treated as a failed registration by callers.
pub async fn register_network_flow(
    socket: &str,
    registration: FlowRegistration,
    timeout: Duration,
) -> std::io::Result<bool> {
    let response = policy_rpc(
        socket,
        RpcRequest::RegisterNetworkFlow { registration },
        timeout,
    )
    .await
    .map_err(|error| std::io::Error::other(error.to_string()))?;

    match response {
        RpcReply::Simple(reply) => Ok(reply.ok),
        RpcReply::Error(error) => Err(std::io::Error::other(error.error)),

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "policyd returned an unexpected reply for RegisterNetworkFlow",
        )),
    }
}
