//! Policy RPC client for NFQUEUE, calls policyd's `Check` endpoint.

use std::time::Duration;

use agent_sandbox_core::{
    FlowRegistration, ProcessIds, RequestContext, RpcReply, RpcRequest, SandboxPaths,
    attach_check_aliases, policy_rpc,
};

use crate::packet::TransportProtocol;

/// Result of a policy check for a queued packet.
pub struct PolicyResult(pub bool);

struct PolicyContext {
    paths: SandboxPaths,
    ids: ProcessIds,
}

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
) -> std::io::Result<PolicyResult> {
    let ctx = resolve_context(args.src_pid);
    let scheme = args.protocol.as_str();
    let url = format!("{scheme}://{}:{}", args.hostname, args.dst_port);
    let req = RpcRequest::Check {
        host: Some(args.hostname.to_string()),
        connect_host: Some(args.dst_ip.to_string()),
        port: Some(args.dst_port),
        scheme: scheme.to_string(),
        url: attach_check_aliases(Some(url), args.aliases),
        ctx: request_context(
            &ctx.paths,
            ctx.ids,
            args.src_pid
                .and_then(agent_sandbox_core::sandbox_session_id_from_pid),
        ),
    };

    let resp = policy_rpc(socket, req, timeout)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let allowed = matches!(resp, RpcReply::Check(check) if check.allowed);
    Ok(PolicyResult(allowed))
}

/// Register one owner-identified flow with policyd before proxy forwarding.
///
/// Registration is deliberately separate from transport `Check`: proxy mode
/// asks policyd to validate the typed owner snapshot and stores the flow for
/// mitmproxy to claim later. Any malformed reply is an RPC failure and must be
/// treated as a failed registration by callers.
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
/// Resolve sandbox paths and process IDs from a PID by reading
/// `/proc/<pid>/environ`.
fn resolve_context(pid: Option<u32>) -> PolicyContext {
    let pid = pid.unwrap_or(0);
    let uid = pid_uid(pid).unwrap_or(0);

    let ids = ProcessIds::new(pid, uid);
    let paths = agent_sandbox_core::resolve_daemon_paths(ids);
    agent_sandbox_core::persist_session_paths(&paths);
    PolicyContext { paths, ids }
}

fn request_context(
    paths: &SandboxPaths,
    ids: ProcessIds,
    sandbox_session_id: Option<String>,
) -> RequestContext {
    let mut ctx = RequestContext::from_paths_and_ids(paths, ids);
    ctx.sandbox_session_id = sandbox_session_id;
    ctx
}

/// Read the UID of a process from `/proc/<pid>/status`.
fn pid_uid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            return parts.first().and_then(|s| s.parse().ok());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use agent_sandbox_core::{ProcessIds, SandboxPaths};

    use super::request_context;

    #[test]
    fn request_context_preserves_sandbox_session_id() {
        let paths = SandboxPaths::new("/work", "/home/user", "/work");
        let ctx = request_context(&paths, ProcessIds::new(0, 1000), Some("s1".into()));

        assert_eq!(ctx.sandbox_session_id.as_deref(), Some("s1"));
        assert_eq!(ctx.cwd.as_deref(), Some(Path::new("/work")));
        assert_eq!(ctx.home.as_deref(), Some(Path::new("/home/user")));
        assert_eq!(ctx.project_root.as_deref(), Some(Path::new("/work")));
    }
}
