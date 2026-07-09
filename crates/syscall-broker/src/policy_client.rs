use std::io;
use std::path::Path;
use std::time::Duration;

use agent_sandbox_core::{
    FileAccess, FilesystemCheckReply, ProcessIds, RequestContext, ResourceCheckReply, RpcReply,
    RpcRequest, SandboxPaths, policy_rpc,
};

use crate::{NetworkTarget, ResourceTarget};

fn request_context(pid: u32, sandbox_session_id: Option<String>) -> RequestContext {
    let mut ctx = RequestContext::from_paths_and_ids(
        &SandboxPaths::default(),
        ProcessIds::from_options(Some(pid), None),
    );
    ctx.sandbox_session_id = sandbox_session_id;
    ctx
}

pub async fn check_target(
    policy_socket: &Path,
    target: &NetworkTarget,
    sandbox_session_id: Option<String>,
    pid: u32,
    timeout: Duration,
) -> bool {
    let req = RpcRequest::Check {
        host: Some(target.host.clone()),
        connect_host: Some(target.connect_host.clone()),
        port: Some(target.port),
        scheme: target.scheme.clone(),
        url: Some(format!(
            "{}://{}:{}",
            target.scheme, target.host, target.port
        )),
        ctx: request_context(pid, sandbox_session_id),
    };
    matches!(
        policy_rpc(&policy_socket.display().to_string(), req, timeout).await,
        Ok(RpcReply::Check(reply)) if reply.allowed
    )
}

/// Ask policyd whether a resource-gated syscall is allowed.
///
/// Returns the `ResourceCheckReply` so the broker can distinguish a policy
/// denial from a policyd error and log the source label policyd attached to
/// the verdict.
///
/// # Errors
///
/// Returns an error if the RPC itself fails (policyd unreachable, timeout,
/// malformed reply). A policy denial is returned as `Ok(ResourceCheckReply {
/// allowed: false, .. })`, not as an error.
pub async fn check_resource(
    policy_socket: &Path,
    target: &ResourceTarget,
    sandbox_session_id: Option<String>,
    pid: u32,
    timeout: Duration,
) -> io::Result<ResourceCheckReply> {
    let req = RpcRequest::CheckResource {
        kind: target.kind,
        path: target.path.clone(),
        access: target.access,
        ctx: request_context(pid, sandbox_session_id),
    };
    match policy_rpc(&policy_socket.display().to_string(), req, timeout).await {
        Ok(RpcReply::ResourceCheck(reply)) => Ok(reply),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "policyd returned a non-ResourceCheck reply for CheckResource",
        )),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

/// Ask policyd whether a filesystem-gated syscall path/access pair is allowed.
///
/// Returns the `FilesystemCheckReply` so the broker can distinguish a policy
/// denial from a policyd error and log the source label policyd attached to
/// the verdict.
///
/// # Errors
///
/// Returns an error if the RPC itself fails (policyd unreachable, timeout,
/// malformed reply). A policy denial is returned as `Ok(FilesystemCheckReply {
/// allowed: false, .. })`, not as an error.
pub async fn check_filesystem(
    policy_socket: &Path,
    path: &Path,
    access: FileAccess,
    sandbox_session_id: Option<String>,
    pid: u32,
    timeout: Duration,
) -> io::Result<FilesystemCheckReply> {
    let req = RpcRequest::CheckFilesystem {
        path: path.to_path_buf(),
        access,
        ctx: request_context(pid, sandbox_session_id),
    };
    match policy_rpc(&policy_socket.display().to_string(), req, timeout).await {
        Ok(RpcReply::FilesystemCheck(reply)) => Ok(reply),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "policyd returned a non-FilesystemCheck reply for CheckFilesystem",
        )),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}
