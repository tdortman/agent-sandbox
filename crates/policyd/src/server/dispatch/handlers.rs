//! RPC request handlers after context resolution.

use std::path::PathBuf;
use std::sync::Arc;

use agent_sandbox_core::{
    ApprovalScope, RegisterUiReply, ResolvedRequestContext, RpcReply, SimpleOkReply,
    split_check_aliases,
};

use crate::error::PolicydError;
use crate::server::dispatch::check::{CheckArgs, handle_check};
use crate::server::dispatch::context::ResolvedRpcRequest;
use crate::server::peer::ClientPeer;
use crate::store::PolicyStore;
use crate::wire::{ElevationRequest, HostApproveRequest, PendingDecision, ScopeWire};

pub async fn handle(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    req: ResolvedRpcRequest,
) -> Result<RpcReply, PolicydError> {
    if is_proxy_request(&req) {
        return handle_proxy_request(store, client.id, req).await;
    }
    handle_non_proxy_request(store, client, peer, req).await
}

const fn is_proxy_request(req: &ResolvedRpcRequest) -> bool {
    matches!(
        req,
        ResolvedRpcRequest::OpenProxySession
            | ResolvedRpcRequest::RegisterNetworkFlow { .. }
            | ResolvedRpcRequest::ClaimNetworkFlow { .. }
            | ResolvedRpcRequest::CheckHttp { .. }
            | ResolvedRpcRequest::CheckNetworkFlow { .. }
            | ResolvedRpcRequest::CancelCheck { .. }
            | ResolvedRpcRequest::ReleaseNetworkFlow { .. }
    )
}

async fn handle_proxy_request(
    store: &Arc<PolicyStore>,
    client_id: u64,
    req: ResolvedRpcRequest,
) -> Result<RpcReply, PolicydError> {
    match req {
        ResolvedRpcRequest::OpenProxySession => Ok(RpcReply::ProxySession(
            store.open_proxy_session(client_id).await?,
        )),
        ResolvedRpcRequest::RegisterNetworkFlow { registration } => {
            store.register_network_flow(registration).await?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }
        ResolvedRpcRequest::ClaimNetworkFlow {
            proxy_session,
            flow,
            connection_id,
        } => Ok(RpcReply::FlowClaim(
            store
                .claim_network_flow(proxy_session, flow, connection_id)
                .await?,
        )),
        ResolvedRpcRequest::CheckHttp {
            proxy_session,
            request_id,
            attribution_token,
            request,
        } => Ok(RpcReply::HttpCheck(
            store
                .check_http(proxy_session, request_id, attribution_token, request)
                .await?,
        )),
        ResolvedRpcRequest::CheckNetworkFlow {
            proxy_session,
            request_id,
            attribution_token,
        } => Ok(RpcReply::Check(
            store
                .check_network_flow(proxy_session, request_id, attribution_token)
                .await?,
        )),
        ResolvedRpcRequest::CancelCheck {
            proxy_session,
            request_id,
        } => {
            store.cancel_check(proxy_session, request_id).await?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }
        ResolvedRpcRequest::ReleaseNetworkFlow {
            proxy_session,
            attribution_token,
        } => {
            store
                .release_network_flow(proxy_session, attribution_token)
                .await?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }
        _ => unreachable!("non-proxy request passed to proxy handler"),
    }
}

async fn handle_network_check(
    store: &Arc<PolicyStore>,
    args: CheckArgs,
) -> Result<RpcReply, PolicydError> {
    let CheckArgs {
        host,
        connect_host,
        port,
        scheme,
        url,
        ctx,
        ..
    } = args;
    let result = split_check_aliases(url);
    handle_check(
        store,
        CheckArgs {
            host,
            connect_host,
            port,
            scheme,
            url: result.url,
            aliases: result.aliases,
            ctx,
        },
    )
    .await
}

async fn handle_non_proxy_request(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    req: ResolvedRpcRequest,
) -> Result<RpcReply, PolicydError> {
    match req {
        ResolvedRpcRequest::RegisterUi { ctx } => {
            handle_register_ui(store, client, peer, ctx).await
        }
        ResolvedRpcRequest::UnregisterUi => {
            store.end_ui_session(client.id).await;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }
        ResolvedRpcRequest::Check {
            host,
            connect_host,
            port,
            scheme,
            url,
            ctx,
        } => {
            handle_network_check(
                store,
                CheckArgs {
                    host,
                    connect_host,
                    port,
                    scheme,
                    url,
                    aliases: Vec::new(),
                    ctx,
                },
            )
            .await
        }
        ResolvedRpcRequest::CheckFilesystem { path, access, ctx } => Ok(RpcReply::FilesystemCheck(
            store
                .check_filesystem(crate::wire::FilesystemCheckRequest { path, access, ctx })
                .await,
        )),
        ResolvedRpcRequest::CheckResource {
            kind,
            path,
            access,
            ctx,
        } => handle_check_resource(store, kind, path, access, ctx).await,
        ResolvedRpcRequest::CheckDbus { target, ctx } => Ok(RpcReply::DbusCheck(
            store
                .check_dbus(crate::wire::DbusCheckRequest { target, ctx })
                .await,
        )),
        ResolvedRpcRequest::StartFilesystemMonitor {
            peer_pid,
            ctx,
            static_allow,
        } => handle_start_filesystem_monitor(store, peer_pid, ctx, static_allow).await,
        req => handle_non_proxy_tail(store, client, peer, req).await,
    }
}

async fn handle_non_proxy_tail(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    req: ResolvedRpcRequest,
) -> Result<RpcReply, PolicydError> {
    match req {
        ResolvedRpcRequest::Elevate { argv, ctx } => handle_elevate_request(store, argv, ctx).await,
        ResolvedRpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx,
        } => Ok(store
            .approve(PendingDecision {
                pending_id: id,
                scope,
                target,
                wire: ScopeWire {
                    comment,
                    ..ScopeWire::from_resolved(&ctx, session_id)
                },
                client_id: client.id,
                approver_uid: (peer.uid > 0).then_some(peer.uid),
            })
            .await),
        ResolvedRpcRequest::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx,
        } => handle_approve_host(store, host, port, scope, session_id, ctx).await,
        ResolvedRpcRequest::ApproveHttp {
            target,
            scope,
            session_id,
            ctx,
        } => Ok(RpcReply::ScopeAction(
            store.approve_http(target, scope, session_id, ctx).await?,
        )),
        ResolvedRpcRequest::Deny {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx,
        } => Ok(store
            .deny(PendingDecision {
                pending_id: id,
                scope,
                target,
                wire: ScopeWire {
                    comment,
                    ..ScopeWire::from_resolved(&ctx, session_id)
                },
                client_id: client.id,
                approver_uid: (peer.uid > 0).then_some(peer.uid),
            })
            .await),
        ResolvedRpcRequest::Status { ctx } => Ok(RpcReply::Status(store.status(ctx).await)),
        ResolvedRpcRequest::Reload { ctx } => store
            .export_policy_files(ctx.paths)
            .map_err(PolicydError::from)
            .map(|()| RpcReply::Simple(SimpleOkReply::OK)),
        _ => unreachable!("proxy request passed to non-proxy handler"),
    }
}

async fn handle_check_resource(
    store: &Arc<PolicyStore>,
    kind: agent_sandbox_core::ResourceKind,
    path: PathBuf,
    access: agent_sandbox_core::ResourceAccess,
    ctx: ResolvedRequestContext,
) -> Result<RpcReply, PolicydError> {
    Ok(RpcReply::ResourceCheck(
        store
            .check_resource(crate::wire::ResourceCheckRequest {
                kind,
                path,
                access,
                ctx,
            })
            .await,
    ))
}

async fn handle_start_filesystem_monitor(
    store: &Arc<PolicyStore>,
    peer_pid: u32,
    ctx: ResolvedRequestContext,
    static_allow: Vec<agent_sandbox_core::FilesystemRule>,
) -> Result<RpcReply, PolicydError> {
    Ok(RpcReply::FilesystemMonitor(
        store
            .start_filesystem_monitor(crate::wire::FilesystemMonitorRequest {
                peer_pid,
                ctx,
                static_allow,
            })
            .await,
    ))
}

async fn handle_register_ui(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    ctx: ResolvedRequestContext,
) -> Result<RpcReply, PolicydError> {
    let paths = ctx.paths;
    let Some(sandbox_session_id) = ctx.sandbox_session_id else {
        return Err(PolicydError::UnauthorizedApprovalSession);
    };
    if peer.uid > 0 {
        let sessions = store.sandbox_sessions.read().ok();
        if let Some(reg) = sessions.as_ref().and_then(|s| s.get(&sandbox_session_id))
            && reg.owner_uid != peer.uid
        {
            return Err(PolicydError::UnauthorizedUiRegistration);
        }
    }
    let session_id = store
        .start_ui_session(
            client,
            peer,
            crate::store::UiSessionContext {
                cwd: paths.cwd_path(),
                home: paths.home_path(),
                project_root: paths.project_root_path(),
                sandbox_session_id: Some(sandbox_session_id),
                owner_uid: (peer.uid > 0).then_some(peer.uid),
                client_id: client.id,
            },
        )
        .await;
    if let Some(sess) = store.ui_context_for_session(&session_id).await
        && let Some(project_root) = &sess.project_root
    {
        tracing::info!(project_root = ?project_root, "policy UI registered");
    }
    Ok(RpcReply::RegisterUi(RegisterUiReply {
        ok: true,
        role: "ui".into(),
        session_id,
    }))
}

async fn handle_elevate_request(
    store: &Arc<PolicyStore>,
    argv: Vec<String>,
    ctx: ResolvedRequestContext,
) -> Result<RpcReply, PolicydError> {
    if argv.is_empty() {
        return Err(PolicydError::ArgvRequired);
    }
    Ok(RpcReply::Elevate(
        store
            .request_elevation(ElevationRequest { argv, ctx })
            .await,
    ))
}

async fn handle_approve_host(
    store: &Arc<PolicyStore>,
    host: String,
    port: u16,
    scope: ApprovalScope,
    session_id: Option<String>,
    ctx: ResolvedRequestContext,
) -> Result<RpcReply, PolicydError> {
    if port == 0 {
        return Err(PolicydError::PortRequired);
    }
    Ok(store
        .approve_host(HostApproveRequest {
            host,
            port,
            scope,
            session_id,
            ctx,
        })
        .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PolicydError;
    use crate::store::{PolicyStore, PolicydArgs, TrustedPeer};
    use agent_sandbox_core::{ProcessIds, SandboxPaths};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    fn test_store() -> PolicyStore {
        PolicyStore::new(PolicydArgs {
            host_socket: "/tmp/test.sock".into(),
            sandbox_socket: "/tmp/test-sandbox.sock".into(),
            declarative: "/tmp/declarative.json".into(),
            export_json: "/tmp/export.json".into(),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
            proxy_socket: None,
            proxy_gid: None,
        })
    }

    fn writer() -> Arc<Mutex<tokio::net::unix::OwnedWriteHalf>> {
        Arc::new(Mutex::new(
            UnixStream::pair()
                .expect("unix stream pair")
                .0
                .into_split()
                .1,
        ))
    }

    #[tokio::test]
    async fn register_ui_rejects_cross_uid_peer() {
        let store = Arc::new(test_store());
        store.note_sandbox_peer(
            TrustedPeer {
                pid: 100,
                uid: 1000,
            },
            "sandbox-a",
        );
        let handle = PolicyStore::new_client_handle(writer());
        let result = handle_register_ui(
            &store,
            &handle,
            ClientPeer {
                pid: 200,
                uid: 2000,
                gid: 0,
            },
            ResolvedRequestContext::new(
                SandboxPaths::default(),
                ProcessIds::default(),
                Some("sandbox-a".into()),
            ),
        )
        .await;
        assert!(
            matches!(result, Err(PolicydError::UnauthorizedUiRegistration)),
            "cross-uid RegisterUi must be rejected, got: {result:?}"
        );
    }
}
