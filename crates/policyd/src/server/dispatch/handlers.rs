//! RPC request handlers after context resolution.

use std::{path::PathBuf, sync::Arc};

use agent_sandbox_core::{
    ApprovalScope, RegisterUiReply, RequestContext, ResolvedRequestContext, RpcReply, RpcRequest,
    SimpleOkReply, split_check_aliases,
};

use crate::{
    error::PolicydError,
    server::{
        dispatch::{
            SocketRole,
            check::{CheckArgs, handle_check},
            context,
        },
        peer::ClientPeer,
    },
    store::{DecisionAction, PolicyStore, TrustedPeer, UiClientHandle},
    wire::{ElevationRequest, HostApproveRequest, MergeContext, PendingDecision, ScopeWire},
};

pub async fn handle(
    store: &Arc<PolicyStore>,
    client: &UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    if is_proxy_request(&req) {
        return handle_proxy_request(store, client.id, req).await;
    }

    handle_non_proxy_request(store, client, peer, role, req).await
}

const fn is_proxy_request(req: &RpcRequest) -> bool {
    matches!(
        req,
        RpcRequest::OpenProxySession
            | RpcRequest::RegisterNetworkFlow { .. }
            | RpcRequest::ClaimNetworkFlow { .. }
            | RpcRequest::ClaimNetworkFlowBySource { .. }
            | RpcRequest::RebindNetworkFlow { .. }
            | RpcRequest::CheckHttp { .. }
            | RpcRequest::CheckNetworkFlow { .. }
            | RpcRequest::CancelCheck { .. }
            | RpcRequest::ReleaseNetworkFlow { .. }
    )
}

async fn handle_proxy_request(
    store: &Arc<PolicyStore>,
    client_id: u64,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    match req {
        RpcRequest::OpenProxySession => Ok(RpcReply::ProxySession(
            store.open_proxy_session(client_id).await?,
        )),

        RpcRequest::RegisterNetworkFlow { registration } => {
            store.register_network_flow(registration).await?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }

        RpcRequest::ClaimNetworkFlow {
            proxy_session,
            flow,
            connection_id,
        } => Ok(RpcReply::FlowClaim(
            store
                .claim_network_flow(proxy_session, flow, connection_id)
                .await?,
        )),

        RpcRequest::ClaimNetworkFlowBySource {
            proxy_session,
            selector,
            connection_id,
        } => Ok(RpcReply::FlowClaim(
            store
                .claim_network_flow_by_source(proxy_session, selector, connection_id)
                .await?,
        )),

        RpcRequest::RebindNetworkFlow {
            proxy_session,
            attribution_token,
            connection_id,
            flow,
        } => {
            store
                .rebind_network_flow(proxy_session, attribution_token, connection_id, flow)
                .await?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }

        RpcRequest::CheckHttp {
            proxy_session,
            request_id,
            attribution_token,
            request,
        } => Ok(RpcReply::HttpCheck(
            store
                .check_http(proxy_session, request_id, attribution_token, request)
                .await?,
        )),

        RpcRequest::CheckNetworkFlow {
            proxy_session,
            request_id,
            attribution_token,
        } => Ok(RpcReply::Check(
            store
                .check_network_flow(proxy_session, request_id, attribution_token)
                .await?,
        )),

        RpcRequest::CancelCheck {
            proxy_session,
            request_id,
        } => {
            store.cancel_check(proxy_session, request_id).await?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }

        RpcRequest::ReleaseNetworkFlow {
            proxy_session,
            attribution_token,
            connection_id,
        } => {
            store
                .release_network_flow(proxy_session, attribution_token, connection_id)
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

    handle_check(store, CheckArgs {
        host,
        connect_host,
        port,
        scheme,
        url: result.url,
        aliases: result.aliases,
        ctx,
    })
    .await
}

async fn handle_non_proxy_request(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    let resolve = |ctx: &RequestContext| context::resolve_request_context(store, peer, role, ctx);

    match req {
        RpcRequest::RegisterUi { ui_client: _, ctx } => {
            handle_register_ui(store, client, peer, resolve(&ctx)).await
        }

        RpcRequest::UnregisterUi => {
            store.end_ui_session(client.id).await;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }

        RpcRequest::RegisterSandbox {
            session_id,
            package,
            launcher_pid,
        } => store
            .register_sandbox(&session_id, &package, peer.uid, launcher_pid, peer.pid)
            .map(|()| RpcReply::Simple(SimpleOkReply::OK)),

        RpcRequest::Check {
            host,
            connect_host,
            port,
            scheme,
            url,
            ctx,
        } => {
            handle_network_check(store, CheckArgs {
                host,
                connect_host,
                port,
                scheme,
                url,
                aliases: Vec::new(),
                ctx: resolve(&ctx),
            })
            .await
        }

        RpcRequest::CheckFilesystem { path, access, ctx } => Ok(RpcReply::FilesystemCheck(
            store
                .check_filesystem(crate::wire::FilesystemCheckRequest {
                    path,
                    access,
                    ctx: resolve(&ctx),
                })
                .await,
        )),

        RpcRequest::CheckResource {
            kind,
            path,
            access,
            ctx,
        } => handle_check_resource(store, kind, path, access, resolve(&ctx)).await,

        RpcRequest::CheckDbus { target, ctx } => {
            let ctx = if role == SocketRole::Host {
                store.resolve_dbus_proxy_context(&MergeContext::from(&ctx), TrustedPeer {
                    pid: peer.pid,
                    uid: peer.uid,
                })
            } else {
                resolve(&ctx)
            };
            Ok(RpcReply::DbusCheck(
                store
                    .check_dbus(crate::wire::DbusCheckRequest { target, ctx })
                    .await,
            ))
        }

        RpcRequest::StartFilesystemMonitor { ctx, static_allow } => {
            let ctx = resolve(&ctx);
            let peer_pid = if peer.pid > 0 {
                peer.pid
            } else {
                ctx.ids.pid().unwrap_or(0)
            };
            handle_start_filesystem_monitor(store, peer_pid, ctx, static_allow).await
        }

        req => handle_non_proxy_tail(store, client, peer, role, req).await,
    }
}

async fn handle_non_proxy_tail(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    let resolve = |ctx: &RequestContext| context::resolve_request_context(store, peer, role, ctx);

    match req {
        RpcRequest::Elevate { argv, ctx } => {
            handle_elevate_request(store, argv, resolve(&ctx)).await
        }

        RpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx,
        } => Ok(store
            .apply_pending_decision(
                PendingDecision {
                    pending_id: id,
                    scope,
                    target,
                    wire: ScopeWire {
                        comment,
                        ..ScopeWire::from_resolved(&resolve(&ctx), session_id)
                    },
                    client_id: client.id,
                    approver_uid: (peer.uid > 0).then_some(peer.uid),
                },
                DecisionAction::Approve,
            )
            .await),

        RpcRequest::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx,
        } => handle_approve_host(store, host, port, scope, session_id, resolve(&ctx)).await,

        RpcRequest::ApproveHttp {
            target,
            scope,
            session_id,
            ctx,
        } => Ok(RpcReply::ScopeAction(
            store
                .approve_http(target, scope, session_id, resolve(&ctx))
                .await?,
        )),

        RpcRequest::Deny {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx,
        } => Ok(store
            .apply_pending_decision(
                PendingDecision {
                    pending_id: id,
                    scope,
                    target,
                    wire: ScopeWire {
                        comment,
                        ..ScopeWire::from_resolved(&resolve(&ctx), session_id)
                    },
                    client_id: client.id,
                    approver_uid: (peer.uid > 0).then_some(peer.uid),
                },
                DecisionAction::Deny,
            )
            .await),

        RpcRequest::Status { ctx } => Ok(RpcReply::Status(store.status(resolve(&ctx)).await)),

        RpcRequest::Reload { ctx } => store
            .export_policy_files(resolve(&ctx).paths)
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
        .start_ui_session(client, peer, crate::store::UiSessionContext {
            cwd: paths.cwd_path(),
            home: paths.home_path(),
            project_root: paths.project_root_path(),
            sandbox_session_id: Some(sandbox_session_id),
            owner_uid: (peer.uid > 0).then_some(peer.uid),
            client_id: client.id,
        })
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
    use std::sync::Arc;

    use agent_sandbox_core::{ProcessIds, SandboxPaths};
    use tokio::{net::UnixStream, sync::Mutex};

    use super::*;
    use crate::{
        error::PolicydError,
        store::{PolicyStore, TrustedPeer, test_store},
    };

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
