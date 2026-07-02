//! RPC request handlers after context resolution.

use std::path::PathBuf;
use std::sync::Arc;

use agent_sandbox_core::{
    ApprovalScope, RegisterUiReply, RequestContext, RpcReply, RpcRequest, SimpleOkReply,
    split_check_aliases,
};

use crate::error::PolicydError;
use crate::server::dispatch::check::{CheckArgs, handle_check};
use crate::server::peer::ClientPeer;
use crate::store::PolicyStore;
use crate::wire::{ElevationRequest, HostApproveRequest, MergeContext, PendingDecision, ScopeWire};

pub async fn handle(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    match req {
        RpcRequest::RegisterUi { ui_client: _, ctx } => {
            handle_register_ui(store, client, ctx).await
        }
        RpcRequest::UnregisterUi => {
            store.end_ui_session(client.id).await;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }
        RpcRequest::Check {
            host,
            connect_host,
            port,
            scheme,
            url,
            ctx,
        } => {
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
        RpcRequest::CheckFilesystem { path, access, ctx } => Ok(RpcReply::FilesystemCheck(
            store
                .check_filesystem(crate::wire::FilesystemCheckRequest {
                    path,
                    access,
                    ctx: MergeContext::from(&ctx),
                })
                .await,
        )),
        RpcRequest::CheckResource {
            kind,
            path,
            access,
            ctx,
        } => handle_check_resource(store, kind, path, access, ctx).await,
        RpcRequest::StartFilesystemMonitor { ctx, static_allow } => {
            handle_start_filesystem_monitor(store, peer, ctx, static_allow).await
        }
        RpcRequest::Elevate { argv, ctx } => handle_elevate_request(store, argv, ctx).await,
        RpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            ctx,
        } => Ok(store
            .approve(PendingDecision {
                pending_id: id,
                scope,
                target,
                wire: ScopeWire::from_request(&ctx, session_id),
            })
            .await),
        RpcRequest::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx,
        } => handle_approve_host(store, host, port, scope, session_id, ctx).await,
        RpcRequest::Deny {
            id,
            scope,
            session_id,
            target,
            ctx,
        } => Ok(store
            .deny(PendingDecision {
                pending_id: id,
                scope,
                target,
                wire: ScopeWire::from_request(&ctx, session_id),
            })
            .await),
        RpcRequest::Status { ctx } => {
            let body = store.status(ctx.sandbox_paths()).await;
            Ok(RpcReply::Status(body))
        }
        RpcRequest::Reload { ctx } => {
            store.export_policy_files(ctx.sandbox_paths())?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }
    }
}
async fn handle_check_resource(
    store: &Arc<PolicyStore>,
    kind: agent_sandbox_core::ResourceKind,
    path: PathBuf,
    access: agent_sandbox_core::ResourceAccess,
    ctx: RequestContext,
) -> Result<RpcReply, PolicydError> {
    Ok(RpcReply::ResourceCheck(
        store
            .check_resource(crate::wire::ResourceCheckRequest {
                kind,
                path,
                access,
                ctx: MergeContext::from(&ctx),
            })
            .await,
    ))
}
async fn handle_start_filesystem_monitor(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    ctx: RequestContext,
    static_allow: Vec<agent_sandbox_core::FilesystemRule>,
) -> Result<RpcReply, PolicydError> {
    let peer_pid = peer.pid;
    Ok(RpcReply::FilesystemMonitor(
        store
            .start_filesystem_monitor(crate::wire::FilesystemMonitorRequest {
                peer_pid,
                ctx: MergeContext::from(&ctx),
                static_allow,
            })
            .await,
    ))
}
async fn handle_register_ui(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    ctx: RequestContext,
) -> Result<RpcReply, PolicydError> {
    let paths = ctx.sandbox_paths();
    let Some(sandbox_session_id) = ctx.sandbox_session_id else {
        return Err(PolicydError::UnauthorizedApprovalSession);
    };
    let session_id = store
        .start_ui_session(
            client,
            crate::store::UiSessionContext {
                cwd: paths.cwd_path(),
                home: paths.home_path(),
                project_root: paths.project_root_path(),
                sandbox_session_id: Some(sandbox_session_id),
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
    ctx: RequestContext,
) -> Result<RpcReply, PolicydError> {
    if argv.is_empty() {
        return Err(PolicydError::ArgvRequired);
    }
    Ok(RpcReply::Elevate(
        store
            .request_elevation(ElevationRequest {
                argv,
                ctx: MergeContext::from(&ctx),
            })
            .await,
    ))
}

async fn handle_approve_host(
    store: &Arc<PolicyStore>,
    host: String,
    port: u16,
    scope: ApprovalScope,
    session_id: Option<String>,
    ctx: RequestContext,
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
            ctx: MergeContext::from(&ctx),
        })
        .await)
}
