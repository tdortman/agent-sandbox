//! RPC request handlers after context resolution.

use std::sync::Arc;

use agent_sandbox_core::{RegisterUiReply, RpcReply, RpcRequest, SimpleOkReply};

use crate::error::PolicydError;
use crate::server::peer::ClientPeer;
use crate::store::PolicyStore;
use crate::wire::{ElevationRequest, HostApproveRequest, MergeContext, PendingDecision, ScopeWire};

pub(crate) async fn handle(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    match req {
        RpcRequest::RegisterUi { ui_client: _, ctx } => {
            let paths = ctx.sandbox_paths();
            let session_id = store
                .start_ui_session(
                    client,
                    crate::store::UiSessionContext {
                        cwd: paths.cwd_string(),
                        home: paths.home_string(),
                        project_root: paths.project_root_string(),
                        sandbox_session_id: ctx.sandbox_session_id,
                    },
                )
                .await;
            if let Some(sess) = store.ui_context_for_session(&session_id).await
                && let Some(project_root) = &sess.project_root
            {
                tracing::info!(project_root = %project_root, "policy UI registered");
            }
            Ok(RpcReply::RegisterUi(RegisterUiReply {
                ok: true,
                role: "ui".into(),
                session_id,
            }))
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
        } => super::check::handle_check(store, host, connect_host, port, scheme, url, ctx).await,
        RpcRequest::CheckFilesystem { path, access, ctx } => Ok(RpcReply::FilesystemCheck(
            store
                .check_filesystem(crate::wire::FilesystemCheckRequest {
                    path,
                    access,
                    ctx: MergeContext::from(&ctx),
                })
                .await,
        )),
        RpcRequest::StartFilesystemMonitor { ctx, static_allow } => {
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
        RpcRequest::Elevate { argv, ctx } => {
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
        } => {
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
            store.export_policy_files(ctx.sandbox_paths()).await?;
            Ok(RpcReply::Simple(SimpleOkReply::OK))
        }
    }
}
