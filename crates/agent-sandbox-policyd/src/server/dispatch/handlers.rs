//! RPC request handlers after context resolution.

use std::sync::Arc;

use agent_sandbox_core::{RegisterUiReply, RpcReply, RpcRequest, SimpleOkReply};

use crate::error::PolicydError;
use crate::server::peer::ClientPeer;
use crate::store::{PolicyStore, UiSessionOwner};
use crate::wire::{ElevationRequest, HostApproveRequest, MergeContext, PendingDecision, ScopeWire};

pub(crate) async fn handle(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    match req {
        RpcRequest::RegisterUi { ui_client, ctx } => {
            let ui_client = ui_client.as_deref().unwrap_or("standalone");
            let paths = ctx.sandbox_paths();
            let owner = (ui_client == "omp").then_some(UiSessionOwner {
                uid: peer.uid,
                pid: peer.pid,
            });
            let session_id = store
                .start_ui_session(
                    client,
                    ui_client,
                    owner,
                    paths.cwd_string(),
                    paths.home_string(),
                    paths.project_root_string(),
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
