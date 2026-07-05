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
            handle_register_ui(store, client, peer, ctx).await
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
                client_id: client.id,
                approver_uid: (peer.uid > 0).then_some(peer.uid),
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
                client_id: client.id,
                approver_uid: (peer.uid > 0).then_some(peer.uid),
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
    // Prefer the SO_PEERCRED pid: the kernel translates it into policyd's
    // pid namespace. `ctx.pid` is the client's own `getpid()`, which inside
    // a `--unshare-pid` sandbox is a namespace-local pid (typically 1).
    // Using it verbatim would make fsmon setns into /proc/1/ns/mnt — the
    // HOST mount namespace — and mark every host mount.
    let monitor_pid = if peer.pid > 0 {
        peer.pid
    } else {
        ctx.pid.unwrap_or(0)
    };
    Ok(RpcReply::FilesystemMonitor(
        store
            .start_filesystem_monitor(crate::wire::FilesystemMonitorRequest {
                peer_pid: monitor_pid,
                ctx: MergeContext::from(&ctx),
                static_allow,
            })
            .await,
    ))
}
async fn handle_register_ui(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    ctx: RequestContext,
) -> Result<RpcReply, PolicydError> {
    let paths = ctx.sandbox_paths();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PolicydError;
    use crate::store::{PolicyStore, PolicydArgs, TrustedPeer};
    use agent_sandbox_core::RequestContext;
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
            RequestContext {
                sandbox_session_id: Some("sandbox-a".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(
            matches!(result, Err(PolicydError::UnauthorizedUiRegistration)),
            "cross-uid RegisterUi must be rejected, got: {result:?}"
        );
    }
}
