//! Resolve request context from an incoming RPC.

use std::{path::PathBuf, sync::Arc};

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, AttributionToken, FileAccess, FilesystemRule, FlowRegistration,
    HttpRequest, HttpRuleTarget, NetworkFlowKey, ProxyConnectionId, ProxyRequestId,
    ProxySessionToken, RequestContext, ResolvedRequestContext, ResourceAccess, ResourceKind,
    RpcRequest,
};

use crate::{
    server::{dispatch::SocketRole, peer::ClientPeer},
    store::{PolicyStore, TrustedPeer},
};

pub(super) enum ResolvedRpcRequest {
    RegisterUi {
        ctx: ResolvedRequestContext,
    },
    UnregisterUi,

    OpenProxySession,
    RegisterNetworkFlow {
        registration: FlowRegistration,
    },
    ClaimNetworkFlow {
        proxy_session: ProxySessionToken,
        flow: NetworkFlowKey,
        connection_id: ProxyConnectionId,
    },
    CheckHttp {
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
        request: HttpRequest,
    },
    CheckNetworkFlow {
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
    },
    CancelCheck {
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
    },
    ReleaseNetworkFlow {
        proxy_session: ProxySessionToken,
        attribution_token: AttributionToken,
    },
    Check {
        host: Option<String>,
        connect_host: Option<String>,
        port: Option<u16>,
        scheme: String,
        url: Option<String>,
        ctx: ResolvedRequestContext,
    },
    CheckFilesystem {
        path: PathBuf,
        access: FileAccess,
        ctx: ResolvedRequestContext,
    },
    CheckResource {
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        ctx: ResolvedRequestContext,
    },
    CheckDbus {
        target: agent_sandbox_core::DbusTarget,
        ctx: ResolvedRequestContext,
    },
    StartFilesystemMonitor {
        peer_pid: u32,
        ctx: ResolvedRequestContext,
        static_allow: Vec<FilesystemRule>,
    },
    Elevate {
        argv: Vec<String>,
        ctx: ResolvedRequestContext,
    },
    Approve {
        id: String,
        scope: ApprovalScope,
        session_id: Option<String>,
        target: Option<ApprovalTarget>,
        comment: Option<String>,
        ctx: ResolvedRequestContext,
    },
    ApproveHost {
        host: String,
        port: u16,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: ResolvedRequestContext,
    },
    ApproveHttp {
        target: HttpRuleTarget,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: ResolvedRequestContext,
    },
    Deny {
        id: String,
        scope: ApprovalScope,
        session_id: Option<String>,
        target: Option<ApprovalTarget>,
        comment: Option<String>,
        ctx: ResolvedRequestContext,
    },
    Status {
        ctx: ResolvedRequestContext,
    },
    Reload {
        ctx: ResolvedRequestContext,
    },
}

fn resolve_request_context(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    role: SocketRole,

    ctx: &RequestContext,
) -> ResolvedRequestContext {
    if role == SocketRole::Sandbox
        && let Some(sandbox_session_id) = ctx.sandbox_session_id.clone()
    {
        store.note_sandbox_peer(
            TrustedPeer {
                pid: peer.pid,
                uid: peer.uid,
            },
            &sandbox_session_id,
        );
    }
    let mc = crate::wire::MergeContext::from(ctx);
    store.resolve_context_with_peer(
        &mc,
        Some(TrustedPeer {
            pid: peer.pid,
            uid: peer.uid,
        }),
    )
}

fn plan_simple(req: RpcRequest) -> Result<ResolvedRpcRequest, Box<RpcRequest>> {
    match req {
        RpcRequest::UnregisterUi => Ok(ResolvedRpcRequest::UnregisterUi),
        RpcRequest::OpenProxySession => Ok(ResolvedRpcRequest::OpenProxySession),
        RpcRequest::RegisterNetworkFlow { registration } => {
            Ok(ResolvedRpcRequest::RegisterNetworkFlow { registration })
        }
        RpcRequest::ClaimNetworkFlow {
            proxy_session,
            flow,
            connection_id,
        } => Ok(ResolvedRpcRequest::ClaimNetworkFlow {
            proxy_session,
            flow,
            connection_id,
        }),
        RpcRequest::CheckHttp {
            proxy_session,
            request_id,
            attribution_token,
            request,
        } => Ok(ResolvedRpcRequest::CheckHttp {
            proxy_session,
            request_id,
            attribution_token,
            request,
        }),
        RpcRequest::CheckNetworkFlow {
            proxy_session,
            request_id,
            attribution_token,
        } => Ok(ResolvedRpcRequest::CheckNetworkFlow {
            proxy_session,
            request_id,
            attribution_token,
        }),
        RpcRequest::CancelCheck {
            proxy_session,
            request_id,
        } => Ok(ResolvedRpcRequest::CancelCheck {
            proxy_session,
            request_id,
        }),
        RpcRequest::ReleaseNetworkFlow {
            proxy_session,
            attribution_token,
        } => Ok(ResolvedRpcRequest::ReleaseNetworkFlow {
            proxy_session,
            attribution_token,
        }),
        req => Err(Box::new(req)),
    }
}

fn plan_approval_context(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> Result<ResolvedRpcRequest, Box<RpcRequest>> {
    let resolve = |ctx: RequestContext| resolve_request_context(store, peer, role, &ctx);
    match req {
        RpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx,
        } => Ok(ResolvedRpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx: resolve(ctx),
        }),
        RpcRequest::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx,
        } => Ok(ResolvedRpcRequest::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx: resolve(ctx),
        }),
        RpcRequest::ApproveHttp {
            target,
            scope,
            session_id,
            ctx,
        } => Ok(ResolvedRpcRequest::ApproveHttp {
            target,
            scope,
            session_id,
            ctx: resolve(ctx),
        }),
        RpcRequest::Deny {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx,
        } => Ok(ResolvedRpcRequest::Deny {
            id,
            scope,
            session_id,
            target,
            comment,
            ctx: resolve(ctx),
        }),
        req => Err(Box::new(req)),
    }
}

fn plan_context(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> ResolvedRpcRequest {
    let req = match plan_approval_context(store, peer, role, req) {
        Ok(resolved) => return resolved,
        Err(req) => *req,
    };
    let resolve = |ctx: RequestContext| resolve_request_context(store, peer, role, &ctx);
    match req {
        RpcRequest::RegisterUi { ui_client: _, ctx } => {
            ResolvedRpcRequest::RegisterUi { ctx: resolve(ctx) }
        }
        RpcRequest::Check {
            host,
            connect_host,
            port,
            scheme,
            url,
            ctx,
        } => ResolvedRpcRequest::Check {
            host,
            connect_host,
            port,
            scheme,
            url,
            ctx: resolve(ctx),
        },
        RpcRequest::CheckFilesystem { path, access, ctx } => ResolvedRpcRequest::CheckFilesystem {
            path,
            access,
            ctx: resolve(ctx),
        },
        RpcRequest::CheckResource {
            kind,
            path,
            access,
            ctx,
        } => ResolvedRpcRequest::CheckResource {
            kind,
            path,
            access,
            ctx: resolve(ctx),
        },
        RpcRequest::CheckDbus { target, ctx } => {
            let ctx = if role == SocketRole::Host {
                crate::store::PolicyStore::resolve_dbus_proxy_context(
                    &crate::wire::MergeContext::from(&ctx),
                    TrustedPeer {
                        pid: peer.pid,
                        uid: peer.uid,
                    },
                )
            } else {
                resolve(ctx)
            };
            ResolvedRpcRequest::CheckDbus { target, ctx }
        }
        RpcRequest::StartFilesystemMonitor { ctx, static_allow } => {
            let ctx = resolve(ctx);
            let peer_pid = if peer.pid > 0 {
                peer.pid
            } else {
                ctx.ids.pid().unwrap_or(0)
            };
            ResolvedRpcRequest::StartFilesystemMonitor {
                peer_pid,
                ctx,
                static_allow,
            }
        }
        RpcRequest::Elevate { argv, ctx } => ResolvedRpcRequest::Elevate {
            argv,
            ctx: resolve(ctx),
        },
        RpcRequest::Status { ctx } => ResolvedRpcRequest::Status { ctx: resolve(ctx) },
        RpcRequest::Reload { ctx } => ResolvedRpcRequest::Reload { ctx: resolve(ctx) },
        req => unreachable!("unhandled non-context request: {req:?}"),
    }
}

pub fn plan(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> ResolvedRpcRequest {
    match plan_simple(req) {
        Ok(req) => req,
        Err(req) => plan_context(store, peer, role, *req),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use agent_sandbox_core::{
        FileAccess, ProcessIds, RequestContext, ResolvedRequestContext, RpcRequest, home_from_uid,
    };

    use super::{ResolvedRpcRequest, plan};
    use crate::{
        server::{dispatch::SocketRole, peer::ClientPeer},
        store::PolicyStore,
    };

    fn test_store(dir: &tempfile::TempDir) -> Arc<PolicyStore> {
        Arc::new(PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("policy.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            true,
        )))
    }

    #[test]
    fn sandbox_dispatch_plans_trusted_context_before_handlers_run() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let store = test_store(&dir);
        let peer_pid = std::process::id();
        let socket_uid = match nix::unistd::getuid().as_raw() {
            0 => 1,
            uid => uid,
        };
        let expected_home = home_from_uid(Some(socket_uid)).map(PathBuf::from);
        let req = RpcRequest::CheckFilesystem {
            path: "/tmp/allowed".into(),
            access: FileAccess::Read,
            ctx: RequestContext {
                cwd: Some("/attacker/cwd".into()),
                home: Some("/attacker/home".into()),
                project_root: Some("/attacker/project".into()),
                pid: Some(peer_pid.saturating_add(10_000)),
                uid: Some(socket_uid.saturating_add(1)),
                sandbox_session_id: Some("sandbox-a".into()),
            },
        };

        let ResolvedRpcRequest::CheckFilesystem { ctx, .. } = plan(
            &store,
            ClientPeer {
                pid: peer_pid,
                uid: socket_uid,
                gid: 0,
            },
            SocketRole::Sandbox,
            req,
        ) else {
            panic!("expected planned filesystem request");
        };

        assert_eq!(ctx.ids, ProcessIds::new(peer_pid, socket_uid));
        assert_eq!(ctx.paths.home_path(), expected_home);
        assert_ne!(ctx.paths.home(), Some(Path::new("/attacker/home")));
        assert_ne!(
            ctx.paths.project_root(),
            Some(Path::new("/attacker/project"))
        );
        assert_eq!(ctx.sandbox_session_id.as_deref(), Some("sandbox-a"));

        let rehydrated =
            ResolvedRequestContext::new(ctx.paths.clone(), ctx.ids, ctx.sandbox_session_id);
        assert_eq!(rehydrated.ids, ProcessIds::new(peer_pid, socket_uid));
        assert_eq!(rehydrated.paths.home_path(), expected_home);
        assert_ne!(rehydrated.paths.home(), Some(Path::new("/attacker/home")));
        assert_eq!(rehydrated.sandbox_session_id.as_deref(), Some("sandbox-a"));
    }
}
