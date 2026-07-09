//! Resolve request context from an incoming RPC.

use std::path::PathBuf;
use std::sync::Arc;

use agent_sandbox_core::{
    ApprovalScope, ApprovalTarget, FileAccess, FilesystemRule, RequestContext,
    ResolvedRequestContext, ResourceAccess, ResourceKind, RpcRequest,
};

use crate::server::dispatch::SocketRole;
use crate::server::peer::ClientPeer;
use crate::store::{PolicyStore, TrustedPeer};

pub(super) enum ResolvedRpcRequest {
    RegisterUi {
        ctx: ResolvedRequestContext,
    },
    UnregisterUi,
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
        ctx: ResolvedRequestContext,
    },
    ApproveHost {
        host: String,
        port: u16,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: ResolvedRequestContext,
    },
    Deny {
        id: String,
        scope: ApprovalScope,
        session_id: Option<String>,
        target: Option<ApprovalTarget>,
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

pub fn plan(
    store: &Arc<PolicyStore>,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> ResolvedRpcRequest {
    match req {
        RpcRequest::RegisterUi { ui_client: _, ctx } => ResolvedRpcRequest::RegisterUi {
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::UnregisterUi => ResolvedRpcRequest::UnregisterUi,
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
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::CheckFilesystem { path, access, ctx } => ResolvedRpcRequest::CheckFilesystem {
            path,
            access,
            ctx: resolve_request_context(store, peer, role, &ctx),
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
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::StartFilesystemMonitor { ctx, static_allow } => {
            let ctx = resolve_request_context(store, peer, role, &ctx);
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
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            ctx,
        } => ResolvedRpcRequest::Approve {
            id,
            scope,
            session_id,
            target,
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx,
        } => ResolvedRpcRequest::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::Deny {
            id,
            scope,
            session_id,
            target,
            ctx,
        } => ResolvedRpcRequest::Deny {
            id,
            scope,
            session_id,
            target,
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::Status { ctx } => ResolvedRpcRequest::Status {
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
        RpcRequest::Reload { ctx } => ResolvedRpcRequest::Reload {
            ctx: resolve_request_context(store, peer, role, &ctx),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{ResolvedRpcRequest, plan};
    use crate::server::{ClientPeer, dispatch::SocketRole};
    use crate::store::{PolicyStore, PolicydArgs};
    use agent_sandbox_core::{
        FileAccess, ProcessIds, RequestContext, ResolvedRequestContext, RpcRequest, home_from_uid,
    };
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    fn test_store(dir: &tempfile::TempDir) -> Arc<PolicyStore> {
        Arc::new(PolicyStore::new(PolicydArgs {
            host_socket: dir.path().join("host.sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("policy.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        }))
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
