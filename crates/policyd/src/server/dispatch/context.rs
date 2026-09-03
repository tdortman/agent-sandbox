//! Resolve request context from an incoming RPC.

use std::sync::Arc;

use agent_sandbox_core::{RequestContext, ResolvedRequestContext};

use crate::{
    server::{dispatch::SocketRole, peer::ClientPeer},
    store::{PolicyStore, TrustedPeer},
};

pub(super) fn resolve_request_context(
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

    let resolved = ResolvedRequestContext::new(
        ctx.sandbox_paths(),
        ctx.ids(),
        ctx.sandbox_session_id.clone(),
    );

    store.resolve_context_with_peer(
        &resolved,
        Some(TrustedPeer {
            pid: peer.pid,
            uid: peer.uid,
        }),
    )
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

    use super::resolve_request_context;
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

        let RpcRequest::CheckFilesystem { ctx, .. } = req else {
            panic!("expected filesystem request");
        };

        let ctx = resolve_request_context(
            &store,
            ClientPeer {
                pid: peer_pid,
                uid: socket_uid,
                gid: 0,
            },
            SocketRole::Sandbox,
            &ctx,
        );

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
