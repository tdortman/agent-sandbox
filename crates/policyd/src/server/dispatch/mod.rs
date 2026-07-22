//! Route incoming RPC requests to store methods.

mod auth;
pub use auth::SocketRole;
mod check;
mod context;
mod handlers;

use std::sync::Arc;

use agent_sandbox_core::{RpcReply, RpcRequest};

use crate::{error::PolicydError, server::peer::ClientPeer, store::PolicyStore};

pub async fn dispatch(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    auth::ensure_allowed(role, &req)?;
    if matches!(&req, RpcRequest::RegisterNetworkFlow { .. }) && peer.uid != 0 {
        return Err(PolicydError::UnauthorizedRequest);
    }
    let req = context::plan(store, peer, role, req);
    handlers::handle(store, client, peer, req).await
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use agent_sandbox_core::{
        FileAccess, FlowContext, FlowProtocol, FlowRegistration, NetworkFlowKey,
        NormalizedPolicyHost, ProcessIdentity, RequestContext, RpcRequest, SocketIdentity,
        SocketInode,
    };
    use tokio::{net::UnixStream, sync::Mutex};

    use super::{SocketRole, dispatch};
    use crate::{error::PolicydError, server::peer::ClientPeer, store::PolicyStore};

    fn test_store(dir: &tempfile::TempDir) -> Arc<PolicyStore> {
        Arc::new(PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("policy.json"),
            dir.path().join("export.json"),
            Duration::from_secs(30),
            false,
        )))
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

    fn test_registration() -> FlowRegistration {
        FlowRegistration::new(
            NetworkFlowKey::try_new(
                FlowProtocol::Tcp,
                "127.0.0.1".parse().expect("valid test source address"),
                12345,
                "192.0.2.1".parse().expect("valid test destination address"),
                443,
            )
            .expect("test flow ports are non-zero"),
            SocketIdentity::new(
                ProcessIdentity::new(1, 0, 1).expect("test process identity is non-zero"),
                SocketInode::new(1).expect("test socket inode is non-zero"),
            ),
            NormalizedPolicyHost::parse("example.com").expect("valid test policy host"),
            FlowContext::default(),
        )
    }

    #[tokio::test]
    async fn sandbox_dispatch_records_owner_for_later_ui_registration() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let file = dir.path().join("file.txt");
        std::fs::write(&file, "contents").expect("write test file");
        let store = test_store(&dir);
        let client = PolicyStore::new_client_handle(writer());

        dispatch(
            &store,
            &client,
            ClientPeer {
                pid: std::process::id(),
                uid: 1000,
                gid: 0,
            },
            SocketRole::Sandbox,
            RpcRequest::CheckFilesystem {
                path: file,
                access: FileAccess::Read,
                ctx: RequestContext {
                    sandbox_session_id: Some("sandbox-a".into()),
                    ..RequestContext::default()
                },
            },
        )
        .await
        .expect("sandbox request dispatches");

        let result = dispatch(
            &store,
            &client,
            ClientPeer {
                pid: std::process::id(),
                uid: 2000,
                gid: 0,
            },
            SocketRole::Host,
            RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext {
                    uid: Some(1000),
                    sandbox_session_id: Some("sandbox-a".into()),
                    ..RequestContext::default()
                },
            },
        )
        .await;

        assert!(
            matches!(result, Err(PolicydError::UnauthorizedUiRegistration)),
            "dispatch must reject cross-uid UI registration after planning sandbox ownership, \
             got: {result:?}"
        );
    }

    #[tokio::test]
    async fn sandbox_dispatch_rejects_unprivileged_network_flow_registration() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let store = test_store(&dir);
        let client = PolicyStore::new_client_handle(writer());

        let result = dispatch(
            &store,
            &client,
            ClientPeer {
                pid: std::process::id(),
                uid: 1000,
                gid: 0,
            },
            SocketRole::Sandbox,
            RpcRequest::RegisterNetworkFlow {
                registration: test_registration(),
            },
        )
        .await;

        assert!(
            matches!(result, Err(PolicydError::UnauthorizedRequest)),
            "sandbox socket must reject unprivileged flow registration, got: {result:?}"
        );
    }
}
