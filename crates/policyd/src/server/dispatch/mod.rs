//! Route incoming RPC requests to store methods.

mod auth;
pub use auth::SocketRole;
mod check;
mod context;
mod handlers;

use std::sync::Arc;

use agent_sandbox_core::{RpcReply, RpcRequest};

use crate::error::PolicydError;
use crate::server::peer::ClientPeer;
use crate::store::PolicyStore;

pub async fn dispatch(
    store: &Arc<PolicyStore>,
    client: &crate::store::UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    req: RpcRequest,
) -> Result<RpcReply, PolicydError> {
    auth::ensure_allowed(role, &req)?;
    let req = context::plan(store, peer, role, req);
    handlers::handle(store, client, peer, req).await
}

#[cfg(test)]
mod tests {
    use super::{SocketRole, dispatch};
    use crate::error::PolicydError;
    use crate::server::peer::ClientPeer;
    use crate::store::{PolicyStore, PolicydArgs};
    use agent_sandbox_core::{FileAccess, RequestContext, RpcRequest};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;

    fn test_store(dir: &tempfile::TempDir) -> Arc<PolicyStore> {
        Arc::new(PolicyStore::new(PolicydArgs {
            host_socket: dir.path().join("host.sock"),
            sandbox_socket: dir.path().join("sandbox.sock"),
            declarative: dir.path().join("policy.json"),
            export_json: dir.path().join("export.json"),
            export_nix: None,
            approval_timeout: Duration::from_secs(30),
            interactive_approval: false,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        }))
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
            "dispatch must reject cross-uid UI registration after planning sandbox ownership, got: {result:?}"
        );
    }
}
