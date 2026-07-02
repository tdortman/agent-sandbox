//! Per-connection read loop and reply framing.

use std::sync::Arc;

use agent_sandbox_core::{RpcReply, RpcRequest};

use super::dispatch::SocketRole;
use crate::error::PolicydError;
use crate::server::peer::ClientPeer;
use crate::store::PolicyStore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixStream, unix::OwnedWriteHalf};
use tokio::sync::Mutex;

pub async fn handle_client(
    store: Arc<PolicyStore>,
    stream: UnixStream,
    mut role: SocketRole,
) -> std::io::Result<()> {
    let peer = ClientPeer::from_stream(&stream);
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let client = PolicyStore::new_client_handle(writer.clone());
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }
        let req: RpcRequest = if let Ok(req) = serde_json::from_str(&line) {
            req
        } else {
            reply(writer.clone(), &PolicydError::InvalidJson.into()).await;
            continue;
        };
        let is_register = matches!(req, RpcRequest::RegisterUi { .. });
        let flush_pending = is_register;

        let resp = match super::dispatch::dispatch(&store, &client, peer, role, req).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(error = %err, "policyd dispatch error");
                err.into()
            }
        };

        let register_succeeded = is_register && resp.is_ok();
        reply(writer.clone(), &resp).await;

        // Transition Host/Sandbox → UiFd ONLY after a *successful* RegisterUi.
        // A rejected RegisterUi (notably on the sandbox socket, where it is
        // refused to block the self-approval escape) must NOT grant the UiFd
        // role, because UiFd is approval-capable (Approve/Deny/ApproveHost).
        // Transitioning on the request shape alone, ignoring the verdict,
        // would let an attacker attain the approval role by sending a
        // RegisterUi that policyd rejects.
        if (role == SocketRole::Host || role == SocketRole::Sandbox) && register_succeeded {
            role = SocketRole::UiFd;
        }

        if flush_pending && register_succeeded {
            store.resolve_pending_declarative_allow().await;
            store.flush_pending_to_ui().await;
        }
    }

    store.end_ui_session(client.id).await;
    Ok(())
}

async fn reply(writer: Arc<Mutex<OwnedWriteHalf>>, payload: &RpcReply) {
    let line = payload.to_string();
    let mut w = writer.lock().await;
    if w.write_all(line.as_bytes()).await.is_err() {
        return;
    }
    drop(line);
    let _ = w.flush().await;
    drop(w);
}
