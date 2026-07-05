//! Per-connection read loop and reply framing.

use std::sync::Arc;

use agent_sandbox_core::{RpcReply, RpcRequest};

use super::dispatch::SocketRole;
use crate::error::PolicydError;
use crate::server::peer::ClientPeer;
use crate::store::{MAX_RPC_LINE_BYTES, PolicyStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixStream, unix::OwnedWriteHalf};
use tokio::sync::Mutex;

pub async fn handle_client(
    store: Arc<PolicyStore>,
    stream: UnixStream,
    mut role: SocketRole,
) -> std::io::Result<()> {
    let peer = ClientPeer::from_stream(&stream);
    if !store.try_acquire_connection(peer).await {
        let (_reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        reply(writer, &PolicydError::TooManyConnections.into()).await;
        return Ok(());
    }

    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let client = PolicyStore::new_client_handle(writer.clone());
    let mut reader = BufReader::new(reader);

    loop {
        let line = match read_line_limited(&mut reader, MAX_RPC_LINE_BYTES).await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                reply(writer.clone(), &PolicydError::RpcLineTooLarge.into()).await;
                continue;
            }
            Err(err) => return Err(err),
        };
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

        if (role == SocketRole::Host || role == SocketRole::Sandbox) && register_succeeded {
            role = SocketRole::UiFd;
        }

        if flush_pending && register_succeeded {
            store.resolve_pending_declarative_allow().await;
            store.flush_pending_to_ui().await;
        }
    }

    store.end_ui_session(client.id).await;
    store.release_connection(peer).await;
    Ok(())
}

async fn read_line_limited(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    max_bytes: usize,
) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8(buf).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8")
                })?))
            };
        }
        if chunk[0] == b'\n' {
            return Ok(Some(String::from_utf8(buf).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8")
            })?));
        }
        if buf.len() >= max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RPC line too large",
            ));
        }
        buf.push(chunk[0]);
    }
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
