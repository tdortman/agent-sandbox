//! Per-connection read loop and reply framing.

use std::sync::Arc;

use agent_sandbox_core::{ProxyReply, ProxyRequestId, ProxySessionToken, RpcReply, RpcRequest};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixStream, unix::OwnedWriteHalf},
    sync::Mutex,
};

use super::dispatch::SocketRole;
use crate::{
    error::PolicydError,
    server::peer::ClientPeer,
    store::{MAX_RPC_LINE_BYTES, PolicyStore, UiClientHandle},
};

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
    let mut read_error = None;
    let active_checks: Arc<Mutex<Vec<(ProxySessionToken, ProxyRequestId)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let mut proxy_session_owner = false;
    let mut proxy_single_request = false;

    loop {
        let line = match read_line_limited(&mut reader, MAX_RPC_LINE_BYTES).await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                reply(writer.clone(), &PolicydError::RpcLineTooLarge.into()).await;
                continue;
            }
            Err(err) => {
                read_error = Some(err);
                break;
            }
        };
        if role == SocketRole::Proxy && (proxy_session_owner || proxy_single_request) {
            break;
        }
        if line.is_empty() {
            continue;
        }
        let req: RpcRequest = if let Ok(req) = serde_json::from_str(&line) {
            req
        } else {
            reply(writer.clone(), &PolicydError::InvalidJson.into()).await;
            continue;
        };

        let is_long_check = matches!(
            &req,
            RpcRequest::CheckHttp { .. } | RpcRequest::CheckNetworkFlow { .. }
        );
        if role == SocketRole::Proxy && is_long_check {
            if !spawn_proxy_check(
                store.clone(),
                client.clone(),
                writer.clone(),
                active_checks.clone(),
                peer,
                req,
            )
            .await
            {
                continue;
            }
            proxy_single_request = true;
            continue;
        }
        let request_id = proxy_request_id(&req);

        let is_open_proxy_session = matches!(&req, RpcRequest::OpenProxySession);
        let is_register = matches!(req, RpcRequest::RegisterUi { .. });
        let resp = match super::dispatch::dispatch(&store, &client, peer, role, req).await {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(error = %err, "policyd dispatch error");
                err.into()
            }
        };
        let resp = envelope_proxy_reply(role, request_id, resp);
        let register_succeeded = is_register && resp.is_ok();
        reply(writer.clone(), &resp).await;
        if role == SocketRole::Proxy {
            if is_open_proxy_session && resp.is_ok() {
                proxy_session_owner = true;
            } else {
                break;
            }
        }

        if (role == SocketRole::Host || role == SocketRole::Sandbox) && register_succeeded {
            role = SocketRole::UiFd;
        }

        if is_register && register_succeeded {
            store.resolve_pending_declarative_allow().await;
            store.flush_pending_to_ui().await;
        }
    }

    finish_client(store, client, peer, role, active_checks, read_error).await
}
async fn finish_client(
    store: Arc<PolicyStore>,
    client: UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    active_checks: Arc<Mutex<Vec<(ProxySessionToken, ProxyRequestId)>>>,
    read_error: Option<std::io::Error>,
) -> std::io::Result<()> {
    let active_checks = {
        let mut active = active_checks.lock().await;
        std::mem::take(&mut *active)
    };
    for (proxy_session, request_id) in active_checks {
        let _ = store.cancel_check(proxy_session, request_id).await;
    }
    if role == SocketRole::Proxy {
        store.close_proxy_session(client.id).await;
    }
    store.end_ui_session(client.id).await;
    store.release_connection(peer).await;
    if let Some(err) = read_error {
        return Err(err);
    }
    Ok(())
}

async fn spawn_proxy_check(
    store: Arc<PolicyStore>,
    client: UiClientHandle,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    active_checks: Arc<Mutex<Vec<(ProxySessionToken, ProxyRequestId)>>>,
    peer: ClientPeer,
    req: RpcRequest,
) -> bool {
    let Some((proxy_session, request_id)) = proxy_check_identity(&req) else {
        return false;
    };
    active_checks
        .lock()
        .await
        .push((proxy_session.clone(), request_id));
    let active_checks_for_task = active_checks;
    tokio::spawn(async move {
        let resp =
            match super::dispatch::dispatch(&store, &client, peer, SocketRole::Proxy, req).await {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!(error = %err, "policyd dispatch error");
                    err.into()
                }
            };
        let resp = envelope_proxy_reply(SocketRole::Proxy, Some(request_id), resp);
        reply(writer, &resp).await;
        let mut active = active_checks_for_task.lock().await;
        if let Some(index) = active
            .iter()
            .position(|(session, id)| *id == request_id && session == &proxy_session)
        {
            active.remove(index);
        }
    });
    true
}

const fn proxy_request_id(req: &RpcRequest) -> Option<ProxyRequestId> {
    match req {
        RpcRequest::CheckHttp { request_id, .. }
        | RpcRequest::CheckNetworkFlow { request_id, .. }
        | RpcRequest::CancelCheck { request_id, .. } => Some(*request_id),
        _ => None,
    }
}

fn proxy_check_identity(req: &RpcRequest) -> Option<(ProxySessionToken, ProxyRequestId)> {
    match req {
        RpcRequest::CheckHttp {
            proxy_session,
            request_id,
            ..
        }
        | RpcRequest::CheckNetworkFlow {
            proxy_session,
            request_id,
            ..
        } => Some((proxy_session.clone(), *request_id)),
        _ => None,
    }
}
fn envelope_proxy_reply(
    role: SocketRole,
    request_id: Option<ProxyRequestId>,
    reply: RpcReply,
) -> RpcReply {
    if role == SocketRole::Proxy
        && let Some(request_id) = request_id
    {
        return RpcReply::Proxy(ProxyReply::from_reply(request_id, reply));
    }
    reply
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
