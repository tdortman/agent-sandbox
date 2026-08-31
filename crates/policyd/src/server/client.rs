//! Per-connection read loop and reply framing.

use std::sync::Arc;

use agent_sandbox_core::{
    CONTEXT_ADAPTER_PROTOCOL_MAJOR, ContextAdapterErrorCode, ContextAdapterMessage,
    ContextAdapterRequest, ProxyReply, ProxyRequestId, ReleasableHandle, RpcMessage, RpcReply,
    RpcRequest, parse_rpc_request,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixStream, unix::OwnedWriteHalf},
    sync::Mutex,
};

use super::dispatch::SocketRole;
use crate::{
    error::PolicydError,
    server::peer::ClientPeer,
    store::{MAX_RPC_LINE_BYTES, PolicyStore, ProxyCheckId, TrustedPeer, UiClientHandle},
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

    let active_checks: Arc<Mutex<Vec<ProxyCheckId>>> = Arc::new(Mutex::new(Vec::new()));

    let mut proxy_session_owner = false;
    let mut proxy_single_request = false;
    let mut context_adapter = false;

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

        if context_adapter {
            let request = match serde_json::from_str::<ContextAdapterRequest>(&line) {
                Ok(request) => request,
                Err(_) => {
                    reply_context_adapter(writer.clone(), &ContextAdapterMessage::Error {
                        request_id: None,
                        code: ContextAdapterErrorCode::MalformedMessage,
                        detail: "invalid context adapter request".into(),
                    })
                    .await;
                    continue;
                }
            };
            let message = dispatch_context_adapter(&store, client.id, request, true, peer, role);
            reply_context_adapter(writer.clone(), &message).await;
            continue;
        }

        if let Ok(request) = serde_json::from_str::<ContextAdapterRequest>(&line) {
            let message = dispatch_context_adapter(&store, client.id, request, false, peer, role);
            context_adapter = matches!(message, ContextAdapterMessage::Registered { .. });
            reply_context_adapter(writer.clone(), &message).await;
            continue;
        }

        let req: RpcRequest = if let Ok(req) = parse_rpc_request(&line) {
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

    if context_adapter {
        store.disconnect_context_adapter(client.id);
    }

    finish_client(store, client, peer, role, active_checks, read_error).await
}

async fn finish_client(
    store: Arc<PolicyStore>,
    client: UiClientHandle,
    peer: ClientPeer,
    role: SocketRole,
    active_checks: Arc<Mutex<Vec<ProxyCheckId>>>,

    read_error: Option<std::io::Error>,
) -> std::io::Result<()> {
    let active_checks = {
        let mut active = active_checks.lock().await;
        std::mem::take(&mut *active)
    };

    for check in active_checks {
        let _ = store.cancel_check(check.session, check.request).await;
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
    active_checks: Arc<Mutex<Vec<ProxyCheckId>>>,

    peer: ClientPeer,
    req: RpcRequest,
) -> bool {
    let Some(check) = proxy_check_identity(&req) else {
        return false;
    };

    active_checks.lock().await.push(check.clone());

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

        let resp = envelope_proxy_reply(SocketRole::Proxy, Some(check.request), resp);

        reply(writer, &resp).await;
        let mut active = active_checks_for_task.lock().await;

        if let Some(index) = active
            .iter()
            .position(|c| c.request == check.request && c.session == check.session)
        {
            active.remove(index);
        }
    });

    true
}

fn adapter_error(
    request_id: Option<u64>,
    code: ContextAdapterErrorCode,
    detail: impl Into<String>,
) -> ContextAdapterMessage {
    ContextAdapterMessage::Error {
        request_id,
        code,
        detail: detail.into(),
    }
}

fn dispatch_context_adapter(
    store: &PolicyStore,
    connection_id: u64,
    request: ContextAdapterRequest,
    registered: bool,
    peer: ClientPeer,
    role: SocketRole,
) -> ContextAdapterMessage {
    let request_id = request.request_id();
    let result = match request {
        ContextAdapterRequest::RegisterContextAdapter {
            protocol_major,
            sandbox_session_id,
            ..
        } => {
            if registered {
                return adapter_error(
                    Some(request_id),
                    ContextAdapterErrorCode::Conflict,
                    "context adapter is already registered",
                );
            }
            if role != SocketRole::Host
                || !store.authenticates_context_adapter(&sandbox_session_id, TrustedPeer {
                    pid: peer.pid,
                    uid: peer.uid,
                })
            {
                return adapter_error(
                    Some(request_id),
                    ContextAdapterErrorCode::Unauthorized,
                    "context adapter registration is not authorized",
                );
            }
            if protocol_major != CONTEXT_ADAPTER_PROTOCOL_MAJOR {
                return adapter_error(
                    Some(request_id),
                    ContextAdapterErrorCode::UnsupportedVersion,
                    "unsupported context adapter protocol major",
                );
            }
            return match store.register_context_adapter(connection_id, &sandbox_session_id) {
                Ok(activations) => ContextAdapterMessage::Registered {
                    request_id,
                    protocol_major: CONTEXT_ADAPTER_PROTOCOL_MAJOR,
                    boot_epoch: store.project_context_boot_epoch(),
                    activations,
                },
                Err(error) => adapter_error(Some(request_id), error.code, error.detail),
            };
        }
        ContextAdapterRequest::BindSession {
            session_key,
            activation,
            ..
        } if registered => store
            .bind_project_session(connection_id, session_key, activation)
            .map(|binding| ContextAdapterMessage::SessionBound {
                request_id,
                binding,
            }),
        ContextAdapterRequest::BeginOperation {
            operation_key,
            binding,
            activation,
            ..
        } if registered => store
            .begin_project_operation(connection_id, operation_key, binding, activation)
            .map(|claim| ContextAdapterMessage::OperationBegun { request_id, claim }),
        ContextAdapterRequest::Release { handle, .. } if registered => match handle {
            ReleasableHandle::Binding(binding) => {
                store.release_project_binding(connection_id, &binding)
            }
            ReleasableHandle::Claim(claim) => store.release_project_claim(connection_id, &claim),
        }
        .map(|()| ContextAdapterMessage::Released { request_id }),
        ContextAdapterRequest::AttachProcess { .. } if registered => {
            return adapter_error(
                Some(request_id),
                ContextAdapterErrorCode::InvalidProcess,
                "attach_process requires exactly one pidfd",
            );
        }
        _ => {
            return adapter_error(
                Some(request_id),
                ContextAdapterErrorCode::Unauthorized,
                "register_context_adapter must be the first request",
            );
        }
    };

    result.unwrap_or_else(|error| adapter_error(Some(request_id), error.code, error.detail))
}

async fn reply_context_adapter(
    writer: Arc<Mutex<OwnedWriteHalf>>,
    payload: &ContextAdapterMessage,
) {
    let Ok(mut line) = serde_json::to_string(payload) else {
        tracing::error!("failed to serialize context adapter reply");
        return;
    };
    line.push('\n');
    let mut writer = writer.lock().await;
    if writer.write_all(line.as_bytes()).await.is_ok() {
        let _ = writer.flush().await;
    }
}

const fn proxy_request_id(req: &RpcRequest) -> Option<ProxyRequestId> {
    match req {
        RpcRequest::CheckHttp { request_id, .. }
        | RpcRequest::CheckNetworkFlow { request_id, .. }
        | RpcRequest::CancelCheck { request_id, .. } => Some(*request_id),

        _ => None,
    }
}

fn proxy_check_identity(req: &RpcRequest) -> Option<ProxyCheckId> {
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
        } => Some(ProxyCheckId {
            session: proxy_session.clone(),
            request: *request_id,
        }),

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
    let n = reader.read_until(b'\n', &mut buf).await?;

    if n == 0 {
        return Ok(None);
    }

    if buf.last() == Some(&b'\n') {
        buf.pop();
    }

    if buf.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RPC line too large",
        ));
    }

    Ok(Some(String::from_utf8(buf).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8")
    })?))
}

async fn reply(writer: Arc<Mutex<OwnedWriteHalf>>, payload: &RpcReply) {
    let line = match RpcMessage::Reply(payload.clone()).encode_line() {
        Ok(line) => line,
        Err(error) => {
            tracing::error!(%error, "failed to serialize policyd RPC reply");
            return;
        }
    };

    let mut w = writer.lock().await;

    if w.write_all(line.as_bytes()).await.is_err() {
        return;
    }

    drop(line);
    let _ = w.flush().await;
    drop(w);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_must_register_before_binding() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::new(crate::store::test_args(
            dir.path().join("host.sock"),
            dir.path().join("sandbox.sock"),
            dir.path().join("policy.json"),
            dir.path().join("export.json"),
            std::time::Duration::from_secs(30),
            false,
        ));
        let response = dispatch_context_adapter(
            &store,
            7,
            ContextAdapterRequest::BindSession {
                request_id: 9,
                session_key: agent_sandbox_core::ExternalSessionKey::new("session").unwrap(),
                activation: agent_sandbox_core::ActivationHandle::new(),
            },
            false,
            ClientPeer {
                pid: std::process::id(),
                uid: nix::unistd::getuid().as_raw(),
                gid: nix::unistd::getgid().as_raw() as i32,
            },
            SocketRole::Host,
        );
        assert!(matches!(response, ContextAdapterMessage::Error {
            request_id: Some(9),
            code: ContextAdapterErrorCode::Unauthorized,
            ..
        }));
    }
}
