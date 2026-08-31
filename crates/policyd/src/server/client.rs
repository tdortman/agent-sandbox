//! Per-connection read loop and reply framing.

use std::{io::IoSliceMut, os::fd::AsRawFd, sync::Arc};

use agent_sandbox_core::{
    CONTEXT_ADAPTER_PROTOCOL_MAJOR, ContextAdapterErrorCode, ContextAdapterMessage,
    ContextAdapterRequest, ProxyReply, ProxyRequestId, ReleasableHandle, RpcMessage, RpcReply,
    RpcRequest, parse_rpc_request,
};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use tokio::{
    io::AsyncWriteExt,
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
};

use super::dispatch::SocketRole;
use crate::{
    error::PolicydError,
    project_context::ReceivedFd,
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

    let (reader_half, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let client = PolicyStore::new_client_handle(writer.clone());
    let mut reader = FrameReader::default();
    let mut read_error = None;

    let active_checks: Arc<Mutex<Vec<ProxyCheckId>>> = Arc::new(Mutex::new(Vec::new()));

    let mut proxy_session_owner = false;
    let mut proxy_single_request = false;
    let mut context_adapter = false;

    loop {
        let frame = match reader.read(&reader_half, MAX_RPC_LINE_BYTES).await {
            Ok(Some(frame)) => frame,
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
        let ReceivedFrame { line, fds } = frame;

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
            let message =
                dispatch_context_adapter(&store, client.id, request, fds, true, peer, role);
            reply_context_adapter(writer.clone(), &message).await;
            continue;
        }

        if let Ok(request) = serde_json::from_str::<ContextAdapterRequest>(&line) {
            let message =
                dispatch_context_adapter(&store, client.id, request, fds, false, peer, role);
            context_adapter = matches!(message, ContextAdapterMessage::Registered { .. });
            reply_context_adapter(writer.clone(), &message).await;
            continue;
        }

        if !fds.is_empty() {
            reply(writer.clone(), &PolicydError::InvalidJson.into()).await;
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
    fds: Vec<ReceivedFd>,
    registered: bool,
    peer: ClientPeer,
    role: SocketRole,
) -> ContextAdapterMessage {
    let request_id = request.request_id();
    let attaches_process = matches!(&request, ContextAdapterRequest::AttachProcess { .. });
    if (attaches_process && fds.len() != 1) || (!attaches_process && !fds.is_empty()) {
        return adapter_error(
            Some(request_id),
            ContextAdapterErrorCode::MalformedMessage,
            "unexpected ancillary descriptor count",
        );
    }
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
        ContextAdapterRequest::AttachProcess { context, .. } if registered => store
            .attach_project_process(
                connection_id,
                context,
                fds.into_iter()
                    .next()
                    .expect("descriptor count was validated"),
            )
            .map(|()| ContextAdapterMessage::ProcessAttached { request_id }),
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

struct ReceivedFrame {
    line: String,
    fds: Vec<ReceivedFd>,
}

#[derive(Default)]
struct FrameReader {
    bytes: Vec<u8>,
    fds: Vec<ReceivedFd>,
}

impl FrameReader {
    async fn read(
        &mut self,
        reader: &OwnedReadHalf,
        max_bytes: usize,
    ) -> std::io::Result<Option<ReceivedFrame>> {
        loop {
            if let Some(newline) = self.bytes.iter().position(|byte| *byte == b'\n') {
                if newline > max_bytes {
                    self.bytes.clear();
                    self.fds.clear();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "RPC line too large",
                    ));
                }
                let mut bytes: Vec<_> = self.bytes.drain(..=newline).collect();
                bytes.pop();
                let line = String::from_utf8(bytes).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8")
                })?;
                return Ok(Some(ReceivedFrame {
                    line,
                    fds: std::mem::take(&mut self.fds),
                }));
            }
            if self.bytes.len() > max_bytes {
                self.bytes.clear();
                self.fds.clear();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "RPC line too large",
                ));
            }

            reader.readable().await?;
            let mut chunk = [0_u8; 8192];
            let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 2]);
            let received = {
                let mut iov = [IoSliceMut::new(&mut chunk)];
                match recvmsg::<()>(
                    reader.as_ref().as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
                ) {
                    Ok(message) => {
                        if message.flags.contains(MsgFlags::MSG_CTRUNC) {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "too many ancillary descriptors",
                            ));
                        }
                        let mut descriptors = Vec::new();
                        for control in message.cmsgs().map_err(std::io::Error::from)? {
                            if let ControlMessageOwned::ScmRights(rights) = control {
                                descriptors.extend(rights);
                            }
                        }
                        (message.bytes, descriptors)
                    }
                    Err(nix::errno::Errno::EAGAIN) => continue,
                    Err(error) => return Err(std::io::Error::from(error)),
                }
            };
            if received.0 == 0 {
                return Ok(None);
            }
            self.bytes.extend_from_slice(&chunk[..received.0]);
            self.fds.extend(received.1.into_iter().map(ReceivedFd::new));
        }
    }
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
            Vec::new(),
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
