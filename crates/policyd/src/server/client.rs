//! Per-connection read loop and reply framing.

use std::{sync::Arc, time::Duration};

use agent_sandbox_core::{
    Heartbeat, ProxyReply, ProxyRequestId, RpcMessage, RpcReply, RpcRequest, parse_rpc_envelope,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixStream, unix::OwnedWriteHalf},
    sync::Mutex,
    time,
};

use super::dispatch::SocketRole;
use crate::{
    error::PolicydError,
    server::peer::ClientPeer,
    store::{ConnectionBucket, MAX_RPC_LINE_BYTES, PolicyStore, ProxyCheckId, UiClientHandle},
};

/// How often a heartbeat line is written while policyd is still working on a
/// request whose client opted in. Clients bound their silence tolerance by
/// far more than this.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// How long one heartbeat write may take before the client is treated as no
/// longer reading.
const HEARTBEAT_WRITE_LIMIT: Duration = Duration::from_secs(2);

pub async fn handle_client(
    store: Arc<PolicyStore>,
    stream: UnixStream,
    role: SocketRole,
) -> std::io::Result<()> {
    serve_client(store, stream, role, HEARTBEAT_INTERVAL).await
}

async fn serve_client(
    store: Arc<PolicyStore>,
    stream: UnixStream,
    mut role: SocketRole,
    heartbeat_interval: Duration,
) -> std::io::Result<()> {
    let peer = ClientPeer::from_stream(&stream);
    let bucket = ConnectionBucket::for_peer(peer.pid, peer.uid, role == SocketRole::Sandbox);

    if !store.try_acquire_connection(&bucket).await {
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

        if role == SocketRole::Proxy
            && (proxy_session_owner || !active_checks.lock().await.is_empty())
        {
            break;
        }

        if line.is_empty() {
            continue;
        }

        let Ok(envelope) = parse_rpc_envelope(&line) else {
            reply(writer.clone(), &PolicydError::InvalidJson.into()).await;
            continue;
        };

        let heartbeat = envelope.heartbeat.then_some(heartbeat_interval);
        let req = envelope.request;

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
                heartbeat,
            )
            .await
            {
                continue;
            }

            continue;
        }

        let request_id = proxy_request_id(&req);
        let is_open_proxy_session = matches!(
            &req,
            RpcRequest::OpenProxySession | RpcRequest::ResumeProxySession { .. }
        );
        let is_register = matches!(req, RpcRequest::RegisterUi { .. });

        let resp = match with_heartbeats(
            &writer,
            heartbeat,
            Box::pin(super::dispatch::dispatch(&store, &client, peer, role, req)),
        )
        .await
        {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(error = %err, "policyd dispatch error");
                err.into()
            }
        };

        let resp = envelope_proxy_reply(role, request_id, resp);
        let register_succeeded = is_register && resp.is_ok();
        reply(writer.clone(), &resp).await;

        if role == SocketRole::Proxy && is_open_proxy_session && resp.is_ok() {
            proxy_session_owner = true;
        }

        if (role == SocketRole::Host || role == SocketRole::Sandbox) && register_succeeded {
            role = SocketRole::UiFd;
        }

        if is_register && register_succeeded {
            store.settle_covered_pendings().await;
            store.flush_pending_to_ui().await;
        }
    }

    finish_client(store, client, bucket, role, active_checks, read_error).await
}

async fn finish_client(
    store: Arc<PolicyStore>,
    client: UiClientHandle,
    bucket: ConnectionBucket,
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
    store.release_connection(&bucket).await;

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
    heartbeat: Option<Duration>,
) -> bool {
    let Some(check) = proxy_check_identity(&req) else {
        return false;
    };

    active_checks.lock().await.push(check.clone());
    let active_checks_for_task = active_checks;

    tokio::spawn(async move {
        let resp = match with_heartbeats(
            &writer,
            heartbeat,
            Box::pin(super::dispatch::dispatch(
                &store,
                &client,
                peer,
                SocketRole::Proxy,
                req,
            )),
        )
        .await
        {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(error = %err, "policyd dispatch error");
                err.into()
            }
        };

        let resp = envelope_proxy_reply(SocketRole::Proxy, Some(check.request), resp);

        // Publish completion with the reply. A sequential client may send its
        // next request as soon as it reads this reply, but cannot overtake
        // removal from the active list. EOF still cancels unfinished checks.
        let mut active = active_checks_for_task.lock().await;
        reply(writer, &resp).await;

        if let Some(index) = active
            .iter()
            .position(|c| c.request == check.request && c.session == check.session)
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

/// Await `work`, writing a heartbeat line every `interval` until it finishes.
/// `None` writes none, which is what a client that did not opt in must get.
///
/// Callers write the reply only after this returns, so no heartbeat can
/// follow it.
async fn with_heartbeats<T>(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    interval: Option<Duration>,
    work: impl Future<Output = T>,
) -> T {
    let Some(interval) = interval else {
        return work.await;
    };

    tokio::pin!(work);
    let mut ticker = time::interval_at(time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            output = &mut work => return output,
            _ = ticker.tick() => {
                let beat = send(writer.clone(), &RpcMessage::Heartbeat(Heartbeat::Alive));

                // A client that stopped reading must not hold the request
                // back: it gets no further heartbeats, and the request runs
                // to its end.
                if time::timeout(HEARTBEAT_WRITE_LIMIT, beat).await.is_err() {
                    return work.await;
                }
            }
        }
    }
}

async fn reply(writer: Arc<Mutex<OwnedWriteHalf>>, payload: &RpcReply) {
    send(writer, &RpcMessage::Reply(payload.clone())).await;
}

async fn send(writer: Arc<Mutex<OwnedWriteHalf>>, message: &RpcMessage) {
    let line = match message.encode_line() {
        Ok(line) => line,
        Err(error) => {
            tracing::error!(%error, "failed to serialize policyd RPC message");
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
    use std::{sync::Arc, time::Duration};

    use agent_sandbox_core::{
        AttributionToken, FlowContext, FlowProtocol, FlowRegistration, HttpRequest, NetworkFlowKey,
        NormalizedPolicyHost, ProxyConnectionId, ProxyReplyBody, ProxyRequestId, RequestContext,
        RpcConnection, RpcReply, RpcRequest,
        socket_owner::{OwnerResolution, SocketProtocol, SocketTuple, resolve_owner_snapshot},
    };
    use tokio::{io::AsyncReadExt, net::UnixListener};

    use super::{SocketRole, handle_client, with_heartbeats};
    use crate::store::PolicyStore;

    /// Run `work_for` of slow work through [`with_heartbeats`] and return
    /// every line the client side of the socket received meanwhile.
    async fn heartbeat_lines(interval: Option<Duration>, work_for: Duration) -> String {
        let (server, mut client) = tokio::net::UnixStream::pair().expect("socket pair");
        let (_read, write) = server.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(write));

        with_heartbeats(&writer, interval, tokio::time::sleep(work_for)).await;
        drop(writer);

        let mut received = String::new();
        client
            .read_to_string(&mut received)
            .await
            .expect("read heartbeats");
        received
    }

    #[tokio::test]
    async fn slow_work_of_an_opted_in_request_writes_heartbeats() {
        let received =
            heartbeat_lines(Some(Duration::from_millis(20)), Duration::from_millis(200)).await;
        let lines: Vec<&str> = received.lines().collect();

        assert!(
            lines.len() >= 3,
            "expected several heartbeats: {received:?}"
        );
        assert!(lines.iter().all(|line| *line == r#"{"type":"heartbeat"}"#));
    }

    #[tokio::test]
    async fn slow_work_without_opt_in_writes_nothing() {
        let received = heartbeat_lines(None, Duration::from_millis(200)).await;

        assert_eq!(received, "");
    }

    #[tokio::test]
    async fn work_that_finishes_before_the_interval_writes_no_heartbeat() {
        let received =
            heartbeat_lines(Some(Duration::from_secs(30)), Duration::from_millis(10)).await;

        assert_eq!(received, "");
    }

    #[tokio::test]
    async fn client_that_stopped_reading_does_not_hold_the_request_back() {
        let (server, _client) = tokio::net::UnixStream::pair().expect("socket pair");
        let (_read, write) = server.into_split();

        // Fill the socket buffer: nothing reads the other end.
        while write.try_write(&[0_u8; 4096]).is_ok() {}

        let writer = Arc::new(tokio::sync::Mutex::new(write));
        let work = async {
            tokio::time::sleep(Duration::from_millis(2_500)).await;
            7
        };

        let output = tokio::time::timeout(
            Duration::from_secs(10),
            with_heartbeats(&writer, Some(Duration::from_millis(20)), work),
        )
        .await
        .expect("a blocked heartbeat write must not stall the request");

        assert_eq!(output, 7);
    }

    #[tokio::test]
    async fn sequential_proxy_rpcs_preserve_reply_ids_and_session_lease() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("proxy.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let store = Arc::new(PolicyStore::new(crate::store::test_args(
                dir.path().join("host.sock"),
                dir.path().join("sandbox.sock"),
                dir.path().join("policy.json"),
                dir.path().join("export.json"),
                Duration::from_secs(30),
                true,
            )));
            let mut lease = RpcConnection::connect(&path).await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let lease_task = tokio::spawn(handle_client(store.clone(), stream, SocketRole::Proxy));
            let RpcReply::ProxySession(session) =
                lease.request(RpcRequest::OpenProxySession).await.unwrap()
            else {
                panic!("expected session token");
            };
            let mut client = RpcConnection::connect(&path).await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let client_task = tokio::spawn(handle_client(store.clone(), stream, SocketRole::Proxy));
            // Reuse the real proxy-role connection across synchronous replies
            // and spawned checks, including rejected requests.
            for _ in 0..16 {
                let request_id = ProxyRequestId::new();
                let reply = client
                    .request(RpcRequest::CancelCheck {
                        proxy_session: session.proxy_session.clone(),
                        request_id,
                    })
                    .await
                    .unwrap();
                assert!(matches!(reply, RpcReply::Proxy(reply)
                    if reply.request_id == request_id
                    && matches!(reply.reply, ProxyReplyBody::Canceled(ref ok) if ok.ok)));
                let request_id = ProxyRequestId::new();
                let reply = client
                    .request(RpcRequest::CheckHttp {
                        proxy_session: session.proxy_session.clone(),
                        request_id,
                        attribution_token: AttributionToken::from_bytes([2; 32]),
                        request: HttpRequest::from_parts("GET", "http", "example.test", "/")
                            .unwrap(),
                    })
                    .await
                    .unwrap();
                assert!(matches!(reply, RpcReply::Proxy(reply)
                    if reply.request_id == request_id
                    && matches!(reply.reply, ProxyReplyBody::Error(_))));
            }
            drop(client);
            client_task.await.unwrap().unwrap();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let source = socket.local_addr().unwrap();
            let OwnerResolution::Unique(owner) = resolve_owner_snapshot(
                SocketProtocol::Udp,
                SocketTuple::from_local(source.ip(), source.port()),
            ) else {
                panic!("test socket must have a unique owner");
            };
            let flow = NetworkFlowKey::try_new(
                FlowProtocol::Udp,
                source.ip(),
                source.port(),
                "1.1.1.1".parse().unwrap(),
                443,
            )
            .unwrap();
            store
                .register_network_flow(
                    FlowRegistration::new(
                        flow.clone(),
                        owner.identity(),
                        NormalizedPolicyHost::parse("example.test").unwrap(),
                        FlowContext::default(),
                    ),
                    None,
                )
                .await
                .unwrap();
            let claim = store
                .claim_network_flow(
                    session.proxy_session.clone(),
                    flow,
                    ProxyConnectionId::new(),
                )
                .await
                .unwrap();
            // Proxy network checks freeze the owner during approval, which no
            // test process can satisfy: the check fails closed over the wire
            // with its request id preserved. The session lease connection
            // carries no RPCs, so this uses a fresh worker connection.
            let mut worker = RpcConnection::connect(&path)
                .await
                .expect("connect worker RPC");
            let (stream, _) = listener.accept().await.expect("accept worker RPC");
            let worker_task =
                tokio::spawn(handle_client(store.clone(), stream, SocketRole::Proxy));
            let request_id = ProxyRequestId::new();
            let reply = worker
                .request(RpcRequest::CheckNetworkFlow {
                    proxy_session: session.proxy_session.clone(),
                    request_id,
                    attribution_token: claim.attribution_token.clone(),
                })
                .await
                .expect("network check must reply");
            assert!(
                matches!(&reply, RpcReply::Proxy(reply)
                    if reply.request_id == request_id
                    && matches!(&reply.reply, ProxyReplyBody::NetworkFlow(check)
                        if !check.verdict.allowed
                            && check.error.as_deref().is_some_and(|error| error.contains("freeze")))),
                "unfreezable proxy check must fail closed, got {reply:?}"
            );
            drop(worker);
            worker_task
                .await
                .expect("worker task joins")
                .expect("no worker error");
            // The shared approval path freezes too: a direct check from a
            // real peer fails closed without creating an approval.
            let mut sandbox = RpcConnection::connect(&path)
                .await
                .expect("connect sandbox RPC");
            let (stream, _) = listener.accept().await.expect("accept sandbox RPC");
            let task = tokio::spawn(handle_client(store.clone(), stream, SocketRole::Sandbox));
            let reply = sandbox
                .request(RpcRequest::Check {
                    host: Some("1.1.1.1".into()),
                    connect_host: Some("1.1.1.1".into()),
                    port: Some(443),
                    scheme: "udp".into(),
                    url: Some("udp://1.1.1.1:443".into()),
                    ctx: RequestContext::default(),
                })
                .await
                .expect("direct check must reply");
            assert!(
                matches!(&reply, RpcReply::Check(check)
                    if !check.verdict.allowed
                        && check.error.as_deref().is_some_and(|error| error.contains("freeze"))),
                "unfreezable direct check must fail closed, got {reply:?}"
            );
            drop(sandbox);
            task.await.expect("client task joins").expect("no client error");
            // An RPC connection ending must not own the session lease.
            assert!(store.open_proxy_session(u64::MAX).await.is_err());
            drop(lease);
            lease_task.await.unwrap().unwrap();
            assert!(store.open_proxy_session(u64::MAX).await.is_ok());
        })
        .await
        .expect("sequential RPCs must not hang");
    }
}
