use agent_sandbox_core::{
    AttributionToken, ErrorReply, FlowClaimReply, HttpCheckReply, HttpRequest, ProxyConnectionId,
    ProxySessionReply, ProxySessionToken, RpcReply, SimpleOkReply, Verdict, VerdictSource,
};
use bytes::Buf;
use nix::{
    libc,
    sys::socket::{setsockopt, sockopt::Linger},
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::pem::PemObject;
use std::{
    io::{ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsFd,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener},
    sync::Notify,
    task::JoinHandle,
    time::{sleep, timeout},
};

/// One observed flow claim with the connection identity that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEvent {
    pub flow: agent_sandbox_core::NetworkFlowKey,
    pub connection_id: ProxyConnectionId,
}

/// One observed ownership release. The connection identifier must match the
/// identifier recorded when the flow was claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRelease {
    pub token: AttributionToken,
    pub connection_id: ProxyConnectionId,
}

#[derive(Debug, Default)]
pub struct PolicyEvents {
    pub claims: Vec<ClaimEvent>,
    pub checks: Vec<HttpRequest>,
    pub decisions: Vec<bool>,
    pub cancellations: Vec<agent_sandbox_core::ProxyRequestId>,
    pub rebinds: Vec<agent_sandbox_core::NetworkFlowKey>,
    pub releases: Vec<FlowRelease>,
}

pub struct FakePolicy {
    pub socket: PathBuf,
    pub events: Arc<Mutex<PolicyEvents>>,
    task: JoinHandle<()>,
}

impl FakePolicy {
    pub fn start(root: &Path) -> Self {
        Self::start_with_behavior(root, false)
    }

    /// Start a policy service that rejects every flow claim, so the proxy's
    /// connection-level failure path can be observed.
    pub fn start_claim_error(root: &Path) -> Self {
        Self::start_with_behavior(root, true)
    }

    fn start_with_behavior(root: &Path, claim_errors: bool) -> Self {
        let socket = root.join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind fake policy socket");
        let events = Arc::new(Mutex::new(PolicyEvents::default()));
        let task_events = events.clone();
        let cancel_gate = Arc::new(Notify::new());

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let events = task_events.clone();
                let cancel_gate = cancel_gate.clone();
                tokio::spawn(serve_policy_connection(
                    stream,
                    events,
                    cancel_gate,
                    claim_errors,
                ));
            }
        });

        Self {
            socket,
            events,
            task,
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the fake policy RPC table mirrors the full proxy wire contract"
)]
async fn serve_policy_connection(
    stream: tokio::net::UnixStream,
    events: Arc<Mutex<PolicyEvents>>,
    cancel_gate: Arc<Notify>,
    claim_errors: bool,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    while reader.read_line(&mut line).await.is_ok() && !line.is_empty() {
        let value: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(_) => break,
        };
        let Some(op) = value.get("op").and_then(serde_json::Value::as_str) else {
            break;
        };
        let reply = match op {
            "open_proxy_session" => RpcReply::ProxySession(ProxySessionReply {
                ok: true,
                proxy_session: ProxySessionToken::from_bytes([1; 32]),
            }),
            "claim_network_flow" => {
                let flow = serde_json::from_value(value.get("flow").cloned().expect("flow"))
                    .expect("flow value");
                let connection_id = serde_json::from_value(
                    value.get("connection_id").cloned().expect("connection id"),
                )
                .expect("connection id value");
                let mut events = events.lock().expect("policy events lock");
                events.claims.push(ClaimEvent {
                    flow,
                    connection_id,
                });
                drop(events);

                if claim_errors {
                    RpcReply::Error(ErrorReply::new("unknown connection identifier"))
                } else {
                    RpcReply::FlowClaim(FlowClaimReply {
                        ok: true,
                        attribution_token: AttributionToken::from_bytes([2; 32]),
                    })
                }
            }
            "rebind_network_flow" => {
                let flow = serde_json::from_value(value.get("flow").cloned().expect("flow"))
                    .expect("flow value");
                events
                    .lock()
                    .expect("policy events lock")
                    .rebinds
                    .push(flow);
                RpcReply::Simple(SimpleOkReply::OK)
            }
            "check_http" => {
                let request: HttpRequest =
                    serde_json::from_value(value.get("request").cloned().expect("request"))
                        .expect("HTTP request value");
                let url = request.url.to_string();
                events
                    .lock()
                    .expect("policy events lock")
                    .checks
                    .push(request.clone());

                if url.contains("/policy-error") {
                    RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
                        serde_json::from_value(
                            value.get("request_id").cloned().expect("request id"),
                        )
                        .expect("request id"),
                        RpcReply::Error(ErrorReply::new("socket owner changed")),
                    ))
                } else if url.contains("/cancel") {
                    cancel_gate.notified().await;
                    RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
                        serde_json::from_value(
                            value.get("request_id").cloned().expect("request id"),
                        )
                        .expect("request id"),
                        RpcReply::HttpCheck(HttpCheckReply::blocked(
                            "agent-sandbox: HTTP check cancelled",
                        )),
                    ))
                } else {
                    let allowed = !url.contains("/deny");
                    let mut events = events.lock().expect("policy events lock");
                    events.decisions.push(allowed);
                    drop(events);
                    RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
                        serde_json::from_value(
                            value.get("request_id").cloned().expect("request id"),
                        )
                        .expect("request id"),
                        RpcReply::HttpCheck(HttpCheckReply::from_verdict(
                            request,
                            if allowed {
                                Verdict::allowed(VerdictSource::policy())
                            } else {
                                Verdict::denied(VerdictSource::policy())
                            },
                        )),
                    ))
                }
            }
            "release_network_flow" => {
                let token =
                    serde_json::from_value(value.get("attribution_token").cloned().expect("token"))
                        .expect("attribution token");
                let connection_id = serde_json::from_value(
                    value.get("connection_id").cloned().expect("connection id"),
                )
                .expect("connection id value");
                events
                    .lock()
                    .expect("policy events lock")
                    .releases
                    .push(FlowRelease {
                        token,
                        connection_id,
                    });
                RpcReply::Simple(SimpleOkReply::OK)
            }
            "cancel_check" => {
                let request_id =
                    serde_json::from_value(value.get("request_id").cloned().expect("request id"))
                        .expect("request id");
                events
                    .lock()
                    .expect("policy events lock")
                    .cancellations
                    .push(request_id);
                cancel_gate.notify_waiters();
                RpcReply::Simple(SimpleOkReply::OK)
            }
            _ => break,
        };
        let encoded = serde_json::to_vec(&reply).expect("encode policy reply");
        if writer.write_all(&encoded).await.is_err()
            || writer.write_all(b"\n").await.is_err()
            || writer.flush().await.is_err()
        {
            break;
        }
        line.clear();
    }
}

impl Drop for FakePolicy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_http_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();

    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0; 1];
        stream
            .read_exact(&mut byte)
            .await
            .expect("read response header");
        response.push(byte[0]);
    }

    let headers = String::from_utf8_lossy(&response);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then_some(value)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .expect("response content length");
    let body_start = response.len();
    response.resize(body_start + content_length, 0);
    stream
        .read_exact(&mut response[body_start..])
        .await
        .expect("read response body");

    response
}

pub struct TcpOrigin {
    pub address: SocketAddr,
    pub stream_gate: Arc<Notify>,
    pub attempts: Arc<AtomicUsize>,
    pub resets: Arc<AtomicUsize>,
    pub request_heads: Arc<Mutex<Vec<String>>>,
    task: Option<JoinHandle<()>>,
}

#[expect(
    clippy::too_many_lines,
    reason = "the plain-text origin serves every harness response shape"
)]
async fn serve_tcp_origin_connection(
    mut stream: TcpStream,
    body: &'static [u8],
    keep_alive: bool,
    stream_gate: Arc<Notify>,
    stream_resets: Arc<AtomicUsize>,
    request_heads: Arc<Mutex<Vec<String>>>,
) {
    loop {
        let mut request = Vec::new();
        let read_result = timeout(Duration::from_secs(2), async {
            loop {
                let mut byte = [0; 1];
                stream.read_exact(&mut byte).await?;
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }

            Ok::<_, std::io::Error>(())
        })
        .await;

        if !matches!(read_result, Ok(Ok(()))) {
            break;
        }

        request_heads
            .lock()
            .expect("request heads lock")
            .push(String::from_utf8_lossy(&request).into_owned());

        let doh_packet = if request
            .windows(b"/doh-ech".len())
            .any(|window| window == b"/doh-ech")
        {
            Some(doh_dns_message(false))
        } else if request
            .windows(b"/doh-dnssec".len())
            .any(|window| window == b"/doh-dnssec")
        {
            Some(doh_dns_message(true))
        } else {
            None
        };

        if let Some(packet) = doh_packet {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \
                 {}\r\nConnection: close\r\n\r\n",
                packet.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&packet).await;
            break;
        }

        let websocket = request
            .windows(b"upgrade: websocket".len())
            .any(|window| window.eq_ignore_ascii_case(b"upgrade: websocket"));

        if websocket {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: Upgrade\r\n\
                      Upgrade: websocket\r\n\
                      Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                )
                .await;
            let mut payload = [0; 4];
            if stream.read_exact(&mut payload).await.is_ok() {
                let _ = stream.write_all(&payload).await;
            }
            break;
        }

        let abort_probe = request
            .windows(b"/stream-abort".len())
            .any(|window| window == b"/stream-abort");
        let declared_length = body.len() + usize::from(abort_probe) * 4 * 1024 * 1024;
        let connection = if keep_alive { "keep-alive" } else { "close" };
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {declared_length}\r\nConnection: \
             {connection}\r\n\r\n"
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let split = body.len() / 2;
        let _ = stream.write_all(&body[..split]).await;
        if request
            .windows(b"/stream".len())
            .any(|window| window == b"/stream")
        {
            stream_gate.notified().await;
        }

        if let Err(error) = stream.write_all(&body[split..]).await {
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
            ) {
                stream_resets.fetch_add(1, Ordering::SeqCst);
            }
        } else if abort_probe {
            let probe = vec![0_u8; 65_536];
            let probe_error = timeout(Duration::from_secs(2), async {
                for _ in 0..64 {
                    if let Err(error) = stream.write_all(&probe).await {
                        return Some(error.kind());
                    }
                }
                None
            })
            .await;
            if matches!(
                probe_error,
                Ok(Some(
                    ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted,
                ))
            ) {
                stream_resets.fetch_add(1, Ordering::SeqCst);
            }
        }

        if !keep_alive {
            break;
        }
    }
}

/// One canned `application/dns-message` response with an HTTPS record whose
/// ECH configuration the proxy must rewrite (or reject when DNSSEC-bearing).
fn doh_dns_message(dnssec: bool) -> Vec<u8> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{
            Name, RData, Record, RecordType,
            rdata::svcb::{EchConfigList, SVCB, SvcParamKey, SvcParamValue},
            rdata::HTTPS,
        },
    };

    let name = Name::from_ascii("example.test.").expect("valid name");
    let params = vec![
        (SvcParamKey::Port, SvcParamValue::Port(443)),
        (
            SvcParamKey::EchConfigList,
            SvcParamValue::EchConfigList(EchConfigList(vec![1, 2, 3, 4])),
        ),
    ];

    let https = RData::HTTPS(HTTPS(SVCB::new(1, name.clone(), params)));

    let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
    message.metadata.authentic_data = dnssec;
    message.add_query(Query::query(name.clone(), RecordType::HTTPS));
    message.add_answer(Record::from_rdata(name, 300, https));
    message.to_vec().expect("encode DNS response")
}

impl TcpOrigin {
    pub async fn start(ip: IpAddr, port: u16, body: &'static [u8]) -> Self {
        Self::start_with_keep_alive(ip, port, body, false).await
    }

    pub async fn start_keep_alive(ip: IpAddr, port: u16, body: &'static [u8]) -> Self {
        Self::start_with_keep_alive(ip, port, body, true).await
    }

    async fn start_with_keep_alive(
        ip: IpAddr,
        port: u16,
        body: &'static [u8],
        keep_alive: bool,
    ) -> Self {
        let listener = TcpListener::bind(SocketAddr::new(ip, port))
            .await
            .expect("bind TCP origin");
        let address = listener.local_addr().expect("origin address");
        let attempts = Arc::new(AtomicUsize::new(0));
        let stream_gate = Arc::new(Notify::new());
        let task_stream_gate = stream_gate.clone();
        let resets = Arc::new(AtomicUsize::new(0));
        let task_resets = resets.clone();
        let task_attempts = attempts.clone();
        let request_heads = Arc::new(Mutex::new(Vec::new()));
        let task_request_heads = request_heads.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let stream_resets = task_resets.clone();
                let stream_gate = task_stream_gate.clone();
                let request_heads = task_request_heads.clone();
                task_attempts.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_tcp_origin_connection(
                    stream,
                    body,
                    keep_alive,
                    stream_gate,
                    stream_resets,
                    request_heads,
                ));
            }
        });

        Self {
            address,
            stream_gate,
            attempts,
            resets,
            request_heads,
            task: Some(task),
        }
    }
}

impl Drop for TcpOrigin {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Origin selection for one harness.
struct OriginOptions {
    ip: IpAddr,
    origin_port: u16,
    tls: bool,
    keep_alive: bool,
    http3: bool,
    alt_port: Option<u16>,
    certificate: PathBuf,
    private_key: PathBuf,
    root: PathBuf,
}

/// The origins a harness can start; only the modes the harness asked for
/// are populated.
struct HarnessOrigins {
    tcp: TcpOrigin,
    tls: Option<TlsOrigin>,
    h3: Option<Http3Origin>,
}

async fn start_harness_origin(options: OriginOptions) -> HarnessOrigins {
    if options.http3 {
        let gate = options.root.join("gate");
        let alt_svc = options
            .alt_port
            .map(|port| format!("h3=\":{port}\"; persist=1"));
        let origin = Http3Origin::start_with_alt_svc(
            options.ip,
            0,
            &options.certificate,
            &options.private_key,
            &options.root,
            Some(&gate),
            alt_svc.as_deref(),
        )
        .await;

        return HarnessOrigins {
            tcp: TcpOrigin::start(options.ip, free_port(options.ip), b"unused").await,
            tls: None,
            h3: Some(origin),
        };
    }

    if options.tls {
        let origin_address = SocketAddr::new(options.ip, options.origin_port);
        let (origin, tls_origin) = start_tls_origin(
            options.ip,
            origin_address,
            &options.certificate,
            &options.private_key,
        )
        .await;

        return HarnessOrigins {
            tcp: origin,
            tls: Some(tls_origin),
            h3: None,
        };
    }

    let origin = if options.keep_alive {
        TcpOrigin::start_keep_alive(options.ip, options.origin_port, b"origin-response").await
    } else {
        TcpOrigin::start(options.ip, options.origin_port, b"origin-response").await
    };

    HarnessOrigins {
        tcp: origin,
        tls: None,
        h3: None,
    }
}

async fn start_tls_origin(
    ip: IpAddr,
    address: SocketAddr,
    certificate: &Path,
    key: &Path,
) -> (TcpOrigin, TlsOrigin) {
    let listener = TcpListener::bind(address).await.expect("bind TLS origin");
    let inner_port = free_port(ip);

    let child = Command::new("openssl")
        .args([
            "s_server",
            "-quiet",
            "-www",
            "-alpn",
            "http/1.1",
            "-accept",
            &inner_port.to_string(),
            "-cert",
            certificate.to_str().expect("origin certificate path"),
            "-key",
            key.to_str().expect("origin key path"),
        ])
        .stdout(Stdio::null())
        .spawn()
        .expect("start TLS origin");

    wait_for_socket(SocketAddr::new(ip, inner_port)).await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let task_attempts = attempts.clone();

    let task = tokio::spawn(async move {
        loop {
            let Ok((mut downstream, _)) = listener.accept().await else {
                break;
            };
            task_attempts.fetch_add(1, Ordering::SeqCst);
            let Ok(mut upstream) = TcpStream::connect(SocketAddr::new(ip, inner_port)).await else {
                continue;
            };
            let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
        }
    });

    (
        TcpOrigin {
            address,
            attempts,
            resets: Arc::new(AtomicUsize::new(0)),
            stream_gate: Arc::new(Notify::new()),
            request_heads: Arc::new(Mutex::new(Vec::new())),
            task: None,
        },
        TlsOrigin { child, task },
    )
}

pub struct UdpOrigin {
    pub address: SocketAddr,
    pub attempts: Arc<AtomicUsize>,
    pub received: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl UdpOrigin {
    pub async fn start(ip: IpAddr) -> Self {
        let socket = UdpSocket::bind(SocketAddr::new(ip, 0))
            .await
            .expect("bind UDP origin");

        let address = socket.local_addr().expect("UDP origin address");
        let attempts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let task_attempts = attempts.clone();
        let task_received = received.clone();

        let task = tokio::spawn(async move {
            let mut packet = [0; 2048];
            loop {
                let Ok((size, peer)) = socket.recv_from(&mut packet).await else {
                    break;
                };
                task_attempts.fetch_add(1, Ordering::SeqCst);
                task_received
                    .lock()
                    .expect("UDP origin lock")
                    .push(packet[..size].to_vec());
                let _ = socket.send_to(&packet[..size], peer).await;
            }
        });

        Self {
            address,
            attempts,
            received,
            task,
        }
    }
}

impl Drop for UdpOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct TlsOrigin {
    child: Child,
    task: JoinHandle<()>,
}

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.task.abort();
    }
}

/// HTTP/3 origin used by the transparent harness.
///
/// The origin is a separate process (`h3-origin`) that records request and
/// connection events to a log file, so tests can observe upstream attempts
/// and association release without instrumenting the proxy.
pub struct Http3Origin {
    pub address: SocketAddr,
    log: PathBuf,
    child: Child,
}

impl Http3Origin {
    pub async fn start(
        ip: IpAddr,
        port: u16,
        certificate: &Path,
        private_key: &Path,
        root: &Path,
        gate: Option<&Path>,
    ) -> Self {
        Self::start_with_alt_svc(ip, port, certificate, private_key, root, gate, None).await
    }

    /// Start an origin that advertises one `Alt-Svc` value on every
    /// non-stream response.
    pub async fn start_with_alt_svc(
        ip: IpAddr,
        port: u16,
        certificate: &Path,
        private_key: &Path,
        root: &Path,
        gate: Option<&Path>,
        alt_svc: Option<&str>,
    ) -> Self {
        let address = SocketAddr::new(ip, if port == 0 { free_port(ip) } else { port });
        let log = root.join("origin.log");

        let mut command = Command::new(env!("CARGO_BIN_EXE_h3-origin"));
        command.args([
            "--port",
            &address.port().to_string(),
            "--address",
            &ip.to_string(),
            "--certificate",
            certificate.to_str().expect("certificate path"),
            "--private-key",
            private_key.to_str().expect("private key path"),
            "--log",
            log.to_str().expect("log path"),
        ]);

        if let Some(gate) = gate {
            command.args(["--gate", gate.to_str().expect("gate path")]);
        }

        if let Some(alt_svc) = alt_svc {
            command.args(["--alt-svc", alt_svc]);
        }

        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start HTTP/3 origin");

        let origin = Self {
            address,
            log,
            child,
        };

        for _ in 0..200 {
            if std::fs::read_to_string(&origin.log).is_ok_and(|log| log.contains("listening")) {
                return origin;
            }

            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        panic!("HTTP/3 origin did not start listening");
    }

    /// Path of the origin log file.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log
    }

    /// Number of requests the origin has received.
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.request_lines().len()
    }

    /// Request heads in the form `METHOD PATH`.
    #[must_use]
    pub fn request_heads(&self) -> Vec<String> {
        self.request_lines()
    }

    /// Number of upstream associations the origin has accepted.
    #[must_use]
    pub fn connections_opened(&self) -> usize {
        self.log_lines()
            .iter()
            .filter(|line| line.as_str() == "conn-opened")
            .count()
    }

    /// Number of upstream associations the origin has seen close.
    #[must_use]
    pub fn connections_closed(&self) -> usize {
        self.log_lines()
            .iter()
            .filter(|line| line.as_str() == "conn-closed")
            .count()
    }

    fn request_lines(&self) -> Vec<String> {
        self.log_lines()
            .into_iter()
            .filter_map(|line| line.strip_prefix("request ").map(str::to_owned))
            .collect()
    }

    fn log_lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for Http3Origin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One HTTP/3 response with an incremental body reader.
///
/// The request sender is retained because dropping the last handle closes
/// the client's HTTP/3 connection, which the proxy must treat as a critical
/// stream failure.
pub struct Http3Response {
    status: u16,
    headers: http::HeaderMap,
    stream: Option<H3RequestStream>,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _connection: h3::client::Connection<h3_quinn::Connection, bytes::Bytes>,
}

impl Http3Response {
    /// The response status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The response headers.
    #[must_use]
    pub const fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    /// Read the next response body chunk.
    pub async fn next_chunk(&mut self) -> Option<Vec<u8>> {
        let stream = self.stream.as_mut()?;

        if let Ok(Some(mut chunk)) = stream.recv_data().await {
            return Some(chunk.copy_to_bytes(chunk.remaining()).to_vec());
        }

        self.stream = None;
        None
    }

    /// Read the complete response body.
    pub async fn body(mut self) -> Vec<u8> {
        let mut body = Vec::new();

        while let Some(chunk) = self.next_chunk().await {
            body.extend_from_slice(&chunk);
        }

        body
    }
}

type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;

/// HTTP/3 client used by the transparent harness to reach the proxy.
pub struct Http3Client {
    endpoint: quinn::Endpoint,
}

impl Http3Client {
    /// Build a client that trusts the harness CA.
    #[must_use]
    pub fn new(ca_file: &Path) -> Self {
        Self::with_alpn(ca_file, b"h3")
    }

    /// Build a client that offers one explicit ALPN protocol.
    #[must_use]
    pub fn with_alpn(ca_file: &Path, alpn: &[u8]) -> Self {
        let pem = std::fs::read(ca_file).expect("read harness CA");
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse harness CA");

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(certificates);

        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        tls.alpn_protocols = vec![alpn.to_vec()];

        let client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client config");
        let client_config = quinn::ClientConfig::new(Arc::new(client_config));

        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().expect("client address"))
            .expect("client endpoint");
        endpoint.set_default_client_config(client_config);

        Self { endpoint }
    }

    /// Send one GET request and return the response.
    pub async fn request(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Http3Response, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3 = h3_quinn::Connection::new(connection);
        let (connection, mut send_request) = h3::client::new(h3)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("client request");

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("request failed: {error}"))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("response failed: {error}"))?;

        Ok(Http3Response {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            stream: Some(stream),
            _send_request: send_request,
            _connection: connection,
        })
    }
}

/// Extra HTTP/3 options for one harness.
#[derive(Default)]
struct Http3Options {
    alt_port: Option<u16>,
    test_ech_dns: Option<SocketAddr>,
}

pub struct TransparentHarness {
    pub proxy_address: SocketAddr,
    pub origin: TcpOrigin,
    pub udp_origin: UdpOrigin,
    pub policy: FakePolicy,
    pub h3_origin: Option<Http3Origin>,
    /// Address of the alternative endpoint the proxy intercepts, when the
    /// harness started one.
    pub h3_alt_address: Option<SocketAddr>,
    pub proxy_log: PathBuf,
    tls_origin: Option<TlsOrigin>,
    root: TempDir,
    proxy: Child,
}

impl TransparentHarness {
    pub async fn start(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, false, false, false, false, false, Http3Options::default()).await
    }

    pub async fn start_keep_alive(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, false, true, false, false, false, Http3Options::default()).await
    }

    pub async fn start_tls(ip: IpAddr) -> Self {
        Self::start_inner(ip, free_port(ip), true, false, false, false, false, Http3Options::default()).await
    }

    /// Start a plain harness whose origin is an explicit HTTP/1.0 upstream.
    pub async fn start_with_http10_origin(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, false, false, true, false, false, Http3Options::default()).await
    }

    /// Start a harness whose policy service rejects every flow claim.
    pub async fn start_claim_error(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, false, false, false, true, false, Http3Options::default()).await
    }

    /// Start a harness with the HTTP/3 backend enabled and an HTTP/3 origin.
    pub async fn start_http3(ip: IpAddr) -> Self {
        Self::start_inner(
            ip,
            0,
            false,
            false,
            false,
            false,
            true,
            Http3Options::default(),
        )
        .await
    }

    /// Start an HTTP/3 harness whose origin advertises one alternative
    /// endpoint, which the proxy also intercepts.
    pub async fn start_http3_with_alt(ip: IpAddr) -> Self {
        let options = Http3Options {
            alt_port: Some(free_port(ip)),
            ..Http3Options::default()
        };
        Self::start_inner(ip, 0, false, false, false, false, true, options).await
    }

    /// Start an HTTP/3 harness whose upstream ECH lookups use `dns`.
    pub async fn start_http3_with_ech_dns(ip: IpAddr, dns: SocketAddr) -> Self {
        let options = Http3Options {
            test_ech_dns: Some(dns),
            ..Http3Options::default()
        };
        Self::start_inner(ip, 0, false, false, false, false, true, options).await
    }

    #[expect(
        clippy::fn_params_excessive_bools,
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "harness constructor flags map directly to proxy options"
    )]
    async fn start_inner(
        ip: IpAddr,
        origin_port: u16,
        tls: bool,
        keep_alive: bool,
        http10_origin: bool,
        claim_errors: bool,
        http3: bool,
        http3_options: Http3Options,
    ) -> Self {
        let root = tempfile::tempdir().expect("temporary harness directory");
        let policy = if claim_errors {
            FakePolicy::start_claim_error(root.path())
        } else {
            FakePolicy::start(root.path())
        };
        let ca = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate CA");
        let ca_cert = root.path().join("ca.pem");
        let ca_key = root.path().join("ca-key.pem");
        std::fs::write(&ca_cert, ca.cert.pem()).expect("write CA certificate");
        std::fs::write(&ca_key, ca.signing_key.serialize_pem()).expect("write CA key");
        let origin_cert = ca_cert.clone();
        let origin_key = ca_key.clone();

        let origins = start_harness_origin(OriginOptions {
            ip,
            origin_port,
            tls,
            keep_alive,
            http3,
            alt_port: http3_options.alt_port,
            certificate: origin_cert.clone(),
            private_key: origin_key.clone(),
            root: root.path().to_owned(),
        })
        .await;

        let origin = origins.tcp;
        let tls_origin = origins.tls;
        let h3_origin = origins.h3;

        let udp_origin = UdpOrigin::start(ip).await;
        let ready = root.path().join("ready");
        let state = root.path().join("ech");
        let proxy_port = free_port(ip);
        let proxy_address = SocketAddr::new(ip, proxy_port);
        let destination = h3_origin
            .as_ref()
            .map_or(origin.address, |origin| origin.address);
        let mut proxy_command = Command::new(env!("CARGO_BIN_EXE_agent-sandbox-proxy"));

        proxy_command.args([
            "--policy-socket",
            policy.socket.to_str().expect("policy socket path"),
            "--ca-certificate",
            ca_cert.to_str().expect("CA path"),
            "--ca-private-key",
            ca_key.to_str().expect("CA key path"),
            "--ech-state-dir",
            state.to_str().expect("ECH state path"),
            "--listen-port",
            &proxy_port.to_string(),
            "--test-destination",
            &destination.to_string(),
        ]);

        if tls {
            proxy_command.arg("--test-tls");
        }

        if http10_origin {
            proxy_command.args([
                "--http10-upstream-origin",
                &format!("http://localhost:{}", origin.address.port()),
            ]);
        }

        if tls_origin.is_some() {
            proxy_command.env("SSL_CERT_FILE", &origin_cert);
        }

        if http3 {
            proxy_command.args(["--http3", "--http3-listen-port", &proxy_port.to_string()]);

            if let Some(alt_port) = http3_options.alt_port {
                proxy_command.args(["--http3-alt-port", &alt_port.to_string()]);
            }

            if let Some(dns) = http3_options.test_ech_dns {
                proxy_command.args(["--test-ech-dns", &dns.to_string()]);
            }

            proxy_command.env("SSL_CERT_FILE", &origin_cert);
        }

        let proxy_log = root.path().join("proxy.log");

        let proxy = proxy_command
            .env("AGENT_SANDBOX_PROXY_SESSION_READY", &ready)
            .env("INVOCATION_ID", "0123456789abcdef0123456789abcdef")
            .stdout(Stdio::from(
                std::fs::File::create(&proxy_log).expect("create proxy log"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&proxy_log).expect("create proxy log"),
            ))
            .spawn()
            .expect("start proxy");

        wait_for_path(&ready).await;

        let h3_alt_address = http3_options.alt_port.map(|port| SocketAddr::new(ip, port));

        Self {
            proxy_address,
            origin,
            udp_origin,
            policy,
            h3_origin,
            h3_alt_address,
            proxy_log,
            tls_origin,
            root,
            proxy,
        }
    }

    pub async fn request(&self, path: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write client request");

        let mut response = Vec::new();

        stream
            .read_to_end(&mut response)
            .await
            .expect("read client response");

        response
    }

    pub async fn pooled_requests(&self) -> (Vec<u8>, Vec<u8>) {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");
        let host = format!("localhost:{}", self.origin.address.port());

        let first_request = format!("GET /pool-first HTTP/1.1\r\nHost: {host}\r\n\r\n");
        stream
            .write_all(first_request.as_bytes())
            .await
            .expect("write first pooled request");
        let first_response = read_http_response(&mut stream).await;

        let second_request = format!("GET /pool-second HTTP/1.1\r\nHost: {host}\r\n\r\n");
        stream
            .write_all(second_request.as_bytes())
            .await
            .expect("write second pooled request");
        let second_response = read_http_response(&mut stream).await;

        (first_response, second_response)
    }

    pub async fn websocket_request(&self) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");
        let request = format!(
            "GET /websocket HTTP/1.1\r\nHost: localhost:{}\r\nUpgrade: websocket\r\nConnection: \
             Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: \
             13\r\n\r\n",
            self.origin.address.port()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write websocket request");

        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            stream
                .read_exact(&mut byte)
                .await
                .expect("read websocket response");
            response.push(byte[0]);
        }

        stream
            .write_all(b"ping")
            .await
            .expect("write websocket payload");
        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read websocket payload");
        response.extend_from_slice(&payload);
        response
    }

    pub async fn http10_request(&self, path: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!("GET {path} HTTP/1.0\r\nConnection: close\r\n\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write HTTP/1.0 request");

        let mut response = Vec::new();

        stream
            .read_to_end(&mut response)
            .await
            .expect("read HTTP/1.0 response");

        response
    }

    pub async fn streaming_request(&self, path: &str) -> (Vec<u8>, Vec<u8>) {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write client request");

        let mut first = Vec::new();

        while !first.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];

            stream
                .read_exact(&mut byte)
                .await
                .expect("read response header");

            first.push(byte[0]);
        }

        let mut first_body = [0; 7];

        stream
            .read_exact(&mut first_body)
            .await
            .expect("read first response body chunk");

        first.extend_from_slice(&first_body);
        self.origin.stream_gate.notify_one();
        let mut rest = Vec::new();

        stream
            .read_to_end(&mut rest)
            .await
            .expect("read remaining response");

        (first, rest)
    }

    pub async fn abort_streaming_request(&self, path: &str) {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write client request");

        let mut headers = Vec::new();

        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];

            stream
                .read_exact(&mut byte)
                .await
                .expect("read response headers");

            headers.push(byte[0]);
        }

        let mut first_body = [0; 7];

        stream
            .read_exact(&mut first_body)
            .await
            .expect("read first response body chunk");

        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };

        setsockopt(&stream.as_fd(), Linger, &linger).expect("set reset linger");
        drop(stream);
        self.origin.stream_gate.notify_one();
    }

    /// Send raw bytes over TLS to the proxy and return the client output.
    ///
    /// `servername` selects the TLS SNI value, which the proxy treats as the
    /// verified TLS identity for authority resolution.
    pub fn tls_raw_request(&self, request: &str, servername: Option<&str>) -> Vec<u8> {
        let ip = self.proxy_address.ip().to_string();

        let endpoint = if self.proxy_address.is_ipv6() {
            format!("[{ip}]:{}", self.proxy_address.port())
        } else {
            format!("{ip}:{}", self.proxy_address.port())
        };

        let mut command = Command::new("openssl");
        command.args([
            "s_client",
            "-quiet",
            "-connect",
            &endpoint,
            "-CAfile",
            self.root.path().join("ca.pem").to_str().expect("CA path"),
        ]);

        if let Some(servername) = servername {
            command.args(["-servername", servername]);
        }

        let mut client = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start TLS client");

        client
            .stdin
            .take()
            .expect("TLS client stdin")
            .write_all(request.as_bytes())
            .expect("write TLS request");

        client
            .wait_with_output()
            .expect("read TLS client response")
            .stdout
    }

    pub fn tls_request(&self, path: &str) -> Vec<u8> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );
        self.tls_raw_request(&request, None)
    }

    /// Send a hostless HTTP/1.0 request over TLS with SNI.
    pub fn tls_http10_request(&self, path: &str) -> Vec<u8> {
        self.tls_raw_request(&format!("GET {path} HTTP/1.0\r\n\r\n"), Some("localhost"))
    }

    pub fn policy_events(&self) -> Arc<Mutex<PolicyEvents>> {
        self.policy.events.clone()
    }

    /// Send one HTTP/3 GET request through the proxy.
    pub async fn http3_request(&self, path: &str) -> Result<Http3Response, String> {
        self.http3_request_to(self.proxy_address, path).await
    }

    /// Send one HTTP/3 GET request to an explicit proxy endpoint.
    pub async fn http3_request_to(
        &self,
        address: SocketAddr,
        path: &str,
    ) -> Result<Http3Response, String> {
        let client = Http3Client::new(&self.root.path().join("ca.pem"));
        client.request(address, "localhost", path).await
    }

    /// Directory holding the proxy's ECH key material and configuration.
    #[must_use]
    pub fn ech_state_dir(&self) -> PathBuf {
        self.root.path().join("ech")
    }

    /// Path of the harness CA certificate.
    #[must_use]
    pub fn ca_file(&self) -> PathBuf {
        self.root.path().join("ca.pem")
    }

    /// The HTTP/3 origin started with this harness.
    #[must_use]
    pub const fn h3_origin(&self) -> &Http3Origin {
        self.h3_origin.as_ref().expect("HTTP/3 origin")
    }

    /// Path of the streaming gate file for the HTTP/3 origin.
    #[must_use]
    pub fn h3_stream_gate(&self) -> PathBuf {
        self.root.path().join("gate")
    }
}

impl Drop for TransparentHarness {
    fn drop(&mut self) {
        let _ = self.proxy.kill();
        let _ = self.proxy.wait();
        let _ = self.tls_origin.take();
    }
}

fn free_port(ip: IpAddr) -> u16 {
    std::net::TcpListener::bind(SocketAddr::new(ip, 0))
        .expect("reserve proxy port")
        .local_addr()
        .expect("reserved port")
        .port()
}

async fn wait_for_path(path: &Path) {
    timeout(Duration::from_secs(5), async {
        while !path.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy readiness");
}

async fn wait_for_socket(address: SocketAddr) {
    timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TLS origin readiness");
}

pub const fn loopback(version: IpVersion) -> IpAddr {
    match version {
        IpVersion::V4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpVersion::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

#[derive(Clone, Copy)]
pub enum IpVersion {
    V4,
    V6,
}
