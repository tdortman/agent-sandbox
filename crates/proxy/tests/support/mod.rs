use agent_sandbox_core::{
    AttributionToken, ErrorReply, FlowClaimReply, HttpCheckReply, HttpRequest, NetworkFlowKey,
    NetworkFlowSelector, NormalizedPolicyHost, ProxyConnectionId, ProxySessionReply,
    ProxySessionToken, RpcReply, SimpleOkReply, Verdict, VerdictSource,
};
use bytes::{Buf, Bytes};
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
        Arc, LazyLock, Mutex,
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

fn harness_startup_mutex() -> Arc<tokio::sync::Mutex<()>> {
    static LOCK: LazyLock<Arc<tokio::sync::Mutex<()>>> =
        LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

    LOCK.clone()
}

struct HarnessStartupLock {
    path: PathBuf,
    _local_guard: tokio::sync::OwnedMutexGuard<()>,
}

impl HarnessStartupLock {
    async fn acquire() -> Self {
        let local_guard = harness_startup_mutex().lock_owned().await;
        let path = std::env::temp_dir().join("agent-sandbox-proxy-harness-startup.lock");

        loop {
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
            {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id()).expect("write harness lock owner");
                    return Self {
                        path,
                        _local_guard: local_guard,
                    };
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if !harness_lock_owner_is_alive(&path)
                        && let Err(error) = std::fs::remove_file(&path)
                        && error.kind() != ErrorKind::NotFound
                    {
                        panic!("remove stale harness startup lock: {error}");
                    }
                    sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("create harness startup lock: {error}"),
            }
        }
    }
}

impl Drop for HarnessStartupLock {
    fn drop(&mut self) {
        let owner = std::process::id().to_string();

        if std::fs::read_to_string(&self.path).is_ok_and(|contents| contents.trim() == owner)
            && let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != ErrorKind::NotFound
        {
            panic!("remove harness startup lock: {error}");
        }
    }
}

fn harness_lock_owner_is_alive(path: &Path) -> bool {
    let Ok(owner) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = owner.trim().parse::<u32>() else {
        return false;
    };

    Path::new("/proc").join(pid.to_string()).exists()
}

struct PortReservation(std::net::TcpListener);

impl PortReservation {
    fn new(ip: IpAddr) -> Self {
        Self(std::net::TcpListener::bind(SocketAddr::new(ip, 0)).expect("reserve harness port"))
    }

    fn port(&self) -> u16 {
        self.0.local_addr().expect("reserved port address").port()
    }
}

fn free_port(ip: IpAddr) -> u16 {
    PortReservation::new(ip).port()
}

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
        let Some(reply) =
            handle_policy_operation(op, &value, &events, &cancel_gate, claim_errors).await
        else {
            break;
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

async fn handle_policy_operation(
    op: &str,
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    cancel_gate: &Notify,
    claim_errors: bool,
) -> Option<RpcReply> {
    match op {
        "open_proxy_session" => Some(RpcReply::ProxySession(ProxySessionReply {
            ok: true,
            proxy_session: ProxySessionToken::from_bytes([1; 32]),
        })),
        "claim_network_flow" => Some(handle_claim(value, events, claim_errors)),
        "claim_network_flow_by_source" => Some(handle_claim_by_source(value, events, claim_errors)),
        "rebind_network_flow" => Some(handle_rebind(value, events)),
        "check_http" => Some(handle_check(value, events, cancel_gate).await),
        "release_network_flow" => Some(handle_release(value, events)),
        "cancel_check" => Some(handle_cancel(value, events, cancel_gate)),
        _ => None,
    }
}

fn parse_policy_field<T: serde::de::DeserializeOwned>(value: &serde_json::Value, name: &str) -> T {
    serde_json::from_value(value.get(name).cloned().expect(name)).expect(name)
}

fn handle_claim(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    claim_errors: bool,
) -> RpcReply {
    let flow = parse_policy_field(value, "flow");
    handle_claim_flow(value, flow, events, claim_errors)
}

fn handle_claim_by_source(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    claim_errors: bool,
) -> RpcReply {
    let selector: NetworkFlowSelector = parse_policy_field(value, "selector");
    let flow = NetworkFlowKey::new(
        selector.protocol(),
        selector.source_ip(),
        selector.source_port(),
        selector.source_ip(),
        selector.destination_port(),
    );
    handle_claim_flow(value, flow, events, claim_errors)
}

fn handle_claim_flow(
    value: &serde_json::Value,
    flow: NetworkFlowKey,
    events: &Arc<Mutex<PolicyEvents>>,
    claim_errors: bool,
) -> RpcReply {
    let connection_id = parse_policy_field(value, "connection_id");
    events
        .lock()
        .expect("policy events lock")
        .claims
        .push(ClaimEvent {
            flow: flow.clone(),
            connection_id,
        });
    if claim_errors {
        RpcReply::Error(ErrorReply::new("unknown connection identifier"))
    } else {
        RpcReply::FlowClaim(FlowClaimReply {
            ok: true,
            attribution_token: AttributionToken::from_bytes([2; 32]),
            flow,
            policy_host: NormalizedPolicyHost::parse("localhost").expect("valid policy host"),
        })
    }
}

fn handle_rebind(value: &serde_json::Value, events: &Arc<Mutex<PolicyEvents>>) -> RpcReply {
    let flow = parse_policy_field(value, "flow");
    events
        .lock()
        .expect("policy events lock")
        .rebinds
        .push(flow);
    RpcReply::Simple(SimpleOkReply::OK)
}

async fn handle_check(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    cancel_gate: &Notify,
) -> RpcReply {
    let request: HttpRequest = parse_policy_field(value, "request");
    let url = request.url.to_string();
    events
        .lock()
        .expect("policy events lock")
        .checks
        .push(request.clone());
    let request_id = || parse_policy_field(value, "request_id");

    if url.contains("/policy-error") {
        RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
            request_id(),
            RpcReply::Error(ErrorReply::new("socket owner changed")),
        ))
    } else if url.contains("/cancel") {
        cancel_gate.notified().await;
        RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
            request_id(),
            RpcReply::HttpCheck(HttpCheckReply::blocked(
                "agent-sandbox: HTTP check cancelled",
            )),
        ))
    } else {
        let allowed = !url.contains("/deny");
        events
            .lock()
            .expect("policy events lock")
            .decisions
            .push(allowed);
        RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
            request_id(),
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

fn handle_release(value: &serde_json::Value, events: &Arc<Mutex<PolicyEvents>>) -> RpcReply {
    let token = parse_policy_field(value, "attribution_token");
    let connection_id = parse_policy_field(value, "connection_id");
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

fn handle_cancel(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    cancel_gate: &Notify,
) -> RpcReply {
    let request_id = parse_policy_field(value, "request_id");
    events
        .lock()
        .expect("policy events lock")
        .cancellations
        .push(request_id);
    cancel_gate.notify_waiters();
    RpcReply::Simple(SimpleOkReply::OK)
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
            serve_doh_response(&mut stream, &packet).await;
            break;
        }
        let websocket = request
            .windows(b"upgrade: websocket".len())
            .any(|window| window.eq_ignore_ascii_case(b"upgrade: websocket"));

        if websocket {
            serve_websocket_response(&mut stream).await;
            break;
        }

        let abort_probe = request
            .windows(b"/stream-abort".len())
            .any(|window| window == b"/stream-abort");

        serve_origin_body(
            &mut stream,
            body,
            &request,
            keep_alive,
            &stream_gate,
            &stream_resets,
            abort_probe,
        )
        .await;

        if !keep_alive {
            break;
        }
    }
}

async fn serve_doh_response(stream: &mut TcpStream, packet: &[u8]) {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \
         {}\r\nConnection: close\r\n\r\n",
        packet.len()
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(packet).await;
}

async fn serve_websocket_response(stream: &mut TcpStream) {
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
}

async fn serve_origin_body(
    stream: &mut TcpStream,
    body: &[u8],
    request: &[u8],
    keep_alive: bool,
    stream_gate: &Notify,
    stream_resets: &AtomicUsize,
    abort_probe: bool,
) {
    let declared_length = body.len() + usize::from(abort_probe) * 4 * 1024 * 1024;
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {declared_length}\r\nConnection: {connection}\r\n\r\n"
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
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted,
            ))
        ) {
            stream_resets.fetch_add(1, Ordering::SeqCst);
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
            rdata::{
                HTTPS,
                svcb::{EchConfigList, SVCB, SvcParamKey, SvcParamValue},
            },
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

#[derive(Clone, Copy)]
enum TlsAlpn {
    Http11,
    None,
}

const fn harness_tls_alpn(advertise_http11_alpn: bool) -> TlsAlpn {
    if advertise_http11_alpn {
        TlsAlpn::Http11
    } else {
        TlsAlpn::None
    }
}

#[derive(Clone, Copy)]
enum Http3SessionSettings {
    Enabled,
    Rejected,
}

/// Origin selection for one harness.
struct OriginOptions {
    ip: IpAddr,
    origin_port: u16,
    tls: bool,
    tls_alpn: TlsAlpn,
    keep_alive: bool,
    http3: Option<Http3OriginOptions>,
    certificate: PathBuf,
    private_key: PathBuf,
    root: PathBuf,
}

struct Http3OriginOptions {
    alt_port: Option<u16>,
    session_settings: Http3SessionSettings,
    refuse_sessions: bool,
    drop_first_session: bool,
}

/// The origins a harness can start; only the modes the harness asked for
/// are populated.
struct HarnessOrigins {
    tcp: TcpOrigin,
    tls: Option<TlsOrigin>,
    h3: Option<Http3Origin>,
}

async fn start_harness_origin(options: OriginOptions) -> HarnessOrigins {
    if let Some(http3) = options.http3.as_ref() {
        let gate = options.root.join("gate");
        let alt_svc = http3
            .alt_port
            .map(|port| format!("h3=\":{port}\"; persist=1"));
        let origin = Http3Origin::start_with_settings(
            options.ip,
            0,
            &options.certificate,
            &options.private_key,
            &options.root,
            Http3OriginSettings {
                gate: Some(&gate),
                alt_svc: alt_svc.as_deref(),
                reject_sessions: matches!(http3.session_settings, Http3SessionSettings::Rejected),
                refuse_sessions: http3.refuse_sessions,
                drop_first_session: http3.drop_first_session,
            },
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
            options.tls_alpn,
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
    tls_alpn: TlsAlpn,
) -> (TcpOrigin, TlsOrigin) {
    let listener = TcpListener::bind(address).await.expect("bind TLS origin");
    let inner_port = free_port(ip);

    let mut command = Command::new("openssl");
    command.args([
        "s_server",
        "-quiet",
        "-www",
        "-accept",
        &inner_port.to_string(),
        "-cert",
        certificate.to_str().expect("origin certificate path"),
        "-key",
        key.to_str().expect("origin key path"),
    ]);

    if matches!(tls_alpn, TlsAlpn::Http11) {
        command.args(["-alpn", "http/1.1"]);
    }

    let child = command
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

struct Http3OriginSettings<'a> {
    gate: Option<&'a Path>,
    alt_svc: Option<&'a str>,
    reject_sessions: bool,
    refuse_sessions: bool,
    drop_first_session: bool,
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
        Self::start_with_settings(
            ip,
            port,
            certificate,
            private_key,
            root,
            Http3OriginSettings {
                gate,
                alt_svc: None,
                reject_sessions: false,
                refuse_sessions: false,
                drop_first_session: false,
            },
        )
        .await
    }

    async fn start_with_settings(
        ip: IpAddr,
        port: u16,
        certificate: &Path,
        private_key: &Path,
        root: &Path,
        settings: Http3OriginSettings<'_>,
    ) -> Self {
        let address = SocketAddr::new(ip, port);
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

        if let Some(gate) = settings.gate {
            command.args(["--gate", gate.to_str().expect("gate path")]);
        }

        if let Some(alt_svc) = settings.alt_svc {
            command.args(["--alt-svc", alt_svc]);
        }

        if settings.reject_sessions {
            command.arg("--reject-sessions");
        }

        if settings.refuse_sessions {
            command.arg("--refuse-sessions");
        }

        if settings.drop_first_session {
            command.arg("--drop-first-session");
        }

        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start HTTP/3 origin");

        let mut origin = Self {
            address,
            log,
            child,
        };

        for _ in 0..200 {
            let listening_address = std::fs::read_to_string(&origin.log).ok().and_then(|log| {
                log.lines()
                    .find_map(|line| line.strip_prefix("listening ")?.parse().ok())
            });

            if let Some(listening_address) = listening_address {
                origin.address = listening_address;
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

        match stream.recv_data().await {
            Ok(Some(mut chunk)) => Some(chunk.copy_to_bytes(chunk.remaining()).to_vec()),
            Ok(None) => {
                self.stream = None;
                None
            }
            Err(error) => panic!("response body failed: {error}"),
        }
    }

    /// Read the complete response body.
    pub async fn body(self) -> Vec<u8> {
        self.body_with_trailers().await.0
    }

    /// Read the complete response body and trailers.
    pub async fn body_with_trailers(mut self) -> (Vec<u8>, http::HeaderMap) {
        let mut body = Vec::new();

        let Some(mut stream) = self.stream.take() else {
            return (body, http::HeaderMap::new());
        };

        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .unwrap_or_else(|error| panic!("response body failed: {error}"))
        {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        let trailers = stream
            .recv_trailers()
            .await
            .unwrap_or_else(|error| panic!("response trailers failed: {error}"))
            .unwrap_or_default();

        (body, trailers)
    }
}

type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;

const MAX_INFORMATIONAL_RESPONSES: usize = 16;

fn assert_webtransport_response(response: &http::Response<()>) -> Result<(), String> {
    if !response.status().is_success() {
        return Err(format!("WebTransport response was {}", response.status()));
    }

    if response.headers().get("x-origin-webtransport")
        != Some(&http::HeaderValue::from_static("preserved"))
    {
        return Err("WebTransport response header was not preserved".to_owned());
    }
    Ok(())
}

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
        Self::with_alpn_and_ip(ca_file, alpn, IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }

    /// Build an HTTP/3 client bound to one local address family.
    #[must_use]
    pub fn with_local_ip(ca_file: &Path, local_ip: IpAddr) -> Self {
        Self::with_alpn_and_ip(ca_file, b"h3", local_ip)
    }

    /// Build an HTTP/3 client that offers QUIC 0-RTT data.
    #[must_use]
    pub fn with_early_data(ca_file: &Path) -> Self {
        Self::with_alpn_and_ip_and_early_data(
            ca_file,
            b"h3",
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            true,
        )
    }

    fn with_alpn_and_ip(ca_file: &Path, alpn: &[u8], local_ip: IpAddr) -> Self {
        Self::with_alpn_and_ip_and_early_data(ca_file, alpn, local_ip, false)
    }

    fn with_alpn_and_ip_and_early_data(
        ca_file: &Path,
        alpn: &[u8],
        local_ip: IpAddr,
        enable_early_data: bool,
    ) -> Self {
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

        if enable_early_data {
            tls.enable_early_data = true;
        }

        let client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client config");
        let client_config = quinn::ClientConfig::new(Arc::new(client_config));

        let mut endpoint =
            quinn::Endpoint::client(SocketAddr::new(local_ip, 0)).expect("client endpoint");
        endpoint.set_default_client_config(client_config);

        Self { endpoint }
    }

    /// Report whether a resumed connection accepts QUIC 0-RTT data.
    ///
    /// Returns `None` when the server does not issue a resumption ticket.
    pub async fn zero_rtt_is_accepted(
        &self,
        server: SocketAddr,
        server_name: &str,
    ) -> Result<Option<bool>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        match connecting.into_0rtt() {
            Ok((connection, accepted)) => {
                let accepted = timeout(Duration::from_secs(5), accepted)
                    .await
                    .map_err(|_| "0-RTT acceptance timed out".to_owned())?;
                connection.close(quinn::VarInt::from_u32(0), b"0-RTT probe");
                Ok(Some(accepted))
            }

            Err(connecting) => {
                let connection = timeout(Duration::from_secs(5), connecting)
                    .await
                    .map_err(|_| "QUIC handshake timed out".to_owned())?
                    .map_err(|error| format!("QUIC handshake failed: {error}"))?;
                connection.close(quinn::VarInt::from_u32(0), b"0-RTT unavailable");
                Ok(None)
            }
        }
    }

    /// Send one GET request and return the response.
    pub async fn request(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Http3Response, String> {
        let (_, response) = self
            .request_with_informational(server, server_name, path)
            .await?;
        Ok(response)
    }

    /// Send one GET request and retain informational responses.
    pub async fn request_with_informational(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(Vec<http::Response<()>>, Http3Response), String> {
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

        let (informational, response) = stream
            .recv_response_with_informational()
            .await
            .map_err(|error| format!("response failed: {error}"))?;

        Ok((informational, Http3Response {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            stream: Some(stream),
            _send_request: send_request,
            _connection: connection,
        }))
    }

    /// Send a POST request that waits for `100 Continue` before its body.
    pub async fn request_with_expect(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Http3Response, String> {
        self.request_with_body(server, server_name, path, true, false)
            .await
    }

    /// Send a POST request with request trailers.
    pub async fn request_with_trailers(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Http3Response, String> {
        self.request_with_body(server, server_name, path, false, true)
            .await
    }

    async fn request_with_body(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        expect_continue: bool,
        send_trailers: bool,
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

        let mut request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{server_name}{path}"));

        if expect_continue {
            request = request.header("expect", "100-continue");
        }
        if send_trailers {
            request = request.header("trailer", "x-request-trailer");
        }
        let request = request.body(()).expect("client request");
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("request failed: {error}"))?;

        let early_response = if expect_continue {
            let mut informational_count = 0;
            loop {
                let response = stream
                    .recv_response_head()
                    .await
                    .map_err(|error| format!("response failed: {error}"))?;

                if response.status() == http::StatusCode::CONTINUE {
                    break None;
                }

                if response.status().is_informational() {
                    if informational_count == MAX_INFORMATIONAL_RESPONSES {
                        return Err("too many informational responses".to_owned());
                    }
                    informational_count += 1;
                    continue;
                }

                break Some(response);
            }
        } else {
            None
        };

        if let Some(response) = early_response {
            return Ok(Http3Response {
                status: response.status().as_u16(),
                headers: response.headers().clone(),
                stream: Some(stream),
                _send_request: send_request,
                _connection: connection,
            });
        }

        stream
            .send_data(Bytes::from_static(b"request-body"))
            .await
            .map_err(|error| format!("request body failed: {error}"))?;

        if send_trailers {
            let mut trailers = http::HeaderMap::new();
            trailers.insert(
                "x-request-trailer",
                http::HeaderValue::from_static("present"),
            );

            stream
                .send_trailers(trailers)
                .await
                .map_err(|error| format!("request trailers failed: {error}"))?;
        }

        stream
            .finish()
            .await
            .map_err(|error| format!("request finish failed: {error}"))?;

        let (_, response) = stream
            .recv_response_with_informational()
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

    /// Rebind one live HTTP/3 request to a new local UDP address.
    pub async fn request_with_rebind(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        local_ip: IpAddr,
        release_gate: Option<&Path>,
    ) -> Result<Vec<u8>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;
        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;
        let h3 = h3_quinn::Connection::new(quinn_connection.clone());
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
        if !response.status().is_success() {
            return Err(format!("unexpected response status {}", response.status()));
        }

        let mut body = Vec::new();

        if let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("response body failed: {error}"))?
        {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        let socket = std::net::UdpSocket::bind(SocketAddr::new(local_ip, 0))
            .map_err(|error| format!("bind migration socket failed: {error}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| format!("set migration socket nonblocking failed: {error}"))?;
        self.endpoint
            .rebind(socket)
            .map_err(|error| format!("rebind QUIC endpoint failed: {error}"))?;

        stream
            .finish()
            .await
            .map_err(|error| format!("finish migration request failed: {error}"))?;

        if let Some(gate) = release_gate {
            std::fs::write(gate, b"open")
                .map_err(|error| format!("open migration stream gate failed: {error}"))?;
        }

        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("response body failed: {error}"))?
        {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        quinn_connection.close(quinn::VarInt::from_u32(0), b"migration complete");
        drop(send_request);
        drop(connection);
        Ok(body)
    }

    pub async fn websocket_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;
        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;
        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true);
        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("WebSocket request");
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::WEBSOCKET);
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("WebSocket request failed: {error}"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("WebSocket response failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("WebSocket response was {}", response.status()));
        }

        stream
            .send_data(bytes::Bytes::from_static(b"websocket-probe"))
            .await
            .map_err(|error| format!("WebSocket request body failed: {error}"))?;
        stream
            .finish()
            .await
            .map_err(|error| format!("WebSocket request close failed: {error}"))?;

        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("WebSocket response body failed: {error}"))?
        {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(stream);
        drop(send_request);
        drop(h3_connection);
        Ok(body)
    }

    /// Open one WebTransport child stream and read the origin response.
    pub async fn webtransport_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        self.webtransport_probe_with_settings(server, server_name, path, true, false)
            .await
    }

    /// Open one WebTransport child stream without HTTP Datagram support.
    pub async fn webtransport_probe_without_datagram(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        self.webtransport_probe_with_settings(server, server_name, path, false, false)
            .await
    }

    /// Open a child stream with an unapproved WebTransport session ID.
    pub async fn webtransport_invalid_session_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.webtransport_probe_with_settings(server, server_name, path, true, true)
            .await
            .map(|_| ())
    }

    async fn webtransport_probe_with_settings(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        enable_datagram: bool,
        invalid_session: bool,
    ) -> Result<Vec<u8>, String> {
        use h3::quic::{RecvStream as _, SendStream as _};
        use h3_datagram::datagram_handler::HandleDatagramsExt;

        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;
        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;
        let h3_quic = h3_quinn::Connection::new(quinn_connection.clone());
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true);

        if enable_datagram {
            builder.enable_datagram(true);
        }

        builder.enable_webtransport(true);
        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("WebTransport request");
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::WEB_TRANSPORT);
        let mut connect_stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("WebTransport request failed: {error}"))?;
        let session_id = h3::webtransport::SessionId::from(connect_stream.id());
        let child_session_id = if invalid_session {
            h3::webtransport::SessionId::try_from(4).expect("invalid session id")
        } else {
            session_id
        };
        let response = connect_stream
            .recv_response()
            .await
            .map_err(|error| format!("WebTransport response failed: {error}"))?;
        assert_webtransport_response(&response)?;
        if enable_datagram && !invalid_session {
            let stream_id = connect_stream.id();
            let mut datagram_sender = h3_connection.get_datagram_sender(stream_id);
            let mut datagram_reader = h3_connection.get_datagram_reader();
            datagram_sender
                .send_datagram(bytes::Bytes::from_static(b"\0webtransport-datagram"))
                .map_err(|error| format!("WebTransport datagram send failed: {error}"))?;
            let datagram =
                tokio::time::timeout(Duration::from_secs(5), datagram_reader.read_datagram())
                    .await
                    .map_err(|_| "WebTransport datagram receive timed out".to_owned())?
                    .map_err(|error| format!("WebTransport datagram receive failed: {error}"))?;
            if datagram.stream_id() != stream_id {
                return Err("WebTransport datagram stream context changed".to_owned());
            }
            if datagram.into_payload() != bytes::Bytes::from_static(b"\0webtransport-datagram") {
                return Err("WebTransport datagram payload changed".to_owned());
            }
        }

        let child_quic = h3_quinn::Connection::new(quinn_connection);
        let mut opener =
            <h3_quinn::Connection as h3::quic::Connection<bytes::Bytes>>::opener(&child_quic);
        let mut child = std::future::poll_fn(|context| {
            <h3_quinn::OpenStreams as h3::quic::OpenStreams<bytes::Bytes>>::poll_open_bidi(
                &mut opener,
                context,
            )
        })
        .await
        .map_err(|error| format!("WebTransport child stream failed: {error}"))?;
        child
            .send_data(h3::stream::BidiStreamHeader::WebTransportBidi(
                child_session_id,
            ))
            .map_err(|error| format!("WebTransport child header failed: {error}"))?;
        std::future::poll_fn(|context| child.poll_ready(context))
            .await
            .map_err(|error| format!("WebTransport child header failed: {error}"))?;
        std::future::poll_fn(|context| child.poll_finish(context))
            .await
            .map_err(|error| format!("WebTransport child close failed: {error}"))?;

        let mut body = Vec::new();
        while let Some(mut chunk) = std::future::poll_fn(|context| child.poll_data(context))
            .await
            .map_err(|error| format!("WebTransport child response failed: {error}"))?
        {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(connect_stream);
        drop(send_request);
        drop(h3_connection);
        Ok(body)
    }

    pub async fn connect_udp_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        self.connect_udp_probe_with_context(server, server_name, path, false)
            .await
    }

    pub async fn connect_udp_capsule_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<(u64, Vec<u8>)>, String> {
        self.connect_udp_capsule_probe_with_settings(server, server_name, path, false, true)
            .await
    }

    pub async fn connect_udp_capsule_probe_without_protocol(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.connect_udp_capsule_probe_with_settings(server, server_name, path, false, false)
            .await
            .map(|_| ())
    }

    pub async fn connect_udp_malformed_capsule_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.connect_udp_capsule_probe_with_settings(server, server_name, path, true, true)
            .await
            .map(|_| ())
    }

    async fn connect_udp_capsule_probe_with_settings(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        malformed: bool,
        capsule_protocol: bool,
    ) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;
        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;
        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("CONNECT-UDP request");
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_UDP);
        if capsule_protocol {
            request
                .headers_mut()
                .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
        }
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("CONNECT-UDP request failed: {error}"))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("CONNECT-UDP response failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("CONNECT-UDP response was {}", response.status()));
        }

        let body = if malformed {
            vec![0, 5, 1, 2]
        } else {
            [
                encode_test_capsule(0, b"\0capsule-probe"),
                encode_test_capsule(0x21, b"unknown-capsule"),
            ]
            .concat()
        };
        if let Err(error) = stream.send_data(bytes::Bytes::from(body)).await {
            return malformed
                .then_some(Vec::new())
                .ok_or_else(|| format!("CONNECT-UDP Capsule Protocol body failed: {error}"));
        }
        if let Err(error) = stream.finish().await {
            return malformed
                .then_some(Vec::new())
                .ok_or_else(|| format!("CONNECT-UDP Capsule Protocol close failed: {error}"));
        }

        if malformed {
            return match tokio::time::timeout(Duration::from_secs(5), stream.recv_data()).await {
                Ok(Err(_)) => Ok(Vec::new()),
                Ok(Ok(_)) => Err("malformed CONNECT-UDP capsule was accepted".to_owned()),
                Err(_) => Err("malformed CONNECT-UDP capsule was not reset".to_owned()),
            };
        }

        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("CONNECT-UDP capsule response failed: {error}"))?
        {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(stream);
        drop(send_request);
        drop(h3_connection);
        decode_test_capsules(&body)
    }

    pub async fn connect_udp_invalid_context_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.connect_udp_probe_with_context(server, server_name, path, true)
            .await
            .map(|_| ())
    }

    pub async fn connect_udp_two_streams_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        first_path: &str,
        second_path: &str,
    ) -> Result<Vec<Vec<u8>>, String> {
        use h3_datagram::datagram_handler::HandleDatagramsExt;

        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;
        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;
        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut streams = Vec::new();
        for path in [first_path, second_path] {
            let mut request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("https://{server_name}{path}"))
                .body(())
                .expect("CONNECT-UDP request");
            request
                .extensions_mut()
                .insert(h3::ext::Protocol::CONNECT_UDP);
            let mut stream = send_request
                .send_request(request)
                .await
                .map_err(|error| format!("CONNECT-UDP request failed: {error}"))?;
            let response = stream
                .recv_response()
                .await
                .map_err(|error| format!("CONNECT-UDP response failed: {error}"))?;
            if !response.status().is_success() {
                return Err(format!("CONNECT-UDP response was {}", response.status()));
            }
            streams.push(stream);
        }

        let stream_ids = [streams[0].id(), streams[1].id()];
        if stream_ids[0] == stream_ids[1] {
            return Err("CONNECT-UDP request streams reused one ID".to_owned());
        }
        let mut senders = [
            h3_connection.get_datagram_sender(stream_ids[0]),
            h3_connection.get_datagram_sender(stream_ids[1]),
        ];
        for (index, sender) in senders.iter_mut().enumerate() {
            sender
                .send_datagram(bytes::Bytes::from(format!("\0route-{index}")))
                .map_err(|error| format!("CONNECT-UDP datagram send failed: {error}"))?;
        }

        let mut datagram_reader = h3_connection.get_datagram_reader();
        let mut bodies = [None, None];
        for _ in 0..2 {
            let datagram = datagram_reader
                .read_datagram()
                .await
                .map_err(|error| format!("CONNECT-UDP datagram receive failed: {error}"))?;
            let index = stream_ids
                .iter()
                .position(|stream_id| *stream_id == datagram.stream_id())
                .ok_or_else(|| "CONNECT-UDP datagram context changed".to_owned())?;
            let payload = datagram.into_payload();
            if payload.first() != Some(&0) {
                return Err("CONNECT-UDP inner context changed".to_owned());
            }
            bodies[index] = Some(payload.slice(1..).to_vec());
        }

        for stream in &mut streams {
            stream
                .finish()
                .await
                .map_err(|error| format!("CONNECT-UDP session close failed: {error}"))?;
        }

        Ok(bodies
            .into_iter()
            .map(|body| body.expect("two CONNECT-UDP responses"))
            .collect())
    }

    async fn connect_udp_probe_with_context(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        invalid_context: bool,
    ) -> Result<Vec<u8>, String> {
        use h3_datagram::datagram_handler::HandleDatagramsExt;

        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;
        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;
        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("CONNECT-UDP request");
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_UDP);
        let mut connect_stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("CONNECT-UDP request failed: {error}"))?;
        let stream_id = connect_stream.id();
        let response = connect_stream
            .recv_response()
            .await
            .map_err(|error| format!("CONNECT-UDP response failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("CONNECT-UDP response was {}", response.status()));
        }

        let datagram_context = stream_id;
        let mut datagram_sender = h3_connection.get_datagram_sender(datagram_context);
        let mut datagram_reader = h3_connection.get_datagram_reader();
        let payload = if invalid_context {
            bytes::Bytes::from_static(b"\x01connect-udp-probe")
        } else {
            bytes::Bytes::from_static(b"\0connect-udp-probe")
        };
        datagram_sender
            .send_datagram(payload)
            .map_err(|error| format!("CONNECT-UDP datagram send failed: {error}"))?;
        if invalid_context {
            return match connect_stream.recv_data().await {
                Err(_error) => Ok(Vec::new()),
                Ok(_) => Err("invalid CONNECT-UDP context was accepted".to_owned()),
            };
        }
        let datagram = datagram_reader
            .read_datagram()
            .await
            .map_err(|error| format!("CONNECT-UDP datagram receive failed: {error}"))?;
        if datagram.stream_id() != stream_id {
            return Err("CONNECT-UDP datagram context changed".to_owned());
        }

        connect_stream
            .finish()
            .await
            .map_err(|error| format!("CONNECT-UDP session close failed: {error}"))?;
        let payload = datagram.into_payload();
        if payload.first() != Some(&0) {
            return Err("CONNECT-UDP inner context changed".to_owned());
        }

        Ok(payload.slice(1..).to_vec())
    }
}

fn encode_test_capsule(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_test_varint(kind, &mut encoded);
    encode_test_varint(
        u64::try_from(payload.len()).expect("capsule payload length fits"),
        &mut encoded,
    );
    encoded.extend_from_slice(payload);
    encoded
}

fn decode_test_capsules(mut encoded: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut capsules = Vec::new();
    while !encoded.is_empty() {
        let Some((kind, kind_len)) = decode_test_varint(encoded) else {
            return Err("truncated Capsule Protocol type".to_owned());
        };
        let Some((length, length_len)) = decode_test_varint(&encoded[kind_len..]) else {
            return Err("truncated Capsule Protocol length".to_owned());
        };
        let length = usize::try_from(length).map_err(|_| "Capsule Protocol length is too large")?;
        let start = kind_len + length_len;
        let end = start
            .checked_add(length)
            .ok_or("Capsule Protocol length overflows")?;
        if end > encoded.len() {
            return Err("truncated Capsule Protocol payload".to_owned());
        }
        capsules.push((kind, encoded[start..end].to_vec()));
        encoded = &encoded[end..];
    }
    Ok(capsules)
}

fn encode_test_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(u8::try_from(value).expect("bounded test varint")),
        64..=16_383 => {
            let value = u16::try_from(value | 0x4000).expect("bounded test varint");
            output.extend_from_slice(&value.to_be_bytes());
        }
        16_384..=1_073_741_823 => {
            let value = u32::try_from(value | 0x8000_0000).expect("bounded test varint");
            output.extend_from_slice(&value.to_be_bytes());
        }
        _ => {
            let value = value | 0xC000_0000_0000_0000;
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_test_varint(encoded: &[u8]) -> Option<(u64, usize)> {
    let first = encoded.first().copied()?;
    let length = 1usize << (first >> 6);
    if encoded.len() < length {
        return None;
    }

    let mut value = u64::from(first & 0x3F);
    for byte in &encoded[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

/// Extra HTTP/3 options for one harness.
#[derive(Default)]
enum Http3AltPort {
    #[default]
    None,
    Allocate,
    Fixed(u16),
}

impl Http3AltPort {
    const fn value(&self) -> Option<u16> {
        match self {
            Self::Fixed(port) => Some(*port),
            Self::None | Self::Allocate => None,
        }
    }
}

/// Extra HTTP/3 options for one harness.
#[derive(Default)]
struct Http3Options {
    alt_port: Http3AltPort,
    test_ech_dns: Option<SocketAddr>,
    reject_sessions: bool,
    refuse_sessions: bool,
    drop_first_session: bool,
}

impl Http3Options {
    fn resolve_alt_port(&mut self, enabled: bool, ip: IpAddr) {
        if enabled && matches!(&self.alt_port, Http3AltPort::Allocate) {
            self.alt_port = Http3AltPort::Fixed(free_port(ip));
        }
    }

    const fn session_settings(&self) -> Http3SessionSettings {
        if self.reject_sessions {
            Http3SessionSettings::Rejected
        } else {
            Http3SessionSettings::Enabled
        }
    }
}

#[derive(Default)]
enum HarnessMode {
    #[default]
    Plain,
    Http10Origin,
    ClaimErrors,
    Http3(Http3Options),
}

#[derive(Default)]
struct HarnessOptions {
    tls: bool,
    advertise_http11_alpn: bool,
    keep_alive: bool,
    mode: HarnessMode,
}

fn harness_mode_options(mode: HarnessMode) -> (bool, bool, bool, Http3Options) {
    match mode {
        HarnessMode::Plain => (false, false, false, Http3Options::default()),
        HarnessMode::Http10Origin => (true, false, false, Http3Options::default()),
        HarnessMode::ClaimErrors => (false, true, false, Http3Options::default()),
        HarnessMode::Http3(options) => (false, false, true, options),
    }
}

fn spawn_harness_proxy(mut command: Command, proxy_log: &Path, ready: &Path) -> Child {
    command
        .env("AGENT_SANDBOX_PROXY_SESSION_READY", ready)
        .env("INVOCATION_ID", "0123456789abcdef0123456789abcdef")
        .stdout(Stdio::from(
            std::fs::File::create(proxy_log).expect("create proxy log"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(proxy_log).expect("create proxy log"),
        ))
        .spawn()
        .expect("start proxy")
}
fn write_harness_ca(root: &TempDir) -> (PathBuf, PathBuf) {
    let ca = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate CA");
    let ca_cert = root.path().join("ca.pem");
    let ca_key = root.path().join("ca-key.pem");
    std::fs::write(&ca_cert, ca.cert.pem()).expect("write CA certificate");
    std::fs::write(&ca_key, ca.signing_key.serialize_pem()).expect("write CA key");
    (ca_cert, ca_key)
}
fn start_harness_policy(root: &TempDir, claim_errors: bool) -> FakePolicy {
    if claim_errors {
        FakePolicy::start_claim_error(root.path())
    } else {
        FakePolicy::start(root.path())
    }
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
        Self::start_inner(ip, origin_port, HarnessOptions::default()).await
    }

    pub async fn start_keep_alive(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, HarnessOptions {
            keep_alive: true,
            ..HarnessOptions::default()
        })
        .await
    }

    pub async fn start_tls(ip: IpAddr) -> Self {
        Self::start_inner(ip, free_port(ip), HarnessOptions {
            tls: true,
            advertise_http11_alpn: true,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a TLS harness whose origin does not advertise ALPN.
    pub async fn start_tls_without_alpn(ip: IpAddr) -> Self {
        Self::start_inner(ip, free_port(ip), HarnessOptions {
            tls: true,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a plain harness whose origin is an explicit HTTP/1.0 upstream.
    pub async fn start_with_http10_origin(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, HarnessOptions {
            mode: HarnessMode::Http10Origin,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a harness whose policy service rejects every flow claim.
    pub async fn start_claim_error(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, HarnessOptions {
            mode: HarnessMode::ClaimErrors,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a harness with the HTTP/3 backend enabled and an HTTP/3 origin.
    pub async fn start_http3(ip: IpAddr) -> Self {
        Self::start_inner(ip, 0, HarnessOptions {
            mode: HarnessMode::Http3(Http3Options::default()),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose origin omits session settings.
    pub async fn start_http3_rejecting_sessions(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            reject_sessions: true,
            ..Http3Options::default()
        };
        Self::start_inner(ip, 0, HarnessOptions {
            mode: HarnessMode::Http3(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose origin refuses approved sessions.
    pub async fn start_http3_refusing_sessions(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            refuse_sessions: true,
            ..Http3Options::default()
        };
        Self::start_inner(ip, 0, HarnessOptions {
            mode: HarnessMode::Http3(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose first approved session closes early.
    pub async fn start_http3_reconnecting_sessions(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            drop_first_session: true,
            ..Http3Options::default()
        };
        Self::start_inner(ip, 0, HarnessOptions {
            mode: HarnessMode::Http3(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose origin advertises one alternative
    /// endpoint, which the proxy also intercepts.
    pub async fn start_http3_with_alt(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            alt_port: Http3AltPort::Allocate,
            ..Http3Options::default()
        };
        Self::start_inner(ip, 0, HarnessOptions {
            mode: HarnessMode::Http3(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose upstream ECH lookups use `dns`.
    pub async fn start_http3_with_ech_dns(ip: IpAddr, dns: SocketAddr) -> Self {
        let http3_options = Http3Options {
            test_ech_dns: Some(dns),
            ..Http3Options::default()
        };
        Self::start_inner(ip, 0, HarnessOptions {
            mode: HarnessMode::Http3(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    async fn start_inner(ip: IpAddr, origin_port: u16, options: HarnessOptions) -> Self {
        let HarnessOptions {
            tls,
            advertise_http11_alpn,
            keep_alive,
            mode,
        } = options;

        let _startup_lock = HarnessStartupLock::acquire().await;

        let (http10_origin, claim_errors, http3, mut http3_options) = harness_mode_options(mode);

        http3_options.resolve_alt_port(http3, ip);
        let root = tempfile::tempdir().expect("temporary harness directory");
        let policy = start_harness_policy(&root, claim_errors);
        let (ca_cert, ca_key) = write_harness_ca(&root);

        let origins = start_harness_origin(OriginOptions {
            ip,
            origin_port,
            tls,
            tls_alpn: harness_tls_alpn(advertise_http11_alpn),
            keep_alive,
            http3: http3.then_some(Http3OriginOptions {
                alt_port: http3_options.alt_port.value(),
                session_settings: http3_options.session_settings(),
                refuse_sessions: http3_options.refuse_sessions,
                drop_first_session: http3_options.drop_first_session,
            }),
            certificate: ca_cert.clone(),
            private_key: ca_key.clone(),
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
            proxy_command.env("SSL_CERT_FILE", &ca_cert);
        }

        if http3 {
            proxy_command
                .args(["--enable-http3-backend", "--http3-listen-port"])
                .arg(proxy_port.to_string());

            if let Some(alt_port) = http3_options.alt_port.value() {
                proxy_command.args(["--http3-alt-port", &alt_port.to_string()]);
            }

            if let Some(dns) = http3_options.test_ech_dns {
                proxy_command.args(["--test-ech-dns", &dns.to_string()]);
            }

            proxy_command.env("SSL_CERT_FILE", &ca_cert);
        }

        let proxy_log = root.path().join("proxy.log");

        let proxy = spawn_harness_proxy(proxy_command, &proxy_log, &ready);

        wait_for_path(&ready).await;

        let h3_alt_address = http3_options
            .alt_port
            .value()
            .map(|port| SocketAddr::new(ip, port));

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
