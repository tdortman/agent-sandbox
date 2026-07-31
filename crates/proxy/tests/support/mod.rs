use agent_sandbox_core::{
    AttributionToken, FlowClaimReply, HttpCheckReply, HttpRequest, ProxySessionReply,
    ProxySessionToken, RpcReply, Verdict, VerdictSource,
};
use nix::{
    libc,
    sys::socket::{setsockopt, sockopt::Linger},
};
use rcgen::generate_simple_self_signed;
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

#[derive(Debug, Default)]
pub struct PolicyEvents {
    pub claims: Vec<agent_sandbox_core::NetworkFlowKey>,
    pub checks: Vec<HttpRequest>,
    pub decisions: Vec<bool>,
    pub releases: Vec<AttributionToken>,
}

pub struct FakePolicy {
    pub socket: PathBuf,
    pub events: Arc<Mutex<PolicyEvents>>,
    task: JoinHandle<()>,
}

impl FakePolicy {
    pub fn start(root: &Path) -> Self {
        let socket = root.join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind fake policy socket");
        let events = Arc::new(Mutex::new(PolicyEvents::default()));
        let task_events = events.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let events = task_events.clone();
                tokio::spawn(async move {
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
                                let flow = serde_json::from_value(
                                    value.get("flow").cloned().expect("flow"),
                                )
                                .expect("flow value");
                                events.lock().expect("policy events lock").claims.push(flow);
                                RpcReply::FlowClaim(FlowClaimReply {
                                    ok: true,
                                    attribution_token: AttributionToken::from_bytes([2; 32]),
                                })
                            }
                            "check_http" => {
                                let request: HttpRequest = serde_json::from_value(
                                    value.get("request").cloned().expect("request"),
                                )
                                .expect("HTTP request value");
                                let allowed = !request.url.to_string().contains("/deny");
                                let mut events = events.lock().expect("policy events lock");
                                events.checks.push(request.clone());
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
                            "release_network_flow" => {
                                let token = serde_json::from_value(
                                    value.get("attribution_token").cloned().expect("token"),
                                )
                                .expect("attribution token");
                                events
                                    .lock()
                                    .expect("policy events lock")
                                    .releases
                                    .push(token);
                                RpcReply::Simple(agent_sandbox_core::SimpleOkReply::OK)
                            }
                            "cancel_check" => {
                                RpcReply::Simple(agent_sandbox_core::SimpleOkReply::OK)
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
                });
            }
        });

        Self {
            socket,
            events,
            task,
        }
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

pub struct TransparentHarness {
    pub proxy_address: SocketAddr,
    pub origin: TcpOrigin,
    pub udp_origin: UdpOrigin,
    pub policy: FakePolicy,
    tls_origin: Option<TlsOrigin>,
    root: TempDir,
    proxy: Child,
}

impl TransparentHarness {
    pub async fn start(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, false, false, false).await
    }

    pub async fn start_keep_alive(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, false, true, false).await
    }

    pub async fn start_tls(ip: IpAddr) -> Self {
        Self::start_inner(ip, free_port(ip), true, false, false).await
    }

    /// Start a plain harness whose origin is an explicit HTTP/1.0 upstream.
    pub async fn start_with_http10_origin(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, false, false, true).await
    }

    async fn start_inner(
        ip: IpAddr,
        origin_port: u16,
        tls: bool,
        keep_alive: bool,
        http10_origin: bool,
    ) -> Self {
        let root = tempfile::tempdir().expect("temporary harness directory");
        let policy = FakePolicy::start(root.path());
        let ca = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate CA");
        let ca_cert = root.path().join("ca.pem");
        let ca_key = root.path().join("ca-key.pem");
        std::fs::write(&ca_cert, ca.cert.pem()).expect("write CA certificate");
        std::fs::write(&ca_key, ca.signing_key.serialize_pem()).expect("write CA key");
        let origin_cert = ca_cert.clone();
        let origin_key = ca_key.clone();
        let origin_address = SocketAddr::new(ip, origin_port);

        let (origin, tls_origin) = if tls {
            let (origin, tls_origin) =
                start_tls_origin(ip, origin_address, &origin_cert, &origin_key).await;
            (origin, Some(tls_origin))
        } else {
            (
                if keep_alive {
                    TcpOrigin::start_keep_alive(ip, origin_port, b"origin-response").await
                } else {
                    TcpOrigin::start(ip, origin_port, b"origin-response").await
                },
                None,
            )
        };

        let udp_origin = UdpOrigin::start(ip).await;
        let ready = root.path().join("ready");
        let state = root.path().join("ech");
        let proxy_port = free_port(ip);
        let proxy_address = SocketAddr::new(ip, proxy_port);
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
            &origin.address.to_string(),
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

        let proxy = proxy_command
            .env("AGENT_SANDBOX_PROXY_SESSION_READY", &ready)
            .env("INVOCATION_ID", "0123456789abcdef0123456789abcdef")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start proxy");

        wait_for_path(&ready).await;

        Self {
            proxy_address,
            origin,
            udp_origin,
            policy,
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
