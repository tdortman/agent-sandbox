use super::*;

pub(super) async fn read_http_response(stream: &mut TcpStream) -> Vec<u8> {
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
pub(super) enum TlsAlpn {
    Http11,
    None,
}

pub(super) const fn harness_tls_alpn(advertise_http11_alpn: bool) -> TlsAlpn {
    if advertise_http11_alpn {
        TlsAlpn::Http11
    } else {
        TlsAlpn::None
    }
}

pub(super) async fn start_tls_origin(
    address: SocketAddr,
    certificate: &Path,
    key: &Path,
    tls_alpn: TlsAlpn,
) -> (TcpOrigin, TlsOrigin) {
    let listener = TcpListener::bind(address).await.expect("bind TLS origin");
    let address = listener.local_addr().expect("TLS origin address");

    // The inner TLS terminator listens on a Unix socket instead of a TCP
    // port, so no free port is handed to a child process and raced. The
    // socket lives in its own short /tmp directory: openssl 3.6 fails to
    // start when the path exceeds 31 characters (its post-bind getnameinfo
    // call overflows on longer paths).
    let socket_dir = tempfile::Builder::new()
        .prefix("asot")
        .tempdir_in("/tmp")
        .expect("create TLS origin socket directory");
    let inner_socket = socket_dir.path().join("s.sock");
    let mut command = Command::new("openssl");

    command.args([
        "s_server",
        "-quiet",
        "-www",
        "-unix",
        inner_socket.to_str().expect("TLS origin socket path"),
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

    wait_for_unix_socket(&inner_socket).await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let task_attempts = attempts.clone();
    let forward_socket = inner_socket.clone();

    let task = tokio::spawn(async move {
        loop {
            let Ok((mut downstream, _)) = listener.accept().await else {
                break;
            };
            task_attempts.fetch_add(1, Ordering::SeqCst);
            let Ok(mut upstream) = UnixStream::connect(&forward_socket).await else {
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
        TlsOrigin {
            child,
            task,
            _socket_dir: socket_dir,
        },
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

pub(super) struct TlsOrigin {
    child: Child,
    task: JoinHandle<()>,
    _socket_dir: TempDir,
}

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.task.abort();
    }
}

async fn wait_for_unix_socket(path: &Path) {
    timeout(Duration::from_secs(5), async {
        loop {
            if UnixStream::connect(path).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TLS origin readiness");
}
