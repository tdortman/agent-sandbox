//! Controllable HTTP/3 origin for the transparent proxy harness.
//!
//! The origin speaks HTTP/3 over QUIC and records one line per request,
//! connection event, and received UDP datagram to a log file. Harness tests
//! can observe upstream attempts without instrumenting the proxy.
//!
//! The `/stream` path sends one chunk, then waits until the gate file
//! exists before sending the rest. This gives deterministic streaming
//! tests a way to observe partial responses.

use agent_sandbox_proxy::http3::CapsuleDecoder;
use bytes::{Buf, Bytes};
use clap::Parser;
use h3::quic::{SendStream as _, SendStreamUnframed as _};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use rustls::pki_types::pem::PemObject;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::unix::AsyncFd;

#[derive(Debug)]
struct LoggedUdpSocket {
    inner: Arc<AsyncFd<std::net::UdpSocket>>,
    bound: SocketAddr,
    log: Arc<std::sync::Mutex<std::fs::File>>,
}

impl LoggedUdpSocket {
    fn new(
        socket: std::net::UdpSocket,
        bound: SocketAddr,
        log: Arc<std::sync::Mutex<std::fs::File>>,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::new(AsyncFd::new(socket)?),
            bound,
            log,
        })
    }

    fn recv_one(&self, buffer: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        match self.inner.get_ref().recv_from(buffer) {
            Ok((length, source)) => {
                log_line(&self.log, &format!("datagram {length}"));
                Ok(Some((length, source)))
            }

            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug)]
struct LoggedUdpPoller {
    inner: Arc<AsyncFd<std::net::UdpSocket>>,
}

impl quinn::UdpPoller for LoggedUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner
            .poll_write_ready(cx)
            .map(|result| result.map(|_| ()))
    }
}

impl quinn::AsyncUdpSocket for LoggedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(LoggedUdpPoller {
            inner: Arc::clone(&self.inner),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner
            .get_ref()
            .send_to(transmit.contents, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        metas: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buffer) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };

        let Some(meta) = metas.first_mut() else {
            return Poll::Ready(Err(io::Error::other(
                "quinn supplied no receive metadata slot",
            )));
        };

        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };

            match self.recv_one(buffer) {
                Ok(Some((length, source))) => {
                    meta.addr = source;
                    meta.len = length;
                    meta.stride = length;
                    meta.ecn = None;
                    meta.dst_ip = None;
                    return Poll::Ready(Ok(1));
                }

                Ok(None) => guard.clear_ready(),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bound)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug, Parser)]
#[command(name = "h3-origin")]
struct Args {
    #[arg(long)]
    port: u16,

    #[arg(long)]
    certificate: PathBuf,

    #[arg(long)]
    private_key: PathBuf,

    #[arg(long, default_value = "127.0.0.1")]
    address: IpAddr,

    #[arg(long)]
    log: PathBuf,

    /// File holding the advertised `Alt-Svc` port; read on every response
    /// so the harness can advertise a port discovered after startup.
    #[arg(long)]
    alt_svc_file: Option<PathBuf>,

    #[arg(long)]
    gate: Option<PathBuf>,

    /// Omit extended CONNECT, WebTransport, and HTTP Datagram settings.
    #[arg(long)]
    reject_sessions: bool,

    /// Refuse extended CONNECT requests with a non-success response.
    #[arg(long)]
    refuse_sessions: bool,

    /// Close the first extended CONNECT before sending its response.
    #[arg(long)]
    drop_first_session: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.log)?;

    let log = Arc::new(std::sync::Mutex::new(log));

    let certificates = rustls::pki_types::CertificateDer::pem_file_iter(&args.certificate)?
        .collect::<Result<Vec<_>, _>>()?;

    let private_key = rustls::pki_types::PrivateKeyDer::from_pem_file(&args.private_key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;

    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_config));
    let bind_address = SocketAddr::new(args.address, args.port);
    let socket = std::net::UdpSocket::bind(bind_address)?;
    socket.set_nonblocking(true)?;
    let bound = socket.local_addr()?;
    let socket = Arc::new(LoggedUdpSocket::new(socket, bound, log.clone())?);

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    let address = endpoint.local_addr()?;
    log_line(&log, &format!("listening {address}"));
    let drop_first_session = Arc::new(AtomicBool::new(args.drop_first_session));

    while let Some(incoming) = endpoint.accept().await {
        let log = log.clone();
        let gate = args.gate.clone();
        let alt_svc_file = args.alt_svc_file.clone();
        let reject_sessions = args.reject_sessions;
        let refuse_sessions = args.refuse_sessions;
        let drop_first_session = drop_first_session.clone();

        log_line(
            &log,
            &format!("incoming from {}", incoming.remote_address()),
        );

        tokio::spawn(async move {
            log_line(&log, "conn-opened");

            if let Err(error) = serve_connection(
                incoming,
                log.clone(),
                gate,
                alt_svc_file.as_deref(),
                reject_sessions,
                refuse_sessions,
                drop_first_session,
            )
            .await
            {
                log_line(&log, &format!("conn-error {error}"));
            }

            log_line(&log, "conn-closed");
        });
    }

    Ok(())
}

async fn serve_connect_udp(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3: &h3::server::Connection<h3_quinn::Connection, Bytes>,
    drop_session: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream_id = stream.id();
    let mut datagram_reader = h3.get_datagram_reader();
    let mut datagram_sender = h3.get_datagram_sender(stream_id);

    stream
        .send_response(http::Response::builder().status(200).body(())?)
        .await?;

    if drop_session {
        return Ok(());
    }

    tokio::select! {
        datagram = datagram_reader.read_datagram() => {
            let datagram = datagram?;
            if datagram.stream_id() != stream_id {
                return Err("invalid CONNECT-UDP datagram context".into());
            }
            let payload = datagram.into_payload();
            if payload.first() != Some(&0) {
                return Err("invalid CONNECT-UDP inner context".into());
            }
            datagram_sender.send_datagram(payload)?;
            while stream.recv_data().await?.is_some() {}
            stream.finish().await?;
        }
        first = stream.recv_data() => {
            let Some(first) = first? else {
                return Err("CONNECT-UDP Capsule Protocol body is empty".into());
            };
            let mut capsules = Vec::new();
            let mut first = first;
            while first.has_remaining() {
                let chunk = first.chunk();
                capsules.extend_from_slice(chunk);
                first.advance(chunk.len());
            }
            while let Some(mut chunk) = stream.recv_data().await? {
                while chunk.has_remaining() {
                    let chunk_bytes = chunk.chunk();
                    capsules.extend_from_slice(chunk_bytes);
                    chunk.advance(chunk_bytes.len());
                }
            }
            validate_capsules(&capsules)?;
            stream.send_data(capsules.into()).await?;
            stream.finish().await?;
        }
    }

    Ok(())
}

fn validate_capsules(encoded: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut decoder = CapsuleDecoder::default();
    decoder.push(encoded)?;
    decoder.finish()?;
    Ok(())
}

async fn serve_websocket(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    drop_session: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream
        .send_response(http::Response::builder().status(200).body(())?)
        .await?;

    if drop_session {
        return Ok(());
    }

    stream
        .send_data(Bytes::from_static(b"websocket-response\n"))
        .await?;

    while stream.recv_data().await?.is_some() {}
    stream.finish().await?;
    Ok(())
}

async fn serve_webtransport(
    request: http::Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3: h3::server::Connection<h3_quinn::Connection, Bytes>,
    drop_session: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = http::Response::builder()
        .status(200)
        .header("x-origin-webtransport", "preserved")
        .body(())?;

    let session = h3_webtransport::server::WebTransportSession::accept_with_response(
        request, stream, h3, response,
    )
    .await?;

    if drop_session {
        return Ok(());
    }

    let mut datagram_reader = session.datagram_reader();
    let mut datagram_sender = session.datagram_sender();

    let datagram_task = tokio::spawn(async move {
        while let Ok(datagram) = datagram_reader.read_datagram().await {
            if datagram_sender
                .send_datagram(datagram.into_payload())
                .is_err()
            {
                break;
            }
        }
    });

    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        while let Some(accepted) = session.accept_bi().await? {
            match accepted {
                h3_webtransport::server::AcceptedBi::BidiStream(session_id, mut stream) => {
                    if session_id != session.session_id() {
                        return Err("invalid WebTransport session identifier".into());
                    }

                    let mut response = Bytes::from_static(b"webtransport-response\n");
                    while response.has_remaining() {
                        std::future::poll_fn(|context| stream.poll_send(context, &mut response))
                            .await?;
                    }

                    std::future::poll_fn(|context| stream.poll_finish(context)).await?;
                }
                h3_webtransport::server::AcceptedBi::Request(_, mut stream) => {
                    stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                    stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                }
            }
        }

        Ok(())
    }
    .await;

    datagram_task.abort();
    let _ = datagram_task.await;
    result
}

async fn serve_connection(
    incoming: quinn::Incoming,
    log: Arc<std::sync::Mutex<std::fs::File>>,
    gate: Option<PathBuf>,
    alt_svc_file: Option<&Path>,
    reject_sessions: bool,
    refuse_sessions: bool,
    drop_first_session: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connecting = incoming.accept()?;
    let connection = connecting.await?;
    let mut builder = h3::server::builder();

    if !reject_sessions {
        builder.enable_extended_connect(true);
        builder.enable_datagram(true);
        builder.enable_webtransport(true);
    }

    let mut h3 = builder.build(h3_quinn::Connection::new(connection)).await?;

    while let Some(resolver) = h3.accept().await? {
        let (request, mut stream) = resolver.resolve_request().await?;
        let path = request.uri().path().to_owned();
        let method = request.method().as_str().to_owned();
        log_line(&log, &format!("request {method} {path}"));
        let session_protocol = request.extensions().get::<h3::ext::Protocol>().copied();

        if let Some(protocol) = session_protocol {
            if refuse_sessions {
                stream
                    .send_response(http::Response::builder().status(403).body(())?)
                    .await?;

                stream.finish().await?;
                continue;
            }

            let drop_session = drop_first_session.swap(false, Ordering::SeqCst);

            if drop_session {
                log_line(&log, "session-dropped");
                return Ok(());
            }

            if protocol == h3::ext::Protocol::CONNECT_UDP {
                serve_connect_udp(stream, &h3, false).await?;
                continue;
            }

            if protocol == h3::ext::Protocol::WEBSOCKET {
                serve_websocket(stream, false).await?;
                continue;
            }

            if protocol == h3::ext::Protocol::WEB_TRANSPORT {
                return serve_webtransport(request, stream, h3, false).await;
            }
        }

        serve_request(&path, &mut stream, gate.as_deref(), alt_svc_file).await?;
    }

    Ok(())
}

const MAX_INFORMATIONAL_RESPONSES: usize = 16;
type OriginRequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn send_informational_response(
    stream: &mut OriginRequestStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream
        .send_response(
            http::Response::builder()
                .status(103)
                .header("link", "</style.css>; rel=preload")
                .body(())?,
        )
        .await?;

    Ok(())
}

async fn send_excessive_informational_responses(
    stream: &mut OriginRequestStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for _ in 0..=MAX_INFORMATIONAL_RESPONSES {
        stream
            .send_response(http::Response::builder().status(103).body(())?)
            .await?;
    }

    Ok(())
}

async fn serve_request(
    path: &str,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    gate: Option<&std::path::Path>,
    alt_svc_file: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if path == "/informational" {
        send_informational_response(stream).await?;
    }

    if path == "/informational-overflow" {
        send_excessive_informational_responses(stream).await?;
    }

    let alt_svc = match path {
        "/alt-svc-clear" => Some("clear".to_owned()),
        "/alt-svc-filtered" => Some("h3=\":59999\"".to_owned()),
        _ => alt_svc_file.and_then(read_alt_svc),
    };

    if matches!(path, "/expect" | "/request-trailers") {
        let early_body = if path == "/expect" {
            matches!(
                tokio::time::timeout(Duration::from_millis(250), stream.recv_data()).await,
                Ok(Ok(Some(_)))
            )
        } else {
            false
        };

        if path == "/expect" {
            stream
                .send_response(http::Response::builder().status(100).body(())?)
                .await?;
        }

        let (request_body, request_trailers) = read_request_body(stream).await?;

        let valid = !early_body
            && request_body == b"request-body"
            && (path == "/expect"
                || request_trailers
                    .get("x-request-trailer")
                    .is_some_and(|value| value == "present"));

        let status = if valid { 200 } else { 400 };

        let body = if valid {
            b"request-body-ok\n".as_slice()
        } else {
            b"request-body-invalid\n".as_slice()
        };

        let response = http::Response::builder()
            .status(status)
            .header("content-length", body.len().to_string())
            .body(())?;

        stream.send_response(response).await?;
        stream.send_data(Bytes::from_static(body)).await?;
        stream.finish().await?;
        return Ok(());
    }

    if path == "/stream" {
        let mut builder = http::Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream");

        if let Some(alt_svc) = alt_svc {
            builder = builder.header("alt-svc", alt_svc);
        }

        let response = builder.body(()).expect("response head");
        stream.send_response(response).await?;
        stream.send_data(Bytes::from_static(b"first-chunk")).await?;

        if let Some(gate) = gate {
            wait_for_gate(gate).await;
        }

        stream
            .send_data(Bytes::from_static(b"second-chunk"))
            .await?;

        stream.finish().await?;
        return Ok(());
    }

    let body = match path {
        "/allowed" => b"allowed-get\n".as_slice(),
        "/denied" => b"denied-get\n".as_slice(),
        _ => b"origin-response\n".as_slice(),
    };

    let mut builder = http::Response::builder()
        .status(200)
        .header("content-length", body.len().to_string());

    if let Some(alt_svc) = alt_svc {
        builder = builder.header("alt-svc", alt_svc);
    }

    let response = builder.body(()).expect("response head");

    if path == "/trailers" {
        stream.send_response(response).await?;
        stream.send_data(Bytes::from_static(body)).await?;
        let mut trailers = http::HeaderMap::new();

        trailers.insert(
            "x-origin-trailer",
            http::HeaderValue::from_static("present"),
        );

        stream.send_trailers(trailers).await?;
        stream.finish().await?;
        return Ok(());
    }

    stream.send_response(response).await?;
    stream.send_data(Bytes::from_static(body)).await?;
    stream.finish().await?;
    Ok(())
}

/// Read the advertised alternative endpoint from `path`, written by the
/// harness once the proxy reports the port it actually bound.
///
/// The file holds either a bare port (`4444`, advertising the same host)
/// or a validated `host:port` (`169.254.100.1:4444`, advertising an
/// absolute alternative that needs no hostname resolution).
fn read_alt_svc(path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let contents = contents.trim();

    if let Ok(address) = contents.parse::<SocketAddr>() {
        return Some(format!("h3=\"{address}\"; persist=1"));
    }

    let port: u16 = contents.parse().ok()?;
    Some(format!("h3=\":{port}\"; persist=1"))
}

async fn read_request_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(Vec<u8>, http::HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
    let mut body = Vec::new();

    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }

    let trailers = stream.recv_trailers().await?.unwrap_or_default();
    Ok((body, trailers))
}

async fn wait_for_gate(gate: &std::path::Path) {
    loop {
        if gate.exists() {
            return;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn log_line(log: &Arc<std::sync::Mutex<std::fs::File>>, line: &str) {
    use std::io::Write;

    if let Ok(mut log) = log.lock() {
        let _ = writeln!(log, "{line}");
        let _ = log.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::read_alt_svc;
    use std::io::Write as _;

    fn alt_svc_file(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes()).expect("write contents");
        file
    }

    #[test]
    fn bare_port_advertises_the_same_host() {
        let file = alt_svc_file("4444");
        assert_eq!(
            read_alt_svc(file.path()),
            Some("h3=\":4444\"; persist=1".to_owned())
        );
    }

    #[test]
    fn absolute_v4_advertises_host_and_port() {
        let file = alt_svc_file("169.254.100.1:4444");
        assert_eq!(
            read_alt_svc(file.path()),
            Some("h3=\"169.254.100.1:4444\"; persist=1".to_owned())
        );
    }

    #[test]
    fn absolute_v6_advertises_host_and_port() {
        let file = alt_svc_file("[fd00:dead:beef::1]:4444");
        assert_eq!(
            read_alt_svc(file.path()),
            Some("h3=\"[fd00:dead:beef::1]:4444\"; persist=1".to_owned())
        );
    }

    #[test]
    fn malformed_contents_are_rejected() {
        let file = alt_svc_file("bad;persist=1:4444");
        assert_eq!(read_alt_svc(file.path()), None);
    }

    #[test]
    fn missing_file_yields_no_advertisement() {
        assert_eq!(read_alt_svc(std::path::Path::new("/nonexistent")), None);
    }
}
