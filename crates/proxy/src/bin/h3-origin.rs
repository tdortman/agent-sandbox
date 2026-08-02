//! Controllable HTTP/3 origin for the transparent proxy harness.
//!
//! The origin speaks HTTP/3 over QUIC and records one line per request and
//! connection event to a log file, so harness tests can observe upstream
//! attempts, request heads, and upstream association release without
//! instrumenting the proxy.
//!
//! The `/stream` path sends one chunk, then waits until the gate file
//! exists before sending the rest. This gives deterministic streaming
//! tests a way to observe partial responses.

use bytes::{Buf, Bytes};
use clap::Parser;
use h3::quic::{SendStream as _, SendStreamUnframed as _};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use rustls::pki_types::pem::PemObject;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

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

    /// `Alt-Svc` header value added to every non-stream response.
    #[arg(long)]
    alt_svc: Option<String>,

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

    let address = SocketAddr::new(args.address, args.port);
    let endpoint = quinn::Endpoint::server(server_config, address)?;

    log_line(&log, &format!("listening {address}"));

    let drop_first_session = Arc::new(AtomicBool::new(args.drop_first_session));

    while let Some(incoming) = endpoint.accept().await {
        let log = log.clone();
        let gate = args.gate.clone();
        let alt_svc = args.alt_svc.clone();
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
                alt_svc.as_deref(),
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

fn validate_capsules(mut encoded: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while !encoded.is_empty() {
        let Some((_, kind_len)) = decode_origin_varint(encoded) else {
            return Err("truncated Capsule Protocol type".into());
        };
        let Some((length, length_len)) = decode_origin_varint(&encoded[kind_len..]) else {
            return Err("truncated Capsule Protocol length".into());
        };
        let length = usize::try_from(length)
            .map_err(|_| std::io::Error::other("Capsule Protocol length is too large"))?;
        let start = kind_len + length_len;
        let end = start
            .checked_add(length)
            .ok_or_else(|| std::io::Error::other("Capsule Protocol length overflows"))?;
        if end > encoded.len() {
            return Err("truncated Capsule Protocol payload".into());
        }
        encoded = &encoded[end..];
    }
    Ok(())
}

fn decode_origin_varint(encoded: &[u8]) -> Option<(u64, usize)> {
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
    let session = h3_webtransport::server::WebTransportSession::accept(request, stream, h3).await?;

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
    alt_svc: Option<&str>,
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

        let alt_svc = match path.as_str() {
            "/alt-svc-clear" => Some("clear"),
            "/alt-svc-filtered" => Some("h3=\":59999\""),
            _ => alt_svc,
        };

        let body = if path == "/stream" {
            let mut builder = http::Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream");

            if let Some(alt_svc) = alt_svc {
                builder = builder.header("alt-svc", alt_svc);
            }

            let response = builder.body(()).expect("response head");

            stream.send_response(response).await?;
            stream.send_data(Bytes::from_static(b"first-chunk")).await?;

            if let Some(gate) = &gate {
                wait_for_gate(gate).await;
            }

            stream
                .send_data(Bytes::from_static(b"second-chunk"))
                .await?;
            stream.finish().await?;
            continue;
        } else {
            match path.as_str() {
                "/allowed" => b"allowed-get\n".as_slice(),
                "/denied" => b"denied-get\n".as_slice(),
                _ => b"origin-response\n".as_slice(),
            }
        };

        let mut builder = http::Response::builder()
            .status(200)
            .header("content-length", body.len().to_string());

        if let Some(alt_svc) = alt_svc {
            builder = builder.header("alt-svc", alt_svc);
        }

        let response = builder.body(()).expect("response head");

        stream.send_response(response).await?;
        stream.send_data(Bytes::from_static(body)).await?;
        stream.finish().await?;
    }

    Ok(())
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
