//! WebTransport client for end-to-end checks.
//!
//! Opens an HTTP/3 connection, sends one ordinary request so the WebTransport
//! CONNECT stream gets a non-zero stream ID, then establishes a WebTransport
//! session and exercises a bidirectional stream, a unidirectional stream echo
//! and an HTTP Datagram echo against the `h3-origin` test server. Exits 0
//! only when every step matches.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes};
use clap::Parser;
use h3::quic::SendStream as _;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use rustls::pki_types::pem::PemObject;

type Failure = Box<dyn std::error::Error + Send + Sync>;

/// A server-initiated WebTransport unidirectional stream and its session.
struct IncomingUni {
    session_id: h3::webtransport::SessionId,
    stream: h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>,
}

const STEP_TIMEOUT: Duration = Duration::from_secs(10);
const BIDI_PAYLOAD: &[u8] = b"bidi-ping";
const UNI_PAYLOAD: &[u8] = b"uni-ping";
const DATAGRAM_PAYLOAD: &[u8] = b"datagram-ping";

#[derive(Debug, Parser)]
#[command(name = "wt-client")]
struct Args {
    /// WebTransport endpoint, for example `https://example.test/webtransport`.
    url: http::Uri,

    /// PEM file with the CA certificates to trust.
    #[arg(long)]
    ca_file: PathBuf,

    /// Path of an ordinary GET request sent before the session, so the
    /// session's CONNECT stream ID is not 0.
    #[arg(long)]
    warmup_path: Option<String>,

    /// UDP endpoint to contact instead of resolving the URL host.
    #[arg(long)]
    server: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wt-client: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Run one step under a timeout and report it on success.
async fn step<T>(
    name: &str,
    future: impl Future<Output = Result<T, Failure>>,
) -> Result<T, Failure> {
    let value = tokio::time::timeout(STEP_TIMEOUT, future)
        .await
        .map_err(|_| format!("{name}: timed out"))?
        .map_err(|error| format!("{name}: {error}"))?;

    println!("ok {name}");
    Ok(value)
}

fn expect(name: &str, actual: &[u8], expected: &[u8]) -> Result<(), Failure> {
    if actual == expected {
        return Ok(());
    }

    Err(format!(
        "{name}: expected {:?}, got {:?}",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(actual)
    )
    .into())
}

fn client_endpoint(ca_file: &PathBuf, remote: &SocketAddr) -> Result<quinn::Endpoint, Failure> {
    let mut roots = rustls::RootCertStore::empty();

    for certificate in rustls::pki_types::CertificateDer::pem_file_iter(ca_file)? {
        roots.add(certificate?)?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    tls.alpn_protocols = vec![b"h3".to_vec()];

    let local_ip = if remote.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };

    let mut endpoint = quinn::Endpoint::client(SocketAddr::new(local_ip, 0))?;

    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    )));

    Ok(endpoint)
}

/// Accept server-initiated WebTransport unidirectional streams until the
/// HTTP/3 connection closes.
async fn drive_connection(
    mut connection: h3::client::Connection<h3_quinn::Connection, Bytes>,
    incoming: tokio::sync::mpsc::UnboundedSender<IncomingUni>,
) {
    std::future::poll_fn(|context: &mut Context<'_>| {
        loop {
            if let Some((session_id, stream)) =
                connection.inner.accepted_streams_mut().wt_uni_streams.pop()
            {
                let stream = h3_webtransport::stream::RecvStream::new(stream);

                if incoming.send(IncomingUni { session_id, stream }).is_err() {
                    return Poll::Ready(());
                }

                continue;
            }

            if connection.poll_close(context).is_ready() {
                return Poll::Ready(());
            }

            if connection
                .inner
                .accepted_streams_mut()
                .wt_uni_streams
                .is_empty()
            {
                return Poll::Pending;
            }
        }
    })
    .await;
}

async fn read_to_end<R>(stream: &mut R) -> Result<Vec<u8>, Failure>
where
    R: h3::quic::RecvStream<Buf = Bytes>,
{
    let mut received = Vec::new();

    while let Some(mut chunk) = std::future::poll_fn(|context| stream.poll_data(context)).await? {
        received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }

    Ok(received)
}

async fn write_and_finish<S>(stream: &mut S, payload: &[u8]) -> Result<(), Failure>
where
    S: h3::quic::SendStream<Bytes> + h3::quic::SendStreamUnframed<Bytes>,
{
    let mut payload = Bytes::copy_from_slice(payload);

    while payload.has_remaining() {
        std::future::poll_fn(|context| stream.poll_send(context, &mut payload)).await?;
    }

    std::future::poll_fn(|context| stream.poll_finish(context)).await?;
    Ok(())
}

async fn warmup_request(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    authority: &str,
    path: &str,
) -> Result<(), Failure> {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://{authority}{path}"))
        .body(())?;

    let mut stream = send_request.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;

    if !response.status().is_success() {
        return Err(format!("warm-up request returned {}", response.status()).into());
    }

    while stream.recv_data().await?.is_some() {}
    Ok(())
}

async fn run(args: Args) -> Result<(), Failure> {
    let authority = args
        .url
        .authority()
        .ok_or("URL has no authority")?
        .as_str()
        .to_owned();

    let host = args.url.host().ok_or("URL has no host")?.to_owned();
    let port = args.url.port_u16().unwrap_or(443);

    let server = match args.server {
        Some(server) => server,
        None => tokio::net::lookup_host((host.as_str(), port))
            .await?
            .next()
            .ok_or_else(|| format!("{host} did not resolve"))?,
    };

    let endpoint = client_endpoint(&args.ca_file, &server)?;

    let quic = step("QUIC handshake", async {
        Ok(endpoint.connect(server, &host)?.await?)
    })
    .await?;

    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true);
    builder.enable_datagram(true);
    builder.enable_webtransport(true);

    let (connection, mut send_request) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(quic.clone()))
        .await?;

    if let Some(path) = &args.warmup_path {
        step(
            "ordinary request",
            warmup_request(&mut send_request, &authority, path),
        )
        .await?;
    }

    let mut connect_request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!(
            "https://{authority}{}",
            args.url.path_and_query().map_or("/", |path| path.as_str())
        ))
        .body(())?;

    connect_request
        .extensions_mut()
        .insert(h3::ext::Protocol::WEB_TRANSPORT);

    let mut connect_stream = send_request.send_request(connect_request).await?;
    let stream_id = connect_stream.id();

    if args.warmup_path.is_some() && stream_id.into_inner() == 0 {
        return Err(
            "CONNECT stream ID is 0, so Quarter Stream ID encoding is not exercised".into(),
        );
    }

    let session_id = h3::webtransport::SessionId::from(stream_id);
    let mut datagram_sender = connection.get_datagram_sender(stream_id);
    let mut datagram_reader = connection.get_datagram_reader();
    let (incoming_tx, mut incoming_rx) = tokio::sync::mpsc::unbounded_channel();
    let driver = tokio::spawn(drive_connection(connection, incoming_tx));

    step("session establishment", async {
        let response = connect_stream.recv_response().await?;

        if !response.status().is_success() {
            return Err(format!("CONNECT returned {}", response.status()).into());
        }

        if response.headers().get("x-origin-webtransport")
            != Some(&http::HeaderValue::from_static("preserved"))
        {
            return Err("x-origin-webtransport header was not preserved".into());
        }

        Ok(())
    })
    .await?;

    step("datagram echo", async {
        datagram_sender.send_datagram(Bytes::from_static(DATAGRAM_PAYLOAD))?;
        let datagram = datagram_reader.read_datagram().await?;

        if datagram.stream_id() != stream_id {
            return Err("datagram arrived for another session".into());
        }

        expect(
            "datagram payload",
            &datagram.into_payload(),
            DATAGRAM_PAYLOAD,
        )
    })
    .await?;

    let h3_quic = h3_quinn::Connection::new(quic.clone());
    let mut opener = <h3_quinn::Connection as h3::quic::Connection<Bytes>>::opener(&h3_quic);

    step("bidirectional stream", async {
        let mut stream = std::future::poll_fn(|context| {
            <h3_quinn::OpenStreams as h3::quic::OpenStreams<Bytes>>::poll_open_bidi(
                &mut opener,
                context,
            )
        })
        .await?;

        stream.send_data(h3::stream::BidiStreamHeader::WebTransportBidi(session_id))?;
        std::future::poll_fn(|context| stream.poll_ready(context)).await?;
        write_and_finish(&mut stream, BIDI_PAYLOAD).await?;
        let received = read_to_end(&mut stream).await?;

        expect(
            "bidirectional echo",
            &received,
            b"webtransport-response\nbidi-ping",
        )
    })
    .await?;

    step("unidirectional stream", async {
        let mut stream = std::future::poll_fn(|context| {
            <h3_quinn::OpenStreams as h3::quic::OpenStreams<Bytes>>::poll_open_send(
                &mut opener,
                context,
            )
        })
        .await?;

        stream.send_data(h3::stream::UniStreamHeader::WebTransportUni(session_id))?;
        std::future::poll_fn(|context| stream.poll_ready(context)).await?;
        write_and_finish(&mut stream, UNI_PAYLOAD).await?;

        let IncomingUni {
            session_id: echo_session,
            stream: mut echo,
        } = incoming_rx
            .recv()
            .await
            .ok_or("connection closed before the unidirectional echo")?;

        if echo_session != session_id {
            return Err("unidirectional echo arrived for another session".into());
        }

        expect(
            "unidirectional echo",
            &read_to_end(&mut echo).await?,
            b"uni-echo:uni-ping",
        )
    })
    .await?;

    quic.close(0u32.into(), b"done");
    driver.abort();
    let _ = tokio::time::timeout(STEP_TIMEOUT, endpoint.wait_idle()).await;
    Ok(())
}
