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

use clap::Parser;
use rustls::pki_types::pem::PemObject;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
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

    while let Some(incoming) = endpoint.accept().await {
        let log = log.clone();
        let gate = args.gate.clone();
        let alt_svc = args.alt_svc.clone();

        log_line(
            &log,
            &format!("incoming from {}", incoming.remote_address()),
        );

        tokio::spawn(async move {
            log_line(&log, "conn-opened");

            if let Err(error) =
                serve_connection(incoming, log.clone(), gate, alt_svc.as_deref()).await
            {
                log_line(&log, &format!("conn-error {error}"));
            }

            log_line(&log, "conn-closed");
        });
    }

    Ok(())
}

async fn serve_connection(
    incoming: quinn::Incoming,
    log: Arc<std::sync::Mutex<std::fs::File>>,
    gate: Option<PathBuf>,
    alt_svc: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connecting = incoming.accept()?;
    let connection = connecting.await?;
    let h3 = h3_quinn::Connection::new(connection);
    let mut h3 = h3::server::builder().build(h3).await?;

    while let Some(resolver) = h3.accept().await? {
        let (request, mut stream) = resolver.resolve_request().await?;
        let path = request.uri().path().to_owned();
        let method = request.method().as_str().to_owned();

        log_line(&log, &format!("request {method} {path}"));

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
            stream
                .send_data(bytes::Bytes::from_static(b"first-chunk"))
                .await?;

            if let Some(gate) = &gate {
                wait_for_gate(gate).await;
            }

            stream
                .send_data(bytes::Bytes::from_static(b"second-chunk"))
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
        stream.send_data(bytes::Bytes::from_static(body)).await?;
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
