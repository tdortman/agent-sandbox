//! HTTP/3 client that holds one connection idle across a sandbox freeze.
//!
//! Opens a single QUIC connection with a short idle timeout and no
//! keep-alive, completes request 1, then waits until the trigger file exists
//! and sends request 2 on the same connection. Prints `request 1 ok`, then
//! either `request 2 reused connection` or `request 2 failed: <reason>`, and
//! exits 0 only in the reuse case. The end-to-end check freezes the sandbox
//! between the two requests for longer than the idle timeout, so request 2
//! succeeds only when the client's monotonic clock did not advance while it
//! was frozen.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use clap::Parser;
use rustls::pki_types::pem::PemObject;

type Failure = Box<dyn std::error::Error + Send + Sync>;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const TRIGGER_TIMEOUT: Duration = Duration::from_secs(120);
const TRIGGER_POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Parser)]
#[command(name = "h3-idle-client")]
struct Args {
    /// URL requested twice, for example `https://example.test/allowed`.
    url: http::Uri,

    /// PEM file with the CA certificates to trust.
    #[arg(long, env = "SSL_CERT_FILE")]
    ca_file: PathBuf,

    /// File whose existence releases request 2.
    #[arg(long)]
    trigger_file: PathBuf,

    /// QUIC idle timeout, in seconds.
    #[arg(long, default_value_t = 10)]
    idle_timeout_secs: u32,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            println!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn client_endpoint(
    ca_file: &Path,
    remote: &SocketAddr,
    idle_timeout_secs: u32,
) -> Result<quinn::Endpoint, Failure> {
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

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(u64::from(idle_timeout_secs)).try_into()?,
    ));
    transport.keep_alive_interval(None);

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    client_config.transport_config(Arc::new(transport));

    let local_ip = if remote.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };

    let mut endpoint = quinn::Endpoint::client(SocketAddr::new(local_ip, 0))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Send one GET and drain its response body.
async fn get(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    url: &http::Uri,
) -> Result<(), Failure> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(url)
            .body(())?;

        let mut stream = send_request.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;

        if !response.status().is_success() {
            return Err(format!("status {}", response.status()).into());
        }

        while stream.recv_data().await?.is_some() {}

        Ok(())
    })
    .await
    .map_err(|_| "timed out")?
}

async fn run(args: Args) -> Result<(), Failure> {
    let host = args.url.host().ok_or("URL has no host")?.to_owned();
    let port = args.url.port_u16().unwrap_or(443);

    let server = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .next()
        .ok_or_else(|| format!("{host} did not resolve"))?;

    let endpoint = client_endpoint(&args.ca_file, &server, args.idle_timeout_secs)?;
    let quic = endpoint.connect(server, &host)?.await?;
    let connection_id = quic.stable_id();

    let (mut driver, mut send_request) = h3::client::builder()
        .build::<_, _, Bytes>(h3_quinn::Connection::new(quic.clone()))
        .await?;

    tokio::spawn(async move {
        driver.wait_idle().await;
    });

    get(&mut send_request, &args.url)
        .await
        .map_err(|error| format!("request 1 failed: {error}"))?;

    println!("request 1 ok");

    tokio::time::timeout(TRIGGER_TIMEOUT, async {
        while !args.trigger_file.exists() {
            tokio::time::sleep(TRIGGER_POLL).await;
        }
    })
    .await
    .map_err(|_| "trigger file never appeared")?;

    get(&mut send_request, &args.url)
        .await
        .map_err(|error| format!("request 2 failed: {error}"))?;

    if quic.close_reason().is_some() || quic.stable_id() != connection_id {
        return Err("request 2 failed: connection was replaced".into());
    }

    println!("request 2 reused connection");
    Ok(())
}
