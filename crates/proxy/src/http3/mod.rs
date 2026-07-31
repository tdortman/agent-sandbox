//! Project-owned HTTP/3 backend boundary.
//!
//! This module terminates downstream QUIC/HTTP/3 associations and relays
//! approved requests through separately controlled upstream HTTP/3
//! connections. Quinn and h3 types stay inside this module and its
//! submodules; the rest of the proxy sees only the configuration and the
//! running backend.
//!
//! The backend is disabled by default. The proxy operator enables it with an
//! explicit flag, and the sandbox firewall must route the intercepted UDP
//! port to the proxy before any HTTP/3 traffic can arrive.

mod association;
mod socket;
pub mod upstream;

use crate::{cert::CertificateIssuer, policy::PolicySession};
use socket::TransparentUdpSocket;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};

/// Shared state for every downstream QUIC association.
pub struct Http3State {
    pub policy: Arc<PolicySession>,
    pub issuer: CertificateIssuer,
    pub shutdown: Arc<Notify>,
    pub active_checks: Arc<Semaphore>,
    pub upstream: Arc<upstream::UpstreamPool>,
    pub destination_port: u16,
}

/// Configuration for the HTTP/3 backend.
pub struct Http3Config {
    pub policy: Arc<PolicySession>,
    pub issuer: CertificateIssuer,
    pub shutdown: Arc<Notify>,
    pub active_checks: Arc<Semaphore>,
    pub listen_port: u16,
    pub test_destination: Option<SocketAddr>,
}

/// Prepare the HTTP/3 backend so every fallible setup step runs before
/// the proxy declares itself ready.
///
/// # Errors
///
/// Returns an error when the upstream trust store is missing or the UDP
/// listeners cannot be bound.
pub fn prepare(config: Http3Config) -> Result<Http3Backend, BoxError> {
    let ca_file = std::env::var_os("SSL_CERT_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| boxed("SSL_CERT_FILE is required to verify upstream HTTP/3 certificates"))?;

    let upstream = Arc::new(upstream::UpstreamPool::new(&ca_file)?);

    let transparent = config.test_destination.is_none();

    let destination_port = config
        .test_destination
        .map_or(config.listen_port, |destination| destination.port());

    let state = Arc::new(Http3State {
        policy: config.policy,
        issuer: config.issuer,
        shutdown: config.shutdown,
        active_checks: config.active_checks,
        upstream,
        destination_port,
    });

    let v4 = bind_endpoint(
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        config.listen_port,
        transparent,
        &state,
    )?;

    let v6 = bind_endpoint(
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        config.listen_port,
        transparent,
        &state,
    )?;

    let destination =
        association::DestinationResolver::new(config.listen_port, config.test_destination);

    Ok(Http3Backend {
        v4,
        v6,
        state,
        destination,
    })
}

/// A prepared HTTP/3 backend; run it with [`run`].
pub struct Http3Backend {
    v4: quinn::Endpoint,
    v6: quinn::Endpoint,
    state: Arc<Http3State>,
    destination: association::DestinationResolver,
}

/// Run a prepared HTTP/3 backend until shutdown is signalled.
pub async fn run(backend: Http3Backend) {
    let Http3Backend {
        v4,
        v6,
        state,
        destination,
    } = backend;

    let v4_loop = tokio::spawn(association::accept_loop(
        v4,
        state.clone(),
        destination.clone(),
    ));
    let v6_loop = tokio::spawn(association::accept_loop(v6, state.clone(), destination));

    tracing::info!("HTTP/3 backend listening");

    let _ = tokio::join!(v4_loop, v6_loop);
}

fn bind_endpoint(
    ip: IpAddr,
    port: u16,
    transparent: bool,
    state: &Http3State,
) -> Result<quinn::Endpoint, BoxError> {
    let socket = TransparentUdpSocket::bind(SocketAddr::new(ip, port), transparent)?;

    let tls = downstream_tls_config(state)?;

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(tls),
        Arc::new(socket),
        quinn::default_runtime()
            .ok_or_else(|| std::io::Error::other("no async runtime available"))?,
    )?;

    Ok(endpoint)
}

fn downstream_tls_config(state: &Http3State) -> Result<quinn::ServerConfig, BoxError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SandboxCertResolver {
            issuer: state.issuer.clone(),
            fallback_name: std::net::Ipv4Addr::LOCALHOST.to_string(),
        }));

    tls.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));

    let tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls));
    server_config.transport_config(Arc::new(transport));

    // Client path changes must not relay on an unapproved UDP tuple until
    // the migration rebind contract is implemented; quinn then rejects
    // active migration and keeps the association on the claimed path.
    server_config.migration(false);

    Ok(server_config)
}

/// Issues a leaf certificate from the sandbox CA for each client's SNI.
struct SandboxCertResolver {
    issuer: CertificateIssuer,
    fallback_name: String,
}

impl std::fmt::Debug for SandboxCertResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxCertResolver")
            .field("issuer", &self.issuer)
            .field("fallback_name", &self.fallback_name)
            .finish()
    }
}
impl rustls::server::ResolvesServerCert for SandboxCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let server_name = client_hello.server_name().unwrap_or(&self.fallback_name);

        let issued = self.issuer.issue(server_name).ok()?;

        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(&issued.private_key).ok()?;

        let key = rustls::sign::CertifiedKey::new(issued.certificate_chain.clone(), signing_key);

        Some(Arc::new(key))
    }
}

/// Shared error type for the HTTP/3 backend.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn boxed(message: &'static str) -> BoxError {
    message.into()
}
