//! Upstream HTTP/3 client connections for the proxy's QUIC backend.
//!
//! Upstream associations are separate from the downstream associations the
//! proxy terminates. They are pooled by origin authority and closed when the
//! peer goes away or the idle timeout expires, so ownership of an upstream
//! association is released after the exchange that used it completes.
//!
//! Each origin's TLS configuration carries the verified upstream ECH
//! configuration when its DNS zone advertises one; origins without ECH keep
//! ordinary TLS, where the SNI and certificate identity still bind to the
//! policy target. An unverifiable advertised configuration fails closed.

use super::{BoxError, ech::UpstreamEch};
use bytes::Bytes;
use h3::client::SendRequest;
use rustls::pki_types::pem::PemObject;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Weak},
    time::Duration,
};

/// Pool of upstream HTTP/3 connections keyed by origin authority.
pub struct UpstreamPool {
    endpoint: quinn::Endpoint,
    connections: Arc<std::sync::Mutex<HashMap<String, Weak<UpstreamConnection>>>>,
    tls: UpstreamTls,
    ech: UpstreamEch,
}

/// Shared upstream TLS material: the crypto provider and the verified roots.
/// The per-origin ECH configuration cache lives in [`UpstreamEch`].
struct UpstreamTls {
    provider: Arc<rustls::crypto::CryptoProvider>,
    roots: Arc<rustls::RootCertStore>,
}

impl UpstreamPool {
    /// Create the upstream client endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the client endpoint or its TLS configuration
    /// cannot be built.
    pub fn new(ca_file: &Path, test_ech_dns: Option<SocketAddr>) -> Result<Self, BoxError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let pem = std::fs::read(ca_file)?;
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()?;

        if certificates.is_empty() {
            return Err(
                std::io::Error::other("upstream CA bundle contains no certificates").into(),
            );
        }

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(certificates);

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std::net::UdpSocket::bind((IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0]), 0))?,
            quinn::default_runtime()
                .ok_or_else(|| std::io::Error::other("no async runtime available"))?,
        )
        .map_err(BoxError::from)?;

        Ok(Self {
            endpoint,
            connections: Arc::new(std::sync::Mutex::new(HashMap::new())),
            tls: UpstreamTls {
                provider,
                roots: Arc::new(roots),
            },
            ech: UpstreamEch::new(test_ech_dns),
        })
    }

    /// Get a live upstream connection for an origin authority, or establish
    /// one.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin cannot be resolved, its advertised
    /// ECH configuration is unverifiable, or the QUIC and HTTP/3 handshakes
    /// fail.
    ///
    /// # Panics
    ///
    /// Panics when the pool lock is poisoned by a panicking task.
    pub async fn connect(
        self: &Arc<Self>,
        scheme: &str,
        authority: &str,
    ) -> Result<Arc<UpstreamConnection>, BoxError> {
        let key = format!("{scheme}://{authority}");

        {
            let pool = self.connections.lock().expect("upstream pool lock");

            if let Some(connection) = pool.get(&key).and_then(Weak::upgrade) {
                return Ok(connection);
            }
        }

        let (host, port) = split_authority(authority)?;

        let addresses = tokio::net::lookup_host((host, port)).await?;

        let mut last_error = None;

        for address in addresses {
            match self.establish(host, authority, address).await {
                Ok(connection) => {
                    self.connections
                        .lock()
                        .expect("upstream pool lock")
                        .insert(key.clone(), Arc::downgrade(&connection));

                    return Ok(connection);
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            BoxError::from(format!("origin {authority} resolved to no addresses"))
        }))
    }

    async fn establish(
        &self,
        host: &str,
        authority: &str,
        address: SocketAddr,
    ) -> Result<Arc<UpstreamConnection>, BoxError> {
        let client_config = self.client_config(host).await?;

        let connecting = self
            .endpoint
            .connect_with(client_config, address, host)
            .map_err(BoxError::from)?;

        let connection = tokio::time::timeout(Duration::from_secs(2), connecting)
            .await
            .map_err(|_| {
                BoxError::from(format!("upstream QUIC handshake timed out for {authority}"))
            })?
            .map_err(|error| {
                BoxError::from(format!(
                    "upstream QUIC handshake failed for {authority}: {error}"
                ))
            })?;

        let h3 = h3_quinn::Connection::new(connection.clone());
        let (mut h3_connection, send_request) = h3::client::new(h3).await.map_err(|error| {
            BoxError::from(format!(
                "upstream HTTP/3 handshake failed for {authority}: {error}"
            ))
        })?;

        let connection = Arc::new(UpstreamConnection {
            authority: authority.to_owned(),
            connection,
            send_request: tokio::sync::Mutex::new(send_request),
        });

        let watcher = connection.clone();
        let pool = Arc::clone(&self.connections);

        tokio::spawn(async move {
            tokio::select! {
                _ = watcher.connection.closed() => {}
                _ = h3_connection.wait_idle() => {}
            }

            pool.lock()
                .expect("upstream pool lock")
                .retain(|key, entry| key != &watcher.authority || entry.strong_count() > 0);
        });

        Ok(connection)
    }

    /// Build the per-origin QUIC client configuration.
    ///
    /// A verified ECH configuration enables ECH for the handshake; a missing
    /// or unadvertised configuration keeps ordinary TLS. An unverifiable
    /// advertised configuration is an error, so the connection fails closed.
    async fn client_config(&self, host: &str) -> Result<quinn::ClientConfig, BoxError> {
        let ech = self.ech.config_for(host).await?;

        // `with_ech` fixes TLS 1.3 as the only protocol version; the plain
        // path keeps the safe defaults instead.
        let builder = rustls::ClientConfig::builder_with_provider(self.tls.provider.clone());

        let builder = match ech {
            Some(config) => builder
                .with_ech(rustls::client::EchMode::Enable((*config).clone()))
                .map_err(BoxError::from)?,
            None => builder.with_safe_default_protocol_versions()?,
        };

        let mut tls = builder
            .with_root_certificates(self.tls.roots.clone())
            .with_no_client_auth();

        tls.alpn_protocols = vec![b"h3".to_vec()];

        let client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(BoxError::from)?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));

        let mut client_config = quinn::ClientConfig::new(Arc::new(client_config));
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }
}

/// Split one origin authority into its host and port.
///
/// # Errors
///
/// Returns an error when the authority has no parseable port.
fn split_authority(authority: &str) -> Result<(&str, u16), BoxError> {
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');

    let port = authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .ok_or_else(|| BoxError::from(format!("origin authority has no port: {authority}")))?;

    Ok((host, port))
}

/// One live upstream HTTP/3 association.
pub struct UpstreamConnection {
    authority: String,
    connection: quinn::Connection,
    send_request: tokio::sync::Mutex<SendRequest<h3_quinn::OpenStreams, Bytes>>,
}

impl UpstreamConnection {
    /// Send one request over the upstream association.
    ///
    /// # Errors
    ///
    /// Returns an error when the association cannot open the request stream.
    pub async fn send_request(
        &self,
        request: http::Request<()>,
    ) -> Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, BoxError> {
        self.send_request
            .lock()
            .await
            .send_request(request)
            .await
            .map_err(|error| BoxError::from(format!("upstream request failed: {error}")))
    }
}
