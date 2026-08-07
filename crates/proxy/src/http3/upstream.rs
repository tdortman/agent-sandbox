//! Upstream HTTP/3 client connections for the proxy's QUIC backend.
//!
//! Upstream associations are separate from the downstream associations the
//! proxy terminates. They are pooled by origin authority, transport address,
//! and policy context, then closed when the peer goes away or the idle timeout
//! expires, so ownership of an upstream association is released after its
//! exchange completes.
//!
//! Each origin's TLS configuration carries the verified upstream ECH
//! configuration when its DNS zone advertises one; origins without ECH keep
//! ordinary TLS, where the SNI and certificate identity still bind to the
//! policy target. An unverifiable advertised configuration fails closed.

use super::{BoxError, ech::UpstreamEch, session::SessionProtocol};
use agent_sandbox_core::AttributionToken;
use bytes::Bytes;
use h3::{
    ConnectionState,
    client::SendRequest,
    quic::{OpenStreams as _, SendStream as _},
};
use rustls::pki_types::pem::PemObject;
use std::{
    collections::HashMap,
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};

pub(crate) enum IncomingWebTransportStream {
    Bidi(Box<h3_webtransport::stream::BidiStream<h3_quinn::BidiStream<Bytes>, Bytes>>),
    Uni(h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>),
}

pub(crate) type IncomingWebTransportReceiver =
    tokio::sync::mpsc::Receiver<IncomingWebTransportStream>;

type IncomingWebTransportSender = tokio::sync::mpsc::Sender<IncomingWebTransportStream>;
type UpstreamPoolKey = (String, String, AttributionToken, SocketAddr);

/// Pool of upstream HTTP/3 connections keyed by origin and policy context.
pub struct UpstreamPool {
    endpoint: quinn::Endpoint,
    connections: Arc<std::sync::Mutex<HashMap<UpstreamPoolKey, Weak<UpstreamConnection>>>>,
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
        security_context: AttributionToken,
    ) -> Result<Arc<UpstreamConnection>, BoxError> {
        let (host, port) = split_authority(authority)?;
        let addresses = tokio::net::lookup_host((host, port)).await?;
        let mut last_error = None;

        for address in addresses {
            match self
                .connect_address(scheme, authority, host, address, Some(&security_context))
                .await
            {
                Ok(connection) => return Ok(connection),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            BoxError::from(format!("origin {authority} resolved to no addresses"))
        }))
    }

    /// Get a live upstream connection for an origin authority at a known
    /// transport address, or establish one.
    ///
    /// The address supplies routing only. The authority still supplies the
    /// TLS server name and HTTP origin identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the advertised ECH configuration is unverifiable
    /// or the QUIC and HTTP/3 handshakes fail.
    ///
    /// # Panics
    ///
    /// Panics when the pool lock is poisoned by a panicking task.
    pub async fn connect_to(
        self: &Arc<Self>,
        scheme: &str,
        authority: &str,
        address: SocketAddr,
        security_context: AttributionToken,
    ) -> Result<Arc<UpstreamConnection>, BoxError> {
        let (host, port) = split_authority(authority)?;
        let address = SocketAddr::new(address.ip(), port);

        self.connect_address(scheme, authority, host, address, Some(&security_context))
            .await
    }

    /// Establish a separate upstream HTTP/3 association for one session.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin cannot be resolved or the HTTP/3
    /// handshake fails.
    pub async fn connect_dedicated(
        self: &Arc<Self>,
        scheme: &str,
        authority: &str,
    ) -> Result<Arc<UpstreamConnection>, BoxError> {
        let (host, port) = split_authority(authority)?;
        let addresses = tokio::net::lookup_host((host, port)).await?;
        let mut last_error = None;

        for address in addresses {
            match self
                .connect_address(scheme, authority, host, address, None)
                .await
            {
                Ok(connection) => return Ok(connection),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            BoxError::from(format!("origin {authority} resolved to no addresses"))
        }))
    }

    /// Establish a separate upstream HTTP/3 association at a known address.
    ///
    /// The address supplies routing only. The authority still supplies the
    /// TLS server name and HTTP origin identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the advertised ECH configuration is unverifiable
    /// or the HTTP/3 handshake fails.
    pub async fn connect_dedicated_to(
        self: &Arc<Self>,
        scheme: &str,
        authority: &str,
        address: SocketAddr,
    ) -> Result<Arc<UpstreamConnection>, BoxError> {
        let (host, port) = split_authority(authority)?;
        let address = SocketAddr::new(address.ip(), port);

        self.connect_address(scheme, authority, host, address, None)
            .await
    }

    async fn connect_address(
        &self,
        scheme: &str,
        authority: &str,
        host: &str,
        address: SocketAddr,
        security_context: Option<&AttributionToken>,
    ) -> Result<Arc<UpstreamConnection>, BoxError> {
        let pool_key = security_context.map(|security_context| {
            (
                scheme.to_owned(),
                authority.to_owned(),
                security_context.clone(),
                address,
            )
        });

        if let Some(pool_key) = pool_key.as_ref()
            && let Some(connection) = self
                .connections
                .lock()
                .expect("upstream pool lock")
                .get(pool_key)
                .and_then(Weak::upgrade)
        {
            return Ok(connection);
        }

        let connection = self
            .establish(host, authority, address, pool_key.as_ref())
            .await?;

        if let Some(pool_key) = pool_key {
            self.connections
                .lock()
                .expect("upstream pool lock")
                .insert(pool_key, Arc::downgrade(&connection));
        }

        Ok(connection)
    }

    async fn establish(
        &self,
        host: &str,
        authority: &str,
        address: SocketAddr,
        pool_key: Option<&UpstreamPoolKey>,
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
        let mut builder = h3::client::builder();

        builder
            .enable_extended_connect(true)
            .enable_datagram(true)
            .enable_webtransport(true);

        let (h3_connection, send_request) = builder.build(h3).await.map_err(|error| {
            BoxError::from(format!(
                "upstream HTTP/3 handshake failed for {authority}: {error}"
            ))
        })?;

        let incoming_sessions = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let connection = Arc::new(UpstreamConnection {
            connection,
            send_request: tokio::sync::Mutex::new(send_request),
            incoming_sessions,
        });

        let watcher = connection.clone();
        let pool = Arc::clone(&self.connections);
        let pool_key = pool_key.cloned();
        let driver_sessions = watcher.incoming_sessions.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = watcher.connection.closed() => {}
                () = drive_upstream(h3_connection, driver_sessions.clone()) => {}
            }

            driver_sessions.lock().await.clear();

            if let Some(pool_key) = pool_key {
                pool.lock()
                    .expect("upstream pool lock")
                    .retain(|key, entry| {
                        key != &pool_key
                            || entry
                                .upgrade()
                                .is_some_and(|entry| !Arc::ptr_eq(&entry, &watcher))
                    });
            }
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

        tls.enable_early_data = false;
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

enum UpstreamEvent {
    Bidi(h3_quinn::BidiStream<Bytes>),

    Uni(
        h3::webtransport::SessionId,
        h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>,
    ),
}

fn poll_upstream_event(
    connection: &mut h3::client::Connection<h3_quinn::Connection, Bytes>,
    context: &mut Context<'_>,
) -> Poll<Result<UpstreamEvent, h3::error::ConnectionError>> {
    if let Some((session_id, stream)) = connection.inner.accepted_streams_mut().wt_uni_streams.pop()
    {
        return Poll::Ready(Ok(UpstreamEvent::Uni(
            session_id,
            h3_webtransport::stream::RecvStream::new(stream),
        )));
    }

    match connection.poll_accept_bi(context) {
        Poll::Ready(Ok(stream)) => return Poll::Ready(Ok(UpstreamEvent::Bidi(stream))),
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Pending => {}
    }

    match connection.poll_close(context) {
        Poll::Ready(error) => Poll::Ready(Err(error)),

        Poll::Pending => {
            if let Some((session_id, stream)) =
                connection.inner.accepted_streams_mut().wt_uni_streams.pop()
            {
                return Poll::Ready(Ok(UpstreamEvent::Uni(
                    session_id,
                    h3_webtransport::stream::RecvStream::new(stream),
                )));
            }

            Poll::Pending
        }
    }
}

async fn drive_upstream(
    mut connection: h3::client::Connection<h3_quinn::Connection, Bytes>,
    sessions: Arc<
        tokio::sync::Mutex<HashMap<h3::webtransport::SessionId, IncomingWebTransportSender>>,
    >,
) {
    loop {
        let event = poll_fn(|context| poll_upstream_event(&mut connection, context)).await;

        match event {
            Ok(UpstreamEvent::Bidi(stream)) => {
                let sessions = Arc::clone(&sessions);
                tokio::spawn(async move {
                    match h3_webtransport::stream::accept_bidi(stream).await {
                        Ok((session_id, stream)) => {
                            dispatch_incoming(
                                session_id,
                                IncomingWebTransportStream::Bidi(Box::new(stream)),
                                sessions,
                            )
                            .await;
                        }
                        Err(error) => {
                            tracing::warn!("upstream WebTransport stream rejected: {error}");
                        }
                    }
                });
            }

            Ok(UpstreamEvent::Uni(session_id, stream)) => {
                dispatch_incoming(
                    session_id,
                    IncomingWebTransportStream::Uni(stream),
                    Arc::clone(&sessions),
                )
                .await;
            }

            Err(error) => {
                tracing::debug!("upstream HTTP/3 driver closed: {error}");
                return;
            }
        }
    }
}

async fn dispatch_incoming(
    session_id: h3::webtransport::SessionId,
    stream: IncomingWebTransportStream,
    sessions: Arc<
        tokio::sync::Mutex<HashMap<h3::webtransport::SessionId, IncomingWebTransportSender>>,
    >,
) {
    let sender = sessions.lock().await.get(&session_id).cloned();

    if let Some(sender) = sender {
        match sender.send(stream).await {
            Ok(()) => return,

            Err(error) => {
                sessions.lock().await.remove(&session_id);
                super::association::reject_webtransport_stream(error.0);
                return;
            }
        }
    }

    super::association::reject_webtransport_stream(stream);
}

/// One live upstream HTTP/3 association.
pub struct UpstreamConnection {
    connection: quinn::Connection,
    send_request: tokio::sync::Mutex<SendRequest<h3_quinn::OpenStreams, Bytes>>,

    incoming_sessions:
        Arc<tokio::sync::Mutex<HashMap<h3::webtransport::SessionId, IncomingWebTransportSender>>>,
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

    /// Require the peer settings for one approved session protocol.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer does not advertise the required
    /// settings before the session timeout.
    pub async fn require_session_settings(
        &self,
        protocol: SessionProtocol,
    ) -> Result<(), BoxError> {
        for _ in 0..200 {
            let settings = {
                let send_request = self.send_request.lock().await;
                *send_request.settings()
            };

            let supported = settings.enable_extended_connect()
                && (!protocol.needs_datagrams() || settings.enable_datagram())
                && (!matches!(protocol, SessionProtocol::WebTransport)
                    || settings.enable_webtransport());

            if supported {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Err(BoxError::from(format!(
            "upstream HTTP/3 peer refused {} settings",
            protocol.name()
        )))
    }

    pub(crate) async fn register_webtransport_session(
        &self,
        session_id: h3::webtransport::SessionId,
    ) -> IncomingWebTransportReceiver {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);

        self.incoming_sessions
            .lock()
            .await
            .insert(session_id, sender);

        receiver
    }

    pub(crate) async fn unregister_webtransport_session(
        &self,
        session_id: h3::webtransport::SessionId,
    ) {
        self.incoming_sessions.lock().await.remove(&session_id);
    }

    /// Open one upstream WebTransport bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the upstream association cannot open or
    /// initialise the stream.
    pub(crate) async fn open_webtransport_stream(
        &self,
        session_id: h3::webtransport::SessionId,
    ) -> Result<h3_quinn::BidiStream<Bytes>, BoxError> {
        let h3 = h3_quinn::Connection::new(self.connection.clone());
        let mut opener = <h3_quinn::Connection as h3::quic::Connection<Bytes>>::opener(&h3);

        let mut stream = poll_fn(|context| opener.poll_open_bidi(context))
            .await
            .map_err(|error| {
                BoxError::from(format!("upstream WebTransport stream failed: {error}"))
            })?;

        stream
            .send_data(h3::stream::BidiStreamHeader::WebTransportBidi(session_id))
            .map_err(|error| {
                BoxError::from(format!("upstream WebTransport header failed: {error}"))
            })?;

        poll_fn(|context| stream.poll_ready(context))
            .await
            .map_err(|error| {
                BoxError::from(format!("upstream WebTransport header failed: {error}"))
            })?;

        Ok(stream)
    }

    /// Open one upstream WebTransport unidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the upstream association cannot open or
    /// initialise the stream.
    pub async fn open_webtransport_uni_stream(
        &self,
        session_id: h3::webtransport::SessionId,
    ) -> Result<h3_quinn::SendStream<Bytes>, BoxError> {
        let h3 = h3_quinn::Connection::new(self.connection.clone());
        let mut opener = <h3_quinn::Connection as h3::quic::Connection<Bytes>>::opener(&h3);

        let mut stream = poll_fn(|context| opener.poll_open_send(context))
            .await
            .map_err(|error| {
                BoxError::from(format!("upstream WebTransport uni stream failed: {error}"))
            })?;

        stream
            .send_data(h3::stream::UniStreamHeader::WebTransportUni(session_id))
            .map_err(|error| {
                BoxError::from(format!("upstream WebTransport uni header failed: {error}"))
            })?;

        poll_fn(|context| stream.poll_ready(context))
            .await
            .map_err(|error| {
                BoxError::from(format!("upstream WebTransport uni header failed: {error}"))
            })?;

        Ok(stream)
    }

    /// Send one raw QUIC datagram through this HTTP/3 association.
    ///
    /// # Errors
    ///
    /// Returns an error when QUIC rejects the datagram.
    pub fn send_datagram(&self, datagram: Bytes) -> Result<(), BoxError> {
        self.connection
            .send_datagram(datagram)
            .map_err(|error| BoxError::from(format!("upstream HTTP Datagram failed: {error}")))
    }

    /// Receive one raw QUIC datagram from this HTTP/3 association.
    ///
    /// # Errors
    ///
    /// Returns an error when the association closes.
    pub async fn recv_datagram(&self) -> Result<Bytes, BoxError> {
        self.connection
            .read_datagram()
            .await
            .map_err(|error| BoxError::from(format!("upstream HTTP Datagram failed: {error}")))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn client_builder_supports_webtransport_settings() {
        let mut builder = h3::client::builder();
        builder.enable_webtransport(true);
    }
}
