use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use agent_sandbox_core::HttpRequest;
use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt},
    extensions::ExtensionsRef,
    rt::Executor,
    service::BoxService,
};
use rama_dns::client::DnsConnectorLayer;
use rama_http::{
    Body, Request, Response, StreamingBody, Version, body::Frame, conn::TargetHttpVersion,
};
use rama_http_backend::client::{
    BasicHttpConId, BindBodyToConn, HttpClientService, HttpConnector, HttpPooledConnectorConfig,
};
use rama_net::{
    address::{Host, HostWithPort},
    client::{ConnectorTarget, EstablishedClientConnection, pool::MultiplexedConnection},
};
use rama_tcp::client::service::TcpConnector;
use rama_tls::client::{NegotiatedTlsParameters, TlsClientConfig};
use rama_tls_rustls::client::{RustlsClientConfigExt, TlsConnector};

use super::{
    FlowState, SemanticRequestBody, canonical_http10_origin, force_websocket_http11,
    is_h2_protocol_negotiation_failure, is_protocol_negotiation_failure, request_head_clone,
};
use crate::{semantic::SemanticRequest, upstream_tls::UpstreamClientIdentities};

/// Bind transport dialing to the destination claimed by policyd.
///
/// The HTTP authority remains the policy-approved hostname for Host, TLS
/// identity, and pool attribution; `ConnectorTarget` makes the transport
/// connector use this immutable concrete address instead of resolving it.
fn claimed_connector_target(destination: std::net::SocketAddr) -> ConnectorTarget {
    ConnectorTarget(HostWithPort::new(
        Host::from(destination.ip()),
        destination.port(),
    ))
}

/// The connection type the pooled upstream client establishes.
type UpstreamConnection = EstablishedClientConnection<
    BindBodyToConn<MultiplexedConnection<HttpClientService<Body>, BasicHttpConId>>,
    Request,
>;

/// Report whether an HTTP/2-targeted connection negotiated no ALPN protocol.
fn connection_h2_without_alpn(connection: &UpstreamConnection) -> bool {
    let extensions = connection.conn.extensions();
    extensions
        .get_ref::<TargetHttpVersion>()
        .is_some_and(|target| target.0 == Version::HTTP_2)
        && extensions
            .get_ref::<NegotiatedTlsParameters>()
            .is_some_and(|params| params.application_layer_protocol.is_none())
}

/// Send one request over an established upstream connection.
async fn send_connection(connection: UpstreamConnection) -> Result<Response, BoxError> {
    let mut request = connection.input;
    let version = request
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .or_else(|| connection.conn.extensions().get_ref::<TargetHttpVersion>())
        .map_or(Version::HTTP_11, |target| target.0);
    rama_http::layer::version_adapter::adapt_request_version(&mut request, version)?;
    connection.conn.serve(request).await
}

struct ReplayBodyState {
    body: std::sync::Mutex<Option<Body>>,
    started: AtomicBool,
}

struct ReplayBody {
    state: Arc<ReplayBodyState>,
    inner: Option<Body>,
}

impl ReplayBody {
    const fn new(state: Arc<ReplayBodyState>) -> Self {
        Self { state, inner: None }
    }
}

impl Drop for ReplayBody {
    fn drop(&mut self) {
        if self.state.started.load(Ordering::Acquire) {
            return;
        }

        let Some(body) = self.inner.take() else {
            return;
        };

        let mut shared = self.state.body.lock().expect("replay body lock");

        if shared.is_none() {
            *shared = Some(body);
        }
    }
}

impl StreamingBody for ReplayBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.inner.is_none() {
            let body = self.state.body.lock().expect("replay body lock").take();
            self.inner = body;
        }

        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };

        let result = Pin::new(inner).poll_frame(cx);

        if matches!(&result, Poll::Ready(Some(Ok(_)))) {
            self.state.started.store(true, Ordering::Release);
        }

        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().map_or_else(
            || {
                self.state
                    .body
                    .lock()
                    .expect("replay body lock")
                    .as_ref()
                    .is_none_or(StreamingBody::is_end_stream)
            },
            StreamingBody::is_end_stream,
        )
    }

    fn size_hint(&self) -> rama_http::body::SizeHint {
        self.inner.as_ref().map_or_else(
            || {
                self.state
                    .body
                    .lock()
                    .expect("replay body lock")
                    .as_ref()
                    .map_or_else(rama_http::body::SizeHint::default, StreamingBody::size_hint)
            },
            StreamingBody::size_hint,
        )
    }
}

pub struct UpstreamClients {
    automatic: BoxService<Request, UpstreamConnection, BoxError>,
    http1: BoxService<Request, UpstreamConnection, BoxError>,
    http2: BoxService<Request, UpstreamConnection, BoxError>,
}

impl UpstreamClients {
    pub fn new(identities: Arc<UpstreamClientIdentities>) -> Result<Self, BoxError> {
        Ok(Self {
            automatic: build_upstream_client(identities.clone())?,
            http1: build_upstream_client(identities.clone())?,
            http2: build_upstream_client(identities)?,
        })
    }

    async fn send_with_recovery(
        &self,
        connection: UpstreamConnection,
        body: &Arc<ReplayBodyState>,
    ) -> Result<Response, BoxError> {
        let version = connection
            .input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .or_else(|| connection.conn.extensions().get_ref::<TargetHttpVersion>())
            .map_or(Version::HTTP_11, |target| target.0);
        let retry = request_head_clone(
            &connection.input,
            version,
            Body::new(ReplayBody::new(body.clone())),
        );
        match send_connection(connection).await {
            Err(error)
                if version == Version::HTTP_2
                    && !body.started.load(Ordering::Acquire)
                    && body.body.lock().expect("replay body lock").is_some()
                    && is_unprocessed_h2(error.as_ref()) =>
            {
                // One retry, preserving the destination, policy context and HTTP version.
                send_connection(self.connect(retry).await?).await
            }
            result => result,
        }
    }

    async fn connect(&self, request: Request) -> Result<UpstreamConnection, BoxError> {
        // Rama's pool key omits the HTTP version. Keep pinned connections out
        // of the automatic pool, including h2 WebSocket Extended CONNECT.
        let client = match request.extensions().get_ref::<TargetHttpVersion>() {
            Some(target) if target.0 == Version::HTTP_2 => &self.http2,
            Some(_) => &self.http1,
            None => &self.automatic,
        };
        client.serve(request).await
    }
}

const fn select_upstream_version(
    requested_http10: bool,
    secure: bool,
    websocket_version: Option<Version>,
) -> Option<Version> {
    if requested_http10 {
        Some(Version::HTTP_10)
    } else if !secure {
        Some(Version::HTTP_11)
    } else {
        websocket_version
    }
}

/// Adjust TLS ALPN and the request version for upstream targets.
///
/// ALPN has no `http/1.0` token, but the TLS connector derives the offered
/// ALPN from `TargetHttpVersion` and would offer the invalid `http/1.0`
/// value. Shadow the target with `HTTP/1.1` during the handshake so the
/// connector offers `http/1.1`, then restore `HTTP/1.0` afterwards so the
/// version adapter still sends HTTP/1.0. TLS can also succeed without ALPN.
/// In that case, return a protocol negotiation error before the HTTP connector
/// starts its HTTP/2 handshake, so the caller can retry with HTTP/1.1.
#[derive(Clone)]
struct TlsAlpnConnector<S> {
    inner: S,
    identities: Arc<UpstreamClientIdentities>,
}

impl<S> TlsAlpnConnector<S> {
    const fn new(inner: S, identities: Arc<UpstreamClientIdentities>) -> Self {
        Self { inner, identities }
    }
}

impl<S, C> Service<Request> for TlsAlpnConnector<S>
where
    S: Service<Request, Output = EstablishedClientConnection<C, Request>, Error: Into<BoxError>>,
    C: ExtensionsRef + Send + 'static,
{
    type Error = BoxError;
    type Output = EstablishedClientConnection<C, Request>;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        let http10_target = request
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .is_some_and(|target| target.0 == Version::HTTP_10);

        let http2_target = request
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .is_some_and(|target| target.0 == Version::HTTP_2);

        if http10_target {
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_11));
        }

        // The URI has already been rebuilt from the policy-approved origin.
        if let Some(authority) = request.uri().authority() {
            let origin = format!(
                "{}://{authority}",
                request.uri().scheme_str().unwrap_or("http")
            );
            if let Some(resolver) = self.identities.resolver(&origin)? {
                TlsClientConfig::new()
                    .with_modify_rustls_config(move |mut config| {
                        config.client_auth_cert_resolver = resolver.clone();
                        Ok(config)
                    })
                    .write_to(request.extensions());
            }
        }

        let established = self.inner.serve(request).await.map_err(Into::into)?;

        let no_alpn_http2 = http2_target
            && established
                .conn
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
                .is_some_and(|params| params.application_layer_protocol.is_none());

        if no_alpn_http2 {
            return Err(BoxError::from_static_str("HTTP/2 handshake requires ALPN"));
        }

        if http10_target {
            established
                .input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_10));
            established
                .conn
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_10));
        }

        Ok(established)
    }
}

/// Acknowledge incoming TLS and HTTP records promptly so an origin using
/// Nagle does not hold its response behind our delayed ACK timer. Linux
/// may leave quick-ACK mode during a connection, so rearm after each read.
#[derive(Debug)]
struct QuickAckStream {
    stream: rama_tcp::TcpStream,
}

impl ExtensionsRef for QuickAckStream {
    fn extensions(&self) -> &rama_core::extensions::Extensions {
        self.stream.extensions()
    }
}

impl tokio::io::AsyncRead for QuickAckStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            rama_net::socket::core::SockRef::from(&self.stream.stream).set_tcp_quickack(true)?;
        }
        result
    }
}

impl tokio::io::AsyncWrite for QuickAckStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn build_upstream_client(
    identities: Arc<UpstreamClientIdentities>,
) -> Result<BoxService<Request, UpstreamConnection, BoxError>, BoxError> {
    let options = Arc::new(rama_net::socket::SocketOptions {
        tcp_no_delay: Some(true),
        ..rama_net::socket::SocketOptions::default_tcp()
    });
    let connector =
        DnsConnectorLayer::new().into_layer(TcpConnector::default().with_connector(options));
    let connector = rama_core::service::service_fn(move |request: Request| {
        let connector = connector.clone();
        async move {
            let connection = connector.serve(request).await?;
            Ok::<_, BoxError>(EstablishedClientConnection {
                input: connection.input,
                conn: QuickAckStream {
                    stream: connection.conn,
                },
            })
        }
    });
    let connector = TlsConnector::auto(connector).with_base_config(TlsClientConfig::default_http());
    let connector = TlsAlpnConnector::new(connector, identities);

    let connector = rama_http::layer::version_adapter::RequestVersionAdapter::new(connector)
        .with_default_version(Version::HTTP_11);

    let client = HttpConnector::new(connector, Executor::default());
    let client = HttpPooledConnectorConfig::default().build_connector(client)?;
    Ok(BoxService::new(client))
}

fn is_unprocessed_h2(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(error) = source {
        if error
            .downcast_ref::<rama_http_core::h2::Error>()
            .is_some_and(rama_http_core::h2::Error::is_unprocessed)
        {
            return true;
        }
        source = error.source();
    }
    false
}

fn is_no_alpn_h2_cancellation(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(error);

    while let Some(error) = source {
        if error
            .downcast_ref::<rama_http_core::Error>()
            .is_some_and(rama_http_core::Error::is_canceled)
        {
            return true;
        }

        source = error.source();
    }

    false
}

pub async fn send_upstream_request(
    mut request: Request,
    state: &FlowState,
    semantic_request: SemanticRequest,
    normalized: &HttpRequest,
    downstream_version: Version,
    websocket: bool,
) -> Result<(Response, String), BoxError> {
    if let Some(sender) = request
        .extensions()
        .get_ref::<rama_http_core::informational::InformationalSender>()
        .cloned()
    {
        request.extensions().insert(
            rama_http::proto::h1::ext::informational::OnInformational::new_fn(move |head| {
                let mut response = Response::new(());
                *response.status_mut() = head.status();
                let tokens = head
                    .headers()
                    .get_all("connection")
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .flat_map(|value| value.split(','))
                    .map(|value| value.trim().to_ascii_lowercase())
                    .collect::<Vec<_>>();
                for (name, value) in head.headers() {
                    if !crate::semantic::is_hop_by_hop_header(name.as_str(), &tokens) {
                        response.headers_mut().append(name.clone(), value.clone());
                    }
                }

                // Errors are also recorded in the sender and terminate the downstream.
                let _ = sender.send(response);
            }),
        );
    }

    let upstream_url = url::Url::parse(&normalized.url.to_string())?;

    let upstream_host = upstream_url
        .host_str()
        .ok_or_else(|| BoxError::from_static_str("normalized policy target has no host"))?;

    let upstream_port = upstream_url
        .port_or_known_default()
        .ok_or_else(|| BoxError::from_static_str("normalized policy target has no port"))?;

    let upstream_authority = super::authority_for_policy(upstream_host, upstream_port);

    let upstream_origin =
        canonical_http10_origin(&format!("{}://{upstream_authority}", upstream_url.scheme()))?;

    let target = semantic_request.forwarding_target();
    let semantic_body = semantic_request.into_body();

    let websocket_http11 = websocket
        && state
            .websocket_http11_urls
            .iter()
            .any(|pattern| pattern.matches(&normalized.url));

    let uri = format!("{}://{upstream_authority}{target}", upstream_url.scheme());
    *request.uri_mut() = uri.parse()?;

    request
        .extensions()
        .insert(claimed_connector_target(state.destination));

    let requested_http10 = downstream_version == Version::HTTP_10
        || state.http10_upstream_origins.contains(&upstream_origin);

    let websocket_version = websocket.then_some(
        if websocket_http11 || downstream_version <= Version::HTTP_11 {
            Version::HTTP_11
        } else {
            Version::HTTP_2
        },
    );
    let h2c = !websocket && state.h2c_upstream_origins.contains(&upstream_origin);
    let upstream_version = if h2c {
        Some(Version::HTTP_2)
    } else {
        select_upstream_version(
            requested_http10,
            upstream_url.scheme() == "https",
            websocket_version,
        )
    };

    request
        .headers_mut()
        .insert("host", upstream_authority.parse()?);

    if let Some(version) = upstream_version {
        request.extensions().insert(TargetHttpVersion(version));
    }

    if upstream_version == Some(Version::HTTP_10) {
        request.headers_mut().remove("transfer-encoding");
        request.headers_mut().remove("trailer");
    }

    force_websocket_http11(&request, &normalized.url, &state.websocket_http11_urls);

    let selected_version = request
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .map(|target| target.0);

    request = request.map(|body| Body::new(SemanticRequestBody::new(body, semantic_body)));
    let source = std::mem::replace(request.body_mut(), Body::empty());

    let replay_state = Arc::new(ReplayBodyState {
        body: std::sync::Mutex::new(Some(source)),
        started: AtomicBool::new(false),
    });

    let mut retry_request =
        (!h2c && selected_version.is_none_or(|version| version == Version::HTTP_2)).then(|| {
            request_head_clone(
                &request,
                Version::HTTP_11,
                Body::new(ReplayBody::new(replay_state.clone())),
            )
        });

    request = request.map(|_| Body::new(ReplayBody::new(replay_state.clone())));

    let response = {
        let connection = match state.upstream_clients.connect(request).await {
            Ok(connection) => connection,
            Err(error)
                if retry_request.is_some()
                    && !replay_state.started.load(Ordering::Acquire)
                    && is_protocol_negotiation_failure(&error) =>
            {
                let retry_request = retry_request.take().expect("retry request was checked");
                state.upstream_clients.connect(retry_request).await?
            }
            Err(error) => return Err(error),
        };

        let h2_without_alpn = connection_h2_without_alpn(&connection);

        match state
            .upstream_clients
            .send_with_recovery(connection, &replay_state)
            .await
        {
            Ok(response) => response,

            Err(error)
                if retry_request.is_some()
                    && !replay_state.started.load(Ordering::Acquire)
                    && (is_h2_protocol_negotiation_failure(error.as_ref(), h2_without_alpn)
                        || (h2_without_alpn && is_no_alpn_h2_cancellation(error.as_ref()))) =>
            {
                let retry_request = retry_request.expect("retry request was checked");
                let connection = state.upstream_clients.connect(retry_request).await?;
                send_connection(connection).await?
            }

            Err(error) => return Err(error),
        }
    };

    Ok((response, upstream_authority))
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{Arc, Mutex, atomic::AtomicBool},
        task::{Context, Poll, Waker},
    };

    use rama_http::{Body, Version};
    use rama_net::{
        address::{Host, HostWithPort},
        client::ConnectorTarget,
    };

    use super::{
        ReplayBody, ReplayBodyState, StreamingBody, claimed_connector_target,
        is_h2_protocol_negotiation_failure, is_protocol_negotiation_failure,
        select_upstream_version,
    };

    #[tokio::test]
    async fn h2_recovery_retries_only_unprocessed_recoverable_requests_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use rama_core::extensions::ExtensionsRef;
        use rama_http::{Request, conn::TargetHttpVersion};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A raw peer makes GOAWAY's last-stream boundary and remote reset
        // reasons explicit, without server-library shutdown heuristics.
        for (goaway, reason, last_stream, upload, always_refuse, expected) in [
            (false, 7u32, 0u32, false, false, 2),
            (true, 0, 0, false, false, 2),
            (true, 0, 1, false, false, 1),
            (false, 8, 0, false, false, 1),
            (false, 7, 0, true, false, 1),
            (false, 7, 0, false, true, 2),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed = attempts.clone();
            let server = tokio::spawn(async move {
                let mut tasks = tokio::task::JoinSet::new();
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let observed = observed.clone();
                    tasks.spawn(async move {
                        let mut preface = [0; 24];
                        socket.read_exact(&mut preface).await.unwrap();
                        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                        socket
                            .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                        loop {
                            let mut head = [0; 9];
                            if socket.read_exact(&mut head).await.is_err() {
                                break;
                            }
                            let length =
                                u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                            let mut payload = vec![0; length];
                            socket.read_exact(&mut payload).await.unwrap();
                            if head[3] != u8::from(!upload) {
                                continue;
                            }
                            let attempt = observed.fetch_add(1, Ordering::SeqCst);
                            let mut response = Vec::new();
                            if attempt == 0 || always_refuse {
                                if goaway {
                                    response.extend_from_slice(&[0, 0, 8, 7, 0, 0, 0, 0, 0]);
                                    response.extend_from_slice(&last_stream.to_be_bytes());
                                } else {
                                    response.extend_from_slice(&[0, 0, 4, 3, 0]);
                                    response.extend_from_slice(&head[5..9]);
                                }
                                response.extend_from_slice(&reason.to_be_bytes());
                            } else {
                                response.extend_from_slice(&[0, 0, 1, 1, 5]);
                                response.extend_from_slice(&head[5..9]);
                                response.push(0x88); // :status 200, END_HEADERS | END_STREAM
                            }
                            socket.write_all(&response).await.unwrap();
                            if goaway {
                                break;
                            }
                        }
                    });
                }
            });
            let clients = super::UpstreamClients::new(Arc::default()).unwrap();
            let state = Arc::new(ReplayBodyState {
                body: Mutex::new(Some(if upload {
                    Body::from("payload")
                } else {
                    Body::empty()
                })),
                started: AtomicBool::new(false),
            });
            let request = Request::builder()
                .method("POST")
                .uri(format!("http://{address}/test"))
                .body(Body::new(ReplayBody::new(state.clone())))
                .unwrap();
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
            request
                .extensions()
                .insert(super::claimed_connector_target(address));
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let connection = clients.connect(request).await.unwrap();
                clients.send_with_recovery(connection, &state).await
            })
            .await
            .expect("recovery must finish");
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                expected,
                "goaway={goaway}, reason={reason}, last={last_stream}, upload={upload}"
            );
            assert_eq!(
                result.is_ok(),
                expected == 2 && !always_refuse,
                "{result:?}"
            );
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn upstream_negotiates_and_reuses_connections_with_mtls() {
        crate::install_process_crypto_provider();

        use std::sync::atomic::{AtomicUsize, Ordering};

        use rama_core::{Service, extensions::ExtensionsRef, rt::Executor, service::service_fn};
        use rama_http::{Request, Response, body::util::BodyExt};
        use rama_tls_rustls::client::RustlsClientConfigExt;

        let identity = crate::upstream_tls::tests::TestIdentity::new();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(identity.roots.clone()),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("server verifier");
        for protocols in [
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            vec![b"h2".to_vec()],
            vec![b"http/1.1".to_vec()],
            vec![],
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("origin");
            let address = listener.local_addr().expect("origin address");
            let origin = format!("https://localhost:{}", address.port());
            let clients =
                super::UpstreamClients::new(identity.identities(&origin)).expect("clients");
            let mut config = identity.server_config();
            config.alpn_protocols = protocols.clone();
            let acceptor = rama_tls_rustls::dep::tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let attempts = Arc::new(AtomicUsize::new(0));
            let accepts = attempts.clone();
            let server = tokio::spawn(async move {
                loop {
                    let accepted = listener.accept().await.expect("accept");
                    accepts.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(stream) =
                            acceptor.accept(rama_tcp::TcpStream::from(accepted.0)).await
                        else {
                            return;
                        };
                        assert!(
                            !stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .expect("client identity")
                                .is_empty()
                        );
                        let stream = rama_tls_rustls::server::TlsStream::new(stream);
                        let service =
                            rama_http_backend::server::HttpServer::auto(Executor::default())
                                .service(service_fn(|request: Request| async move {
                                    Ok::<_, std::convert::Infallible>(Response::new(Body::from(
                                        format!("{:?}", request.version()),
                                    )))
                                }));
                        let _ = service.serve(stream).await;
                    });
                }
            });
            let expected = if protocols.contains(&b"h2".to_vec()) {
                Version::HTTP_2
            } else {
                Version::HTTP_11
            };
            for downstream in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_11] {
                let request = Request::builder()
                    .uri(format!("{origin}/test"))
                    .version(downstream)
                    .body(Body::empty())
                    .expect("request");
                rama_tls::client::TlsClientConfig::new()
                    .with_cert_verifier(verifier.clone())
                    .write_to(request.extensions());
                request
                    .extensions()
                    .insert(super::claimed_connector_target(address));
                let response = super::send_connection({
                    let connection = clients.connect(request).await.expect("connect");
                    assert!(!super::connection_h2_without_alpn(&connection));
                    connection
                })
                .await
                .expect("response");
                assert_eq!(
                    response
                        .into_body()
                        .collect()
                        .await
                        .expect("body")
                        .to_bytes(),
                    format!("{expected:?}")
                );
            }
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                1,
                "automatic pool must reuse the negotiated connection"
            );
            if protocols.len() == 2 {
                for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_10] {
                    let request = Request::builder()
                        .uri(format!("{origin}/pinned"))
                        .body(Body::empty())
                        .expect("request");
                    request
                        .extensions()
                        .insert(rama_http::conn::TargetHttpVersion(version));
                    request
                        .extensions()
                        .insert(super::claimed_connector_target(address));
                    rama_tls::client::TlsClientConfig::new()
                        .with_cert_verifier(verifier.clone())
                        .write_to(request.extensions());
                    let response = super::send_connection(
                        clients.connect(request).await.expect("pinned connect"),
                    )
                    .await
                    .expect("pinned response");
                    assert_eq!(
                        response
                            .into_body()
                            .collect()
                            .await
                            .expect("body")
                            .to_bytes(),
                        format!("{version:?}")
                    );
                }
                assert_eq!(
                    attempts.load(Ordering::SeqCst),
                    3,
                    "pinned HTTP/1 and HTTP/2 use separate pools"
                );
                let other_clients =
                    super::UpstreamClients::new(identity.identities("https://other.example"))
                        .expect("other clients");
                let request = Request::builder()
                    .uri(format!("{origin}/no-identity"))
                    .body(Body::empty())
                    .expect("request");
                request
                    .extensions()
                    .insert(super::claimed_connector_target(address));
                rama_tls::client::TlsClientConfig::new()
                    .with_cert_verifier(verifier.clone())
                    .write_to(request.extensions());
                let result = match other_clients.connect(request).await {
                    Ok(connected) => super::send_connection(connected).await.map(|_| ()),
                    Err(error) => Err(error),
                };
                drop(other_clients);
                assert!(
                    result.is_err(),
                    "another origin's credentials must not be sent"
                );
            }
            server.abort();
        }
    }

    #[test]
    fn upstream_advertises_ecdsa_before_rsa() {
        crate::install_process_crypto_provider();

        use rama_core::conversion::RamaTryFrom;

        let config = <rustls::ClientConfig as RamaTryFrom<
            _,
            rama_tls_rustls::RamaTlsRustlsCrateMarker,
        >>::rama_try_from(rama_tls::client::TlsClientConfig::default_http())
        .expect("TLS config");
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            "test.example".try_into().expect("name"),
        )
        .expect("client");
        let mut hello = Vec::new();
        client.write_tls(&mut hello).expect("ClientHello");
        let mut acceptor = rustls::server::Acceptor::default();
        acceptor
            .read_tls(&mut hello.as_slice())
            .expect("read hello");
        let accepted = acceptor
            .accept()
            .expect("valid hello")
            .expect("complete hello");
        let hello = accepted.client_hello();
        let schemes = hello.signature_schemes();
        assert!(
            schemes
                .iter()
                .position(|s| *s == rustls::SignatureScheme::ECDSA_NISTP256_SHA256)
                .expect("ECDSA")
                < schemes
                    .iter()
                    .position(|s| *s == rustls::SignatureScheme::RSA_PSS_SHA256)
                    .expect("RSA")
        );
        let suites = hello.cipher_suites();
        assert!(
            suites
                .iter()
                .position(|s| *s == rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                .expect("ECDSA suite")
                < suites
                    .iter()
                    .position(|s| *s == rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
                    .expect("RSA suite")
        );
    }

    #[test]
    fn unstarted_replay_body_is_available_for_retry() {
        let state = Arc::new(ReplayBodyState {
            body: Mutex::new(None),
            started: AtomicBool::new(false),
        });

        let mut body = ReplayBody {
            state: state.clone(),
            inner: Some(Body::empty()),
        };

        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut context),
            Poll::Ready(None)
        ));

        drop(body);
        assert!(state.body.lock().expect("replay body lock").is_some());
    }

    #[test]
    fn claimed_target_binds_concrete_destination() {
        let target = claimed_connector_target("192.0.2.10:443".parse().expect("socket address"));

        assert_eq!(
            target,
            ConnectorTarget(HostWithPort::new(
                Host::from(std::net::IpAddr::V4(
                    "192.0.2.10".parse().expect("ip address"),
                )),
                443,
            ))
        );
    }

    #[test]
    fn cleartext_http2_uses_http11_upstream() {
        assert_eq!(
            select_upstream_version(false, false, None),
            Some(Version::HTTP_11)
        );
    }

    #[test]
    fn secure_http2_negotiates_upstream() {
        assert_eq!(select_upstream_version(false, true, None), None);
    }

    #[test]
    fn websocket_http2_uses_http11_upstream() {
        assert_eq!(
            select_upstream_version(false, true, Some(Version::HTTP_11)),
            Some(Version::HTTP_11)
        );
    }

    #[test]
    fn explicit_http10_origin_uses_http10_upstream() {
        assert_eq!(
            select_upstream_version(true, true, None),
            Some(Version::HTTP_10)
        );
    }

    #[test]
    fn only_protocol_negotiation_errors_trigger_retry() {
        assert!(is_protocol_negotiation_failure(&"h2 handshake failed"));
        assert!(is_protocol_negotiation_failure(&"NoApplicationProtocol"));
        assert!(!is_protocol_negotiation_failure(&"http2 error"));
        assert!(!is_protocol_negotiation_failure(&"upstream policy denied"));

        let protocol_error: rama_http_core::h2::Error =
            rama_http_core::h2::Reason::PROTOCOL_ERROR.into();

        assert!(is_h2_protocol_negotiation_failure(&protocol_error, true));
        assert!(!is_h2_protocol_negotiation_failure(&protocol_error, false));

        let frame_size_error: rama_http_core::h2::Error =
            rama_http_core::h2::Reason::FRAME_SIZE_ERROR.into();

        assert!(is_h2_protocol_negotiation_failure(&frame_size_error, true));

        assert!(!is_h2_protocol_negotiation_failure(
            &frame_size_error,
            false
        ));

        let http11_required: rama_http_core::h2::Error =
            rama_http_core::h2::Reason::HTTP_1_1_REQUIRED.into();

        assert!(!is_h2_protocol_negotiation_failure(&http11_required, true));
        let cancel_error: rama_http_core::h2::Error = rama_http_core::h2::Reason::CANCEL.into();
        assert!(!is_h2_protocol_negotiation_failure(&cancel_error, true));
    }
}
