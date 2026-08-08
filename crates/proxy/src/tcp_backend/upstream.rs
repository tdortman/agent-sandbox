use super::{
    FlowState, SemanticRequestBody, canonical_http10_origin, force_websocket_http11,
    is_h2_protocol_negotiation_failure, is_protocol_negotiation_failure, request_head_clone,
};
use crate::semantic::SemanticRequest;
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
use rama_net::client::{EstablishedClientConnection, pool::MultiplexedConnection};
use rama_tcp::client::service::TcpConnector;
use rama_tls::client::{NegotiatedTlsParameters, TlsClientConfig};
use rama_tls_rustls::client::TlsConnector;
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

/// The connection type the pooled upstream client establishes.
type UpstreamConnection = EstablishedClientConnection<
    BindBodyToConn<MultiplexedConnection<HttpClientService<Body>, BasicHttpConId>>,
    Request,
>;

/// Report whether an HTTP/2-targeted connection negotiated no ALPN protocol.
fn connection_h2_without_alpn(connection: &UpstreamConnection) -> bool {
    connection
        .conn
        .extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .is_some_and(|params| params.application_layer_protocol.is_none())
}

/// Send one request over an established upstream connection.
async fn send_connection(connection: UpstreamConnection) -> Result<Response, BoxError> {
    connection.conn.serve(connection.input).await
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
    client: BoxService<Request, UpstreamConnection, BoxError>,
}

impl UpstreamClients {
    pub fn new() -> Result<Self, BoxError> {
        Ok(Self {
            client: build_upstream_client()?,
        })
    }
}

fn select_upstream_version(
    downstream_version: Version,
    requested_http10: bool,
    secure: bool,
    websocket_http11: bool,
) -> Version {
    if requested_http10 {
        Version::HTTP_10
    } else if downstream_version == Version::HTTP_2 && secure && !websocket_http11 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
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
#[derive(Clone, Debug)]
struct TlsAlpnConnector<S> {
    inner: S,
}

impl<S> TlsAlpnConnector<S> {
    const fn new(inner: S) -> Self {
        Self { inner }
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
        }

        Ok(established)
    }
}

fn build_upstream_client() -> Result<BoxService<Request, UpstreamConnection, BoxError>, BoxError> {
    let connector = DnsConnectorLayer::new().into_layer(TcpConnector::default());
    let connector = TlsConnector::auto(connector).with_base_config(TlsClientConfig::default_http());
    let connector = TlsAlpnConnector::new(connector);

    let connector = rama_http::layer::version_adapter::RequestVersionAdapter::new(connector)
        .with_default_version(Version::HTTP_11);

    let client = HttpConnector::new(connector, Executor::default());
    let client = HttpPooledConnectorConfig::default().build_connector(client)?;
    Ok(BoxService::new(client))
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

    let websocket_http11 = websocket
        && state
            .websocket_http11_urls
            .iter()
            .any(|pattern| pattern.matches(&normalized.url));

    let semantic_body = semantic_request.into_body();

    let requested_http10 = downstream_version == Version::HTTP_10
        || state.http10_upstream_origins.contains(&upstream_origin);

    let upstream_version = select_upstream_version(
        downstream_version,
        requested_http10,
        upstream_url.scheme() == "https",
        websocket_http11,
    );

    let uri = format!("{}://{upstream_authority}{target}", upstream_url.scheme());
    *request.uri_mut() = uri.parse()?;

    request
        .headers_mut()
        .insert("host", upstream_authority.parse()?);

    request
        .extensions()
        .insert(TargetHttpVersion(upstream_version));

    if upstream_version == Version::HTTP_10 {
        request.headers_mut().remove("transfer-encoding");
        request.headers_mut().remove("trailer");
    }

    force_websocket_http11(&request, &normalized.url, &state.websocket_http11_urls);

    let selected_version = request
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .map_or(upstream_version, |target| target.0);

    // Pooled connections skip the version adapter, so the request version
    // must already match an in-class target. Cross-class translations (h2
    // extended CONNECT to HTTP/1.1) are left to the adapter.
    if request.version() <= Version::HTTP_11 && selected_version <= Version::HTTP_11 {
        *request.version_mut() = selected_version;
    }

    request = request.map(|body| Body::new(SemanticRequestBody::new(body, semantic_body)));
    let source = std::mem::replace(request.body_mut(), Body::empty());

    let replay_state = Arc::new(ReplayBodyState {
        body: std::sync::Mutex::new(Some(source)),
        started: AtomicBool::new(false),
    });

    let mut retry_request = (selected_version == Version::HTTP_2).then(|| {
        request_head_clone(
            &request,
            Version::HTTP_11,
            Body::new(ReplayBody::new(replay_state.clone())),
        )
    });

    request = request.map(|_| Body::new(ReplayBody::new(replay_state.clone())));

    let response = {
        let connection = match state.upstream_clients.client.serve(request).await {
            Ok(connection) => connection,
            Err(error)
                if retry_request.is_some()
                    && !replay_state.started.load(Ordering::Acquire)
                    && is_protocol_negotiation_failure(&error) =>
            {
                let retry_request = retry_request.take().expect("retry request was checked");
                state.upstream_clients.client.serve(retry_request).await?
            }
            Err(error) => return Err(error),
        };

        let h2_without_alpn = connection_h2_without_alpn(&connection);

        match send_connection(connection).await {
            Ok(response) => response,

            Err(error)
                if retry_request.is_some()
                    && !replay_state.started.load(Ordering::Acquire)
                    && (is_h2_protocol_negotiation_failure(error.as_ref(), h2_without_alpn)
                        || (h2_without_alpn && is_no_alpn_h2_cancellation(error.as_ref()))) =>
            {
                let retry_request = retry_request.expect("retry request was checked");
                let connection = state.upstream_clients.client.serve(retry_request).await?;
                send_connection(connection).await?
            }

            Err(error) => return Err(error),
        }
    };

    Ok((response, upstream_authority))
}

#[cfg(test)]
mod tests {
    use super::{
        ReplayBody, ReplayBodyState, StreamingBody, is_h2_protocol_negotiation_failure,
        is_protocol_negotiation_failure, select_upstream_version,
    };
    use rama_http::{Body, Version};
    use std::{
        pin::Pin,
        sync::{Arc, Mutex, atomic::AtomicBool},
        task::{Context, Poll, Waker},
    };

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
    fn cleartext_http2_uses_http11_upstream() {
        assert_eq!(
            select_upstream_version(Version::HTTP_2, false, false, false),
            Version::HTTP_11
        );
    }

    #[test]
    fn secure_http2_preserves_http2_upstream() {
        assert_eq!(
            select_upstream_version(Version::HTTP_2, false, true, false),
            Version::HTTP_2
        );
    }

    #[test]
    fn websocket_http2_uses_http11_upstream() {
        assert_eq!(
            select_upstream_version(Version::HTTP_2, false, true, true),
            Version::HTTP_11
        );
    }

    #[test]
    fn explicit_http10_origin_uses_http10_upstream() {
        assert_eq!(
            select_upstream_version(Version::HTTP_11, true, true, false),
            Version::HTTP_10
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
