use crate::{
    FlowState, SemanticRequestBody, canonical_http10_origin, force_websocket_http11,
    is_h2_protocol_negotiation_failure, is_protocol_negotiation_failure, request_head_clone,
};
use agent_sandbox_core::HttpRequest;
use agent_sandbox_proxy::semantic::SemanticRequest;
use async_trait::async_trait;
use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt},
    extensions::ExtensionsRef,
    rt::Executor,
};
use rama_dns::client::DnsConnectorLayer;
use rama_http::{
    Body, Request, Response, StreamingBody, Version, body::Frame, conn::TargetHttpVersion,
};
use rama_http_backend::client::{HttpConnector, HttpPooledConnectorConfig};
use rama_net::client::EstablishedClientConnection;
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

#[async_trait]
trait UpstreamConnection: Send {
    fn h2_without_alpn(&self) -> bool;

    async fn send(self: Box<Self>) -> Result<Response, BoxError>;
}

#[async_trait]
impl<C> UpstreamConnection for EstablishedClientConnection<C, Request>
where
    C: Service<Request, Output = Response, Error: Into<BoxError>> + ExtensionsRef + Send + 'static,
{
    fn h2_without_alpn(&self) -> bool {
        self.conn
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .is_some_and(|params| params.application_layer_protocol.is_none())
    }

    async fn send(self: Box<Self>) -> Result<Response, BoxError> {
        let connection = *self;

        connection
            .conn
            .serve(connection.input)
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
trait UpstreamClient: Send + Sync {
    async fn connect(&self, request: Request) -> Result<Box<dyn UpstreamConnection>, BoxError>;
}

#[async_trait]
impl<S, C> UpstreamClient for Arc<S>
where
    S: Service<Request, Output = EstablishedClientConnection<C, Request>> + Send + Sync + 'static,
    S::Error: Into<BoxError>,
    C: Service<Request, Output = Response, Error: Into<BoxError>> + ExtensionsRef + Send + 'static,
{
    async fn connect(&self, request: Request) -> Result<Box<dyn UpstreamConnection>, BoxError> {
        self.serve(request)
            .await
            .map(|connection| Box::new(connection) as Box<dyn UpstreamConnection>)
            .map_err(Into::into)
    }
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
    http10: Arc<dyn UpstreamClient>,
    http11: Arc<dyn UpstreamClient>,
    http2: Arc<dyn UpstreamClient>,
}

impl UpstreamClients {
    pub fn new() -> Result<Self, BoxError> {
        Ok(Self {
            http10: build_upstream_client()?,
            http11: build_upstream_client()?,
            http2: build_upstream_client()?,
        })
    }

    fn for_version(&self, version: Version) -> &dyn UpstreamClient {
        match version {
            Version::HTTP_10 => self.http10.as_ref(),
            Version::HTTP_2 => self.http2.as_ref(),
            _ => self.http11.as_ref(),
        }
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

fn build_upstream_client() -> Result<Arc<dyn UpstreamClient>, BoxError> {
    let connector = DnsConnectorLayer::new().into_layer(TcpConnector::default());
    let connector = TlsConnector::auto(connector).with_base_config(TlsClientConfig::default_http());

    let connector = rama_http::layer::version_adapter::RequestVersionAdapter::new(connector)
        .with_default_version(Version::HTTP_11);

    let client = HttpConnector::new(connector, Executor::default());
    let client = Arc::new(HttpPooledConnectorConfig::default().build_connector(client)?);
    Ok(Arc::new(client))
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

    let upstream_authority = crate::authority_for_policy(upstream_host, upstream_port);

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
    let client = state.upstream_clients.for_version(selected_version);
    let connection = match client.connect(request).await {
        Ok(connection) => connection,
        Err(error)
            if retry_request.is_some()
                && !replay_state.started.load(Ordering::Acquire)
                && is_protocol_negotiation_failure(&error) =>
        {
            let retry_request = retry_request.take().expect("retry request was checked");
            state
                .upstream_clients
                .for_version(Version::HTTP_11)
                .connect(retry_request)
                .await?
        }
        Err(error) => return Err(error),
    };
    let h2_without_alpn = connection.h2_without_alpn();

    let response = match connection.send().await {
        Ok(response) => response,
        Err(error)
            if retry_request.is_some()
                && !replay_state.started.load(Ordering::Acquire)
                && (is_h2_protocol_negotiation_failure(error.as_ref(), h2_without_alpn)
                    || (h2_without_alpn && is_no_alpn_h2_cancellation(error.as_ref()))) =>
        {
            let retry_request = retry_request.expect("retry request was checked");
            let connection = state
                .upstream_clients
                .for_version(Version::HTTP_11)
                .connect(retry_request)
                .await?;
            connection.send().await?
        }
        Err(error) => return Err(error),
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
