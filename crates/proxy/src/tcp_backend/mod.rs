//! TCP (HTTP/1.x and HTTP/2) transparent proxy backend.
//!
//! Accepts downstream TCP connections, claims the intercepted flow with
//! policyd, and relays approved requests through isolated upstream
//! connections.
mod doh;
mod semantic;
mod tls;
pub(crate) mod upstream;

#[cfg(debug_assertions)]
use std::path::{Path, PathBuf};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use agent_sandbox_core::{HttpCheckReply, HttpUrl};
use doh::{is_doh_request, rewrite_doh_response};
use nix::sys::socket::{getsockopt, sockopt};
use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt},
    extensions::ExtensionsRef,
    matcher::{match_fn, service::MatcherServicePair},
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version,
    body::{Frame, StreamingBody},
    conn::TargetHttpVersion,
    io::upgrade::OnUpgrade,
    layer::{
        upgrade::mitm::HttpUpgradeMitmRelay,
        version_adapter::{ResponseVersionAdaptCtx, adapt_response_version},
    },
};
use rama_http_backend::server::HttpServer;
use rama_net::{
    address::SocketAddress,
    http::server::HttpPeekRouter,
    proxy::IoForwardService,
    socket::{SocketOptions, opts::Domain},
    stream::Socket,
};
use rama_tcp::{TcpStream, server::TcpListener};
use rama_tls::server::TlsPeekRouter;
pub(crate) use semantic::SemanticRequestBody;
use semantic::{bridge_response_body, semantic_http_version};
use tls::{RustlsTlsService, TlsServerName, build_tcp_tls_config};
use tokio::sync::{Notify, Semaphore};
use tracing::{error, info};
use upstream::UpstreamClients;

use crate::{
    alt_svc::{AltSvcStore, preserve_response_alt_svc},
    cert::CertificateIssuer,
    ech_state::DownstreamEch,
    http3,
    policy::{
        FlowClaim, PolicySession, authority_for_policy, flow_key, normalize_authority,
        reconcile_authorities,
    },
    semantic::{
        BoundedRequestBody, SemanticRequest, SemanticRequestParts, semantic_request_headers,
    },
};

/// The maximum number of concurrent in-flight policy checks per proxy.
pub const MAX_ACTIVE_CHECKS: usize = 256;
pub(crate) const POLICY_DENIED_BODY: &str = "blocked by agent-sandbox policy\n";

#[derive(Debug)]
pub(crate) struct PolicyDenied;

impl Display for PolicyDenied {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(POLICY_DENIED_BODY)
    }
}

impl Error for PolicyDenied {}

/// Canonicalise an upstream origin for HTTP/1.0 relays.
///
/// Rejects origins that cannot be mapped onto a stable authority: URLs with
/// a path, credentials, a query string, or a fragment.
///
/// # Errors
///
/// Returns a `BoxError` when the value is not a valid URL or carries any
/// component that the HTTP/1.0 upgrade check cannot represent.
pub fn canonical_http10_origin(value: &str) -> Result<String, BoxError> {
    let parsed = url::Url::parse(value)?;

    let raw_path = value
        .find("://")
        .and_then(|scheme_end| {
            let authority_start = scheme_end + 3;

            value[authority_start..].find('/').map(|path_start| {
                value[authority_start + path_start..]
                    .split(['?', '#'])
                    .next()
                    .unwrap_or_default()
            })
        })
        .unwrap_or_default();

    if !matches!(raw_path, "" | "/") {
        return Err(BoxError::from(format!(
            "HTTP/1.0 upstream origin must not include a path: {value:?}"
        )));
    }

    let origin = HttpUrl::parse(value)
        .map_err(|error| BoxError::from(format!("invalid HTTP/1.0 upstream origin: {error}")))?;

    if origin.path().is_none_or(|path| path.as_str() != "/") {
        return Err(BoxError::from(format!(
            "HTTP/1.0 upstream origin must not include a path: {value:?}"
        )));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BoxError::from(format!(
            "HTTP/1.0 upstream origin must not include userinfo: {value:?}"
        )));
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(BoxError::from(format!(
            "HTTP/1.0 upstream origin must not include a query or fragment: {value:?}"
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| BoxError::from_static_str("HTTP/1.0 upstream origin has no host"))?;

    if host.ends_with('.') {
        return Err(BoxError::from(format!(
            "HTTP/1.0 upstream origin must not use a trailing dot: {value:?}"
        )));
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| BoxError::from_static_str("HTTP/1.0 upstream origin has no port"))?;

    Ok(format!(
        "{}://{}",
        parsed.scheme(),
        authority_for_policy(host, port)
    ))
}

/// Canonicalise the configured upstream origins for HTTP/1.0 relays.
///
/// # Errors
///
/// Returns the first `BoxError` produced by [`canonical_http10_origin`].
pub fn canonical_http10_origins(values: &[String]) -> Result<Vec<String>, BoxError> {
    values
        .iter()
        .map(String::as_str)
        .map(canonical_http10_origin)
        .collect()
}

#[derive(Clone)]
pub(crate) struct FlowState {
    destination: SocketAddr,
    tls: bool,
    active_checks: Arc<Semaphore>,
    policy: Arc<PolicySession>,
    claim: FlowClaim,
    ech: Option<DownstreamEch>,
    alt_svc: Arc<AltSvcStore>,
    websocket_http11_urls: Arc<Vec<HttpUrl>>,
    http10_upstream_origins: Arc<Vec<String>>,
    upstream_clients: Arc<UpstreamClients>,
}

impl FlowState {
    /// The fallback port for port-less authorities: the destination port,
    /// or the recorded origin port when the destination is a validated
    /// `Alt-Svc` alternative endpoint.
    #[must_use]
    fn authority_fallback_port(&self) -> u16 {
        self.alt_svc
            .origin_port_for(self.destination.ip(), self.destination.port())
            .unwrap_or_else(|| self.destination.port())
    }
}

/// Resolve the original destination of one accepted connection.
///
/// The production build is a plain function pointer. Only debug builds
/// pay for the `dyn Fn` indirection that hosts the test override hook.
#[cfg(not(debug_assertions))]
pub type DestinationResolver = fn(&TcpStream, u16) -> Result<SocketAddr, BoxError>;

/// Debug-build destination resolver: a heap closure hosting the test hook.
#[cfg(debug_assertions)]
pub type DestinationResolver =
    Arc<dyn Fn(&TcpStream, u16) -> Result<SocketAddr, BoxError> + Send + Sync>;

/// Test-only override that always resolves the destination to one value.
///
/// Debug builds use this to route intercepted connections to a fixture
/// regardless of the kernel's original destination.
#[cfg(debug_assertions)]
#[must_use]
pub fn destination_override(destination: SocketAddr) -> DestinationResolver {
    Arc::new(move |_stream: &TcpStream, _listen_port: u16| Ok(destination))
}

/// Run the TCP listener backend until shutdown.
///
/// Binds the IPv4 and IPv6 listeners, builds the per-connection service,
/// and serves until a termination signal fires. The actually bound TCP
/// port is written to the harness ports file before serving starts when
/// requested.
///
/// # Errors
///
/// Returns a `BoxError` when a listener cannot bind, the service cannot be
/// built, or the policy session cannot be marked ready.
pub async fn run_tcp_listener(
    config: ListenConfig,
    executor: Executor,
    policy: Arc<PolicySession>,
    shutdown: Arc<Notify>,
    active_checks: Arc<Semaphore>,
) -> Result<(), BoxError> {
    let transparent = config.transparent;

    let v4 = bind_listener(
        Domain::IPv4,
        config.listen_port,
        executor.clone(),
        transparent,
    )
    .await?;

    let listen_port = v4.local_addr()?.port();

    #[cfg(debug_assertions)]
    if let Some((path, http3_ports)) = &config.write_bound_ports {
        write_bound_ports_file(path, listen_port, http3_ports)?;
    }

    let service = build_listener_service(
        executor.clone(),
        policy.clone(),
        config,
        shutdown.clone(),
        active_checks.clone(),
        listen_port,
    )?;

    run_listeners(
        service,
        policy,
        shutdown,
        executor,
        v4,
        listen_port,
        transparent,
    )
    .await
}

/// Write the actually bound listener ports for the harness to read back.
#[cfg(debug_assertions)]
fn write_bound_ports_file(
    path: &Path,
    listen_port: u16,
    http3_ports: &[u16],
) -> Result<(), BoxError> {
    use std::fmt::Write as _;

    let mut content = format!("tcp {listen_port}\n");

    for port in http3_ports {
        writeln!(content, "http3 {port}")
            .map_err(|error| BoxError::from(format!("write bound proxy ports: {error}")))?;
    }

    std::fs::write(path, content).map_err(|error| {
        BoxError::from(format!(
            "write bound proxy ports to {}: {error}",
            path.display()
        ))
    })?;

    Ok(())
}

async fn run_listeners(
    service: impl Service<TcpStream, Output = (), Error = BoxError> + Clone,
    policy: Arc<PolicySession>,
    shutdown: Arc<Notify>,
    executor: Executor,
    v4: TcpListener,
    listen_port: u16,
    transparent: bool,
) -> Result<(), BoxError> {
    let v6 = bind_listener(Domain::IPv6, listen_port, executor, transparent).await?;
    policy.mark_ready()?;
    info!(port = listen_port, "transparent HTTP proxy listening");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let listeners = async {
        tokio::join!(v4.serve(service.clone()), v6.serve(service));
    };

    tokio::select! {
        () = listeners => {}
        result = tokio::signal::ctrl_c() => {
            result?;
            shutdown.notify_waiters();
        }
        _ = terminate.recv() => shutdown.notify_waiters(),
    }

    shutdown.notify_waiters();
    Ok(())
}

async fn bind_listener(
    domain: Domain,
    port: u16,
    executor: Executor,
    transparent: bool,
) -> Result<TcpListener, BoxError> {
    let address = match domain {
        Domain::IPv4 => SocketAddress::default_ipv4(port),
        Domain::IPv6 => SocketAddress::default_ipv6(port),
        Domain::Unix => {
            return Err(BoxError::from_static_str(
                "unsupported listener address family",
            ));
        }
    };

    let options = SocketOptions {
        address: Some(address),
        ip_transparent: (transparent && matches!(domain, Domain::IPv4)).then_some(true),
        ip_transparent_v6: (transparent && matches!(domain, Domain::IPv6)).then_some(true),
        only_v6: matches!(domain, Domain::IPv6).then_some(true),
        ..SocketOptions::default_tcp()
    };

    let socket = options.try_build_socket(domain)?;
    socket.listen(32_768)?;
    TcpListener::bind_socket(socket, executor).await
}

fn policy_denied_response() -> Response {
    let mut response = Response::new(Body::from(POLICY_DENIED_BODY));
    *response.status_mut() = StatusCode::FORBIDDEN;

    response.headers_mut().insert(
        "x-agent-sandbox-policy",
        HeaderValue::from_static("blocked"),
    );

    response
}

/// Configuration for the TCP listener backend.
#[derive(Clone)]
pub struct ListenConfig {
    /// The TCP port to listen on (0 requests an ephemeral port).
    pub listen_port: u16,
    /// Whether the listener uses transparent (`IP_TRANSPARENT`) interception.
    pub transparent: bool,
    /// The certificate issuer serving downstream SNI names.
    pub issuer: CertificateIssuer,
    /// Optional ECH key material shared with the HTTP/3 leg.
    pub ech: Option<DownstreamEch>,
    /// The Alt-Svc store shared with the HTTP/3 leg.
    pub alt_svc: Arc<AltSvcStore>,
    /// Upstream URL patterns forced to HTTP/1.x WebSocket upgrades.
    pub websocket_http11_urls: Arc<Vec<HttpUrl>>,
    /// Upstream origins canonicalised for HTTP/1.0 relays.
    pub http10_upstream_origins: Arc<Vec<String>>,
    /// Resolves the original destination of each accepted connection.
    pub destination_resolver: DestinationResolver,
    /// Test-only: force TLS termination regardless of destination port.
    pub test_tls: bool,

    #[cfg(debug_assertions)]
    /// Test-only: write the bound listener ports for the harness.
    pub write_bound_ports: Option<(PathBuf, Vec<u16>)>,
}

/// Build the per-flow upstream client pool, releasing the flow claim when
/// connector construction fails so policyd does not hold the claim until
/// the session ends.
async fn build_upstream_clients(
    policy: &Arc<PolicySession>,
    claim: &FlowClaim,
) -> Result<Arc<UpstreamClients>, BoxError> {
    match UpstreamClients::new() {
        Ok(clients) => Ok(Arc::new(clients)),

        Err(error) => {
            let _ = policy.release(claim).await;
            Err(error)
        }
    }
}

fn build_listener_service(
    executor: Executor,
    policy: Arc<PolicySession>,
    listener_config: ListenConfig,
    shutdown: Arc<Notify>,
    active_checks: Arc<Semaphore>,
    listen_port: u16,
) -> Result<impl Service<TcpStream, Output = (), Error = BoxError> + Clone, BoxError> {
    let tls_config = Arc::new(build_tcp_tls_config(
        listener_config.issuer.clone(),
        listener_config.ech.as_ref(),
        Ipv4Addr::LOCALHOST.to_string(),
    )?);

    Ok(service_fn(move |stream: TcpStream| {
        let executor = executor.clone();
        let policy = policy.clone();
        let alt_svc = listener_config.alt_svc.clone();
        let websocket_http11_urls = listener_config.websocket_http11_urls.clone();
        let http10_upstream_origins = listener_config.http10_upstream_origins.clone();
        let shutdown = shutdown.clone();

        #[cfg(debug_assertions)]
        let destination_resolver = listener_config.destination_resolver.clone();

        #[cfg(not(debug_assertions))]
        let destination_resolver = listener_config.destination_resolver;

        let test_tls = listener_config.test_tls;
        let active_checks = active_checks.clone();
        let tls_config = tls_config.clone();
        let issuer = listener_config.issuer.clone();
        let ech = listener_config.ech.clone();

        async move {
            let peer: SocketAddr = stream.peer_addr()?.into();
            let destination = destination_resolver(&stream, listen_port)?;
            let destination_ip = destination.ip();
            let source = peer;
            info!(%peer, %source, %destination, "accepted transparent proxy stream");
            let flow = flow_key(source, destination)?;
            let claim = policy.claim(flow).await?;

            let state = {
                let upstream_clients = build_upstream_clients(&policy, &claim).await?;

                FlowState {
                    destination,
                    tls: test_tls || matches!(destination.port(), 443 | 8443),
                    active_checks: active_checks.clone(),
                    policy: policy.clone(),
                    claim: claim.clone(),
                    ech: ech.clone(),
                    alt_svc: alt_svc.clone(),
                    websocket_http11_urls: websocket_http11_urls.clone(),
                    http10_upstream_origins,
                    upstream_clients,
                }
            };

            let request_service = service_fn(move |request: Request| {
                let state = state.clone();
                let shutdown = shutdown.clone();

                async move {
                    let tls_server_name = request
                        .extensions()
                        .ingress()
                        .and_then(|ingress| ingress.get_ref::<TlsServerName>())
                        .map(|name| name.0.clone());

                    if let Some(server_name) = tls_server_name {
                        request.extensions().insert(TlsServerName(server_name));
                    }

                    match proxy_request(request, state, shutdown).await {
                        Ok(response) => Ok(response),

                        Err(error) if error.downcast_ref::<PolicyDenied>().is_some() => {
                            info!(%error, "proxy request denied by policy");
                            Ok(policy_denied_response())
                        }

                        Err(error) => {
                            error!(%error, "proxy request failed");
                            let mut response = Response::new(Body::empty());
                            *response.status_mut() = StatusCode::BAD_GATEWAY;
                            Ok(response)
                        }
                    }
                }
            });

            let upgrade_matcher = MatcherServicePair::new(
                match_fn(is_websocket_upgrade_request),
                MatcherServicePair::new(
                    match_fn(is_websocket_upgrade_response),
                    IoForwardService::new(executor.clone()),
                ),
            );

            let request_service =
                HttpUpgradeMitmRelay::new(executor.clone(), upgrade_matcher, request_service);

            let mut http_server = HttpServer::auto(executor.clone());
            http_server.h2_mut().set_enable_connect_protocol();
            let http = http_server.service(request_service);
            let fallback_http = HttpPeekRouter::new_http1(http.clone());

            // Clone the shared listener configuration per connection so the
            // certificate resolver can fall back to the destination address
            // for clients that send no SNI. The clone shares the ticketer
            // and session storage through their `Arc` fields, so resumption
            // state survives between connections.
            let mut tls_config = tls_config.as_ref().clone();

            tls_config.cert_resolver = Arc::new(http3::SandboxCertResolver {
                issuer: issuer.clone(),
                fallback_name: destination_ip.to_string(),
            });

            let tls = RustlsTlsService {
                config: Arc::new(tls_config),
                inner: http,
            };

            let service = TlsPeekRouter::new(tls).with_fallback(fallback_http);
            let result = service.serve(stream).await;
            let release_result = policy.release(&claim).await;
            release_result?;
            result
        }
    }))
}

/// Resolve the original destination of a transparent connection.
///
/// Returns the socket's local address for connections that arrived on a
/// different port, otherwise the original destination of the transparent
/// connection.
///
/// # Errors
///
/// Returns a `BoxError` when the local address cannot be read or the
/// transparent connection has no original destination.
pub fn destination_for_stream(
    stream: &TcpStream,
    listen_port: u16,
) -> Result<SocketAddr, BoxError> {
    let local: SocketAddr = stream.local_addr()?.into();

    if local.port() != listen_port {
        return Ok(local);
    }

    original_destination(stream).ok_or_else(|| {
        BoxError::from_static_str("transparent proxy connection has no original destination")
    })
}

fn original_destination(stream: &TcpStream) -> Option<SocketAddr> {
    if let Ok(address) = getsockopt(stream, sockopt::OriginalDst) {
        return Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
            u16::from_be(address.sin_port),
        )));
    }

    getsockopt(stream, sockopt::Ip6tOriginalDst)
        .ok()
        .map(|address| {
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                0,
                0,
            ))
        })
}

async fn check_http_policy(
    request: &Request,
    state: &FlowState,
    shutdown: &Arc<Notify>,
) -> Result<(SemanticRequest, HttpCheckReply, String, String), BoxError> {
    let header_host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let uri_host = request.uri().authority().map(|value| value.to_string());

    if let (Some(header_host), Some(uri_host)) = (&header_host, &uri_host) {
        reconcile_authorities(&[header_host, uri_host], state.authority_fallback_port())
            .map_err(|error| error.into_boxed("HTTP request has conflicting origin authorities"))?;
    }

    let tls_host = request
        .extensions()
        .get_ref::<TlsServerName>()
        .map(|name| name.0.clone());

    if let Some(tls_host) = tls_host.as_deref()
        && let Some(request_host) = header_host.as_deref().or(uri_host.as_deref())
    {
        reconcile_authorities(&[tls_host, request_host], state.authority_fallback_port())
            .map_err(|error| error.into_boxed("HTTP request conflicts with TLS server identity"))?;
    }

    let host = header_host
        .or(uri_host)
        .or(tls_host)
        .or_else(|| {
            (request.version() == Version::HTTP_10).then(|| {
                authority_for_policy(
                    &state.destination.ip().to_string(),
                    state.destination.port(),
                )
            })
        })
        .ok_or_else(|| BoxError::from_static_str("HTTP request has no authority"))?;

    let scheme = if state.tls { "https" } else { "http" };
    let authority = normalize_authority(&host, state.authority_fallback_port())?;
    let target = request_target(request);

    let path = target
        .split_once('?')
        .map_or(target.as_str(), |(path, _)| path)
        .to_owned();

    let raw_query = request.uri().query().map(|query| query.to_string());
    semantic_http_version(request.version())?;

    let semantic_request = SemanticRequest::from_parts(SemanticRequestParts {
        method: request.method().as_str(),
        scheme,
        authority: &authority,
        path: &path,
        raw_query: raw_query.as_deref(),
        headers: semantic_request_headers(&http::HeaderMap::from_iter(
            request.headers().iter().map(|(name, value)| {
                (
                    http::HeaderName::from_bytes(name.as_str().as_bytes())
                        .expect("rama header names are valid"),
                    http::HeaderValue::from_bytes(value.as_bytes())
                        .expect("rama header values are valid"),
                )
            }),
        ))?,
        session: None,
        body: BoundedRequestBody::empty(),
    })?;

    let check = state
        .policy
        .check_http_cancellable(
            state.claim.attribution_token.clone(),
            semantic_request.policy_request()?,
            &state.active_checks,
            shutdown,
        )
        .await?;

    Ok((semantic_request, check, authority, path))
}

async fn proxy_request(
    request: Request,
    state: FlowState,
    shutdown: Arc<Notify>,
) -> Result<Response, BoxError> {
    let websocket = is_websocket_upgrade_request(&request);
    let downstream_version = request.version();

    if blocked_http_request(&request) {
        return Err(Box::new(PolicyDenied));
    }

    let response_context = ResponseVersionAdaptCtx::from_request(&request);
    let doh = is_doh_request(&request);

    let (semantic_request, check, authority, path) =
        check_http_policy(&request, &state, &shutdown).await?;

    if !check.ok || !check.allowed {
        info!(
            %authority, %path, method = %request.method().as_str(),
            ?websocket, version = ?request.version(),
            "HTTP request denied by policy"
        );

        return Err(Box::new(PolicyDenied));
    }

    let normalized = check.request.ok_or_else(|| {
        BoxError::from_static_str("policy allowed request without normalized target")
    })?;

    let original_uri = request.uri().to_string();

    let (mut response, upstream_authority) = upstream::send_upstream_request(
        request,
        &state,
        semantic_request,
        &normalized,
        downstream_version,
        websocket,
    )
    .await?;

    let response_status = response.status();
    let response_version = response.version();

    if websocket {
        info!(host = %upstream_authority, ?response_status, ?response_version, "received WebSocket upgrade response");
    }

    adapt_response_version(&mut response, &response_context)?;

    if downstream_version == Version::HTTP_10 {
        response = adapt_http10_response(response);
    }

    preserve_response_alt_svc(&mut response, &state.alt_svc, &authority).await;

    if doh {
        response = rewrite_doh_response(
            response,
            state.ech.as_ref().map(|ech| ech.config_list.as_slice()),
        )
        .await?;
    }

    response = bridge_response_body(response)?;

    info!(
        %original_uri,
        host = %upstream_authority,
        destination = %state.destination,
        ?websocket,
        ?response_status,
        ?response_version,
        "proxied HTTP request"
    );

    Ok(response)
}

fn request_head_clone(request: &Request, version: Version, body: Body) -> Request {
    let mut clone = Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone())
        .version(version)
        .body(body)
        .expect("request head is already valid");

    *clone.headers_mut() = request.headers().clone();
    clone.extensions().extend(request.extensions());
    clone.extensions().insert(TargetHttpVersion(version));
    clone
}

fn is_protocol_negotiation_failure(error: &dyn Display) -> bool {
    let error = error.to_string().to_ascii_lowercase();

    [
        "targethttpversion incompatible",
        "http/2 handshake",
        "h2 handshake",
        "no application protocol",
        "no_application_protocol",
        "noapplicationprotocol",
        "unsupported http version",
    ]
    .iter()
    .any(|marker| error.contains(marker))
}

fn is_h2_protocol_negotiation_failure(
    error: &(dyn Error + 'static),
    h2_without_alpn: bool,
) -> bool {
    let mut source = Some(error);

    while let Some(error) = source {
        if let Some(h2_error) = error.downcast_ref::<rama_http_core::h2::Error>() {
            return match h2_error.reason() {
                Some(
                    rama_http_core::h2::Reason::PROTOCOL_ERROR
                    | rama_http_core::h2::Reason::FRAME_SIZE_ERROR,
                ) => h2_without_alpn && !h2_error.is_remote(),
                Some(rama_http_core::h2::Reason::HTTP_1_1_REQUIRED) => {
                    !h2_error.is_library() && h2_error.is_remote()
                }
                _ => false,
            };
        }

        source = error.source();
    }

    false
}

fn adapt_http10_response(mut response: Response) -> Response {
    response.headers_mut().remove("content-length");
    response.headers_mut().remove("transfer-encoding");
    response.headers_mut().remove("trailer");

    response
        .headers_mut()
        .insert("connection", HeaderValue::from_static("close"));

    let body = std::mem::replace(response.body_mut(), Body::empty());
    *response.body_mut() = Body::new(Http10ResponseBody::new(body));
    response
}

struct Http10ResponseBody {
    inner: Body,
    terminal: bool,
}

impl Http10ResponseBody {
    const fn new(inner: Body) -> Self {
        Self {
            inner,
            terminal: false,
        }
    }
}

impl StreamingBody for Http10ResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,

                Poll::Ready(None) => {
                    self.terminal = true;
                    return Poll::Ready(None);
                }

                Poll::Ready(Some(Err(error))) => {
                    self.terminal = true;
                    return Poll::Ready(Some(Err(error)));
                }

                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(Frame::data(data)))),
                    Err(frame) => {
                        if frame.into_trailers().is_ok() {
                            continue;
                        }

                        self.terminal = true;
                        return Poll::Ready(Some(Err(BoxError::from_static_str(
                            "HTTP body frame has unknown type",
                        ))));
                    }
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> rama_http::body::SizeHint {
        rama_http::body::SizeHint::default()
    }
}

fn is_websocket_upgrade_request(request: &Request) -> bool {
    if request.method().as_str().eq_ignore_ascii_case("CONNECT") {
        return request
            .extensions()
            .get_ref::<rama_http::proto::h2::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"));
    }

    request.method().as_str().eq_ignore_ascii_case("GET")
        && request
            .headers()
            .get("upgrade")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get("connection")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        && request.headers().get("sec-websocket-key").is_some()
}

fn force_websocket_http11(request: &Request, target: &HttpUrl, patterns: &[HttpUrl]) {
    // RequestVersionAdapter translates H2 WebSocket CONNECT into H1 GET/Upgrade.
    if is_websocket_upgrade_request(request)
        && patterns.iter().any(|pattern| pattern.matches(target))
    {
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
    }
}

pub(crate) fn is_websocket_upgrade_response(response: &Response) -> bool {
    matches!(
        response.status(),
        StatusCode::SWITCHING_PROTOCOLS | StatusCode::OK
    ) && response.extensions().get_ref::<OnUpgrade>().is_some()
}

fn request_target(request: &Request) -> String {
    let path = request.uri().path_or_root().to_string();
    let query = request.uri().query_or_empty();

    if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    }
}

fn blocked_http_request(request: &Request) -> bool {
    if request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("h2c"))
        })
    {
        return true;
    }

    if is_websocket_upgrade_request(request) {
        return false;
    }

    if ["CONNECT", "MASQUE", "WEBTRANSPORT"]
        .iter()
        .any(|method| request.method().as_str().eq_ignore_ascii_case(method))
    {
        return true;
    }

    ["protocol", ":protocol", "upgrade"].iter().any(|name| {
        request
            .headers()
            .get(*name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("webtransport"))
    })
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        net::{IpAddr, SocketAddr},
        num::NonZeroU16,
        path::PathBuf,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use agent_sandbox_core::{
        AttributionToken, FlowProtocol, NetworkFlowKey, NormalizedPolicyHost, ProxyConnectionId,
    };
    use rama_core::{
        Service,
        bytes::Bytes,
        extensions::{Extensions, ExtensionsRef},
        matcher::{match_fn, service::MatcherServicePair},
        rt::Executor,
        service::service_fn,
    };
    use rama_http::{
        HeaderMap, HeaderValue, Response,
        body::util::BodyExt,
        io::upgrade::{Upgraded, pending},
        layer::{upgrade::mitm::HttpUpgradeMitmRelay, version_adapter::adapt_request_version},
    };
    use rama_net::proxy::IoForwardService;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
        sync::{Notify, Semaphore},
        time::{Duration, timeout},
    };

    use super::{
        Body, FlowState, HttpUrl, MAX_ACTIVE_CHECKS, POLICY_DENIED_BODY, Request,
        ResponseVersionAdaptCtx, StatusCode, TargetHttpVersion, TlsServerName, Version,
        adapt_http10_response, adapt_response_version, blocked_http_request,
        canonical_http10_origin, check_http_policy, force_websocket_http11,
        is_websocket_upgrade_request, is_websocket_upgrade_response, policy_denied_response,
        request_head_clone,
    };
    use crate::{
        alt_svc::AltSvcStore,
        policy::{FlowClaim, PolicySession, test_support::FakePolicy},
        tcp_backend::upstream::UpstreamClients,
    };

    struct TestIo {
        stream: DuplexStream,
        extensions: Extensions,
    }

    impl TestIo {
        fn new(stream: DuplexStream) -> Self {
            Self {
                stream,
                extensions: Extensions::new(),
            }
        }
    }

    impl ExtensionsRef for TestIo {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(context)
        }
    }

    #[test]
    fn canonical_http10_origin_normalizes_defaults() {
        assert_eq!(
            canonical_http10_origin("http://example.com").expect("origin"),
            "http://example.com:80"
        );

        assert_eq!(
            canonical_http10_origin("https://example.com/").expect("origin"),
            "https://example.com:443"
        );

        assert!(canonical_http10_origin("http://example.com *").is_err());
        assert!(canonical_http10_origin("http://example.com/path").is_err());
        assert!(canonical_http10_origin("http://example.com/foo/..").is_err());
        assert!(canonical_http10_origin("http://example.com.").is_err());
        assert!(canonical_http10_origin("http://example.com/?query").is_err());
        assert!(canonical_http10_origin("http://example.com/#fragment").is_err());
        assert!(canonical_http10_origin("http://user:pass@example.com").is_err());
    }

    #[test]
    fn blocks_tunnel_methods_case_insensitively() {
        for method in ["connect", "MASQUE", "WebTransport"] {
            let request = Request::builder()
                .method(method)
                .body(Body::empty())
                .expect("test request");

            assert!(blocked_http_request(&request));
        }
    }

    #[test]
    fn blocks_webtransport_protocol_headers() {
        let request = Request::builder()
            .header("upgrade", "WebTransport")
            .body(Body::empty())
            .expect("test request");

        assert!(blocked_http_request(&request));
    }

    #[test]
    fn request_head_clone_preserves_h2_protocol() {
        let request = Request::builder()
            .method("CONNECT")
            .body(Body::empty())
            .expect("test request");

        request
            .extensions()
            .insert(rama_http::proto::h2::ext::Protocol::from_static(
                "websocket",
            ));

        let clone = request_head_clone(&request, Version::HTTP_11, Body::empty());

        assert_eq!(
            clone
                .extensions()
                .get_ref::<rama_http::proto::h2::ext::Protocol>()
                .map(rama_http::proto::h2::ext::Protocol::as_str),
            Some("websocket")
        );

        assert_eq!(
            clone
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0),
            Some(Version::HTTP_11)
        );
    }

    #[test]
    fn allows_websocket_upgrade_requests() {
        let request = Request::builder()
            .method("GET")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .expect("test request");

        assert!(is_websocket_upgrade_request(&request));
        assert!(!blocked_http_request(&request));

        let live_pattern =
            HttpUrl::parse_pattern("https://api.openai.com/v1/live").expect("live URL pattern");

        let live_target = HttpUrl::parse("https://api.openai.com/v1/live/rtc").expect("live URL");

        let ordinary_target =
            HttpUrl::parse("https://api.openai.com/v1/responses").expect("ordinary URL");

        let patterns = [live_pattern];
        force_websocket_http11(&request, &live_target, &[]);

        assert!(
            request
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .is_none()
        );

        force_websocket_http11(&request, &ordinary_target, &patterns);

        assert!(
            request
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .is_none()
        );

        let ordinary = Request::builder()
            .method("GET")
            .body(Body::empty())
            .expect("test request");

        force_websocket_http11(&ordinary, &live_target, &patterns);

        assert!(
            ordinary
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .is_none()
        );

        let mut extended_connect = Request::builder()
            .method("CONNECT")
            .uri("https://api.openai.com/v1/live/rtc")
            .body(Body::empty())
            .expect("test request");

        extended_connect
            .extensions()
            .insert(rama_http::proto::h2::ext::Protocol::from_static(
                "websocket",
            ));

        *extended_connect.version_mut() = Version::HTTP_2;
        assert!(is_websocket_upgrade_request(&extended_connect));
        assert!(!blocked_http_request(&extended_connect));
        force_websocket_http11(&extended_connect, &live_target, &patterns);

        assert_eq!(
            extended_connect
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0),
            Some(Version::HTTP_11)
        );

        adapt_request_version(&mut extended_connect, Version::HTTP_11).expect("H1 adaptation");
        assert_eq!(extended_connect.method().as_str(), "GET");

        assert_eq!(
            extended_connect
                .headers()
                .get("upgrade")
                .and_then(|value| value.to_str().ok()),
            Some("websocket")
        );

        assert_eq!(
            extended_connect
                .headers()
                .get("connection")
                .and_then(|value| value.to_str().ok()),
            Some("upgrade")
        );
    }

    #[test]
    fn rejects_h2c_upgrade_requests() {
        let request = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("connection", "Upgrade, HTTP2-Settings")
            .header("upgrade", "h2c")
            .header("http2-settings", "AAMAAABkAAQAAP__")
            .body(Body::empty())
            .expect("test request");

        assert!(blocked_http_request(&request));
    }

    #[test]
    fn adapts_websocket_response_for_http2() {
        let mut request = Request::builder()
            .method("CONNECT")
            .body(Body::empty())
            .expect("test request");

        *request.version_mut() = Version::HTTP_2;

        request
            .extensions()
            .insert(rama_http::proto::h2::ext::Protocol::from_static(
                "websocket",
            ));

        let context = ResponseVersionAdaptCtx::from_request(&request);
        let (_, on_upgrade) = pending();
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *response.version_mut() = Version::HTTP_11;
        response.extensions().insert(on_upgrade);
        adapt_response_version(&mut response, &context).expect("adapt websocket response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_2);
    }

    #[tokio::test]
    async fn relays_websocket_upgrade_bytes() {
        let (ingress_pending, ingress_on_upgrade) = pending();
        let (egress_pending, egress_on_upgrade) = pending();

        let inner = service_fn(move |_request: Request| {
            let on_upgrade = egress_on_upgrade.clone();

            async move {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                response.extensions().insert(on_upgrade);
                Ok::<_, Infallible>(response)
            }
        });

        let matcher = MatcherServicePair::new(
            match_fn(|request: &Request| is_websocket_upgrade_request(request)),
            MatcherServicePair::new(
                match_fn(is_websocket_upgrade_response),
                IoForwardService::new(Executor::default()),
            ),
        );

        let relay = HttpUpgradeMitmRelay::new(Executor::default(), matcher, inner);

        let request = Request::builder()
            .method("GET")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .expect("test request");

        request.extensions().insert(ingress_on_upgrade);
        let response = relay.serve(request).await.expect("upgrade response");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let (mut ingress_peer, ingress_io) = duplex(1024);
        let (mut egress_peer, egress_io) = duplex(1024);
        ingress_pending.fulfill(Upgraded::new(TestIo::new(ingress_io), Bytes::new()));
        egress_pending.fulfill(Upgraded::new(TestIo::new(egress_io), Bytes::new()));

        ingress_peer
            .write_all(b"ping")
            .await
            .expect("write ingress");

        let mut received = [0; 4];

        timeout(
            Duration::from_secs(1),
            egress_peer.read_exact(&mut received),
        )
        .await
        .expect("ingress relay timeout")
        .expect("read relayed ingress bytes");

        assert_eq!(&received, b"ping");
        egress_peer.write_all(b"pong").await.expect("write egress");
        let mut received = [0; 4];

        timeout(
            Duration::from_secs(1),
            ingress_peer.read_exact(&mut received),
        )
        .await
        .expect("egress relay timeout")
        .expect("read relayed egress bytes");

        assert_eq!(&received, b"pong");
    }

    #[tokio::test]
    async fn http10_adaptation_removes_framing_and_drops_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trailer", HeaderValue::from_static("dropped"));

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-length", "11")
            .header("transfer-encoding", "chunked")
            .header("trailer", "x-trailer")
            .body(Body::from("http10-body").with_trailer_headers(trailers))
            .expect("response");

        let mut response = adapt_http10_response(response);
        assert!(response.headers().get("content-length").is_none());
        assert!(response.headers().get("transfer-encoding").is_none());
        assert!(response.headers().get("trailer").is_none());

        assert_eq!(
            response
                .headers()
                .get("connection")
                .and_then(|value| value.to_str().ok()),
            Some("close")
        );

        let data = response
            .body_mut()
            .frame()
            .await
            .expect("data frame")
            .expect("data frame result")
            .into_data()
            .expect("data");

        assert_eq!(data, "http10-body");
        assert!(response.body_mut().frame().await.is_none());
    }

    #[test]
    fn policy_denial_response_is_explicit() {
        let response = policy_denied_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        assert_eq!(
            response
                .headers()
                .get("x-agent-sandbox-policy")
                .and_then(|value| value.to_str().ok()),
            Some("blocked")
        );

        assert_eq!(POLICY_DENIED_BODY, "blocked by agent-sandbox policy\n");
    }

    async fn flow_state(
        policy_socket: PathBuf,
    ) -> Result<FlowState, Box<dyn std::error::Error + Send + Sync>> {
        let policy = Arc::new(PolicySession::open(policy_socket, Duration::from_secs(2)).await?);

        Ok(FlowState {
            destination: SocketAddr::from(([127, 0, 0, 1], 8080)),
            tls: false,
            active_checks: Arc::new(Semaphore::new(MAX_ACTIVE_CHECKS)),
            policy,
            claim: FlowClaim {
                attribution_token: AttributionToken::from_bytes([2; 32]),
                connection_id: ProxyConnectionId::new(),
                flow: NetworkFlowKey::new(
                    FlowProtocol::Tcp,
                    IpAddr::from([127, 0, 0, 1]),
                    NonZeroU16::new(12345).expect("source port"),
                    IpAddr::from([127, 0, 0, 1]),
                    NonZeroU16::new(8080).expect("destination port"),
                ),
                policy_host: NormalizedPolicyHost::parse("localhost").expect("policy host"),
            },
            ech: None,
            alt_svc: Arc::new(AltSvcStore::new(Vec::new())),
            websocket_http11_urls: Arc::new(Vec::new()),
            http10_upstream_origins: Arc::new(Vec::new()),
            upstream_clients: Arc::new(UpstreamClients::new()?),
        })
    }

    #[tokio::test]
    async fn check_http_policy_rejects_conflicting_origin_authorities()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fake = FakePolicy::start();
        let state = flow_state(fake.socket.clone()).await?;
        let shutdown = Arc::new(Notify::new());

        let request = Request::builder()
            .uri("http://other.test/")
            .header("host", "example.test")
            .body(Body::empty())
            .expect("request");

        let error = check_http_policy(&request, &state, &shutdown)
            .await
            .expect_err("conflicting authorities are rejected");

        drop(state);

        assert_eq!(
            error.to_string(),
            "HTTP request has conflicting origin authorities"
        );

        Ok(())
    }

    #[tokio::test]
    async fn check_http_policy_rejects_tls_server_name_conflict()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fake = FakePolicy::start();
        let state = flow_state(fake.socket.clone()).await?;
        let shutdown = Arc::new(Notify::new());

        let request = Request::builder()
            .uri("http://example.test/")
            .header("host", "example.test")
            .extension(TlsServerName("other.test".to_owned()))
            .body(Body::empty())
            .expect("request");

        let error = check_http_policy(&request, &state, &shutdown)
            .await
            .expect_err("TLS identity conflict is rejected");

        drop(state);

        assert_eq!(
            error.to_string(),
            "HTTP request conflicts with TLS server identity"
        );

        Ok(())
    }

    #[tokio::test]
    async fn check_http_policy_rejects_request_without_authority()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fake = FakePolicy::start();
        let state = flow_state(fake.socket.clone()).await?;
        let shutdown = Arc::new(Notify::new());

        let request = Request::builder()
            .version(Version::HTTP_11)
            .uri("/")
            .body(Body::empty())
            .expect("request");

        let error = check_http_policy(&request, &state, &shutdown)
            .await
            .expect_err("missing authority is rejected");

        drop(state);
        assert_eq!(error.to_string(), "HTTP request has no authority");
        Ok(())
    }

    #[tokio::test]
    async fn check_http_policy_falls_back_to_destination_for_http10()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fake = FakePolicy::start();
        let state = flow_state(fake.socket.clone()).await?;
        let shutdown = Arc::new(Notify::new());
        fake.release_checks.notify_one();

        let request = Request::builder()
            .version(Version::HTTP_10)
            .uri("/")
            .body(Body::empty())
            .expect("request");

        let (semantic, check, authority, path) =
            check_http_policy(&request, &state, &shutdown).await?;

        assert!(check.ok);
        assert!(check.allowed);
        assert_eq!(authority, "127.0.0.1:8080");
        assert_eq!(path, "/");
        assert_eq!(semantic.authority(), "127.0.0.1:8080");
        Ok(())
    }
}
