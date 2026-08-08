pub(crate) mod upstream;

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
        BoundedRequestBody, HttpVersion as SemanticHttpVersion, RequestTerminal, ResponseEvent,
        ResponseHead, ResponseSequence, SemanticHeaders, SemanticRequest, SemanticRequestParts,
        TerminalError, is_hop_by_hop_header, semantic_request_headers,
    },
};
use agent_sandbox_core::{EchRewrite, HttpCheckReply, HttpUrl, rewrite_ech_config};
use nix::sys::socket::{getsockopt, sockopt};
use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt},
    extensions::ExtensionsRef,
    io::Io,
    matcher::{match_fn, service::MatcherServicePair},
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, HeaderMap, HeaderValue, Request, Response, StatusCode, Version,
    body::{Frame, StreamingBody, util::BodyExt},
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
use rama_tls_rustls::server::TlsStream as RustlsTlsStream;
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
use tokio::sync::{Notify, Semaphore};
use tracing::{error, info};
use upstream::UpstreamClients;

pub const MAX_ACTIVE_CHECKS: usize = 256;
const POLICY_DENIED_BODY: &str = "blocked by agent-sandbox policy\n";

#[derive(Debug)]
struct PolicyDenied;

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

#[derive(Debug, Clone)]
struct TlsServerName(String);

impl rama_core::extensions::Extension for TlsServerName {}

/// Resolve the original destination of one accepted connection.
///
/// The production build is a plain function pointer. Only debug builds
/// pay for the `dyn Fn` indirection that hosts the test override hook.
#[cfg(not(debug_assertions))]
pub type DestinationResolver = fn(&TcpStream, u16) -> Result<SocketAddr, BoxError>;

#[cfg(debug_assertions)]
pub type DestinationResolver =
    Arc<dyn Fn(&TcpStream, u16) -> Result<SocketAddr, BoxError> + Send + Sync>;

#[cfg(debug_assertions)]
#[must_use]
pub fn destination_override(destination: SocketAddr) -> DestinationResolver {
    Arc::new(move |_stream: &TcpStream, _listen_port: u16| Ok(destination))
}

#[derive(Clone)]
struct RustlsTlsService<S> {
    config: Arc<rustls::ServerConfig>,
    inner: S,
}

impl<S, IO> Service<IO> for RustlsTlsService<S>
where
    IO: Io + Unpin + ExtensionsRef + std::fmt::Debug + Sync + 'static,
    S: Service<RustlsTlsStream<IO>, Error: Into<BoxError>>,
{
    type Error = BoxError;
    type Output = S::Output;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        // `TlsAcceptor` drives the full handshake state machine on a
        // `ServerConnection`, including ECH decryption. The
        // `LazyConfigAcceptor` path cannot be used: its config-independent
        // ClientHello pre-processing skips ECH entirely.
        let acceptor = rama_tls_rustls::dep::tokio_rustls::TlsAcceptor::from(self.config.clone());
        let stream = acceptor.accept(stream).await?;

        // Record the negotiated SNI on the connection extensions. The HTTP
        // server clones those extensions into each request's `Ingress`,
        // giving policy the verified TLS identity for authority resolution.
        // With an accepted ECH offer this is the decrypted inner name.
        let server_name = stream.get_ref().1.server_name().map(ToString::to_string);

        let stream = RustlsTlsStream::new(stream);

        if let Some(server_name) = server_name {
            stream.extensions().insert(TlsServerName(server_name));
        }

        self.inner.serve(stream).await.map_err(Into::into)
    }
}

/// Build the shared TLS configuration for one TCP listener.
///
/// The configuration is built once per listener and cloned per
/// connection with a destination-aware certificate resolver. The clone
/// shares the ticketer and session storage through their `Arc` fields,
/// so resumption state survives between handshakes.
fn build_tcp_tls_config(
    issuer: CertificateIssuer,
    ech: Option<&DownstreamEch>,
    fallback_name: String,
) -> Result<rustls::ServerConfig, BoxError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // The per-connection clone replaces this resolver with one that
    // issues certificates for the destination address, so the placeholder
    // is never used for a real handshake.
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(http3::SandboxCertResolver {
            issuer,
            fallback_name,
        }));

    // Terminate downstream ECH with the same key material the HTTP/3 leg
    // uses, so clients that fetch their configuration through the sandbox
    // DNS rewrite get a decryptable offer on both legs.
    if let Some(ech) = ech {
        tls = tls.with_ech_keys(ech.ech_keys()?).map_err(BoxError::from)?;
    }

    // h2 preferred, http/1.1 fallback: server preference order matching
    // the previous accept implementation's ALPN callback.
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Real stateless tickets for TLS 1.2 and 1.3 resumption; the rustls
    // default ticketer never produces tickets.
    tls.ticketer = rustls::crypto::ring::Ticketer::new()?;

    Ok(tls)
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

#[derive(Clone)]
pub struct ListenConfig {
    pub listen_port: u16,
    pub transparent: bool,
    pub issuer: CertificateIssuer,
    pub ech: Option<DownstreamEch>,
    pub alt_svc: Arc<AltSvcStore>,
    pub websocket_http11_urls: Arc<Vec<HttpUrl>>,
    pub http10_upstream_origins: Arc<Vec<String>>,
    pub destination_resolver: DestinationResolver,
    pub test_tls: bool,
    #[cfg(debug_assertions)]
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

fn is_doh_request(request: &Request) -> bool {
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message"))
        });

    let dns_query = request.uri().query().is_some_and(|query| {
        query
            .to_string()
            .split('&')
            .any(|part| part.starts_with("dns="))
    });

    (request.method().as_str().eq_ignore_ascii_case("POST") && content_type)
        || (request.method().as_str().eq_ignore_ascii_case("GET") && dns_query)
}

fn is_doh_response(response: &Response) -> bool {
    response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message"))
        })
}

/// Rewrite a successful `DoH` DNS response before returning it to the client.
///
/// Only `application/dns-message` responses are inspected. Unsupported content
/// encodings and DNSSEC-protected ECH answers fail closed.
async fn rewrite_doh_response(
    mut response: Response,
    ech_config_list: Option<&[u8]>,
) -> Result<Response, BoxError> {
    let Some(replacement) = ech_config_list else {
        return Ok(response);
    };

    if !is_doh_response(&response) {
        return Err(Box::new(PolicyDenied));
    }

    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|value| value != "identity")
    {
        return Err(BoxError::from_static_str(
            "cannot inspect encoded DoH response",
        ));
    }

    let body = std::mem::replace(response.body_mut(), Body::empty());
    let body = body.limited(65_535).collect().await?.to_bytes();

    let body = match rewrite_ech_config(&body, replacement)? {
        EchRewrite::Rewritten(body) => body,
        EchRewrite::Unchanged => body.to_vec(),
        EchRewrite::DnssecProtected => {
            return Err(Box::new(PolicyDenied));
        }
    };

    response.headers_mut().remove("transfer-encoding");

    response.headers_mut().insert(
        "content-length",
        HeaderValue::from_str(&body.len().to_string())?,
    );

    *response.body_mut() = Body::from(body);
    Ok(response)
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
    let semantic_version = semantic_http_version(request.version())?;

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
        source_version: semantic_version,
        target_version: semantic_version,
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

fn is_websocket_upgrade_response(response: &Response) -> bool {
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

const SEMANTIC_BODY_CHUNK_BYTES: usize = 16 * 1024;

struct SemanticRequestBody {
    inner: Body,
    semantic: BoundedRequestBody,
    terminal: bool,
}

impl SemanticRequestBody {
    fn new(inner: Body, mut semantic: BoundedRequestBody) -> Self {
        let terminal = inner.is_end_stream();

        if terminal {
            let _ = semantic.finish();
        }

        Self {
            inner,
            semantic,
            terminal,
        }
    }

    fn finish(&mut self, terminal: RequestTerminal) {
        if !self.terminal {
            let _ = self.semantic.terminate(terminal);
            self.terminal = true;
        }
    }
}

impl StreamingBody for SemanticRequestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,

            Poll::Ready(None) => {
                self.finish(RequestTerminal::Complete);
                Poll::Ready(None)
            }

            Poll::Ready(Some(Err(error))) => {
                self.finish(RequestTerminal::Error(TerminalError::Transport(
                    error.to_string().into_boxed_str(),
                )));
                Poll::Ready(Some(Err(error)))
            }

            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    for chunk in data.chunks(SEMANTIC_BODY_CHUNK_BYTES) {
                        if let Err(error) = self.semantic.push_chunk(chunk) {
                            self.finish(RequestTerminal::Error(TerminalError::ProtocolViolation(
                                error.to_string().into_boxed_str(),
                            )));
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }
                    }
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        let semantic = match semantic_headers_from_map(&trailers) {
                            Ok(semantic) => semantic,
                            Err(error) => {
                                self.finish(RequestTerminal::Error(
                                    TerminalError::ProtocolViolation(
                                        error.to_string().into_boxed_str(),
                                    ),
                                ));
                                return Poll::Ready(Some(Err(error)));
                            }
                        };

                        if let Err(error) = self.semantic.set_trailers(semantic) {
                            self.finish(RequestTerminal::Error(TerminalError::ProtocolViolation(
                                error.to_string().into_boxed_str(),
                            )));
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }

                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    } else {
                        let error = BoxError::from_static_str("HTTP body frame has unknown type");
                        self.finish(RequestTerminal::Error(TerminalError::ProtocolViolation(
                            error.to_string().into_boxed_str(),
                        )));
                        Poll::Ready(Some(Err(error)))
                    }
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> rama_http::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for SemanticRequestBody {
    fn drop(&mut self) {
        self.finish(RequestTerminal::Cancellation);
    }
}

struct SemanticResponseBody {
    inner: Body,
    sequence: ResponseSequence,
    terminal: bool,
}

impl SemanticResponseBody {
    fn new(inner: Body, head: ResponseHead) -> Result<Self, BoxError> {
        let terminal = inner.is_end_stream();
        let mut sequence = ResponseSequence::new();
        sequence.push(ResponseEvent::Final(head))?;

        if terminal {
            sequence.push(ResponseEvent::Complete)?;
        }

        Ok(Self {
            inner,
            sequence,
            terminal,
        })
    }

    fn finish(&mut self, event: ResponseEvent) {
        if !self.terminal {
            let _ = self.sequence.push(event);
            self.terminal = true;
        }
    }
}

impl StreamingBody for SemanticResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,

            Poll::Ready(None) => {
                self.finish(ResponseEvent::Complete);
                Poll::Ready(None)
            }

            Poll::Ready(Some(Err(error))) => {
                self.finish(ResponseEvent::Error(TerminalError::Transport(
                    error.to_string().into_boxed_str(),
                )));
                Poll::Ready(Some(Err(error)))
            }

            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    if let Err(error) = self.sequence.push(ResponseEvent::BodyChunk(data.to_vec()))
                    {
                        self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                            error.to_string().into_boxed_str(),
                        )));
                        return Poll::Ready(Some(Err(Box::new(error))));
                    }

                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        let semantic = match semantic_headers_from_map(&trailers) {
                            Ok(semantic) => semantic,
                            Err(error) => {
                                self.finish(ResponseEvent::Error(
                                    TerminalError::ProtocolViolation(
                                        error.to_string().into_boxed_str(),
                                    ),
                                ));
                                return Poll::Ready(Some(Err(error)));
                            }
                        };

                        if let Err(error) = self.sequence.push(ResponseEvent::Trailers(semantic)) {
                            self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                                error.to_string().into_boxed_str(),
                            )));
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }

                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    } else {
                        let error = BoxError::from_static_str("HTTP body frame has unknown type");
                        self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                            error.to_string().into_boxed_str(),
                        )));
                        Poll::Ready(Some(Err(error)))
                    }
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> rama_http::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for SemanticResponseBody {
    fn drop(&mut self) {
        self.finish(ResponseEvent::Cancelled);
    }
}

fn semantic_headers_from_map(headers: &HeaderMap) -> Result<SemanticHeaders, BoxError> {
    let mut semantic = SemanticHeaders::new();

    for (name, value) in headers {
        semantic.try_push(name.as_str(), value.as_bytes())?;
    }

    Ok(semantic)
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect()
}

fn semantic_response_headers(headers: &HeaderMap) -> Result<SemanticHeaders, BoxError> {
    let connection_tokens = connection_tokens(headers);
    let mut semantic = SemanticHeaders::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name.as_str(), &connection_tokens) {
            continue;
        }

        semantic.try_push(name.as_str(), value.as_bytes())?;
    }

    Ok(semantic)
}

fn bridge_response_body(mut response: Response) -> Result<Response, BoxError> {
    if response.status().as_u16() < 200 || is_websocket_upgrade_response(&response) {
        return Ok(response);
    }

    let headers = semantic_response_headers(response.headers())?;
    let head = ResponseHead::final_head(response.status().as_u16(), headers)?;
    let body = std::mem::replace(response.body_mut(), Body::empty());
    *response.body_mut() = Body::new(SemanticResponseBody::new(body, head)?);
    Ok(response)
}

fn semantic_http_version(version: Version) -> Result<SemanticHttpVersion, BoxError> {
    match version {
        Version::HTTP_10 => Ok(SemanticHttpVersion::Http10),
        Version::HTTP_11 => Ok(SemanticHttpVersion::Http11),
        Version::HTTP_2 => Ok(SemanticHttpVersion::Http2),
        Version::HTTP_3 => Ok(SemanticHttpVersion::Http3),
        Version::HTTP_09 => Err(BoxError::from_static_str("HTTP/0.9 is not supported")),
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
    use super::{
        Body, BoundedRequestBody, FlowState, HttpUrl, MAX_ACTIVE_CHECKS, POLICY_DENIED_BODY,
        Request, ResponseVersionAdaptCtx, SemanticRequestBody, StatusCode, TargetHttpVersion,
        TlsServerName, Version, adapt_http10_response, adapt_response_version,
        blocked_http_request, bridge_response_body, canonical_http10_origin, check_http_policy,
        force_websocket_http11, is_doh_request, is_websocket_upgrade_request,
        is_websocket_upgrade_response, policy_denied_response, request_head_clone,
        semantic_response_headers,
    };
    use crate::{
        alt_svc::AltSvcStore,
        policy::{FlowClaim, PolicySession, test_support::FakePolicy},
        semantic::semantic_request_headers,
        tcp_backend::upstream::UpstreamClients,
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
    use std::{
        convert::Infallible,
        net::{IpAddr, SocketAddr},
        num::NonZeroU16,
        path::PathBuf,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
        sync::{Notify, Semaphore},
        time::{Duration, timeout},
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
    fn semantic_headers_preserve_opaque_values() {
        let mut request = Request::builder()
            .uri("http://localhost/")
            .body(Body::empty())
            .expect("request");

        request.headers_mut().insert(
            "x-opaque",
            HeaderValue::from_bytes(&[0x80, b'a']).expect("opaque header"),
        );

        let headers = semantic_request_headers(&http::HeaderMap::from_iter(
            request.headers().iter().map(|(name, value)| {
                (
                    http::HeaderName::from_bytes(name.as_str().as_bytes())
                        .expect("rama header names are valid"),
                    http::HeaderValue::from_bytes(value.as_bytes())
                        .expect("rama header values are valid"),
                )
            }),
        ))
        .expect("semantic headers");
        assert_eq!(headers.as_slice()[0].value(), &[0x80, b'a']);
    }

    #[test]
    fn semantic_headers_filter_hop_by_hop_fields_and_connection_tokens() {
        let request = Request::builder()
            .header("connection", "x-remove")
            .header("x-remove", "one")
            .header("keep-alive", "timeout=5")
            .header("x-end-to-end", "yes")
            .body(Body::empty())
            .expect("request");

        let headers = semantic_request_headers(&http::HeaderMap::from_iter(
            request.headers().iter().map(|(name, value)| {
                (
                    http::HeaderName::from_bytes(name.as_str().as_bytes())
                        .expect("rama header names are valid"),
                    http::HeaderValue::from_bytes(value.as_bytes())
                        .expect("rama header values are valid"),
                )
            }),
        ))
        .expect("semantic headers");

        assert!(
            headers.as_slice().iter().all(|header| {
                !["connection", "x-remove", "keep-alive"].contains(&header.name())
            })
        );

        assert!(
            headers
                .as_slice()
                .iter()
                .any(|header| header.name() == "x-end-to-end")
        );
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

    #[test]
    fn filters_hop_by_hop_response_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("x-private"));
        headers.insert("x-private", HeaderValue::from_static("hidden"));
        headers.insert("keep-alive", HeaderValue::from_static("hidden"));
        headers.insert("x-visible", HeaderValue::from_static("visible"));
        let semantic = semantic_response_headers(&headers).expect("response headers");

        assert!(
            semantic
                .as_slice()
                .iter()
                .any(|header| { header.name() == "x-visible" && header.value() == b"visible" })
        );

        assert!(
            !semantic
                .as_slice()
                .iter()
                .any(|header| header.name() == "x-private")
        );
    }

    #[tokio::test]
    async fn empty_semantic_body_finishes_without_frames() {
        let mut body = Body::new(SemanticRequestBody::new(
            Body::empty(),
            BoundedRequestBody::empty(),
        ));

        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn semantic_body_bridges_data_and_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-request-trailer", HeaderValue::from_static("present"));
        let source = Body::from("request-body").with_trailer_headers(trailers);

        let mut body = Body::new(SemanticRequestBody::new(
            source,
            BoundedRequestBody::empty(),
        ));

        let data = body
            .frame()
            .await
            .expect("data frame")
            .expect("data frame result")
            .into_data()
            .expect("data");

        assert_eq!(data, "request-body");

        let trailers = body
            .frame()
            .await
            .expect("trailer frame")
            .expect("trailer frame result")
            .into_trailers()
            .expect("trailers");

        assert_eq!(
            trailers
                .get("x-request-trailer")
                .expect("request trailer")
                .to_str()
                .expect("trailer value"),
            "present"
        );

        assert!(body.frame().await.is_none());
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

    #[tokio::test]
    async fn semantic_response_bridge_preserves_data_and_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-response-trailer", HeaderValue::from_static("present"));

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("response-body").with_trailer_headers(trailers))
            .expect("response");

        let mut response = bridge_response_body(response).expect("bridge response");

        let data = response
            .body_mut()
            .frame()
            .await
            .expect("data frame")
            .expect("data frame result")
            .into_data()
            .expect("data");

        assert_eq!(data, "response-body");

        let trailers = response
            .body_mut()
            .frame()
            .await
            .expect("trailer frame")
            .expect("trailer frame result")
            .into_trailers()
            .expect("trailers");

        assert_eq!(
            trailers
                .get("x-response-trailer")
                .expect("response trailer")
                .to_str()
                .expect("trailer value"),
            "present"
        );

        assert!(response.body_mut().frame().await.is_none());
    }

    #[test]
    fn detects_doh_post_and_get_requests() {
        let post = Request::builder()
            .method("POST")
            .header("content-type", "application/dns-message")
            .body(Body::empty())
            .expect("test request");

        assert!(is_doh_request(&post));

        let get = Request::builder()
            .method("GET")
            .uri("/dns-query?dns=abc")
            .body(Body::empty())
            .expect("test request");

        assert!(is_doh_request(&get));
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

    /// Drive a rustls client and server handshake through an in-memory pipe.
    fn drive_handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) {
        let mut to_server = Vec::new();
        let mut to_client = Vec::new();

        for _ in 0..64 {
            while client.wants_write() {
                client.write_tls(&mut to_server).expect("client writes");
            }
            while server.wants_write() {
                server.write_tls(&mut to_client).expect("server writes");
            }
            if client.wants_read() && !to_client.is_empty() {
                let read = client
                    .read_tls(&mut to_client.as_slice())
                    .expect("client reads");
                to_client.drain(..read);
                client.process_new_packets().expect("client processes");
            }
            if server.wants_read() && !to_server.is_empty() {
                let read = server
                    .read_tls(&mut to_server.as_slice())
                    .expect("server reads");
                to_server.drain(..read);
                server.process_new_packets().expect("server processes");
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
        }

        panic!("TLS handshake did not finish");
    }

    #[test]
    fn downstream_ech_handshake_decrypts_inner_hello() {
        // Generate the same key material the proxy persists in its ECH state.
        let dir = tempfile::tempdir().expect("temp ECH state");
        let state = crate::ech_state::load_or_generate(dir.path()).expect("ECH state");

        // A server that terminates ECH with that state, issuing certificates
        // for the inner (real) server name.
        let inner_name = "ech-test.example";
        let certified = rcgen::generate_simple_self_signed(vec![inner_name.to_owned()])
            .expect("test certificate");
        let certificate = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let private_key =
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .expect("test key");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let keys = crate::http3::hpke::ECH_SUPPORTED_SUITES
            .iter()
            .map(|hpke| {
                rustls::server::ech::EchKeys::new(
                    rustls::pki_types::EchConfigListBytes::from(state.config_list.as_slice()),
                    &state.private_key,
                    *hpke,
                )
                .expect("ECH keys")
            })
            .collect();

        let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .expect("server certificate")
            .with_ech_keys(keys)
            .expect("server ECH keys");
        let mut server =
            rustls::ServerConnection::new(Arc::new(server_config)).expect("server connection");

        // A client that fetched the proxy's ECH configuration (the same bytes
        // the sandbox DNS rewrite distributes) and connects to the inner name.
        let config = rustls::client::EchConfig::new(
            rustls::pki_types::EchConfigListBytes::from(state.config_list.as_slice()),
            crate::http3::hpke::ECH_SUPPORTED_SUITES,
        )
        .expect("client ECH configuration");

        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_ech(rustls::client::EchMode::Enable(config))
            .expect("client ECH mode")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            rustls::pki_types::ServerName::try_from(inner_name).expect("server name"),
        )
        .expect("client connection");

        drive_handshake(&mut client, &mut server);

        assert_eq!(client.ech_status(), rustls::client::EchStatus::Accepted);
        assert!(!server.is_handshaking());
        assert_eq!(
            server.server_name().map(ToString::to_string),
            Some(inner_name.to_owned())
        );
    }

    /// Accepts any server certificate; the test asserts ECH behaviour, not
    /// certificate verification.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            certificate: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                certificate,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                certificate,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
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
