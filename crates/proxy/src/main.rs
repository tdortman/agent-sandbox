mod ech_state;
pub(crate) mod upstream;
use agent_sandbox_core::{EchRewrite, HttpCheckReply, HttpUrl, ProxyRequestId, rewrite_ech_config};
use agent_sandbox_proxy::{
    alt_svc::AltSvcStore,
    cert::CertificateIssuer,
    http3::{self, Http3Config},
    policy::{
        FlowClaim, PendingPolicyCheck, PolicySession, authority_for_policy, flow_key,
        normalize_authority,
    },
    semantic::{
        BoundedRequestBody, HttpVersion as SemanticHttpVersion, RequestTerminal, ResponseEvent,
        ResponseHead, ResponseSequence, SemanticHeaders, SemanticRequest, TerminalError,
        is_hop_by_hop_header,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Parser;
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
use rama_tls_boring::{
    TlsStream,
    core::{
        hpke::HpkeKey,
        ssl::{AlpnError, NameType, SelectCertError, SslAcceptor, SslEchKeys, SslMethod, SslRef},
        x509::X509,
    },
};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};
use tracing::{error, info};
use upstream::UpstreamClients;

const MAX_ACTIVE_CHECKS: usize = 256;
const POLICY_DENIED_BODY: &str = "blocked by agent-sandbox policy\n";

#[derive(Debug)]
struct PolicyDenied;

fn select_alpn<'a>(_: &mut SslRef, offered: &'a [u8]) -> Result<&'a [u8], AlpnError> {
    let mut offset = 0;
    let mut http11 = None;

    while offset < offered.len() {
        let length = offered[offset] as usize;
        let end = offset.saturating_add(1 + length);

        if end > offered.len() {
            return Err(AlpnError::ALERT_FATAL);
        }

        let protocol = &offered[offset + 1..end];

        if protocol == b"h2" {
            return Ok(protocol);
        }

        if protocol == b"http/1.1" {
            http11 = Some(protocol);
        }

        offset = end;
    }

    http11.ok_or(AlpnError::NOACK)
}

impl Display for PolicyDenied {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(POLICY_DENIED_BODY)
    }
}

impl Error for PolicyDenied {}

/// Select the client-facing ECH configuration and verify explicit overrides.
///
/// An override is accepted only when it is byte-for-byte identical to the
/// persisted configuration whose private key the proxy will use.
fn select_ech_config_list(
    encoded: Option<&str>,
    state: Option<&ech_state::EchState>,
) -> Result<Option<Arc<Vec<u8>>>, BoxError> {
    let Some(encoded) = encoded else {
        return Ok(state.map(|state| Arc::new(state.config_list.clone())));
    };

    let config_list = STANDARD.decode(encoded)?;

    let Some(state) = state else {
        return Err(BoxError::from_static_str(
            "ECH config override requires ECH state",
        ));
    };

    if config_list != state.config_list {
        return Err(BoxError::from_static_str(
            "ECH config override does not match ECH private key",
        ));
    }

    Ok(Some(Arc::new(config_list)))
}

#[derive(Debug, Parser)]
#[command(name = "agent-sandbox-proxy")]
struct Args {
    #[arg(
        long,
        env = "AGENT_SANDBOX_PROXY_SOCKET",
        default_value = "/run/agent-sandbox/proxy-policy.sock"
    )]
    policy_socket: PathBuf,

    #[arg(long, env = "AGENT_SANDBOX_PROXY_CA_CERT")]
    ca_certificate: Option<PathBuf>,

    #[arg(long, env = "AGENT_SANDBOX_PROXY_CA_KEY")]
    ca_private_key: Option<PathBuf>,

    #[arg(long, env = "AGENT_SANDBOX_PROXY_HTTP3")]
    http3: bool,

    #[arg(long, default_value_t = 443)]
    http3_listen_port: u16,

    /// Additional UDP ports whose intercepted QUIC traffic terminates at
    /// the proxy, for validated `Alt-Svc` alternative endpoints.
    #[arg(long = "http3-alt-port", value_name = "PORT")]
    http3_alt_ports: Vec<u16>,

    #[arg(long)]
    init_ech_state_only: bool,

    #[arg(long, default_value_t = 18080)]
    listen_port: u16,

    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    test_destination: Option<SocketAddr>,

    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    test_ech_dns: Option<SocketAddr>,

    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    test_tls: bool,

    #[arg(long, default_value_t = 305_000)]
    policy_timeout_ms: u64,

    #[arg(long = "websocket-http11-url", value_name = "URL")]
    websocket_http11_urls: Vec<String>,

    #[arg(long = "http10-upstream-origin", value_name = "ORIGIN")]
    http10_upstream_origins: Vec<String>,

    #[arg(long, env = "AGENT_SANDBOX_ECH_CONFIG_LIST")]
    ech_config_list: Option<String>,

    #[arg(
        long,
        env = "AGENT_SANDBOX_ECH_STATE_DIR",
        default_value = ech_state::DEFAULT_ECH_STATE_DIR
    )]
    ech_state_dir: Option<PathBuf>,
}

fn canonical_http10_origin(value: &str) -> Result<String, BoxError> {
    let origin = HttpUrl::parse(value)
        .map_err(|error| BoxError::from(format!("invalid HTTP/1.0 upstream origin: {error}")))?;

    if origin.path().is_none_or(|path| path.as_str() != "/") {
        return Err(BoxError::from(format!(
            "HTTP/1.0 upstream origin must not include a path: {value:?}"
        )));
    }

    let parsed = url::Url::parse(value)?;

    let host = parsed
        .host_str()
        .ok_or_else(|| BoxError::from_static_str("HTTP/1.0 upstream origin has no host"))?;

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| BoxError::from_static_str("HTTP/1.0 upstream origin has no port"))?;

    Ok(format!(
        "{}://{}",
        parsed.scheme(),
        authority_for_policy(host, port)
    ))
}

fn canonical_http10_origins(values: &[String]) -> Result<Vec<String>, BoxError> {
    values
        .iter()
        .map(String::as_str)
        .map(canonical_http10_origin)
        .collect()
}

#[derive(Clone)]
struct FlowState {
    destination: SocketAddr,
    tls: bool,
    active_checks: Arc<Semaphore>,
    policy: Arc<PolicySession>,
    claim: FlowClaim,
    ech_config_list: Option<Arc<Vec<u8>>>,
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

type DestinationResolver =
    Arc<dyn Fn(&TcpStream, u16) -> Result<SocketAddr, BoxError> + Send + Sync>;

#[cfg(debug_assertions)]
fn destination_override(destination: SocketAddr) -> DestinationResolver {
    Arc::new(move |_stream: &TcpStream, _listen_port: u16| Ok(destination))
}

#[derive(Clone)]
struct BoringTlsService<S> {
    issuer: CertificateIssuer,
    ech_config_list: Option<Arc<Vec<u8>>>,
    ech_private_key: Option<[u8; 32]>,
    fallback_name: String,
    inner: S,
}

impl<S, IO> Service<IO> for BoringTlsService<S>
where
    IO: Io + Unpin + ExtensionsRef + std::fmt::Debug + Sync + 'static,
    S: Service<TlsStream<IO>, Error: Into<BoxError>>,
{
    type Error = BoxError;
    type Output = S::Output;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        acceptor.set_grease_enabled(true);
        acceptor.set_alpn_select_callback(select_alpn);

        if let (Some(config_list), Some(private_key)) =
            (&self.ech_config_list, self.ech_private_key)
        {
            let mut keys = SslEchKeys::builder()?;

            let config = config_list
                .get(2..)
                .ok_or_else(|| BoxError::from_static_str("invalid ECH config list"))?;

            keys.add_key(true, config, HpkeKey::dhkem_p256_sha256(&private_key)?)?;
            acceptor.set_ech_keys(&keys.build())?;
        }

        let issuer = self.issuer.clone();
        let fallback_name = self.fallback_name.clone();

        acceptor.set_select_certificate_callback(move |mut client_hello| {
            let server_name = client_hello
                .servername(NameType::HOST_NAME)
                .unwrap_or(&fallback_name);

            let issued_certificate = issuer
                .issue(server_name)
                .map_err(|_| SelectCertError::ERROR)?;

            let ssl = client_hello.ssl_mut();

            let leaf = X509::from_der(issued_certificate.certificate_chain[0].as_ref())
                .map_err(|_| SelectCertError::ERROR)?;

            ssl.set_certificate(leaf.as_ref())
                .map_err(|_| SelectCertError::ERROR)?;

            for certificate in issued_certificate.certificate_chain.iter().skip(1) {
                let certificate =
                    X509::from_der(certificate.as_ref()).map_err(|_| SelectCertError::ERROR)?;

                ssl.add_chain_cert(certificate.as_ref())
                    .map_err(|_| SelectCertError::ERROR)?;
            }

            let private_key = rama_tls_boring::core::pkey::PKey::private_key_from_der(
                issued_certificate.private_key.secret_der(),
            )
            .map_err(|_| SelectCertError::ERROR)?;

            ssl.set_private_key(private_key.as_ref())
                .map_err(|_| SelectCertError::ERROR)?;

            Ok(())
        });

        let stream = rama_tls_boring::core::tokio::accept(&acceptor.build(), stream).await?;
        let stream = TlsStream::new(stream);

        // Record the negotiated SNI on the connection extensions. The HTTP
        // server clones those extensions into each request's `Ingress`,
        // giving policy the verified TLS identity for authority resolution.
        if let Some(server_name) = stream.ssl_ref().servername(NameType::HOST_NAME) {
            stream
                .extensions()
                .insert(TlsServerName(server_name.to_owned()));
        }

        self.inner.serve(stream).await.map_err(Into::into)
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();

    if args.init_ech_state_only {
        let state_dir = args
            .ech_state_dir
            .as_deref()
            .ok_or_else(|| BoxError::from_static_str("ECH state directory is required"))?;

        ech_state::load_or_generate(state_dir)?;
        return Ok(());
    }

    let (issuer, listener_config) = load_listener_config(&args)?;

    let policy = Arc::new(
        PolicySession::open(
            &args.policy_socket,
            Duration::from_millis(args.policy_timeout_ms),
        )
        .await?,
    );

    let shutdown = Arc::new(Notify::new());
    let active_checks = Arc::new(Semaphore::new(MAX_ACTIVE_CHECKS));
    let executor = Executor::default();
    let alt_svc = listener_config.alt_svc.clone();

    let service = build_listener_service(
        executor.clone(),
        policy.clone(),
        listener_config,
        shutdown.clone(),
        active_checks.clone(),
        args.listen_port,
    );

    #[cfg(debug_assertions)]
    let transparent = args.test_destination.is_none();

    #[cfg(not(debug_assertions))]
    let transparent = true;

    if args.http3 {
        let http3 = Http3Config {
            policy: policy.clone(),
            issuer: issuer.clone(),
            shutdown: shutdown.clone(),
            active_checks: active_checks.clone(),
            listen_port: args.http3_listen_port,
            alt_ports: args.http3_alt_ports.clone(),
            alt_svc,
            #[cfg(debug_assertions)]
            test_destination: args.test_destination,
            #[cfg(not(debug_assertions))]
            test_destination: None,
            #[cfg(debug_assertions)]
            test_ech_dns: args.test_ech_dns,
            #[cfg(not(debug_assertions))]
            test_ech_dns: None,
        };

        let backend = http3::prepare(http3)?;
        tokio::spawn(http3::run(backend));
    }

    run_listeners(
        service,
        policy,
        shutdown,
        executor,
        args.listen_port,
        transparent,
    )
    .await
}

async fn run_listeners(
    service: impl Service<TcpStream, Output = (), Error = BoxError> + Clone,
    policy: Arc<PolicySession>,
    shutdown: Arc<Notify>,
    executor: Executor,
    listen_port: u16,
    transparent: bool,
) -> Result<(), BoxError> {
    let v4 = bind_listener(Domain::IPv4, listen_port, executor.clone(), transparent).await?;
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
struct ListenerConfig {
    issuer: CertificateIssuer,
    ech_config_list: Option<Arc<Vec<u8>>>,
    ech_private_key: Option<[u8; 32]>,
    alt_svc: Arc<AltSvcStore>,
    websocket_http11_urls: Arc<Vec<HttpUrl>>,
    http10_upstream_origins: Arc<Vec<String>>,
    destination_resolver: DestinationResolver,
    test_tls: bool,
}

fn build_listener_service(
    executor: Executor,
    policy: Arc<PolicySession>,
    listener_config: ListenerConfig,
    shutdown: Arc<Notify>,
    active_checks: Arc<Semaphore>,
    listen_port: u16,
) -> impl Service<TcpStream, Output = (), Error = BoxError> + Clone {
    service_fn(move |stream: TcpStream| {
        let executor = executor.clone();
        let policy = policy.clone();
        let issuer = listener_config.issuer.clone();
        let ech_config_list = listener_config.ech_config_list.clone();
        let ech_private_key = listener_config.ech_private_key;
        let alt_svc = listener_config.alt_svc.clone();
        let websocket_http11_urls = listener_config.websocket_http11_urls.clone();
        let http10_upstream_origins = listener_config.http10_upstream_origins.clone();
        let shutdown = shutdown.clone();
        let destination_resolver = listener_config.destination_resolver.clone();
        let test_tls = listener_config.test_tls;
        let active_checks = active_checks.clone();

        async move {
            let peer: SocketAddr = stream.peer_addr()?.into();
            let destination = destination_resolver(&stream, listen_port)?;
            let source = peer;
            info!(%peer, %source, %destination, "accepted transparent proxy stream");
            let flow = flow_key(source, destination)?;
            let upstream_clients = Arc::new(UpstreamClients::new()?);
            let claim = policy.claim(flow).await?;

            let state = FlowState {
                destination,
                tls: test_tls || matches!(destination.port(), 443 | 8443),
                active_checks: active_checks.clone(),
                policy: policy.clone(),
                claim: claim.clone(),
                ech_config_list: ech_config_list.clone(),
                alt_svc: alt_svc.clone(),
                websocket_http11_urls: websocket_http11_urls.clone(),
                http10_upstream_origins,
                upstream_clients,
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

            let tls = BoringTlsService {
                issuer,
                ech_config_list: ech_config_list.clone(),
                ech_private_key,
                fallback_name: destination.ip().to_string(),
                inner: http,
            };

            let service = TlsPeekRouter::new(tls).with_fallback(fallback_http);
            let result = service.serve(stream).await;
            let release_result = policy.release(&claim).await;
            release_result?;
            result
        }
    })
}

fn load_listener_config(args: &Args) -> Result<(CertificateIssuer, ListenerConfig), BoxError> {
    let websocket_http11_urls = args
        .websocket_http11_urls
        .iter()
        .map(|pattern| {
            HttpUrl::parse_pattern(pattern).map_err(|error| {
                BoxError::from(format!(
                    "invalid WebSocket HTTP/1.1 URL pattern {pattern:?}: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let websocket_http11_urls = Arc::new(websocket_http11_urls);

    let http10_upstream_origins =
        Arc::new(canonical_http10_origins(&args.http10_upstream_origins)?);

    let ech_state = args
        .ech_state_dir
        .as_deref()
        .map(ech_state::load_or_generate)
        .transpose()?;

    let ech_config_list =
        select_ech_config_list(args.ech_config_list.as_deref(), ech_state.as_ref())?;

    let ech_private_key = ech_state.map(|state| state.private_key);

    let ca_certificate = args
        .ca_certificate
        .as_deref()
        .ok_or_else(|| BoxError::from_static_str("CA certificate is required"))?;

    let ca_certificate = std::fs::read_to_string(ca_certificate)?;

    let ca_private_key = args
        .ca_private_key
        .as_deref()
        .ok_or_else(|| BoxError::from_static_str("CA private key is required"))?;

    let ca_private_key = std::fs::read_to_string(ca_private_key)?;
    let issuer = CertificateIssuer::from_pem(&ca_certificate, &ca_private_key)?;

    let intercepted_udp_ports = if args.http3 {
        std::iter::once(args.http3_listen_port)
            .chain(args.http3_alt_ports.iter().copied())
            .collect()
    } else {
        Vec::new()
    };

    let listener_config = ListenerConfig {
        issuer: issuer.clone(),
        ech_config_list,
        ech_private_key,
        alt_svc: Arc::new(AltSvcStore::new(intercepted_udp_ports)),
        websocket_http11_urls,
        http10_upstream_origins,
        #[cfg(debug_assertions)]
        destination_resolver: args
            .test_destination
            .map_or_else(|| Arc::new(destination_for_stream), destination_override),
        #[cfg(not(debug_assertions))]
        destination_resolver: Arc::new(destination_for_stream),
        #[cfg(debug_assertions)]
        test_tls: args.test_tls,
        #[cfg(not(debug_assertions))]
        test_tls: false,
    };

    Ok((issuer, listener_config))
}

fn destination_for_stream(stream: &TcpStream, listen_port: u16) -> Result<SocketAddr, BoxError> {
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

/// Rewrite the `Alt-Svc` headers of one approved response.
///
/// Validated alternatives are preserved for HTTP/3 discovery, filtered
/// alternatives are removed, and the special `clear` value passes through.
/// The header is removed entirely when no alternative survives validation.
async fn preserve_alt_svc(
    response: &mut Response,
    store: &AltSvcStore,
    origin: &str,
) -> Result<(), BoxError> {
    let values = response
        .headers()
        .get_all("alt-svc")
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();

    if values.is_empty() {
        return Ok(());
    }

    let borrowed = values.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let rewritten = store.record(origin, &borrowed).await;

    response.headers_mut().remove("alt-svc");

    if let Some(value) = rewritten
        && let Ok(value) = HeaderValue::from_bytes(&value)
    {
        response.headers_mut().insert("alt-svc", value);
    }

    Ok(())
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
        let header_authority = normalize_authority(header_host, state.authority_fallback_port())?;
        let uri_authority = normalize_authority(uri_host, state.authority_fallback_port())?;

        if header_authority != uri_authority {
            return Err(BoxError::from_static_str(
                "HTTP request has conflicting origin authorities",
            ));
        }
    }

    let tls_host = request
        .extensions()
        .get_ref::<TlsServerName>()
        .map(|name| name.0.clone());

    if let Some(tls_host) = tls_host.as_deref()
        && let Some(request_host) = header_host.as_deref().or(uri_host.as_deref())
    {
        let tls_authority = normalize_authority(tls_host, state.authority_fallback_port())?;
        let request_authority = normalize_authority(request_host, state.authority_fallback_port())?;

        if tls_authority != request_authority {
            return Err(BoxError::from_static_str(
                "HTTP request conflicts with TLS server identity",
            ));
        }
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

    let semantic_request = SemanticRequest::from_parts(
        request.method().as_str(),
        scheme,
        &authority,
        &path,
        raw_query.as_deref(),
        semantic_request_headers(request)?,
        semantic_version,
        semantic_version,
        None,
        BoundedRequestBody::empty(),
    )?;

    let request_id = ProxyRequestId::new();

    let _permit = state
        .active_checks
        .clone()
        .try_acquire_owned()
        .map_err(|_| BoxError::from_static_str("too many active policy checks"))?;

    let mut pending = PendingPolicyCheck::new(state.policy.clone(), request_id);

    let check = tokio::select! {
        result = state.policy.check_http(
            request_id,
            state.claim.attribution_token.clone(),
            semantic_request.policy_request()?,
        ) => result?,
        () = shutdown.notified() => {
            state.policy.cancel(request_id).await?;
            pending.disarm();
            return Err(BoxError::from_static_str("proxy shutting down"));
        }
    };

    pending.disarm();
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

    preserve_alt_svc(&mut response, &state.alt_svc, &authority).await?;

    if doh {
        response = rewrite_doh_response(
            response,
            state.ech_config_list.as_ref().map(|value| value.as_slice()),
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
                        if let Err(error) = self.semantic.push_chunk(chunk.to_vec()) {
                            self.finish(RequestTerminal::Error(TerminalError::ProtocolViolation(
                                error.to_string().into_boxed_str(),
                            )));
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }
                        let _ = self.semantic.pop_chunk();
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
        record_response_event(&mut sequence, ResponseEvent::Final(head))?;

        if terminal {
            record_response_event(&mut sequence, ResponseEvent::Complete)?;
        }

        Ok(Self {
            inner,
            sequence,
            terminal,
        })
    }

    fn finish(&mut self, event: ResponseEvent) {
        if !self.terminal {
            let _ = record_response_event(&mut self.sequence, event);
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
                    if let Err(error) = record_response_event(
                        &mut self.sequence,
                        ResponseEvent::BodyChunk(data.to_vec()),
                    ) {
                        self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                            error.to_string().into_boxed_str(),
                        )));
                        return Poll::Ready(Some(Err(error)));
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

                        if let Err(error) = record_response_event(
                            &mut self.sequence,
                            ResponseEvent::Trailers(semantic),
                        ) {
                            self.finish(ResponseEvent::Error(TerminalError::ProtocolViolation(
                                error.to_string().into_boxed_str(),
                            )));
                            return Poll::Ready(Some(Err(error)));
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

fn record_response_event(
    sequence: &mut ResponseSequence,
    event: ResponseEvent,
) -> Result<(), BoxError> {
    sequence.push(event)?;

    sequence
        .pop_event()
        .ok_or_else(|| BoxError::from_static_str("semantic response event was not queued"))
        .map(|_| ())
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

fn semantic_request_headers(request: &Request) -> Result<SemanticHeaders, BoxError> {
    let connection_tokens = connection_tokens(request.headers());
    let mut headers = SemanticHeaders::new();

    for (name, value) in request.headers() {
        if is_hop_by_hop_header(name.as_str(), &connection_tokens) {
            continue;
        }

        headers.try_push(name.as_str(), value.as_bytes())?;
    }

    Ok(headers)
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
        Body, BoundedRequestBody, HttpUrl, POLICY_DENIED_BODY, Request, ResponseVersionAdaptCtx,
        SemanticRequestBody, StatusCode, TargetHttpVersion, Version, adapt_http10_response,
        adapt_response_version, blocked_http_request, bridge_response_body,
        canonical_http10_origin, force_websocket_http11, is_doh_request,
        is_websocket_upgrade_request, is_websocket_upgrade_response, policy_denied_response,
        request_head_clone, select_ech_config_list, semantic_request_headers,
        semantic_response_headers,
    };
    use crate::ech_state::EchState;
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
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
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

        let headers = semantic_request_headers(&request).expect("semantic headers");
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

        let headers = semantic_request_headers(&request).expect("semantic headers");

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
    fn ech_config_override_must_match_private_key() {
        let state = EchState {
            config_list: vec![1],
            private_key: [0; 32],
        };

        assert!(select_ech_config_list(Some("Ag=="), Some(&state)).is_err());

        assert_eq!(
            select_ech_config_list(Some("AQ=="), Some(&state))
                .expect("matching ECH config")
                .expect("ECH config")
                .as_slice(),
            &[1]
        );
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
}
