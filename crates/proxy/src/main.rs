mod ech_state;

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::{EchRewrite, HttpRequest, ProxyRequestId, rewrite_ech_config};
use agent_sandbox_proxy::{
    cert::CertificateIssuer,
    policy::{PolicySession, authority_for_policy, flow_key, normalize_authority},
    strip_alt_svc,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Parser;
use nix::sys::socket::{getsockopt, sockopt};
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt},
    extensions::ExtensionsRef,
    io::Io,
    matcher::{match_fn, service::MatcherServicePair},
    rt::Executor,
    service::service_fn,
};
use rama_dns::client::DnsConnectorLayer;
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version,
    body::util::BodyExt,
    conn::TargetHttpVersion,
    io::upgrade::OnUpgrade,
    layer::{
        upgrade::mitm::HttpUpgradeMitmRelay,
        version_adapter::{RequestVersionAdapter, ResponseVersionAdaptCtx, adapt_response_version},
    },
};
use rama_http_backend::{client::HttpConnector, server::HttpServer};
use rama_net::{
    address::SocketAddress,
    proxy::IoForwardService,
    socket::{SocketOptions, opts::Domain},
    stream::Socket,
};
use rama_tcp::{TcpStream, client::service::TcpConnector, server::TcpListener};
use rama_tls::{client::TlsClientConfig, server::TlsPeekRouter};
use rama_tls_boring::{
    TlsStream,
    core::{
        hpke::HpkeKey,
        ssl::{AlpnError, NameType, SelectCertError, SslAcceptor, SslEchKeys, SslMethod, SslRef},
        x509::X509,
    },
};
use rama_tls_rustls::client::TlsConnector;
use tokio::sync::{Notify, Semaphore};
use tracing::{error, info};

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

    #[arg(long)]
    init_ech_state_only: bool,

    #[arg(long, default_value_t = 18080)]
    listen_port: u16,

    #[arg(long, default_value_t = 305_000)]
    policy_timeout_ms: u64,

    #[arg(long, env = "AGENT_SANDBOX_ECH_CONFIG_LIST")]
    ech_config_list: Option<String>,

    #[arg(
        long,
        env = "AGENT_SANDBOX_ECH_STATE_DIR",
        default_value = ech_state::DEFAULT_ECH_STATE_DIR
    )]
    ech_state_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct FlowState {
    destination: SocketAddr,
    tls: bool,
    active_checks: Arc<Semaphore>,
    policy: Arc<PolicySession>,
    attribution_token: agent_sandbox_core::AttributionToken,
    ech_config_list: Option<Arc<Vec<u8>>>,
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
        self.inner
            .serve(TlsStream::new(stream))
            .await
            .map_err(Into::into)
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

    let listener_config = ListenerConfig {
        issuer,
        ech_config_list,
        ech_private_key,
    };
    let service = build_listener_service(
        executor.clone(),
        policy.clone(),
        listener_config,
        shutdown.clone(),
        active_checks,
        args.listen_port,
    );

    let v4 = bind_listener(Domain::IPv4, args.listen_port, executor.clone()).await?;
    let v6 = bind_listener(Domain::IPv6, args.listen_port, executor.clone()).await?;
    policy.mark_ready()?;

    info!(port = args.listen_port, "transparent HTTP proxy listening");
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
        ip_transparent: matches!(domain, Domain::IPv4).then_some(true),
        ip_transparent_v6: matches!(domain, Domain::IPv6).then_some(true),
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
        let shutdown = shutdown.clone();
        let active_checks = active_checks.clone();
        async move {
            let peer: SocketAddr = stream.peer_addr()?.into();
            let destination = destination_for_stream(&stream, listen_port)?;
            let source = peer;
            info!(%peer, %source, %destination, "accepted transparent proxy stream");
            let flow = flow_key(source, destination)?;
            let attribution_token = policy.claim(flow).await?;

            let state = FlowState {
                destination,
                tls: matches!(destination.port(), 443 | 8443),
                active_checks: active_checks.clone(),
                policy: policy.clone(),
                attribution_token: attribution_token.clone(),
                ech_config_list: ech_config_list.clone(),
            };
            let request_service = service_fn(move |request| {
                let state = state.clone();
                let shutdown = shutdown.clone();

                async move {
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
            let fallback_http = http.clone();
            let tls = BoringTlsService {
                issuer,
                ech_config_list: ech_config_list.clone(),
                ech_private_key,
                fallback_name: destination.ip().to_string(),
                inner: http.clone(),
            };

            let service = TlsPeekRouter::new(tls).with_fallback(fallback_http);
            let result = service.serve(stream).await;
            let release_result = policy.release(attribution_token).await;
            release_result?;
            result
        }
    })
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

#[cfg(target_os = "linux")]
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

#[cfg(not(target_os = "linux"))]
fn original_destination(_stream: &TcpStream) -> Option<SocketAddr> {
    None
}

struct PendingPolicyCheck {
    policy: Arc<PolicySession>,
    request_id: ProxyRequestId,
    armed: bool,
}

impl PendingPolicyCheck {
    const fn new(policy: Arc<PolicySession>, request_id: ProxyRequestId) -> Self {
        Self {
            policy,
            request_id,
            armed: true,
        }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingPolicyCheck {
    fn drop(&mut self) {
        if self.armed {
            let policy = self.policy.clone();
            let request_id = self.request_id;

            tokio::spawn(async move {
                if let Err(error) = policy.cancel(request_id).await {
                    error!(%error, "failed to cancel dropped HTTP policy check");
                }
            });
        }
    }
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

async fn proxy_request(
    mut request: Request,
    state: FlowState,
    shutdown: Arc<Notify>,
) -> Result<Response, BoxError> {
    let websocket = is_websocket_upgrade_request(&request);
    if blocked_http_request(&request) {
        return Err(Box::new(PolicyDenied));
    }
    let response_context = ResponseVersionAdaptCtx::from_request(&request);

    let doh = is_doh_request(&request);

    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| request.uri().authority().map(|value| value.to_string()))
        .ok_or_else(|| BoxError::from_static_str("HTTP request has no authority"))?;

    let scheme = if state.tls { "https" } else { "http" };
    let authority = normalize_authority(&host, state.destination.port())?;
    let target = request_target(&request);

    let path = target
        .split_once('?')
        .map_or(target.as_str(), |(path, _)| path);

    let policy_request =
        HttpRequest::from_parts(request.method().as_str(), scheme, &authority, path)?;

    let request_id = ProxyRequestId::new();

    let check = {
        let _permit = state
            .active_checks
            .clone()
            .try_acquire_owned()
            .map_err(|_| BoxError::from_static_str("too many active policy checks"))?;

        let mut pending = PendingPolicyCheck::new(state.policy.clone(), request_id);

        let check = tokio::select! {
            result = state.policy.check_http(request_id, state.attribution_token, policy_request) => result?,
            () = shutdown.notified() => {
                state.policy.cancel(request_id).await?;
                pending.disarm();
                return Err(BoxError::from_static_str("proxy shutting down"));
            }
        };

        pending.disarm();
        check
    };

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

    let upstream_url = url::Url::parse(&normalized.url.to_string())?;

    let upstream_host = upstream_url
        .host_str()
        .ok_or_else(|| BoxError::from_static_str("normalized policy target has no host"))?;

    let upstream_port = upstream_url
        .port_or_known_default()
        .ok_or_else(|| BoxError::from_static_str("normalized policy target has no port"))?;

    let upstream_authority = authority_for_policy(upstream_host, upstream_port);
    let original_uri = request.uri().to_string();
    let target = request_target(&request);
    let uri = format!("{}://{upstream_authority}{target}", upstream_url.scheme());

    *request.uri_mut() = uri.parse()?;

    request
        .headers_mut()
        .insert("host", upstream_authority.parse()?);
    force_websocket_http11(&request);

    let connector = DnsConnectorLayer::new().into_layer(TcpConnector::default());
    let connector = TlsConnector::auto(connector).with_base_config(TlsClientConfig::default_http());
    let connector = RequestVersionAdapter::new(connector).with_default_version(Version::HTTP_11);
    let client = HttpConnector::new(connector, Executor::default());

    let connection = client.serve(request).await?;
    let mut response = connection.conn.serve(connection.input).await?;
    let response_status = response.status();
    let response_version = response.version();
    if websocket {
        info!(host = %upstream_authority, ?response_status, ?response_version, "received WebSocket upgrade response");
    }

    adapt_response_version(&mut response, &response_context)?;
    strip_alt_svc(&mut response);

    if doh {
        response = rewrite_doh_response(
            response,
            state.ech_config_list.as_ref().map(|value| value.as_slice()),
        )
        .await?;
    }

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

fn force_websocket_http11(request: &Request) {
    // RequestVersionAdapter translates H2 WebSocket CONNECT into H1 GET/Upgrade.
    if is_websocket_upgrade_request(request) {
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

fn blocked_http_request(request: &Request) -> bool {
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
        pin::Pin,
        task::{Context, Poll},
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
        Response,
        io::upgrade::{Upgraded, pending},
        layer::{upgrade::mitm::HttpUpgradeMitmRelay, version_adapter::adapt_request_version},
    };
    use rama_net::proxy::IoForwardService;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
        time::{Duration, timeout},
    };

    use super::{
        Body, POLICY_DENIED_BODY, Request, ResponseVersionAdaptCtx, StatusCode, TargetHttpVersion,
        Version, adapt_response_version, blocked_http_request, force_websocket_http11,
        is_doh_request, is_websocket_upgrade_request, is_websocket_upgrade_response,
        policy_denied_response, select_ech_config_list,
    };
    use crate::ech_state::EchState;

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

        let ordinary = Request::builder()
            .method("GET")
            .body(Body::empty())
            .expect("test request");
        force_websocket_http11(&ordinary);
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
        force_websocket_http11(&extended_connect);
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
