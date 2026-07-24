use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::{HttpRequest, ProxyRequestId};
use agent_sandbox_proxy::{
    cert::CertificateIssuer,
    policy::{PolicySession, authority_for_policy, flow_key, normalize_authority},
    strip_alt_svc,
};
use clap::Parser;
use nix::sys::socket::{getsockopt, sockopt};
use rama_core::{
    Layer, Service,
    conversion::RamaTryFrom,
    error::{BoxError, BoxErrorExt},
    rt::Executor,
    service::service_fn,
};
use rama_dns::client::DnsConnectorLayer;
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version,
    layer::version_adapter::RequestVersionAdapter,
};
use rama_http_backend::{client::HttpConnector, server::HttpServer};
use rama_net::{
    address::SocketAddress,
    socket::{SocketOptions, opts::Domain},
    stream::Socket,
};
use rama_tcp::{TcpStream, client::service::TcpConnector, server::TcpListener};
use rama_tls::{
    client::TlsClientConfig,
    server::{ServerAuthData, TlsPeekRouter, TlsServerConfig},
};
use rama_tls_rustls::{
    client::TlsConnector,
    dep::rustls::{ServerConfig, server::ClientHello},
    server::{DynamicConfigProvider, RustlsServerConfigExt, TlsAcceptorLayer},
};
use tokio::sync::{Notify, Semaphore};
use tracing::{error, info};

const MAX_ACTIVE_CHECKS: usize = 256;
const POLICY_DENIED_BODY: &str = "blocked by agent-sandbox policy\n";

#[derive(Debug)]
struct PolicyDenied;

impl Display for PolicyDenied {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(POLICY_DENIED_BODY)
    }
}

impl Error for PolicyDenied {}

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
    ca_certificate: PathBuf,

    #[arg(long, env = "AGENT_SANDBOX_PROXY_CA_KEY")]
    ca_private_key: PathBuf,

    #[arg(long, default_value_t = 18080)]
    listen_port: u16,
    #[arg(long, default_value_t = 305_000)]
    policy_timeout_ms: u64,
}

#[derive(Clone)]
struct FlowState {
    destination: SocketAddr,
    tls: bool,
    active_checks: Arc<Semaphore>,
    policy: Arc<PolicySession>,
    attribution_token: agent_sandbox_core::AttributionToken,
}

#[derive(Clone)]
struct DynamicTls {
    issuer: CertificateIssuer,
    server_name: String,
}

impl DynamicConfigProvider for DynamicTls {
    fn get_config(
        &self,
        client_hello: ClientHello<'_>,
    ) -> impl Future<Output = Result<Arc<ServerConfig>, BoxError>> {
        let result = (|| {
            let server_name = client_hello.server_name().unwrap_or(&self.server_name);

            let issued = self.issuer.issue(server_name)?;

            let tls_config = TlsServerConfig::new()
                .with_alpn_http_auto()
                .with_single_cert(ServerAuthData {
                    private_key: issued.private_key.as_ref().clone_key(),
                    cert_chain: issued.certificate_chain.clone(),
                    ocsp: None,
                });

            Ok(Arc::new(ServerConfig::rama_try_from(tls_config)?))
        })();

        std::future::ready(result)
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();
    let ca_certificate = std::fs::read_to_string(&args.ca_certificate)?;
    let ca_private_key = std::fs::read_to_string(&args.ca_private_key)?;
    let issuer = CertificateIssuer::from_pem(&ca_certificate, &ca_private_key)?;

    let policy = Arc::new(
        PolicySession::open(
            &args.policy_socket,
            Duration::from_millis(args.policy_timeout_ms),
        )
        .await?,
    );

    let active_checks = Arc::new(Semaphore::new(MAX_ACTIVE_CHECKS));
    let executor = Executor::default();
    let shutdown = Arc::new(Notify::new());

    let service = build_listener_service(
        executor.clone(),
        policy.clone(),
        issuer,
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

fn build_listener_service(
    executor: Executor,
    policy: Arc<PolicySession>,
    issuer: CertificateIssuer,
    shutdown: Arc<Notify>,
    active_checks: Arc<Semaphore>,
    listen_port: u16,
) -> impl Service<TcpStream, Output = (), Error = BoxError> + Clone {
    service_fn(move |stream: TcpStream| {
        let executor = executor.clone();
        let policy = policy.clone();
        let issuer = issuer.clone();
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
            };

            let http = HttpServer::auto(executor.clone()).service(service_fn(move |request| {
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
            }));

            let tls = TlsAcceptorLayer::new(TlsServerConfig::new().with_dynamic_config(Arc::new(
                DynamicTls {
                    issuer,
                    server_name: destination.ip().to_string(),
                },
            )))
            .into_layer(http.clone());

            let service = TlsPeekRouter::new(tls).with_fallback(http);
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

async fn proxy_request(
    mut request: Request,
    state: FlowState,
    shutdown: Arc<Notify>,
) -> Result<Response, BoxError> {
    if blocked_http_request(&request) {
        return Err(Box::new(PolicyDenied));
    }

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

    let connector = DnsConnectorLayer::new().into_layer(TcpConnector::default());
    let connector = TlsConnector::auto(connector).with_base_config(TlsClientConfig::default_http());
    let connector = RequestVersionAdapter::new(connector).with_default_version(Version::HTTP_11);
    let client = HttpConnector::new(connector, Executor::default());

    let connection = client.serve(request).await?;
    let mut response = connection.conn.serve(connection.input).await?;
    strip_alt_svc(&mut response);
    info!(
        %original_uri,
        host = %upstream_authority,
        destination = %state.destination,
        "proxied HTTP request"
    );
    Ok(response)
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
        Body, POLICY_DENIED_BODY, Request, StatusCode, blocked_http_request, policy_denied_response,
    };

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
