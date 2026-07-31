//! Downstream QUIC association handling for the HTTP/3 backend.
//!
//! Each intercepted UDP association is claimed with policyd before the QUIC
//! handshake is accepted. Every HTTP/3 request stream is checked against
//! policy before any upstream connection is used. Denied or cancelled
//! streams are reset without closing other approved streams, and the
//! association claim is released when the connection completes.

use crate::{
    http3::{BoxError, Http3State},
    policy::{FlowClaim, PendingPolicyCheck, PolicySession, normalize_authority},
    semantic::{
        BoundedRequestBody, HttpVersion, SemanticHeaders, SemanticRequest, is_hop_by_hop_header,
    },
};
use agent_sandbox_core::{HttpCheckReply, ProxyRequestId};
use bytes::{Buf, Bytes};
use h3::{
    error::{Code, StreamError},
    server::{RequestResolver, RequestStream},
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

/// Resolve the original destination for intercepted UDP associations.
#[derive(Clone)]
pub struct DestinationResolver {
    port: u16,
    test_destination: Option<SocketAddr>,
}

impl DestinationResolver {
    /// Build a resolver for one listener.
    #[must_use]
    pub const fn new(port: u16, test_destination: Option<SocketAddr>) -> Self {
        Self {
            port,
            test_destination,
        }
    }

    /// Resolve the original destination for one incoming association.
    #[must_use]
    pub fn resolve(&self, incoming: &quinn::Incoming) -> SocketAddr {
        if let Some(destination) = self.test_destination {
            return destination;
        }

        let ip = incoming.local_ip().unwrap_or_else(|| {
            warn!("intercepted QUIC association has no original destination");
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        });

        SocketAddr::new(ip, self.port)
    }
}

/// Accept and serve downstream QUIC associations until the endpoint closes.
pub async fn accept_loop(
    endpoint: quinn::Endpoint,
    state: Arc<Http3State>,
    destination: DestinationResolver,
) {
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        let destination = destination.clone();

        tokio::spawn(async move {
            if let Err(error) = serve_incoming(incoming, state, destination).await {
                warn!(%error, "downstream QUIC association failed");
            }
        });
    }
}

async fn serve_incoming(
    incoming: quinn::Incoming,
    state: Arc<Http3State>,
    destination: DestinationResolver,
) -> Result<(), BoxError> {
    let source = incoming.remote_address();
    let destination = destination.resolve(&incoming);
    let flow = crate::policy::udp_flow_key(source, destination)?;

    let claim = match state.policy.claim(flow).await {
        Ok(claim) => claim,
        Err(error) => {
            incoming.refuse();
            return Err(error.into());
        }
    };

    info!(%source, %destination, "claimed downstream QUIC association");

    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(error) => {
            let _ = state.policy.release(&claim).await;
            return Err(format!("QUIC handshake failed: {error}").into());
        }
    };

    let connection = match connecting.await {
        Ok(connection) => connection,
        Err(error) => {
            release_claim(&state.policy, &claim).await;
            return Err(format!("QUIC handshake failed: {error}").into());
        }
    };

    let h3 = h3_quinn::Connection::new(connection.clone());

    let mut h3 = match h3::server::builder().build(h3).await {
        Ok(h3) => h3,
        Err(error) => {
            connection.close(varint(Code::H3_INTERNAL_ERROR), b"http3 setup failed");
            release_claim(&state.policy, &claim).await;
            return Err(format!("HTTP/3 setup failed: {error}").into());
        }
    };

    loop {
        let accepted = tokio::select! {
            () = state.shutdown.notified() => break,
            accepted = h3.accept() => accepted,
        };

        match accepted {
            Ok(Some(resolver)) => {
                let state = state.clone();
                let claim = claim.clone();

                tokio::spawn(async move {
                    if let Err(error) = serve_request(resolver, state, claim).await {
                        warn!(%error, "downstream HTTP/3 stream failed");
                    }
                });
            }
            Ok(None) => break,
            Err(error) => {
                info!(%error, "downstream HTTP/3 connection closed");
                break;
            }
        }
    }

    connection.close(varint(Code::H3_NO_ERROR), b"proxy shutdown");
    release_claim(&state.policy, &claim).await;
    Ok(())
}

async fn release_claim(policy: &PolicySession, claim: &FlowClaim) {
    if let Err(error) = policy.release(claim).await {
        tracing::error!(%error, "failed to release downstream QUIC association claim");
    }
}

async fn serve_request(
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    state: Arc<Http3State>,
    claim: FlowClaim,
) -> Result<(), BoxError> {
    let (request, stream) = resolver.resolve_request().await?;

    let semantic = match semantic_request(&request, &state) {
        Ok(semantic) => semantic,
        Err(error) => {
            let mut stream = stream;
            stream.stop_sending(Code::H3_MESSAGE_ERROR);
            stream.stop_stream(Code::H3_MESSAGE_ERROR);
            return Err(error);
        }
    };

    let request_id = ProxyRequestId::new();

    let _permit = state
        .active_checks
        .clone()
        .try_acquire_owned()
        .map_err(|_| boxed("too many active policy checks"))?;

    let mut pending = PendingPolicyCheck::new(state.policy.clone(), request_id);

    let check = tokio::select! {
        result = state.policy.check_http(
            request_id,
            claim.attribution_token.clone(),
            semantic.policy_request()?,
        ) => result?,
        () = state.shutdown.notified() => {
            state.policy.cancel(request_id).await?;
            pending.disarm();
            return Err(boxed("proxy shutting down"));
        }
    };

    pending.disarm();

    let HttpCheckReply {
        ok: true,
        allowed: true,
        request: Some(normalized),
        ..
    } = check
    else {
        info!(
            method = %request.method().as_str(),
            url = %semantic.forwarding_target(),
            "downstream HTTP/3 request denied by policy"
        );

        let mut stream = stream;
        stream.stop_sending(Code::H3_REQUEST_REJECTED);
        stream.stop_stream(Code::H3_REQUEST_REJECTED);
        return Ok(());
    };

    relay_request(stream, state, semantic, normalized).await
}

fn semantic_request(
    request: &http::Request<()>,
    state: &Http3State,
) -> Result<SemanticRequest, BoxError> {
    let uri = request.uri();

    let authority = uri
        .authority()
        .ok_or_else(|| boxed("HTTP/3 request has no :authority"))?;

    let authority = normalize_authority(authority.as_str(), state.destination_port)?;

    let scheme = uri
        .scheme_str()
        .ok_or_else(|| boxed("HTTP/3 request has no :scheme"))?;

    let headers = semantic_request_headers(request.headers())?;

    Ok(SemanticRequest::from_parts(
        request.method().as_str(),
        scheme,
        &authority,
        uri.path(),
        uri.query(),
        headers,
        HttpVersion::Http3,
        HttpVersion::Http3,
        None,
        BoundedRequestBody::empty(),
    )?)
}

fn semantic_request_headers(headers: &http::HeaderMap) -> Result<SemanticHeaders, BoxError> {
    let connection_tokens = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();

    let mut semantic = SemanticHeaders::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name.as_str(), &connection_tokens) {
            continue;
        }

        semantic.try_push(name.as_str(), value.as_bytes())?;
    }

    Ok(semantic)
}

async fn relay_request(
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: Arc<Http3State>,
    semantic: SemanticRequest,
    normalized: agent_sandbox_core::HttpRequest,
) -> Result<(), BoxError> {
    let upstream_url = url::Url::parse(&normalized.url.to_string())?;

    let upstream_host = upstream_url
        .host_str()
        .ok_or_else(|| boxed("normalized policy target has no host"))?;

    let upstream_port = upstream_url
        .port_or_known_default()
        .ok_or_else(|| boxed("normalized policy target has no port"))?;

    let upstream_authority = crate::policy::authority_for_policy(upstream_host, upstream_port);

    let upstream = state
        .upstream
        .connect(upstream_url.scheme(), &upstream_authority)
        .await?;

    let target = semantic.forwarding_target();
    let uri = format!("{}://{upstream_authority}{target}", upstream_url.scheme());

    let mut request = http::Request::builder()
        .method(semantic.method().as_str())
        .uri(uri)
        .body(())
        .map_err(|error| BoxError::from(format!("invalid upstream request: {error}")))?;

    *request.headers_mut() = upstream_headers(semantic.headers())?;

    let request_stream = upstream.send_request(request).await?;
    let (mut send_stream, mut recv_response) = request_stream.split();

    let (mut send_half, mut recv_half) = stream.split();

    let body_task =
        tokio::spawn(async move { relay_request_body(&mut recv_half, &mut send_stream).await });

    let relay_result = relay_response(&mut send_half, &mut recv_response).await;

    body_task.abort();

    match relay_result {
        Ok(()) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn relay_request_body(
    stream: &mut RequestStream<h3_quinn::RecvStream, Bytes>,
    send_stream: &mut h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                let mut chunk = chunk;
                let chunk = chunk.copy_to_bytes(chunk.remaining());
                send_stream.send_data(chunk).await?;
            }
            Ok(None) => break,
            Err(error) => {
                send_stream.stop_stream(map_stream_error(&error));
                return Err(BoxError::from(format!(
                    "downstream request body failed: {error}"
                )));
            }
        }
    }

    if let Some(trailers) = stream.recv_trailers().await? {
        send_stream.send_trailers(trailers).await?;
    }

    send_stream.finish().await?;
    Ok(())
}

async fn relay_response(
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    recv_response: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
) -> Result<(), BoxError> {
    let response = match recv_response.recv_response().await {
        Ok(response) => response,
        Err(error) => {
            return Err(BoxError::from(format!("upstream response failed: {error}")));
        }
    };

    stream.send_response(response).await?;

    loop {
        match recv_response.recv_data().await {
            Ok(Some(chunk)) => {
                let mut chunk = chunk;
                let chunk = chunk.copy_to_bytes(chunk.remaining());
                stream.send_data(chunk).await?;
            }
            Ok(None) => break,
            Err(error) => {
                stream.stop_stream(map_stream_error(&error));
                return Err(BoxError::from(format!(
                    "upstream response body failed: {error}"
                )));
            }
        }
    }

    if let Some(trailers) = recv_response.recv_trailers().await? {
        stream.send_trailers(trailers).await?;
    }

    stream.finish().await?;
    Ok(())
}

fn upstream_headers(headers: &SemanticHeaders) -> Result<http::HeaderMap, BoxError> {
    let mut map = http::HeaderMap::new();

    for header in headers.as_slice() {
        let name = http::header::HeaderName::from_bytes(header.name().as_bytes())
            .map_err(|error| BoxError::from(format!("invalid upstream header name: {error}")))?;

        let value = http::header::HeaderValue::from_bytes(header.value())
            .map_err(|error| BoxError::from(format!("invalid upstream header value: {error}")))?;

        map.append(name, value);
    }

    Ok(map)
}

const fn map_stream_error(error: &StreamError) -> Code {
    match error {
        StreamError::StreamError { code, .. } | StreamError::RemoteTerminate { code, .. } => *code,
        StreamError::HeaderTooBig { .. } => Code::H3_EXCESSIVE_LOAD,
        _ => Code::H3_INTERNAL_ERROR,
    }
}

fn boxed(message: &'static str) -> BoxError {
    message.into()
}

fn varint(code: Code) -> quinn::VarInt {
    quinn::VarInt::from_u64(code.value()).expect("HTTP/3 error codes fit in VarInt")
}
