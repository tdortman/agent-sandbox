//! Request relay for approved downstream HTTP/3 streams: semantic request
//! building, policy authorization, upstream session opening, and body and
//! response relay.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use agent_sandbox_core::{AttributionToken, HttpCheckReply, HttpRequest};
use bytes::{Buf, Bytes};
use h3::{
    ConnectionState,
    error::{Code, StreamError},
    quic::StreamId,
    server::RequestStream,
};
use h3_datagram::datagram_handler::DatagramSender;
use h3_quinn::datagram::SendDatagramHandler;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

use crate::{
    alt_svc::AltSvcStore,
    http3::{
        BoxError, Http3State,
        association::{Http3RequestContext, MAX_INFORMATIONAL_RESPONSES},
        boxed,
        datagram::{DatagramRelay, RoutedDatagram},
        session::{self, SessionKey, SessionProtocol},
        session_registry::{SessionBinding, SessionRegistry, session_key},
        upstream::IncomingWebTransportReceiver,
        webtransport::{
            PendingWebTransportSessions, relay_webtransport_capsules,
            relay_webtransport_response_capsules,
        },
    },
    policy::{FlowClaim, normalize_authority, reconcile_authorities},
    semantic::{
        BoundedRequestBody, SemanticHeaders, SemanticRequest, SemanticRequestParts,
        semantic_request_headers,
    },
};

pub(super) type UpstreamRequestStream =
    h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub(super) struct SessionOpen {
    pub(super) upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    pub(super) stream: UpstreamRequestStream,
    pub(super) informational_responses: Vec<http::Response<()>>,
    pub(super) response: http::Response<()>,
    pub(super) upstream_incoming: Option<IncomingWebTransportReceiver>,
}

pub(super) struct SessionOpenContext<'a> {
    pub(super) state: &'a Http3State,
    pub(super) scheme: &'a str,
    pub(super) authority: &'a str,
    pub(super) destination: Option<SocketAddr>,
    pub(super) sessions: &'a SessionRegistry,
    pub(super) pending_webtransport: &'a PendingWebTransportSessions,
}

struct RelayRequestOpen {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    stream: UpstreamRequestStream,
    preflight_informational: Vec<http::Response<()>>,
    preflight_response: Option<http::Response<()>>,
    key: Option<SessionKey>,
    protocol: Option<SessionProtocol>,
}

struct ResponseRelayContext {
    preflight_informational: Vec<http::Response<()>>,
    preflight_response: Option<http::Response<()>>,
    alt_svc: Arc<AltSvcStore>,
    origin: String,
    protocol: Option<SessionProtocol>,
    capsule_protocol: bool,
    binding: Option<SessionBinding>,
    normalized: Option<HttpRequest>,
    sessions: Arc<SessionRegistry>,
}

struct RequestRelayResults {
    relay_result: Result<(), BoxError>,
    body_result: Result<(), BoxError>,
    body_failed_first: bool,
}

fn spawn_datagram_relay(
    datagrams: Option<DatagramRelay>,
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_stream_id: StreamId,
) -> Option<tokio::task::JoinHandle<Result<(), BoxError>>> {
    let datagrams = datagrams?;

    Some(tokio::spawn(async move {
        relay_connect_udp_datagrams(
            datagrams.reader,
            datagrams.sender,
            upstream,
            upstream_stream_id,
        )
        .await
    }))
}

async fn select_datagram_relay(
    relay_response: impl Future<Output = Result<(), BoxError>>,
    datagram_task: &mut Option<tokio::task::JoinHandle<Result<(), BoxError>>>,
) -> Result<(), BoxError> {
    let Some(datagram_task) = datagram_task.as_mut() else {
        return relay_response.await;
    };

    tokio::select! {
        result = relay_response => {
            datagram_task.abort();
            result
        }
        result = &mut *datagram_task => match result {
            Ok(result) => result,
            Err(error) => Err(BoxError::from(format!("HTTP Datagram relay failed: {error}"))),
        }
    }
}

async fn await_request_relays(
    body_task: &mut tokio::task::JoinHandle<Result<(), BoxError>>,
    relay_response: impl Future<Output = Result<(), BoxError>>,
    datagram_task: &mut Option<tokio::task::JoinHandle<Result<(), BoxError>>>,
) -> RequestRelayResults {
    let mut relay_task = Box::pin(select_datagram_relay(relay_response, datagram_task));

    tokio::select! {
        biased;
        body_result = &mut *body_task => {
            let body_result = body_task_result(body_result);
            if body_result.is_err() {
                RequestRelayResults {
                    relay_result: Ok(()),
                    body_result,
                    body_failed_first: true,
                }
            } else {
                RequestRelayResults {
                    relay_result: relay_task.await,
                    body_result,
                    body_failed_first: false,
                }
            }
        }
        relay_result = &mut relay_task => {
            body_task.abort();
            let body_result = await_body_task(body_task).await;
            RequestRelayResults {
                relay_result,
                body_result,
                body_failed_first: false,
            }
        }
    }
}

fn body_task_result(
    result: Result<Result<(), BoxError>, tokio::task::JoinError>,
) -> Result<(), BoxError> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),

        Err(error) => Err(BoxError::from(format!(
            "HTTP request body relay failed: {error}"
        ))),
    }
}

async fn await_body_task(
    body_task: &mut tokio::task::JoinHandle<Result<(), BoxError>>,
) -> Result<(), BoxError> {
    body_task_result(body_task.await)
}

async fn relay_connect_udp_datagrams(
    mut downstream_reader: mpsc::Receiver<RoutedDatagram>,
    mut downstream_sender: DatagramSender<SendDatagramHandler, Bytes>,
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_stream_id: StreamId,
) -> Result<(), BoxError> {
    loop {
        tokio::select! {
            payload = downstream_reader.recv() => {
                let payload = payload
                    .ok_or_else(|| boxed("downstream datagram router closed"))?
                    .map_err(BoxError::from)?;
                session::decode_connect_udp_datagram(&payload)?;
                let encoded = session::encode_http_datagram(upstream_stream_id, &payload)?;
                upstream.send_datagram(encoded)?;
            }
            datagram = upstream.recv_datagram() => {
                let datagram = datagram?;
                let payload = session::decode_http_datagram(&datagram, upstream_stream_id)?;
                session::decode_connect_udp_datagram(&payload)?;
                downstream_sender
                    .send_datagram(payload)
                    .map_err(|error| {
                        BoxError::from(format!("downstream HTTP Datagram failed: {error}"))
                    })?;
            }
        }
    }
}

pub(super) async fn wait_for_downstream_settings(
    stream: &RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    protocol: SessionProtocol,
) -> Result<(), BoxError> {
    for _ in 0..200 {
        let settings = stream.settings();

        let supported = settings.enable_extended_connect()
            && (!protocol.needs_datagrams() || settings.enable_datagram())
            && (!matches!(protocol, SessionProtocol::WebTransport)
                || settings.enable_webtransport());

        if supported {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Err(format!(
        "downstream HTTP/3 peer refused {} settings",
        protocol.name()
    )
    .into())
}

pub(super) async fn serve_request(
    request: http::Request<()>,
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: Http3RequestContext,
    datagrams: Option<DatagramRelay>,
) -> Result<(), BoxError> {
    let Http3RequestContext {
        state,
        claim,
        destination,
        upstream_destination,
        origin_port,
        origin_authority,
        sessions,
        pending_webtransport,
    } = context;

    // An alternative endpoint changes only the transport. The fallback
    // port for a port-less authority stays the origin's port.
    let fallback_port = origin_port.unwrap_or(state.destination_port);

    let semantic = match semantic_request(&request, origin_authority.as_deref(), fallback_port) {
        Ok(semantic) => semantic,
        Err(error) => {
            let mut stream = stream;
            stream.stop_sending(Code::H3_MESSAGE_ERROR);
            stream.stop_stream(Code::H3_MESSAGE_ERROR);
            return Err(error);
        }
    };

    let requested_protocol = request
        .extensions()
        .get::<h3::ext::Protocol>()
        .copied()
        .map(SessionProtocol::from_extension)
        .transpose()?;

    if let Some(protocol) = requested_protocol
        && let Err(error) = wait_for_downstream_settings(&stream, protocol).await
    {
        let mut stream = stream;
        stream.stop_sending(Code::H3_SETTINGS_ERROR);
        stream.stop_stream(Code::H3_SETTINGS_ERROR);
        return Err(error);
    }

    let normalized = authorize_request(
        &request,
        &semantic,
        &state,
        &claim,
        &sessions,
        requested_protocol,
    )
    .await?;

    let Some(normalized) = normalized else {
        // Answer the denied request like the TCP backend does, so clients see
        // a policy block instead of a reset connection (and stop retrying).
        let mut response = http::Response::new(());

        *response.status_mut() = http::StatusCode::FORBIDDEN;

        response.headers_mut().insert(
            "x-agent-sandbox-policy",
            http::HeaderValue::from_static("blocked"),
        );

        let mut stream = stream;
        stream.send_response(response).await?;

        stream
            .send_data(Bytes::from_static(
                crate::tcp_backend::POLICY_DENIED_BODY.as_bytes(),
            ))
            .await?;

        stream.finish().await?;

        // Read the request body to its end so the stream closes cleanly on
        // drop. quinn sends STOP_SENDING on an unread receive stream, which
        // clients report as a reset after the deny response.
        while stream.recv_data().await?.is_some() {}

        let _ = stream.recv_trailers().await?;
        return Ok(());
    };

    let datagrams = if requested_protocol == Some(SessionProtocol::ConnectUdp) {
        datagrams
    } else {
        None
    };

    let relay_context = Http3RequestContext {
        state,
        claim,
        destination,
        upstream_destination,
        origin_port,
        origin_authority,
        sessions,
        pending_webtransport,
    };

    relay_request(stream, semantic, normalized, relay_context, datagrams).await
}

pub(super) async fn authorize_request(
    request: &http::Request<()>,
    semantic: &SemanticRequest,
    state: &Http3State,
    claim: &FlowClaim,
    sessions: &SessionRegistry,
    requested_protocol: Option<SessionProtocol>,
) -> Result<Option<agent_sandbox_core::HttpRequest>, BoxError> {
    let reused = if let Some(protocol) = requested_protocol {
        sessions
            .approved(semantic, protocol, claim.attribution_token.clone())
            .await
    } else {
        None
    };

    let Some(reused) = reused else {
        let check = state
            .policy
            .check_http_cancellable(
                claim.attribution_token.clone(),
                semantic.policy_request()?,
                &state.active_checks,
                &state.shutdown,
            )
            .await?;

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

            return Ok(None);
        };

        return Ok(Some(normalized));
    };

    Ok(Some(reused))
}

pub(super) fn semantic_request(
    request: &http::Request<()>,
    origin_authority: Option<&str>,
    fallback_port: u16,
) -> Result<SemanticRequest, BoxError> {
    let uri = request.uri();

    let authority = uri
        .authority()
        .ok_or_else(|| boxed("HTTP/3 request has no :authority"))?;

    let authority = if let Some(origin_authority) = origin_authority {
        reconcile_authorities(&[authority.as_str(), origin_authority], fallback_port)
            .map_err(|error| error.into_boxed("HTTP/3 authority does not match its origin"))?
    } else {
        normalize_authority(authority.as_str(), fallback_port)?
    };

    let scheme = uri
        .scheme_str()
        .ok_or_else(|| boxed("HTTP/3 request has no :scheme"))?;

    let protocol = request
        .extensions()
        .get::<h3::ext::Protocol>()
        .copied()
        .map(SessionProtocol::from_extension)
        .transpose()?;

    if request.method() == http::Method::CONNECT && protocol.is_none() {
        return Err(boxed("HTTP/3 CONNECT request has no supported protocol"));
    }

    if request.method() != http::Method::CONNECT && protocol.is_some() {
        return Err(boxed("HTTP/3 session protocol requires CONNECT"));
    }

    let session = protocol
        .map(|protocol| session::metadata(protocol, &authority))
        .transpose()?;

    let headers = semantic_request_headers(request.headers())?;

    for header in headers
        .as_slice()
        .iter()
        .filter(|header| header.name() == "host")
    {
        let host = std::str::from_utf8(header.value())
            .map_err(|_| boxed("HTTP/3 Host header is not valid UTF-8"))?;

        reconcile_authorities(&[&authority, host], fallback_port)
            .map_err(|error| error.into_boxed("HTTP/3 Host header does not match :authority"))?;
    }

    Ok(SemanticRequest::from_parts(SemanticRequestParts {
        method: request.method().as_str(),
        scheme,
        authority: &authority,
        path: uri.path(),
        raw_query: uri.query(),
        headers,
        session,
        body: BoundedRequestBody::empty(),
    })?)
}

fn has_capsule_protocol(semantic: &SemanticRequest) -> bool {
    let mut values = semantic
        .headers()
        .as_slice()
        .iter()
        .filter(|header| header.name() == "capsule-protocol");

    let Some(header) = values.next() else {
        return false;
    };

    header.value() == b"?1" && values.next().is_none()
}

fn require_capsule_protocol(enabled: bool) -> Result<(), BoxError> {
    if enabled {
        Ok(())
    } else {
        Err(boxed(
            "HTTP/3 CONNECT-UDP body requires Capsule-Protocol: ?1",
        ))
    }
}

async fn relay_request(
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    semantic: SemanticRequest,
    normalized: agent_sandbox_core::HttpRequest,
    context: Http3RequestContext,
    datagrams: Option<DatagramRelay>,
) -> Result<(), BoxError> {
    let downstream_stream_id = stream.id();

    let RelayRequestOpen {
        upstream,
        stream: request_stream,
        preflight_informational,
        preflight_response,
        key,
        protocol,
    } = open_relay_request(
        &context.state,
        &semantic,
        &normalized,
        &context,
        downstream_stream_id,
    )
    .await?;

    let Http3RequestContext {
        state, sessions, ..
    } = context;

    let alt_svc = state.alt_svc.clone();
    let origin = semantic.authority().to_owned();
    let upstream_stream_id = request_stream.id();

    let binding = key.map(|key| SessionBinding {
        key,
        downstream_stream_id,
        upstream_stream_id,
    });

    let binding_id = binding.as_ref().map(|binding| binding.downstream_stream_id);
    let cleanup_sessions = sessions.clone();
    let (mut send_stream, mut recv_response) = request_stream.split();
    let (mut send_half, mut recv_half) = stream.split();
    let body_protocol = protocol;
    let capsule_protocol = has_capsule_protocol(&semantic);

    let expects_continue = protocol.is_none()
        && semantic.headers().as_slice().iter().any(|header| {
            header.name().eq_ignore_ascii_case("expect")
                && header.value().eq_ignore_ascii_case(b"100-continue")
        });

    let (continue_tx, continue_rx) = oneshot::channel();

    let mut body_task = tokio::spawn(async move {
        relay_request_body(
            &mut recv_half,
            &mut send_stream,
            body_protocol,
            capsule_protocol,
            expects_continue.then_some(continue_rx),
        )
        .await
    });

    let mut datagram_task = spawn_datagram_relay(datagrams, upstream.clone(), upstream_stream_id);

    let relay_response = relay_response(
        &mut send_half,
        &mut recv_response,
        ResponseRelayContext {
            preflight_informational,
            preflight_response,
            alt_svc,
            origin,
            protocol,
            binding,
            capsule_protocol,
            normalized: protocol.map(|_| normalized.clone()),
            sessions,
        },
        expects_continue.then_some(continue_tx),
    );

    let RequestRelayResults {
        relay_result,
        body_result,
        body_failed_first,
    } = await_request_relays(&mut body_task, relay_response, &mut datagram_task).await;

    if body_failed_first {
        if let Some(datagram_task) = datagram_task.as_mut() {
            datagram_task.abort();
        }

        send_half.stop_stream(Code::H3_MESSAGE_ERROR);
    } else if relay_result.is_err() {
        send_half.stop_stream(Code::H3_MESSAGE_ERROR);
    }

    if (relay_result.is_err() || body_result.is_err())
        && let Some(binding_id) = binding_id
    {
        cleanup_sessions.remove(binding_id).await;
    }

    relay_result?;
    body_result
}

async fn open_relay_request(
    state: &Http3State,
    semantic: &SemanticRequest,
    normalized: &agent_sandbox_core::HttpRequest,
    context: &Http3RequestContext,
    downstream_stream_id: StreamId,
) -> Result<RelayRequestOpen, BoxError> {
    let claim = &context.claim;
    let destination = context.upstream_destination;
    let sessions = &context.sessions;
    let pending_webtransport = &context.pending_webtransport;
    let upstream_url = url::Url::parse(&normalized.url.to_string())?;

    let upstream_host = upstream_url
        .host_str()
        .ok_or_else(|| boxed("normalized policy target has no host"))?;

    let upstream_port = upstream_url
        .port_or_known_default()
        .ok_or_else(|| boxed("normalized policy target has no port"))?;

    let upstream_authority = crate::policy::authority_for_policy(upstream_host, upstream_port);

    let protocol = semantic
        .session()
        .map(|metadata| match metadata.protocol() {
            Some("websocket") => Ok(SessionProtocol::WebSocket),
            Some("webtransport") => Ok(SessionProtocol::WebTransport),
            Some("connect-udp") => Ok(SessionProtocol::ConnectUdp),
            _ => Err(BoxError::from("invalid HTTP/3 session protocol")),
        })
        .transpose()?;

    let key = protocol.map(|protocol| {
        session_key(
            semantic,
            normalized,
            protocol,
            claim.attribution_token.clone(),
        )
    });

    let request = build_upstream_request(semantic, &upstream_url, &upstream_authority, protocol)?;

    let session_open = if let Some(key) = key.as_ref() {
        sessions.reserve(downstream_stream_id, key).await?;
        match open_session_request(
            SessionOpenContext {
                state,
                scheme: upstream_url.scheme(),
                authority: &upstream_authority,
                destination,
                sessions,
                pending_webtransport,
            },
            key,
            request.clone(),
            downstream_stream_id,
        )
        .await
        {
            Ok(opened) => Some(opened),
            Err(error) => {
                sessions.remove(downstream_stream_id).await;
                return Err(error);
            }
        }
    } else {
        None
    };

    let (upstream, stream, preflight_informational, preflight_response) =
        if let Some(opened) = session_open {
            (
                opened.upstream,
                opened.stream,
                opened.informational_responses,
                Some(opened.response),
            )
        } else {
            let upstream = connect_upstream_for_request(
                state,
                upstream_url.scheme(),
                &upstream_authority,
                destination,
                None,
                claim.attribution_token.clone(),
            )
            .await?;
            let stream = upstream.send_request(request).await?;
            (upstream, stream, Vec::new(), None)
        };

    Ok(RelayRequestOpen {
        upstream,
        stream,
        preflight_informational,
        preflight_response,
        key,
        protocol,
    })
}

async fn connect_upstream_for_request(
    state: &Http3State,
    scheme: &str,
    authority: &str,
    destination: Option<SocketAddr>,
    protocol: Option<SessionProtocol>,
    security_context: AttributionToken,
) -> Result<Arc<crate::http3::upstream::UpstreamConnection>, BoxError> {
    let upstream = match (protocol.is_some(), destination) {
        (true, Some(destination)) => {
            state
                .upstream
                .connect_to(scheme, authority, destination, None)
                .await?
        }
        (true, None) => state.upstream.connect(scheme, authority, None).await?,
        (false, Some(destination)) => {
            state
                .upstream
                .connect_to(scheme, authority, destination, Some(&security_context))
                .await?
        }
        (false, None) => {
            state
                .upstream
                .connect(scheme, authority, Some(&security_context))
                .await?
        }
    };

    if let Some(protocol) = protocol {
        upstream.require_session_settings(protocol).await?;
    }

    Ok(upstream)
}

pub(super) async fn open_session_request(
    context: SessionOpenContext<'_>,
    key: &SessionKey,
    request: http::Request<()>,
    downstream_stream_id: StreamId,
) -> Result<SessionOpen, BoxError> {
    let state = context.state;
    let scheme = context.scheme;
    let authority = context.authority;
    let destination = context.destination;
    let sessions = context.sessions;
    let pending_webtransport = context.pending_webtransport;
    let mut last_error = None;

    for _attempt in 0..2 {
        sessions.validate(downstream_stream_id, key).await?;

        let upstream = match connect_upstream_for_request(
            state,
            scheme,
            authority,
            destination,
            Some(key.protocol),
            key.attribution.clone(),
        )
        .await
        {
            Ok(upstream) => upstream,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };

        let mut stream = match upstream.send_request(request.clone()).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(BoxError::from(format!(
                    "upstream {} session request failed: {error}",
                    key.protocol.name()
                )));
                continue;
            }
        };

        let upstream_session_id = h3::webtransport::SessionId::from(stream.id());

        let upstream_incoming = if key.protocol == SessionProtocol::WebTransport {
            let incoming = upstream
                .register_webtransport_session(upstream_session_id)
                .await;

            pending_webtransport.insert(upstream.clone(), upstream_session_id);
            Some(incoming)
        } else {
            None
        };

        match stream.recv_response_with_informational().await {
            Ok((informational_responses, response)) if response.status().is_success() => {
                if let Err(error) = sessions.validate(downstream_stream_id, key).await {
                    if upstream_incoming.is_some() {
                        pending_webtransport
                            .remove_and_unregister(&upstream, upstream_session_id)
                            .await;
                    }
                    return Err(error);
                }
                return Ok(SessionOpen {
                    upstream,
                    stream,
                    informational_responses,
                    response,
                    upstream_incoming,
                });
            }

            Ok((_informational_responses, response)) => {
                if upstream_incoming.is_some() {
                    pending_webtransport
                        .remove_and_unregister(&upstream, upstream_session_id)
                        .await;
                }
                return Err(format!(
                    "upstream refused approved HTTP/3 session with {}",
                    response.status()
                )
                .into());
            }

            Err(error) => {
                if upstream_incoming.is_some() {
                    pending_webtransport
                        .remove_and_unregister(&upstream, upstream_session_id)
                        .await;
                }
                if is_session_refusal(&error) {
                    return Err(format!(
                        "upstream refused approved {} session: {error}",
                        key.protocol.name()
                    )
                    .into());
                }
                last_error = Some(BoxError::from(format!(
                    "upstream {} session response failed: {error}",
                    key.protocol.name()
                )));
            }
        }
    }

    Err(session_open_error(last_error, key))
}

fn session_open_error(last_error: Option<BoxError>, key: &SessionKey) -> BoxError {
    last_error.unwrap_or_else(|| {
        BoxError::from(format!(
            "upstream {} session could not be established",
            key.protocol.name()
        ))
    })
}

pub(super) fn build_upstream_request(
    semantic: &SemanticRequest,
    upstream_url: &url::Url,
    upstream_authority: &str,
    protocol: Option<SessionProtocol>,
) -> Result<http::Request<()>, BoxError> {
    let target = semantic.forwarding_target();
    let uri = format!("{}://{upstream_authority}{target}", upstream_url.scheme());

    let mut request = http::Request::builder()
        .method(semantic.method().as_str())
        .uri(uri)
        .body(())
        .map_err(|error| BoxError::from(format!("invalid upstream request: {error}")))?;

    if let Some(protocol) = protocol {
        request.extensions_mut().insert(protocol.extension());
    }

    *request.headers_mut() = upstream_headers(semantic.headers())?;
    Ok(request)
}

pub(super) async fn relay_request_body(
    stream: &mut RequestStream<h3_quinn::RecvStream, Bytes>,
    send_stream: &mut h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    protocol: Option<SessionProtocol>,
    capsule_protocol: bool,
    continue_rx: Option<oneshot::Receiver<()>>,
) -> Result<(), BoxError> {
    if let Some(continue_rx) = continue_rx {
        continue_rx
            .await
            .map_err(|_| boxed("upstream closed before 100 Continue"))?;
    }

    let mut capsules = session::CapsuleDecoder::default();

    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                let mut chunk = chunk;
                let chunk = chunk.copy_to_bytes(chunk.remaining());

                if protocol == Some(SessionProtocol::ConnectUdp) {
                    require_capsule_protocol(capsule_protocol)?;
                }

                match protocol {
                    Some(SessionProtocol::ConnectUdp) => {
                        relay_connect_udp_capsules(&mut capsules, &chunk, send_stream).await?;
                    }
                    Some(SessionProtocol::WebTransport) => {
                        relay_webtransport_capsules(&mut capsules, &chunk, send_stream).await?;
                    }
                    _ => send_stream.send_data(chunk).await?,
                }
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

    if matches!(
        protocol,
        Some(SessionProtocol::ConnectUdp | SessionProtocol::WebTransport)
    ) {
        capsules.finish()?;
    }

    if let Some(trailers) = stream.recv_trailers().await? {
        send_stream.send_trailers(trailers).await?;
    }

    send_stream.finish().await?;
    Ok(())
}

fn encode_connect_udp_capsule(capsule: session::Capsule) -> Result<Bytes, BoxError> {
    let payload = if capsule.kind == session::DATAGRAM_CAPSULE_TYPE {
        let payload = session::decode_connect_udp_datagram(&capsule.payload)?;
        session::encode_connect_udp_datagram_payload(&payload)
    } else {
        capsule.payload
    };

    Ok(session::encode_capsule(capsule.kind, &payload))
}

async fn relay_connect_udp_capsules(
    decoder: &mut session::CapsuleDecoder,
    chunk: &Bytes,
    send_stream: &mut h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    for capsule in decoder.push(chunk)? {
        send_stream
            .send_data(encode_connect_udp_capsule(capsule)?)
            .await?;
    }

    Ok(())
}

async fn relay_connect_udp_response_capsules(
    decoder: &mut session::CapsuleDecoder,
    chunk: &Bytes,
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    for capsule in decoder.push(chunk)? {
        stream
            .send_data(encode_connect_udp_capsule(capsule)?)
            .await?;
    }

    Ok(())
}

async fn relay_informational_response(
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut response: http::Response<()>,
    alt_svc: &AltSvcStore,
    origin: &str,
    continue_tx: &mut Option<oneshot::Sender<()>>,
) -> Result<(), BoxError> {
    let is_continue = response.status().as_u16() == 100;
    crate::alt_svc::preserve_response_alt_svc(&mut response, alt_svc, origin).await;
    stream.send_response(response).await?;

    if is_continue && let Some(sender) = continue_tx.take() {
        let _ = sender.send(());
    }

    Ok(())
}

async fn set_session_binding(
    sessions: &SessionRegistry,
    binding: Option<&SessionBinding>,
    normalized: Option<&HttpRequest>,
) -> Result<(), BoxError> {
    if let (Some(binding), Some(normalized)) = (binding, normalized)
        && let Err(error) = sessions.set(binding, normalized).await
    {
        sessions.remove(binding.downstream_stream_id).await;
        return Err(error);
    }

    Ok(())
}

async fn relay_response_heads(
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    recv_response: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    alt_svc: &AltSvcStore,
    origin: &str,
    continue_tx: &mut Option<oneshot::Sender<()>>,
) -> Result<http::Response<()>, BoxError> {
    let mut informational_count = 0;

    loop {
        let response = recv_response
            .recv_response_head()
            .await
            .map_err(|error| BoxError::from(format!("upstream response failed: {error}")))?;

        if !response.status().is_informational() {
            return Ok(response);
        }

        if informational_count == MAX_INFORMATIONAL_RESPONSES {
            recv_response.stop_sending(Code::H3_EXCESSIVE_LOAD);
            return Err(boxed("too many informational responses"));
        }

        informational_count += 1;
        relay_informational_response(stream, response, alt_svc, origin, continue_tx).await?;
    }
}

async fn relay_response(
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    recv_response: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    context: ResponseRelayContext,
    continue_tx: Option<oneshot::Sender<()>>,
) -> Result<(), BoxError> {
    let ResponseRelayContext {
        preflight_informational,
        preflight_response,
        alt_svc,
        origin,
        protocol,
        capsule_protocol,
        binding,
        normalized,
        sessions,
    } = context;

    let mut continue_tx = continue_tx;

    let mut response = if let Some(response) = preflight_response {
        for informational_response in preflight_informational {
            relay_informational_response(
                stream,
                informational_response,
                &alt_svc,
                &origin,
                &mut continue_tx,
            )
            .await?;
        }
        response
    } else {
        relay_response_heads(stream, recv_response, &alt_svc, &origin, &mut continue_tx).await?
    };

    if binding.is_some() && !response.status().is_success() {
        return Err(format!(
            "upstream refused approved HTTP/3 session with {}",
            response.status()
        )
        .into());
    }

    let binding_id = binding.as_ref().map(|binding| binding.downstream_stream_id);
    set_session_binding(&sessions, binding.as_ref(), normalized.as_ref()).await?;

    let relay_result: Result<(), BoxError> = async {
        crate::alt_svc::preserve_response_alt_svc(&mut response, &alt_svc, &origin).await;
        stream.send_response(response).await?;

        let mut capsules = session::CapsuleDecoder::default();

        loop {
            match recv_response.recv_data().await {
                Ok(Some(chunk)) => {
                    let mut chunk = chunk;
                    let chunk = chunk.copy_to_bytes(chunk.remaining());

                    if protocol == Some(SessionProtocol::ConnectUdp) {
                        require_capsule_protocol(capsule_protocol)?;
                    }

                    match protocol {
                        Some(SessionProtocol::ConnectUdp) => {
                            relay_connect_udp_response_capsules(&mut capsules, &chunk, stream)
                                .await?;
                        }
                        Some(SessionProtocol::WebTransport) => {
                            relay_webtransport_response_capsules(&mut capsules, &chunk, stream)
                                .await?;
                        }
                        _ => stream.send_data(chunk).await?,
                    }
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

        if matches!(
            protocol,
            Some(SessionProtocol::ConnectUdp | SessionProtocol::WebTransport)
        ) {
            capsules.finish()?;
        }

        if let Some(trailers) = recv_response.recv_trailers().await? {
            stream.send_trailers(trailers).await?;
        }

        stream.finish().await?;
        Ok(())
    }
    .await;

    if let Some(binding_id) = binding_id {
        sessions.remove(binding_id).await;
    }

    relay_result
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

    map.remove("host");
    Ok(map)
}

const fn is_session_refusal(error: &StreamError) -> bool {
    matches!(
        error,
        StreamError::StreamError {
            code: Code::H3_REQUEST_REJECTED,
            ..
        } | StreamError::RemoteTerminate {
            code: Code::H3_REQUEST_REJECTED,
            ..
        }
    )
}

pub(super) const fn map_stream_error(error: &StreamError) -> Code {
    match error {
        StreamError::StreamError { code, .. } | StreamError::RemoteTerminate { code, .. } => *code,
        StreamError::HeaderTooBig { .. } => Code::H3_EXCESSIVE_LOAD,
        _ => Code::H3_INTERNAL_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::AttributionToken;

    use super::{
        body_task_result, build_upstream_request, has_capsule_protocol, require_capsule_protocol,
        semantic_request, session_open_error, upstream_headers,
    };
    use crate::http3::{
        BoxError,
        session::{SessionKey, SessionProtocol},
    };

    fn request(uri: &str, host: Option<&str>) -> http::Request<()> {
        let mut builder = http::Request::builder().uri(uri);

        if let Some(host) = host {
            builder = builder.header("host", host);
        }

        builder.body(()).expect("valid request")
    }

    fn request_with_header(name: &str, value: &str) -> http::Request<()> {
        http::Request::builder()
            .uri("https://example.test/path")
            .header(name, value)
            .body(())
            .expect("valid request")
    }

    fn session_key() -> SessionKey {
        SessionKey {
            origin: "example.test".to_owned(),
            target: "https://example.test/path".to_owned(),
            protocol: SessionProtocol::WebSocket,
            attribution: AttributionToken::from_bytes([7; 32]),
        }
    }

    #[test]
    fn semantic_request_accepts_authority_matching_host()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = request("https://example.test/path", Some("example.test"));
        let semantic = semantic_request(&request, None, 8443)?;
        assert_eq!(semantic.authority(), "example.test:8443");
        Ok(())
    }

    #[test]
    fn semantic_request_accepts_matching_origin_authority()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = request("https://example.test/path", None);
        let semantic = semantic_request(&request, Some("example.test"), 8443)?;
        assert_eq!(semantic.authority(), "example.test:8443");
        Ok(())
    }

    #[test]
    fn semantic_request_applies_fallback_port()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = request("https://example.test/path", None);
        let semantic = semantic_request(&request, None, 443)?;
        assert_eq!(semantic.authority(), "example.test");
        Ok(())
    }

    #[test]
    fn semantic_request_rejects_mismatched_origin_authority() {
        let request = request("https://example.test/path", None);

        let error = semantic_request(&request, Some("other.test"), 8443)
            .expect_err("origin mismatch is rejected");

        assert_eq!(
            error.to_string(),
            "HTTP/3 authority does not match its origin"
        );
    }

    #[test]
    fn semantic_request_rejects_mismatched_host_header() {
        let request = request("https://example.test/path", Some("other.test"));
        let error = semantic_request(&request, None, 8443).expect_err("host mismatch is rejected");

        assert_eq!(
            error.to_string(),
            "HTTP/3 Host header does not match :authority"
        );
    }

    #[test]
    fn semantic_request_rejects_request_without_authority() {
        let request = http::Request::builder()
            .uri("/path")
            .body(())
            .expect("request");

        let error =
            semantic_request(&request, None, 8443).expect_err("missing authority is rejected");

        assert_eq!(error.to_string(), "HTTP/3 request has no :authority");
    }

    #[test]
    fn has_capsule_protocol_accepts_a_single_marker_header()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = request_with_header("capsule-protocol", "?1");

        assert!(has_capsule_protocol(&semantic_request(
            &request, None, 8443
        )?));

        Ok(())
    }

    #[test]
    fn has_capsule_protocol_rejects_missing_wrong_or_duplicate_markers()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let plain = request("https://example.test/path", None);

        assert!(!has_capsule_protocol(&semantic_request(
            &plain, None, 8443
        )?));

        let wrong = request_with_header("capsule-protocol", "?0");

        assert!(!has_capsule_protocol(&semantic_request(
            &wrong, None, 8443
        )?));

        let duplicate = http::Request::builder()
            .uri("https://example.test/path")
            .header("capsule-protocol", "?1")
            .header("capsule-protocol", "?1")
            .body(())
            .expect("valid request");

        assert!(!has_capsule_protocol(&semantic_request(
            &duplicate, None, 8443
        )?));

        Ok(())
    }

    #[test]
    fn require_capsule_protocol_gates_connect_udp_bodies() {
        require_capsule_protocol(true).expect("enabled capsule protocol is accepted");

        let error =
            require_capsule_protocol(false).expect_err("missing capsule protocol is rejected");

        assert_eq!(
            error.to_string(),
            "HTTP/3 CONNECT-UDP body requires Capsule-Protocol: ?1"
        );
    }

    #[test]
    fn build_upstream_request_uses_the_semantic_target_and_authority()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let semantic = semantic_request(&request("https://example.test/path", None), None, 8443)?;
        let upstream_url = url::Url::parse("https://example.test/path")?;

        let built = build_upstream_request(
            &semantic,
            &upstream_url,
            "example.test:8443",
            Some(SessionProtocol::WebSocket),
        )?;

        assert_eq!(built.method(), http::Method::GET);
        assert_eq!(built.uri().to_string(), "https://example.test:8443/path");

        assert_eq!(
            built.extensions().get::<h3::ext::Protocol>(),
            Some(&h3::ext::Protocol::WEBSOCKET)
        );

        Ok(())
    }

    #[test]
    fn build_upstream_request_omits_the_protocol_extension_without_a_session()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let semantic = semantic_request(&request("https://example.test/path", None), None, 8443)?;
        let upstream_url = url::Url::parse("https://example.test/path")?;
        let built = build_upstream_request(&semantic, &upstream_url, "example.test:8443", None)?;
        assert!(built.extensions().get::<h3::ext::Protocol>().is_none());
        Ok(())
    }

    #[test]
    fn upstream_headers_removes_host_and_preserves_other_headers()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = http::Request::builder()
            .uri("https://example.test/path")
            .header("host", "example.test")
            .header("x-custom", "value")
            .body(())?;

        let semantic = semantic_request(&request, None, 8443)?;
        let headers = upstream_headers(semantic.headers())?;
        assert!(!headers.contains_key("host"));
        assert_eq!(headers.get("x-custom").expect("custom header"), "value");
        Ok(())
    }

    #[test]
    fn session_open_error_reports_the_last_attempt_or_the_protocol() {
        let key = session_key();
        let last_error: BoxError = "upstream refused".into();

        assert_eq!(
            session_open_error(Some(last_error), &key).to_string(),
            "upstream refused"
        );

        assert_eq!(
            session_open_error(None, &key).to_string(),
            "upstream websocket session could not be established"
        );
    }

    #[tokio::test]
    async fn body_task_result_treats_cancellation_as_clean() {
        let task = tokio::spawn(std::future::pending::<Result<(), BoxError>>());
        task.abort();
        let join_error = task.await.expect_err("aborted task fails to join");
        assert!(body_task_result(Err(join_error)).is_ok());
    }

    #[tokio::test]
    async fn body_task_result_propagates_body_and_join_errors() {
        let body_error: BoxError = "body failed".into();
        let task = tokio::spawn(async { Err::<(), BoxError>(body_error) });
        let result = task.await.expect("body task joins");

        assert_eq!(
            body_task_result(Ok(result))
                .expect_err("body error propagates")
                .to_string(),
            "body failed"
        );

        let task = tokio::spawn(async { panic!("relay panic") });
        let join_error = task.await.expect_err("panicking task fails to join");
        assert!(!join_error.is_cancelled());
        let error = body_task_result(Err(join_error)).expect_err("join error surfaces");

        assert!(
            error
                .to_string()
                .starts_with("HTTP request body relay failed")
        );
    }
}
