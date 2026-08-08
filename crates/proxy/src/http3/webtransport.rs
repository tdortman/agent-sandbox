//! WebTransport session handling for downstream HTTP/3 associations:
//! preparation, approval, session association, and stream relay.

use crate::{
    http3::{
        BoxError, Http3State,
        association::{
            H3RequestContext, Http3RequestContext, MAX_WEBTRANSPORT_SESSIONS, ResolvedRequest,
            finish_h3_request, rebind_migrated_path, reject_0rtt_stream, stop_h3_tasks,
            upstream_destination_for,
        },
        boxed,
        connection_id::ConnectionIdBindings,
        datagram::{DatagramRelay, DatagramRouter, DatagramRouterState, RoutedDatagram},
        relay::{
            SessionOpen, SessionOpenContext, UpstreamRequestStream, build_upstream_request,
            map_stream_error, open_session_request, relay_request_body, semantic_request,
            serve_request, wait_for_downstream_settings,
        },
        session::{self, SessionProtocol},
        session_registry::{SessionBinding, SessionRegistry, session_key},
        upstream::{IncomingWebTransportReceiver, IncomingWebTransportStream},
    },
    policy::FlowClaim,
    semantic::SemanticRequest,
};
use agent_sandbox_core::HttpCheckReply;
use bytes::{Buf, Bytes};
use h3::{
    error::Code,
    quic::{BidiStream as _, RecvStream as _, SendStream as _, StreamId},
    server::RequestStream,
};
use h3_datagram::datagram_handler::DatagramSender;
use h3_quinn::datagram::SendDatagramHandler;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};
use tracing::warn;

pub(super) struct WebTransportRoute {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_session_id: h3::webtransport::SessionId,
    downstream_stream_id: StreamId,
    upstream_stream_id: StreamId,
    binding_id: StreamId,
    cancel: Option<watch::Sender<bool>>,
    incoming_task: Option<tokio::task::JoinHandle<()>>,
}

pub(super) struct WebTransportSetup {
    semantic: SemanticRequest,
    normalized: agent_sandbox_core::HttpRequest,
    downstream_stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    informational_responses: Vec<http::Response<()>>,
    response: http::Response<()>,
    pub(super) upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    pub(super) upstream_session_id: h3::webtransport::SessionId,
    upstream_incoming: IncomingWebTransportReceiver,
    upstream_stream_id: StreamId,
    upstream_stream: UpstreamRequestStream,
}

struct AcceptedWebTransportRequest {
    semantic: SemanticRequest,
    normalized: agent_sandbox_core::HttpRequest,
    session_id: h3::webtransport::SessionId,
    downstream_stream_id: StreamId,
    downstream_stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_session_id: h3::webtransport::SessionId,
    upstream_incoming: IncomingWebTransportReceiver,
    upstream_stream_id: StreamId,
    upstream_stream: UpstreamRequestStream,
}

pub(super) struct WebTransportPrep {
    pub(super) request: http::Request<()>,
    pub(super) setup: Result<WebTransportSetup, BoxError>,
}

#[derive(Clone, Default)]
pub(super) struct PendingWebTransportSessions {
    sessions: Arc<std::sync::Mutex<Vec<PendingWebTransportSession>>>,
}

struct PendingWebTransportSession {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    session_id: h3::webtransport::SessionId,
}

impl PendingWebTransportSessions {
    pub(super) fn insert(
        &self,
        upstream: Arc<crate::http3::upstream::UpstreamConnection>,
        session_id: h3::webtransport::SessionId,
    ) {
        self.sessions
            .lock()
            .expect("pending WebTransport sessions lock")
            .push(PendingWebTransportSession {
                upstream,
                session_id,
            });
    }

    pub(super) fn remove(
        &self,
        upstream: &Arc<crate::http3::upstream::UpstreamConnection>,
        session_id: h3::webtransport::SessionId,
    ) {
        self.sessions
            .lock()
            .expect("pending WebTransport sessions lock")
            .retain(|pending| {
                pending.session_id != session_id || !Arc::ptr_eq(&pending.upstream, upstream)
            });
    }

    pub(super) async fn remove_and_unregister(
        &self,
        upstream: &Arc<crate::http3::upstream::UpstreamConnection>,
        session_id: h3::webtransport::SessionId,
    ) {
        self.remove(upstream, session_id);
        upstream.unregister_webtransport_session(session_id).await;
    }

    pub(super) async fn cleanup(&self) {
        let pending = {
            let mut sessions = self
                .sessions
                .lock()
                .expect("pending WebTransport sessions lock");
            std::mem::take(&mut *sessions)
        };

        for pending in pending {
            pending
                .upstream
                .unregister_webtransport_session(pending.session_id)
                .await;
        }
    }
}

pub(super) async fn reject_webtransport_request(
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    stream
        .send_response(
            http::Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(())?,
        )
        .await?;

    stream.finish().await?;
    Ok(())
}

async fn send_informational_responses(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    responses: impl IntoIterator<Item = http::Response<()>>,
) -> Result<(), BoxError> {
    for response in responses {
        stream.send_response(response).await?;
    }

    Ok(())
}

pub(super) fn is_webtransport_request(request: &http::Request<()>) -> bool {
    request
        .extensions()
        .get::<h3::ext::Protocol>()
        .is_some_and(|protocol| protocol.as_str() == "webtransport")
}

pub(super) struct WebTransportServeInput {
    pub(super) request: http::Request<()>,
    pub(super) h3: h3::server::Connection<h3_quinn::Connection, Bytes>,
    pub(super) connection: quinn::Connection,
    pub(super) destination: SocketAddr,
    pub(super) bound_source: SocketAddr,
    pub(super) context: H3RequestContext,
    pub(super) datagram_router: DatagramRouterState,
    pub(super) resolved_rx: mpsc::UnboundedReceiver<ResolvedRequest>,
    pub(super) setup: WebTransportSetup,
    pub(super) connection_ids: ConnectionIdBindings,
}

struct WebTransportRegistration {
    downstream_stream_id: StreamId,
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    datagram_task: tokio::task::JoinHandle<()>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

pub(super) async fn serve_webtransport(input: WebTransportServeInput) -> Result<(), BoxError> {
    let WebTransportServeInput {
        request,
        h3,
        connection,
        destination,
        bound_source,
        context,
        datagram_router,
        resolved_rx,
        setup,
        connection_ids,
    } = input;

    let H3RequestContext {
        state,
        claim,
        origin_port,
        origin_authority,
        sessions,
        pending_webtransport,
        tasks,
        ..
    } = context;

    let DatagramRouterState {
        router: datagram_router,
        task: datagram_task,
    } = datagram_router;

    let WebTransportRegistration {
        downstream_stream_id,
        upstream,
        datagram_task,
        tasks,
    } = register_webtransport_session(&sessions, &setup, &claim, datagram_task, tasks).await?;

    let AcceptedWebTransport {
        session,
        downstream_connect,
        tasks,
        datagram_task,
    } = accept_webtransport_for_binding(
        request,
        setup.downstream_stream,
        h3,
        setup.informational_responses,
        WebTransportAcceptCleanup {
            upstream: upstream.clone(),
            upstream_session_id: setup.upstream_session_id,
            datagram_task,
            tasks,
            response: setup.response,
        },
        downstream_stream_id,
        &sessions,
    )
    .await?;

    let cleanup_sessions = sessions.clone();
    let binding_id = downstream_stream_id;

    run_webtransport_association(
        session,
        WebTransportRoute {
            upstream: upstream.clone(),
            upstream_session_id: setup.upstream_session_id,
            downstream_stream_id,
            upstream_stream_id: setup.upstream_stream_id,
            binding_id,
            cancel: None,
            incoming_task: None,
        },
        setup.upstream_incoming,
        WebTransportAssociationConfig {
            state,
            origin_authority,
            claim,
            origin_port,
            sessions,
            pending_webtransport,
            datagram_router,
            downstream_connect,
            upstream_connect: setup.upstream_stream,
            tasks,
            resolved_rx,
            connection,
            destination,
            bound_source,
            connection_ids,
        },
        WebTransportAssociationCleanup {
            upstream,
            upstream_session_id: setup.upstream_session_id,
            sessions: cleanup_sessions,
            binding_id,
            datagram_task,
        },
    )
    .await
}

/// Start the accepted WebTransport association and run it to completion.
async fn run_webtransport_association(
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>,
    route: WebTransportRoute,
    upstream_incoming: IncomingWebTransportReceiver,
    config: WebTransportAssociationConfig,
    cleanup: WebTransportAssociationCleanup,
) -> Result<(), BoxError> {
    let StartedWebTransportAssociation {
        association,
        datagram_task,
    } = start_webtransport_association(session, route, upstream_incoming, config, cleanup).await?;

    let result = Box::pin(association.run()).await;
    stop_datagram_task(datagram_task).await;
    result
}

async fn register_webtransport_session(
    sessions: &SessionRegistry,
    setup: &WebTransportSetup,
    claim: &FlowClaim,
    datagram_task: tokio::task::JoinHandle<()>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
) -> Result<WebTransportRegistration, BoxError> {
    let downstream_stream_id = setup.downstream_stream.id();
    let upstream = setup.upstream.clone();

    let (_, datagram_task, tasks) = register_webtransport_binding(
        sessions,
        setup,
        claim,
        downstream_stream_id,
        datagram_task,
        tasks,
    )
    .await?;

    Ok(WebTransportRegistration {
        downstream_stream_id,
        upstream,
        datagram_task,
        tasks,
    })
}

async fn start_webtransport_association(
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>,
    first_route: WebTransportRoute,
    first_incoming: IncomingWebTransportReceiver,
    config: WebTransportAssociationConfig,
    cleanup: WebTransportAssociationCleanup,
) -> Result<StartedWebTransportAssociation, BoxError> {
    match Box::pin(WebTransportAssociation::new(
        session,
        first_route,
        first_incoming,
        config,
    ))
    .await
    {
        Ok(association) => Ok(StartedWebTransportAssociation {
            association,
            datagram_task: cleanup.datagram_task,
        }),

        Err(error) => {
            cleanup
                .upstream
                .unregister_webtransport_session(cleanup.upstream_session_id)
                .await;
            cleanup.sessions.remove(cleanup.binding_id).await;
            stop_datagram_task(cleanup.datagram_task).await;
            Err(error)
        }
    }
}

async fn register_webtransport_binding(
    sessions: &SessionRegistry,
    setup: &WebTransportSetup,
    claim: &FlowClaim,
    downstream_stream_id: StreamId,
    datagram_task: tokio::task::JoinHandle<()>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
) -> Result<
    (
        SessionBinding,
        tokio::task::JoinHandle<()>,
        Vec<tokio::task::JoinHandle<()>>,
    ),
    BoxError,
> {
    let binding = SessionBinding {
        key: session_key(
            &setup.semantic,
            &setup.normalized,
            SessionProtocol::WebTransport,
            claim.attribution_token.clone(),
        ),
        downstream_stream_id,
        upstream_stream_id: setup.upstream_stream_id,
    };

    if let Err(error) = sessions.set(&binding, &setup.normalized).await {
        sessions.remove(downstream_stream_id).await;

        setup
            .upstream
            .unregister_webtransport_session(setup.upstream_session_id)
            .await;

        stop_datagram_task(datagram_task).await;
        stop_h3_tasks(tasks).await;
        return Err(error);
    }

    Ok((binding, datagram_task, tasks))
}

struct WebTransportAcceptCleanup {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_session_id: h3::webtransport::SessionId,
    datagram_task: tokio::task::JoinHandle<()>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    response: http::Response<()>,
}

struct AcceptedWebTransport {
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>,
    downstream_connect: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    datagram_task: tokio::task::JoinHandle<()>,
}

async fn accept_webtransport_session(
    request: http::Request<()>,
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3: h3::server::Connection<h3_quinn::Connection, Bytes>,
    informational_responses: Vec<http::Response<()>>,

    cleanup: WebTransportAcceptCleanup,
) -> Result<AcceptedWebTransport, BoxError> {
    let mut stream = stream;

    let WebTransportAcceptCleanup {
        upstream,
        upstream_session_id,
        datagram_task,
        tasks,
        response,
    } = cleanup;

    for response in informational_responses {
        if let Err(error) = stream.send_response(response).await {
            upstream
                .unregister_webtransport_session(upstream_session_id)
                .await;

            stop_datagram_task(datagram_task).await;
            stop_h3_tasks(tasks).await;
            return Err(error.into());
        }
    }

    let mut session = match h3_webtransport::server::WebTransportSession::accept_with_response(
        request, stream, h3, response,
    )
    .await
    {
        Ok(session) => session,
        Err(error) => {
            upstream
                .unregister_webtransport_session(upstream_session_id)
                .await;
            stop_datagram_task(datagram_task).await;
            stop_h3_tasks(tasks).await;
            return Err(error.into());
        }
    };

    let Some(downstream_connect) = session.take_connect_stream() else {
        upstream
            .unregister_webtransport_session(upstream_session_id)
            .await;

        stop_datagram_task(datagram_task).await;
        stop_h3_tasks(tasks).await;
        return Err(boxed("WebTransport CONNECT stream already consumed"));
    };

    Ok(AcceptedWebTransport {
        session,
        downstream_connect,
        tasks,
        datagram_task,
    })
}

async fn accept_webtransport_for_binding(
    request: http::Request<()>,
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3: h3::server::Connection<h3_quinn::Connection, Bytes>,
    informational_responses: Vec<http::Response<()>>,
    cleanup: WebTransportAcceptCleanup,
    binding_id: StreamId,
    sessions: &SessionRegistry,
) -> Result<AcceptedWebTransport, BoxError> {
    match accept_webtransport_session(request, stream, h3, informational_responses, cleanup).await {
        Ok(accepted) => Ok(accepted),

        Err(error) => {
            sessions.remove(binding_id).await;
            Err(error)
        }
    }
}

pub(super) async fn prepare_webtransport(
    request: &http::Request<()>,
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: Http3RequestContext,
) -> Result<WebTransportSetup, BoxError> {
    let Http3RequestContext {
        state,
        claim,
        origin_port,
        origin_authority,
        upstream_destination,
        sessions,
        pending_webtransport,
        ..
    } = context;

    let (semantic, normalized, downstream_stream) = approve_webtransport_request(
        request,
        stream,
        &state,
        &claim,
        origin_port,
        origin_authority.as_deref(),
        &sessions,
    )
    .await?;

    let upstream_url = url::Url::parse(&normalized.url.to_string())?;

    let upstream_host = upstream_url
        .host_str()
        .ok_or_else(|| boxed("normalized policy target has no host"))?;

    let upstream_port = upstream_url
        .port_or_known_default()
        .ok_or_else(|| boxed("normalized policy target has no port"))?;

    let upstream_authority = crate::policy::authority_for_policy(upstream_host, upstream_port);

    let key = session_key(
        &semantic,
        &normalized,
        SessionProtocol::WebTransport,
        claim.attribution_token.clone(),
    );

    let downstream_stream_id = downstream_stream.id();

    let upstream_request = build_upstream_request(
        &semantic,
        &upstream_url,
        &upstream_authority,
        Some(key.protocol),
    )?;

    sessions.reserve(downstream_stream_id, &key).await?;

    let session_open = open_session_request(
        SessionOpenContext {
            state: &state,
            scheme: upstream_url.scheme(),
            authority: &upstream_authority,
            destination: upstream_destination,
            sessions: &sessions,
            pending_webtransport: &pending_webtransport,
        },
        &key,
        upstream_request,
        downstream_stream_id,
    )
    .await;

    let SessionOpen {
        upstream,
        stream: upstream_stream,
        mut informational_responses,
        mut response,
        upstream_incoming,
    } = match session_open {
        Ok(session_open) => session_open,
        Err(error) => {
            sessions.remove(downstream_stream_id).await;
            return Err(error);
        }
    };

    for informational_response in &mut informational_responses {
        crate::alt_svc::preserve_response_alt_svc(
            informational_response,
            &state.alt_svc,
            semantic.authority(),
        )
        .await;
    }

    crate::alt_svc::preserve_response_alt_svc(&mut response, &state.alt_svc, semantic.authority())
        .await;

    let Some(upstream_incoming) = upstream_incoming else {
        sessions.remove(downstream_stream_id).await;
        return Err(boxed("WebTransport session has no incoming stream route"));
    };

    let upstream_stream_id = upstream_stream.id();
    let upstream_session_id = h3::webtransport::SessionId::from(upstream_stream_id);

    Ok(WebTransportSetup {
        semantic,
        normalized,
        downstream_stream,
        informational_responses,
        response,
        upstream,
        upstream_session_id,
        upstream_incoming,
        upstream_stream_id,
        upstream_stream,
    })
}

async fn approve_webtransport_request(
    request: &http::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: &Http3State,
    claim: &FlowClaim,
    origin_port: Option<u16>,
    origin_authority: Option<&str>,
    sessions: &SessionRegistry,
) -> Result<
    (
        SemanticRequest,
        agent_sandbox_core::HttpRequest,
        RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ),
    BoxError,
> {
    // An alternative endpoint changes only the transport. The fallback
    // port for a port-less authority stays the origin's port.
    let fallback_port = origin_port.unwrap_or(state.destination_port);

    let semantic = match semantic_request(request, origin_authority, fallback_port) {
        Ok(semantic) => semantic,
        Err(error) => {
            stream.stop_sending(Code::H3_MESSAGE_ERROR);
            stream.stop_stream(Code::H3_MESSAGE_ERROR);
            return Err(error);
        }
    };

    if let Err(error) = wait_for_downstream_settings(&stream, SessionProtocol::WebTransport).await {
        stream.stop_sending(Code::H3_SETTINGS_ERROR);
        stream.stop_stream(Code::H3_SETTINGS_ERROR);
        return Err(error);
    }

    if let Some(normalized) = sessions
        .approved(
            &semantic,
            SessionProtocol::WebTransport,
            claim.attribution_token.clone(),
        )
        .await
    {
        return Ok((semantic, normalized, stream));
    }

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
        stream.stop_sending(Code::H3_REQUEST_REJECTED);
        stream.stop_stream(Code::H3_REQUEST_REJECTED);
        return Err(boxed("WebTransport request denied by policy"));
    };

    Ok((semantic, normalized, stream))
}

struct WebTransportAssociationConfig {
    state: Arc<Http3State>,
    claim: FlowClaim,
    origin_port: Option<u16>,
    origin_authority: Option<String>,
    sessions: Arc<SessionRegistry>,
    pending_webtransport: PendingWebTransportSessions,
    datagram_router: DatagramRouter,
    downstream_connect: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstream_connect: UpstreamRequestStream,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    resolved_rx: mpsc::UnboundedReceiver<ResolvedRequest>,
    connection: quinn::Connection,
    destination: SocketAddr,
    bound_source: SocketAddr,
    connection_ids: ConnectionIdBindings,
}

struct WebTransportAssociationCleanup {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_session_id: h3::webtransport::SessionId,
    sessions: Arc<SessionRegistry>,
    binding_id: StreamId,
    datagram_task: tokio::task::JoinHandle<()>,
}

struct StartedWebTransportAssociation {
    association: WebTransportAssociation,
    datagram_task: tokio::task::JoinHandle<()>,
}

struct WebTransportAssociation {
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>,
    connection: quinn::Connection,
    destination: SocketAddr,
    bound_source: SocketAddr,
    state: Arc<Http3State>,
    claim: FlowClaim,
    origin_port: Option<u16>,
    origin_authority: Option<String>,
    sessions: Arc<SessionRegistry>,
    pending_webtransport: PendingWebTransportSessions,
    datagram_router: DatagramRouter,
    resolved_rx: mpsc::UnboundedReceiver<ResolvedRequest>,
    route_error_rx: mpsc::UnboundedReceiver<(h3::webtransport::SessionId, String)>,
    route_error_tx: mpsc::UnboundedSender<(h3::webtransport::SessionId, String)>,
    incoming_rx: mpsc::Receiver<(StreamId, IncomingWebTransportStream)>,
    incoming_tx: mpsc::Sender<(StreamId, IncomingWebTransportStream)>,
    routes: HashMap<h3::webtransport::SessionId, WebTransportRoute>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    datagram_tasks: Vec<tokio::task::JoinHandle<Result<(), BoxError>>>,
    connection_ids: ConnectionIdBindings,
}

impl WebTransportAssociation {
    async fn new(
        session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>,
        first_route: WebTransportRoute,
        first_incoming: IncomingWebTransportReceiver,
        config: WebTransportAssociationConfig,
    ) -> Result<Self, BoxError> {
        let WebTransportAssociationConfig {
            state,
            claim,
            origin_port,
            origin_authority,
            sessions,
            pending_webtransport,
            datagram_router,
            downstream_connect,
            upstream_connect,
            mut tasks,
            resolved_rx,
            connection,
            destination,
            bound_source,
            connection_ids,
        } = config;

        let (route_error_tx, route_error_rx) = mpsc::unbounded_channel();
        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        let session_id = session.session_id();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut first_route = first_route;
        first_route.cancel = Some(cancel_tx);

        tasks.push(spawn_webtransport_connect_relay(
            downstream_connect,
            upstream_connect,
            cancel_rx,
            route_error_tx.clone(),
            session_id,
        ));

        let mut association = Self {
            session,
            connection,
            destination,
            bound_source,
            state,
            claim,
            origin_authority,
            origin_port,
            sessions,
            pending_webtransport,
            datagram_router,
            resolved_rx,
            route_error_rx,
            route_error_tx,
            incoming_rx,
            incoming_tx,
            routes: HashMap::new(),
            tasks,
            datagram_tasks: Vec::new(),
            connection_ids,
        };

        if let Err(error) = association
            .register_route(session_id, first_route, first_incoming)
            .await
        {
            stop_h3_tasks(association.tasks).await;
            return Err(error);
        }

        Ok(association)
    }

    async fn run(mut self) -> Result<(), BoxError> {
        let mut migration_tick = tokio::time::interval(Duration::from_millis(10));

        let result = loop {
            if let Err(error) = self.connection_ids.drain_or_close(&self.connection) {
                break Err(error);
            }

            tokio::select! {
                _ = migration_tick.tick() => {
                    if let Err(error) = rebind_migrated_path(
                        &self.connection,
                        &mut self.connection_ids,
                        &self.state.policy,
                        &self.claim,
                        self.destination,
                        &mut self.bound_source,
                    )
                    .await
                    {
                        break Err(error);
                    }
                }

                incoming = self.incoming_rx.recv() => {
                    let Some((binding_id, stream)) = incoming else {
                        break Err(boxed("upstream WebTransport session closed"));
                    };
                    if let Err(error) = self.handle_incoming_stream(binding_id, stream).await {
                        warn!(%error, "upstream WebTransport stream rejected");
                    }
                }
                () = self.state.shutdown.notified() => break Ok(()),
                accepted = self.session.accept_bi() => {
                    let accepted = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(BoxError::from(format!(
                            "WebTransport bidirectional stream failed: {error}"
                        ))),
                    };

                    let Some(accepted) = accepted else {
                        break Ok(());
                    };
                    if let Err(error) = Box::pin(self.handle_bi(accepted)).await {
                        warn!(%error, "WebTransport bidirectional stream rejected");
                    }
                }
                Some((session_id, error)) = self.route_error_rx.recv() => {
                    self.fail_route(session_id, error).await;
                }
                accepted = self.session.accept_uni() => {
                    let accepted = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(BoxError::from(format!(
                            "WebTransport unidirectional stream failed: {error}"
                        ))),
                    };

                    let Some((session_id, stream)) = accepted else {
                        break Ok(());
                    };
                    if let Err(error) = self.handle_uni(session_id, stream).await {
                        warn!(%error, "WebTransport unidirectional stream rejected");
                    }
                }
                Some(resolved) = self.resolved_rx.recv() => match resolved {
                    Ok((request, stream)) => {
                        if let Err(error) =
                            Box::pin(self.handle_request(request, stream)).await
                        {
                            warn!(%error, "WebTransport request rejected");
                        }
                    }
                    Err(error) => warn!(%error, "downstream HTTP/3 request resolution failed"),
                }
            }
        };

        self.finish().await;
        result
    }

    async fn handle_incoming_stream(
        &mut self,
        binding_id: StreamId,
        stream: IncomingWebTransportStream,
    ) -> Result<(), BoxError> {
        let session_id = self.routes.iter().find_map(|(session_id, route)| {
            (route.binding_id == binding_id).then_some(*session_id)
        });

        let Some(session_id) = session_id else {
            reject_webtransport_stream(stream);
            return Ok(());
        };

        match stream {
            IncomingWebTransportStream::Bidi(upstream) => {
                let mut cancel = self
                    .routes
                    .get(&session_id)
                    .and_then(|route| route.cancel.as_ref())
                    .expect("WebTransport route cancellation")
                    .subscribe();
                let downstream = self.session.open_bi(session_id).await?;
                self.tasks.push(tokio::spawn(async move {
                    tokio::select! {
                        result = relay_webtransport_bidi_reverse(downstream, *upstream) => {
                            if let Err(error) = result {
                                warn!(%error, "upstream WebTransport bidirectional stream relay failed");
                            }
                        }
                        _ = cancel.changed() => {}
                    }
                }));
            }

            IncomingWebTransportStream::Uni(mut upstream) => {
                let mut cancel = self
                    .routes
                    .get(&session_id)
                    .and_then(|route| route.cancel.as_ref())
                    .expect("WebTransport route cancellation")
                    .subscribe();
                let mut downstream = self.session.open_uni(session_id).await?;
                self.tasks.push(tokio::spawn(async move {
                    tokio::select! {
                        result = relay_quic_direction(&mut upstream, &mut downstream) => {
                            if let Err(error) = result {
                                warn!(%error, "upstream WebTransport unidirectional stream relay failed");
                            }
                        }
                        _ = cancel.changed() => {}
                    }
                }));
            }
        }

        Ok(())
    }

    async fn handle_bi(
        &mut self,
        accepted: h3_webtransport::server::AcceptedBi<h3_quinn::Connection, Bytes>,
    ) -> Result<(), BoxError> {
        match accepted {
            h3_webtransport::server::AcceptedBi::BidiStream(session_id, mut stream) => {
                let Some(route) = self.routes.get(&session_id) else {
                    stream.stop_sending(Code::H3_REQUEST_REJECTED.into());
                    stream.reset(Code::H3_REQUEST_REJECTED.value());
                    return Ok(());
                };
                let mut cancel = route
                    .cancel
                    .as_ref()
                    .expect("WebTransport route cancellation")
                    .subscribe();
                let upstream = route.upstream.clone();
                let upstream_session_id = route.upstream_session_id;
                let upstream_stream = upstream
                    .open_webtransport_stream(upstream_session_id)
                    .await?;
                let task = tokio::spawn(async move {
                    tokio::select! {
                        result = relay_webtransport_bidi(stream, upstream_stream) => {
                            if let Err(error) = result {
                                warn!(%error, "WebTransport stream relay failed");
                            }
                        }
                        _ = cancel.changed() => {}
                    }
                });
                self.tasks.push(task);
            }

            h3_webtransport::server::AcceptedBi::Request(request, stream) => {
                if let Err(error) = Box::pin(self.handle_request(request, stream)).await {
                    warn!(%error, "WebTransport request rejected");
                }
            }
        }

        Ok(())
    }

    async fn handle_uni(
        &mut self,
        session_id: h3::webtransport::SessionId,
        mut stream: h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>,
    ) -> Result<(), BoxError> {
        let Some(route) = self.routes.get(&session_id) else {
            stream.stop_sending(Code::H3_REQUEST_REJECTED.value());

            return Err(boxed(
                "WebTransport uni stream has an invalid session identifier",
            ));
        };

        let mut cancel = route
            .cancel
            .as_ref()
            .expect("WebTransport route cancellation")
            .subscribe();

        let upstream = route.upstream.clone();

        let upstream_stream = upstream
            .open_webtransport_uni_stream(route.upstream_session_id)
            .await?;

        let task = tokio::spawn(async move {
            tokio::select! {
                result = relay_webtransport_uni(stream, upstream_stream) => {
                    if let Err(error) = result {
                        warn!(%error, "WebTransport uni stream relay failed");
                    }
                }
                _ = cancel.changed() => {}
            }
        });

        self.tasks.push(task);
        Ok(())
    }

    async fn handle_request(
        &mut self,
        request: http::Request<()>,
        mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), BoxError> {
        if reject_0rtt_stream(&mut stream) {
            return Ok(());
        }

        if is_webtransport_request(&request) {
            return self.handle_webtransport_request(request, stream).await;
        }

        let downstream_stream_id = stream.id();

        let downstream_datagrams = if request
            .extensions()
            .get::<h3::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str() == "connect-udp")
        {
            Some(DatagramRelay {
                reader: self.datagram_router.register(downstream_stream_id).await,
                sender: self.session.datagram_sender_for(downstream_stream_id),
            })
        } else {
            None
        };

        let has_datagrams = downstream_datagrams.is_some();
        let datagram_router = has_datagrams.then(|| self.datagram_router.clone());

        let request_context = Http3RequestContext {
            state: self.state.clone(),
            claim: self.claim.clone(),
            destination: self.destination,
            upstream_destination: upstream_destination_for(
                self.origin_authority.as_deref(),
                self.origin_port,
                self.destination,
            ),
            origin_port: self.origin_port,
            origin_authority: self.origin_authority.clone(),
            sessions: self.sessions.clone(),
            pending_webtransport: self.pending_webtransport.clone(),
        };

        let task = tokio::spawn(async move {
            let result =
                serve_request(request, stream, request_context, downstream_datagrams).await;
            finish_h3_request(result, has_datagrams, datagram_router, downstream_stream_id).await;
        });

        self.tasks.push(task);
        Ok(())
    }

    async fn cleanup_webtransport_setup(
        &self,
        downstream_stream_id: StreamId,
        upstream: &Arc<crate::http3::upstream::UpstreamConnection>,
        upstream_session_id: h3::webtransport::SessionId,
    ) {
        self.sessions.remove(downstream_stream_id).await;

        self.pending_webtransport
            .remove_and_unregister(upstream, upstream_session_id)
            .await;
    }

    async fn accept_prepared_webtransport_request(
        &self,
        request: http::Request<()>,
        stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<AcceptedWebTransportRequest, BoxError> {
        let WebTransportSetup {
            semantic,
            normalized,
            downstream_stream,
            informational_responses,
            response,
            upstream,
            upstream_session_id,
            upstream_incoming,
            upstream_stream_id,
            upstream_stream,
        } = prepare_webtransport(&request, stream, Http3RequestContext {
            state: self.state.clone(),
            claim: self.claim.clone(),
            destination: self.destination,
            upstream_destination: upstream_destination_for(
                self.origin_authority.as_deref(),
                self.origin_port,
                self.destination,
            ),
            origin_port: self.origin_port,
            origin_authority: self.origin_authority.clone(),
            sessions: self.sessions.clone(),
            pending_webtransport: self.pending_webtransport.clone(),
        })
        .await?;

        let downstream_stream_id = downstream_stream.id();
        let cleanup_upstream = upstream.clone();
        let mut downstream_stream = downstream_stream;

        if let Err(error) =
            send_informational_responses(&mut downstream_stream, informational_responses).await
        {
            self.cleanup_webtransport_setup(
                downstream_stream_id,
                &cleanup_upstream,
                upstream_session_id,
            )
            .await;

            return Err(error);
        }

        let (session_id, downstream_stream) = match self
            .session
            .accept_request_with_response(request, downstream_stream, response)
            .await
        {
            Ok(accepted) => accepted,
            Err(error) => {
                self.cleanup_webtransport_setup(
                    downstream_stream_id,
                    &cleanup_upstream,
                    upstream_session_id,
                )
                .await;
                return Err(error.into());
            }
        };

        Ok(AcceptedWebTransportRequest {
            semantic,
            normalized,
            session_id,
            downstream_stream_id,
            downstream_stream,
            upstream,
            upstream_session_id,
            upstream_incoming,
            upstream_stream_id,
            upstream_stream,
        })
    }

    async fn handle_webtransport_request(
        &mut self,
        request: http::Request<()>,
        stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Result<(), BoxError> {
        if request.method() != http::Method::CONNECT {
            reject_webtransport_request(stream).await?;
            return Ok(());
        }

        if self.routes.len() >= MAX_WEBTRANSPORT_SESSIONS {
            let mut stream = stream;
            stream.stop_sending(Code::H3_REQUEST_REJECTED);
            stream.stop_stream(Code::H3_REQUEST_REJECTED);
            return Ok(());
        }

        let AcceptedWebTransportRequest {
            semantic,
            normalized,
            session_id,
            downstream_stream_id,
            downstream_stream,
            upstream,
            upstream_session_id,
            upstream_incoming,
            upstream_stream_id,
            upstream_stream,
        } = self
            .accept_prepared_webtransport_request(request, stream)
            .await?;

        let cleanup_upstream = upstream.clone();

        let binding = SessionBinding {
            key: session_key(
                &semantic,
                &normalized,
                SessionProtocol::WebTransport,
                self.claim.attribution_token.clone(),
            ),
            downstream_stream_id,
            upstream_stream_id,
        };

        if let Err(error) = self.sessions.set(&binding, &normalized).await {
            self.cleanup_webtransport_setup(
                downstream_stream_id,
                &cleanup_upstream,
                upstream_session_id,
            )
            .await;

            return Err(error);
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);

        if let Err(error) = self
            .register_route(
                session_id,
                WebTransportRoute {
                    upstream,
                    upstream_session_id,
                    downstream_stream_id,
                    upstream_stream_id,
                    binding_id: downstream_stream_id,
                    cancel: Some(cancel_tx),
                    incoming_task: None,
                },
                upstream_incoming,
            )
            .await
        {
            self.cleanup_webtransport_setup(
                downstream_stream_id,
                &cleanup_upstream,
                upstream_session_id,
            )
            .await;

            return Err(error);
        }

        self.pending_webtransport
            .remove(&cleanup_upstream, upstream_session_id);

        self.tasks.push(spawn_webtransport_connect_relay(
            downstream_stream,
            upstream_stream,
            cancel_rx,
            self.route_error_tx.clone(),
            session_id,
        ));

        Ok(())
    }

    async fn register_route(
        &mut self,
        session_id: h3::webtransport::SessionId,
        route: WebTransportRoute,
        mut upstream_incoming: IncomingWebTransportReceiver,
    ) -> Result<(), BoxError> {
        if self.routes.contains_key(&session_id) {
            return Err(boxed(
                "WebTransport session identifier is already registered",
            ));
        }

        let WebTransportRoute {
            upstream,
            upstream_session_id,
            downstream_stream_id,
            upstream_stream_id,
            binding_id,
            cancel,
            incoming_task: _,
        } = route;

        let cancel = cancel.ok_or_else(|| boxed("WebTransport route has no cancellation"))?;
        let downstream_reader = self.datagram_router.register(downstream_stream_id).await;
        let downstream_sender = self.session.datagram_sender_for(downstream_stream_id);
        let mut datagram_cancel = cancel.subscribe();
        let error_tx = self.route_error_tx.clone();
        let datagram_upstream = upstream.clone();

        let datagram_task = tokio::spawn(async move {
            let result = tokio::select! {
                result = relay_webtransport_datagrams(
                    downstream_reader,
                    downstream_sender,
                    datagram_upstream,
                    upstream_stream_id,
                ) => result,
                _ = datagram_cancel.changed() => Ok(()),
            };
            if let Err(error) = &result {
                let _ = error_tx.send((session_id, error.to_string()));
            }
            result
        });

        self.datagram_tasks.push(datagram_task);
        let incoming_tx = self.incoming_tx.clone();
        let incoming_error_tx = self.route_error_tx.clone();

        let incoming_task = tokio::spawn(async move {
            while let Some(stream) = upstream_incoming.recv().await {
                if incoming_tx.send((binding_id, stream)).await.is_err() {
                    return;
                }
            }
            let _ = incoming_error_tx.send((
                session_id,
                "upstream WebTransport session closed".to_owned(),
            ));
        });

        self.routes.insert(session_id, WebTransportRoute {
            upstream,
            upstream_session_id,
            downstream_stream_id,
            upstream_stream_id,
            binding_id,
            cancel: Some(cancel),
            incoming_task: Some(incoming_task),
        });

        Ok(())
    }

    async fn fail_route(&mut self, session_id: h3::webtransport::SessionId, error: String) {
        let Some(mut route) = self.routes.remove(&session_id) else {
            return;
        };

        warn!(%error, ?session_id, "WebTransport session failed");
        let _ = route.cancel.as_ref().map(|cancel| cancel.send(true));

        if let Some(task) = route.incoming_task.take() {
            task.abort();
            let _ = task.await;
        }

        self.datagram_router
            .unregister(route.downstream_stream_id)
            .await;

        route
            .upstream
            .unregister_webtransport_session(route.upstream_session_id)
            .await;

        self.sessions.remove(route.binding_id).await;
    }

    async fn finish(mut self) {
        stop_h3_tasks(self.tasks).await;

        for task in self.datagram_tasks {
            task.abort();
            let _ = task.await;
        }

        for (_, mut route) in self.routes.drain() {
            if let Some(task) = route.incoming_task.take() {
                task.abort();
                let _ = task.await;
            }

            self.datagram_router
                .unregister(route.downstream_stream_id)
                .await;

            route
                .upstream
                .unregister_webtransport_session(route.upstream_session_id)
                .await;

            self.sessions.remove(route.binding_id).await;
        }

        self.pending_webtransport.cleanup().await;
    }
}

fn spawn_webtransport_connect_relay(
    downstream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstream: UpstreamRequestStream,
    mut cancel: watch::Receiver<bool>,
    error_tx: mpsc::UnboundedSender<(h3::webtransport::SessionId, String)>,
    session_id: h3::webtransport::SessionId,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let result = tokio::select! {
            result = relay_webtransport_connect(downstream, upstream) => Some(result),
            _ = cancel.changed() => None,
        };
        if let Some(result) = result {
            let message = result.err().map_or_else(
                || "WebTransport CONNECT relay closed".to_owned(),
                |error| format!("WebTransport CONNECT relay failed: {error}"),
            );
            let _ = error_tx.send((session_id, message));
        }
    })
}

async fn stop_datagram_task(task: tokio::task::JoinHandle<()>) {
    task.abort();
    let _ = task.await;
}

async fn relay_webtransport_datagrams(
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
                let encoded = session::encode_http_datagram(upstream_stream_id, &payload)?;
                upstream.send_datagram(encoded)?;
            }
            datagram = upstream.recv_datagram() => {
                let datagram = datagram?;
                let payload = session::decode_http_datagram(&datagram, upstream_stream_id)?;
                downstream_sender
                    .send_datagram(payload)
                    .map_err(|error| BoxError::from(format!("downstream HTTP Datagram failed: {error}")))?;
            }
        }
    }
}

async fn relay_webtransport_bidi(
    downstream: h3_webtransport::stream::BidiStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstream: h3_quinn::BidiStream<Bytes>,
) -> Result<(), BoxError> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();
    let downstream_to_upstream = relay_quic_direction(&mut downstream_recv, &mut upstream_send);
    let upstream_to_downstream = relay_quic_direction(&mut upstream_recv, &mut downstream_send);
    tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
    Ok(())
}

async fn relay_webtransport_bidi_reverse(
    downstream: h3_webtransport::stream::BidiStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstream: h3_webtransport::stream::BidiStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();
    let downstream_to_upstream = relay_quic_direction(&mut downstream_recv, &mut upstream_send);
    let upstream_to_downstream = relay_quic_direction(&mut upstream_recv, &mut downstream_send);
    tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
    Ok(())
}

pub(super) fn reject_webtransport_stream(stream: IncomingWebTransportStream) {
    match stream {
        IncomingWebTransportStream::Bidi(mut stream) => {
            stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
            stream.reset(Code::H3_REQUEST_REJECTED.value());
        }

        IncomingWebTransportStream::Uni(mut stream) => {
            stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
        }
    }
}

async fn relay_webtransport_uni(
    mut downstream: h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>,
    mut upstream: h3_quinn::SendStream<Bytes>,
) -> Result<(), BoxError> {
    relay_quic_direction(&mut downstream, &mut upstream).await
}

async fn relay_quic_direction<R, S>(recv: &mut R, output: &mut S) -> Result<(), BoxError>
where
    R: h3::quic::RecvStream<Buf = Bytes>,
    S: h3::quic::SendStream<Bytes> + h3::quic::SendStreamUnframed<Bytes>,
{
    loop {
        let data = std::future::poll_fn(|context| recv.poll_data(context)).await?;

        let Some(mut data) = data else {
            std::future::poll_fn(|context| output.poll_finish(context)).await?;
            return Ok(());
        };

        while data.has_remaining() {
            let written =
                std::future::poll_fn(|context| output.poll_send(context, &mut data)).await?;

            if written == 0 {
                return Err(boxed("WebTransport stream made no send progress"));
            }
        }
    }
}

async fn relay_webtransport_connect(
    downstream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstream: UpstreamRequestStream,
) -> Result<(), BoxError> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();

    tokio::try_join!(
        relay_request_body(
            &mut downstream_recv,
            &mut upstream_send,
            Some(SessionProtocol::WebTransport),
            false,
            None,
        ),
        relay_webtransport_response_body(&mut upstream_recv, &mut downstream_send),
    )?;

    Ok(())
}

pub(super) async fn relay_webtransport_capsules(
    decoder: &mut session::CapsuleDecoder,
    chunk: &Bytes,
    send_stream: &mut h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    for capsule in decoder.push(chunk)? {
        send_stream
            .send_data(session::encode_capsule(capsule.kind, &capsule.payload))
            .await?;
    }

    Ok(())
}

async fn relay_webtransport_response_body(
    recv_response: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    let mut capsules = session::CapsuleDecoder::default();

    loop {
        match recv_response.recv_data().await {
            Ok(Some(chunk)) => {
                let mut chunk = chunk;
                let chunk = chunk.copy_to_bytes(chunk.remaining());
                relay_webtransport_response_capsules(&mut capsules, &chunk, stream).await?;
            }

            Ok(None) => break,

            Err(error) => {
                stream.stop_stream(map_stream_error(&error));
                return Err(BoxError::from(format!(
                    "upstream WebTransport body failed: {error}"
                )));
            }
        }
    }

    capsules.finish()?;

    if let Some(trailers) = recv_response.recv_trailers().await? {
        stream.send_trailers(trailers).await?;
    }

    stream.finish().await?;
    Ok(())
}

pub(super) async fn relay_webtransport_response_capsules(
    decoder: &mut session::CapsuleDecoder,
    chunk: &Bytes,
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
) -> Result<(), BoxError> {
    for capsule in decoder.push(chunk)? {
        stream
            .send_data(session::encode_capsule(capsule.kind, &capsule.payload))
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_webtransport_request;

    #[test]
    fn is_webtransport_request_detects_the_protocol_extension() {
        let request = http::Request::builder()
            .uri("https://example.test/path")
            .body(())
            .expect("valid request");
        assert!(!is_webtransport_request(&request));

        let mut request = request;
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::WEB_TRANSPORT);
        assert!(is_webtransport_request(&request));

        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_UDP);
        assert!(!is_webtransport_request(&request));
    }
}
