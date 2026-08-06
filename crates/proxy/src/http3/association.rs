//! Downstream QUIC association handling for the HTTP/3 backend.
//!
//! Each intercepted UDP association is claimed with policyd before the QUIC
//! handshake is accepted. Every HTTP/3 request stream is checked against
//! policy before any upstream connection is used. Denied or cancelled
//! streams are reset without closing other approved streams, and the
//! association claim is released when the connection completes.
//!
//! Associations that arrive at an `Alt-Svc` alternative endpoint are
//! attributed to the recorded origin before the flow is claimed. The
//! alternative host and port stay transport details: `:authority`, SNI,
//! certificate identity, policy identity, and the upstream pool keep using
//! the original origin. An association at an alternative endpoint whose
//! mapping is missing or expired is refused before any claim is made.

use crate::{
    alt_svc::AltSvcStore,
    http3::{
        BoxError, ConnectionIdOwner, Http3State,
        session::{self, SessionKey, SessionProtocol},
        upstream::{IncomingWebTransportReceiver, IncomingWebTransportStream},
    },
    policy::{FlowClaim, PendingPolicyCheck, PolicySession, normalize_authority},
    semantic::{
        BoundedRequestBody, HttpVersion, SemanticHeaders, SemanticRequest, SemanticRequestParts,
        is_hop_by_hop_header,
    },
};
use agent_sandbox_core::{AttributionToken, HttpCheckReply, HttpRequest, ProxyRequestId};
use bytes::{Buf, Bytes};
use h3::{
    ConnectionState,
    error::{Code, StreamError},
    quic::{BidiStream as _, RecvStream as _, SendStream as _, StreamId},
    server::RequestStream,
};
use h3_datagram::datagram_handler::{DatagramReader, DatagramSender, HandleDatagramsExt};
use h3_quinn::datagram::{RecvDatagramHandler, SendDatagramHandler};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tracing::{info, warn};

const MAX_WEBTRANSPORT_SESSIONS: usize = 64;
const MAX_INFORMATIONAL_RESPONSES: usize = 16;

/// Resolve the original destination for intercepted UDP associations.
#[derive(Clone)]
pub struct DestinationResolver {
    port: u16,
    test_destination: Option<SocketAddr>,
    alternative: bool,
}

impl DestinationResolver {
    /// Build a resolver for one listener.
    #[must_use]
    pub const fn new(port: u16, test_destination: Option<SocketAddr>, alternative: bool) -> Self {
        Self {
            port,
            test_destination,
            alternative,
        }
    }

    /// Whether this listener serves an alternative (non-primary) endpoint.
    #[must_use]
    pub const fn is_alternative(&self) -> bool {
        self.alternative
    }

    /// Resolve the original destination for one incoming association.
    pub fn resolve(&self, incoming: &quinn::Incoming) -> Result<SocketAddr, BoxError> {
        if let Some(destination) = self.test_destination {
            if self.alternative {
                return Ok(SocketAddr::new(destination.ip(), self.port));
            }

            return Ok(destination);
        }

        let ip = incoming.local_ip().ok_or_else(|| {
            warn!("intercepted QUIC association has no original destination");
            boxed("intercepted QUIC association has no original destination")
        })?;

        Ok(SocketAddr::new(ip, self.port))
    }
}

#[derive(Clone)]
struct SessionBinding {
    key: SessionKey,
    downstream_stream_id: StreamId,
    upstream_stream_id: StreamId,
}

/// Tracks the authenticated locally-issued CID set for one policy-owned
/// downstream association. Quinn itself rejects unknown CIDs before they can
/// reach this layer; this registry binds every accepted CID to the stable
/// Quinn connection handle and the policy connection identity.
struct ConnectionIdBindings {
    registry: Arc<crate::http3::ConnectionIdRegistry>,
    owner: ConnectionIdOwner,
    sequences: HashMap<u64, quinn::ConnectionId>,
}

impl ConnectionIdBindings {
    fn new(
        connection: &quinn::Connection,
        claim: &FlowClaim,
        registry: Arc<crate::http3::ConnectionIdRegistry>,
    ) -> Self {
        Self {
            registry,
            owner: ConnectionIdOwner {
                stable_id: connection.stable_id(),
                proxy_connection_id: claim.connection_id,
            },
            sequences: HashMap::new(),
        }
    }

    fn drain(&mut self, connection: &quinn::Connection) -> Result<(), BoxError> {
        while let Some(event) = connection.poll_connection_id_event() {
            match event {
                quinn::ConnectionIdEvent::Active { sequence, id } => {
                    if let Some(existing) = self.sequences.get(&sequence)
                        && *existing != id
                    {
                        return Err(boxed_owned(format!(
                            "QUIC connection-ID sequence {sequence} changed from {existing} to \
                             {id}"
                        )));
                    }
                    if !id.is_empty() {
                        self.registry.bind(id, self.owner).map_err(boxed_owned)?;
                    }
                    self.sequences.insert(sequence, id);
                    info!(
                        connection_id = %self.owner.proxy_connection_id,
                        stable_id = self.owner.stable_id,
                        sequence,
                        %id,
                        "QUIC connection ID bound to policy association"
                    );
                }
                quinn::ConnectionIdEvent::Retired { sequence, id } => {
                    self.retire(sequence, id)?;
                    info!(
                        connection_id = %self.owner.proxy_connection_id,
                        stable_id = self.owner.stable_id,
                        sequence,
                        %id,
                        "QUIC connection ID released from policy association"
                    );
                }
                quinn::ConnectionIdEvent::Removed { sequence, id } => {
                    self.remove(sequence, id);
                    info!(
                        connection_id = %self.owner.proxy_connection_id,
                        stable_id = self.owner.stable_id,
                        sequence,
                        %id,
                        "QUIC connection ID removed from policy association"
                    );
                }
            }
        }

        Ok(())
    }

    fn drain_or_close(&mut self, connection: &quinn::Connection) -> Result<(), BoxError> {
        if let Err(error) = self.drain(connection) {
            connection.close(varint(Code::H3_INTERNAL_ERROR), b"QUIC CID registry failed");
            return Err(error);
        }
        Ok(())
    }

    fn retire(&mut self, sequence: u64, id: quinn::ConnectionId) -> Result<(), BoxError> {
        let Some(existing) = self.sequences.remove(&sequence) else {
            return Err(boxed_owned(format!(
                "unknown QUIC connection-ID retirement for sequence {sequence} ({id})"
            )));
        };
        if existing != id {
            return Err(boxed_owned(format!(
                "QUIC connection-ID sequence {sequence} retired as {id}, expected {existing}"
            )));
        }

        if !id.is_empty() {
            self.registry.unbind(id, self.owner).map_err(boxed_owned)?;
        }
        Ok(())
    }

    /// Teardown events are best-effort and idempotent: the owner cleanup also
    /// runs when the association task is dropped.
    fn remove(&mut self, sequence: u64, id: quinn::ConnectionId) {
        self.sequences.remove(&sequence);
        if !id.is_empty() {
            let _ = self.registry.unbind(id, self.owner);
        }
    }
}

impl Drop for ConnectionIdBindings {
    fn drop(&mut self) {
        for (&sequence, id) in &self.sequences {
            info!(
                connection_id = %self.owner.proxy_connection_id,
                stable_id = self.owner.stable_id,
                sequence,
                %id,
                "QUIC connection ID removed from policy association"
            );
        }
        self.registry.remove_owner(self.owner);
    }
}

type UpstreamRequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

struct SessionOpen {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    stream: UpstreamRequestStream,
    informational_responses: Vec<http::Response<()>>,
    response: http::Response<()>,
    upstream_incoming: Option<IncomingWebTransportReceiver>,
}

struct SessionOpenContext<'a> {
    state: &'a Http3State,
    scheme: &'a str,
    authority: &'a str,
    destination: Option<SocketAddr>,
    sessions: &'a SessionRegistry,
    pending_webtransport: &'a PendingWebTransportSessions,
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

struct WebTransportRoute {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_session_id: h3::webtransport::SessionId,
    downstream_stream_id: StreamId,
    upstream_stream_id: StreamId,
    binding_id: StreamId,
    cancel: Option<watch::Sender<bool>>,
    incoming_task: Option<tokio::task::JoinHandle<()>>,
}

struct WebTransportSetup {
    semantic: SemanticRequest,
    normalized: agent_sandbox_core::HttpRequest,
    downstream_stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    informational_responses: Vec<http::Response<()>>,
    response: http::Response<()>,
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    upstream_session_id: h3::webtransport::SessionId,
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

type RoutedDatagram = Result<Bytes, String>;

struct DatagramRelay {
    reader: mpsc::Receiver<RoutedDatagram>,
    sender: DatagramSender<SendDatagramHandler, Bytes>,
}

#[derive(Clone)]
struct DatagramRouter {
    routes: Arc<Mutex<HashMap<StreamId, mpsc::Sender<RoutedDatagram>>>>,
}

struct DatagramRouterState {
    router: DatagramRouter,
    task: tokio::task::JoinHandle<()>,
}

impl DatagramRouter {
    fn start(mut reader: DatagramReader<RecvDatagramHandler>) -> DatagramRouterState {
        let routes: Arc<Mutex<HashMap<StreamId, mpsc::Sender<RoutedDatagram>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let task_routes = routes.clone();

        let task = tokio::spawn(async move {
            loop {
                let datagram = match reader.read_datagram().await {
                    Ok(datagram) => datagram,
                    Err(error) => {
                        let senders = {
                            let mut routes = task_routes.lock().await;
                            routes.drain().map(|(_, sender)| sender).collect::<Vec<_>>()
                        };
                        let message = format!("downstream HTTP Datagram failed: {error}");
                        for sender in senders {
                            let _ = sender.send(Err(message.clone())).await;
                        }
                        break;
                    }
                };
                let stream_id = datagram.stream_id();
                let payload = datagram.into_payload();
                let sender = task_routes.lock().await.get(&stream_id).cloned();
                let Some(sender) = sender else {
                    continue;
                };

                if sender.send(Ok(payload)).await.is_err() {
                    task_routes.lock().await.remove(&stream_id);
                }
            }
        });

        DatagramRouterState {
            router: Self { routes },
            task,
        }
    }

    async fn register(&self, stream_id: StreamId) -> mpsc::Receiver<RoutedDatagram> {
        let (sender, receiver) = mpsc::channel(64);
        self.routes.lock().await.insert(stream_id, sender);
        receiver
    }

    async fn unregister(&self, stream_id: StreamId) {
        self.routes.lock().await.remove(&stream_id);
    }
}

type ResolvedRequestValue = (
    http::Request<()>,
    RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
);

type ResolvedRequest = Result<ResolvedRequestValue, StreamError>;

struct WebTransportPrep {
    request: http::Request<()>,
    setup: Result<WebTransportSetup, BoxError>,
}

#[derive(Clone, Default)]
struct PendingWebTransportSessions {
    sessions: Arc<std::sync::Mutex<Vec<PendingWebTransportSession>>>,
}

struct PendingWebTransportSession {
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    session_id: h3::webtransport::SessionId,
}

impl PendingWebTransportSessions {
    fn insert(
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

    fn remove(
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

    async fn remove_and_unregister(
        &self,
        upstream: &Arc<crate::http3::upstream::UpstreamConnection>,
        session_id: h3::webtransport::SessionId,
    ) {
        self.remove(upstream, session_id);
        upstream.unregister_webtransport_session(session_id).await;
    }

    async fn cleanup(&self) {
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

struct ApprovedSession {
    normalized: HttpRequest,
}

#[derive(Default)]
struct SessionRegistry {
    leases: Mutex<HashMap<StreamId, SessionKey>>,
    approvals: Mutex<HashMap<SessionKey, ApprovedSession>>,
}

impl SessionRegistry {
    async fn reserve(
        &self,
        downstream_stream_id: StreamId,
        key: &SessionKey,
    ) -> Result<(), BoxError> {
        let mut leases = self.leases.lock().await;

        if let Some(existing) = leases.get(&downstream_stream_id)
            && existing != key
        {
            return Err("HTTP/3 session identity changed during reconnect".into());
        }

        leases.insert(downstream_stream_id, key.clone());
        drop(leases);
        Ok(())
    }

    async fn validate(
        &self,
        downstream_stream_id: StreamId,
        key: &SessionKey,
    ) -> Result<(), BoxError> {
        let leases = self.leases.lock().await;

        if leases.get(&downstream_stream_id) == Some(key) {
            drop(leases);
            return Ok(());
        }

        drop(leases);
        Err("HTTP/3 session identity changed during reconnect".into())
    }

    async fn approved(
        &self,
        semantic: &SemanticRequest,
        protocol: SessionProtocol,
        attribution: agent_sandbox_core::AttributionToken,
    ) -> Option<HttpRequest> {
        let target = semantic.policy_request().ok()?.url.to_string();

        let key = SessionKey {
            origin: semantic.authority().to_owned(),
            target,
            protocol,
            attribution,
        };

        let approvals = self.approvals.lock().await;
        let normalized = approvals.get(&key)?.normalized.clone();
        drop(approvals);
        Some(normalized)
    }

    async fn set(
        &self,
        binding: &SessionBinding,
        normalized: &HttpRequest,
    ) -> Result<(), BoxError> {
        let downstream_datagram = session::encode_http_datagram(binding.downstream_stream_id, &[])?;
        session::decode_http_datagram(&downstream_datagram, binding.downstream_stream_id)?;
        let upstream_datagram = session::encode_http_datagram(binding.upstream_stream_id, &[])?;
        session::decode_http_datagram(&upstream_datagram, binding.upstream_stream_id)?;

        self.reserve(binding.downstream_stream_id, &binding.key)
            .await?;

        self.approvals
            .lock()
            .await
            .insert(binding.key.clone(), ApprovedSession {
                normalized: normalized.clone(),
            });

        Ok(())
    }

    async fn remove(&self, downstream_stream_id: StreamId) {
        let (key, remove_approval) = {
            let mut leases = self.leases.lock().await;
            let key = leases.remove(&downstream_stream_id);
            let remove_approval = key
                .as_ref()
                .is_some_and(|key| !leases.values().any(|lease| lease == key));
            drop(leases);
            (key, remove_approval)
        };

        if remove_approval && let Some(key) = key {
            self.approvals.lock().await.remove(&key);
        }
    }
}

fn session_key(
    semantic: &SemanticRequest,
    normalized: &agent_sandbox_core::HttpRequest,
    protocol: SessionProtocol,
    attribution: agent_sandbox_core::AttributionToken,
) -> SessionKey {
    SessionKey {
        origin: semantic.authority().to_owned(),
        target: normalized.url.to_string(),
        protocol,
        attribution,
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
            if let Err(error) = Box::pin(serve_incoming(incoming, state, destination)).await {
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

    let destination_address = match destination.resolve(&incoming) {
        Ok(destination) => destination,
        Err(error) => {
            incoming.refuse();
            return Err(error);
        }
    };

    // An alternative endpoint carries no origin identity of its own. Resolve
    // the recorded origin before claiming the flow so an unmapped or expired
    // alternative fails closed without touching policy state.
    let (origin_authority, origin_port) = if destination.is_alternative() {
        let Some(origin_authority) = state
            .alt_svc
            .origin_for(destination_address.ip(), destination_address.port())
        else {
            warn!(
                %source,
                %destination_address,
                "refusing QUIC association at unmapped alternative endpoint"
            );
            incoming.refuse();
            return Ok(());
        };
        let origin_port = url::Url::parse(&format!("http://{origin_authority}/"))?
            .port()
            .unwrap_or(state.destination_port);

        info!(
            %source,
            %destination_address,
            origin = %origin_authority,
            origin_port,
            "attributed alternative QUIC endpoint to its origin"
        );

        (Some(origin_authority), Some(origin_port))
    } else {
        (None, None)
    };

    let claim = match state
        .policy
        .claim_udp_redirected(source, destination_address.port())
        .await
    {
        Ok(claim) => claim,
        Err(error) => {
            incoming.refuse();
            return Err(error.into());
        }
    };

    let destination_address = SocketAddr::new(
        claim.flow.destination_ip(),
        claim.flow.destination_port().get(),
    );

    info!(
        %source,
        destination = %destination_address,
        "claimed downstream QUIC association"
    );

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

    let result = Box::pin(serve_h3_connection(
        connection,
        state.clone(),
        claim.clone(),
        source,
        destination_address,
        origin_port,
        origin_authority,
    ))
    .await;

    release_claim(&state.policy, &claim).await;
    result
}

struct H3RequestContext {
    state: Arc<Http3State>,
    claim: FlowClaim,
    destination: SocketAddr,
    origin_port: Option<u16>,
    origin_authority: Option<String>,
    sessions: Arc<SessionRegistry>,
    pending_webtransport: PendingWebTransportSessions,
    datagram_router: Option<DatagramRouterState>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

fn new_h3_request_context(
    state: Arc<Http3State>,
    claim: FlowClaim,
    destination: SocketAddr,
    origin_port: Option<u16>,
    origin_authority: Option<String>,
) -> H3RequestContext {
    H3RequestContext {
        state,
        claim,
        destination,
        origin_port,
        origin_authority,
        sessions: Arc::new(SessionRegistry::default()),
        pending_webtransport: PendingWebTransportSessions::default(),
        datagram_router: None,
        tasks: Vec::new(),
    }
}

#[derive(Clone)]
struct Http3RequestContext {
    state: Arc<Http3State>,
    claim: FlowClaim,
    destination: SocketAddr,
    upstream_destination: Option<SocketAddr>,
    origin_port: Option<u16>,
    origin_authority: Option<String>,
    sessions: Arc<SessionRegistry>,
    pending_webtransport: PendingWebTransportSessions,
}

/// Resolve the transport address for the upstream connection.
///
/// Primary flows route to the claimed destination. Alternative flows route
/// to the alternative's address (the origin's own address) with the recorded
/// origin port; the origin authority still supplies the TLS identity.
fn upstream_destination_for(
    origin_authority: Option<&str>,
    origin_port: Option<u16>,
    destination: SocketAddr,
) -> Option<SocketAddr> {
    match origin_authority {
        Some(_) => origin_port.map(|port| SocketAddr::new(destination.ip(), port)),
        None => Some(destination),
    }
}

impl H3RequestContext {
    async fn serve(
        &mut self,
        request: http::Request<()>,
        mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        h3: &h3::server::Connection<h3_quinn::Connection, Bytes>,
    ) {
        if reject_0rtt_stream(&mut stream) {
            return;
        }

        let downstream_stream_id = stream.id();

        let downstream_datagrams = if request
            .extensions()
            .get::<h3::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str() == "connect-udp")
        {
            if self.datagram_router.is_none() {
                let datagram_state = DatagramRouter::start(h3.get_datagram_reader());
                self.datagram_router = Some(datagram_state);
            }
            let router = &self
                .datagram_router
                .as_ref()
                .expect("router initialised")
                .router;
            Some(DatagramRelay {
                reader: router.register(downstream_stream_id).await,
                sender: h3.get_datagram_sender(downstream_stream_id),
            })
        } else {
            None
        };

        let has_datagrams = downstream_datagrams.is_some();

        let datagram_router = self
            .datagram_router
            .as_ref()
            .map(|state| state.router.clone());

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
    }

    const fn take_datagram_router(&mut self) -> DatagramRouterState {
        self.datagram_router
            .take()
            .expect("WebTransport datagram router")
    }
}

fn reject_0rtt_stream(stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>) -> bool {
    if !stream.is_0rtt() {
        return false;
    }

    stream.stop_stream(Code::H3_REQUEST_REJECTED);
    true
}

async fn reject_webtransport_request(
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

fn queue_webtransport_preparation(
    request_context: &mut H3RequestContext,
    h3: &h3::server::Connection<h3_quinn::Connection, Bytes>,
    request: http::Request<()>,
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    prepare_tx: &mpsc::UnboundedSender<WebTransportPrep>,
) -> tokio::task::JoinHandle<()> {
    let datagram_router = request_context
        .datagram_router
        .take()
        .unwrap_or_else(|| DatagramRouter::start(h3.get_datagram_reader()));

    request_context.datagram_router = Some(datagram_router);
    let prepare_tx = prepare_tx.clone();

    let request_context = Http3RequestContext {
        state: request_context.state.clone(),
        claim: request_context.claim.clone(),
        destination: request_context.destination,
        upstream_destination: upstream_destination_for(
            request_context.origin_authority.as_deref(),
            request_context.origin_port,
            request_context.destination,
        ),
        origin_port: request_context.origin_port,
        origin_authority: request_context.origin_authority.clone(),
        sessions: request_context.sessions.clone(),
        pending_webtransport: request_context.pending_webtransport.clone(),
    };

    tokio::spawn(async move {
        let setup = prepare_webtransport(&request, stream, request_context).await;
        let _ = prepare_tx.send(WebTransportPrep { request, setup });
    })
}

async fn build_h3_server(
    connection: &quinn::Connection,
) -> Result<h3::server::Connection<h3_quinn::Connection, Bytes>, BoxError> {
    let h3 = h3_quinn::Connection::new(connection.clone());
    let mut builder = h3::server::builder();

    builder
        .enable_extended_connect(true)
        .enable_webtransport(true)
        .enable_datagram(true)
        .max_webtransport_sessions(
            u64::try_from(MAX_WEBTRANSPORT_SESSIONS)
                .expect("WebTransport session limit fits in u64"),
        );

    match builder.build(h3).await {
        Ok(h3) => Ok(h3),

        Err(error) => {
            connection.close(varint(Code::H3_INTERNAL_ERROR), b"http3 setup failed");
            Err(format!("HTTP/3 setup failed: {error}").into())
        }
    }
}

fn is_webtransport_request(request: &http::Request<()>) -> bool {
    request
        .extensions()
        .get::<h3::ext::Protocol>()
        .is_some_and(|protocol| protocol.as_str() == "webtransport")
}

async fn serve_h3_connection(
    connection: quinn::Connection,
    state: Arc<Http3State>,
    claim: FlowClaim,
    source: SocketAddr,
    destination: SocketAddr,
    origin_port: Option<u16>,
    origin_authority: Option<String>,
) -> Result<(), BoxError> {
    let mut h3 = build_h3_server(&connection).await?;
    let mut connection_ids =
        ConnectionIdBindings::new(&connection, &claim, state.connection_ids.clone());
    connection_ids.drain_or_close(&connection)?;

    let mut bound_source = source;

    let mut request_context =
        new_h3_request_context(state, claim, destination, origin_port, origin_authority);

    let (resolved_tx, mut resolved_rx) = mpsc::unbounded_channel::<ResolvedRequest>();
    let (webtransport_tx, mut webtransport_rx) = mpsc::unbounded_channel::<WebTransportPrep>();
    let mut webtransport_pending = false;
    let mut migration_tick = tokio::time::interval(Duration::from_millis(10));

    let result = loop {
        if let Err(error) = rebind_migrated_path(
            &connection,
            &mut connection_ids,
            &request_context.state.policy,
            &request_context.claim,
            destination,
            &mut bound_source,
        )
        .await
        {
            break Err(error);
        }

        tokio::select! {
            () = request_context.state.shutdown.notified() => break Ok(()),
            _ = migration_tick.tick() => {}
            accepted = h3.accept() => match accepted {
                Ok(Some(resolver)) => {
                    request_context.tasks.push(spawn_h3_request_resolution(
                        resolver,
                        resolved_tx.clone(),
                    ));
                }
                Ok(None) => break Ok(()),
                Err(error) => {
                    info!(%error, "downstream HTTP/3 connection closed");
                    break Ok(());
                }
            },
            Some(WebTransportPrep { request, setup }) = webtransport_rx.recv(),
                if webtransport_pending => {
                webtransport_pending = false;
                let datagram_router = request_context.take_datagram_router();
                match setup {
                    Ok(setup) => {
                        request_context
                            .pending_webtransport
                            .remove(&setup.upstream, setup.upstream_session_id);
                        let input = WebTransportServeInput {
                            request,
                            h3,
                            connection: connection.clone(),
                            destination,
                            bound_source,
                            context: request_context,
                            datagram_router,
                            resolved_rx,
                            setup,
                            connection_ids,
                        };

                        let result = Box::pin(serve_webtransport(input)).await;
                        connection.close(varint(Code::H3_NO_ERROR), b"proxy shutdown");
                        return result;
                    }
                    Err(error) => {
                        warn!(%error, "downstream WebTransport request rejected");
                        request_context.datagram_router = Some(datagram_router);
                    }
                }
            },
            Some(resolved) = resolved_rx.recv(), if !webtransport_pending => {
                if handle_resolved_request(resolved, &mut request_context, &h3, &webtransport_tx)
                    .await
                {
                    webtransport_pending = true;
                }
            }
        }
    };

    connection_ids.drain_or_close(&connection)?;

    finish_h3_connection(&mut request_context).await;
    connection.close(varint(Code::H3_NO_ERROR), b"proxy shutdown");
    result
}

async fn finish_h3_connection(request_context: &mut H3RequestContext) {
    stop_h3_tasks(std::mem::take(&mut request_context.tasks)).await;

    if let Some(datagram_state) = request_context.datagram_router.take() {
        datagram_state.task.abort();
        let _ = datagram_state.task.await;
    }

    request_context.pending_webtransport.cleanup().await;
}

async fn stop_h3_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}

fn spawn_h3_request_resolution(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    resolved_tx: mpsc::UnboundedSender<ResolvedRequest>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = resolved_tx.send(resolver.resolve_request().await);
    })
}

fn resolved_request(resolved: ResolvedRequest) -> Option<ResolvedRequestValue> {
    match resolved {
        Ok(request) => Some(request),

        Err(error) => {
            warn!(%error, "downstream HTTP/3 request resolution failed");
            None
        }
    }
}

/// Dispatch one accepted downstream HTTP/3 request.
///
/// Returns whether a WebTransport preparation was queued, which gates further
/// resolved-request handling until the preparation completes.
async fn handle_resolved_request(
    resolved: ResolvedRequest,
    request_context: &mut H3RequestContext,
    h3: &h3::server::Connection<h3_quinn::Connection, Bytes>,
    webtransport_tx: &mpsc::UnboundedSender<WebTransportPrep>,
) -> bool {
    let Some((request, mut stream)) = resolved_request(resolved) else {
        return false;
    };

    if reject_0rtt_stream(&mut stream) {
        return false;
    }

    if is_webtransport_request(&request) {
        if request.method() != http::Method::CONNECT {
            if let Err(error) = reject_webtransport_request(stream).await {
                warn!(%error, "malformed WebTransport request rejected");
            }
            return false;
        }

        let task =
            queue_webtransport_preparation(request_context, h3, request, stream, webtransport_tx);
        request_context.tasks.push(task);
        return true;
    }

    request_context.serve(request, stream, h3).await;
    false
}

async fn rebind_migrated_path(
    connection: &quinn::Connection,
    connection_ids: &mut ConnectionIdBindings,
    policy: &PolicySession,
    claim: &FlowClaim,
    destination: SocketAddr,
    bound_source: &mut SocketAddr,
) -> Result<(), BoxError> {
    connection_ids.drain_or_close(connection)?;
    let source = connection.remote_address();

    if source == *bound_source {
        return Ok(());
    }

    let flow = crate::policy::udp_flow_key(source, destination)?;

    if let Err(error) = policy.rebind(claim, flow).await {
        connection.close(varint(Code::H3_INTERNAL_ERROR), b"QUIC path rebind failed");
        return Err(error.into());
    }

    *bound_source = source;
    Ok(())
}

async fn finish_h3_request(
    result: Result<(), BoxError>,
    has_datagrams: bool,
    datagram_router: Option<DatagramRouter>,
    downstream_stream_id: StreamId,
) {
    if has_datagrams && let Some(router) = datagram_router {
        router.unregister(downstream_stream_id).await;
    }

    if let Err(error) = result {
        warn!(%error, "downstream HTTP/3 stream failed");
    }
}

struct WebTransportServeInput {
    request: http::Request<()>,
    h3: h3::server::Connection<h3_quinn::Connection, Bytes>,
    connection: quinn::Connection,
    destination: SocketAddr,
    bound_source: SocketAddr,
    context: H3RequestContext,
    datagram_router: DatagramRouterState,
    resolved_rx: mpsc::UnboundedReceiver<ResolvedRequest>,
    setup: WebTransportSetup,
    connection_ids: ConnectionIdBindings,
}

struct WebTransportRegistration {
    downstream_stream_id: StreamId,
    upstream: Arc<crate::http3::upstream::UpstreamConnection>,
    datagram_task: tokio::task::JoinHandle<()>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn release_claim(policy: &PolicySession, claim: &FlowClaim) {
    if let Err(error) = policy.release(claim).await {
        tracing::error!(%error, "failed to release downstream QUIC association claim");
    }
}

async fn serve_webtransport(input: WebTransportServeInput) -> Result<(), BoxError> {
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

async fn prepare_webtransport(
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
    let semantic = match semantic_request(request, state, origin_port, origin_authority) {
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

async fn stop_datagram_task(task: tokio::task::JoinHandle<()>) {
    task.abort();
    let _ = task.await;
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

fn reject_webtransport_stream(stream: IncomingWebTransportStream) {
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

async fn wait_for_downstream_settings(
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

async fn serve_request(
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

    let semantic =
        match semantic_request(&request, &state, origin_port, origin_authority.as_deref()) {
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
        let mut stream = stream;
        stream.stop_sending(Code::H3_REQUEST_REJECTED);
        stream.stop_stream(Code::H3_REQUEST_REJECTED);
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

async fn authorize_request(
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

            return Ok(None);
        };

        return Ok(Some(normalized));
    };

    Ok(Some(reused))
}

fn semantic_request(
    request: &http::Request<()>,
    state: &Http3State,
    origin_port: Option<u16>,
    origin_authority: Option<&str>,
) -> Result<SemanticRequest, BoxError> {
    let uri = request.uri();

    let authority = uri
        .authority()
        .ok_or_else(|| boxed("HTTP/3 request has no :authority"))?;

    // An alternative endpoint changes only the transport; the fallback port
    // for a port-less authority stays the origin's port.
    let fallback_port = origin_port.unwrap_or(state.destination_port);

    let request_authority = normalize_authority(authority.as_str(), fallback_port)?;

    let authority = if let Some(origin_authority) = origin_authority {
        let origin_authority = normalize_authority(origin_authority, fallback_port)?;
        if request_authority != origin_authority {
            return Err(boxed("HTTP/3 authority does not match its origin"));
        }
        origin_authority
    } else {
        request_authority
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

        if normalize_authority(host, fallback_port)? != authority {
            return Err(boxed("HTTP/3 Host header does not match :authority"));
        }
    }

    Ok(SemanticRequest::from_parts(SemanticRequestParts {
        method: request.method().as_str(),
        scheme,
        authority: &authority,
        path: uri.path(),
        raw_query: uri.query(),
        headers,
        source_version: HttpVersion::Http3,
        target_version: HttpVersion::Http3,
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
                .connect_dedicated_to(scheme, authority, destination)
                .await?
        }
        (true, None) => state.upstream.connect_dedicated(scheme, authority).await?,
        (false, Some(destination)) => {
            state
                .upstream
                .connect_to(scheme, authority, destination, security_context)
                .await?
        }
        (false, None) => {
            state
                .upstream
                .connect(scheme, authority, security_context)
                .await?
        }
    };

    if let Some(protocol) = protocol {
        upstream.require_session_settings(protocol).await?;
    }

    Ok(upstream)
}

async fn open_session_request(
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

fn build_upstream_request(
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

async fn relay_request_body(
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

async fn relay_webtransport_capsules(
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

async fn relay_webtransport_response_capsules(
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

fn boxed_owned(message: impl Into<String>) -> BoxError {
    std::io::Error::other(message.into()).into()
}

fn varint(code: Code) -> quinn::VarInt {
    quinn::VarInt::from_u64(code.value()).expect("HTTP/3 error codes fit in VarInt")
}
