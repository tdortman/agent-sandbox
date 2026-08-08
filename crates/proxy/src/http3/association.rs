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
    http3::{
        BoxError, Http3State, boxed,
        connection_id::ConnectionIdBindings,
        datagram::{DatagramRelay, DatagramRouter, DatagramRouterState},
        relay::serve_request,
        session_registry::SessionRegistry,
        varint,
        webtransport::{
            PendingWebTransportSessions, WebTransportPrep, WebTransportServeInput,
            is_webtransport_request, prepare_webtransport, reject_webtransport_request,
            serve_webtransport,
        },
    },
    policy::{FlowClaim, PolicySession},
};

use bytes::Bytes;

use h3::{
    error::{Code, StreamError},
    quic::StreamId,
    server::RequestStream,
};

use h3_datagram::datagram_handler::HandleDatagramsExt;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{info, warn};

pub(super) const MAX_WEBTRANSPORT_SESSIONS: usize = 64;
pub(super) const MAX_INFORMATIONAL_RESPONSES: usize = 16;

pub(super) type ResolvedRequestValue = (
    http::Request<()>,
    RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
);

pub(super) type ResolvedRequest = Result<ResolvedRequestValue, StreamError>;

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

pub(super) struct H3RequestContext {
    pub(super) state: Arc<Http3State>,
    pub(super) claim: FlowClaim,
    pub(super) destination: SocketAddr,
    pub(super) origin_port: Option<u16>,
    pub(super) origin_authority: Option<String>,
    pub(super) sessions: Arc<SessionRegistry>,
    pub(super) pending_webtransport: PendingWebTransportSessions,
    pub(super) datagram_router: Option<DatagramRouterState>,
    pub(super) tasks: Vec<tokio::task::JoinHandle<()>>,
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
pub(super) struct Http3RequestContext {
    pub(super) state: Arc<Http3State>,
    pub(super) claim: FlowClaim,
    pub(super) destination: SocketAddr,
    pub(super) upstream_destination: Option<SocketAddr>,
    pub(super) origin_port: Option<u16>,
    pub(super) origin_authority: Option<String>,
    pub(super) sessions: Arc<SessionRegistry>,
    pub(super) pending_webtransport: PendingWebTransportSessions,
}

/// Resolve the transport address for the upstream connection.
///
/// Primary flows route to the claimed destination. Alternative flows route
/// to the alternative's address (the origin's own address) with the recorded
/// origin port; the origin authority still supplies the TLS identity.
pub(super) fn upstream_destination_for(
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

pub(super) fn reject_0rtt_stream(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> bool {
    if !stream.is_0rtt() {
        return false;
    }

    stream.stop_stream(Code::H3_REQUEST_REJECTED);
    true
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

pub(super) async fn stop_h3_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
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

pub(super) async fn rebind_migrated_path(
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

pub(super) async fn finish_h3_request(
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

async fn release_claim(policy: &PolicySession, claim: &FlowClaim) {
    if let Err(error) = policy.release(claim).await {
        tracing::error!(%error, "failed to release downstream QUIC association claim");
    }
}

#[cfg(test)]
mod tests {
    use super::upstream_destination_for;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    #[test]
    fn upstream_destination_uses_the_claimed_destination_for_primary_flows() {
        assert_eq!(
            upstream_destination_for(None, None, address(443)),
            Some(address(443))
        );
    }

    #[test]
    fn upstream_destination_uses_the_origin_port_for_alternative_flows() {
        assert_eq!(
            upstream_destination_for(Some("example.test"), Some(8443), address(443)),
            Some(address(8443))
        );
    }

    #[test]
    fn upstream_destination_requires_the_origin_port_for_alternative_flows() {
        assert_eq!(
            upstream_destination_for(Some("example.test"), None, address(443)),
            None
        );
    }
}
