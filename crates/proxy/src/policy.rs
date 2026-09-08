//! Policy client logic for the transparent proxy.
//!
//! Builds flow claims and authority keys, stores per-claim policy session
//! state, and communicates with policyd to obtain verdicts for intercepted
//! traffic.
use std::{
    env, fs,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use agent_sandbox_core::{
    AttributionToken, CheckReply, FlowClaimReply, FlowProtocol, HttpCheckReply, HttpRequest,
    NetworkFlowKey, NetworkFlowSelector, NormalizedPolicyHost, PersistentRpcClient,
    ProxyConnectionId, ProxyReply, ProxyReplyBody, ProxyRequestId, ProxySessionReply,
    ProxySessionToken, RpcClientError, RpcConnection, RpcReply, RpcRequest,
};
use rama_core::error::{BoxError, BoxErrorExt};
use tokio::sync::{Notify, Semaphore};

/// One claimed intercepted flow and the stable connection identity that owns
/// the claim. The proxy presents both when it rebinds or releases the
/// association, so policyd can reject unknown identifiers.
#[derive(Debug, Clone)]
pub struct FlowClaim {
    /// The attribution token bound to the claimed flow.
    pub attribution_token: AttributionToken,

    /// The stable connection identifier owning this claim.
    pub connection_id: ProxyConnectionId,

    /// The claimed intercepted network flow.
    pub flow: NetworkFlowKey,

    /// The normalized policy host assigned to the flow.
    pub policy_host: NormalizedPolicyHost,
}

/// A long-lived policy session bound to one policyd instance.
///
/// The session carries a stable token and reuses idle Unix RPC connections.
/// Concurrent requests use separate connections, including pending approvals.
/// Each proxy holds one session; drops remove the readiness marker.
pub struct PolicySession {
    /// The session lease: policyd closes the proxy session when this
    /// connection ends, so RPC failures must never close this lease.
    _connection: RpcConnection,
    idle: Mutex<Vec<PersistentRpcClient>>,

    socket: PathBuf,
    token: ProxySessionToken,
    timeout: Duration,
    ready_path: Option<PathBuf>,
}

/// Cancels a pending HTTP approval when dropped before a reply arrives.
///
/// The drop path runs in a spawned task so the cancellation RPC can be
/// awaited without blocking the dropping frame.
pub struct PendingPolicyCheck {
    policy: Arc<PolicySession>,
    request_id: ProxyRequestId,
    armed: bool,
}

impl PendingPolicyCheck {
    /// Create an armed pending check for the given policy session and request.
    #[must_use]
    pub const fn new(policy: Arc<PolicySession>, request_id: ProxyRequestId) -> Self {
        Self {
            policy,
            request_id,
            armed: true,
        }
    }

    /// Disarm the pending check so dropping it does not send a cancellation.
    pub const fn disarm(&mut self) {
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
                    tracing::error!(%error, "failed to cancel dropped HTTP policy check");
                }
            });
        }
    }
}

impl PolicySession {
    /// Open the long-lived policy session used by this proxy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy socket cannot be reached or rejects
    /// the session.
    pub async fn open(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, PolicyError> {
        let socket = path.as_ref().to_owned();

        let mut connection = tokio::time::timeout(timeout, async {
            loop {
                match RpcConnection::connect(&socket).await {
                    Ok(connection) => break Ok(connection),
                    Err(RpcClientError::Io(error))
                        if matches!(
                            error.kind(),
                            ErrorKind::NotFound | ErrorKind::ConnectionRefused
                        ) =>
                    {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(error) => break Err(error),
                }
            }
        })
        .await
        .map_err(|_| PolicyError::Rpc("policy RPC timed out".to_owned()))?
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        let reply = tokio::time::timeout(timeout, connection.request(RpcRequest::OpenProxySession))
            .await
            .map_err(|_| PolicyError::Rpc("policy RPC timed out".to_owned()))?
            .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        let RpcReply::ProxySession(ProxySessionReply {
            ok: true,
            proxy_session,
        }) = reply
        else {
            return Err(PolicyError::UnexpectedReply("open_proxy_session"));
        };

        let ready_path = session_ready_path();

        Ok(Self {
            _connection: connection,
            idle: Mutex::new(Vec::new()),
            socket,
            token: proxy_session,
            timeout,
            ready_path,
        })
    }

    async fn rpc<T>(
        &self,
        request: RpcRequest,
        decode: impl FnOnce(RpcReply) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        let mut client = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .unwrap_or_else(|| PersistentRpcClient::new(&self.socket));
        let reply = client
            .request(request, self.timeout)
            .await
            .map_err(|error| PolicyError::Rpc(error.to_string()))?;
        let result = decode(reply)?;
        // Interrupted, failed, or malformed exchanges drop their connection.
        // Never hold the idle-list lock across an RPC or wait for a busy client.
        {
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // ponytail: retain eight idle clients; grow this if measured
            // connection churn warrants using more of policyd's per-UID limit.
            if idle.len() < 8 {
                idle.push(client);
            }
        }
        Ok(result)
    }

    /// Publish the readiness marker after both listeners are bound.
    ///
    /// # Errors
    ///
    /// Returns an error when the systemd invocation ID is invalid or the
    /// marker cannot be installed.
    pub fn mark_ready(&self) -> Result<(), PolicyError> {
        if let Some(path) = &self.ready_path {
            mark_session_ready(path)?;
        }

        Ok(())
    }

    /// Claim one intercepted transport flow for this proxy session.
    ///
    /// # Errors
    ///
    /// Returns an error when policyd rejects or cannot identify the flow.
    pub async fn claim(&self, flow: NetworkFlowKey) -> Result<FlowClaim, PolicyError> {
        let connection_id = ProxyConnectionId::new();

        self.rpc(
            RpcRequest::ClaimNetworkFlow {
                proxy_session: self.token.clone(),
                flow,
                connection_id,
            },
            |reply| decode_flow_claim(reply, connection_id, "claim_network_flow"),
        )
        .await
    }

    /// Claim one output-redirected UDP flow by its visible socket tuple.
    ///
    /// # Errors
    ///
    /// Returns an error when policyd rejects or cannot uniquely identify the
    /// registered flow.
    pub async fn claim_udp_redirected(
        &self,
        source: SocketAddr,
        destination_port: u16,
    ) -> Result<FlowClaim, PolicyError> {
        let source_port = NonZeroU16::new(source.port())
            .ok_or_else(|| PolicyError::Rpc("source port must be non-zero".to_owned()))?;

        let destination_port = NonZeroU16::new(destination_port)
            .ok_or_else(|| PolicyError::Rpc("destination port must be non-zero".to_owned()))?;

        let connection_id = ProxyConnectionId::new();

        self.rpc(
            RpcRequest::ClaimNetworkFlowBySource {
                proxy_session: self.token.clone(),
                selector: NetworkFlowSelector::new(
                    FlowProtocol::Udp,
                    source.ip(),
                    source_port,
                    destination_port,
                ),
                connection_id,
            },
            |reply| decode_flow_claim(reply, connection_id, "claim_network_flow_by_source"),
        )
        .await
    }

    /// Rebind a claimed association to a migrated UDP path.
    ///
    /// # Errors
    ///
    /// Returns an error when policyd rejects the attribution, connection
    /// identifier, owner, tuple, or destination.
    pub async fn rebind(&self, claim: &FlowClaim, flow: NetworkFlowKey) -> Result<(), PolicyError> {
        self.rpc(
            RpcRequest::RebindNetworkFlow {
                proxy_session: self.token.clone(),
                attribution_token: claim.attribution_token.clone(),
                connection_id: claim.connection_id,
                flow,
            },
            |reply| decode_simple_reply(reply, "rebind_network_flow"),
        )
        .await
    }

    /// Ask policyd for a decision on one normalized HTTP request.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy RPC fails or has an unexpected reply.
    pub async fn check_http(
        &self,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
        request: HttpRequest,
    ) -> Result<HttpCheckReply, PolicyError> {
        self.rpc(
            RpcRequest::CheckHttp {
                proxy_session: self.token.clone(),
                request_id,
                attribution_token,
                request,
            },
            |reply| decode_http_check_reply(reply, request_id),
        )
        .await
    }

    /// Ask policyd for a decision on one normalized HTTP request, holding
    /// one concurrency permit for the whole decision.
    ///
    /// The pending check is cancelled when the proxy shuts down before the
    /// decision arrives.
    ///
    /// # Errors
    ///
    /// Returns an error when the permit is unavailable, the policy RPC
    /// fails, or the proxy shuts down while the decision is pending.
    pub async fn check_http_cancellable(
        self: &Arc<Self>,
        attribution_token: AttributionToken,
        request: HttpRequest,
        active_checks: &Arc<Semaphore>,
        shutdown: &Notify,
    ) -> Result<HttpCheckReply, PolicyError> {
        let _permit = active_checks
            .clone()
            .try_acquire_owned()
            .map_err(|_| PolicyError::TooManyActiveChecks)?;

        let request_id = ProxyRequestId::new();
        let mut pending = PendingPolicyCheck::new(Arc::clone(self), request_id);

        let check = tokio::select! {
            result = self.check_http(request_id, attribution_token, request) => result?,
            () = shutdown.notified() => {
                self.cancel(request_id).await?;
                pending.disarm();
                return Err(PolicyError::Shutdown);
            }
        };

        pending.disarm();
        Ok(check)
    }

    /// Ask policyd for a connection-level decision on a claimed flow whose
    /// stream carries no HTTP to decode (raw TCP passthrough).
    ///
    /// The check runs under one concurrency permit and is cancelled when the
    /// proxy shuts down before the decision arrives.
    ///
    /// # Errors
    ///
    /// Returns an error when the permit is unavailable, the policy RPC fails
    /// or has an unexpected reply, or the proxy shuts down while the
    /// decision is pending.
    pub async fn check_network_flow_cancellable(
        self: &Arc<Self>,
        attribution_token: AttributionToken,
        active_checks: &Arc<Semaphore>,
        shutdown: &Arc<Notify>,
    ) -> Result<CheckReply, PolicyError> {
        let _permit = active_checks
            .clone()
            .try_acquire_owned()
            .map_err(|_| PolicyError::TooManyActiveChecks)?;

        let request_id = ProxyRequestId::new();
        let mut pending = PendingPolicyCheck::new(Arc::clone(self), request_id);

        let check = tokio::select! {
            result = self.check_network_flow(request_id, attribution_token) => result?,
            () = shutdown.notified() => {
                self.cancel(request_id).await?;
                pending.disarm();
                return Err(PolicyError::Shutdown);
            }
        };

        pending.disarm();
        Ok(check)
    }

    /// Ask policyd for a connection-level decision on a claimed flow.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy RPC fails or has an unexpected reply.
    pub async fn check_network_flow(
        &self,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
    ) -> Result<CheckReply, PolicyError> {
        self.rpc(
            RpcRequest::CheckNetworkFlow {
                proxy_session: self.token.clone(),
                request_id,
                attribution_token,
            },
            |reply| match reply {
                RpcReply::Proxy(ProxyReply {
                    request_id: reply_request_id,
                    reply,
                }) if reply_request_id == request_id => match reply {
                    ProxyReplyBody::NetworkFlow(check) => Ok(check),
                    ProxyReplyBody::Error(error) => Err(PolicyError::Rpc(error.error)),
                    _ => Err(PolicyError::UnexpectedReply("check_network_flow")),
                },
                _ => Err(PolicyError::UnexpectedReply("check_network_flow")),
            },
        )
        .await
    }

    /// Cancel a pending HTTP approval request.
    ///
    /// # Errors
    ///
    /// Returns an error when the cancellation RPC fails.
    pub async fn cancel(&self, request_id: ProxyRequestId) -> Result<(), PolicyError> {
        self.rpc(
            RpcRequest::CancelCheck {
                proxy_session: self.token.clone(),
                request_id,
            },
            |reply| match reply {
                RpcReply::Proxy(ProxyReply {
                    request_id: reply_request_id,
                    reply: ProxyReplyBody::Canceled(ok),
                }) if reply_request_id == request_id && ok.ok => Ok(()),
                _ => Err(PolicyError::UnexpectedReply("cancel_check")),
            },
        )
        .await
    }

    /// Release a previously claimed intercepted flow.
    ///
    /// # Errors
    ///
    /// Returns an error when the release RPC fails or policyd rejects the
    /// claim identifier.
    pub async fn release(&self, claim: &FlowClaim) -> Result<(), PolicyError> {
        self.rpc(
            RpcRequest::ReleaseNetworkFlow {
                proxy_session: self.token.clone(),
                attribution_token: claim.attribution_token.clone(),
                connection_id: claim.connection_id,
            },
            |reply| decode_simple_reply(reply, "release_network_flow"),
        )
        .await
    }

    fn clear_session_ready(&self) {
        if let Some(path) = &self.ready_path {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for PolicySession {
    fn drop(&mut self) {
        self.clear_session_ready();
    }
}

fn decode_flow_claim(
    reply: RpcReply,
    connection_id: ProxyConnectionId,
    operation: &'static str,
) -> Result<FlowClaim, PolicyError> {
    if let RpcReply::FlowClaim(FlowClaimReply {
        ok: true,
        attribution_token,
        flow,
        policy_host,
    }) = reply
    {
        Ok(FlowClaim {
            attribution_token,
            connection_id,
            flow,
            policy_host,
        })
    } else {
        Err(PolicyError::UnexpectedReply(operation))
    }
}

fn decode_simple_reply(reply: RpcReply, operation: &'static str) -> Result<(), PolicyError> {
    match reply {
        RpcReply::Simple(ok) if ok.ok => Ok(()),
        RpcReply::Error(error) => Err(PolicyError::Rpc(error.error)),
        _ => Err(PolicyError::UnexpectedReply(operation)),
    }
}

fn decode_http_check_reply(
    reply: RpcReply,
    request_id: ProxyRequestId,
) -> Result<HttpCheckReply, PolicyError> {
    match reply {
        RpcReply::Proxy(ProxyReply {
            request_id: reply_request_id,
            reply,
        }) if reply_request_id == request_id => match reply {
            ProxyReplyBody::HttpCheck(check) => Ok(check),
            ProxyReplyBody::Error(error) => Err(PolicyError::Rpc(error.error)),
            _ => Err(PolicyError::UnexpectedReply("check_http")),
        },

        _ => Err(PolicyError::UnexpectedReply("check_http")),
    }
}

fn session_ready_path() -> Option<PathBuf> {
    env::var_os("AGENT_SANDBOX_PROXY_SESSION_READY").map(PathBuf::from)
}

fn mark_session_ready(path: &Path) -> Result<(), PolicyError> {
    let invocation_id = env::var("INVOCATION_ID")
        .map_err(|_| PolicyError::Rpc("systemd invocation ID is unavailable".to_owned()))?;

    if invocation_id.len() != 32
        || !invocation_id.bytes().all(|byte| {
            byte.is_ascii_digit() || byte.is_ascii_hexdigit() && byte.is_ascii_lowercase()
        })
    {
        return Err(PolicyError::Rpc(
            "systemd invocation ID is not lowercase hexadecimal".to_owned(),
        ));
    }

    let temporary = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));

    fs::write(&temporary, format!("{invocation_id}\n"))
        .map_err(|error| PolicyError::Rpc(format!("write proxy readiness marker: {error}")))?;

    #[cfg(unix)]
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).map_err(|error| {
        PolicyError::Rpc(format!("set proxy readiness marker permissions: {error}"))
    })?;

    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);

        return Err(PolicyError::Rpc(format!(
            "install proxy readiness marker: {error}"
        )));
    }

    Ok(())
}

/// A failure interacting with the policyd service.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The policy RPC failed.
    #[error("policy RPC failed: {0}")]
    Rpc(String),

    /// Policyd returned an unexpected reply for the named operation.
    #[error("policyd returned an unexpected reply for {0}")]
    UnexpectedReply(&'static str),

    /// The proxy is shutting down.
    #[error("proxy shutting down")]
    Shutdown,

    /// Too many policy checks are active concurrently.
    #[error("too many active policy checks")]
    TooManyActiveChecks,

    /// The request carries conflicting HTTP authorities.
    #[error("conflicting HTTP authorities")]
    AuthorityConflict,
}

impl PolicyError {
    /// Convert to a boxed error, replacing the generic authority conflict
    /// with the call-site message while preserving any other cause.
    pub(crate) fn into_boxed(self, conflict_message: &'static str) -> BoxError {
        match self {
            Self::AuthorityConflict => BoxError::from_static_str(conflict_message),
            other => BoxError::from(other),
        }
    }
}

/// Build the typed flow key used to claim an intercepted flow.
///
/// # Errors
///
/// Returns an error when either socket endpoint has a zero port.
pub fn flow_key(
    protocol: FlowProtocol,
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<NetworkFlowKey, PolicyError> {
    let source_port = NonZeroU16::new(source.port())
        .ok_or_else(|| PolicyError::Rpc("source port must be non-zero".to_owned()))?;

    let destination_port = NonZeroU16::new(destination.port())
        .ok_or_else(|| PolicyError::Rpc("destination port must be non-zero".to_owned()))?;

    Ok(NetworkFlowKey::new(
        protocol,
        source.ip(),
        source_port,
        destination.ip(),
        destination_port,
    ))
}

/// Format a host and port as a policy authority.
#[must_use]
pub fn authority_for_policy(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

/// Normalize an HTTP authority and apply a fallback port when absent.
///
/// # Errors
///
/// Returns an error when the authority is malformed or has no host.
pub fn normalize_authority(value: &str, fallback_port: u16) -> Result<String, PolicyError> {
    let url = url::Url::parse(&format!("http://{value}/"))
        .map_err(|error| PolicyError::Rpc(format!("invalid HTTP authority: {error}")))?;

    let host = url
        .host_str()
        .ok_or_else(|| PolicyError::Rpc("HTTP authority has no host".to_owned()))?;

    Ok(authority_for_policy(
        host,
        url.port().unwrap_or(fallback_port),
    ))
}

/// Reconcile HTTP authority candidates into one canonical authority.
///
/// Every present candidate must normalize to the same authority.
///
/// # Errors
///
/// Returns an error when the candidates disagree or none is present.
pub fn reconcile_authorities(
    candidates: &[&str],
    fallback_port: u16,
) -> Result<String, PolicyError> {
    let mut canonical: Option<String> = None;

    for candidate in candidates {
        let normalized = normalize_authority(candidate, fallback_port)?;

        if canonical
            .as_deref()
            .is_some_and(|existing| existing != normalized)
        {
            return Err(PolicyError::AuthorityConflict);
        }

        canonical = Some(normalized);
    }

    canonical.ok_or_else(|| PolicyError::Rpc("HTTP request has no authority".to_owned()))
}

/// Minimal policyd used by policy-decision tests in this crate.
///
/// Answers session opens and policy checks, and records every check and
/// cancellation it observes. Check replies wait on `release_checks`, so a
/// test can hold a decision pending while it exercises the shutdown path.
#[cfg(test)]
pub(crate) mod test_support {
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use agent_sandbox_core::{
        AttributionToken, CheckReply, FlowClaimReply, HttpCheckReply, HttpRequest, NetworkFlowKey,
        NormalizedPolicyHost, ProxyReply, ProxyRequestId, ProxySessionReply, ProxySessionToken,
        RpcReply, SimpleOkReply, Verdict, VerdictSource,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
        sync::{Notify, mpsc},
    };

    /// One policy operation observed by the fake service.
    pub enum FakePolicyEvent {
        Check,
        Cancel,
    }

    /// A fake policyd bound to a Unix socket in a temporary directory.
    pub struct FakePolicy {
        pub socket: PathBuf,
        pub events: mpsc::UnboundedReceiver<FakePolicyEvent>,
        pub release_checks: Arc<Notify>,
        pub connections: Arc<AtomicUsize>,
        _dir: tempfile::TempDir,
        _task: tokio::task::JoinHandle<()>,
    }

    impl FakePolicy {
        /// Start the fake service on a fresh socket in a temporary directory.
        pub fn start() -> Self {
            Self::start_with_network_verdict(true)
        }

        /// Start the fake service whose connection-level network checks deny.
        pub fn start_denying_network() -> Self {
            Self::start_with_network_verdict(false)
        }

        fn start_with_network_verdict(allow_network: bool) -> Self {
            let dir = tempfile::tempdir().expect("temporary directory");
            let socket = dir.path().join("policy.sock");
            let listener = UnixListener::bind(&socket).expect("bind fake policy socket");
            let (events_tx, events) = mpsc::unbounded_channel();
            let release_checks = Arc::new(Notify::new());
            let connections = Arc::new(AtomicUsize::new(0));
            let deny_network = Arc::new(AtomicBool::new(!allow_network));
            let task = tokio::spawn(serve(
                listener,
                events_tx,
                release_checks.clone(),
                connections.clone(),
                deny_network,
            ));

            Self {
                socket,
                events,
                release_checks,
                connections,
                _dir: dir,
                _task: task,
            }
        }
    }

    async fn serve(
        listener: UnixListener,
        events: mpsc::UnboundedSender<FakePolicyEvent>,
        release_checks: Arc<Notify>,
        connections: Arc<AtomicUsize>,
        deny_network: Arc<AtomicBool>,
    ) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };

            connections.fetch_add(1, Ordering::SeqCst);
            let events = events.clone();
            let release_checks = release_checks.clone();
            let deny_network = deny_network.clone();
            tokio::spawn(serve_connection(
                stream,
                events,
                release_checks,
                deny_network,
            ));
        }
    }

    async fn serve_connection(
        stream: tokio::net::UnixStream,
        events: mpsc::UnboundedSender<FakePolicyEvent>,
        release_checks: Arc<Notify>,
        deny_network: Arc<AtomicBool>,
    ) {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            if reader.read_line(&mut line).await.is_err() || line.is_empty() {
                return;
            }

            let value: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(value) => value,
                Err(_) => return,
            };

            let reply = match value.get("op").and_then(serde_json::Value::as_str) {
                Some("open_proxy_session") => Some(RpcReply::ProxySession(ProxySessionReply {
                    ok: true,
                    proxy_session: ProxySessionToken::from_bytes([1; 32]),
                })),

                Some("check_http") => {
                    let request_id: ProxyRequestId = field(&value, "request_id");

                    let _ = events.send(FakePolicyEvent::Check);

                    release_checks.notified().await;

                    let request: HttpRequest = field(&value, "request");

                    Some(RpcReply::Proxy(ProxyReply::from_reply(
                        request_id,
                        RpcReply::HttpCheck(HttpCheckReply::from_verdict(
                            request,
                            Verdict::allowed(VerdictSource::policy()),
                        )),
                    )))
                }

                Some("claim_network_flow") => {
                    let flow: NetworkFlowKey = field(&value, "flow");

                    Some(RpcReply::FlowClaim(FlowClaimReply {
                        ok: true,
                        attribution_token: AttributionToken::from_bytes([2; 32]),
                        flow,
                        policy_host: NormalizedPolicyHost::parse("example.test")
                            .expect("static policy host"),
                    }))
                }

                Some("check_network_flow") => {
                    let _ = events.send(FakePolicyEvent::Check);
                    let allowed = !deny_network.load(Ordering::SeqCst);

                    Some(RpcReply::Proxy(ProxyReply::from_reply(
                        field(&value, "request_id"),
                        RpcReply::Check(if allowed {
                            CheckReply::allowed(VerdictSource::policy())
                        } else {
                            CheckReply::denied(VerdictSource::policy())
                        }),
                    )))
                }

                Some("release_network_flow") => Some(RpcReply::Simple(SimpleOkReply { ok: true })),

                Some("cancel_check") => {
                    let _ = events.send(FakePolicyEvent::Cancel);

                    Some(RpcReply::Proxy(ProxyReply::from_reply(
                        field(&value, "request_id"),
                        RpcReply::Simple(SimpleOkReply { ok: true }),
                    )))
                }

                _ => None,
            };

            let Some(reply) = reply else {
                return;
            };

            let encoded = serde_json::to_vec(&reply).expect("encode policy reply");
            let _ = writer.write_all(&encoded).await;
            let _ = writer.write_all(b"\n").await;
            let _ = writer.flush().await;
        }
    }

    fn field<T: serde::de::DeserializeOwned>(value: &serde_json::Value, name: &str) -> T {
        serde_json::from_value(value.get(name).cloned().expect(name)).expect(name)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use agent_sandbox_core::{
        AttributionToken, ErrorReply, HttpCheckReply, HttpRequest, ProxyReply, ProxyReplyBody,
        ProxyRequestId, RpcReply,
    };
    use tokio::sync::{Notify, Semaphore};

    use super::{
        PolicyError, PolicySession, decode_http_check_reply, normalize_authority,
        reconcile_authorities,
    };
    use crate::policy::test_support::{FakePolicy, FakePolicyEvent};

    #[test]
    fn accepts_matching_pipelined_http_reply() -> Result<(), Box<dyn std::error::Error>> {
        let request_id = ProxyRequestId::new();

        let reply = RpcReply::Proxy(ProxyReply {
            request_id,
            reply: ProxyReplyBody::HttpCheck(HttpCheckReply::blocked("approval pending")),
        });

        assert!(!decode_http_check_reply(reply, request_id)?.ok);
        Ok(())
    }

    #[test]
    fn rejects_pipelined_http_reply_for_another_request() {
        let request_id = ProxyRequestId::new();

        let reply = RpcReply::Proxy(ProxyReply {
            request_id: ProxyRequestId::new(),
            reply: ProxyReplyBody::HttpCheck(HttpCheckReply::blocked("approval pending")),
        });

        assert!(decode_http_check_reply(reply, request_id).is_err());
    }

    #[test]
    fn reports_pipelined_policy_errors() {
        let request_id = ProxyRequestId::new();

        let reply = RpcReply::Proxy(ProxyReply {
            request_id,
            reply: ProxyReplyBody::Error(ErrorReply::new("policy unavailable")),
        });

        assert!(matches!(
            decode_http_check_reply(reply, request_id),
            Err(PolicyError::Rpc(message)) if message == "policy unavailable"
        ));
    }

    #[test]
    fn preserves_explicit_alternate_port() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            normalize_authority("example.test:8080", 80)?,
            "example.test:8080"
        );

        Ok(())
    }

    #[test]
    fn formats_ipv6_authority() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            normalize_authority("[2001:db8::1]:8443", 443)?,
            "[2001:db8::1]:8443"
        );

        Ok(())
    }

    #[test]
    fn reconcile_authorities_accepts_matching_candidates() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            reconcile_authorities(&["example.test", "example.test:80"], 80)?,
            "example.test:80"
        );

        Ok(())
    }

    #[test]
    fn reconcile_authorities_applies_fallback_port() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            reconcile_authorities(&["example.test"], 8080)?,
            "example.test:8080"
        );

        Ok(())
    }

    #[test]
    fn reconcile_authorities_rejects_conflicting_candidates() {
        assert!(reconcile_authorities(&["example.test", "other.test"], 80).is_err());
        assert!(reconcile_authorities(&["example.test:80", "example.test:8080"], 80).is_err());
    }

    #[test]
    fn reconcile_authorities_requires_at_least_one_candidate() {
        assert!(reconcile_authorities(&[], 80).is_err());
    }

    #[tokio::test]
    async fn rpc_pool_reuses_only_validated_exchanges() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::Ordering;

        use agent_sandbox_core::RpcRequest;

        let mut fake = FakePolicy::start();
        let policy = Arc::new(PolicySession::open(&fake.socket, Duration::from_secs(2)).await?);
        for _ in 0..2 {
            policy.cancel(ProxyRequestId::new()).await?;
            assert!(matches!(
                fake.events.recv().await,
                Some(FakePolicyEvent::Cancel)
            ));
        }
        assert_eq!(
            fake.connections.load(Ordering::SeqCst),
            2,
            "lease plus one reused RPC connection"
        );
        let invalid = policy
            .rpc(
                RpcRequest::CancelCheck {
                    proxy_session: policy.token.clone(),
                    request_id: ProxyRequestId::new(),
                },
                |_| Err::<(), _>(PolicyError::UnexpectedReply("test")),
            )
            .await;
        assert!(invalid.is_err());
        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Cancel)
        ));
        policy.cancel(ProxyRequestId::new()).await?;
        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Cancel)
        ));
        assert_eq!(
            fake.connections.load(Ordering::SeqCst),
            3,
            "invalid exchanges must be discarded"
        );

        let pending = {
            let policy = policy.clone();
            tokio::spawn(async move {
                policy
                    .check_http(
                        ProxyRequestId::new(),
                        AttributionToken::from_bytes([2; 32]),
                        HttpRequest::from_parts("GET", "https", "example.test", "/").unwrap(),
                    )
                    .await
            })
        };
        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Check)
        ));
        tokio::time::timeout(Duration::from_secs(2), policy.cancel(ProxyRequestId::new()))
            .await??;
        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Cancel)
        ));
        assert_eq!(
            fake.connections.load(Ordering::SeqCst),
            4,
            "a pending check cannot block another RPC"
        );
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        // Discard the completed cancellation connection, leaving no valid idle
        // client. The interrupted check must not have returned its client.
        assert!(
            policy
                .rpc(
                    RpcRequest::CancelCheck {
                        proxy_session: policy.token.clone(),
                        request_id: ProxyRequestId::new()
                    },
                    |_| Err::<(), _>(PolicyError::UnexpectedReply("test")),
                )
                .await
                .is_err()
        );
        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Cancel)
        ));
        policy.cancel(ProxyRequestId::new()).await?;
        assert_eq!(
            fake.connections.load(Ordering::SeqCst),
            5,
            "interrupted exchanges must be discarded"
        );
        fake.release_checks.notify_one();
        Ok(())
    }

    #[tokio::test]
    async fn cancellable_check_returns_allowed_decision() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut fake = FakePolicy::start();
        let policy = Arc::new(PolicySession::open(&fake.socket, Duration::from_secs(2)).await?);
        let active_checks = Arc::new(Semaphore::new(2));
        let shutdown = Arc::new(Notify::new());
        fake.release_checks.notify_one();
        let request = HttpRequest::from_parts("GET", "https", "example.test", "/")?;

        let check = policy
            .check_http_cancellable(
                AttributionToken::from_bytes([2; 32]),
                request,
                &active_checks,
                &shutdown,
            )
            .await?;

        assert!(check.ok);
        assert!(check.verdict.allowed);

        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Check)
        ));

        Ok(())
    }

    #[tokio::test]
    async fn cancellable_check_cancels_on_shutdown() -> Result<(), Box<dyn std::error::Error>> {
        let mut fake = FakePolicy::start();
        let policy = Arc::new(PolicySession::open(&fake.socket, Duration::from_secs(2)).await?);
        let active_checks = Arc::new(Semaphore::new(2));
        let shutdown = Arc::new(Notify::new());
        let request = HttpRequest::from_parts("GET", "https", "example.test", "/")?;

        let task = {
            let policy = policy.clone();
            let active_checks = active_checks.clone();
            let shutdown = shutdown.clone();

            tokio::spawn(async move {
                policy
                    .check_http_cancellable(
                        AttributionToken::from_bytes([2; 32]),
                        request,
                        &active_checks,
                        &shutdown,
                    )
                    .await
            })
        };

        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Check)
        ));

        shutdown.notify_one();

        assert!(matches!(
            task.await.expect("check task"),
            Err(PolicyError::Shutdown)
        ));

        assert!(matches!(
            fake.events.recv().await,
            Some(FakePolicyEvent::Cancel)
        ));

        fake.release_checks.notify_one();
        Ok(())
    }

    #[tokio::test]
    async fn cancellable_check_rejects_when_semaphore_is_full()
    -> Result<(), Box<dyn std::error::Error>> {
        let fake = FakePolicy::start();
        let policy = Arc::new(PolicySession::open(&fake.socket, Duration::from_secs(2)).await?);
        let active_checks = Arc::new(Semaphore::new(1));
        let shutdown = Arc::new(Notify::new());
        let _held = active_checks.clone().try_acquire_owned().expect("permit");
        let request = HttpRequest::from_parts("GET", "https", "example.test", "/")?;

        let result = policy
            .check_http_cancellable(
                AttributionToken::from_bytes([2; 32]),
                request,
                &active_checks,
                &shutdown,
            )
            .await;

        assert!(matches!(result, Err(PolicyError::TooManyActiveChecks)));
        Ok(())
    }
}
