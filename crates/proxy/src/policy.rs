use agent_sandbox_core::{
    AttributionToken, FlowClaimReply, FlowProtocol, HttpCheckReply, HttpRequest, NetworkFlowKey,
    NetworkFlowSelector, NormalizedPolicyHost, ProxyConnectionId, ProxyReply, ProxyReplyBody,
    ProxyRequestId, ProxySessionReply, ProxySessionToken, RpcClientError, RpcConnection, RpcReply,
    RpcRequest, policy_rpc,
};
use rama_core::error::{BoxError, BoxErrorExt};
use std::{
    env, fs,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};

/// One claimed intercepted flow and the stable connection identity that owns
/// the claim. The proxy presents both when it rebinds or releases the
/// association, so policyd can reject unknown identifiers.
#[derive(Debug, Clone)]
pub struct FlowClaim {
    pub attribution_token: AttributionToken,
    pub connection_id: ProxyConnectionId,
    pub flow: NetworkFlowKey,
    pub policy_host: NormalizedPolicyHost,
}

pub struct PolicySession {
    /// The session lease: policyd closes the proxy session when this
    /// connection ends, so it must outlive the session even though RPC
    /// calls use fresh connections.
    _connection: RpcConnection,
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
    #[must_use]
    pub const fn new(policy: Arc<PolicySession>, request_id: ProxyRequestId) -> Self {
        Self {
            policy,
            request_id,
            armed: true,
        }
    }

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
            socket,
            token: proxy_session,
            timeout,
            ready_path,
        })
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

        let reply = policy_rpc(
            &self.socket,
            RpcRequest::ClaimNetworkFlow {
                proxy_session: self.token.clone(),
                flow,
                connection_id,
            },
            self.timeout,
        )
        .await
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

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
            Err(PolicyError::UnexpectedReply("claim_network_flow"))
        }
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

        let reply = policy_rpc(
            &self.socket,
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
            self.timeout,
        )
        .await
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

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
            Err(PolicyError::UnexpectedReply("claim_network_flow_by_source"))
        }
    }

    /// Rebind a claimed association to a migrated UDP path.
    ///
    /// # Errors
    ///
    /// Returns an error when policyd rejects the attribution, connection
    /// identifier, owner, tuple, or destination.
    pub async fn rebind(&self, claim: &FlowClaim, flow: NetworkFlowKey) -> Result<(), PolicyError> {
        let reply = policy_rpc(
            &self.socket,
            RpcRequest::RebindNetworkFlow {
                proxy_session: self.token.clone(),
                attribution_token: claim.attribution_token.clone(),
                connection_id: claim.connection_id,
                flow,
            },
            self.timeout,
        )
        .await
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        decode_simple_reply(reply, "rebind_network_flow")
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
        let reply = policy_rpc(
            &self.socket,
            RpcRequest::CheckHttp {
                proxy_session: self.token.clone(),
                request_id,
                attribution_token,
                request,
            },
            self.timeout,
        )
        .await
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        decode_http_check_reply(reply, request_id)
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

    /// Cancel a pending HTTP approval request.
    ///
    /// # Errors
    ///
    /// Returns an error when the cancellation RPC fails.
    pub async fn cancel(&self, request_id: ProxyRequestId) -> Result<(), PolicyError> {
        policy_rpc(
            &self.socket,
            RpcRequest::CancelCheck {
                proxy_session: self.token.clone(),
                request_id,
            },
            self.timeout,
        )
        .await
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        Ok(())
    }

    /// Release a previously claimed intercepted flow.
    ///
    /// # Errors
    ///
    /// Returns an error when the release RPC fails or policyd rejects the
    /// claim identifier.
    pub async fn release(&self, claim: &FlowClaim) -> Result<(), PolicyError> {
        let reply = policy_rpc(
            &self.socket,
            RpcRequest::ReleaseNetworkFlow {
                proxy_session: self.token.clone(),
                attribution_token: claim.attribution_token.clone(),
                connection_id: claim.connection_id,
            },
            self.timeout,
        )
        .await
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        decode_simple_reply(reply, "release_network_flow")
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

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy RPC failed: {0}")]
    Rpc(String),

    #[error("policyd returned an unexpected reply for {0}")]
    UnexpectedReply(&'static str),

    #[error("proxy shutting down")]
    Shutdown,

    #[error("too many active policy checks")]
    TooManyActiveChecks,

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

/// Build the typed flow key used to claim an intercepted TCP connection.
///
/// # Errors
///
/// Returns an error when either socket endpoint has a zero port.
pub fn flow_key(
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<NetworkFlowKey, PolicyError> {
    let source_port = NonZeroU16::new(source.port())
        .ok_or_else(|| PolicyError::Rpc("source port must be non-zero".to_owned()))?;

    let destination_port = NonZeroU16::new(destination.port())
        .ok_or_else(|| PolicyError::Rpc("destination port must be non-zero".to_owned()))?;

    Ok(NetworkFlowKey::new(
        FlowProtocol::Tcp,
        source.ip(),
        source_port,
        destination.ip(),
        destination_port,
    ))
}

/// Build the typed flow key used to claim an intercepted UDP association.
///
/// # Errors
///
/// Returns an error when either socket endpoint has a zero port.
pub fn udp_flow_key(
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<NetworkFlowKey, PolicyError> {
    let source_port = NonZeroU16::new(source.port())
        .ok_or_else(|| PolicyError::Rpc("source port must be non-zero".to_owned()))?;

    let destination_port = NonZeroU16::new(destination.port())
        .ok_or_else(|| PolicyError::Rpc("destination port must be non-zero".to_owned()))?;

    Ok(NetworkFlowKey::new(
        FlowProtocol::Udp,
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
    use agent_sandbox_core::{
        HttpCheckReply, HttpRequest, ProxyReply, ProxyRequestId, ProxySessionReply,
        ProxySessionToken, RpcReply, SimpleOkReply, Verdict, VerdictSource,
    };
    use std::{path::PathBuf, sync::Arc};
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
        _dir: tempfile::TempDir,
        _task: tokio::task::JoinHandle<()>,
    }

    impl FakePolicy {
        /// Start the fake service on a fresh socket in a temporary directory.
        pub fn start() -> Self {
            let dir = tempfile::tempdir().expect("temporary directory");
            let socket = dir.path().join("policy.sock");
            let listener = UnixListener::bind(&socket).expect("bind fake policy socket");
            let (events_tx, events) = mpsc::unbounded_channel();
            let release_checks = Arc::new(Notify::new());

            let task = tokio::spawn(serve(listener, events_tx, release_checks.clone()));

            Self {
                socket,
                events,
                release_checks,
                _dir: dir,
                _task: task,
            }
        }
    }

    async fn serve(
        listener: UnixListener,
        events: mpsc::UnboundedSender<FakePolicyEvent>,
        release_checks: Arc<Notify>,
    ) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };

            let events = events.clone();
            let release_checks = release_checks.clone();

            tokio::spawn(serve_connection(stream, events, release_checks));
        }
    }

    async fn serve_connection(
        stream: tokio::net::UnixStream,
        events: mpsc::UnboundedSender<FakePolicyEvent>,
        release_checks: Arc<Notify>,
    ) {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

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

            Some("cancel_check") => {
                let _ = events.send(FakePolicyEvent::Cancel);

                Some(RpcReply::Simple(SimpleOkReply { ok: true }))
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

    fn field<T: serde::de::DeserializeOwned>(value: &serde_json::Value, name: &str) -> T {
        serde_json::from_value(value.get(name).cloned().expect(name)).expect(name)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PolicyError, PolicySession, decode_http_check_reply, normalize_authority,
        reconcile_authorities,
    };
    use crate::policy::test_support::{FakePolicy, FakePolicyEvent};
    use agent_sandbox_core::{
        AttributionToken, ErrorReply, HttpCheckReply, HttpRequest, ProxyReply, ProxyReplyBody,
        ProxyRequestId, RpcReply,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::sync::{Notify, Semaphore};

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
        assert!(check.allowed);
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
