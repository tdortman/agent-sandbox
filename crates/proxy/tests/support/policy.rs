use super::*;

#[derive(Debug, Default)]
pub struct PolicyEvents {
    pub claims: Vec<ClaimEvent>,
    pub checks: Vec<HttpRequest>,
    pub decisions: Vec<bool>,
    pub cancellations: Vec<agent_sandbox_core::ProxyRequestId>,
    pub rebinds: Vec<agent_sandbox_core::NetworkFlowKey>,
    pub releases: Vec<FlowRelease>,
}

/// How many connections the real policyd admits for the proxy's user; it
/// answers the rest with an error and closes them.
const MAX_CONNECTIONS: usize = 64;

pub struct FakePolicy {
    pub socket: PathBuf,
    pub events: Arc<Mutex<PolicyEvents>>,
    /// Connections refused for exceeding [`MAX_CONNECTIONS`].
    pub refused_connections: Arc<AtomicUsize>,
    release_gate: Arc<Notify>,
    task: JoinHandle<()>,
}

impl FakePolicy {
    pub fn start(root: &Path) -> Self {
        Self::start_with_behavior(root, false, Duration::ZERO)
    }

    /// Start a policy service that takes `delay` to answer each flow claim,
    /// so claims for a burst of connections overlap.
    pub fn start_slow_claims(root: &Path, delay: Duration) -> Self {
        Self::start_with_behavior(root, false, delay)
    }

    /// Start a policy service that rejects every flow claim, so the proxy's
    /// connection-level failure path can be observed.
    pub fn start_claim_error(root: &Path) -> Self {
        Self::start_with_behavior(root, true, Duration::ZERO)
    }

    fn start_with_behavior(root: &Path, claim_errors: bool, claim_delay: Duration) -> Self {
        let socket = root.join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind fake policy socket");
        let events = Arc::new(Mutex::new(PolicyEvents::default()));
        let task_events = events.clone();
        let cancel_gate = Arc::new(Notify::new());
        let release_gate = Arc::new(Notify::new());
        let task_release_gate = release_gate.clone();
        let refused_connections = Arc::new(AtomicUsize::new(0));
        let task_refused = refused_connections.clone();
        let live_connections = Arc::new(AtomicUsize::new(0));

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let events = task_events.clone();
                let cancel_gate = cancel_gate.clone();
                let release_gate = task_release_gate.clone();
                let admitted = ConnectionSlot::admit(&live_connections);
                if admitted.is_none() {
                    task_refused.fetch_add(1, Ordering::SeqCst);
                }
                tokio::spawn(serve_policy_connection(
                    stream,
                    events,
                    cancel_gate,
                    release_gate,
                    PolicyBehavior {
                        claim_errors,
                        claim_delay,
                    },
                    admitted,
                ));
            }
        });

        Self {
            socket,
            events,
            refused_connections,
            release_gate,
            task,
        }
    }

    /// Allow the HTTP check of a `/pending` request that waits for it, as a
    /// user approving a prompt would.
    pub fn approve_pending(&self) {
        self.release_gate.notify_one();
    }
}

#[derive(Clone, Copy)]
struct PolicyBehavior {
    claim_errors: bool,
    claim_delay: Duration,
}

/// One of the [`MAX_CONNECTIONS`] connections the fake policy admits; the
/// slot frees when the connection ends.
struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn admit(live: &Arc<AtomicUsize>) -> Option<Self> {
        if live.fetch_add(1, Ordering::SeqCst) < MAX_CONNECTIONS {
            Some(Self(live.clone()))
        } else {
            live.fetch_sub(1, Ordering::SeqCst);
            None
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn serve_policy_connection(
    stream: tokio::net::UnixStream,
    events: Arc<Mutex<PolicyEvents>>,
    cancel_gate: Arc<Notify>,
    release_gate: Arc<Notify>,
    behavior: PolicyBehavior,
    slot: Option<ConnectionSlot>,
) {
    let PolicyBehavior {
        claim_errors,
        claim_delay,
    } = behavior;
    let (reader, mut writer) = stream.into_split();

    let Some(_slot) = slot else {
        let encoded = serde_json::to_vec(&RpcReply::Error(ErrorReply::new(
            "too many connections for this uid",
        )))
        .expect("encode policy reply");
        let _ = writer.write_all(&encoded).await;
        let _ = writer.write_all(b"\n").await;
        return;
    };

    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await.is_ok() && !line.is_empty() {
        let value: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(_) => break,
        };

        let Some(op) = value.get("op").and_then(serde_json::Value::as_str) else {
            break;
        };

        if op == "claim_network_flow" {
            sleep(claim_delay).await;
        }

        let Some(reply) = handle_policy_operation(
            op,
            &value,
            &events,
            &cancel_gate,
            &release_gate,
            claim_errors,
        )
        .await
        else {
            break;
        };

        let encoded = serde_json::to_vec(&reply).expect("encode policy reply");

        if writer.write_all(&encoded).await.is_err()
            || writer.write_all(b"\n").await.is_err()
            || writer.flush().await.is_err()
        {
            break;
        }

        line.clear();
    }
}

async fn handle_policy_operation(
    op: &str,
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    cancel_gate: &Notify,
    release_gate: &Notify,
    claim_errors: bool,
) -> Option<RpcReply> {
    match op {
        "open_proxy_session" => Some(RpcReply::ProxySession(ProxySessionReply {
            ok: true,
            proxy_session: ProxySessionToken::from_bytes([1; 32]),
        })),

        "claim_network_flow" => Some(handle_claim(value, events, claim_errors)),
        "claim_network_flow_by_source" => Some(handle_claim_by_source(value, events, claim_errors)),
        "rebind_network_flow" => Some(handle_rebind(value, events)),
        "check_http" => Some(handle_check(value, events, cancel_gate, release_gate).await),
        "release_network_flow" => Some(handle_release(value, events)),
        "cancel_check" => Some(handle_cancel(value, events, cancel_gate)),
        _ => None,
    }
}

fn parse_policy_field<T: serde::de::DeserializeOwned>(value: &serde_json::Value, name: &str) -> T {
    serde_json::from_value(value.get(name).cloned().expect(name)).expect(name)
}

fn handle_claim(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    claim_errors: bool,
) -> RpcReply {
    let flow = parse_policy_field(value, "flow");
    handle_claim_flow(value, flow, events, claim_errors)
}

fn handle_claim_by_source(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    claim_errors: bool,
) -> RpcReply {
    let selector: NetworkFlowSelector = parse_policy_field(value, "selector");

    let flow = NetworkFlowKey::new(
        selector.protocol(),
        selector.source_ip(),
        selector.source_port(),
        selector.source_ip(),
        selector.destination_port(),
    );

    handle_claim_flow(value, flow, events, claim_errors)
}

fn handle_claim_flow(
    value: &serde_json::Value,
    flow: NetworkFlowKey,
    events: &Arc<Mutex<PolicyEvents>>,
    claim_errors: bool,
) -> RpcReply {
    let connection_id = parse_policy_field(value, "connection_id");

    events
        .lock()
        .expect("policy events lock")
        .claims
        .push(ClaimEvent {
            flow: flow.clone(),
            connection_id,
        });

    if claim_errors {
        RpcReply::Error(ErrorReply::new("unknown connection identifier"))
    } else {
        RpcReply::FlowClaim(FlowClaimReply {
            ok: true,
            attribution_token: AttributionToken::from_bytes([2; 32]),
            flow,
            policy_host: NormalizedPolicyHost::parse("localhost").expect("valid policy host"),
            owner_cgroup: None,
        })
    }
}

fn handle_rebind(value: &serde_json::Value, events: &Arc<Mutex<PolicyEvents>>) -> RpcReply {
    let flow = parse_policy_field(value, "flow");

    events
        .lock()
        .expect("policy events lock")
        .rebinds
        .push(flow);

    RpcReply::Simple(SimpleOkReply::OK)
}

async fn handle_check(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    cancel_gate: &Notify,
    release_gate: &Notify,
) -> RpcReply {
    let request: HttpRequest = parse_policy_field(value, "request");
    let url = request.url.to_string();

    events
        .lock()
        .expect("policy events lock")
        .checks
        .push(request.clone());

    let request_id = || parse_policy_field(value, "request_id");

    if url.contains("/policy-error") {
        RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
            request_id(),
            RpcReply::Error(ErrorReply::new("socket owner changed")),
        ))
    } else if url.contains("/pending") {
        release_gate.notified().await;

        events
            .lock()
            .expect("policy events lock")
            .decisions
            .push(true);

        RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
            request_id(),
            RpcReply::HttpCheck(HttpCheckReply::from_verdict(
                request,
                Verdict::allowed(VerdictSource::policy()),
            )),
        ))
    } else if url.contains("/cancel") {
        cancel_gate.notified().await;

        RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
            request_id(),
            RpcReply::HttpCheck(HttpCheckReply::blocked(
                "agent-sandbox: HTTP check cancelled",
            )),
        ))
    } else {
        let allowed = !url.contains("/deny");

        events
            .lock()
            .expect("policy events lock")
            .decisions
            .push(allowed);

        RpcReply::Proxy(agent_sandbox_core::ProxyReply::from_reply(
            request_id(),
            RpcReply::HttpCheck(HttpCheckReply::from_verdict(
                request,
                if allowed {
                    Verdict::allowed(VerdictSource::policy())
                } else {
                    Verdict::denied(VerdictSource::policy())
                },
            )),
        ))
    }
}

fn handle_release(value: &serde_json::Value, events: &Arc<Mutex<PolicyEvents>>) -> RpcReply {
    let token = parse_policy_field(value, "attribution_token");
    let connection_id = parse_policy_field(value, "connection_id");

    events
        .lock()
        .expect("policy events lock")
        .releases
        .push(FlowRelease {
            token,
            connection_id,
        });

    RpcReply::Simple(SimpleOkReply::OK)
}

fn handle_cancel(
    value: &serde_json::Value,
    events: &Arc<Mutex<PolicyEvents>>,
    cancel_gate: &Notify,
) -> RpcReply {
    let request_id = parse_policy_field(value, "request_id");

    events
        .lock()
        .expect("policy events lock")
        .cancellations
        .push(request_id);

    cancel_gate.notify_waiters();
    RpcReply::Simple(SimpleOkReply::OK)
}

impl Drop for FakePolicy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
