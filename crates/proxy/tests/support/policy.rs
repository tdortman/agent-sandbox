use super::*;

/// One observed flow claim with the connection identity that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEvent {
    pub flow: agent_sandbox_core::NetworkFlowKey,
    pub connection_id: ProxyConnectionId,
}

/// One observed ownership release. The connection identifier must match the
/// identifier recorded when the flow was claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRelease {
    pub token: AttributionToken,
    pub connection_id: ProxyConnectionId,
}

#[derive(Debug, Default)]
pub struct PolicyEvents {
    pub claims: Vec<ClaimEvent>,
    pub checks: Vec<HttpRequest>,
    pub decisions: Vec<bool>,
    pub cancellations: Vec<agent_sandbox_core::ProxyRequestId>,
    pub rebinds: Vec<agent_sandbox_core::NetworkFlowKey>,
    pub releases: Vec<FlowRelease>,
}

pub struct FakePolicy {
    pub socket: PathBuf,
    pub events: Arc<Mutex<PolicyEvents>>,
    task: JoinHandle<()>,
}

impl FakePolicy {
    pub fn start(root: &Path) -> Self {
        Self::start_with_behavior(root, false)
    }

    /// Start a policy service that rejects every flow claim, so the proxy's
    /// connection-level failure path can be observed.
    pub fn start_claim_error(root: &Path) -> Self {
        Self::start_with_behavior(root, true)
    }

    fn start_with_behavior(root: &Path, claim_errors: bool) -> Self {
        let socket = root.join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind fake policy socket");
        let events = Arc::new(Mutex::new(PolicyEvents::default()));
        let task_events = events.clone();
        let cancel_gate = Arc::new(Notify::new());

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let events = task_events.clone();
                let cancel_gate = cancel_gate.clone();
                tokio::spawn(serve_policy_connection(
                    stream,
                    events,
                    cancel_gate,
                    claim_errors,
                ));
            }
        });

        Self {
            socket,
            events,
            task,
        }
    }
}

async fn serve_policy_connection(
    stream: tokio::net::UnixStream,
    events: Arc<Mutex<PolicyEvents>>,
    cancel_gate: Arc<Notify>,
    claim_errors: bool,
) {
    let (reader, mut writer) = stream.into_split();
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

        let Some(reply) =
            handle_policy_operation(op, &value, &events, &cancel_gate, claim_errors).await
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
        "check_http" => Some(handle_check(value, events, cancel_gate).await),
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
