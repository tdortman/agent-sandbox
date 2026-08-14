//! Incoming RPC request types (`op` tag).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{
    proxy::{
        AttributionToken, FlowRegistration, NetworkFlowKey, NetworkFlowSelector, ProxyConnectionId,
        ProxyRequestId, ProxySessionToken,
    },
    scope::ApprovalScope,
};
use crate::{
    ProcessIds, ResolvedRequestContext, SandboxPaths,
    http::{HttpRequest, HttpRuleTarget},
    policy::{DbusTarget, FileAccess, FilesystemRule, ResourceAccess, ResourceKind},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
/// Contextual metadata that accompanies a request.
///
/// Carries the invoking process's runtime environment (working directory,
/// home, project root, PID, UID) and, when present, the sandbox session it
/// belongs to. All fields are optional: requests without a full context set
/// them to `None`, and callers resolve them via [`SandboxPaths`] /
/// [`ProcessIds`] as needed.
pub struct RequestContext {
    /// The invoking process's working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,

    /// The invoking process's home directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<PathBuf>,

    /// The project root directory the process is operating in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<PathBuf>,

    /// PID of the invoking process, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// UID of the invoking process, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,

    /// Identifier of the sandbox session the request belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_session_id: Option<String>,
}

impl RequestContext {
    /// Resolve the `cwd`, `home`, and `project_root` fields into a
    /// [`SandboxPaths`], applying the sandbox defaults for paths that are
    /// unset.
    #[must_use]
    pub fn sandbox_paths(&self) -> SandboxPaths {
        SandboxPaths::from_wire(
            self.cwd.clone(),
            self.home.clone(),
            self.project_root.clone(),
        )
    }

    /// Resolve the `pid` and `uid` into [`ProcessIds`], treating zero
    /// values as absent.
    #[must_use]
    pub const fn ids(&self) -> ProcessIds {
        ProcessIds::from_options(self.pid, self.uid)
    }

    /// Overwrite this context's `cwd`, `home`, and `project_root` from
    /// `paths`, returning the updated context.
    #[must_use]
    pub fn with_paths(mut self, paths: &SandboxPaths) -> Self {
        self.cwd = paths.cwd_path();
        self.home = paths.home_path();
        self.project_root = paths.project_root_path();
        self
    }

    /// Build a context from sandbox `paths` and process `ids`, leaving the
    /// session id unset.
    #[must_use]
    pub fn from_paths_and_ids(paths: &SandboxPaths, ids: ProcessIds) -> Self {
        Self {
            cwd: paths.cwd_path(),
            home: paths.home_path(),
            project_root: paths.project_root_path(),
            pid: ids.pid(),
            uid: ids.uid(),
            sandbox_session_id: None,
        }
    }

    /// Build a context from a fully resolved [`ResolvedRequestContext`],
    /// carrying over its paths, ids, and session id.
    #[must_use]
    pub fn from_resolved(ctx: &ResolvedRequestContext) -> Self {
        Self {
            cwd: ctx.paths.cwd_path(),
            home: ctx.paths.home_path(),
            project_root: ctx.paths.project_root_path(),
            pid: ctx.ids.pid(),
            uid: ctx.ids.uid(),
            sandbox_session_id: ctx.sandbox_session_id.clone(),
        }
    }
}

impl From<&SandboxPaths> for RequestContext {
    fn from(paths: &SandboxPaths) -> Self {
        Self {
            cwd: paths.cwd_path(),
            home: paths.home_path(),
            project_root: paths.project_root_path(),
            pid: None,
            uid: None,
            sandbox_session_id: None,
        }
    }
}

impl From<ResolvedRequestContext> for RequestContext {
    fn from(ctx: ResolvedRequestContext) -> Self {
        Self::from_resolved(&ctx)
    }
}

impl From<&ResolvedRequestContext> for RequestContext {
    fn from(ctx: &ResolvedRequestContext) -> Self {
        Self::from_resolved(ctx)
    }
}

/// The resource an approval (`Approve`/`Deny`) decision applies to, used
/// to narrow a decision to a specific host, command, path, or D-Bus target.
///
/// Serialized with a `kind` tag naming the target class, so a UI can
/// present the exact subject being approved or denied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalTarget {
    /// A network connection to a bare host.
    NetworkHost {
        /// The hostname or IP address being connected to.
        host: String,
    },

    /// An HTTP request matched by an [`HttpRuleTarget`].
    Http {
        /// The HTTP rule that describes the approved/denied request.
        target: HttpRuleTarget,
    },

    /// A command run through `sudo` inside the sandbox.
    SudoCommand {
        /// The command and its arguments as an argument vector.
        argv: Vec<String>,
    },

    /// Access to a bare filesystem path.
    FilesystemPath {
        /// The path being accessed.
        path: PathBuf,
    },

    /// Access to a resource at a path within a resource root.
    ResourcePath {
        /// The kind of resource (e.g. token, credential) being accessed.
        resource_kind: ResourceKind,
        /// The path within the resource root.
        path: PathBuf,
    },

    /// A D-Bus connection or message targeted by a rule.
    Dbus {
        /// The D-Bus target the decision applies to.
        target: DbusTarget,
    },
}

/// Incoming RPC request (`op` tag).
///
/// `Check` attribution hints are embedded in `url` via
/// [`attach_check_aliases`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RpcRequest {
    /// Register a UI client so it can send approval requests and receive
    /// decision notifications.
    RegisterUi {
        /// Optional name identifying the UI client.
        #[serde(default)]
        ui_client: Option<String>,

        /// Context of the registering process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Unregister the UI client that sent the request.
    UnregisterUi,

    /// Register a sandbox session and the package that will run inside it.
    RegisterSandbox {
        /// Identifier of the sandbox session being registered.
        session_id: String,
        /// Name of the package running in the sandbox.
        package: String,

        /// PID of the launcher process that will spawn the sandbox (the
        /// wrapper script's `$$`). policyd verifies it against the RPC
        /// peer's real parent so a sandboxed attacker cannot adopt another
        /// session's pre-registered package. 0 on legacy wires means no
        /// binding and is rejected by the store.
        #[serde(default)]
        launcher_pid: u32,
    },

    /// Open a new proxy session for outbound network flows.
    OpenProxySession,

    /// Register a network flow so its connections can be attributed back to
    /// a sandboxed process.
    RegisterNetworkFlow {
        /// The flow registration describing the new network flow.
        registration: FlowRegistration,
    },

    /// Claim an existing network flow for a sandbox session.
    ClaimNetworkFlow {
        /// Token identifying the proxy session.
        proxy_session: ProxySessionToken,
        /// The flow to claim.
        flow: NetworkFlowKey,
        /// The connection to bind to the claimed flow.
        connection_id: ProxyConnectionId,
    },

    /// Claim a network flow by a source selector rather than by key.
    ClaimNetworkFlowBySource {
        /// Token identifying the proxy session.
        proxy_session: ProxySessionToken,
        /// Selector describing the flow's origin.
        selector: NetworkFlowSelector,
        /// The connection to bind to the claimed flow.
        connection_id: ProxyConnectionId,
    },

    /// Rebind a connection from one attributed flow to another.
    RebindNetworkFlow {
        /// Token identifying the proxy session.
        proxy_session: ProxySessionToken,
        /// Token proving the prior attribution.
        attribution_token: AttributionToken,
        /// The connection being rebound.
        connection_id: ProxyConnectionId,
        /// The flow to bind the connection to.
        flow: NetworkFlowKey,
    },

    /// Check whether an HTTP request is allowed to proceed.
    CheckHttp {
        /// Token identifying the proxy session.
        proxy_session: ProxySessionToken,
        /// Identifier used to correlate the check with a response.
        request_id: ProxyRequestId,
        /// Token proving attribution of the flow.
        attribution_token: AttributionToken,
        /// The HTTP request being checked against policy.
        request: HttpRequest,
    },

    /// Check whether a network flow is allowed to proceed.
    CheckNetworkFlow {
        /// Token identifying the proxy session.
        proxy_session: ProxySessionToken,
        /// Identifier used to correlate the check with a response.
        request_id: ProxyRequestId,
        /// Token proving attribution of the flow.
        attribution_token: AttributionToken,
    },

    /// Cancel a previously issued check so its result is ignored.
    CancelCheck {
        /// Token identifying the proxy session.
        proxy_session: ProxySessionToken,
        /// Identifier of the check to cancel.
        request_id: ProxyRequestId,
    },

    /// Release a network flow's binding so its connection.id is freed.
    ReleaseNetworkFlow {
        /// Token identifying the proxy session.
        proxy_session: ProxySessionToken,
        /// Token proving attribution of the flow being released.
        attribution_token: AttributionToken,
        /// The connection being released.
        connection_id: ProxyConnectionId,
    },

    /// Check whether a network connection to a host is allowed.
    Check {
        /// The hostname or IP the check applies to, if any.
        #[serde(default)]
        host: Option<String>,

        /// The host actually being connected to when `host` is an alias,
        /// if any.
        #[serde(default)]
        connect_host: Option<String>,

        /// The remote port, if any.
        #[serde(default)]
        port: Option<u16>,

        /// The URL scheme (defaults to `https`).
        #[serde(default = "default_https")]
        scheme: String,

        /// The full URL being checked, including attribution hints.
        url: Option<String>,

        /// Context of the checking process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Check whether a filesystem access is allowed.
    CheckFilesystem {
        /// The path being accessed.
        path: PathBuf,

        /// The kind of access (read/write/execute) being requested.
        #[serde(default)]
        access: FileAccess,

        /// Context of the checking process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Check whether access to a resource at a path is allowed.
    CheckResource {
        /// The kind of resource being accessed.
        kind: ResourceKind,
        /// The path within the resource root.
        path: PathBuf,

        /// The kind of resource access being requested.
        #[serde(default)]
        access: ResourceAccess,

        /// Context of the checking process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Check whether a D-Bus connection or message is allowed.
    CheckDbus {
        /// The D-Bus target being checked.
        target: DbusTarget,

        /// Context of the checking process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Start monitoring a filesystem tree for rule violations.
    StartFilesystemMonitor {
        /// Context of the monitoring process.
        #[serde(default)]
        ctx: RequestContext,

        /// Static rules always allowed without triggering an event.
        #[serde(default)]
        static_allow: Vec<FilesystemRule>,
    },

    /// Elevate privileges to a given command.
    Elevate {
        /// The command and its arguments to run with elevated privileges.
        argv: Vec<String>,

        /// Context of the elevating process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Approve a previously issued check.
    Approve {
        /// Identifier of the check being approved.
        id: String,
        /// How long the approval remains in effect.
        scope: ApprovalScope,

        /// Sandbox session the approval applies to, if any.
        #[serde(default)]
        session_id: Option<String>,

        /// Specific target the approval is narrowed to, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<ApprovalTarget>,

        /// Human-readable note attached to the approval, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,

        /// Context of the approving process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Approve a check for a host, without referencing a check id.
    ApproveHost {
        /// The host being approved.
        host: String,
        /// The port being approved.
        port: u16,
        /// How long the approval remains in effect.
        scope: ApprovalScope,

        /// Sandbox session the approval applies to, if any.
        #[serde(default)]
        session_id: Option<String>,

        /// Context of the approving process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Approve a check for HTTP traffic, without referencing a check id.
    ApproveHttp {
        /// The HTTP rule being approved.
        target: HttpRuleTarget,
        /// How long the approval remains in effect.
        scope: ApprovalScope,

        /// Sandbox session the approval applies to, if any.
        #[serde(default)]
        session_id: Option<String>,

        /// Context of the approving process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Deny a previously issued check.
    Deny {
        /// Identifier of the check being denied.
        id: String,

        /// How long the denial remains in effect (defaults to a one-off).
        #[serde(default = "default_once_scope")]
        scope: ApprovalScope,

        /// Sandbox session the denial applies to, if any.
        #[serde(default)]
        session_id: Option<String>,

        /// Specific target the denial is narrowed to, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<ApprovalTarget>,

        /// Human-readable note attached to the denial, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,

        /// Context of the denying process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Request the current status of a process.
    Status {
        /// Context of the requesting process.
        #[serde(default)]
        ctx: RequestContext,
    },

    /// Request a reload of policy and configuration.
    Reload {
        /// Context of the requesting process.
        #[serde(default)]
        ctx: RequestContext,
    },
}

/// Parse a JSON-line RPC request, rejecting unknown fields on proxy ops.
///
/// The derived [`Deserialize`] for [`RpcRequest`] is intentionally lenient
/// about unknown fields so UI clients can send extra metadata. Proxy
/// attribution requests are strict: a mistyped field would otherwise be
/// silently dropped and a flow attributed without its session token.
///
/// # Errors
///
/// Returns a JSON error when the line is not a valid request or carries an
/// unknown field on a proxy op.
pub fn parse_rpc_request(line: &str) -> Result<RpcRequest, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    validate_proxy_fields(&value).map_err(<serde_json::Error as serde::de::Error>::custom)?;
    serde_json::from_value(value)
}

fn validate_proxy_fields(value: &serde_json::Value) -> Result<(), String> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };

    let Some(op) = object.get("op").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };

    let allowed = match op {
        "open_proxy_session" => &["op"][..],
        "register_network_flow" => &["op", "registration"][..],
        "claim_network_flow" => &["op", "proxy_session", "flow", "connection_id"][..],
        "claim_network_flow_by_source" => &["op", "proxy_session", "selector", "connection_id"][..],
        "rebind_network_flow" => &[
            "op",
            "proxy_session",
            "attribution_token",
            "connection_id",
            "flow",
        ][..],
        "check_http" => &[
            "op",
            "proxy_session",
            "request_id",
            "attribution_token",
            "request",
        ][..],
        "check_network_flow" => &["op", "proxy_session", "request_id", "attribution_token"][..],
        "cancel_check" => &["op", "proxy_session", "request_id"][..],
        "release_network_flow" => {
            &["op", "proxy_session", "attribution_token", "connection_id"][..]
        }
        _ => return Ok(()),
    };

    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(format!("unknown field `{field}`"));
    }

    Ok(())
}

impl RpcRequest {
    #[must_use]
    /// Return the [`RequestContext`] carried by variants that embed one, or
    /// `None` for variants that do not carry a context.
    pub const fn context(&self) -> Option<&RequestContext> {
        match self {
            Self::RegisterUi { ctx, .. }
            | Self::Check { ctx, .. }
            | Self::CheckFilesystem { ctx, .. }
            | Self::CheckResource { ctx, .. }
            | Self::CheckDbus { ctx, .. }
            | Self::StartFilesystemMonitor { ctx, .. }
            | Self::Elevate { ctx, .. }
            | Self::Approve { ctx, .. }
            | Self::ApproveHost { ctx, .. }
            | Self::ApproveHttp { ctx, .. }
            | Self::Deny { ctx, .. }
            | Self::Status { ctx }
            | Self::Reload { ctx } => Some(ctx),

            Self::UnregisterUi
            | Self::OpenProxySession
            | Self::RegisterNetworkFlow { .. }
            | Self::ClaimNetworkFlow { .. }
            | Self::ClaimNetworkFlowBySource { .. }
            | Self::RebindNetworkFlow { .. }
            | Self::CheckHttp { .. }
            | Self::CheckNetworkFlow { .. }
            | Self::CancelCheck { .. }
            | Self::ReleaseNetworkFlow { .. }
            | Self::RegisterSandbox { .. } => None,
        }
    }
}

const CHECK_ALIASES_MARKER: &str = "#agent-sandbox-aliases=";

/// Attach attribution hints to a check URL for UI display only.
#[must_use]
pub fn attach_check_aliases(url: Option<String>, aliases: &[String]) -> Option<String> {
    if aliases.is_empty() {
        return url;
    }

    let base = url.unwrap_or_default();
    let payload = serde_json::to_string(aliases).ok()?;
    Some(format!("{base}{CHECK_ALIASES_MARKER}{payload}"))
}

/// Result of splitting attribution aliases from a check/UI URL.
pub struct AliasSplit {
    /// The URL with any attribution hints stripped, or `None` if the input
    /// URL was `None`.
    pub url: Option<String>,
    /// Attribution aliases parsed from the URL (empty when none present).
    pub aliases: Vec<String>,
}

/// Split attribution hints from a check URL.
#[must_use]
pub fn split_check_aliases(url: Option<String>) -> AliasSplit {
    let Some(url) = url else {
        return AliasSplit {
            url: None,
            aliases: Vec::new(),
        };
    };

    let Some((base, raw)) = url.split_once(CHECK_ALIASES_MARKER) else {
        return AliasSplit {
            url: Some(url),
            aliases: Vec::new(),
        };
    };

    let aliases = serde_json::from_str(raw).unwrap_or_default();

    AliasSplit {
        url: Some(base.to_string()),
        aliases,
    }
}

fn default_https() -> String {
    "https".into()
}

const fn default_once_scope() -> ApprovalScope {
    ApprovalScope::Once
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ApprovalTarget, RequestContext, RpcRequest};
    use crate::{FileAccess, ProcessIds, ResolvedRequestContext, SandboxPaths};

    #[test]
    fn attach_check_aliases_roundtrip() {
        let result = super::split_check_aliases(super::attach_check_aliases(
            Some("tcp://104.18.32.47:443".into()),
            &["chatgpt.com".into()],
        ));

        assert_eq!(result.url.as_deref(), Some("tcp://104.18.32.47:443"));
        assert_eq!(result.aliases, vec!["chatgpt.com".to_string()]);
    }

    #[test]
    fn check_request_deserializes() {
        let req: RpcRequest = serde_json::from_str(
            r#"{"op":"check","host":"example.com","port":443,"scheme":"https","ctx":{"cwd":"/tmp"}}"#,
        )
        .unwrap();

        assert!(matches!(req, RpcRequest::Check { .. }));
    }

    #[test]
    fn proxy_request_rejects_unknown_fields() {
        let error = super::parse_rpc_request(r#"{"op":"open_proxy_session","unexpected":true}"#)
            .expect_err("proxy wire must reject unknown fields");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rebind_network_flow_round_trips_and_rejects_unknown_fields() {
        use crate::{
            AttributionToken, FlowProtocol, NetworkFlowKey, ProxyConnectionId, ProxySessionToken,
        };

        let flow = NetworkFlowKey::try_new(
            FlowProtocol::Udp,
            "127.0.0.1".parse().expect("valid source"),
            4242,
            "1.1.1.1".parse().expect("valid destination"),
            443,
        )
        .expect("valid flow");

        let request = RpcRequest::RebindNetworkFlow {
            proxy_session: ProxySessionToken::from_bytes([1; 32]),
            attribution_token: AttributionToken::from_bytes([2; 32]),
            connection_id: ProxyConnectionId::new(),
            flow,
        };

        let wire = serde_json::to_value(&request).expect("serialize rebind");
        assert_eq!(wire["op"], "rebind_network_flow");

        let decoded =
            serde_json::from_value::<RpcRequest>(wire.clone()).expect("deserialize rebind");

        assert_eq!(
            serde_json::to_value(&decoded).expect("reserialize rebind"),
            wire
        );

        let mut unknown = wire;
        unknown["unexpected"] = serde_json::json!(true);
        let line = serde_json::to_string(&unknown).expect("serialize rebind with unknown field");

        let error =
            super::parse_rpc_request(&line).expect_err("rebind wire must reject unknown fields");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn release_network_flow_requires_connection_identifier() {
        use crate::{AttributionToken, ProxyConnectionId, ProxySessionToken};

        let request = RpcRequest::ReleaseNetworkFlow {
            proxy_session: ProxySessionToken::from_bytes([1; 32]),
            attribution_token: AttributionToken::from_bytes([2; 32]),
            connection_id: ProxyConnectionId::new(),
        };

        let wire = serde_json::to_value(&request).expect("serialize release");
        assert_eq!(wire["op"], "release_network_flow");

        let decoded =
            serde_json::from_value::<RpcRequest>(wire.clone()).expect("deserialize release");

        assert_eq!(
            serde_json::to_value(&decoded).expect("reserialize release"),
            wire
        );

        let mut unknown = wire;
        unknown["unexpected"] = serde_json::json!(true);
        let line = serde_json::to_string(&unknown).expect("serialize release with unknown field");

        let error =
            super::parse_rpc_request(&line).expect_err("release wire must reject unknown fields");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn register_sandbox_round_trips() {
        let request = RpcRequest::RegisterSandbox {
            session_id: "sandbox-1".into(),
            package: "omp".into(),
            launcher_pid: 42,
        };

        let wire = serde_json::to_value(&request).expect("serialize register sandbox");
        assert_eq!(wire["op"], "register_sandbox");
        assert_eq!(wire["session_id"], "sandbox-1");
        assert_eq!(wire["package"], "omp");
        assert_eq!(wire["launcher_pid"], 42);

        let decoded = serde_json::from_value::<RpcRequest>(wire.clone())
            .expect("deserialize register sandbox");

        assert_eq!(
            serde_json::to_value(&decoded).expect("reserialize register sandbox"),
            wire
        );
    }

    #[test]
    fn register_sandbox_defaults_missing_launcher_pid_to_zero() {
        let req: RpcRequest = serde_json::from_str(
            r#"{"op":"register_sandbox","session_id":"sandbox-1","package":"omp"}"#,
        )
        .expect("legacy wire without launcher_pid must still deserialize");

        match req {
            RpcRequest::RegisterSandbox { launcher_pid, .. } => {
                assert_eq!(launcher_pid, 0, "missing launcher_pid must default to 0");
            }

            _ => panic!("expected RegisterSandbox request"),
        }
    }

    #[test]
    fn approve_request_deserializes_with_target_override() {
        let req: RpcRequest = serde_json::from_str(
            r#"{"op":"approve","id":"p1","scope":"project","target":{"kind":"network_host","host":"*.baz.com"},"ctx":{"cwd":"/tmp"}}"#,
        )
        .unwrap();

        assert!(matches!(req, RpcRequest::Approve {
            target: Some(ApprovalTarget::NetworkHost { .. }),
            ..
        }));
    }

    #[test]
    fn request_context_preserves_resolved_context_fields() {
        let resolved = ResolvedRequestContext::new(
            SandboxPaths::new("/cwd", "/home/user", "/repo"),
            ProcessIds::new(42, 1000),
            Some("sandbox-a".into()),
        );

        let bridged = RequestContext::from(&resolved);
        assert_eq!(bridged.cwd.as_deref(), Some(std::path::Path::new("/cwd")));

        assert_eq!(
            bridged.home.as_deref(),
            Some(std::path::Path::new("/home/user"))
        );

        assert_eq!(
            bridged.project_root.as_deref(),
            Some(std::path::Path::new("/repo"))
        );

        assert_eq!(bridged.pid, Some(42));
        assert_eq!(bridged.uid, Some(1000));
        assert_eq!(bridged.sandbox_session_id.as_deref(), Some("sandbox-a"));
    }

    #[test]
    fn start_filesystem_monitor_defaults_static_allow_empty() {
        let req: RpcRequest =
            serde_json::from_str(r#"{"op":"start_filesystem_monitor","ctx":{"cwd":"/home/user"}}"#)
                .unwrap();

        match req {
            RpcRequest::StartFilesystemMonitor { static_allow, .. } => {
                assert!(
                    static_allow.is_empty(),
                    "static_allow must default to empty"
                );
            }

            _ => panic!("expected StartFilesystemMonitor"),
        }
    }

    #[test]
    fn start_filesystem_monitor_with_static_allow() {
        let req: RpcRequest = serde_json::from_str(
            r#"{"op":"start_filesystem_monitor","ctx":{"cwd":"/home/user"},"static_allow":[{"path":"/home/user","access":"all"}]}"#,
        )
        .unwrap();

        match req {
            RpcRequest::StartFilesystemMonitor { static_allow, .. } => {
                assert_eq!(static_allow.len(), 1);
                assert_eq!(static_allow[0].path, PathBuf::from("/home/user"));
                assert_eq!(static_allow[0].access, FileAccess::All);
            }

            _ => panic!("expected StartFilesystemMonitor"),
        }
    }
}
