//! Incoming RPC request types (`op` tag).

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

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<PathBuf>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<PathBuf>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_session_id: Option<String>,
}

impl RequestContext {
    #[must_use]
    pub fn sandbox_paths(&self) -> SandboxPaths {
        SandboxPaths::from_wire(
            self.cwd.clone(),
            self.home.clone(),
            self.project_root.clone(),
        )
    }

    #[must_use]
    pub const fn ids(&self) -> ProcessIds {
        ProcessIds::from_options(self.pid, self.uid)
    }

    #[must_use]
    pub fn with_paths(mut self, paths: &SandboxPaths) -> Self {
        self.cwd = paths.cwd_path();
        self.home = paths.home_path();
        self.project_root = paths.project_root_path();
        self
    }

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalTarget {
    NetworkHost {
        host: String,
    },

    Http {
        target: HttpRuleTarget,
    },

    SudoCommand {
        argv: Vec<String>,
    },

    FilesystemPath {
        path: PathBuf,
    },

    ResourcePath {
        resource_kind: ResourceKind,
        path: PathBuf,
    },

    Dbus {
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
    RegisterUi {
        #[serde(default)]
        ui_client: Option<String>,

        #[serde(default)]
        ctx: RequestContext,
    },

    UnregisterUi,
    OpenProxySession,

    RegisterNetworkFlow {
        registration: FlowRegistration,
    },

    ClaimNetworkFlow {
        proxy_session: ProxySessionToken,
        flow: NetworkFlowKey,
        connection_id: ProxyConnectionId,
    },

    ClaimNetworkFlowBySource {
        proxy_session: ProxySessionToken,
        selector: NetworkFlowSelector,
        connection_id: ProxyConnectionId,
    },

    RebindNetworkFlow {
        proxy_session: ProxySessionToken,
        attribution_token: AttributionToken,
        connection_id: ProxyConnectionId,
        flow: NetworkFlowKey,
    },

    CheckHttp {
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
        request: HttpRequest,
    },

    CheckNetworkFlow {
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
    },

    CancelCheck {
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
    },

    ReleaseNetworkFlow {
        proxy_session: ProxySessionToken,
        attribution_token: AttributionToken,
        connection_id: ProxyConnectionId,
    },

    Check {
        #[serde(default)]
        host: Option<String>,

        #[serde(default)]
        connect_host: Option<String>,

        #[serde(default)]
        port: Option<u16>,

        #[serde(default = "default_https")]
        scheme: String,

        url: Option<String>,

        #[serde(default)]
        ctx: RequestContext,
    },

    CheckFilesystem {
        path: PathBuf,

        #[serde(default)]
        access: FileAccess,

        #[serde(default)]
        ctx: RequestContext,
    },

    CheckResource {
        kind: ResourceKind,
        path: PathBuf,

        #[serde(default)]
        access: ResourceAccess,

        #[serde(default)]
        ctx: RequestContext,
    },

    CheckDbus {
        target: DbusTarget,

        #[serde(default)]
        ctx: RequestContext,
    },

    StartFilesystemMonitor {
        #[serde(default)]
        ctx: RequestContext,

        #[serde(default)]
        static_allow: Vec<FilesystemRule>,
    },

    Elevate {
        argv: Vec<String>,

        #[serde(default)]
        ctx: RequestContext,
    },

    Approve {
        id: String,
        scope: ApprovalScope,

        #[serde(default)]
        session_id: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<ApprovalTarget>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,

        #[serde(default)]
        ctx: RequestContext,
    },

    ApproveHost {
        host: String,
        port: u16,
        scope: ApprovalScope,

        #[serde(default)]
        session_id: Option<String>,

        #[serde(default)]
        ctx: RequestContext,
    },

    ApproveHttp {
        target: HttpRuleTarget,
        scope: ApprovalScope,

        #[serde(default)]
        session_id: Option<String>,

        #[serde(default)]
        ctx: RequestContext,
    },

    Deny {
        id: String,

        #[serde(default = "default_once_scope")]
        scope: ApprovalScope,

        #[serde(default)]
        session_id: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<ApprovalTarget>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,

        #[serde(default)]
        ctx: RequestContext,
    },

    Status {
        #[serde(default)]
        ctx: RequestContext,
    },

    Reload {
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
            | Self::ReleaseNetworkFlow { .. } => None,
        }
    }

    pub const fn context_mut(&mut self) -> Option<&mut RequestContext> {
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
            | Self::ReleaseNetworkFlow { .. } => None,
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
    pub url: Option<String>,
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
    use super::{ApprovalTarget, RequestContext, RpcRequest};
    use crate::{FileAccess, ProcessIds, ResolvedRequestContext, SandboxPaths};
    use std::path::PathBuf;

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
