//! Incoming RPC request types (`op` tag).

use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};

use crate::http::{HttpRequest, HttpRuleTarget};
use crate::{ProcessIds, ResolvedRequestContext, SandboxPaths};

use super::proxy::{
    AttributionToken, FlowRegistration, NetworkFlowKey, ProxyConnectionId, ProxyRequestId,
    ProxySessionToken,
};
use super::scope::ApprovalScope;
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

use crate::policy::FileAccess;

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
        resource_kind: crate::policy::ResourceKind,
        path: PathBuf,
    },
}

/// Incoming RPC request (`op` tag).
///
/// `Check` attribution hints are embedded in `url` via [`attach_check_aliases`].
#[derive(Debug, Clone, Serialize)]
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
        kind: crate::policy::ResourceKind,
        path: PathBuf,
        #[serde(default)]
        access: crate::policy::ResourceAccess,
        #[serde(default)]
        ctx: RequestContext,
    },
    StartFilesystemMonitor {
        #[serde(default)]
        ctx: RequestContext,
        #[serde(default)]
        static_allow: Vec<crate::policy::FilesystemRule>,
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

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum RpcRequestWire {
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
        kind: crate::policy::ResourceKind,
        path: PathBuf,
        #[serde(default)]
        access: crate::policy::ResourceAccess,
        #[serde(default)]
        ctx: RequestContext,
    },
    StartFilesystemMonitor {
        #[serde(default)]
        ctx: RequestContext,
        #[serde(default)]
        static_allow: Vec<crate::policy::FilesystemRule>,
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

impl<'de> Deserialize<'de> for RpcRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        validate_proxy_fields(&value).map_err(serde::de::Error::custom)?;
        let wire: RpcRequestWire =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(wire.into())
    }
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
        "check_http" => &[
            "op",
            "proxy_session",
            "request_id",
            "attribution_token",
            "request",
        ][..],
        "check_network_flow" => &["op", "proxy_session", "request_id", "attribution_token"][..],
        "cancel_check" => &["op", "proxy_session", "request_id"][..],
        "release_network_flow" => &["op", "proxy_session", "attribution_token"][..],
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
    const fn register_network_flow(registration: FlowRegistration) -> Self {
        Self::RegisterNetworkFlow { registration }
    }

    const fn claim_network_flow(
        proxy_session: ProxySessionToken,
        flow: NetworkFlowKey,
        connection_id: ProxyConnectionId,
    ) -> Self {
        Self::ClaimNetworkFlow {
            proxy_session,
            flow,
            connection_id,
        }
    }

    const fn check_http(
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
        request: HttpRequest,
    ) -> Self {
        Self::CheckHttp {
            proxy_session,
            request_id,
            attribution_token,
            request,
        }
    }

    const fn check_network_flow(
        proxy_session: ProxySessionToken,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
    ) -> Self {
        Self::CheckNetworkFlow {
            proxy_session,
            request_id,
            attribution_token,
        }
    }

    const fn cancel_check(proxy_session: ProxySessionToken, request_id: ProxyRequestId) -> Self {
        Self::CancelCheck {
            proxy_session,
            request_id,
        }
    }

    const fn release_network_flow(
        proxy_session: ProxySessionToken,
        attribution_token: AttributionToken,
    ) -> Self {
        Self::ReleaseNetworkFlow {
            proxy_session,
            attribution_token,
        }
    }

    const fn check(
        host: Option<String>,
        connect_host: Option<String>,
        port: Option<u16>,
        scheme: String,
        url: Option<String>,
        ctx: RequestContext,
    ) -> Self {
        Self::Check {
            host,
            connect_host,
            port,
            scheme,
            url,
            ctx,
        }
    }

    const fn check_resource(
        kind: crate::policy::ResourceKind,
        path: PathBuf,
        access: crate::policy::ResourceAccess,
        ctx: RequestContext,
    ) -> Self {
        Self::CheckResource {
            kind,
            path,
            access,
            ctx,
        }
    }

    const fn start_filesystem_monitor(
        ctx: RequestContext,
        static_allow: Vec<crate::policy::FilesystemRule>,
    ) -> Self {
        Self::StartFilesystemMonitor { ctx, static_allow }
    }

    const fn approve(
        id: String,
        scope: ApprovalScope,
        session_id: Option<String>,
        target: Option<ApprovalTarget>,
        ctx: RequestContext,
    ) -> Self {
        Self::Approve {
            id,
            scope,
            session_id,
            target,
            ctx,
        }
    }

    const fn approve_host(
        host: String,
        port: u16,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: RequestContext,
    ) -> Self {
        Self::ApproveHost {
            host,
            port,
            scope,
            session_id,
            ctx,
        }
    }

    const fn approve_http(
        target: HttpRuleTarget,
        scope: ApprovalScope,
        session_id: Option<String>,
        ctx: RequestContext,
    ) -> Self {
        Self::ApproveHttp {
            target,
            scope,
            session_id,
            ctx,
        }
    }

    const fn deny(
        id: String,
        scope: ApprovalScope,
        session_id: Option<String>,
        target: Option<ApprovalTarget>,
        ctx: RequestContext,
    ) -> Self {
        Self::Deny {
            id,
            scope,
            session_id,
            target,
            ctx,
        }
    }
}

impl From<RpcRequestWire> for RpcRequest {
    fn from(value: RpcRequestWire) -> Self {
        match value {
            RpcRequestWire::RegisterUi { ui_client, ctx } => Self::RegisterUi { ui_client, ctx },
            RpcRequestWire::UnregisterUi => Self::UnregisterUi,
            RpcRequestWire::OpenProxySession => Self::OpenProxySession,
            RpcRequestWire::RegisterNetworkFlow { registration } => {
                Self::register_network_flow(registration)
            }
            RpcRequestWire::ClaimNetworkFlow {
                proxy_session,
                flow,
                connection_id,
            } => Self::claim_network_flow(proxy_session, flow, connection_id),
            RpcRequestWire::CheckHttp {
                proxy_session,
                request_id,
                attribution_token,
                request,
            } => Self::check_http(proxy_session, request_id, attribution_token, request),
            RpcRequestWire::CheckNetworkFlow {
                proxy_session,
                request_id,
                attribution_token,
            } => Self::check_network_flow(proxy_session, request_id, attribution_token),
            RpcRequestWire::CancelCheck {
                proxy_session,
                request_id,
            } => Self::cancel_check(proxy_session, request_id),
            RpcRequestWire::ReleaseNetworkFlow {
                proxy_session,
                attribution_token,
            } => Self::release_network_flow(proxy_session, attribution_token),
            RpcRequestWire::Check {
                host,
                connect_host,
                port,
                scheme,
                url,
                ctx,
            } => Self::check(host, connect_host, port, scheme, url, ctx),
            RpcRequestWire::CheckFilesystem { path, access, ctx } => {
                Self::CheckFilesystem { path, access, ctx }
            }
            RpcRequestWire::CheckResource {
                kind,
                path,
                access,
                ctx,
            } => Self::check_resource(kind, path, access, ctx),
            RpcRequestWire::StartFilesystemMonitor { ctx, static_allow } => {
                Self::start_filesystem_monitor(ctx, static_allow)
            }
            RpcRequestWire::Elevate { argv, ctx } => Self::Elevate { argv, ctx },
            RpcRequestWire::Approve {
                id,
                scope,
                session_id,
                target,
                ctx,
            } => Self::approve(id, scope, session_id, target, ctx),
            RpcRequestWire::ApproveHost {
                host,
                port,
                scope,
                session_id,
                ctx,
            } => Self::approve_host(host, port, scope, session_id, ctx),
            RpcRequestWire::ApproveHttp {
                target,
                scope,
                session_id,
                ctx,
            } => Self::approve_http(target, scope, session_id, ctx),
            RpcRequestWire::Deny {
                id,
                scope,
                session_id,
                target,
                ctx,
            } => Self::deny(id, scope, session_id, target, ctx),
            RpcRequestWire::Status { ctx } => Self::Status { ctx },
            RpcRequestWire::Reload { ctx } => Self::Reload { ctx },
        }
    }
}

impl RpcRequest {
    #[must_use]
    pub const fn context(&self) -> Option<&RequestContext> {
        match self {
            Self::RegisterUi { ctx, .. }
            | Self::Check { ctx, .. }
            | Self::CheckFilesystem { ctx, .. }
            | Self::CheckResource { ctx, .. }
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

/// Attach attribution hints to a UI prompt URL.
#[must_use]
pub fn attach_ui_aliases(url: Option<String>, aliases: &[String]) -> Option<String> {
    attach_check_aliases(url, aliases)
}

/// Split attribution hints from a UI prompt URL.
#[must_use]
pub fn split_ui_aliases(url: Option<String>) -> AliasSplit {
    split_check_aliases(url)
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
    use crate::{ProcessIds, ResolvedRequestContext, SandboxPaths};
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
        let error =
            serde_json::from_str::<RpcRequest>(r#"{"op":"open_proxy_session","unexpected":true}"#)
                .expect_err("proxy wire must reject unknown fields");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn approve_request_deserializes_with_target_override() {
        let req: RpcRequest = serde_json::from_str(
            r#"{"op":"approve","id":"p1","scope":"project","target":{"kind":"network_host","host":"*.baz.com"},"ctx":{"cwd":"/tmp"}}"#,
        )
        .unwrap();
        assert!(matches!(
            req,
            RpcRequest::Approve {
                target: Some(ApprovalTarget::NetworkHost { .. }),
                ..
            }
        ));
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
                assert_eq!(static_allow[0].access, crate::policy::FileAccess::All);
            }
            _ => panic!("expected StartFilesystemMonitor"),
        }
    }
}
