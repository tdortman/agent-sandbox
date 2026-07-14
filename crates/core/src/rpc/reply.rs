use std::borrow::Cow;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::http::{HttpRequest, HttpRuleTarget};
use crate::policy::{FileAccess, Policy, ResourceAccess, ResourceKind};

use super::{
    message::RpcMessage,
    proxy::{AttributionToken, ProxyRequestId, ProxySessionToken},
    scope::ApprovalScope,
};
/// Response envelope for pipelined proxy checks and cancellations.
///
/// The request identifier is part of the response rather than relying on
/// response ordering, because proxy checks may complete out of order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyReply {
    pub request_id: ProxyRequestId,
    pub reply: ProxyReplyBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reply", rename_all = "snake_case")]
pub enum ProxyReplyBody {
    HttpCheck(HttpCheckReply),
    NetworkFlow(CheckReply),
    Canceled(SimpleOkReply),
    Error(ErrorReply),
}

impl ProxyReply {
    #[must_use]
    pub fn from_reply(request_id: ProxyRequestId, reply: RpcReply) -> Self {
        let reply = match reply {
            RpcReply::HttpCheck(reply) => ProxyReplyBody::HttpCheck(reply),
            RpcReply::Check(reply) => ProxyReplyBody::NetworkFlow(reply),
            RpcReply::Simple(reply) => ProxyReplyBody::Canceled(reply),
            RpcReply::Error(reply) => ProxyReplyBody::Error(reply),
            _ => ProxyReplyBody::Error(ErrorReply::new(
                "invalid reply for a pipelined proxy request",
            )),
        };
        Self { request_id, reply }
    }
}

/// policyd → client response line.
///
/// Variants with optional `error` fields come before `Error` so untagged
/// serde does not greedily match them as `Error`. `Simple` must be last:
/// it only has `ok`, so it would otherwise accept any `{"ok": true, ...}`
/// object and drop fields.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum RpcReply {
    RegisterUi(RegisterUiReply),
    Proxy(ProxyReply),
    ProxySession(ProxySessionReply),
    FlowClaim(FlowClaimReply),
    FilesystemCheck(FilesystemCheckReply),
    ResourceCheck(ResourceCheckReply),
    FilesystemMonitor(FilesystemMonitorReply),
    HttpCheck(HttpCheckReply),
    Check(CheckReply),
    Elevate(ElevateReply),
    ScopeAction(ScopeActionReply),
    Status(StatusReply),
    Error(ErrorReply),
    Simple(SimpleOkReply),
}

impl<'de> Deserialize<'de> for RpcReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        macro_rules! try_variant {
            ($variant:ident, $ty:ty) => {
                match serde_json::from_value::<$ty>(value.clone()) {
                    Ok(reply) => return Ok(Self::$variant(reply)),
                    Err(err) => {
                        let err = err.to_string();
                        if err.contains("invalid source") {
                            return Err(serde::de::Error::custom(err));
                        }
                    }
                }
            };
        }
        try_variant!(Proxy, ProxyReply);
        try_variant!(ProxySession, ProxySessionReply);
        try_variant!(FlowClaim, FlowClaimReply);

        try_variant!(RegisterUi, RegisterUiReply);
        try_variant!(FilesystemCheck, FilesystemCheckReply);
        try_variant!(ResourceCheck, ResourceCheckReply);
        try_variant!(FilesystemMonitor, FilesystemMonitorReply);
        try_variant!(Check, CheckReply);
        try_variant!(HttpCheck, HttpCheckReply);
        try_variant!(Elevate, ElevateReply);
        try_variant!(ScopeAction, ScopeActionReply);
        try_variant!(Status, StatusReply);
        try_variant!(Error, ErrorReply);
        try_variant!(Simple, SimpleOkReply);

        Err(serde::de::Error::custom(
            "data did not match any RpcReply variant",
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReply {
    pub ok: bool,
    pub error: String,
}

impl ErrorReply {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
        }
    }
}

impl From<crate::error::InvalidScopeError> for RpcReply {
    fn from(err: crate::error::InvalidScopeError) -> Self {
        Self::Error(ErrorReply::new(err.to_string()))
    }
}

impl From<crate::error::ScopeResolveError> for RpcReply {
    fn from(err: crate::error::ScopeResolveError) -> Self {
        Self::Error(ErrorReply::new(err.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimpleOkReply {
    pub ok: bool,
}

impl SimpleOkReply {
    pub const OK: Self = Self { ok: true };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterUiReply {
    pub ok: bool,
    pub role: String,
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VerdictSource {
    Policy { comment: Option<String> },
    Scope(ApprovalScope),
    User,
    Blocked,
    Static,
    Infrastructure,
    PortZero,
}

impl VerdictSource {
    #[must_use]
    pub const fn policy() -> Self {
        Self::Policy { comment: None }
    }

    #[must_use]
    pub fn policy_with_comment(comment: impl Into<String>) -> Self {
        Self::Policy {
            comment: Some(comment.into()),
        }
    }

    #[must_use]
    pub const fn blocked() -> Self {
        Self::Blocked
    }

    #[must_use]
    pub const fn is_once(&self) -> bool {
        matches!(self, Self::Scope(ApprovalScope::Once))
    }

    fn to_wire(&self, allowed: bool) -> Result<Cow<'_, str>, &'static str> {
        match (allowed, self) {
            (
                true,
                Self::Policy {
                    comment: Some(comment),
                },
            ) => Ok(Cow::Owned(format!("allow:{comment}"))),
            (true, Self::Policy { comment: None }) => Ok(Cow::Borrowed("allow")),
            (false, Self::Policy { .. }) => Ok(Cow::Borrowed("deny")),
            (true, Self::Scope(scope)) => Ok(Cow::Borrowed(scope.as_str())),
            (false, Self::User) => Ok(Cow::Borrowed("denied")),
            (false, Self::Blocked) => Ok(Cow::Borrowed("blocked")),
            (true, Self::Static) => Ok(Cow::Borrowed("static")),
            (true, Self::Infrastructure) => Ok(Cow::Borrowed("infrastructure")),
            (false, Self::PortZero) => Ok(Cow::Borrowed("port-zero")),
            _ => Err("inconsistent verdict source for allowed flag"),
        }
    }

    fn from_wire(allowed: bool, value: &str) -> Result<Self, String> {
        if allowed {
            if value == "allow" {
                return Ok(Self::policy());
            }
            if let Some(comment) = value.strip_prefix("allow:") {
                return Ok(Self::policy_with_comment(comment));
            }
        }
        match (allowed, value) {
            (false, "deny") => Ok(Self::policy()),
            (false, "denied") => Ok(Self::User),
            (false, "blocked") => Ok(Self::Blocked),
            (true, "once") => Ok(Self::Scope(ApprovalScope::Once)),
            (true, "session") => Ok(Self::Scope(ApprovalScope::Session)),
            (true, "project") => Ok(Self::Scope(ApprovalScope::Project)),
            (true, "global") => Ok(Self::Scope(ApprovalScope::Global)),
            (true, "static") => Ok(Self::Static),
            (true, "infrastructure") => Ok(Self::Infrastructure),
            (false, "port-zero") => Ok(Self::PortZero),
            _ => Err(format!("invalid source `{value}` for allowed={allowed}")),
        }
    }
}

impl fmt::Display for VerdictSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy {
                comment: Some(comment),
            } => write!(f, "policy:{comment}"),
            Self::Policy { comment: None } => f.write_str("policy"),
            Self::Scope(scope) => f.write_str(scope.as_str()),
            Self::User => f.write_str("user"),
            Self::Blocked => f.write_str("blocked"),
            Self::Static => f.write_str("static"),
            Self::Infrastructure => f.write_str("infrastructure"),
            Self::PortZero => f.write_str("port-zero"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Verdict {
    pub allowed: bool,
    pub source: VerdictSource,
}

impl Verdict {
    #[must_use]
    pub const fn allowed(source: VerdictSource) -> Self {
        Self {
            allowed: true,
            source,
        }
    }

    #[must_use]
    pub const fn denied(source: VerdictSource) -> Self {
        Self {
            allowed: false,
            source,
        }
    }

    #[must_use]
    pub const fn blocked() -> Self {
        Self::denied(VerdictSource::Blocked)
    }

    #[must_use]
    pub const fn is_policy_denied(&self) -> bool {
        !self.allowed && matches!(self.source, VerdictSource::Policy { .. })
    }

    #[must_use]
    pub const fn is_once(&self) -> bool {
        self.allowed && matches!(self.source, VerdictSource::Scope(ApprovalScope::Once))
    }
}

impl From<ApprovalScope> for VerdictSource {
    fn from(value: ApprovalScope) -> Self {
        Self::Scope(value)
    }
}

#[derive(Debug, Clone)]
pub struct CheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: VerdictSource,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCheckReply {
    ok: bool,
    allowed: bool,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl CheckReply {
    #[must_use]
    pub fn allowed(source: VerdictSource) -> Self {
        Self::from_verdict(Verdict::allowed(source))
    }

    #[must_use]
    pub fn denied(source: VerdictSource) -> Self {
        Self::from_verdict(Verdict::denied(source))
    }

    #[must_use]
    pub fn from_verdict(verdict: Verdict) -> Self {
        Self {
            ok: true,
            allowed: verdict.allowed,
            source: verdict.source,
            error: None,
        }
    }

    pub fn blocked(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: VerdictSource::blocked(),
            error: Some(message.into()),
        }
    }
}

impl Serialize for CheckReply {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let source = self
            .source
            .to_wire(self.allowed)
            .map_err(serde::ser::Error::custom)?;
        let field_count = if self.error.is_some() { 4 } else { 3 };
        let mut state = serializer.serialize_struct("CheckReply", field_count)?;
        state.serialize_field("ok", &self.ok)?;
        state.serialize_field("allowed", &self.allowed)?;
        state.serialize_field("source", source.as_ref())?;
        if let Some(error) = &self.error {
            state.serialize_field("error", error)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for CheckReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireCheckReply::deserialize(deserializer)?;
        Ok(Self {
            ok: wire.ok,
            allowed: wire.allowed,
            source: VerdictSource::from_wire(wire.allowed, &wire.source)
                .map_err(serde::de::Error::custom)?,
            error: wire.error,
        })
    }
}

/// HTTP request verdict with the exact normalized request echoed on success.
#[derive(Debug, Clone)]
pub struct HttpCheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: VerdictSource,
    pub error: Option<String>,
    pub request: Option<HttpRequest>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHttpCheckReply {
    ok: bool,
    allowed: bool,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default)]
    request: Option<HttpRequest>,
}

impl HttpCheckReply {
    #[must_use]
    pub fn from_verdict(request: HttpRequest, verdict: Verdict) -> Self {
        Self {
            ok: true,
            allowed: verdict.allowed,
            source: verdict.source,
            error: None,
            request: Some(request),
        }
    }

    #[must_use]
    pub fn blocked(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            allowed: false,
            source: VerdictSource::blocked(),
            error: Some(message.into()),
            request: None,
        }
    }
}

impl Serialize for HttpCheckReply {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let source = self
            .source
            .to_wire(self.allowed)
            .map_err(serde::ser::Error::custom)?;
        let mut field_count = 3;
        if self.error.is_some() {
            field_count += 1;
        }
        if self.request.is_some() {
            field_count += 1;
        }
        let mut state = serializer.serialize_struct("HttpCheckReply", field_count)?;
        state.serialize_field("ok", &self.ok)?;
        state.serialize_field("allowed", &self.allowed)?;
        state.serialize_field("source", source.as_ref())?;
        if let Some(error) = &self.error {
            state.serialize_field("error", error)?;
        }
        if let Some(request) = &self.request {
            state.serialize_field("request", request)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for HttpCheckReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireHttpCheckReply::deserialize(deserializer)?;
        Ok(Self {
            ok: wire.ok,
            allowed: wire.allowed,
            source: VerdictSource::from_wire(wire.allowed, &wire.source)
                .map_err(serde::de::Error::custom)?,
            error: wire.error,
            request: wire.request,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySessionReply {
    pub ok: bool,
    pub proxy_session: ProxySessionToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowClaimReply {
    pub ok: bool,
    pub attribution_token: AttributionToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlowCheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevateReply {
    pub ok: bool,
    pub allowed: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ElevateReply {
    #[must_use]
    pub fn denied() -> Self {
        Self {
            ok: true,
            allowed: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: "agent-sandbox: elevation denied".into(),
        }
    }

    #[must_use]
    pub const fn executed(exit_code: i32, stdout: String, stderr: String) -> Self {
        Self {
            ok: true,
            allowed: true,
            exit_code,
            stdout,
            stderr,
        }
    }

    pub fn exec_failed(err: impl std::fmt::Display) -> Self {
        Self {
            ok: true,
            allowed: true,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("agent-sandbox: elevation exec failed: {err}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemCheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: VerdictSource,
    pub path: PathBuf,
    pub access: FileAccess,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireFilesystemCheckReply {
    ok: bool,
    allowed: bool,
    source: String,
    path: PathBuf,
    access: FileAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl FilesystemCheckReply {
    #[must_use]
    pub fn allowed(source: VerdictSource, path: PathBuf, access: FileAccess) -> Self {
        Self::from_verdict(Verdict::allowed(source), path, access)
    }

    #[must_use]
    pub fn denied(source: VerdictSource, path: PathBuf, access: FileAccess) -> Self {
        Self::from_verdict(Verdict::denied(source), path, access)
    }

    #[must_use]
    pub fn from_verdict(verdict: Verdict, path: PathBuf, access: FileAccess) -> Self {
        Self {
            ok: true,
            allowed: verdict.allowed,
            source: verdict.source,
            path,
            access,
            error: None,
        }
    }

    pub fn blocked(message: impl Into<String>, path: PathBuf, access: FileAccess) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: VerdictSource::blocked(),
            path,
            access,
            error: Some(message.into()),
        }
    }
}

impl Serialize for FilesystemCheckReply {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let source = self
            .source
            .to_wire(self.allowed)
            .map_err(serde::ser::Error::custom)?;
        let field_count = if self.error.is_some() { 6 } else { 5 };
        let mut state = serializer.serialize_struct("FilesystemCheckReply", field_count)?;
        state.serialize_field("ok", &self.ok)?;
        state.serialize_field("allowed", &self.allowed)?;
        state.serialize_field("source", source.as_ref())?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("access", &self.access)?;
        if let Some(error) = &self.error {
            state.serialize_field("error", error)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for FilesystemCheckReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireFilesystemCheckReply::deserialize(deserializer)?;
        Ok(Self {
            ok: wire.ok,
            allowed: wire.allowed,
            source: VerdictSource::from_wire(wire.allowed, &wire.source)
                .map_err(serde::de::Error::custom)?,
            path: wire.path,
            access: wire.access,
            error: wire.error,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResourceCheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: VerdictSource,
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireResourceCheckReply {
    ok: bool,
    allowed: bool,
    source: String,
    kind: ResourceKind,
    path: PathBuf,
    access: ResourceAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ResourceCheckReply {
    #[must_use]
    pub fn allowed(
        source: VerdictSource,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self::from_verdict(Verdict::allowed(source), kind, path, access)
    }

    #[must_use]
    pub fn denied(
        source: VerdictSource,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self::from_verdict(Verdict::denied(source), kind, path, access)
    }

    #[must_use]
    pub fn from_verdict(
        verdict: Verdict,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self {
            ok: true,
            allowed: verdict.allowed,
            source: verdict.source,
            kind,
            path,
            access,
            error: None,
        }
    }

    pub fn blocked(
        message: impl Into<String>,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: VerdictSource::blocked(),
            kind,
            path,
            access,
            error: Some(message.into()),
        }
    }
}

impl Serialize for ResourceCheckReply {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let source = self
            .source
            .to_wire(self.allowed)
            .map_err(serde::ser::Error::custom)?;
        let field_count = if self.error.is_some() { 7 } else { 6 };
        let mut state = serializer.serialize_struct("ResourceCheckReply", field_count)?;
        state.serialize_field("ok", &self.ok)?;
        state.serialize_field("allowed", &self.allowed)?;
        state.serialize_field("source", source.as_ref())?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("access", &self.access)?;
        if let Some(error) = &self.error {
            state.serialize_field("error", error)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for ResourceCheckReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireResourceCheckReply::deserialize(deserializer)?;
        Ok(Self {
            ok: wire.ok,
            allowed: wire.allowed,
            source: VerdictSource::from_wire(wire.allowed, &wire.source)
                .map_err(serde::de::Error::custom)?,
            kind: wire.kind,
            path: wire.path,
            access: wire.access,
            error: wire.error,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemMonitorReply {
    pub ok: bool,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FilesystemMonitorReply {
    #[must_use]
    pub const fn active() -> Self {
        Self {
            ok: true,
            active: true,
            error: None,
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            active: false,
            error: Some(message.into()),
        }
    }
}

/// Approve / deny / approve-host success payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeActionReply {
    Network(NetworkScopeActionReply),
    Http(HttpScopeActionReply),
    Sudo(SudoScopeActionReply),
    Elevation(ElevationScopeActionReply),
    Filesystem(FilesystemScopeActionReply),
    Resource(ResourceScopeActionReply),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpScopeActionReply {
    pub ok: bool,
    pub target: HttpRuleTarget,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkScopeActionReply {
    pub ok: bool,
    pub host: String,
    pub port: u16,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SudoScopeActionReply {
    pub ok: bool,
    pub argv: Vec<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationScopeActionReply {
    pub ok: bool,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemScopeActionReply {
    pub ok: bool,
    pub path: PathBuf,
    pub access: FileAccess,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScopeActionReply {
    pub ok: bool,
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<PathBuf>,
}

impl ScopeActionReply {
    #[must_use]
    pub fn ok_http(target: HttpRuleTarget, scope: ApprovalScope, path: Option<PathBuf>) -> Self {
        Self::Http(HttpScopeActionReply {
            ok: true,
            target,
            scope: scope.to_string(),
            path,
        })
    }
    #[must_use]
    pub fn ok_network(
        host: String,
        port: u16,
        scope: ApprovalScope,
        path: Option<PathBuf>,
    ) -> Self {
        Self::Network(NetworkScopeActionReply {
            ok: true,
            host,
            port,
            scope: scope.to_string(),
            path,
        })
    }

    #[must_use]
    pub fn ok_sudo(argv: Vec<String>, scope: ApprovalScope, path: Option<PathBuf>) -> Self {
        Self::Sudo(SudoScopeActionReply {
            ok: true,
            argv,
            scope: scope.to_string(),
            path,
        })
    }

    #[must_use]
    pub fn ok_elevation_approve(scope: ApprovalScope, path: Option<PathBuf>) -> Self {
        Self::Elevation(ElevationScopeActionReply {
            ok: true,
            scope: scope.to_string(),
            path,
            allowed: true,
        })
    }

    #[must_use]
    pub fn ok_filesystem(
        path: PathBuf,
        access: FileAccess,
        scope: ApprovalScope,
        policy_path: Option<PathBuf>,
    ) -> Self {
        Self::Filesystem(FilesystemScopeActionReply {
            ok: true,
            path,
            access,
            scope: scope.to_string(),
            policy_path,
        })
    }

    #[must_use]
    pub fn ok_resource(
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        scope: ApprovalScope,
        policy_path: Option<PathBuf>,
    ) -> Self {
        Self::Resource(ResourceScopeActionReply {
            ok: true,
            kind,
            path,
            access,
            scope: scope.to_string(),
            policy_path,
        })
    }
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        match self {
            Self::Network(reply) => reply.ok,
            Self::Sudo(reply) => reply.ok,
            Self::Http(reply) => reply.ok,
            Self::Elevation(reply) => reply.ok,
            Self::Filesystem(reply) => reply.ok,
            Self::Resource(reply) => reply.ok,
        }
    }

    #[must_use]
    pub fn scope_label(&self) -> &str {
        match self {
            Self::Http(reply) => &reply.scope,
            Self::Network(reply) => &reply.scope,
            Self::Sudo(reply) => &reply.scope,
            Self::Elevation(reply) => &reply.scope,
            Self::Filesystem(reply) => &reply.scope,
            Self::Resource(reply) => &reply.scope,
        }
    }

    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Http(reply) => reply.path.as_deref(),
            Self::Network(reply) => reply.path.as_deref(),
            Self::Sudo(reply) => reply.path.as_deref(),
            Self::Elevation(reply) => reply.path.as_deref(),
            Self::Filesystem(reply) => Some(&reply.path),
            Self::Resource(reply) => Some(&reply.path),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    pub ok: bool,
    pub merged: Policy,
    pub pending: Vec<super::push::PendingSummary>,
}

impl RpcReply {
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        match self {
            Self::Proxy(reply) => match &reply.reply {
                ProxyReplyBody::HttpCheck(reply) => reply.ok,
                ProxyReplyBody::NetworkFlow(reply) => reply.ok,
                ProxyReplyBody::Canceled(reply) => reply.ok,
                ProxyReplyBody::Error(_) => false,
            },
            Self::Error(_) => false,
            _ => true,
        }
    }

    #[must_use]
    pub const fn scope_succeeded(&self) -> bool {
        matches!(self, Self::ScopeAction(reply) if reply.is_ok())
    }

    #[must_use]
    pub fn scope_label(&self) -> Option<&str> {
        match self {
            Self::ScopeAction(reply) => Some(reply.scope_label()),
            _ => None,
        }
    }
    #[must_use]
    pub fn scope_path(&self) -> Option<String> {
        match self {
            Self::ScopeAction(reply) => reply.path().map(|p| p.display().to_string()),
            _ => None,
        }
    }
}

impl fmt::Display for RpcReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        RpcMessage::Reply(self.clone()).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalScope, RpcReply, ScopeActionReply};

    #[test]
    fn scope_action_reply_deserializes_as_scope_action() {
        let line = serde_json::to_string(&ScopeActionReply::ok_network(
            "example.com".into(),
            443,
            ApprovalScope::Once,
            None,
        ))
        .unwrap();
        let reply: RpcReply = serde_json::from_str(&line).unwrap();
        assert!(matches!(
            reply,
            RpcReply::ScopeAction(ScopeActionReply::Network(_))
        ));
    }

    #[test]
    fn scope_action_reply_omits_irrelevant_fields() {
        let json = serde_json::to_value(ScopeActionReply::ok_network(
            "ex.com".into(),
            443,
            ApprovalScope::Once,
            None,
        ))
        .unwrap();
        assert!(json.get("argv").is_none());
        assert!(json.get("allowed").is_none());
        assert_eq!(json["host"], "ex.com");
    }
}
