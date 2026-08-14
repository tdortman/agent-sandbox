use std::{
    borrow::Cow,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};

use super::{
    message::RpcMessage,
    proxy::{
        AttributionToken, NetworkFlowKey, NormalizedPolicyHost, ProxyRequestId, ProxySessionToken,
    },
    scope::ApprovalScope,
};
use crate::{
    error::{InvalidScopeError, ScopeResolveError},
    http::{HttpRequest, HttpRuleTarget},
    policy::{DbusTarget, FileAccess, Policy, ResourceAccess, ResourceKind},
};

/// Response envelope for pipelined proxy checks and cancellations.
///
/// The request identifier is part of the response rather than relying on
/// response ordering, because proxy checks may complete out of order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyReply {
    /// Identifier of the request this reply answers.
    pub request_id: ProxyRequestId,
    /// The body of the reply for the pipelined request.
    pub reply: ProxyReplyBody,
}

/// Body of a [`ProxyReply`], tagged by the kind of request it answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reply", rename_all = "snake_case")]
pub enum ProxyReplyBody {
    /// Reply to an HTTP check request.
    HttpCheck(HttpCheckReply),
    /// Reply to a network-flow check request.
    NetworkFlow(CheckReply),
    /// Reply acknowledging a canceled request.
    Canceled(SimpleOkReply),
    /// Failure reply.
    Error(ErrorReply),
}

impl ProxyReply {
    /// Builds a proxy reply carrying `reply`, mapping unsupported reply
    /// kinds to an error body.
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
    /// Successful UI registration, echoing the assigned role and session.
    RegisterUi(RegisterUiReply),
    /// Reply to a pipelined proxy check or cancellation.
    Proxy(ProxyReply),
    /// Result of starting a proxied proxy session.
    ProxySession(ProxySessionReply),
    /// Result of claiming a network flow attribution.
    FlowClaim(FlowClaimReply),
    /// Filesystem access check result.
    FilesystemCheck(FilesystemCheckReply),
    /// Resource access check result.
    ResourceCheck(ResourceCheckReply),
    /// D-Bus access check result.
    DbusCheck(DbusCheckReply),
    /// Result of starting or stopping a filesystem monitor.
    FilesystemMonitor(FilesystemMonitorReply),
    /// HTTP access check result.
    HttpCheck(HttpCheckReply),
    /// Network flow access check result.
    Check(CheckReply),
    /// Result of an elevation attempt.
    Elevate(ElevateReply),
    /// Payload of a successful approve/deny/approve-host scope action.
    ScopeAction(ScopeActionReply),
    /// Process status: the merged policy and pending push requests.
    Status(StatusReply),
    /// Failure reply.
    Error(ErrorReply),
    /// Minimal success acknowledgment.
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
        try_variant!(DbusCheck, DbusCheckReply);
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

/// Failure reply carrying a human-readable error message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReply {
    /// Always `false` for an error reply.
    pub ok: bool,
    /// Human-readable description of the failure.
    pub error: String,
}

impl ErrorReply {
    /// Builds an error reply with the given message and `ok: false`.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
        }
    }
}

impl From<InvalidScopeError> for RpcReply {
    fn from(err: InvalidScopeError) -> Self {
        Self::Error(ErrorReply::new(err.to_string()))
    }
}

impl From<ScopeResolveError> for RpcReply {
    fn from(err: ScopeResolveError) -> Self {
        Self::Error(ErrorReply::new(err.to_string()))
    }
}

/// Minimal success acknowledgment, carrying only an `ok` flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimpleOkReply {
    /// Whether the operation succeeded.
    pub ok: bool,
}

impl SimpleOkReply {
    /// A successful `SimpleOkReply` with `ok: true`.
    pub const OK: Self = Self { ok: true };
}

/// Response to a UI `register` request, echoing the granted role and session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterUiReply {
    /// Whether registration succeeded.
    pub ok: bool,
    /// The role granted to the registering UI session.
    pub role: String,
    /// Identifier of the register UI session.
    pub session_id: String,
}

/// Origin of a check verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VerdictSource {
    /// A verdict decided by the policy, optionally carrying the policy
    /// comment that authorized it.
    Policy {
        /// The policy comment authorizing the verdict, when present.
        comment: Option<String>,
    },
    /// A verdict granted via an approval scope (once, session, project, …).
    Scope(ApprovalScope),
    /// A verdict arrived at because the requesting user matched the policy.
    User,
    /// The request was blocked outright rather than judged by policy.
    Blocked,
    /// The request targets static lookup-only content.
    Static,
    /// The request is infrastructure traffic outside the requestable scope.
    Infrastructure,
    /// The request targets port zero (invalid / reserved).
    PortZero,
}

impl VerdictSource {
    /// A policy verdict with no comment attached.
    #[must_use]
    pub const fn policy() -> Self {
        Self::Policy { comment: None }
    }

    /// A policy verdict carrying the given explanatory comment.
    #[must_use]
    pub fn policy_with_comment(comment: impl Into<String>) -> Self {
        Self::Policy {
            comment: Some(comment.into()),
        }
    }

    /// A blocked verdict.
    #[must_use]
    pub const fn blocked() -> Self {
        Self::Blocked
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
            (true, "project_package") => Ok(Self::Scope(ApprovalScope::ProjectPackage)),
            (true, "project") => Ok(Self::Scope(ApprovalScope::Project)),
            (true, "global_package") => Ok(Self::Scope(ApprovalScope::GlobalPackage)),
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

/// Outcome of a permission check: whether it was allowed and by whom.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Verdict {
    /// Whether the request was allowed.
    pub allowed: bool,
    /// The source that produced the verdict.
    pub source: VerdictSource,
}

impl Verdict {
    /// An allowed verdict with the given source.
    #[must_use]
    pub const fn allowed(source: VerdictSource) -> Self {
        Self {
            allowed: true,
            source,
        }
    }

    /// A denied verdict with the given source.
    #[must_use]
    pub const fn denied(source: VerdictSource) -> Self {
        Self {
            allowed: false,
            source,
        }
    }

    /// A blocked (non-policy) denied verdict.
    #[must_use]
    pub const fn blocked() -> Self {
        Self::denied(VerdictSource::Blocked)
    }

    /// Whether the request was denied by policy rather than blocked.
    #[must_use]
    pub const fn is_policy_denied(&self) -> bool {
        !self.allowed && matches!(self.source, VerdictSource::Policy { .. })
    }

    /// Whether the request was granted a one-time approval scope.
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

/// Result of a network-flow access check.
#[derive(Debug, Clone)]
pub struct CheckReply {
    /// Whether the request was processed (protocol-level success).
    pub ok: bool,
    /// Whether the network flow is permitted.
    pub allowed: bool,
    /// Where the verdict came from.
    pub source: VerdictSource,
    /// Human-readable failure detail, present when `allowed` is false.
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
    /// An allowed reply with the given source.
    #[must_use]
    pub fn allowed(source: VerdictSource) -> Self {
        Self::from_verdict(Verdict::allowed(source))
    }

    /// A denied reply with the given source.
    #[must_use]
    pub fn denied(source: VerdictSource) -> Self {
        Self::from_verdict(Verdict::denied(source))
    }

    /// Builds a reply from a [`Verdict`].
    #[must_use]
    pub fn from_verdict(verdict: Verdict) -> Self {
        Self {
            ok: true,
            allowed: verdict.allowed,
            source: verdict.source,
            error: None,
        }
    }

    /// A blocked reply carrying the given message.
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
    /// Whether the request was processed (protocol-level success).
    pub ok: bool,
    /// Whether the HTTP request is permitted.
    pub allowed: bool,
    /// Where the verdict came from.
    pub source: VerdictSource,
    /// Human-readable failure detail, present when `allowed` is false.
    pub error: Option<String>,
    /// The normalized request echoed back on an allowed verdict.
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
    /// Builds an allowed reply echoing the normalized `request` and verdict.
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

    /// A blocked reply carrying the given message, with no request echoed.
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

/// Reply acknowledging creation of a proxied session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySessionReply {
    /// Whether the session was created.
    pub ok: bool,
    /// The token identifying the proxied session.
    pub proxy_session: ProxySessionToken,
}

/// Reply to a claim of a network flow for attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowClaimReply {
    /// Whether the flow was claimed.
    pub ok: bool,
    /// The attribution token granted for the flow.
    pub attribution_token: AttributionToken,
    /// The network flow that was claimed.
    pub flow: NetworkFlowKey,
    /// The normalized policy host matched for the flow.
    pub policy_host: NormalizedPolicyHost,
}

/// Result of a network-flow access check carried on an untyped wire body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlowCheckReply {
    /// Whether the request was processed (protocol-level success).
    pub ok: bool,
    /// Whether the network flow is permitted.
    pub allowed: bool,
    /// Wire-level verdict source string.
    pub source: String,

    /// Human-readable failure detail, present when `allowed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of an elevation attempt, echoing the executed process output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevateReply {
    /// Whether the elevation request was processed.
    pub ok: bool,
    /// Whether elevation was permitted.
    pub allowed: bool,
    /// Exit code of the elevated process, or `1` when denied or failed.
    pub exit_code: i32,
    /// Captured standard output of the elevated process.
    pub stdout: String,
    /// Captured standard error of the elevated process or denial reason.
    pub stderr: String,
}

impl ElevateReply {
    /// A reply for an elevation request that was denied by the operator.
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

    /// A reply for an elevation that ran to completion with the given output.
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

    /// A reply for an elevation that passed policy but failed to execute.
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

/// Result of a filesystem access check.
#[derive(Debug, Clone)]
pub struct FilesystemCheckReply {
    /// Whether the request was processed (protocol-level success).
    pub ok: bool,
    /// Whether the filesystem access is permitted.
    pub allowed: bool,
    /// Where the verdict came from.
    pub source: VerdictSource,
    /// The path subjected to the check.
    pub path: PathBuf,
    /// The filesystem access mode checked.
    pub access: FileAccess,
    /// Human-readable failure detail, present when `allowed` is false.
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
    /// An allowed reply for `path`/`access` with the given source.
    #[must_use]
    pub fn allowed(source: VerdictSource, path: PathBuf, access: FileAccess) -> Self {
        Self::from_verdict(Verdict::allowed(source), path, access)
    }

    /// A denied reply for `path`/`access` with the given source.
    #[must_use]
    pub fn denied(source: VerdictSource, path: PathBuf, access: FileAccess) -> Self {
        Self::from_verdict(Verdict::denied(source), path, access)
    }

    /// Builds a filesystem reply from a [`Verdict`].
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

    /// A blocked reply for `path`/`access` carrying the given message.
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

/// Result of a resource access check.
#[derive(Debug, Clone)]
pub struct ResourceCheckReply {
    /// Whether the request was processed (protocol-level success).
    pub ok: bool,
    /// Whether the resource access is permitted.
    pub allowed: bool,
    /// Where the verdict came from.
    pub source: VerdictSource,
    /// The kind of resource checked.
    pub kind: ResourceKind,
    /// The resource path or device subjected to the check.
    pub path: PathBuf,
    /// The resource access mode checked.
    pub access: ResourceAccess,
    /// Human-readable failure detail, present when `allowed` is false.
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
    /// An allowed reply for `kind`/`path`/`access` with the given source.
    #[must_use]
    pub fn allowed(
        source: VerdictSource,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self::from_verdict(Verdict::allowed(source), kind, path, access)
    }

    /// A denied reply for `kind`/`path`/`access` with the given source.
    #[must_use]
    pub fn denied(
        source: VerdictSource,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self::from_verdict(Verdict::denied(source), kind, path, access)
    }

    /// Builds a resource reply from a [`Verdict`].
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

    /// A blocked reply for `kind`/`path`/`access` carrying the given message.
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

/// Result of a D-Bus access check.
#[derive(Debug, Clone)]
pub struct DbusCheckReply {
    /// Whether the request was processed (protocol-level success).
    pub ok: bool,
    /// Whether the D-Bus access is permitted.
    pub allowed: bool,
    /// Where the verdict came from.
    pub source: VerdictSource,
    /// The D-Bus target subjected to the check.
    pub target: DbusTarget,
    /// Human-readable failure detail, present when `allowed` is false.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDbusCheckReply {
    ok: bool,
    allowed: bool,
    source: String,
    target: DbusTarget,

    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl DbusCheckReply {
    /// Builds a D-Bus reply from a [`Verdict`] for `target`.
    #[must_use]
    pub fn from_verdict(verdict: Verdict, target: DbusTarget) -> Self {
        Self {
            ok: true,
            allowed: verdict.allowed,
            source: verdict.source,
            target,
            error: None,
        }
    }

    /// An allowed reply for `target` with the given source.
    #[must_use]
    pub fn allowed(source: VerdictSource, target: DbusTarget) -> Self {
        Self::from_verdict(Verdict::allowed(source), target)
    }

    /// A denied reply for `target` with the given source.
    #[must_use]
    pub fn denied(source: VerdictSource, target: DbusTarget) -> Self {
        Self::from_verdict(Verdict::denied(source), target)
    }

    /// A blocked reply for `target` carrying the given message.
    pub fn blocked(message: impl Into<String>, target: DbusTarget) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: VerdictSource::blocked(),
            target,
            error: Some(message.into()),
        }
    }
}

impl Serialize for DbusCheckReply {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let source = self
            .source
            .to_wire(self.allowed)
            .map_err(serde::ser::Error::custom)?;

        let field_count = if self.error.is_some() { 5 } else { 4 };
        let mut state = serializer.serialize_struct("DbusCheckReply", field_count)?;
        state.serialize_field("ok", &self.ok)?;
        state.serialize_field("allowed", &self.allowed)?;
        state.serialize_field("source", source.as_ref())?;
        state.serialize_field("target", &self.target)?;

        if let Some(error) = &self.error {
            state.serialize_field("error", error)?;
        }

        state.end()
    }
}

impl<'de> Deserialize<'de> for DbusCheckReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireDbusCheckReply::deserialize(deserializer)?;

        Ok(Self {
            ok: wire.ok,
            allowed: wire.allowed,
            source: VerdictSource::from_wire(wire.allowed, &wire.source)
                .map_err(serde::de::Error::custom)?,
            target: wire.target,
            error: wire.error,
        })
    }
}

/// Result of starting or stopping a filesystem monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemMonitorReply {
    /// Whether the request was processed.
    pub ok: bool,
    /// Whether the filesystem monitor is currently active.
    pub active: bool,

    /// Human-readable failure detail, present when the monitor is not active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FilesystemMonitorReply {
    /// A reply reporting the monitor is active.
    #[must_use]
    pub const fn active() -> Self {
        Self {
            ok: true,
            active: true,
            error: None,
        }
    }

    /// A reply reporting the monitor failed to start, with the given message.
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
    /// Success payload for a network scope action.
    Network(NetworkScopeActionReply),
    /// Success payload for an HTTP scope action.
    Http(HttpScopeActionReply),
    /// Success payload for a sudo scope action.
    Sudo(SudoScopeActionReply),
    /// Success payload for an elevation scope action.
    Elevation(ElevationScopeActionReply),
    /// Success payload for a filesystem scope action.
    Filesystem(FilesystemScopeActionReply),
    /// Success payload for a resource scope action.
    Resource(ResourceScopeActionReply),
    /// Success payload for a D-Bus scope action.
    Dbus(DbusScopeActionReply),
}

/// Success payload for an HTTP scope action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpScopeActionReply {
    /// Whether the scope action was applied.
    pub ok: bool,
    /// The HTTP rule target the scope was granted for.
    pub target: HttpRuleTarget,
    /// The granted approval scope as a string.
    pub scope: String,

    /// The policy path the scope was keyed on, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// Success payload for a network scope action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkScopeActionReply {
    /// Whether the scope action was applied.
    pub ok: bool,
    /// The host the scope was granted for.
    pub host: String,
    /// The port the scope was granted for.
    pub port: u16,
    /// The granted approval scope as a string.
    pub scope: String,

    /// The policy path the scope was keyed on, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// Success payload for a sudo scope action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SudoScopeActionReply {
    /// Whether the scope action was applied.
    pub ok: bool,
    /// The command arguments the sudo scope was granted for.
    pub argv: Vec<String>,
    /// The granted approval scope as a string.
    pub scope: String,

    /// The policy path the scope was keyed on, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// Success payload for an elevation scope action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationScopeActionReply {
    /// Whether the scope action was applied.
    pub ok: bool,
    /// The granted approval scope as a string.
    pub scope: String,

    /// The policy path the scope was keyed on, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// Whether elevation was approved.
    pub allowed: bool,
}

/// Success payload for a filesystem scope action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemScopeActionReply {
    /// Whether the scope action was applied.
    pub ok: bool,
    /// The path the scope was granted for.
    pub path: PathBuf,
    /// The filesystem access mode the scope was granted for.
    pub access: FileAccess,
    /// The granted approval scope as a string.
    pub scope: String,

    /// The policy path the granted scope points at, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<PathBuf>,
}

/// Success payload for a resource scope action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScopeActionReply {
    /// Whether the scope action was applied.
    pub ok: bool,
    /// The resource kind the scope was granted for.
    pub kind: ResourceKind,
    /// The resource path the scope was granted for.
    pub path: PathBuf,
    /// The resource access mode the scope was granted for.
    pub access: ResourceAccess,
    /// The granted approval scope as a string.
    pub scope: String,

    /// The policy path the granted scope points at, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<PathBuf>,
}

/// Success payload for a D-Bus scope action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbusScopeActionReply {
    /// Whether the scope action was applied.
    pub ok: bool,
    /// The D-Bus target the scope was granted for.
    pub target: DbusTarget,
    /// The granted approval scope as a string.
    pub scope: String,

    /// The policy path the scope was keyed on, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

impl ScopeActionReply {
    /// An HTTP scope-action success payload.
    #[must_use]
    pub fn ok_http(target: HttpRuleTarget, scope: ApprovalScope, path: Option<PathBuf>) -> Self {
        Self::Http(HttpScopeActionReply {
            ok: true,
            target,
            scope: scope.to_string(),
            path,
        })
    }

    /// A network scope-action success payload.
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

    /// A sudo scope-action success payload.
    #[must_use]
    pub fn ok_sudo(argv: Vec<String>, scope: ApprovalScope, path: Option<PathBuf>) -> Self {
        Self::Sudo(SudoScopeActionReply {
            ok: true,
            argv,
            scope: scope.to_string(),
            path,
        })
    }

    /// An elevation approve scope-action success payload.
    #[must_use]
    pub fn ok_elevation_approve(scope: ApprovalScope, path: Option<PathBuf>) -> Self {
        Self::Elevation(ElevationScopeActionReply {
            ok: true,
            scope: scope.to_string(),
            path,
            allowed: true,
        })
    }

    /// A filesystem scope-action success payload.
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

    /// A resource scope-action success payload.
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

    /// A D-Bus scope-action success payload.
    #[must_use]
    pub fn ok_dbus(target: DbusTarget, scope: ApprovalScope, path: Option<PathBuf>) -> Self {
        Self::Dbus(DbusScopeActionReply {
            ok: true,
            target,
            scope: scope.to_string(),
            path,
        })
    }

    /// Whether the scope action was applied successfully.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        match self {
            Self::Network(reply) => reply.ok,
            Self::Sudo(reply) => reply.ok,
            Self::Http(reply) => reply.ok,
            Self::Elevation(reply) => reply.ok,
            Self::Filesystem(reply) => reply.ok,
            Self::Resource(reply) => reply.ok,
            Self::Dbus(reply) => reply.ok,
        }
    }

    /// The granted approval scope label, as a string.
    #[must_use]
    pub fn scope_label(&self) -> &str {
        match self {
            Self::Http(reply) => &reply.scope,
            Self::Network(reply) => &reply.scope,
            Self::Sudo(reply) => &reply.scope,
            Self::Elevation(reply) => &reply.scope,
            Self::Filesystem(reply) => &reply.scope,
            Self::Resource(reply) => &reply.scope,
            Self::Dbus(reply) => &reply.scope,
        }
    }

    /// The path this scope action was keyed on, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Http(reply) => reply.path.as_deref(),
            Self::Network(reply) => reply.path.as_deref(),
            Self::Sudo(reply) => reply.path.as_deref(),
            Self::Elevation(reply) => reply.path.as_deref(),
            Self::Filesystem(reply) => Some(reply.path.as_path()),
            Self::Resource(reply) => Some(reply.path.as_path()),
            Self::Dbus(reply) => reply.path.as_deref(),
        }
    }
}

/// Process status reply: the merged policy and pending push requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    /// Whether the status was retrieved.
    pub ok: bool,
    /// The currently merged policy.
    pub merged: Policy,
    /// Summaries of pending push requests awaiting approval.
    pub pending: Vec<super::push::PendingSummary>,
}

impl RpcReply {
    /// Whether the reply represents a successful outcome.
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

    /// Whether the reply is a scope action that applied successfully.
    #[must_use]
    pub const fn scope_succeeded(&self) -> bool {
        matches!(self, Self::ScopeAction(reply) if reply.is_ok())
    }

    /// The granted approval scope label if the reply is a scope action.
    #[must_use]
    pub fn scope_label(&self) -> Option<&str> {
        match self {
            Self::ScopeAction(reply) => Some(reply.scope_label()),
            _ => None,
        }
    }

    /// The path a scope action was keyed on, if the reply is a scope action.
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
    use super::{
        ApprovalScope, DbusCheckReply, DbusTarget, RpcReply, ScopeActionReply, VerdictSource,
    };
    use crate::policy::DbusMessageKind;

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

    #[test]
    fn dbus_reply_round_trips_typed_target() {
        let target = DbusTarget::session(
            "org.example.Service",
            "/org/example/Object",
            "org.example.Interface",
            "Read",
            DbusMessageKind::MethodCall,
            "s",
            Vec::new(),
        );

        let reply = DbusCheckReply::allowed(VerdictSource::Static, target.clone());
        let value = serde_json::to_value(&reply).expect("D-Bus reply serializes");

        let decoded: DbusCheckReply =
            serde_json::from_value(value).expect("D-Bus reply deserializes");

        assert_eq!(decoded.target, target);
        assert!(decoded.allowed);
    }
}
