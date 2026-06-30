use std::path::{Path, PathBuf};

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy::{FileAccess, Policy, ResourceAccess, ResourceKind};

use super::{message::RpcMessage, scope::ApprovalScope};

/// policyd → client response line.
///
/// Variants with optional `error` fields come before `Error` so untagged
/// serde does not greedily match them as `Error`. `Simple` must be last:
/// it only has `ok`, so it would otherwise accept any `{"ok": true, ...}`
/// object and drop fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcReply {
    RegisterUi(RegisterUiReply),
    FilesystemCheck(FilesystemCheckReply),
    ResourceCheck(ResourceCheckReply),
    FilesystemMonitor(FilesystemMonitorReply),
    Check(CheckReply),
    Elevate(ElevateReply),
    ScopeAction(ScopeActionReply),
    Status(StatusReply),
    Error(ErrorReply),
    Simple(SimpleOkReply),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CheckReply {
    pub fn allowed(source: impl Into<String>) -> Self {
        Self {
            ok: true,
            allowed: true,
            source: source.into(),
            error: None,
        }
    }

    pub fn denied(source: impl Into<String>) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: source.into(),
            error: None,
        }
    }

    pub fn blocked(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: "blocked".into(),
            error: Some(message.into()),
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemCheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: String,
    pub path: PathBuf,
    pub access: FileAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FilesystemCheckReply {
    pub fn allowed(source: impl Into<String>, path: PathBuf, access: FileAccess) -> Self {
        Self {
            ok: true,
            allowed: true,
            source: source.into(),
            path,
            access,
            error: None,
        }
    }

    pub fn denied(source: impl Into<String>, path: PathBuf, access: FileAccess) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: source.into(),
            path,
            access,
            error: None,
        }
    }

    pub fn blocked(message: impl Into<String>, path: PathBuf, access: FileAccess) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: "blocked".into(),
            path,
            access,
            error: Some(message.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCheckReply {
    pub ok: bool,
    pub allowed: bool,
    pub source: String,
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub access: ResourceAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ResourceCheckReply {
    pub fn allowed(
        source: impl Into<String>,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self {
            ok: true,
            allowed: true,
            source: source.into(),
            kind,
            path,
            access,
            error: None,
        }
    }

    pub fn denied(
        source: impl Into<String>,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
    ) -> Self {
        Self {
            ok: true,
            allowed: false,
            source: source.into(),
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
            source: "blocked".into(),
            kind,
            path,
            access,
            error: Some(message.into()),
        }
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
    Sudo(SudoScopeActionReply),
    Elevation(ElevationScopeActionReply),
    Filesystem(FilesystemScopeActionReply),
    Resource(ResourceScopeActionReply),
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
            Self::Elevation(reply) => reply.ok,
            Self::Filesystem(reply) => reply.ok,
            Self::Resource(reply) => reply.ok,
        }
    }

    #[must_use]
    pub fn scope_label(&self) -> &str {
        match self {
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
        !matches!(self, Self::Error(_))
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
