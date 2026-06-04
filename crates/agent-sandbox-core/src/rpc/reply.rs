//! policyd → client response types.

use serde::{Deserialize, Serialize};

use crate::policy::Policy;

use super::message::RpcMessage;

/// policyd → client response line.
///
/// `Simple` must be last: it only has `ok`, so untagged serde would otherwise
/// accept any `{"ok": true, ...}` object as `SimpleOkReply` and drop fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcReply {
    Error(ErrorReply),
    RegisterUi(RegisterUiReply),
    Check(CheckReply),
    Elevate(ElevateReply),
    ScopeAction(ScopeActionReply),
    Status(StatusReply),
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
    pub fn denied() -> Self {
        Self {
            ok: true,
            allowed: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: "agent-sandbox: elevation denied".into(),
        }
    }

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

/// Approve / deny / approve-host success payloads (shared shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeActionReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
}

impl ScopeActionReply {
    pub fn ok_network(host: String, port: u16, scope: &str, path: Option<String>) -> Self {
        Self {
            ok: true,
            host: Some(host),
            port: Some(port),
            argv: None,
            scope: Some(scope.to_string()),
            path,
            allowed: None,
        }
    }

    pub fn ok_sudo(argv: Vec<String>, scope: &str, path: Option<String>) -> Self {
        Self {
            ok: true,
            host: None,
            port: None,
            argv: Some(argv),
            scope: Some(scope.to_string()),
            path,
            allowed: None,
        }
    }

    pub fn ok_elevation_approve(scope: &str, path: Option<String>) -> Self {
        Self {
            ok: true,
            host: None,
            port: None,
            argv: None,
            scope: Some(scope.to_string()),
            path,
            allowed: Some(true),
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
    pub const fn is_ok(&self) -> bool {
        !matches!(self, Self::Error(_))
    }

    pub const fn scope_succeeded(&self) -> bool {
        matches!(self, Self::ScopeAction(s) if s.ok)
    }

    pub fn scope_label(&self) -> Option<&str> {
        match self {
            Self::ScopeAction(s) => s.scope.as_deref(),
            _ => None,
        }
    }

    pub fn scope_path(&self) -> Option<String> {
        match self {
            Self::ScopeAction(s) => s.path.clone(),
            _ => None,
        }
    }

    pub fn to_line(&self) -> String {
        RpcMessage::Reply(self.clone()).to_line()
    }
}
