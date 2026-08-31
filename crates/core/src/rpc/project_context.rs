//! Strict, harness-neutral project-context adapter protocol.

#![allow(missing_docs)]

use std::{fmt, path::PathBuf};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::ProxySessionToken;

pub const CONTEXT_ADAPTER_PROTOCOL_MAJOR: u16 = 1;
pub const MAX_CONTEXT_KEY_BYTES: usize = 1024;

macro_rules! capability_handle {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(ProxySessionToken);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(ProxySessionToken::new())
            }

            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(ProxySessionToken::from_bytes(bytes))
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"<redacted>")
                    .finish()
            }
        }
    };
}

capability_handle!(ActivationHandle);
capability_handle!(BindingHandle);
capability_handle!(ClaimHandle);

macro_rules! bounded_key {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, String> {
                let value = value.into();
                if value.is_empty() || value.len() > MAX_CONTEXT_KEY_BYTES {
                    return Err(format!(
                        "context key must contain 1 to {MAX_CONTEXT_KEY_BYTES} UTF-8 bytes"
                    ));
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

bounded_key!(ExternalSessionKey);
bounded_key!(ExternalOperationKey);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceActivation {
    pub activation: ActivationHandle,
    /// Informational canonical path. It cannot select an activation.
    pub canonical_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "handle", rename_all = "snake_case")]
pub enum AttachmentHandle {
    Binding(BindingHandle),
    Claim(ClaimHandle),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "handle", rename_all = "snake_case")]
pub enum ReleasableHandle {
    Binding(BindingHandle),
    Claim(ClaimHandle),
}

/// Ordered requests accepted only on an authenticated adapter connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextAdapterRequest {
    RegisterContextAdapter {
        request_id: u64,
        protocol_major: u16,
        sandbox_session_id: String,
    },
    BindSession {
        request_id: u64,
        session_key: ExternalSessionKey,
        activation: ActivationHandle,
    },
    BeginOperation {
        request_id: u64,
        operation_key: ExternalOperationKey,
        binding: BindingHandle,
        activation: ActivationHandle,
    },
    /// The frame must carry exactly one pidfd.
    AttachProcess {
        request_id: u64,
        context: AttachmentHandle,
        namespace_pid: Option<u32>,
    },
    Release {
        request_id: u64,
        handle: ReleasableHandle,
    },
}

impl ContextAdapterRequest {
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        match self {
            Self::RegisterContextAdapter { request_id, .. }
            | Self::BindSession { request_id, .. }
            | Self::BeginOperation { request_id, .. }
            | Self::AttachProcess { request_id, .. }
            | Self::Release { request_id, .. } => *request_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAdapterErrorCode {
    UnsupportedVersion,
    MalformedMessage,
    Unauthorized,
    DuplicateRequestId,
    Conflict,
    WrongHandleType,
    UnknownHandle,
    Released,
    Expired,
    InvalidWorkspace,
    InvalidProcess,
    ResourceExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextAdapterMessage {
    Registered {
        request_id: u64,
        protocol_major: u16,
        boot_epoch: u64,
        activations: Vec<WorkspaceActivation>,
    },
    SessionBound {
        request_id: u64,
        binding: BindingHandle,
    },
    OperationBegun {
        request_id: u64,
        claim: ClaimHandle,
    },
    ProcessAttached {
        request_id: u64,
    },
    Released {
        request_id: u64,
    },
    Error {
        request_id: Option<u64>,
        code: ContextAdapterErrorCode,
        detail: String,
    },
    ActivationAdded {
        workspace: WorkspaceActivation,
    },
    ActivationRemoved {
        activation: ActivationHandle,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_is_strict_bounded_and_redacted() {
        let activation = ActivationHandle::from_bytes([1; 32]);
        let request = ContextAdapterRequest::BeginOperation {
            request_id: 7,
            operation_key: ExternalOperationKey::new("turn-9").unwrap(),
            binding: BindingHandle::from_bytes([2; 32]),
            activation: activation.clone(),
        };
        let wire = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<ContextAdapterRequest>(&wire).unwrap(),
            request
        );
        assert!(wire.contains("\"operation\":\"begin_operation\""));
        assert!(format!("{activation:?}").contains("<redacted>"));
        assert!(ExternalSessionKey::new("").is_err());
        assert!(ExternalSessionKey::new("x".repeat(MAX_CONTEXT_KEY_BYTES + 1)).is_err());
        let unknown = wire.replacen('{', "{\"unexpected\":true,", 1);
        assert!(serde_json::from_str::<ContextAdapterRequest>(&unknown).is_err());
    }
}
