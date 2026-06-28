//! Gate sandbox vs host socket requests by RPC variant.

use agent_sandbox_core::RpcRequest;

use crate::error::PolicydError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketRole {
    Host,
    Sandbox,
    UiFd,
}

/// Whether the request is allowed on the sandbox socket.
#[must_use]
pub const fn is_sandbox_request(req: &RpcRequest) -> bool {
    matches!(
        req,
        RpcRequest::RegisterUi { .. }
            | RpcRequest::Check { .. }
            | RpcRequest::Elevate { .. }
            | RpcRequest::CheckFilesystem { .. }
            | RpcRequest::StartFilesystemMonitor { .. }
    )
}

/// Whether the request is allowed on an inherited UI fd (already-registered UI connection).
#[must_use]
pub const fn is_uifd_request(req: &RpcRequest) -> bool {
    matches!(
        req,
        RpcRequest::Approve { .. }
            | RpcRequest::ApproveHost { .. }
            | RpcRequest::Deny { .. }
            | RpcRequest::Status { .. }
            | RpcRequest::Reload { .. }
            | RpcRequest::UnregisterUi
    )
}

pub const fn ensure_allowed(role: SocketRole, req: &RpcRequest) -> Result<(), PolicydError> {
    match role {
        SocketRole::Sandbox if !is_sandbox_request(req) => Err(PolicydError::UnauthorizedRequest),
        SocketRole::UiFd if !is_uifd_request(req) => Err(PolicydError::UnauthorizedUiFdRequest),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{SocketRole, ensure_allowed};
    use crate::error::PolicydError;
    use agent_sandbox_core::{ApprovalScope, FileAccess, RequestContext, RpcRequest};

    #[test]
    fn sandbox_socket_allows_request_ops() {
        for req in [
            RpcRequest::Check {
                host: None,
                connect_host: None,
                port: None,
                scheme: "https".into(),
                url: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Elevate {
                argv: vec!["id".into()],
                ctx: RequestContext::default(),
            },
            RpcRequest::CheckFilesystem {
                path: "/tmp/test".into(),
                access: FileAccess::ReadWrite,
                ctx: RequestContext::default(),
            },
            RpcRequest::StartFilesystemMonitor {
                ctx: RequestContext::default(),
                static_allow: vec![],
            },
            RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext::default(),
            },
        ] {
            assert!(
                ensure_allowed(SocketRole::Sandbox, &req).is_ok(),
                "sandbox socket should allow request ops, got error for {:?}",
                std::mem::discriminant(&req)
            );
        }
    }

    #[test]
    fn sandbox_socket_rejects_control_ops() {
        for req in [
            RpcRequest::UnregisterUi,
            RpcRequest::Approve {
                id: "p1".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::ApproveHost {
                host: "example.com".into(),
                port: 443,
                scope: ApprovalScope::Once,
                session_id: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Deny {
                id: "p1".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Status {
                ctx: RequestContext::default(),
            },
            RpcRequest::Reload {
                ctx: RequestContext::default(),
            },
        ] {
            assert!(
                matches!(
                    ensure_allowed(SocketRole::Sandbox, &req),
                    Err(PolicydError::UnauthorizedRequest)
                ),
                "sandbox socket should reject control ops"
            );
        }
    }

    #[test]
    fn host_socket_allows_every_rpc_variant() {
        let all = vec![
            RpcRequest::Check {
                host: None,
                connect_host: None,
                port: None,
                scheme: "https".into(),
                url: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Elevate {
                argv: vec!["id".into()],
                ctx: RequestContext::default(),
            },
            RpcRequest::CheckFilesystem {
                path: "/tmp/test".into(),
                access: FileAccess::ReadWrite,
                ctx: RequestContext::default(),
            },
            RpcRequest::StartFilesystemMonitor {
                ctx: RequestContext::default(),
                static_allow: vec![],
            },
            RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext::default(),
            },
            RpcRequest::UnregisterUi,
            RpcRequest::Approve {
                id: "p1".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::ApproveHost {
                host: "example.com".into(),
                port: 443,
                scope: ApprovalScope::Once,
                session_id: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Deny {
                id: "p1".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Status {
                ctx: RequestContext::default(),
            },
            RpcRequest::Reload {
                ctx: RequestContext::default(),
            },
        ];
        for req in &all {
            assert!(
                ensure_allowed(SocketRole::Host, req).is_ok(),
                "host socket should allow all RPC variants, got error for {:?}",
                std::mem::discriminant(req)
            );
        }
    }

    #[test]
    fn uifd_allows_approval_ops() {
        for req in [
            RpcRequest::Approve {
                id: "p1".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::ApproveHost {
                host: "example.com".into(),
                port: 443,
                scope: ApprovalScope::Once,
                session_id: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Deny {
                id: "p1".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Status {
                ctx: RequestContext::default(),
            },
            RpcRequest::Reload {
                ctx: RequestContext::default(),
            },
            RpcRequest::UnregisterUi,
        ] {
            assert!(
                ensure_allowed(SocketRole::UiFd, &req).is_ok(),
                "UiFd socket should allow approval ops"
            );
        }
    }

    #[test]
    fn uifd_rejects_sandbox_ops() {
        for req in [
            RpcRequest::Check {
                host: None,
                connect_host: None,
                port: None,
                scheme: "https".into(),
                url: None,
                ctx: RequestContext::default(),
            },
            RpcRequest::Elevate {
                argv: vec!["id".into()],
                ctx: RequestContext::default(),
            },
            RpcRequest::CheckFilesystem {
                path: "/tmp/test".into(),
                access: FileAccess::ReadWrite,
                ctx: RequestContext::default(),
            },
            RpcRequest::StartFilesystemMonitor {
                ctx: RequestContext::default(),
                static_allow: vec![],
            },
        ] {
            assert!(
                matches!(
                    ensure_allowed(SocketRole::UiFd, &req),
                    Err(PolicydError::UnauthorizedUiFdRequest)
                ),
                "UiFd socket should reject sandbox request ops"
            );
        }
    }

    #[test]
    fn uifd_rejects_register_ui() {
        let req = RpcRequest::RegisterUi {
            ui_client: Some("standalone".into()),
            ctx: RequestContext::default(),
        };
        assert!(
            matches!(
                ensure_allowed(SocketRole::UiFd, &req),
                Err(PolicydError::UnauthorizedUiFdRequest)
            ),
            "UiFd socket should reject RegisterUi after transition"
        );
    }
}
