//! Gate sandbox vs host socket requests by RPC variant.

use agent_sandbox_core::RpcRequest;

use crate::error::PolicydError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketRole {
    Host,
    Sandbox,
    UiFd,
    Proxy,
}

/// Whether the request is allowed on the sandbox socket.
///
/// `RegisterUi` is deliberately **excluded**. The sandbox socket is exposed
/// inside the jail (`/run/agent-sandbox/sandbox-policy.sock`), so any
/// sandboxed process can connect to it. Allowing `RegisterUi` there would let
/// a malicious agent register itself as the UI for its own route, receive the
/// prompt push for its own `Check`/`Elevate` request, and then approve that
/// request — fully bypassing the human-in-the-loop and (for `Elevate`)
/// executing arbitrary commands as root on the host.
///
/// UI registration (and therefore the `UiFd` approval role that only a
/// registered connection can attain) is host-socket-only. The intended
/// approval channel from inside the sandbox is the inherited fd pre-opened by
/// `agent-sandbox-open-ui-fd` against the host socket before bwrap exec; see
/// `open_ui_fd.rs`.
///
/// The privileged NFQ daemon also uses the sandbox socket for flow
/// registration; dispatch separately restricts that request to root peers.
#[must_use]
pub const fn is_sandbox_request(req: &RpcRequest) -> bool {
    matches!(
        req,
        RpcRequest::Check { .. }
            | RpcRequest::Elevate { .. }
            | RpcRequest::CheckFilesystem { .. }
            | RpcRequest::CheckResource { .. }
            | RpcRequest::StartFilesystemMonitor { .. }
            | RpcRequest::RegisterNetworkFlow { .. }
    )
}

/// Whether the request is allowed on the trusted proxy socket.
#[must_use]
pub const fn is_proxy_request(req: &RpcRequest) -> bool {
    matches!(
        req,
        RpcRequest::OpenProxySession
            | RpcRequest::ClaimNetworkFlow { .. }
            | RpcRequest::CheckHttp { .. }
            | RpcRequest::CheckNetworkFlow { .. }
            | RpcRequest::CancelCheck { .. }
            | RpcRequest::ReleaseNetworkFlow { .. }
    )
}
/// Whether the request is allowed on an inherited UI fd (already-registered UI
/// connection).
#[must_use]
pub const fn is_uifd_request(req: &RpcRequest) -> bool {
    matches!(
        req,
        RpcRequest::Approve { .. }
            | RpcRequest::ApproveHost { .. }
            | RpcRequest::ApproveHttp { .. }
            | RpcRequest::Deny { .. }
            | RpcRequest::Status { .. }
            | RpcRequest::Reload { .. }
            | RpcRequest::UnregisterUi
    )
}

pub const fn ensure_allowed(role: SocketRole, req: &RpcRequest) -> Result<(), PolicydError> {
    match role {
        SocketRole::Proxy if !is_proxy_request(req) => Err(PolicydError::UnauthorizedRequest),
        SocketRole::Host | SocketRole::Sandbox | SocketRole::UiFd if is_proxy_request(req) => {
            Err(PolicydError::UnauthorizedRequest)
        }
        SocketRole::Sandbox if !is_sandbox_request(req) => Err(PolicydError::UnauthorizedRequest),
        SocketRole::UiFd if !is_uifd_request(req) => Err(PolicydError::UnauthorizedUiFdRequest),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{
        ApprovalScope, FileAccess, FlowContext, FlowProtocol, FlowRegistration, NetworkFlowKey,
        NormalizedPolicyHost, ProcessIdentity, RequestContext, RpcRequest, SocketIdentity,
        SocketInode,
    };

    use super::{SocketRole, ensure_allowed};
    use crate::error::PolicydError;

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
        ] {
            assert!(
                ensure_allowed(SocketRole::Sandbox, &req).is_ok(),
                "sandbox socket should allow request ops, got error for {:?}",
                std::mem::discriminant(&req)
            );
        }
    }
    #[test]
    fn sandbox_socket_allows_network_flow_registration() {
        let registration = FlowRegistration::new(
            NetworkFlowKey::try_new(
                FlowProtocol::Tcp,
                "127.0.0.1".parse().expect("valid test source address"),
                12345,
                "192.0.2.1".parse().expect("valid test destination address"),
                443,
            )
            .expect("test flow ports are non-zero"),
            SocketIdentity::new(
                ProcessIdentity::new(1, 0, 1).expect("test process identity is non-zero"),
                SocketInode::new(1).expect("test socket inode is non-zero"),
            ),
            NormalizedPolicyHost::parse("example.com").expect("valid test policy host"),
            FlowContext::default(),
        );
        let request = RpcRequest::RegisterNetworkFlow { registration };

        assert!(
            ensure_allowed(SocketRole::Sandbox, &request).is_ok(),
            "sandbox socket should allow privileged flow registration"
        );
    }

    #[test]
    fn sandbox_socket_rejects_register_ui() {
        // RegisterUi must be host-socket-only. The sandbox socket is exposed
        // inside the jail; allowing UI registration there would let a
        // malicious agent approve its own requests. See the audit finding
        // tracked by `sandbox_socket_blocks_self_approval_escape`.
        let req = RpcRequest::RegisterUi {
            ui_client: Some("standalone".into()),
            ctx: RequestContext::default(),
        };
        assert!(
            matches!(
                ensure_allowed(SocketRole::Sandbox, &req),
                Err(PolicydError::UnauthorizedRequest)
            ),
            "sandbox socket must reject RegisterUi"
        );
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
                comment: None,
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
                comment: None,
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
                comment: None,
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
                comment: None,
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
                comment: None,
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
                comment: None,
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
