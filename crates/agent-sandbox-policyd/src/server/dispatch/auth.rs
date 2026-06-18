//! Restrict control-plane RPCs to host-side clients and pinned OMP UI peers.

use agent_sandbox_core::{RpcRequest, is_blocked_sandbox_policy_tool, looks_like_omp_ui_process};

use crate::error::PolicydError;
use crate::server::peer::ClientPeer;
use crate::store::{PolicyStore, PolicydArgs};

/// Whether the request mutates policy/UI state (host-only from sandboxes).
#[must_use]
pub fn is_control_request(req: &RpcRequest) -> bool {
    !matches!(
        req,
        RpcRequest::Check { .. }
            | RpcRequest::Elevate { .. }
            | RpcRequest::CheckFilesystem { .. }
            | RpcRequest::StartFilesystemMonitor { .. }
    )
}

pub async fn ensure_allowed(
    store: &PolicyStore,
    args: &PolicydArgs,
    peer: &ClientPeer,
    req: &RpcRequest,
) -> Result<(), PolicydError> {
    if !peer.is_sandboxed(args) {
        return Ok(());
    }
    if !is_control_request(req) {
        return Ok(());
    }
    if peer.pid != 0 && is_blocked_sandbox_policy_tool(peer.pid) {
        return Err(PolicydError::UnauthorizedRequest);
    }

    if let RpcRequest::RegisterUi { ui_client, .. } = req {
        if ui_client.as_deref() != Some("omp") {
            return Err(PolicydError::UnauthorizedRequest);
        }
        if !looks_like_omp_ui_process(peer.pid) {
            return Err(PolicydError::UnauthorizedRequest);
        }
        return Ok(());
    }

    if !looks_like_omp_ui_process(peer.pid) {
        return Err(PolicydError::UnauthorizedRequest);
    }
    if store.is_registered_sandbox_omp_ui(peer.uid, peer.pid).await {
        Ok(())
    } else {
        Err(PolicydError::UnauthorizedRequest)
    }
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{ApprovalScope, RequestContext, RpcRequest};

    use super::{ensure_allowed, is_control_request};
    use crate::error::PolicydError;
    use crate::server::peer::ClientPeer;
    use crate::store::{PolicyStore, PolicydArgs};

    fn test_args() -> PolicydArgs {
        PolicydArgs {
            sandbox_netns: None,
            socket: "/run/agent-sandbox/policy.sock".into(),
            declarative: "/etc/agent-sandbox/declarative.json".into(),
            export_json: "/var/lib/agent-sandbox/exported-policy.json".into(),
            export_nix: None,
            approval_timeout: std::time::Duration::from_mins(5),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
        }
    }

    #[test]
    fn check_and_elevate_are_not_control_requests() {
        assert!(!is_control_request(&RpcRequest::Check {
            host: None,
            connect_host: None,
            port: None,
            scheme: "https".into(),
            url: None,
            ctx: RequestContext::default(),
        }));
        assert!(!is_control_request(&RpcRequest::Elevate {
            argv: vec!["id".into()],
            ctx: RequestContext::default(),
        }));
    }

    #[test]
    fn approve_is_control_request() {
        assert!(is_control_request(&RpcRequest::Approve {
            id: "p1".into(),
            scope: ApprovalScope::Once,
            session_id: None,
            target: None,
            ctx: RequestContext::default(),
        }));
    }

    #[tokio::test]
    async fn unknown_peer_may_call_control_requests() {
        let args = test_args();
        let store = PolicyStore::new(args.clone());
        let peer = ClientPeer::unknown();
        ensure_allowed(
            &store,
            &args,
            &peer,
            &RpcRequest::RegisterUi {
                ui_client: Some("omp".into()),
                ctx: RequestContext::default(),
            },
        )
        .await
        .expect("unknown peer cred should not be treated as sandboxed");
    }

    #[tokio::test]
    async fn sandboxed_peer_cannot_approve_before_register() {
        let args = test_args();
        let store = PolicyStore::new(args.clone());
        let peer = ClientPeer {
            pid: std::process::id(),
            uid: 0,
            gid: 0,
        };
        if !peer.is_sandboxed(&args) {
            return;
        }
        let err = ensure_allowed(
            &store,
            &args,
            &peer,
            &RpcRequest::Approve {
                id: "p1".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            },
        )
        .await
        .expect_err("sandboxed peer should be blocked until OMP registers");
        assert!(matches!(err, PolicydError::UnauthorizedRequest));
    }
}
