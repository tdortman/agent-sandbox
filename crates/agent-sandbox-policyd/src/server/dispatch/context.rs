//! Resolve cwd/home/project_root and pid/uid from an incoming RPC.

use std::sync::Arc;

use agent_sandbox_core::RpcRequest;

use crate::store::PolicyStore;

pub(crate) struct Resolved {
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
}

pub(crate) async fn resolve(store: &Arc<PolicyStore>, req: &RpcRequest) -> Resolved {
    let (cwd, home, project_root) = match req {
        RpcRequest::RegisterUi {
            cwd,
            home,
            project_root,
            ..
        }
        | RpcRequest::Check {
            cwd,
            home,
            project_root,
            ..
        }
        | RpcRequest::Elevate {
            cwd,
            home,
            project_root,
            ..
        }
        | RpcRequest::Approve {
            cwd,
            home,
            project_root,
            ..
        }
        | RpcRequest::ApproveHost {
            cwd,
            home,
            project_root,
            ..
        }
        | RpcRequest::Deny {
            cwd,
            home,
            project_root,
            ..
        }
        | RpcRequest::Status {
            cwd,
            home,
            project_root,
        }
        | RpcRequest::Reload {
            cwd,
            home,
            project_root,
        } => (cwd.clone(), home.clone(), project_root.clone()),
        RpcRequest::UnregisterUi => (None, None, None),
    };
    let pid = match req {
        RpcRequest::Check { pid, .. }
        | RpcRequest::Elevate { pid, .. }
        | RpcRequest::ApproveHost { pid, .. } => *pid,
        _ => None,
    };
    let uid = match req {
        RpcRequest::Check { uid, .. }
        | RpcRequest::Elevate { uid, .. }
        | RpcRequest::Approve { uid, .. }
        | RpcRequest::ApproveHost { uid, .. }
        | RpcRequest::Deny { uid, .. } => *uid,
        _ => None,
    };
    let (cwd, home, project_root) = store
        .resolve_context(cwd, home, project_root, pid, uid)
        .await;
    Resolved {
        cwd,
        home,
        project_root,
    }
}
