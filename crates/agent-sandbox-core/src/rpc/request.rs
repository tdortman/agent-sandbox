//! Incoming RPC request types (`op` tag).

use serde::{Deserialize, Serialize};

use crate::{ProcessIds, SandboxPaths};

use super::scope::ApprovalScope;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
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
    pub fn ids(&self) -> ProcessIds {
        ProcessIds::from_options(self.pid, self.uid)
    }

    #[must_use]
    pub fn with_paths(mut self, paths: &SandboxPaths) -> Self {
        self.cwd = paths.cwd_string();
        self.home = paths.home_string();
        self.project_root = paths.project_root_string();
        self
    }

    #[must_use]
    pub fn from_paths_and_ids(paths: &SandboxPaths, ids: ProcessIds) -> Self {
        Self {
            cwd: paths.cwd_string(),
            home: paths.home_string(),
            project_root: paths.project_root_string(),
            pid: ids.pid(),
            uid: ids.uid(),
            sandbox_session_id: None,
        }
    }
}

impl From<&SandboxPaths> for RequestContext {
    fn from(paths: &SandboxPaths) -> Self {
        Self {
            cwd: paths.cwd_string(),
            home: paths.home_string(),
            project_root: paths.project_root_string(),
            pid: None,
            uid: None,
            sandbox_session_id: None,
        }
    }
}

use crate::policy::FileAccess;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalTarget {
    NetworkHost { host: String },
    SudoCommand { argv: Vec<String> },
    FilesystemPath { path: String },
}

/// Incoming RPC request (`op` tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RpcRequest {
    RegisterUi {
        #[serde(default)]
        ui_client: Option<String>,
        #[serde(default)]
        ctx: RequestContext,
    },
    UnregisterUi,
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
        path: String,
        #[serde(default)]
        access: FileAccess,
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

impl RpcRequest {
    pub fn context(&self) -> Option<&RequestContext> {
        match self {
            Self::RegisterUi { ctx, .. }
            | Self::Check { ctx, .. }
            | Self::CheckFilesystem { ctx, .. }
            | Self::StartFilesystemMonitor { ctx, .. }
            | Self::Elevate { ctx, .. }
            | Self::Approve { ctx, .. }
            | Self::ApproveHost { ctx, .. }
            | Self::Deny { ctx, .. }
            | Self::Status { ctx }
            | Self::Reload { ctx } => Some(ctx),
            Self::UnregisterUi => None,
        }
    }

    pub fn context_mut(&mut self) -> Option<&mut RequestContext> {
        match self {
            Self::RegisterUi { ctx, .. }
            | Self::Check { ctx, .. }
            | Self::CheckFilesystem { ctx, .. }
            | Self::StartFilesystemMonitor { ctx, .. }
            | Self::Elevate { ctx, .. }
            | Self::Approve { ctx, .. }
            | Self::ApproveHost { ctx, .. }
            | Self::Deny { ctx, .. }
            | Self::Status { ctx }
            | Self::Reload { ctx } => Some(ctx),
            Self::UnregisterUi => None,
        }
    }
}

fn default_https() -> String {
    "https".into()
}

fn default_once_scope() -> ApprovalScope {
    ApprovalScope::Once
}

#[cfg(test)]
mod tests {
    use super::{ApprovalTarget, RequestContext, RpcRequest};
    use crate::{ProcessIds, SandboxPaths};

    #[test]
    fn check_request_deserializes() {
        let req: RpcRequest = serde_json::from_str(
            r#"{"op":"check","host":"example.com","port":443,"scheme":"https","ctx":{"cwd":"/tmp"}}"#,
        )
        .unwrap();
        assert!(matches!(req, RpcRequest::Check { .. }));
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
    fn request_context_roundtrips_paths_and_ids() {
        let paths = SandboxPaths::new("/cwd", "/home/user", "/repo");
        let ctx = RequestContext::from_paths_and_ids(&paths, ProcessIds::new(42, 1000));
        assert_eq!(ctx.sandbox_paths().cwd(), Some("/cwd"));
        assert_eq!(ctx.sandbox_paths().home(), Some("/home/user"));
        assert_eq!(ctx.ids().pid(), Some(42));
        assert_eq!(ctx.ids().uid(), Some(1000));
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
                assert_eq!(static_allow[0].path, "/home/user");
                assert_eq!(static_allow[0].access, crate::policy::FileAccess::All);
            }
            _ => panic!("expected StartFilesystemMonitor"),
        }
    }
}
