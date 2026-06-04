//! Incoming RPC request types (`op` tag).

use serde::{Deserialize, Serialize};

/// Incoming RPC request (`op` tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RpcRequest {
    RegisterUi {
        #[serde(default)]
        ui_client: Option<String>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
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
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
        pid: Option<u32>,
        uid: Option<u32>,
    },
    Elevate {
        argv: Vec<String>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
        pid: Option<u32>,
        uid: Option<u32>,
    },
    Approve {
        id: String,
        scope: String,
        #[serde(default)]
        session_id: Option<String>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
        uid: Option<u32>,
    },
    ApproveHost {
        host: String,
        port: u16,
        scope: String,
        #[serde(default)]
        session_id: Option<String>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
        pid: Option<u32>,
        uid: Option<u32>,
    },
    Deny {
        id: String,
        #[serde(default = "default_once_scope")]
        scope: String,
        #[serde(default)]
        session_id: Option<String>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
        uid: Option<u32>,
    },
    Status {
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    },
    Reload {
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    },
}

fn default_https() -> String {
    "https".into()
}

fn default_once_scope() -> String {
    "once".into()
}
