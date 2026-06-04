//! UI push payloads (after `register_ui`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingSummary {
    Network {
        id: String,
        host: Option<String>,
        port: Option<u16>,
        scheme: Option<String>,
        url: Option<String>,
        cwd: Option<String>,
        home: Option<String>,
    },
    Elevation {
        id: String,
        argv: Option<Vec<String>>,
        cwd: Option<String>,
        home: Option<String>,
    },
}

/// UI push after `register_ui` (not a request response).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UiPush {
    NetworkRequest {
        id: String,
        host: Option<String>,
        port: Option<u16>,
        scheme: Option<String>,
        url: Option<String>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    },
    ElevationRequest {
        id: String,
        argv: Option<Vec<String>>,
        cwd: Option<String>,
        home: Option<String>,
        project_root: Option<String>,
    },
}
