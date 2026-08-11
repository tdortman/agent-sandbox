//! UI push payloads (after `register_ui`).

use crate::{
    http::{HttpRequest, PendingHttpId},
    policy::{DbusTarget, FileAccess, ResourceAccess, ResourceKind},
};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingSummary {
    Network {
        id: String,
        host: Option<String>,
        port: Option<u16>,
        scheme: Option<String>,
        url: Option<String>,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        package: Option<String>,
    },

    Http {
        id: PendingHttpId,
        request: HttpRequest,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        sandbox_session_id: Option<String>,
        package: Option<String>,
    },

    Elevation {
        id: String,
        argv: Option<Vec<String>>,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        package: Option<String>,
    },

    Filesystem {
        id: String,
        path: Option<PathBuf>,
        access: Option<FileAccess>,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        package: Option<String>,
    },

    Resource {
        id: String,
        resource_kind: ResourceKind,
        path: Option<PathBuf>,
        access: Option<ResourceAccess>,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        package: Option<String>,
    },

    Dbus {
        id: String,
        target: DbusTarget,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        sandbox_session_id: Option<String>,
        package: Option<String>,
    },
}

/// UI push after `register_ui` (not a request response).
///
/// `NetworkRequest` attribution hints may be embedded in `url` via
/// [`attach_check_aliases`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UiPush {
    NetworkRequest {
        id: String,
        host: Option<String>,
        port: Option<u16>,
        scheme: Option<String>,
        url: Option<String>,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        package: Option<String>,
    },

    HttpRequest {
        id: PendingHttpId,
        request: HttpRequest,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        sandbox_session_id: Option<String>,
        package: Option<String>,
    },

    ElevationRequest {
        id: String,
        argv: Option<Vec<String>>,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        package: Option<String>,
    },

    FilesystemRequest {
        id: String,
        path: PathBuf,
        access: FileAccess,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        package: Option<String>,
    },

    ResourceRequest {
        id: String,
        kind: ResourceKind,
        path: PathBuf,
        access: ResourceAccess,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        package: Option<String>,
    },

    DbusRequest {
        id: String,
        target: DbusTarget,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        project_root: Option<PathBuf>,
        sandbox_session_id: Option<String>,
        package: Option<String>,
    },
}
