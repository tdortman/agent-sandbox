//! UI push payloads (after `register_ui`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    http::{HttpRequest, PendingHttpId},
    policy::{DbusTarget, FileAccess, ResourceAccess, ResourceKind},
};

/// A summary of a pending permission request, pushed to the UI ahead of the
/// full request (`UiPush`).
///
/// Carried under the `kind` tag (`snake_case`) so callers can render a
/// lightweight preview of what is being asked for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingSummary {
    /// A request to open an outbound network connection.
    Network {
        /// Identifier of the pending request.
        id: String,
        /// Remote host, when known.
        host: Option<String>,
        /// Remote port, when known.
        port: Option<u16>,
        /// Connection scheme (e.g. `tcp`, `udp`), when known.
        scheme: Option<String>,
        /// The URL being contacted, if any.
        url: Option<String>,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A pending HTTP request.
    Http {
        /// Identifier of the pending request.
        id: PendingHttpId,
        /// The HTTP request that triggered the permission check.
        request: HttpRequest,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Sandbox session the request belongs to, if any.
        sandbox_session_id: Option<String>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to spawn a process, possibly elevated.
    Elevation {
        /// Identifier of the pending request.
        id: String,
        /// Command line of the process to be spawned, if known.
        argv: Option<Vec<String>>,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to access a filesystem path.
    Filesystem {
        /// Identifier of the pending request.
        id: String,
        /// The path being accessed, if known.
        path: Option<PathBuf>,
        /// The kind of filesystem access requested, if known.
        access: Option<FileAccess>,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to access a generic resource (e.g. git, shell, package).
    Resource {
        /// Identifier of the pending request.
        id: String,
        /// The kind of resource being accessed.
        resource_kind: ResourceKind,
        /// The resource path or identifier, if any.
        path: Option<PathBuf>,
        /// The kind of resource access requested, if known.
        access: Option<ResourceAccess>,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to open a D-Bus connection or talk to a D-Bus service.
    Dbus {
        /// Identifier of the pending request.
        id: String,
        /// The D-Bus target (bus, service, interface, …) being accessed.
        target: DbusTarget,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Sandbox session the request belongs to, if any.
        sandbox_session_id: Option<String>,
        /// Cargo package that made the request, if attributed.
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
    /// A request to open an outbound network connection.
    NetworkRequest {
        /// Identifier of the request.
        id: String,
        /// Remote host, when known.
        host: Option<String>,
        /// Remote port, when known.
        port: Option<u16>,
        /// Connection scheme (e.g. `tcp`, `udp`), when known.
        scheme: Option<String>,
        /// The URL being contacted, if any.
        url: Option<String>,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A pending HTTP request.
    HttpRequest {
        /// Identifier of the request.
        id: PendingHttpId,
        /// The HTTP request that triggered the permission check.
        request: HttpRequest,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Sandbox session the request belongs to, if any.
        sandbox_session_id: Option<String>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to spawn a process, possibly elevated.
    ElevationRequest {
        /// Identifier of the request.
        id: String,
        /// Command line of the process to be spawned, if known.
        argv: Option<Vec<String>>,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to read from or write to a filesystem path.
    FilesystemRequest {
        /// Identifier of the request.
        id: String,
        /// The path being accessed.
        path: PathBuf,
        /// The kind of filesystem access requested.
        access: FileAccess,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to access a generic resource (e.g. git, shell, package).
    ResourceRequest {
        /// Identifier of the request.
        id: String,
        /// The kind of resource being accessed.
        kind: ResourceKind,
        /// The resource path or identifier.
        path: PathBuf,
        /// The kind of resource access requested.
        access: ResourceAccess,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },

    /// A request to open a D-Bus connection or talk to a D-Bus service.
    DbusRequest {
        /// Identifier of the request.
        id: String,
        /// The D-Bus target (bus, service, interface, …) being accessed.
        target: DbusTarget,
        /// Working directory of the requesting process.
        cwd: Option<PathBuf>,
        /// Home directory of the requesting process.
        home: Option<PathBuf>,
        /// Project root of the requesting process, if any.
        project_root: Option<PathBuf>,
        /// Sandbox session the request belongs to, if any.
        sandbox_session_id: Option<String>,
        /// Cargo package that made the request, if attributed.
        package: Option<String>,
    },
}
