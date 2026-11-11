//! Pure per-kind prompt builders: each request kind turns its push into a
//! [`Prompt`] (form, target parsing, presentation, fallback questions).

mod dbus;
mod elevation;
mod filesystem;
mod http;
mod network;
mod resource;

use std::path::PathBuf;

use agent_sandbox_core::UiPush;

use super::prompt::{ClientContext, Origin, Prompt};

/// Build the prompt for `push` as seen by `client`.
///
/// Network, elevation, filesystem and resource pushes carry no sandbox
/// session; they settle under the client's own. D-Bus and HTTP pushes name
/// theirs.
pub fn prompt_for(client: &ClientContext<'_>, push: UiPush) -> Prompt {
    let session_id = client.session_id;
    let own_sandbox_session = client.sandbox_session_id.map(str::to_owned);

    match push {
        UiPush::NetworkRequest {
            id,
            host,
            port,
            scheme,
            url,
            cwd,
            home,
            project_root,
            package,
        } => network::prompt(
            session_id,
            origin(
                client,
                id,
                own_sandbox_session,
                Paths {
                    cwd,
                    home,
                    project_root,
                },
                package,
            ),
            network::NetworkRequest {
                host,
                port,
                scheme,
                url,
            },
        ),

        UiPush::HttpRequest {
            id,
            request,
            cwd,
            home,
            project_root,
            sandbox_session_id,
            package,
        } => http::prompt(
            session_id,
            origin(
                client,
                id.to_string(),
                sandbox_session_id,
                Paths {
                    cwd,
                    home,
                    project_root,
                },
                package,
            ),
            request,
        ),

        UiPush::ElevationRequest {
            id,
            argv,
            cwd,
            home,
            project_root,
            package,
        } => elevation::prompt(
            session_id,
            origin(
                client,
                id,
                own_sandbox_session,
                Paths {
                    cwd,
                    home,
                    project_root,
                },
                package,
            ),
            argv.unwrap_or_default(),
        ),

        UiPush::FilesystemRequest {
            id,
            path,
            access,
            cwd,
            home,
            project_root,
            package,
        } => filesystem::prompt(
            session_id,
            origin(
                client,
                id,
                own_sandbox_session,
                Paths {
                    cwd,
                    home,
                    project_root,
                },
                package,
            ),
            filesystem::FilesystemRequest { path, access },
        ),

        UiPush::ResourceRequest {
            id,
            kind,
            path,
            access,
            cwd,
            home,
            project_root,
            package,
        } => resource::prompt(
            session_id,
            origin(
                client,
                id,
                own_sandbox_session,
                Paths {
                    cwd,
                    home,
                    project_root,
                },
                package,
            ),
            resource::ResourceRequest { kind, path, access },
        ),

        UiPush::DbusRequest {
            id,
            target,
            cwd,
            home,
            project_root,
            sandbox_session_id,
            package,
        } => dbus::prompt(
            session_id,
            origin(
                client,
                id,
                sandbox_session_id,
                Paths {
                    cwd,
                    home,
                    project_root,
                },
                package,
            ),
            target,
        ),
    }
}

/// Working directory, home and project root a push reports for its
/// requester.
struct Paths {
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

fn origin(
    client: &ClientContext<'_>,
    id: String,
    sandbox_session_id: Option<String>,
    paths: Paths,
    package: Option<String>,
) -> Origin {
    Origin {
        id,
        sandbox_session_id,
        package,
        paths: client
            .paths
            .merged_with(paths.cwd, paths.home, paths.project_root),
    }
}

#[cfg(test)]
mod test_support {
    use std::collections::HashMap;

    use agent_sandbox_core::{ApprovalScope, SandboxPaths};

    use crate::ui::{
        options::{ApprovalFormResult, PromptAction},
        prompt::Origin,
    };

    pub fn origin(package: Option<&str>) -> Origin {
        Origin {
            id: "request-1".into(),
            sandbox_session_id: None,
            package: package.map(str::to_owned),
            paths: SandboxPaths::new("/home/user/repo", "/home/user", "/home/user/repo"),
        }
    }

    /// An allow-at-`Project`-scope submission whose only value is the
    /// `target` field.
    pub fn form_result(target: &str) -> ApprovalFormResult {
        ApprovalFormResult {
            action: Some(PromptAction::Allow),
            scope: ApprovalScope::Project,
            values: HashMap::from([("target".into(), target.into())]),
        }
    }
}
