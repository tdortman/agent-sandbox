//! Shared types for the fanotify-based filesystem monitor binaries.
//!
//! Both binaries talk to policyd through core's single async RPC client
//! ([`agent_sandbox_core::PersistentRpcClient`]). This crate adds the
//! filesystem-specific request shapes: the event-loop check client and the
//! one-shot monitor start.

use agent_sandbox_core::{
    FileAccess, FilesystemCheckReply, FilesystemMonitorReply, FilesystemRule, PersistentRpcClient,
    RequestContext, RpcClientError, RpcReply, RpcRequest,
};

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// Per-check RPC timeout.
///
/// A filesystem verdict may wait for user approval, so the timeout is
/// generous. On expiry the in-flight event fails closed (denied).
const CHECK_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for the one-shot monitor-start request from fs-arm.
///
/// Policyd spawns the monitor and waits up to 10 seconds for its ready line,
/// so 30 seconds is ample headroom.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Async policyd client for the fanotify monitor event loop.
///
/// Wraps core's [`PersistentRpcClient`] for filesystem checks. Any error or
/// unexpected reply fails the in-flight event closed at the caller, and a
/// protocol-level mismatch discards the connection before the next check.
pub struct MonitorClient {
    client: PersistentRpcClient,
}

impl MonitorClient {
    /// Create a client that connects lazily on its first request.
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            client: PersistentRpcClient::new(socket_path),
        }
    }

    /// Check one `open()` against policyd.
    ///
    /// # Errors
    /// Returns any core RPC error. An unexpected reply type discards the
    /// connection before returning, so the next check starts on a fresh
    /// socket.
    pub async fn check_filesystem(
        &mut self,
        path: &Path,
        access: FileAccess,
        ctx: RequestContext,
    ) -> Result<FilesystemCheckReply, RpcClientError> {
        let reply = self
            .client
            .request(
                RpcRequest::CheckFilesystem {
                    path: path.to_path_buf(),
                    access,
                    ctx,
                },
                CHECK_TIMEOUT,
            )
            .await?;

        if let RpcReply::FilesystemCheck(reply) = reply {
            Ok(reply)
        } else {
            self.client.invalidate();

            Err(RpcClientError::UnexpectedReply(
                "expected a filesystem check reply",
            ))
        }
    }
}

/// Send a `StartFilesystemMonitor` request and wait for a success reply.
///
/// # Errors
/// Returns any core RPC error, or [`RpcClientError::UnexpectedReply`] if
/// policyd does not answer with a `FilesystemMonitor` reply.
pub async fn start_monitor(
    socket_path: &Path,
    ctx: RequestContext,
    static_allow: Vec<FilesystemRule>,
) -> Result<FilesystemMonitorReply, RpcClientError> {
    let reply = PersistentRpcClient::new(socket_path)
        .request(
            RpcRequest::StartFilesystemMonitor { ctx, static_allow },
            START_TIMEOUT,
        )
        .await?;

    match reply {
        RpcReply::FilesystemMonitor(reply) => Ok(reply),

        _ => Err(RpcClientError::UnexpectedReply(
            "expected a filesystem monitor reply",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::MonitorClient;

    use agent_sandbox_core::{
        CheckReply, FileAccess, FilesystemCheckReply, RequestContext, RpcMessage, RpcReply,
        VerdictSource,
    };

    use std::path::Path;

    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
    };

    #[tokio::test]
    async fn unexpected_reply_invalidates_connection_before_next_check() {
        let socket_path = std::env::temp_dir().join(format!(
            "agent-sandbox-fsmon-check-{}.sock",
            std::process::id()
        ));

        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind policy socket");

        let server = tokio::spawn(async move {
            let replies = [
                RpcMessage::Reply(RpcReply::Check(CheckReply::allowed(VerdictSource::Static))),
                RpcMessage::Reply(RpcReply::FilesystemCheck(FilesystemCheckReply::allowed(
                    VerdictSource::Static,
                    "/tmp/allowed".into(),
                    FileAccess::Read,
                ))),
            ];

            for reply in replies {
                let (stream, _) = listener.accept().await.expect("accept monitor client");
                let (read, mut write) = stream.into_split();
                let mut reader = BufReader::new(read);
                let mut request = String::new();

                reader
                    .read_line(&mut request)
                    .await
                    .expect("read monitor request");
                write
                    .write_all(reply.to_string().as_bytes())
                    .await
                    .expect("write monitor reply");
            }
        });

        let mut client = MonitorClient::new(socket_path.clone());

        let first = client
            .check_filesystem(
                Path::new("/tmp/first"),
                FileAccess::Read,
                RequestContext::default(),
            )
            .await;

        assert!(
            first.is_err(),
            "an unexpected reply variant must fail the in-flight event"
        );

        let second = client
            .check_filesystem(
                Path::new("/tmp/allowed"),
                FileAccess::Read,
                RequestContext::default(),
            )
            .await
            .expect("next check must reconnect");

        assert!(second.allowed);
        server.await.expect("monitor test server");
        std::fs::remove_file(socket_path).expect("remove test socket");
    }
}
