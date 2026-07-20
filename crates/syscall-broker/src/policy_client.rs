use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_sandbox_core::{
    FileAccess, FilesystemCheckReply, PersistentRpcClient, ProcessIds, RequestContext,
    ResourceCheckReply, RpcReply, RpcRequest, SandboxPaths,
};
use tokio::sync::Mutex;

use crate::{NetworkTarget, ResourceTarget};

fn request_context(pid: u32, sandbox_session_id: Option<String>) -> RequestContext {
    let mut ctx = RequestContext::from_paths_and_ids(
        &SandboxPaths::default(),
        ProcessIds::from_options(Some(pid), None),
    );
    ctx.sandbox_session_id = sandbox_session_id;
    ctx
}

/// Persistent sequential policyd client owned by one syscall broker.
///
/// The mutex is a defensive guard around the current-thread broker's
/// connection. Each policy check holds it for exactly one request/reply
/// exchange, preventing concurrent borrows if the dispatch loop is ever
/// changed to overlap work.
pub struct PersistentPolicyClient {
    client: Mutex<PersistentRpcClient>,
}

impl PersistentPolicyClient {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            client: Mutex::new(PersistentRpcClient::new(socket_path)),
        }
    }

    async fn request(&self, req: RpcRequest, timeout: Duration) -> io::Result<RpcReply> {
        self.client
            .lock()
            .await
            .request(req, timeout)
            .await
            .map_err(|error| io::Error::other(error.to_string()))
    }

    async fn invalidate(&self) {
        self.client.lock().await.invalidate();
    }

    pub async fn check_target(
        &self,
        target: &NetworkTarget,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> bool {
        let req = RpcRequest::Check {
            host: Some(target.host.clone()),
            connect_host: Some(target.connect_host.clone()),
            port: Some(target.port),
            scheme: target.scheme.clone(),
            url: Some(format!(
                "{}://{}:{}",
                target.scheme, target.host, target.port
            )),
            ctx: request_context(pid, sandbox_session_id),
        };
        match self.request(req, timeout).await {
            Ok(RpcReply::Check(reply)) => reply.allowed,
            Ok(_) => {
                self.invalidate().await;
                false
            }
            Err(_) => false,
        }
    }
    /// Ask policyd whether a resource-gated syscall is allowed.
    ///
    /// Returns an error if the RPC itself fails. A policy denial is returned
    /// as `Ok(ResourceCheckReply { allowed: false, .. })`.
    ///
    /// # Errors
    ///
    /// Returns an error if policyd is unreachable, times out, or sends a
    /// malformed response.
    pub async fn check_resource(
        &self,
        target: &ResourceTarget,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> io::Result<ResourceCheckReply> {
        let req = RpcRequest::CheckResource {
            kind: target.kind,
            path: target.path.clone(),
            access: target.access,
            ctx: request_context(pid, sandbox_session_id),
        };
        if let RpcReply::ResourceCheck(reply) = self.request(req, timeout).await? {
            Ok(reply)
        } else {
            self.invalidate().await;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "policyd returned a non-ResourceCheck reply for CheckResource",
            ))
        }
    }

    /// Ask policyd whether a filesystem-gated syscall path/access pair is
    /// allowed.
    ///
    /// # Errors
    ///
    /// Returns an error if policyd is unreachable, times out, or sends a
    /// malformed response.
    pub async fn check_filesystem(
        &self,
        path: &Path,
        access: FileAccess,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> io::Result<FilesystemCheckReply> {
        let req = RpcRequest::CheckFilesystem {
            path: path.to_path_buf(),
            access,
            ctx: request_context(pid, sandbox_session_id),
        };
        if let RpcReply::FilesystemCheck(reply) = self.request(req, timeout).await? {
            Ok(reply)
        } else {
            self.invalidate().await;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "policyd returned a non-FilesystemCheck reply for CheckFilesystem",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PersistentPolicyClient;
    use agent_sandbox_core::{
        CheckReply, FileAccess, FilesystemCheckReply, RpcMessage, RpcReply, VerdictSource,
    };
    use std::path::Path;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn mismatched_reply_invalidates_connection_before_next_request() {
        let socket_path = std::env::temp_dir().join(format!(
            "agent-sandbox-policy-client-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind test policy socket");
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
                let (stream, _) = listener.accept().await.expect("accept policy client");
                let (read, mut write) = stream.into_split();
                let mut reader = BufReader::new(read);
                let mut request = String::new();
                reader
                    .read_line(&mut request)
                    .await
                    .expect("read policy request");
                write
                    .write_all(reply.to_string().as_bytes())
                    .await
                    .expect("write policy reply");
            }
        });

        let client = PersistentPolicyClient::new(&socket_path);
        let first = client
            .check_filesystem(
                Path::new("/tmp/first"),
                FileAccess::Read,
                None,
                1,
                Duration::from_secs(1),
            )
            .await;
        assert!(first.is_err(), "wrong reply variant must fail closed");

        let second = client
            .check_filesystem(
                Path::new("/tmp/allowed"),
                FileAccess::Read,
                None,
                1,
                Duration::from_secs(1),
            )
            .await
            .expect("second request must reconnect");
        assert!(second.allowed);
        server.await.expect("policy test server");
        let _ = std::fs::remove_file(socket_path);
    }
}
