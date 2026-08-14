use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::{
    FileAccess, FilesystemCheckReply, PersistentRpcClient, ProcessIds, RequestContext,
    ResourceCheckReply, RpcReply, RpcRequest, wire_context,
};

use crate::{NetworkTarget, ResourceTarget};

fn request_context(pid: u32, sandbox_session_id: Option<String>) -> RequestContext {
    // The broker is exec'd inside the bwrap jail and inherits the sandbox
    // environment, where the wrapper sets AGENT_SANDBOX_CWD, AGENT_SANDBOX_HOME
    // and AGENT_SANDBOX_PROJECT_ROOT. wire_context resolves the paths from that
    // environment instead of sending empty paths to policyd: without a project
    // root the UI cannot record project-scope approvals and every project-scope
    // approval attempt fails with "project_root required".
    let ids = ProcessIds::from_options(Some(pid), None);

    wire_context(None, None, None, ids, sandbox_session_id)
}

/// Persistent sequential policyd client owned by one syscall broker.
pub struct PersistentPolicyClient {
    client: PersistentRpcClient,
}

impl PersistentPolicyClient {
    /// Connect to the policyd RPC server reachable at `socket_path`.
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            client: PersistentRpcClient::new(socket_path),
        }
    }

    async fn request(&mut self, req: RpcRequest, timeout: Duration) -> io::Result<RpcReply> {
        self.client
            .request(req, timeout)
            .await
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn invalidate(&mut self) {
        self.client.invalidate();
    }

    /// Ask policyd whether the network `target` is allowed for the given
    /// sandbox session and pid.
    ///
    /// Returns `true` when policyd allows the request; a policy denial,
    /// a mismatched reply, or an RPC failure all return `false`.
    pub async fn check_target(
        &mut self,
        target: &NetworkTarget,
        sandbox_session_id: Option<String>,
        pid: u32,
        timeout: Duration,
    ) -> bool {
        let req = RpcRequest::Check {
            host: Some(target.host.clone()),
            connect_host: Some(target.host.clone()),
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
                self.invalidate();
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
        &mut self,
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
            self.invalidate();

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
        &mut self,
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
            self.invalidate();

            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "policyd returned a non-FilesystemCheck reply for CheckFilesystem",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, time::Duration};

    use agent_sandbox_core::{
        CheckReply, FileAccess, FilesystemCheckReply, RpcMessage, RpcReply, VerdictSource,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
    };

    use super::{PersistentPolicyClient, request_context};

    /// Restore process environment mutated by tests that exercise the
    /// sandbox-path resolution fallback.
    struct EnvGuard(Vec<(&'static str, Option<String>)>);

    #[allow(
        unsafe_code,
        reason = "std::env::set_var is unsafe in edition 2024; test-only"
    )]
    impl EnvGuard {
        fn set(entries: &[(&'static str, &str)]) -> Self {
            let previous = entries
                .iter()
                .map(|(key, _)| (*key, std::env::var(key).ok()))
                .collect();

            for (key, value) in entries {
                // SAFETY: tests run single-threaded within this binary's
                // test threads, and every key is restored on drop.
                unsafe { std::env::set_var(key, value) };
            }

            Self(previous)
        }
    }

    #[allow(
        unsafe_code,
        reason = "std::env::remove_var is unsafe in edition 2024; test-only"
    )]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    // SAFETY: restoring the values captured in `set`; tests run
                    // single-threaded and every key is restored on drop.
                    Some(value) => unsafe { std::env::set_var(key, value) },
                    // SAFETY: as above; the key was captured by `set`.
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    #[test]
    fn request_context_resolves_sandbox_paths_from_environment() {
        let _guard = EnvGuard::set(&[
            (
                "AGENT_SANDBOX_SESSION_CONTEXT_PATH",
                "/nonexistent/agent-sandbox-session-context.json",
            ),
            ("AGENT_SANDBOX_CWD", "/work"),
            ("AGENT_SANDBOX_HOME", "/home/sbx"),
            ("AGENT_SANDBOX_PROJECT_ROOT", "/work/repo"),
        ]);

        let ctx = request_context(42, Some("session-a".into()));
        assert_eq!(ctx.sandbox_paths().cwd(), Some(Path::new("/work")));
        assert_eq!(ctx.sandbox_paths().home(), Some(Path::new("/home/sbx")));

        assert_eq!(
            ctx.sandbox_paths().project_root(),
            Some(Path::new("/work/repo"))
        );

        assert_eq!(ctx.sandbox_session_id.as_deref(), Some("session-a"));
        assert_eq!(ctx.ids().pid(), Some(42));
    }

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

        let mut client = PersistentPolicyClient::new(&socket_path);

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
