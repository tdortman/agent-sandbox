//! JSON-line RPC server over Unix domain sockets.

mod client;
mod dispatch;
mod peer;

pub use peer::ClientPeer;

use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;

use crate::store::PolicyStore;

pub struct PolicyServer {
    store: Arc<PolicyStore>,
    host_socket_path: std::path::PathBuf,
    sandbox_socket_path: std::path::PathBuf,
}

impl PolicyServer {
    pub fn new(
        store: Arc<PolicyStore>,
        host_socket_path: impl Into<std::path::PathBuf>,
        sandbox_socket_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            store,
            host_socket_path: host_socket_path.into(),
            sandbox_socket_path: sandbox_socket_path.into(),
        }
    }

    fn bind_socket(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(listener)
    }

    async fn accept_loop(
        listener: UnixListener,
        store: Arc<PolicyStore>,
        role: dispatch::SocketRole,
        socket_path: std::path::PathBuf,
    ) {
        tracing::info!(
            role = ?role,
            socket = %socket_path.display(),
            "policyd listening"
        );
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let store = store.clone();
                    tokio::spawn(async move {
                        if let Err(err) = client::handle_client(store, stream, role).await {
                            tracing::warn!(error = %err, "policyd client error");
                        }
                    });
                }
                Err(err) => {
                    tracing::error!(error = %err, "policyd accept error");
                }
            }
        }
    }

    /// # Errors
    ///
    /// Returns an error if the host and sandbox socket paths are identical, if socket
    /// binding fails (permissions, path length, or filesystem issues), or if Unix-domain
    /// socket setup fails.
    pub async fn run(self) -> std::io::Result<()> {
        if self.host_socket_path == self.sandbox_socket_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "host and sandbox policy sockets must differ",
            ));
        }

        // Host socket: world-accessible like the pre-hardening default. policyd runs
        // as root, so 0600 would mean only root can connect and the desktop user's
        // UI/approve CLI could never register. Sensitive ops still bind to
        // SO_PEERCRED. Sandbox socket: same mode; RPC auth limits it to request ops.
        let host_listener = Self::bind_socket(&self.host_socket_path, 0o666)?;
        let sandbox_listener = Self::bind_socket(&self.sandbox_socket_path, 0o666)?;

        tokio::join!(
            Self::accept_loop(
                host_listener,
                self.store.clone(),
                dispatch::SocketRole::Host,
                self.host_socket_path,
            ),
            Self::accept_loop(
                sandbox_listener,
                self.store.clone(),
                dispatch::SocketRole::Sandbox,
                self.sandbox_socket_path,
            ),
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PolicydArgs;
    use agent_sandbox_core::{
        ApprovalScope, RequestContext, RpcConnection, RpcMessage, RpcReply, RpcRequest, UiPush,
    };
    use std::time::Duration;

    fn test_args(dir: &tempfile::TempDir) -> PolicydArgs {
        PolicydArgs {
            host_socket: dir.path().join("host-policy.sock"),
            sandbox_socket: dir.path().join("sandbox-policy.sock"),
            declarative: dir.path().join("declarative.json"),
            export_json: dir.path().join("exported-policy.json"),
            export_nix: None,
            approval_timeout: Duration::from_mins(5),
            interactive_approval: true,
            ui_spawn_cmd: None,
            fs_monitor_cmd: None,
            syscall_broker_cmd: None,
        }
    }

    async fn send_and_recv(
        socket: &std::path::Path,
        req: RpcRequest,
    ) -> Result<RpcReply, agent_sandbox_core::RpcClientError> {
        let mut conn = RpcConnection::connect(socket).await?;
        conn.request(req).await
    }

    #[tokio::test]
    async fn sandbox_socket_rejects_host_control_requests() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = test_args(&dir);
        let store = Arc::new(PolicyStore::new(args.clone()));
        let server = PolicyServer::new(
            store.clone(),
            args.host_socket.clone(),
            args.sandbox_socket.clone(),
        );

        let server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Allow sockets to be created.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // 1. RegisterUi to host socket without a sandbox session is rejected:
        //    otherwise any host-local process could subscribe to prompts by path.
        let reply = send_and_recv(
            &args.host_socket,
            RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext::default(),
            },
        )
        .await
        .expect("host RegisterUi");
        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "approval session does not match pending sandbox session"),
            "host RegisterUi without sandbox_session_id must be rejected, got: {reply:?}"
        );

        // 2. RegisterUi to sandbox socket must be REJECTED. The sandbox socket
        //    is exposed inside the jail; if an attacker could register as the
        //    UI on it they could approve their own Check/Elevate requests (and
        //    Elevate runs approved commands as root on the host). See
        //    `sandbox_socket_blocks_self_approval_escape` for the full chain.
        let reply = send_and_recv(
            &args.sandbox_socket,
            RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext::default(),
            },
        )
        .await
        .expect("sandbox RegisterUi");
        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "request not allowed on sandbox policy socket"),
            "sandbox RegisterUi must be rejected, got: {reply:?}"
        );

        // 3. StartFilesystemMonitor to sandbox socket should reach handler.
        let reply = send_and_recv(
            &args.sandbox_socket,
            RpcRequest::StartFilesystemMonitor {
                ctx: RequestContext::default(),
                static_allow: vec![],
            },
        )
        .await
        .expect("sandbox StartFilesystemMonitor");
        assert!(
            matches!(&reply, RpcReply::FilesystemMonitor(r) if !r.active && r.error.as_deref() == Some("fs_monitor_cmd not configured")),
            "sandbox StartFilesystemMonitor should reach handler, got: {reply:?}"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn registered_connection_becomes_uifd_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = test_args(&dir);
        let store = Arc::new(PolicyStore::new(args.clone()));
        let server = PolicyServer::new(
            store.clone(),
            args.host_socket.clone(),
            args.sandbox_socket.clone(),
        );

        let server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // 1. Open a host socket connection and register a UI.
        let mut conn = RpcConnection::connect(&args.host_socket)
            .await
            .expect("connect host socket");
        let reply = conn
            .request(RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext {
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("RegisterUi");
        assert!(
            matches!(&reply, RpcReply::RegisterUi(r) if r.ok),
            "RegisterUi should succeed, got: {reply:?}"
        );

        // 2. On the same connection, Check should be rejected because
        //    the connection transitioned to UiFd.
        let reply = conn
            .request(RpcRequest::Check {
                host: None,
                connect_host: None,
                port: None,
                scheme: "https".into(),
                url: None,
                ctx: RequestContext::default(),
            })
            .await
            .expect("Check after RegisterUi");
        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "request not allowed on inherited UI policy fd"),
            "Check should be rejected on UiFd connection, got: {reply:?}"
        );

        // 3. On the same connection, Status should succeed (allowed on UiFd).
        let reply = conn
            .request(RpcRequest::Status {
                ctx: RequestContext::default(),
            })
            .await
            .expect("Status after RegisterUi");
        assert!(
            matches!(&reply, RpcReply::Status(_)),
            "Status should succeed on UiFd connection, got: {reply:?}"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn registered_ui_receives_sandbox_network_push() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = test_args(&dir);
        let store = Arc::new(PolicyStore::new(args.clone()));
        let server = PolicyServer::new(
            store.clone(),
            args.host_socket.clone(),
            args.sandbox_socket.clone(),
        );

        let server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut ui_conn = RpcConnection::connect(&args.host_socket)
            .await
            .expect("connect host socket");
        let reply = ui_conn
            .request(RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext {
                    cwd: Some("/workspace".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/workspace".into()),
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("RegisterUi");
        assert!(matches!(&reply, RpcReply::RegisterUi(r) if r.ok));

        let mut sandbox_conn = RpcConnection::connect(&args.sandbox_socket)
            .await
            .expect("connect sandbox socket");
        sandbox_conn
            .write_request(&RpcRequest::Check {
                host: Some("example.com".into()),
                connect_host: Some("93.184.216.34".into()),
                port: Some(443),
                scheme: "tcp".into(),
                url: Some("tcp://example.com:443".into()),
                ctx: RequestContext {
                    cwd: Some("/workspace".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/workspace".into()),
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("write Check");

        let pushed =
            tokio::time::timeout(std::time::Duration::from_secs(1), ui_conn.read_message())
                .await
                .expect("network push timeout")
                .expect("read network push");
        assert!(
            matches!(
                pushed,
                RpcMessage::UiPush(UiPush::NetworkRequest {
                    host: Some(ref host),
                    port: Some(443),
                    ..
                }) if host == "example.com"
            ),
            "expected network push, got: {pushed:?}"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn registered_ui_receives_sandbox_elevation_push() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = test_args(&dir);
        let store = Arc::new(PolicyStore::new(args.clone()));
        let server = PolicyServer::new(
            store.clone(),
            args.host_socket.clone(),
            args.sandbox_socket.clone(),
        );

        let server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut ui_conn = RpcConnection::connect(&args.host_socket)
            .await
            .expect("connect host socket");
        let reply = ui_conn
            .request(RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext {
                    cwd: Some("/workspace".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/workspace".into()),
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("RegisterUi");
        assert!(matches!(&reply, RpcReply::RegisterUi(r) if r.ok));

        let mut sandbox_conn = RpcConnection::connect(&args.sandbox_socket)
            .await
            .expect("connect sandbox socket");
        sandbox_conn
            .write_request(&RpcRequest::Elevate {
                argv: vec!["whoami".into()],
                ctx: RequestContext {
                    cwd: Some("/workspace".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/workspace".into()),
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("write Elevate");

        let pushed =
            tokio::time::timeout(std::time::Duration::from_secs(1), ui_conn.read_message())
                .await
                .expect("elevation push timeout")
                .expect("read elevation push");
        assert!(
            matches!(
                &pushed,
                RpcMessage::UiPush(UiPush::ElevationRequest {
                    argv: Some(elevation_argv),
                    ..
                }) if elevation_argv == &vec!["whoami".to_string()]
            ),
            "expected elevation push, got: {pushed:?}"
        );

        server_task.abort();
    }

    /// Regression for the self-approval sandbox escape.
    ///
    /// Threat model: a malicious agent inside the jail can reach the
    /// sandbox-facing policy socket (`/run/agent-sandbox/sandbox-policy.sock`,
    /// bound into the sandbox by bwrap). The attack is:
    ///   1. Connect to the sandbox socket.
    ///   2. `RegisterUi` to transition the connection to the `UiFd` role.
    ///   3. Issue an `Elevate` (or `Check`) on another connection.
    ///   4. Receive the prompt push (the attacker matches its own route) and
    ///      read the `pending_id`.
    ///   5. `Approve` the pending id from the `UiFd` connection.
    /// Because policyd runs as root and `Elevate` executes the approved argv
    /// on the host, this is arbitrary-code-execution as root with no human
    /// ever answering a prompt.
    ///
    /// The fix gates the whole chain at step 2: `RegisterUi` is rejected on
    /// the sandbox socket, so an attacker can never attain the `UiFd` role
    /// from inside the jail, and therefore can never call `Approve`.
    #[tokio::test]
    async fn sandbox_socket_blocks_self_approval_escape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = test_args(&dir);
        let store = Arc::new(PolicyStore::new(args.clone()));
        let server = PolicyServer::new(
            store.clone(),
            args.host_socket.clone(),
            args.sandbox_socket.clone(),
        );

        let server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Attacker (inside the sandbox) connects to the sandbox socket and
        // attempts to register as the UI. This MUST be rejected; without the
        // fix it succeeds and the connection becomes an approval-capable UiFd.
        let mut attacker = RpcConnection::connect(&args.sandbox_socket)
            .await
            .expect("connect sandbox socket");
        let reply = attacker
            .request(RpcRequest::RegisterUi {
                ui_client: Some("standalone".into()),
                ctx: RequestContext {
                    cwd: Some("/workspace".into()),
                    home: Some("/home/user".into()),
                    project_root: Some("/workspace".into()),
                    sandbox_session_id: Some("attacker".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("sandbox RegisterUi");
        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "request not allowed on sandbox policy socket"),
            "sandbox RegisterUi must be rejected to block the self-approval escape, got: {reply:?}"
        );

        // Because registration was rejected, the connection did NOT transition
        // to UiFd. A follow-up Approve on the same connection must also be
        // rejected (still Sandbox role), proving the approval capability was
        // never granted.
        let reply = attacker
            .request(RpcRequest::Approve {
                id: "elev:fabricated".into(),
                scope: ApprovalScope::Once,
                session_id: None,
                target: None,
                ctx: RequestContext::default(),
            })
            .await
            .expect("sandbox Approve");
        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error == "request not allowed on sandbox policy socket"),
            "Approve must remain blocked on a sandbox connection that failed to register, got: {reply:?}"
        );

        server_task.abort();
    }
}
