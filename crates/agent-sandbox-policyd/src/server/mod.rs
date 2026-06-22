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

    fn bind_socket(path: &Path) -> std::io::Result<UnixListener> {
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
            perms.set_mode(0o666);
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

    pub async fn run(self) -> std::io::Result<()> {
        if self.host_socket_path == self.sandbox_socket_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "host and sandbox policy sockets must differ",
            ));
        }

        let host_listener = Self::bind_socket(&self.host_socket_path)?;
        let sandbox_listener = Self::bind_socket(&self.sandbox_socket_path)?;

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
        RequestContext, RpcConnection, RpcMessage, RpcReply, RpcRequest, UiPush,
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

        // 1. RegisterUi to host socket should succeed.
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
            matches!(&reply, RpcReply::RegisterUi(r) if r.ok),
            "host RegisterUi should succeed, got: {reply:?}"
        );

        // 2. RegisterUi to sandbox socket should be rejected.
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
            "sandbox RegisterUi should be rejected, got: {reply:?}"
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
    async fn registered_omp_connection_becomes_uifd_only() {
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

        // 1. Open a host socket connection and register as OMP.
        let mut conn = RpcConnection::connect(&args.host_socket)
            .await
            .expect("connect host socket");
        let reply = conn
            .request(RpcRequest::RegisterUi {
                ui_client: Some("omp".into()),
                ctx: RequestContext {
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("RegisterUi");
        assert!(
            matches!(&reply, RpcReply::RegisterUi(r) if r.ok),
            "OMP RegisterUi should succeed, got: {reply:?}"
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
    async fn registered_omp_receives_sandbox_network_push() {
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
                ui_client: Some("omp".into()),
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
    async fn registered_omp_receives_sandbox_elevation_push() {
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
                ui_client: Some("omp".into()),
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
                pushed,
                RpcMessage::UiPush(UiPush::ElevationRequest {
                    argv: Some(ref argv),
                    ..
                }) if argv == &vec!["whoami".to_string()]
            ),
            "expected elevation push, got: {pushed:?}"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn sandbox_rejects_duplicate_omp_ui_registration() {
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

        // First registration from sandbox should succeed and the connection
        // must stay alive (the real OMP extension holds its socket open).
        let mut first_conn = RpcConnection::connect(&args.sandbox_socket)
            .await
            .expect("connect sandbox");
        let reply = first_conn
            .request(RpcRequest::RegisterUi {
                ui_client: Some("omp".into()),
                ctx: RequestContext {
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            })
            .await
            .expect("first sandbox omp RegisterUi");
        assert!(
            matches!(&reply, RpcReply::RegisterUi(r) if r.ok),
            "first omp registration should succeed, got: {reply:?}"
        );

        // Second registration with same sandbox session from a different
        // connection should be rejected while the first connection is live.
        let reply = send_and_recv(
            &args.sandbox_socket,
            RpcRequest::RegisterUi {
                ui_client: Some("omp".into()),
                ctx: RequestContext {
                    sandbox_session_id: Some("s1".into()),
                    ..Default::default()
                },
            },
        )
        .await
        .expect("second sandbox omp RegisterUi");
        assert!(
            matches!(&reply, RpcReply::Error(e) if e.error.contains("already registered")),
            "duplicate omp registration should be rejected, got: {reply:?}"
        );

        // Dropping first_conn closes it, which allows re-registration.
        drop(first_conn);
        server_task.abort();
    }
}
