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
    }
}
