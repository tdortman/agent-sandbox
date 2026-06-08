//! JSON-line RPC server over Unix domain sockets.

mod client;
mod dispatch;
mod peer;

pub use peer::ClientPeer;

use std::sync::Arc;

use tokio::net::UnixListener;

use crate::store::PolicyStore;

pub struct PolicyServer {
    store: Arc<PolicyStore>,
    socket_path: std::path::PathBuf,
}

impl PolicyServer {
    pub fn new(store: Arc<PolicyStore>, socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            store,
            socket_path: socket_path.into(),
        }
    }

    pub async fn run(self) -> std::io::Result<()> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&self.socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.socket_path)?.permissions();
            perms.set_mode(0o666);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }
        tracing::info!(socket = %self.socket_path.display(), "policyd listening");

        loop {
            let (stream, _) = listener.accept().await?;
            let store = self.store.clone();
            tokio::spawn(async move {
                if let Err(err) = client::handle_client(store, stream).await {
                    tracing::warn!(error = %err, "policyd client error");
                }
            });
        }
    }
}
