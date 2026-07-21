//! JSON-line policyd client helpers.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    time,
};

use crate::rpc::{RpcMessage, RpcReply, RpcRequest};

#[derive(Debug, thiserror::Error)]
pub enum RpcClientError {
    #[error("policyd RPC timed out")]
    Timeout,
    #[error("policyd closed connection")]
    Closed,
    #[error("invalid JSON from policyd")]
    InvalidJson(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Connected policyd session (typestate: socket is open).
pub struct RpcConnection {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl RpcConnection {
    /// Connect to a policyd Unix socket.
    ///
    /// # Errors
    /// Returns [`RpcClientError::Io`] if the socket cannot be opened.
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, RpcClientError> {
        let stream = UnixStream::connect(socket_path).await?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(reader),
            writer,
        })
    }

    /// Write a serialized RPC request to the connection.
    ///
    /// # Errors
    /// Returns [`RpcClientError::InvalidJson`] if serialization fails, or
    /// [`RpcClientError::Io`] if the write fails.
    pub async fn write_request(&mut self, req: &RpcRequest) -> Result<(), RpcClientError> {
        let line = serde_json::to_string(req)? + "\n";
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Read the next message from the connection.
    ///
    /// # Errors
    /// Returns [`RpcClientError::Closed`] if the connection is closed by the
    /// peer, [`RpcClientError::InvalidJson`] if the message is not valid
    /// JSON, or [`RpcClientError::Io`] on I/O errors.
    pub async fn read_message(&mut self) -> Result<RpcMessage, RpcClientError> {
        let mut buf = String::new();
        if self.reader.read_line(&mut buf).await? == 0 {
            return Err(RpcClientError::Closed);
        }
        if !buf.ends_with('\n') {
            return Err(RpcClientError::Closed);
        }
        Ok(serde_json::from_str(buf.trim())?)
    }

    /// Send a request and wait for a reply.
    ///
    /// # Errors
    /// Returns any error from [`write_request`](Self::write_request) or
    /// [`read_message`](Self::read_message).
    pub async fn request(&mut self, req: RpcRequest) -> Result<RpcReply, RpcClientError> {
        self.write_request(&req).await?;
        loop {
            let msg = self.read_message().await?;
            if let RpcMessage::Reply(reply) = msg {
                return Ok(reply);
            }
        }
    }
}

/// Persistent sequential policyd client.
///
/// A request uses the current connection, establishing it lazily on the first
/// request. Requests are intentionally sequential (`&mut self`), so a reply
/// can never be attributed to the wrong request. Any transport, framing, JSON,
/// or timeout failure discards the connection. In particular, a failed request
/// is never replayed: after request bytes may have reached policyd, retrying
/// could duplicate a one-shot approval.
pub struct PersistentRpcClient {
    socket_path: PathBuf,
    connection: Option<RpcConnection>,
}

impl PersistentRpcClient {
    /// Create a disconnected client that will connect to `socket_path` lazily.
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            connection: None,
        }
    }

    /// Discard the current connection after a protocol-level mismatch.
    pub fn invalidate(&mut self) {
        self.connection = None;
    }

    /// Send one request over the persistent connection.
    ///
    /// The timeout includes lazy connection establishment and the complete
    /// write/flush/read operation. The connection is discarded on every error
    /// so the next call starts with a fresh socket.
    ///
    /// # Errors
    /// Returns a policyd RPC or timeout error. A failed request is not retried.
    pub async fn request(
        &mut self,
        req: RpcRequest,
        timeout: Duration,
    ) -> Result<RpcReply, RpcClientError> {
        let result = time::timeout(timeout, async {
            if self.connection.is_none() {
                self.connection = Some(RpcConnection::connect(&self.socket_path).await?);
            }
            let Some(connection) = self.connection.as_mut() else {
                return Err(RpcClientError::Closed);
            };
            connection.request(req).await
        })
        .await;

        match result {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(error)) => {
                self.connection = None;
                Err(error)
            }
            Err(_) => {
                self.connection = None;
                Err(RpcClientError::Timeout)
            }
        }
    }
}

/// Open a connection, send a request, and wait for a reply with a timeout.
///
/// # Errors
/// Returns [`RpcClientError::Timeout`] if the operation does not complete
/// within `timeout`, or any error from [`RpcConnection::connect`] or
/// [`RpcConnection::request`].
pub async fn policy_rpc(
    socket_path: impl AsRef<Path>,
    req: RpcRequest,
    timeout: Duration,
) -> Result<RpcReply, RpcClientError> {
    time::timeout(timeout, async {
        let mut conn = RpcConnection::connect(socket_path).await?;
        conn.request(req).await
    })
    .await
    .map_err(|_| RpcClientError::Timeout)?
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::tempdir;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
    };

    use super::{PersistentRpcClient, RpcClientError};
    use crate::{RequestContext, RpcReply, RpcRequest};

    fn request() -> RpcRequest {
        RpcRequest::Check {
            host: Some("example.test".to_owned()),
            connect_host: Some("example.test".to_owned()),
            port: Some(443),
            scheme: "https".to_owned(),
            url: Some("https://example.test:443".to_owned()),
            ctx: RequestContext::default(),
        }
    }

    const ALLOWED_REPLY: &[u8] = br#"{"ok":true,"allowed":true,"source":"allow"}
"#;

    #[tokio::test]
    async fn persistent_client_reuses_one_connection() {
        let dir = tempdir().expect("temporary directory");
        let socket = dir.path().join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind policy socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            for _ in 0..2 {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.expect("read request") > 0);
                assert!(line.contains(r#""op":"check""#));
                write.write_all(ALLOWED_REPLY).await.expect("write reply");
                write.flush().await.expect("flush reply");
            }
        });

        let mut client = PersistentRpcClient::new(socket);
        for _ in 0..2 {
            let reply = client
                .request(request(), Duration::from_secs(1))
                .await
                .expect("request succeeds");
            assert!(matches!(reply, RpcReply::Check(reply) if reply.allowed));
        }
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn failed_request_is_discarded_without_replay() {
        let dir = tempdir().expect("temporary directory");
        let socket = dir.path().join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind policy socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept first");
            let (read, _) = stream.into_split();
            let mut reader = BufReader::new(read);
            let mut line = String::new();
            assert!(
                reader
                    .read_line(&mut line)
                    .await
                    .expect("read first request")
                    > 0
            );
            drop(reader);

            let (stream, _) = listener.accept().await.expect("accept second");
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            line.clear();
            assert!(
                reader
                    .read_line(&mut line)
                    .await
                    .expect("read second request")
                    > 0
            );
            write.write_all(ALLOWED_REPLY).await.expect("write reply");
            write.flush().await.expect("flush reply");
        });

        let mut client = PersistentRpcClient::new(socket);
        assert!(matches!(
            client.request(request(), Duration::from_secs(1)).await,
            Err(RpcClientError::Closed)
        ));
        let reply = client
            .request(request(), Duration::from_secs(1))
            .await
            .expect("next request reconnects");
        assert!(matches!(reply, RpcReply::Check(reply) if reply.allowed));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn incomplete_reply_is_rejected_and_connection_discarded() {
        let dir = tempdir().expect("temporary directory");
        let socket = dir.path().join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind policy socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut line = String::new();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            assert!(reader.read_line(&mut line).await.expect("read request") > 0);
            write
                .write_all(br#"{"ok":true,"allowed":true,"source":"allow"}"#)
                .await
                .expect("write incomplete reply");
        });

        let mut client = PersistentRpcClient::new(socket);
        assert!(matches!(
            client.request(request(), Duration::from_secs(1)).await,
            Err(RpcClientError::Closed)
        ));
        server.await.expect("server task");
    }
}
