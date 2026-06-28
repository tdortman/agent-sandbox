//! JSON-line policyd client helpers.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time;

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
    /// Returns [`RpcClientError::Closed`] if the connection is closed by the peer,
    /// [`RpcClientError::InvalidJson`] if the message is not valid JSON, or
    /// [`RpcClientError::Io`] on I/O errors.
    pub async fn read_message(&mut self) -> Result<RpcMessage, RpcClientError> {
        let mut buf = String::new();
        if self.reader.read_line(&mut buf).await? == 0 {
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

/// Open a connection, send a request, and wait for a reply with a timeout.
///
/// # Errors
/// Returns [`RpcClientError::Timeout`] if the operation does not complete within
/// `timeout`, or any error from [`RpcConnection::connect`] or
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
