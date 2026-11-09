//! JSON-line policyd client helpers.

use std::{
    os::fd::AsRawFd,
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

/// Errors returned by the policyd JSON-line RPC client.
///
/// Every variant is terminal for the connection: after any error the caller
/// should treat the socket as unusable rather than retrying on it.
#[derive(Debug, thiserror::Error)]
pub enum RpcClientError {
    /// The complete request/reply round-trip exceeded the configured timeout.
    #[error("policyd RPC timed out")]
    Timeout,

    /// policyd closed the connection before sending a reply.
    #[error("policyd closed connection")]
    Closed,

    /// policyd replied, but with a message that does not match the request.
    #[error("policyd returned an unexpected reply: {0}")]
    UnexpectedReply(&'static str),

    /// The reply line could not be parsed as valid JSON.
    #[error("invalid JSON from policyd")]
    InvalidJson(#[from] serde_json::Error),

    /// An underlying I/O error from the Unix socket.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The connected peer is not a trusted policyd process.
    #[error("policyd socket listener is untrusted")]
    UntrustedPeer,
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
        Self::connect_inner(socket_path, false).await
    }

    /// Connect to a policyd Unix socket and reject a listener that runs as
    /// our own uid.
    ///
    /// Jail-side policy clients use this so a sandbox-resident impostor
    /// listener (which would answer policy requests itself) is rejected at
    /// connect time, before any request is issued.
    ///
    /// # Errors
    /// Returns [`RpcClientError::UntrustedPeer`] when the listener runs as
    /// the connecting uid, or [`RpcClientError::Io`] if the socket cannot be
    /// opened.
    pub async fn connect_trusted(socket_path: impl AsRef<Path>) -> Result<Self, RpcClientError> {
        Self::connect_inner(socket_path, true).await
    }

    async fn connect_inner(
        socket_path: impl AsRef<Path>,
        require_trusted_peer: bool,
    ) -> Result<Self, RpcClientError> {
        let stream = UnixStream::connect(socket_path).await?;

        if require_trusted_peer && !peer_is_trusted_non_local(&stream) {
            return Err(RpcClientError::UntrustedPeer);
        }

        let (reader, writer) = stream.into_split();

        Ok(Self {
            reader: BufReader::new(reader),
            writer,
        })
    }

    /// Whether the peer has closed or reset the connection while it sat idle.
    ///
    /// Peeks without consuming or blocking, so unread bytes stay available to
    /// [`read_message`](Self::read_message). Pending data means the peer is
    /// still there.
    fn peer_has_closed(&self) -> bool {
        use nix::{
            errno::Errno,
            sys::socket::{MsgFlags, recv},
        };

        let stream: &UnixStream = self.reader.get_ref().as_ref();
        let mut probe = [0_u8; 1];
        let flags = MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT;

        match recv(stream.as_raw_fd(), &mut probe, flags) {
            Ok(received) => received == 0,
            Err(Errno::EAGAIN | Errno::EINTR) => false,
            Err(_) => true,
        }
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

/// Whether the listener on a connected Unix socket runs as a host process
/// other than our own uid.
///
/// policyd runs outside the sandbox as a host identity that never equals the
/// sandbox user; a listener answering on the sandbox uid is an impostor
/// planted to answer policy requests itself. A peer-credential read failure
/// is treated as untrusted so the client fails closed.
fn peer_is_trusted_non_local(stream: &UnixStream) -> bool {
    match nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials) {
        Ok(creds) => creds.uid() != nix::unistd::geteuid().as_raw(),
        Err(_) => false,
    }
}

/// Persistent sequential policyd client.
///
/// A request uses the current connection, establishing it lazily on the first
/// request. Requests are intentionally sequential (`&mut self`), so a reply
/// can never be attributed to the wrong request. A reused connection whose
/// peer closed it while idle (for example across a policyd restart) is
/// replaced by a fresh one before anything is written, so nothing is sent
/// twice. Any transport, framing, JSON, or timeout failure discards the
/// connection. When policyd closes the connection before replying, a
/// request that [`RpcRequest::is_replayable`] is sent once more on a fresh
/// connection within the same timeout; any other failed request is never
/// replayed, because its bytes may have reached policyd and retrying could
/// duplicate a one-shot approval.
pub struct PersistentRpcClient {
    socket_path: PathBuf,
    connection: Option<RpcConnection>,
    require_trusted_peer: bool,
}

impl PersistentRpcClient {
    /// Create a disconnected client that will connect to `socket_path` lazily.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            connection: None,
            require_trusted_peer: false,
        }
    }

    /// Create a lazy client that rejects a policy socket whose listener runs
    /// as the connecting uid.
    ///
    /// Jail-side enforcement processes (the syscall broker, fs-arm, D-Bus
    /// proxy) use this so a sandbox-resident impostor listener is never used
    /// as the policy authority. The rejection happens on the timed persistent
    /// connection, so a briefly absent policyd still retries lazily instead of
    /// aborting at startup.
    #[must_use]
    pub fn new_trusted(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            require_trusted_peer: true,
            ..Self::new(socket_path)
        }
    }

    /// Discard the current connection after a protocol-level mismatch.
    pub fn invalidate(&mut self) {
        self.connection = None;
    }

    /// Send one request over the persistent connection.
    ///
    /// The timeout includes lazy connection establishment, the complete
    /// write/flush/read operation and a replay. The connection is discarded
    /// on every error so the next call starts with a fresh socket.
    ///
    /// # Errors
    /// Returns a policyd RPC or timeout error.
    pub async fn request(
        &mut self,
        req: RpcRequest,
        timeout: Duration,
    ) -> Result<RpcReply, RpcClientError> {
        let replay = req.is_replayable().then(|| req.clone());
        let result = time::timeout(timeout, async {
            let result = self.send(req).await;
            if matches!(result, Err(RpcClientError::Closed))
                && let Some(req) = replay
            {
                self.connection = None;
                return self.send(req).await;
            }
            result
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

    async fn send(&mut self, req: RpcRequest) -> Result<RpcReply, RpcClientError> {
        if self
            .connection
            .as_ref()
            .is_some_and(RpcConnection::peer_has_closed)
        {
            self.connection = None;
        }
        if self.connection.is_none() {
            let connection = if self.require_trusted_peer {
                RpcConnection::connect_trusted(&self.socket_path).await?
            } else {
                RpcConnection::connect(&self.socket_path).await?
            };
            self.connection = Some(connection);
        }
        let Some(connection) = self.connection.as_mut() else {
            return Err(RpcClientError::Closed);
        };
        connection.request(req).await
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

    const ALLOWED_REPLY: &[u8] = br#"{"result":"check","ok":true,"allowed":true,"source":"allow"}
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

            assert!(matches!(reply, RpcReply::Check(reply) if reply.verdict.allowed));
        }

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn connection_closed_while_idle_is_replaced_before_sending() {
        let dir = tempdir().expect("temporary directory");
        let socket = dir.path().join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind policy socket");

        let first_server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            let mut line = String::new();
            assert!(reader.read_line(&mut line).await.expect("read request") > 0);
            write.write_all(ALLOWED_REPLY).await.expect("write reply");
            write.flush().await.expect("flush reply");
        });

        let mut client = PersistentRpcClient::new(&socket);
        client
            .request(request(), Duration::from_secs(1))
            .await
            .expect("first request succeeds");
        first_server.await.expect("first server task");

        // A restarted policyd serves the same path from a new socket.
        std::fs::remove_file(&socket).expect("remove old socket");
        let listener = UnixListener::bind(&socket).expect("rebind policy socket");

        let second_server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            let mut line = String::new();
            assert!(reader.read_line(&mut line).await.expect("read request") > 0);
            write.write_all(ALLOWED_REPLY).await.expect("write reply");
            write.flush().await.expect("flush reply");
        });

        let reply = client
            .request(request(), Duration::from_secs(1))
            .await
            .expect("second request reconnects");

        assert!(matches!(reply, RpcReply::Check(reply) if reply.verdict.allowed));
        second_server.await.expect("second server task");
    }

    /// A policyd restart closes a connection after reading a request but
    /// before replying. The server reads one request on the first connection,
    /// drops it, then serves `replies` requests on a second connection, and
    /// returns the requests it read there.
    fn restart_after_first_request(
        listener: UnixListener,
        replies: usize,
    ) -> tokio::task::JoinHandle<Vec<String>> {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept first");
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            assert!(reader.read_line(&mut line).await.expect("read first") > 0);
            drop(reader);

            let (stream, _) = listener.accept().await.expect("accept second");
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            let mut seen = Vec::new();
            for _ in 0..replies {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.expect("read request") > 0);
                seen.push(line);
                write.write_all(ALLOWED_REPLY).await.expect("write reply");
                write.flush().await.expect("flush reply");
            }
            seen
        })
    }

    #[tokio::test]
    async fn check_is_replayed_after_mid_request_close() {
        let dir = tempdir().expect("temporary directory");
        let socket = dir.path().join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind policy socket");
        let server = restart_after_first_request(listener, 1);

        let reply = PersistentRpcClient::new(socket)
            .request(request(), Duration::from_secs(1))
            .await
            .expect("the check is answered by the restarted policyd");

        assert!(matches!(reply, RpcReply::Check(reply) if reply.verdict.allowed));
        let seen = server.await.expect("server task");
        assert!(seen[0].contains(r#""op":"check""#));
    }

    #[tokio::test]
    async fn one_shot_request_is_not_replayed() {
        let dir = tempdir().expect("temporary directory");
        let socket = dir.path().join("policy.sock");
        let listener = UnixListener::bind(&socket).expect("bind policy socket");
        let server = restart_after_first_request(listener, 1);
        let mut client = PersistentRpcClient::new(socket);

        let elevate = RpcRequest::Elevate {
            argv: vec!["true".to_owned()],
            ctx: RequestContext::default(),
        };
        assert!(matches!(
            client.request(elevate, Duration::from_secs(1)).await,
            Err(RpcClientError::Closed)
        ));

        client
            .request(request(), Duration::from_secs(1))
            .await
            .expect("next request reconnects");

        let seen = server.await.expect("server task");
        assert!(
            seen[0].contains(r#""op":"check""#),
            "the elevation must not reach the restarted policyd: {seen:?}"
        );
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
                .write_all(br#"{"result":"check","ok":true,"allowed":true,"source":"allow"}"#)
                .await
                .expect("write incomplete reply");
        });

        let mut client = PersistentRpcClient::new(socket);
        let elevate = RpcRequest::Elevate {
            argv: vec!["true".to_owned()],
            ctx: RequestContext::default(),
        };

        assert!(matches!(
            client.request(elevate, Duration::from_secs(1)).await,
            Err(RpcClientError::Closed)
        ));

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn trusted_client_rejects_same_uid_listener() {
        let dir = tempdir().expect("temporary directory");
        let socket = dir.path().join("policy.sock");

        // The listener runs as this test process's uid, which is the same euid
        // the connecting client sees. To a trusted client that is an impostor
        // listener, so the connect must be rejected.
        let listener = UnixListener::bind(&socket).expect("bind policy socket");

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            drop(stream);
        });

        let mut client = PersistentRpcClient::new_trusted(socket);

        assert!(matches!(
            client.request(request(), Duration::from_secs(1)).await,
            Err(RpcClientError::UntrustedPeer)
        ));

        server.await.expect("server task");
    }
}
