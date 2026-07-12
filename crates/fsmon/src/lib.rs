//! Shared types for the fanotify-based filesystem monitor binaries.

use std::path::PathBuf;

/// Arguments passed from the arm helper to the fsmon binary via CLI flags.
#[derive(Debug, Clone)]
pub struct FsmonArgs {
    pub pid: u32,
    pub socket: PathBuf,
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
}

/// Minimal RPC client for connecting to policyd over a Unix socket.
pub mod rpc_client {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    use agent_sandbox_core::{
        FileAccess, FilesystemCheckReply, FilesystemMonitorReply, FilesystemRule, RequestContext,
        RpcReply, RpcRequest,
    };
    use serde_json;

    /// Error from the fsmon RPC client.
    #[derive(Debug)]
    pub enum Error {
        Io(std::io::Error),
        Json(serde_json::Error),
        Reply(&'static str),
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(e) => write!(f, "io error: {e}"),
                Self::Json(e) => write!(f, "json error: {e}"),
                Self::Reply(msg) => f.write_str(msg),
            }
        }
    }

    /// Sequential client for multiple JSON-line requests on one Unix socket.
    ///
    /// A failed request permanently discards the current connection. The next
    /// request connects a new socket, and the failed request is never replayed.
    #[derive(Debug)]
    pub struct PersistentClient {
        socket_path: PathBuf,
        stream: Option<BufReader<UnixStream>>,
    }

    impl PersistentClient {
        /// Create a client that connects lazily when its first request is sent.
        #[must_use]
        pub fn new(socket_path: &Path) -> Self {
            Self {
                socket_path: socket_path.to_path_buf(),
                stream: None,
            }
        }

        /// Connect immediately and create a persistent client.
        ///
        /// # Errors
        /// Returns [`Error::Io`] if the Unix socket cannot be opened.
        pub fn connect(socket_path: &Path) -> Result<Self, Error> {
            let stream = UnixStream::connect(socket_path).map_err(Error::Io)?;
            Ok(Self {
                socket_path: socket_path.to_path_buf(),
                stream: Some(BufReader::new(stream)),
            })
        }

        /// Send a `CheckFilesystem` request over the persistent connection.
        ///
        /// # Errors
        /// Returns an error when the socket, JSON framing, or reply is invalid.
        /// After a socket or framing error, this client drops the connection
        /// before returning, so the next request starts on a fresh socket.
        pub fn check_filesystem(
            &mut self,
            path: &Path,
            access: FileAccess,
            ctx: RequestContext,
        ) -> Result<FilesystemCheckReply, Error> {
            let req = RpcRequest::CheckFilesystem {
                path: path.to_path_buf(),
                access,
                ctx,
            };
            let reply = self.send_request(&req)?;
            match reply {
                RpcReply::FilesystemCheck(r) => Ok(r),
                RpcReply::Error(_) => {
                    self.stream = None;
                    Err(Error::Reply("policyd returned an error"))
                }
                _ => {
                    self.stream = None;
                    Err(Error::Reply("unexpected reply type from policyd"))
                }
            }
        }

        fn ensure_connected(&mut self) -> Result<(), Error> {
            if self.stream.is_none() {
                let stream = UnixStream::connect(&self.socket_path).map_err(Error::Io)?;
                self.stream = Some(BufReader::new(stream));
            }
            Ok(())
        }

        fn send_request(&mut self, req: &RpcRequest) -> Result<RpcReply, Error> {
            let line = serde_json::to_vec(req).map_err(Error::Json)?;
            self.ensure_connected()?;

            let io_result = {
                let reader = self
                    .stream
                    .as_mut()
                    .expect("persistent client connected after ensure_connected");
                reader
                    .get_mut()
                    .write_all(&line)
                    .and_then(|()| reader.get_mut().write_all(b"\n"))
                    .and_then(|()| reader.get_mut().flush())
            };
            if let Err(error) = io_result {
                self.stream = None;
                return Err(Error::Io(error));
            }

            let mut response = String::new();
            let read_result = self
                .stream
                .as_mut()
                .expect("persistent client connected after request write")
                .read_line(&mut response);
            let bytes_read = match read_result {
                Ok(bytes_read) => bytes_read,
                Err(error) => {
                    self.stream = None;
                    return Err(Error::Io(error));
                }
            };
            if bytes_read == 0 {
                self.stream = None;
                return Err(Error::Reply("policyd closed the connection"));
            }
            if !response.ends_with('\n') {
                self.stream = None;
                return Err(Error::Reply("policyd returned an incomplete reply"));
            }

            match serde_json::from_str(response.trim()) {
                Ok(reply) => Ok(reply),
                Err(error) => {
                    self.stream = None;
                    Err(Error::Json(error))
                }
            }
        }
    }

    /// Send a `StartFilesystemMonitor` request and wait for a success reply.
    ///
    /// # Errors
    /// Returns [`Error::Io`] on socket/stream I/O failure, [`Error::Json`] on
    /// serialization failure, or [`Error::Reply`] if policyd returns an error or
    /// an unexpected reply type.
    pub fn start_monitor(
        socket_path: &Path,
        ctx: RequestContext,
        static_allow: Vec<FilesystemRule>,
    ) -> Result<FilesystemMonitorReply, Error> {
        let req = RpcRequest::StartFilesystemMonitor { ctx, static_allow };
        let reply = send_request(socket_path, &req)?;
        match reply {
            RpcReply::FilesystemMonitor(r) => Ok(r),
            RpcReply::Error(_) => Err(Error::Reply("policyd returned an error")),
            _ => Err(Error::Reply("unexpected reply type from policyd")),
        }
    }

    /// Send a `CheckFilesystem` request and return the reply.
    ///
    /// # Errors
    /// Returns [`Error::Io`] on socket/stream I/O failure, [`Error::Json`] on
    /// serialization failure, or [`Error::Reply`] if policyd returns an error or
    /// an unexpected reply type.
    pub fn check_filesystem(
        socket_path: &Path,
        path: &Path,
        access: FileAccess,
        ctx: RequestContext,
    ) -> Result<FilesystemCheckReply, Error> {
        let req = RpcRequest::CheckFilesystem {
            path: path.to_path_buf(),
            access,
            ctx,
        };
        let reply = send_request(socket_path, &req)?;
        match reply {
            RpcReply::FilesystemCheck(r) => Ok(r),
            RpcReply::Error(_) => Err(Error::Reply("policyd returned an error")),
            _ => Err(Error::Reply("unexpected reply type from policyd")),
        }
    }

    fn send_request(socket_path: &Path, req: &RpcRequest) -> Result<RpcReply, Error> {
        let mut stream = UnixStream::connect(socket_path).map_err(Error::Io)?;
        let line = serde_json::to_string(req).map_err(Error::Json)?;
        writeln!(stream, "{line}").map_err(Error::Io)?;
        stream.flush().map_err(Error::Io)?;

        let mut reader = std::io::BufReader::new(&stream);
        let mut resp = String::new();
        reader.read_line(&mut resp).map_err(Error::Io)?;
        serde_json::from_str(resp.trim()).map_err(Error::Json)
    }
}

#[cfg(test)]
mod tests {
    use super::rpc_client::PersistentClient;
    use agent_sandbox_core::{
        FileAccess, FilesystemCheckReply, RequestContext, RpcReply, VerdictSource,
    };
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    static SOCKET_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn socket_path(label: &str) -> PathBuf {
        let id = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agent-sandbox-fsmon-{label}-{}-{id}.sock",
            std::process::id()
        ))
    }

    fn reply_line() -> String {
        serde_json::to_string(&RpcReply::FilesystemCheck(FilesystemCheckReply::allowed(
            VerdictSource::policy(),
            PathBuf::from("/tmp/reply"),
            FileAccess::Read,
        )))
        .expect("serialize filesystem reply")
    }

    fn read_request(reader: &mut BufReader<std::os::unix::net::UnixStream>) {
        let mut request = String::new();
        let bytes = reader.read_line(&mut request).expect("read request");
        assert!(bytes > 0);
        assert!(request.ends_with('\n'));
    }

    #[test]
    fn persistent_client_reuses_one_connection_for_ordered_requests() {
        let path = socket_path("reuse");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let reply = reply_line();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept persistent client");
            let mut reader = BufReader::new(stream.try_clone().expect("clone test stream"));
            for _ in 0..2 {
                read_request(&mut reader);
                writeln!(stream, "{reply}").expect("write filesystem reply");
                stream.flush().expect("flush filesystem reply");
            }
        });

        let mut client = PersistentClient::connect(&path).expect("connect persistent client");
        let first = client
            .check_filesystem(
                Path::new("/tmp/first"),
                FileAccess::Read,
                RequestContext::default(),
            )
            .expect("first filesystem check");
        let second = client
            .check_filesystem(
                Path::new("/tmp/second"),
                FileAccess::Write,
                RequestContext::default(),
            )
            .expect("second filesystem check");
        assert!(first.allowed);
        assert!(second.allowed);

        server.join().expect("persistent server");
        std::fs::remove_file(path).expect("remove test socket");
    }

    #[test]
    fn persistent_client_reconnects_after_eof_without_replaying_request() {
        let path = socket_path("eof");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let reply = reply_line();
        let server = thread::spawn(move || {
            let (first, _) = listener.accept().expect("accept first connection");
            let mut first_reader =
                BufReader::new(first.try_clone().expect("clone first test stream"));
            read_request(&mut first_reader);
            drop(first_reader);
            drop(first);

            let (mut second, _) = listener.accept().expect("accept reconnect");
            let mut second_reader =
                BufReader::new(second.try_clone().expect("clone second test stream"));
            read_request(&mut second_reader);
            writeln!(second, "{reply}").expect("write reconnect reply");
            second.flush().expect("flush reconnect reply");
        });

        let mut client = PersistentClient::connect(&path).expect("connect persistent client");
        assert!(
            client
                .check_filesystem(
                    Path::new("/tmp/first"),
                    FileAccess::Read,
                    RequestContext::default(),
                )
                .is_err(),
            "EOF must deny the in-flight event"
        );
        let reply = client
            .check_filesystem(
                Path::new("/tmp/second"),
                FileAccess::Read,
                RequestContext::default(),
            )
            .expect("reconnected filesystem check");
        assert!(reply.allowed);

        server.join().expect("reconnect server");
        std::fs::remove_file(path).expect("remove test socket");
    }

    #[test]
    fn persistent_client_reconnects_after_malformed_reply() {
        let path = socket_path("malformed");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let reply = reply_line();
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("accept first connection");
            let mut first_reader =
                BufReader::new(first.try_clone().expect("clone first test stream"));
            read_request(&mut first_reader);
            writeln!(first, "{{malformed").expect("write malformed reply");
            first.flush().expect("flush malformed reply");
            drop(first_reader);
            drop(first);

            let (mut second, _) = listener.accept().expect("accept reconnect");
            let mut second_reader =
                BufReader::new(second.try_clone().expect("clone second test stream"));
            read_request(&mut second_reader);
            writeln!(second, "{reply}").expect("write reconnect reply");
            second.flush().expect("flush reconnect reply");
        });

        let mut client = PersistentClient::connect(&path).expect("connect persistent client");
        assert!(
            client
                .check_filesystem(
                    Path::new("/tmp/first"),
                    FileAccess::Read,
                    RequestContext::default(),
                )
                .is_err(),
            "malformed reply must deny the in-flight event"
        );
        let reply = client
            .check_filesystem(
                Path::new("/tmp/second"),
                FileAccess::Read,
                RequestContext::default(),
            )
            .expect("reconnected filesystem check");
        assert!(reply.allowed);

        server.join().expect("malformed reply server");
        std::fs::remove_file(path).expect("remove test socket");
    }
}
