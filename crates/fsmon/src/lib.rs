//! Shared types for the fanotify-based filesystem monitor binaries.

/// Arguments passed from the arm helper to the fsmon binary via CLI flags.
#[derive(Debug, Clone)]
pub struct FsmonArgs {
    pub pid: u32,
    pub socket: String,
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
}

/// Minimal RPC client for connecting to policyd over a Unix socket.
pub mod rpc_client {
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

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
        path: &str,
        access: FileAccess,
        ctx: RequestContext,
    ) -> Result<FilesystemCheckReply, Error> {
        let req = RpcRequest::CheckFilesystem {
            path: path.to_owned(),
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
