//! The sandbox side: what a `fusermount3` does for a FUSE client, carried out
//! by asking policyd to mount in this sandbox's mount namespace.

use std::{
    io::{self, Write},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::{HEARTBEAT_FIELD, RequestContext, RpcMessage, RpcReply, RpcRequest};
use agent_sandbox_sysutil::{recv_with_fds, send_fd};
use rustix::{net::sockopt::socket_peercred, process::getuid};
use thiserror::Error;

/// How long policyd may stay silent before the shim gives up. It heartbeats
/// every ten seconds while a mount waits on an approval prompt.
const SILENCE_LIMIT: Duration = Duration::from_secs(60);

/// Most bytes of replies read before the shim gives up.
const MAX_REPLY_BYTES: usize = 1 << 20;

/// Why the shim failed.
#[derive(Debug, Error)]
pub enum ShimError {
    /// Talking to policyd failed.
    #[error("cannot reach the agent-sandbox policy daemon: {0}")]
    Socket(#[from] io::Error),

    /// The listener on the policy socket runs as the sandbox user.
    #[error("the policy socket is not served by the policy daemon")]
    UntrustedListener,

    /// policyd refused or could not do the request.
    #[error("{0}")]
    Refused(String),

    /// policyd's reply did not match the request.
    #[error("unexpected reply from the agent-sandbox policy daemon")]
    Protocol,
}

/// A policyd reply and the descriptors that came with it.
struct Answer {
    reply: RpcReply,
    fds: Vec<OwnedFd>,
}

/// Where the shim reaches policyd and who it speaks for.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The sandbox policy socket.
    pub socket: PathBuf,

    /// The request context: session id, pid and uid.
    pub ctx: RequestContext,

    /// Refuse a listener running as the calling uid, which would be an
    /// impostor inside the sandbox rather than the root policy daemon.
    pub require_foreign_listener: bool,
}

/// Ask policyd to mount `mountpoint` and hand the `/dev/fuse` descriptor it
/// returns to the FUSE client over `comm_fd`.
///
/// # Errors
/// [`ShimError::Refused`] with policyd's reason when the mount is refused.
pub fn mount(
    endpoint: &Endpoint,
    mountpoint: &Path,
    options: &str,
    comm_fd: BorrowedFd<'_>,
) -> Result<(), ShimError> {
    let answer = call(endpoint, &RpcRequest::FuseMount {
        mountpoint: mountpoint.to_path_buf(),
        options: options.to_owned(),
        ctx: endpoint.ctx.clone(),
    })?;

    expect_ok(&answer.reply)?;

    let fuse_fd = answer.fds.first().ok_or(ShimError::Protocol)?;

    // libfuse and go-fuse both read a message with one descriptor attached.
    send_fd(comm_fd, &[0], fuse_fd.as_fd())?;

    Ok(())
}

/// Ask policyd to unmount `mountpoint`.
///
/// # Errors
/// [`ShimError::Refused`] with policyd's reason when the unmount is refused.
pub fn unmount(endpoint: &Endpoint, mountpoint: &Path, lazy: bool) -> Result<(), ShimError> {
    let answer = call(endpoint, &RpcRequest::FuseUnmount {
        mountpoint: mountpoint.to_path_buf(),
        lazy,
        ctx: endpoint.ctx.clone(),
    })?;

    expect_ok(&answer.reply)
}

/// Block until the FUSE client closes its end of `comm_fd`, then unmount
/// lazily: the `auto_unmount` contract.
///
/// # Errors
/// [`ShimError::Refused`] when the unmount is refused.
pub fn unmount_when_client_exits(
    endpoint: &Endpoint,
    mountpoint: &Path,
    comm_fd: BorrowedFd<'_>,
) -> Result<(), ShimError> {
    let mut buf = [0_u8; 16];

    loop {
        match recv_with_fds(comm_fd, &mut buf) {
            Ok(received) if received.len == 0 => break,
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }

    unmount(endpoint, mountpoint, true)
}

fn expect_ok(reply: &RpcReply) -> Result<(), ShimError> {
    match reply {
        RpcReply::Simple(simple) if simple.ok => Ok(()),
        RpcReply::Error(error) => Err(ShimError::Refused(error.error.clone())),
        _ => Err(ShimError::Protocol),
    }
}

/// Send one request and read lines until the reply, keeping any descriptor
/// that arrives meanwhile.
fn call(endpoint: &Endpoint, request: &RpcRequest) -> Result<Answer, ShimError> {
    let mut stream = UnixStream::connect(&endpoint.socket)?;

    if endpoint.require_foreign_listener {
        let listener = socket_peercred(&stream).map_err(io::Error::from)?;

        if listener.uid == getuid() {
            return Err(ShimError::UntrustedListener);
        }
    }

    stream.set_read_timeout(Some(SILENCE_LIMIT))?;

    // The mount may wait on a filesystem approval prompt, so ask for
    // heartbeats and bound the silence instead of the whole wait.
    let mut line = serde_json::to_value(request).map_err(io::Error::from)?;
    line[HEARTBEAT_FIELD] = true.into();
    writeln!(stream, "{line}")?;

    let mut pending = Vec::new();
    let mut fds = Vec::new();
    let mut buf = [0_u8; 4096];

    loop {
        let received = recv_with_fds(&stream, &mut buf).map_err(|err| match err.kind() {
            io::ErrorKind::WouldBlock => io::Error::new(
                io::ErrorKind::TimedOut,
                "the policy daemon stopped responding",
            ),
            _ => err,
        })?;

        fds.extend(received.fds);

        if received.len == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        pending.extend_from_slice(&buf[..received.len]);

        if pending.len() > MAX_REPLY_BYTES {
            return Err(ShimError::Protocol);
        }

        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let text: Vec<u8> = pending.drain(..=end).collect();
            let text = String::from_utf8_lossy(&text);

            if text.trim().is_empty() {
                continue;
            }

            if let RpcMessage::Reply(reply) =
                serde_json::from_str(text.trim()).map_err(io::Error::from)?
            {
                return Ok(Answer { reply, fds });
            }
        }
    }
}

#[cfg(test)]
mod tests;
