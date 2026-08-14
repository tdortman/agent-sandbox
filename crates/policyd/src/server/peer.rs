//! Peer identity for incoming Unix socket RPC clients.

use agent_sandbox_core::peer_cred_unix;
use tokio::net::UnixStream;

/// Peer process connected to policyd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPeer {
    pub pid: u32,
    pub uid: u32,
    pub gid: i32,
}

impl ClientPeer {
    #[must_use]
    pub fn from_stream(stream: &UnixStream) -> Self {
        peer_cred_unix(stream).map_or(Self::unknown(), |cred| Self {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
        })
    }

    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            pid: u32::MAX,
            uid: u32::MAX,
            gid: -1,
        }
    }
}
