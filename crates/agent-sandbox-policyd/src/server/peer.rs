//! Peer identity for incoming Unix socket RPC clients.

use agent_sandbox_core::{peer_cred_unix, peer_in_different_mount_ns, peer_in_netns};
use tokio::net::UnixStream;

use crate::store::PolicydArgs;

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
        peer_cred_unix(stream).map_or(Self::unknown(), |(pid, uid, gid)| Self { pid, uid, gid })
    }

    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            pid: 0,
            uid: 0,
            gid: 0,
        }
    }

    /// Whether this peer is a sandboxed agent (not a host UI / policy tool).
    #[must_use]
    pub fn is_sandboxed(&self, args: &PolicydArgs) -> bool {
        if self.pid == 0 {
            return false;
        }
        if let Some(netns) = args.sandbox_netns.as_deref() {
            return peer_in_netns(self.pid, netns);
        }
        peer_in_different_mount_ns(self.pid)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ClientPeer;
    use crate::store::PolicydArgs;

    fn args_with_netns(path: &str) -> PolicydArgs {
        PolicydArgs {
            sandbox_netns: Some(PathBuf::from(path)),
            socket: PathBuf::from("/run/agent-sandbox/policy.sock"),
            declarative: PathBuf::from("/etc/agent-sandbox/declarative.json"),
            export_json: PathBuf::from("/var/lib/agent-sandbox/exported-policy.json"),
            export_nix: None,
            approval_timeout: std::time::Duration::from_mins(5),
            interactive_approval: true,
            ui_spawn_cmd: None,
        }
    }

    #[test]
    fn unknown_peer_is_not_sandboxed() {
        let args = args_with_netns("/run/netns/agent-sandbox");
        assert!(!ClientPeer::unknown().is_sandboxed(&args));
    }

    #[test]
    fn host_peer_not_in_missing_netns() {
        let args = args_with_netns("/run/netns/does-not-exist-for-agent-sandbox-test");
        let peer = ClientPeer {
            pid: std::process::id(),
            uid: 0,
            gid: 0,
        };
        assert!(!peer.is_sandboxed(&args));
    }
}
