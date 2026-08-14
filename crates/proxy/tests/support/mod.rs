use std::{
    io::{ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsFd,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use agent_sandbox_core::{
    AttributionToken, ErrorReply, FlowClaimReply, HttpCheckReply, HttpRequest, NetworkFlowKey,
    NetworkFlowSelector, NormalizedPolicyHost, ProxyConnectionId, ProxySessionReply,
    ProxySessionToken, RpcReply, SimpleOkReply, Verdict, VerdictSource,
};
use bytes::{Buf, Bytes};
use nix::{
    libc,
    sys::socket::{setsockopt, sockopt::Linger},
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::pem::PemObject;
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
    sync::Notify,
    task::JoinHandle,
    time::{sleep, timeout},
};

pub mod h3;
pub mod harness;
pub mod origins;
pub mod policy;

/// One observed flow claim with the connection identity that owns it.
///
/// Lives in the aggregator so the original `support::ClaimEvent` path stays
/// valid. The fake policy service in `policy.rs` constructs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEvent {
    pub flow: agent_sandbox_core::NetworkFlowKey,
    pub connection_id: ProxyConnectionId,
}

/// One observed ownership release. The connection identifier must match the
/// identifier recorded when the flow was claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRelease {
    pub token: AttributionToken,
    pub connection_id: ProxyConnectionId,
}

pub use h3::{Http3Client, Http3Origin, Http3Response};
pub use harness::{IpVersion, TransparentHarness, loopback};
pub use origins::{TcpOrigin, UdpOrigin};
pub use policy::{FakePolicy, PolicyEvents};
