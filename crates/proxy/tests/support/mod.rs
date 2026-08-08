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

pub use h3::{Http3Client, Http3Origin, Http3Response};
pub use harness::{IpVersion, TransparentHarness, loopback};
pub use origins::{TcpOrigin, UdpOrigin};
pub use policy::{FakePolicy, PolicyEvents};
