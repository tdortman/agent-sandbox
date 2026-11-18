//! Host loopback listeners relayed into a caller's network namespace.
//!
//! A sandboxed OAuth client waits for its redirect on the loopback interface
//! of the sandbox network namespace, but the host browser connects to host
//! loopback. A bridge binds the host side of that port and dials the same
//! address inside the namespace of the process that asked for it.

use std::{
    fs::File,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use nix::sched::{CloneFlags, setns};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tracing::{debug, info, warn};

use crate::{error::PolicydError, server::peer::ClientPeer};

/// OAuth clients give up on the redirect after five minutes (omp's flow
/// timeout), so the host port is not held longer than that.
const BRIDGE_LIFETIME: Duration = Duration::from_mins(5);

/// Bridge host `127.0.0.1:port` and `[::1]:port` into the peer's network
/// namespace for [`BRIDGE_LIFETIME`].
///
/// Each address the host already uses is skipped, so a host service keeps its
/// port.
///
/// # Errors
/// Returns [`PolicydError::InvalidPort`] for privileged ports, and an I/O
/// error when the peer's namespace cannot be opened or no address is free.
pub async fn open(peer: ClientPeer, port: u16) -> Result<(), PolicydError> {
    // policyd runs as root; an unprivileged caller must not gain a
    // privileged port through it.
    if port < 1024 {
        return Err(PolicydError::InvalidPort);
    }

    let netns = Arc::new(peer_netns(peer)?);
    let (closed, _) = watch::channel(false);
    let mut bridged = false;

    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let address = SocketAddr::new(ip, port);
        let bridge = Bridge {
            target: address,
            netns: Arc::clone(&netns),
            closed: closed.clone(),
        };
        match bridge.start(address, BRIDGE_LIFETIME).await {
            Ok(_) => bridged = true,
            Err(error) => debug!(%address, %error, "host loopback address unavailable for bridge"),
        }
    }

    if !bridged {
        return Err(io::Error::from(io::ErrorKind::AddrInUse).into());
    }

    info!(
        port,
        pid = peer.pid,
        "bridging host loopback port into caller namespace"
    );
    Ok(())
}

/// Network namespace of the RPC peer.
fn peer_netns(peer: ClientPeer) -> io::Result<File> {
    let proc_dir = PathBuf::from(format!("/proc/{}", peer.pid));
    let netns = File::open(proc_dir.join("ns/net"))?;

    // The pid comes from SO_PEERCRED; another owner means it was reused.
    if std::fs::metadata(&proc_dir)?.uid() != peer.uid {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }

    Ok(netns)
}

/// Relay from host listeners to one address inside a network namespace.
struct Bridge {
    target: SocketAddr,
    netns: Arc<File>,
    /// Shared by the listeners of one port, so the `127.0.0.1` and `[::1]`
    /// sides close together once the target is gone.
    closed: watch::Sender<bool>,
}

impl Bridge {
    /// Bind `listen` on the host and relay its connections until `lifetime`
    /// passes or the target stops listening.
    async fn start(self, listen: SocketAddr, lifetime: Duration) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(listen).await?;
        let bound = listener.local_addr()?;

        tokio::spawn(async move {
            if tokio::time::timeout(lifetime, self.serve(&listener))
                .await
                .is_err()
            {
                debug!(%bound, "loopback bridge expired");
            }
        });

        Ok(bound)
    }

    async fn serve(&self, listener: &TcpListener) {
        let target = self.target;
        let mut closed = self.closed.subscribe();

        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                _ = closed.wait_for(|closed| *closed) => return,
            };
            let mut inbound = match accepted {
                Ok((stream, _)) => stream,
                Err(error) => {
                    warn!(%target, %error, "loopback bridge accept failed");
                    return;
                }
            };

            let namespace = Arc::clone(&self.netns);
            let dialed = tokio::task::spawn_blocking(move || dial_in(&namespace, target)).await;
            let mut outbound = match dialed.map_err(io::Error::other).and_then(|dialed| dialed) {
                Ok(stream) => match TcpStream::from_std(stream) {
                    Ok(stream) => stream,
                    Err(error) => {
                        warn!(%target, %error, "loopback bridge stream setup failed");
                        continue;
                    }
                },
                Err(error) => {
                    debug!(%target, %error, "loopback bridge target gone; closing bridge");
                    self.closed.send_replace(true);
                    return;
                }
            };

            tokio::spawn(async move {
                if let Err(error) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                {
                    debug!(%target, %error, "loopback bridge connection ended");
                }
            });
        }
    }
}

/// Connect to `target` from inside `netns`.
///
/// `setns` changes only the calling thread, so the connection is made on a
/// short-lived thread; the socket stays in that namespace afterwards.
fn dial_in(netns: &File, target: SocketAddr) -> io::Result<std::net::TcpStream> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                if !is_current_netns(netns)? {
                    setns(netns, CloneFlags::CLONE_NEWNET)?;
                }

                // Without a listener, the sandbox loopback fallback would route
                // this connect back to the host bridge itself.
                if std::net::TcpListener::bind(target).is_ok() {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }

                let stream = std::net::TcpStream::connect(target)?;
                stream.set_nonblocking(true)?;
                Ok(stream)
            })
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("namespace dial thread panicked")))
    })
}

fn is_current_netns(netns: &File) -> io::Result<bool> {
    let target = netns.metadata()?;
    let current = std::fs::metadata("/proc/thread-self/ns/net")?;
    Ok(target.dev() == current.dev() && target.ino() == current.ino())
}

#[cfg(test)]
mod tests {
    use std::{fs::File, net::SocketAddr, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::watch,
    };

    use super::Bridge;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().expect("loopback address")
    }

    async fn wait_until_closed(address: SocketAddr) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while TcpStream::connect(address).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bridge stops listening");
    }

    #[tokio::test]
    async fn relays_a_callback_and_closes_once_the_client_stops_listening() {
        let callback = TcpListener::bind(loopback())
            .await
            .expect("callback listener");
        let target = callback.local_addr().expect("callback address");
        let netns =
            Arc::new(File::open("/proc/thread-self/ns/net").expect("own network namespace"));
        let (closed, _) = watch::channel(false);
        let bridge = || Bridge {
            target,
            netns: Arc::clone(&netns),
            closed: closed.clone(),
        };
        // Stands in for the `[::1]` side of the same port.
        let sibling = bridge()
            .start(loopback(), Duration::from_secs(30))
            .await
            .expect("sibling bridge");
        let host = bridge()
            .start(loopback(), Duration::from_secs(30))
            .await
            .expect("bridge");

        let mut browser = TcpStream::connect(host).await.expect("browser connects");
        browser
            .write_all(b"GET /callback?code=abc")
            .await
            .expect("request sent");
        let (mut server_side, _) = callback.accept().await.expect("callback accepted");
        let mut request = [0_u8; 22];
        server_side
            .read_exact(&mut request)
            .await
            .expect("request relayed");
        assert_eq!(&request, b"GET /callback?code=abc");
        server_side.write_all(b"ok").await.expect("reply sent");
        let mut reply = [0_u8; 2];
        browser.read_exact(&mut reply).await.expect("reply relayed");
        assert_eq!(&reply, b"ok");

        drop(callback);
        // The first connection after the client is gone closes every
        // listener of the port.
        wait_until_closed(host).await;
        wait_until_closed(sibling).await;
    }
}
