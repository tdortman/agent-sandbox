//! Idle bound for downstream connections.
//!
//! Downstream peers are sandbox processes that policyd freezes while an
//! approval is pending. A wall-clock header read timeout would close the
//! keep-alive connection of a client frozen past it, so the HTTP server runs
//! without one. This bound replaces it: a connection that waits for a request
//! head, idle between requests or part-way through a head, for
//! [`IdleBound::budget`] of the owner's unfrozen time is closed. Time with a
//! request in progress, from the service call until its response body is
//! dropped, does not count, and neither does time the owner is frozen.
//! A connection that upgraded (WebSocket) is no longer an HTTP connection and
//! is never closed by this bound.
//!
//! The close is graceful first: the HTTP server is asked to shut the
//! connection down (a GOAWAY for HTTP/2, close-when-idle for HTTP/1), so a
//! request racing the close is refused in a way the client can retry. A
//! connection that is still open after [`IdleBound::grace`] more idle time
//! (a client that ignores the GOAWAY, a partial request head, a stalled TLS
//! handshake) is dropped.

use std::{
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use nix::sys::socket::{getsockopt, sockopt};
use rama_core::{
    Service, bytes::Bytes, error::BoxError, graceful::Shutdown, rt::Executor, service::service_fn,
};
use rama_http::{
    Body, Request, Response,
    body::{Frame, SizeHint, StreamingBody},
};
use tokio::sync::oneshot;
use tracing::info;

use super::is_websocket_upgrade_response;
use crate::{
    freeze::cgroup_frozen,
    peer_socket::{ClientSocket, client_socket},
};

/// How long a downstream connection may idle before it is closed.
#[derive(Debug, Clone, Copy)]
pub struct IdleBound {
    /// Unfrozen idle time before the graceful close starts.
    pub budget: Duration,
    /// Further idle time the graceful close gets before the connection is
    /// dropped.
    pub grace: Duration,
    /// Interval at which the owner's freezer state and the connection's
    /// activity are sampled.
    pub poll: Duration,
}

impl IdleBound {
    /// The production bound: 30 s idle, then 5 s of grace.
    pub const STANDARD: Self = Self {
        budget: Duration::from_secs(30),
        grace: Duration::from_secs(5),
        poll: Duration::from_secs(1),
    };
}

/// Request activity of one downstream connection.
#[derive(Debug, Default)]
pub struct ConnectionActivity {
    in_flight: AtomicUsize,
    /// A request started or finished since the last sample.
    touched: AtomicBool,
    upgraded: AtomicBool,
}

impl ConnectionActivity {
    /// A request entered the service; it stays in progress until the guard
    /// drops.
    #[must_use]
    pub fn begin(self: &Arc<Self>) -> RequestGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.touched.store(true, Ordering::Relaxed);
        RequestGuard {
            activity: Arc::clone(self),
        }
    }

    /// Ends the bound for this connection once `response` upgrades it, and
    /// otherwise keeps the request in progress until the response body is
    /// dropped.
    pub fn track_response(&self, guard: RequestGuard, mut response: Response) -> Response {
        if is_websocket_upgrade_response(&response) {
            self.upgraded.store(true, Ordering::Relaxed);
            return response;
        }

        let body = std::mem::replace(response.body_mut(), Body::empty());
        *response.body_mut() = Body::new(TrackedBody {
            inner: body,
            guard: Some(guard),
        });
        response
    }

    /// Resolves once the connection has waited for a request head for
    /// `budget` of unfrozen time (`owner_cgroup` is `None`: of any time),
    /// sampling every `poll`. Pends forever for an upgraded connection.
    pub async fn expired(&self, owner_cgroup: Option<&Path>, budget: Duration, poll: Duration) {
        let mut idle = Duration::ZERO;
        loop {
            tokio::time::sleep(poll).await;
            let active = self.touched.swap(false, Ordering::Relaxed)
                || self.in_flight.load(Ordering::Relaxed) > 0
                || self.upgraded.load(Ordering::Relaxed);
            if active {
                idle = Duration::ZERO;
            } else if !owner_cgroup.is_some_and(cgroup_frozen) {
                idle += poll;
                if idle >= budget {
                    return;
                }
            }
        }
    }
}

/// Interval at which [`peer_gone`] checks the socket for an error and for
/// bytes or an end of stream waiting to be read.
const PEER_POLL: Duration = Duration::from_millis(250);

/// Interval at which [`peer_gone`] re-reads the socket table once the peer
/// has sent a FIN.
const PEER_TABLE_POLL: Duration = Duration::from_millis(500);

/// Resolves once the client behind `socket` is gone: it reset the connection,
/// the connection timed out, or it closed its socket completely. `client` is
/// the address the proxy sees as the peer; `socket` is a second handle on the
/// proxy's end of the connection.
///
/// The HTTP/1 server runs with half-close enabled so a client that shuts
/// down its write side still gets its response. It then stops reading the
/// socket while a request is in progress and notices neither a reset nor a
/// FIN there, so a client that gave up during a pending approval would leave
/// its check and prompt behind, and an approval would then send the request
/// upstream with nobody waiting. This restores the cancellation:
///
/// - a socket error (a reset) ends the wait;
/// - an end of stream is either a half-close or a full close, which only the
///   client's socket tells apart ([`client_socket`]): an orphan means the
///   client closed it, while a socket a descriptor still owns means the client
///   waits for its response.
pub async fn peer_gone(socket: &tokio::net::TcpStream, client: SocketAddr) {
    let mut probe = [0_u8; 1];

    loop {
        match getsockopt(socket, sockopt::SocketError) {
            Ok(0) => {}
            Ok(_) | Err(_) => return,
        }

        match tokio::time::timeout(PEER_POLL, socket.peek(&mut probe)).await {
            // Nothing to read yet.
            Err(_) => {}
            Ok(Err(_)) => return,
            // A FIN: ask the socket table which kind it is.
            Ok(Ok(0)) => {
                if client_socket(client).await == ClientSocket::Closed {
                    return;
                }
                tokio::time::sleep(PEER_TABLE_POLL).await;
            }
            // Bytes the server has not read yet: the client is still sending.
            Ok(Ok(_)) => tokio::time::sleep(PEER_POLL).await,
        }
    }
}

/// Wrap `service` so every request it serves counts as in progress on
/// `activity` until its response body ends or drops.
pub fn track_requests<S>(
    activity: &Arc<ConnectionActivity>,
    service: S,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone
where
    S: Service<Request, Output = Response, Error = Infallible>,
{
    let activity = Arc::clone(activity);
    let service = Arc::new(service);

    service_fn(move |request: Request| {
        let guard = activity.begin();
        let activity = Arc::clone(&activity);
        let service = Arc::clone(&service);

        async move {
            let result = service.serve(request).await;
            result.map(|response| activity.track_response(guard, response))
        }
    })
}

/// Run one downstream connection under the idle bound.
///
/// `serve` receives the executor the HTTP server must be built with: its
/// shutdown guard is what turns the idle expiry into the server's graceful
/// close. Returns what `serve` returns, or `Ok` when the bound closed the
/// connection.
///
/// # Errors
/// Whatever the serve future fails with.
pub async fn serve_bounded<F, Fut>(
    activity: &ConnectionActivity,
    owner_cgroup: Option<&Path>,
    bound: IdleBound,
    serve: F,
) -> Result<(), BoxError>
where
    F: FnOnce(Executor) -> Fut,
    Fut: Future<Output = Result<(), BoxError>>,
{
    // The shutdown signal is the receiver: it fires when `drain` is sent, or
    // when the connection ends and drops it.
    let (drain, drained) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        let _ = drained.await;
    });
    let serving = serve(Executor::graceful(shutdown.guard()));
    tokio::pin!(serving);

    tokio::select! {
        result = &mut serving => return result,
        () = activity.expired(owner_cgroup, bound.budget, bound.poll) => {}
    }

    info!("closing idle downstream connection gracefully");
    let _ = drain.send(());

    tokio::select! {
        result = &mut serving => result,
        () = activity.expired(owner_cgroup, bound.grace, bound.poll) => {
            info!("dropped downstream connection that ignored the graceful close");
            Ok(())
        }
    }
}

/// One request in progress on a connection.
#[derive(Debug)]
pub struct RequestGuard {
    activity: Arc<ConnectionActivity>,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.activity.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.activity.touched.store(true, Ordering::Relaxed);
    }
}

/// A response body that keeps its request in progress until it ends or drops.
struct TrackedBody {
    inner: Body,
    guard: Option<RequestGuard>,
}

impl StreamingBody for TrackedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(context);
        if matches!(poll, Poll::Ready(None | Some(Err(_)))) {
            self.guard = None;
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use rama_core::extensions::ExtensionsRef as _;
    use rama_http::{Body, Response, StatusCode, body::util::BodyExt, io::upgrade::pending};
    use tokio::{
        task::JoinHandle,
        time::{Instant, sleep},
    };

    use super::{ConnectionActivity, IdleBound, serve_bounded};

    const POLL: Duration = Duration::from_secs(1);
    const BUDGET: Duration = Duration::from_secs(30);

    fn scope(frozen: bool) -> tempfile::TempDir {
        let scope = tempfile::tempdir().expect("scope dir");
        set_frozen(&scope, frozen);
        scope
    }

    fn set_frozen(scope: &tempfile::TempDir, frozen: bool) {
        std::fs::write(
            scope.path().join("cgroup.freeze"),
            if frozen { "1\n" } else { "0\n" },
        )
        .expect("write freeze state");
    }

    /// Run the idle bound of `activity`; the task finishes when it expires.
    fn watch(activity: &Arc<ConnectionActivity>, scope: &Path) -> JoinHandle<()> {
        let activity = Arc::clone(activity);
        let scope = scope.to_path_buf();
        tokio::spawn(async move { activity.expired(Some(&scope), BUDGET, POLL).await })
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_expires_after_the_budget() {
        let activity = Arc::new(ConnectionActivity::default());
        let scope = scope(false);
        let watch = watch(&activity, scope.path());
        sleep(Duration::from_secs(25)).await;
        assert!(!watch.is_finished());
        sleep(Duration::from_secs(10)).await;
        assert!(watch.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn frozen_time_does_not_count() {
        let activity = Arc::new(ConnectionActivity::default());
        let scope = scope(true);
        let watch = watch(&activity, scope.path());
        sleep(Duration::from_secs(120)).await;
        assert!(
            !watch.is_finished(),
            "a frozen owner's idle connection survives"
        );
        set_frozen(&scope, false);
        sleep(BUDGET + POLL * 2).await;
        assert!(watch.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_in_progress_does_not_count_and_resets_the_budget() {
        let activity = Arc::new(ConnectionActivity::default());
        let scope = scope(false);
        let watch = watch(&activity, scope.path());
        let guard = activity.begin();
        sleep(Duration::from_secs(120)).await;
        assert!(!watch.is_finished(), "a request in progress is not idle");

        let response = activity.track_response(guard, Response::new(Body::from("body")));
        sleep(Duration::from_secs(120)).await;
        assert!(!watch.is_finished(), "a response being sent is not idle");

        let mut body = response.into_body();
        while body.frame().await.is_some() {}
        drop(body);
        sleep(Duration::from_secs(25)).await;
        assert!(
            !watch.is_finished(),
            "the budget restarts when the response ends"
        );
        sleep(Duration::from_secs(10)).await;
        assert!(watch.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_shorter_than_a_sample_still_resets_the_budget() {
        let activity = Arc::new(ConnectionActivity::default());
        let scope = scope(false);
        let watch = watch(&activity, scope.path());
        sleep(Duration::from_secs(25)).await;
        drop(activity.begin());
        sleep(Duration::from_secs(25)).await;
        assert!(!watch.is_finished());
        sleep(Duration::from_secs(10)).await;
        assert!(watch.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn an_upgraded_connection_is_never_expired() {
        let activity = Arc::new(ConnectionActivity::default());
        let scope = scope(false);
        let watch = watch(&activity, scope.path());
        let (_, on_upgrade) = pending();
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        response.extensions().insert(on_upgrade);
        let response = activity.track_response(activity.begin(), response);
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        sleep(Duration::from_secs(600)).await;
        assert!(!watch.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_is_asked_to_close_before_it_is_dropped() {
        let activity = ConnectionActivity::default();
        let scope = scope(false);
        let asked = Arc::new(AtomicBool::new(false));
        let started = Instant::now();

        let result = serve_bounded(
            &activity,
            Some(scope.path()),
            IdleBound::STANDARD,
            |executor| {
                let asked = Arc::clone(&asked);
                async move {
                    let guard = executor.guard().expect("graceful executor").clone();
                    guard.cancelled().await;
                    asked.store(true, Ordering::SeqCst);
                    // The server finishes the connection by itself.
                    sleep(Duration::from_secs(1)).await;
                    Ok(())
                }
            },
        )
        .await;

        assert!(result.is_ok());
        assert!(
            asked.load(Ordering::SeqCst),
            "the graceful close was requested"
        );
        assert!(started.elapsed() >= Duration::from_secs(30));
        assert!(
            started.elapsed() < Duration::from_secs(34),
            "a connection that closes on request is not held for the grace"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_ignores_the_close_is_dropped_after_the_grace() {
        let activity = ConnectionActivity::default();
        let scope = scope(false);
        let started = Instant::now();

        let result = serve_bounded(&activity, Some(scope.path()), IdleBound::STANDARD, |_| {
            std::future::pending::<Result<(), rama_core::error::BoxError>>()
        })
        .await;

        assert!(result.is_ok());
        assert!(started.elapsed() >= Duration::from_secs(35));
        assert!(started.elapsed() < Duration::from_secs(38));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_in_progress_during_the_grace_is_not_dropped() {
        let activity = Arc::new(ConnectionActivity::default());
        let scope = scope(false);
        let started = Instant::now();

        let bounded = {
            let activity = Arc::clone(&activity);
            let scope = scope.path().to_path_buf();
            tokio::spawn(async move {
                serve_bounded(&activity, Some(&scope), IdleBound::STANDARD, |_| {
                    std::future::pending::<Result<(), rama_core::error::BoxError>>()
                })
                .await
            })
        };

        sleep(Duration::from_secs(32)).await;
        let request = activity.begin();
        sleep(Duration::from_secs(60)).await;
        assert!(!bounded.is_finished(), "the request outlives the grace");

        drop(request);
        sleep(Duration::from_secs(8)).await;
        assert!(bounded.is_finished(), "the grace restarts once it ends");
        assert!(started.elapsed() > Duration::from_secs(95));
    }

    /// A connected loopback pair: the client and the proxy-side stream.
    struct LoopbackPair {
        client: tokio::net::TcpStream,
        server: tokio::net::TcpStream,
    }

    async fn connected() -> LoopbackPair {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let client = tokio::net::TcpStream::connect(listener.local_addr().expect("address"))
            .await
            .expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        LoopbackPair { client, server }
    }

    async fn gone_within(
        server: &tokio::net::TcpStream,
        client: &tokio::net::TcpStream,
        window: Duration,
    ) -> bool {
        tokio::time::timeout(
            window,
            super::peer_gone(server, client.local_addr().expect("client address")),
        )
        .await
        .is_ok()
    }

    #[tokio::test]
    async fn a_half_close_is_not_a_gone_peer_until_the_client_closes_fully() {
        use tokio::io::AsyncWriteExt;

        let LoopbackPair { mut client, server } = connected().await;
        client.shutdown().await.expect("half-close");
        assert!(
            !gone_within(&server, &client, Duration::from_millis(1500)).await,
            "a shutdown(SHUT_WR) keeps waiting for the response"
        );

        let address = client.local_addr().expect("client address");
        drop(client);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), super::peer_gone(&server, address))
                .await
                .is_ok(),
            "a full close after the half-close is noticed"
        );
    }

    #[tokio::test]
    async fn a_full_close_is_a_gone_peer() {
        let LoopbackPair { client, server } = connected().await;
        let address = client.local_addr().expect("client address");
        drop(client);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), super::peer_gone(&server, address))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_reset_is_a_gone_peer() {
        use nix::sys::socket::{setsockopt, sockopt::Linger};

        let LoopbackPair { client, server } = connected().await;
        let address = client.local_addr().expect("client address");
        setsockopt(&client, Linger, &nix::libc::linger {
            l_onoff: 1,
            l_linger: 0,
        })
        .expect("reset on close");
        drop(client);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), super::peer_gone(&server, address))
                .await
                .is_ok()
        );
    }
}
