//! Idle bound for downstream HTTP connections.
//!
//! Downstream peers are sandbox processes that policyd freezes while an
//! approval is pending. A wall-clock header read timeout would close the
//! keep-alive connection of a client frozen past it, so the HTTP server runs
//! without one. This bound replaces it: a connection that waits for a request
//! head, idle between requests or part-way through a head, for
//! [`IDLE_BUDGET`] of the owner's unfrozen time is closed. Time with a
//! request in progress, from the service call until its response body is
//! dropped, does not count, and neither does time the owner is frozen.
//! A connection that upgraded (WebSocket) is no longer an HTTP connection and
//! is never closed by this bound.

use std::{
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use rama_core::{bytes::Bytes, error::BoxError};
use rama_http::{
    Body, Response,
    body::{Frame, SizeHint, StreamingBody},
};

use super::is_websocket_upgrade_response;
use crate::freeze::cgroup_frozen;

/// Unfrozen time a connection may wait for a request head.
pub const IDLE_BUDGET: Duration = Duration::from_secs(30);

/// Interval at which the owner's freezer state and the connection's activity
/// are sampled.
const IDLE_POLL: Duration = Duration::from_secs(1);

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

    /// [`Self::expired`] with the production budget and sampling interval.
    pub async fn idle_expired(&self, owner_cgroup: Option<&Path>) {
        self.expired(owner_cgroup, IDLE_BUDGET, IDLE_POLL).await;
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
    use std::{path::Path, sync::Arc, time::Duration};

    use rama_core::extensions::ExtensionsRef as _;
    use rama_http::{Body, Response, StatusCode, body::util::BodyExt, io::upgrade::pending};
    use tokio::{task::JoinHandle, time::sleep};

    use super::ConnectionActivity;

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
}
