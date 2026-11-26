//! Freeze-aware read-ahead for relayed response bodies.
//!
//! Policyd freezes a sandbox while an approval is pending, and a frozen
//! client stops reading its socket. Relaying one response normally moves a
//! frame upstream-to-downstream only when the downstream wants it, so the
//! proxy stops reading the origin too, and an origin with a send timeout
//! drops a long download or stream that outlasts a long prompt.
//!
//! [`ReadAhead`] sits between the upstream reader (the producer) and the
//! downstream writer (the consumer). Normally the producer reads one item
//! only while the consumer is waiting with nothing queued, which is today's
//! backpressure with no extra buffering. While the owner's cgroup is frozen
//! the producer keeps reading into memory, charged against a byte budget
//! shared by every response in the process. An exhausted budget falls back to
//! backpressure, and the consumer returns budget as it drains the queue after
//! the thaw. Items leave in the order they were read.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, LazyLock, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use rama_core::{bytes::Bytes, error::BoxError};
use rama_http::{
    Body,
    body::{Frame, SizeHint, StreamingBody, util::BodyExt},
};
use tokio::sync::Notify;

use crate::freeze::cgroup_frozen;

/// Bytes of response data that may sit in read-ahead queues process-wide.
///
/// 128 MiB bridges a 60 s origin send timeout for one download at
/// about 17 Mbit/s (more for a shorter prompt), while capping the proxy's
/// extra memory at a small fraction of a typical host. Responses past the
/// budget fall back to backpressure, no worse than without read-ahead.
pub const READ_AHEAD_BUDGET_BYTES: usize = 128 * 1024 * 1024;

/// Interval at which an idle producer re-checks the owner's freezer state.
const FREEZE_POLL: Duration = Duration::from_millis(250);

/// Process-wide byte budget for read-ahead queues.
///
/// A producer checks for room before each read and charges what it read
/// afterwards, so the total can exceed the limit by one item per producer
/// that read concurrently.
#[derive(Debug)]
pub struct ByteBudget {
    limit: usize,
    used: AtomicUsize,
}

impl ByteBudget {
    /// A budget of `limit` bytes with nothing charged.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    /// Bytes currently held in queues.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    fn has_room(&self) -> bool {
        self.used() < self.limit
    }

    fn charge(&self, bytes: usize) {
        self.used.fetch_add(bytes, Ordering::Relaxed);
    }

    fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::Relaxed);
    }
}

static PROCESS_BUDGET: LazyLock<Arc<ByteBudget>> =
    LazyLock::new(|| Arc::new(ByteBudget::new(READ_AHEAD_BUDGET_BYTES)));

/// The budget shared by every response in this process.
#[must_use]
pub fn process_budget() -> Arc<ByteBudget> {
    Arc::clone(&PROCESS_BUDGET)
}

#[derive(PartialEq, Eq)]
enum Demand {
    Closed,
    Waiting,
    Idle,
}

struct Queued<T> {
    item: T,
    bytes: usize,
}

struct State<T> {
    items: VecDeque<Queued<T>>,
    held: usize,
    finished: bool,
    closed: bool,
    waiting: bool,
    consumer: Option<Waker>,
}

/// An ordered queue between one producer and one consumer, filled ahead of
/// demand only while the owner's cgroup is frozen.
pub struct ReadAhead<T> {
    owner_cgroup: Option<PathBuf>,
    budget: Arc<ByteBudget>,
    state: Mutex<State<T>>,
    producer: Notify,
    closed: Notify,
}

impl<T: Send> ReadAhead<T> {
    /// An empty queue charging `budget`. Without an owner cgroup the producer
    /// only ever reads on demand.
    #[must_use]
    pub fn new(owner_cgroup: Option<PathBuf>, budget: Arc<ByteBudget>) -> Self {
        Self {
            owner_cgroup,
            budget,
            state: Mutex::new(State {
                items: VecDeque::new(),
                held: 0,
                finished: false,
                closed: false,
                waiting: false,
                consumer: None,
            }),
            producer: Notify::new(),
            closed: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Producer side: wait until one more item may be read. That is the case
    /// while the consumer waits with nothing queued, or while the owner is
    /// frozen and the budget has room. Returns `false` once the consumer is
    /// gone.
    pub async fn permit(&self) -> bool {
        loop {
            let demand = self.demand();
            if demand == Demand::Closed {
                return false;
            }

            if demand == Demand::Waiting
                || (self.budget.has_room()
                    && self.owner_cgroup.as_deref().is_some_and(cgroup_frozen))
            {
                return true;
            }

            tokio::select! {
                () = self.producer.notified() => {}
                () = tokio::time::sleep(FREEZE_POLL) => {}
            }
        }
    }

    /// The consumer's state, read under the lock so no guard outlives it.
    fn demand(&self) -> Demand {
        let state = self.lock();
        if state.closed {
            Demand::Closed
        } else if state.waiting && state.items.is_empty() {
            Demand::Waiting
        } else {
            Demand::Idle
        }
    }

    /// Producer side: queue one item of `bytes` bytes, charged to the budget
    /// until the consumer takes it.
    pub fn push(&self, item: T, bytes: usize) {
        let mut state = self.lock();
        if state.closed {
            return;
        }
        self.budget.charge(bytes);
        state.held += bytes;
        state.items.push_back(Queued { item, bytes });
        let consumer = state.consumer.take();
        drop(state);

        if let Some(consumer) = consumer {
            consumer.wake();
        }
    }

    /// Producer side: no further items will be pushed.
    pub fn finish(&self) {
        let mut state = self.lock();
        state.finished = true;
        let consumer = state.consumer.take();
        drop(state);

        if let Some(consumer) = consumer {
            consumer.wake();
        }
    }

    /// Producer side: resolves once the consumer closed the queue.
    pub async fn closed(&self) {
        loop {
            if self.lock().closed {
                return;
            }
            self.closed.notified().await;
        }
    }

    /// Consumer side: the next item in read order, `None` once the producer
    /// finished and the queue drained. Registers the caller as waiting, which
    /// lets the producer read one item.
    pub fn poll_next(&self, context: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = self.lock();

        if let Some(queued) = state.items.pop_front() {
            state.held -= queued.bytes;
            state.waiting = false;
            drop(state);
            self.budget.release(queued.bytes);
            return Poll::Ready(Some(queued.item));
        }

        if state.finished {
            return Poll::Ready(None);
        }

        state.waiting = true;
        state.consumer = Some(context.waker().clone());
        drop(state);
        self.producer.notify_one();
        Poll::Pending
    }

    /// Consumer side: drop everything queued, return its budget and stop the
    /// producer.
    pub fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.items.clear();
        let held = std::mem::take(&mut state.held);
        drop(state);

        self.budget.release(held);
        self.producer.notify_one();
        self.closed.notify_one();
    }
}

type BodyItem = Result<Frame<Bytes>, BoxError>;

/// A response body whose upstream frames are read ahead while the owner's
/// cgroup is frozen. Frames, trailers, errors and the end of the stream reach
/// the reader in the order the upstream produced them.
pub struct ReadAheadBody {
    queue: Arc<ReadAhead<BodyItem>>,
    lower: u64,
    upper: Option<u64>,
    delivered: u64,
    done: bool,
}

impl ReadAheadBody {
    /// Take over `inner`, reading it on a task that obeys the read-ahead
    /// rules for `owner_cgroup`.
    pub fn new(inner: Body, owner_cgroup: PathBuf, budget: Arc<ByteBudget>) -> Self {
        let hint = inner.size_hint();
        let queue = Arc::new(ReadAhead::new(Some(owner_cgroup), budget));
        tokio::spawn(pump_body(inner, Arc::clone(&queue)));

        Self {
            queue,
            lower: hint.lower(),
            upper: hint.upper(),
            delivered: 0,
            done: false,
        }
    }
}

async fn pump_body(mut inner: Body, queue: Arc<ReadAhead<BodyItem>>) {
    while queue.permit().await {
        let frame = tokio::select! {
            () = queue.closed() => return,
            frame = inner.frame() => frame,
        };

        match frame {
            Some(Ok(frame)) => {
                let bytes = frame.data_ref().map_or(0, Bytes::len);
                queue.push(Ok(frame), bytes);
            }
            Some(Err(error)) => {
                queue.push(Err(error), 0);
                break;
            }
            None => break,
        }
    }

    queue.finish();
}

impl StreamingBody for ReadAheadBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }

        match self.queue.poll_next(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                self.delivered += frame.data_ref().map_or(0, |data| data.len() as u64);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        hint.set_lower(self.lower.saturating_sub(self.delivered));
        if let Some(upper) = self.upper {
            hint.set_upper(upper.saturating_sub(self.delivered));
        }
        hint
    }
}

impl Drop for ReadAheadBody {
    fn drop(&mut self) {
        self.queue.close();
    }
}

/// Wrap `body` for read-ahead while `owner_cgroup` is frozen. A body that is
/// already at its end, or a flow without an owner cgroup, is returned as is.
/// Must run inside a tokio runtime when it wraps.
pub fn read_ahead_body(body: Body, owner_cgroup: Option<&Path>) -> Body {
    match owner_cgroup {
        Some(cgroup) if !body.is_end_stream() => Body::new(ReadAheadBody::new(
            body,
            cgroup.to_path_buf(),
            process_budget(),
        )),
        _ => body,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rama_core::{bytes::Bytes, error::BoxError};
    use rama_http::{
        Body, HeaderMap, HeaderValue,
        body::{Frame, StreamingBody, util::BodyExt},
    };
    use tokio::{
        sync::mpsc::{UnboundedSender, unbounded_channel},
        time::{Duration, sleep},
    };

    use super::{ByteBudget, ReadAheadBody};

    struct ChannelBody(tokio::sync::mpsc::UnboundedReceiver<Result<Frame<Bytes>, BoxError>>);

    impl StreamingBody for ChannelBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.0.poll_recv(context)
        }
    }

    struct Fixture {
        cgroup: tempfile::TempDir,
        budget: Arc<ByteBudget>,
        upstream: UnboundedSender<Result<Frame<Bytes>, BoxError>>,
        body: ReadAheadBody,
    }

    impl Fixture {
        fn new(limit: usize, frozen: bool) -> Self {
            let cgroup = tempfile::tempdir().expect("cgroup dir");
            let budget = Arc::new(ByteBudget::new(limit));
            let (upstream, receiver) = unbounded_channel();
            let body = ReadAheadBody::new(
                Body::new(ChannelBody(receiver)),
                cgroup.path().to_path_buf(),
                Arc::clone(&budget),
            );
            let fixture = Self {
                cgroup,
                budget,
                upstream,
                body,
            };
            fixture.set_frozen(frozen);
            fixture
        }

        fn set_frozen(&self, frozen: bool) {
            std::fs::write(
                self.cgroup.path().join("cgroup.freeze"),
                if frozen { "1\n" } else { "0\n" },
            )
            .expect("write freeze state");
        }

        fn send_data(&self, data: &'static str) {
            self.upstream
                .send(Ok(Frame::data(Bytes::from_static(data.as_bytes()))))
                .expect("upstream open");
        }

        /// Let the producer task run through many freezer polls.
        async fn settle() {
            sleep(Duration::from_secs(2)).await;
        }

        async fn next(&mut self) -> String {
            match self.body.frame().await {
                None => "end".to_owned(),
                Some(Err(error)) => format!("error:{error}"),
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => format!("data:{}", String::from_utf8_lossy(&data)),
                    Err(frame) => {
                        let trailers = frame.into_trailers().expect("trailers frame");
                        format!("trailers:{}", trailers["x-sum"].to_str().expect("ascii"))
                    }
                },
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reads_upstream_only_on_demand_until_frozen() {
        let mut fixture = Fixture::new(1024, false);
        fixture.send_data("aaaa");
        fixture.send_data("bbbb");
        fixture.send_data("cccc");

        Fixture::settle().await;
        assert_eq!(
            fixture.budget.used(),
            0,
            "a running owner keeps today's backpressure"
        );

        assert_eq!(fixture.next().await, "data:aaaa");
        Fixture::settle().await;
        assert_eq!(fixture.budget.used(), 0, "one read per demand");

        fixture.set_frozen(true);
        Fixture::settle().await;
        assert_eq!(fixture.budget.used(), 8, "a frozen owner reads ahead");

        assert_eq!(fixture.next().await, "data:bbbb");
        assert_eq!(fixture.next().await, "data:cccc");
        assert_eq!(fixture.budget.used(), 0, "draining returns the budget");

        let Fixture {
            upstream, mut body, ..
        } = fixture;
        drop(upstream);
        assert!(body.frame().await.is_none());
        assert!(body.is_end_stream());
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_budget_falls_back_and_order_is_preserved() {
        let mut fixture = Fixture::new(10, true);
        for chunk in ["0000", "1111", "2222", "3333", "4444"] {
            fixture.send_data(chunk);
        }
        let mut trailers = HeaderMap::new();
        trailers.insert("x-sum", HeaderValue::from_static("done"));
        fixture
            .upstream
            .send(Ok(Frame::trailers(trailers)))
            .expect("upstream open");
        fixture
            .upstream
            .send(Err(BoxError::from("upstream reset")))
            .expect("upstream open");

        Fixture::settle().await;
        assert_eq!(
            fixture.budget.used(),
            12,
            "reads stop once the budget has no room; the last read may overshoot by one frame"
        );

        let mut seen = Vec::new();
        loop {
            let item = fixture.next().await;
            let last = item == "end";
            seen.push(item);
            if last {
                break;
            }
        }

        assert_eq!(seen, [
            "data:0000",
            "data:1111",
            "data:2222",
            "data:3333",
            "data:4444",
            "trailers:done",
            "error:upstream reset",
            "end",
        ]);
        assert_eq!(fixture.budget.used(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_body_returns_its_budget_and_stops_the_reader() {
        let fixture = Fixture::new(1024, true);
        fixture.send_data("aaaa");
        Fixture::settle().await;
        assert_eq!(fixture.budget.used(), 4);

        let Fixture {
            budget,
            upstream,
            body,
            ..
        } = fixture;
        drop(body);
        assert_eq!(budget.used(), 0);

        Fixture::settle().await;
        assert!(
            upstream.is_closed(),
            "the reader task drops the upstream body"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn size_hint_counts_down_with_delivered_bytes() {
        let cgroup = tempfile::tempdir().expect("cgroup dir");
        let mut body = ReadAheadBody::new(
            Body::from("abcd"),
            cgroup.path().to_path_buf(),
            Arc::new(ByteBudget::new(1024)),
        );
        assert_eq!(body.size_hint().exact(), Some(4));

        let frame = body.frame().await.expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data").len(), 4);
        assert_eq!(body.size_hint().exact(), Some(0));
    }
}
