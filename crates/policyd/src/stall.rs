//! Liveness watchdog for the one state lock every request needs.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::warn;

use crate::store::PolicyStore;

const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const STALL_THRESHOLD: Duration = Duration::from_secs(3);
const REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Decides when a held state lock is worth a log line: unavailable for longer
/// than [`STALL_THRESHOLD`] and not reported within [`REPORT_INTERVAL`].
#[derive(Default)]
struct StallTracker {
    held_since: Option<Instant>,
    reported_at: Option<Instant>,
}

impl StallTracker {
    fn observe(&mut self, now: Instant, available: bool) -> Option<Duration> {
        if available {
            *self = Self::default();
            return None;
        }

        let since = *self.held_since.get_or_insert(now);
        let held = now.duration_since(since);

        if held < STALL_THRESHOLD
            || self
                .reported_at
                .is_some_and(|at| now.duration_since(at) < REPORT_INTERVAL)
        {
            return None;
        }

        self.reported_at = Some(now);
        Some(held)
    }
}

/// Warn while [`PolicyStore`]'s state lock stays unavailable, so a daemon that
/// stops answering requests names the lock instead of going silent. Thread
/// count rides along because a runtime that keeps replacing workers blocked in
/// `block_in_place` shows up there and nowhere else.
pub async fn watch_state_lock(store: Arc<PolicyStore>) {
    let mut tracker = StallTracker::default();

    loop {
        tokio::time::sleep(PROBE_INTERVAL).await;

        let available = store.inner.try_lock().is_ok();

        if let Some(held) = tracker.observe(Instant::now(), available) {
            warn!(
                held_secs = held.as_secs(),
                threads = std::fs::read_dir("/proc/self/task").map_or(0, |dir| dir.count()),
                "policyd state lock unavailable; requests cannot be dispatched"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::StallTracker;

    #[test]
    fn reports_only_a_stall_that_outlives_the_threshold_and_report_gap() {
        let base = Instant::now();
        let at = |secs: u64| base + Duration::from_secs(secs);
        let mut tracker = StallTracker::default();

        assert_eq!(tracker.observe(at(1), false), None, "below the threshold");
        assert_eq!(
            tracker.observe(at(4), false),
            Some(Duration::from_secs(3)),
            "a stall is reported once"
        );
        assert_eq!(
            tracker.observe(at(5), false),
            None,
            "no repeat inside the report interval"
        );
        assert_eq!(
            tracker.observe(at(15), false),
            Some(Duration::from_secs(14)),
            "a stalled lock is reported again after the interval"
        );

        assert_eq!(tracker.observe(at(16), true), None, "released");
        assert_eq!(
            tracker.observe(at(17), false),
            None,
            "a fresh stall restarts the threshold"
        );
    }
}
