//! Concurrent downstream connection caps.
//!
//! Every downstream connection (TCP of any protocol, QUIC association) holds
//! a file descriptor, buffers and often an upstream connection for as long as
//! it lives, and the sandbox that opened it decides how long that is: a
//! trickled request body, a stalled response or a request left in progress
//! keeps a connection open indefinitely. Each owner (the cgroup of the
//! process that opened the flow) therefore gets a fixed number of concurrent
//! connections, and connections without an owner share one bucket of the same
//! kind. A connection over the cap is refused, and the refusal is logged at
//! most once per owner per interval.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

/// Concurrent downstream connections one sandbox may hold. Real agents keep
/// tens; a build or a crawler with hundreds of parallel fetches still fits.
pub const MAX_CONNECTIONS_PER_OWNER: u32 = 256;

/// Concurrent downstream connections shared by every flow without an owner.
pub const MAX_UNATTRIBUTED_CONNECTIONS: u32 = 256;

/// Shortest time between two logged refusals for one owner.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// The caps and the live connection counts of one proxy.
#[derive(Debug, Clone)]
pub struct ConnectionLimits {
    per_owner: usize,
    unattributed: usize,
    slots: Arc<Mutex<HashMap<Option<PathBuf>, Slot>>>,
}

#[derive(Debug)]
struct Slot {
    permits: Arc<Semaphore>,
    last_logged: Option<Instant>,
    refused_since_logged: u64,
}

/// One admitted downstream connection; the slot frees when this drops.
#[derive(Debug)]
pub struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

impl ConnectionLimits {
    /// Caps of `per_owner` connections for every owner and `unattributed`
    /// for all flows without one.
    #[must_use]
    pub fn new(per_owner: usize, unattributed: usize) -> Self {
        Self {
            per_owner,
            unattributed,
            slots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Admit one connection of `owner`, or `None` when its cap is reached.
    /// A refusal is logged at most once per owner per interval.
    #[must_use]
    pub fn admit(&self, owner: Option<&Path>) -> Option<ConnectionPermit> {
        let now = Instant::now();
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);

        // A slot is idle once only the table holds its semaphore and its
        // refusal log interval has passed.
        slots.retain(|_, slot| {
            Arc::strong_count(&slot.permits) > 1
                || slot
                    .last_logged
                    .is_some_and(|logged| now.duration_since(logged) < REFUSAL_LOG_INTERVAL)
        });

        let limit = if owner.is_some() {
            self.per_owner
        } else {
            self.unattributed
        };
        let slot = slots
            .entry(owner.map(Path::to_path_buf))
            .or_insert_with(|| Slot {
                permits: Arc::new(Semaphore::new(limit)),
                last_logged: None,
                refused_since_logged: 0,
            });

        if let Ok(permit) = Arc::clone(&slot.permits).try_acquire_owned() {
            return Some(ConnectionPermit { _permit: permit });
        }

        slot.refused_since_logged += 1;
        let due = slot
            .last_logged
            .is_none_or(|logged| now.duration_since(logged) >= REFUSAL_LOG_INTERVAL);
        if due {
            warn!(
                owner = ?owner,
                limit,
                refused = slot.refused_since_logged,
                "refusing downstream connection: the sandbox is at its concurrent connection cap"
            );
            slot.last_logged = Some(now);
            slot.refused_since_logged = 0;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::ConnectionLimits;

    #[test]
    fn an_owner_is_refused_beyond_its_cap_and_regains_slots_when_connections_end() {
        let limits = ConnectionLimits::new(2, 1);
        let owner = Path::new("/sys/fs/cgroup/a.scope");

        let first = limits.admit(Some(owner)).expect("first");
        let _second = limits.admit(Some(owner)).expect("second");
        assert!(limits.admit(Some(owner)).is_none(), "third is over the cap");

        drop(first);
        assert!(
            limits.admit(Some(owner)).is_some(),
            "a freed slot is reusable"
        );
    }

    #[test]
    fn one_owner_at_its_cap_does_not_refuse_another() {
        let limits = ConnectionLimits::new(1, 1);
        let hog = Path::new("/sys/fs/cgroup/hog.scope");
        let other = Path::new("/sys/fs/cgroup/other.scope");

        let _held = limits.admit(Some(hog)).expect("hog");
        assert!(limits.admit(Some(hog)).is_none());
        assert!(limits.admit(Some(other)).is_some());
    }

    #[test]
    fn unattributed_connections_share_one_bucket() {
        let limits = ConnectionLimits::new(5, 2);

        let _one = limits.admit(None).expect("one");
        let _two = limits.admit(None).expect("two");
        assert!(limits.admit(None).is_none(), "the shared bucket is full");
        assert!(
            limits
                .admit(Some(Path::new("/sys/fs/cgroup/a.scope")))
                .is_some(),
            "owned connections do not draw on the shared bucket"
        );
    }
}
