//! Best-effort handoff when systemd stops the daemon.

use std::{sync::Arc, time::Duration};

use tracing::error;

use crate::store::PolicyStore;

/// Write the handoff and return the process exit code, bounded by `timeout`.
///
/// The daemon exits while holding the state lock so no reply can promise state
/// the handoff lacks. A lock that a wedged request never releases must not
/// leave systemd to SIGKILL the daemon with no handoff written at all, so the
/// handoff is best effort: when it fails the caller exits non-zero and the next
/// daemon restores whatever the state file still holds.
pub async fn handoff_or_abort(store: Arc<PolicyStore>, timeout: Duration) -> i32 {
    match tokio::time::timeout(timeout, store.write_handoff()).await {
        Ok(Ok(frozen)) => {
            // Hold the state lock until the process is gone: a reply from here
            // on would describe state the handoff does not carry.
            std::mem::forget(frozen);
            0
        }

        Ok(Err(error)) => {
            error!(%error, "failed to write policyd handoff");
            1
        }

        Err(_) => {
            error!(?timeout, "timed out writing policyd handoff");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use super::handoff_or_abort;
    use crate::store::{PolicyStore, RestartPaths, test_store};

    fn configured_store(dir: &tempfile::TempDir) -> Arc<PolicyStore> {
        let mut store = test_store();

        store.restore_from(RestartPaths {
            state: dir.path().join("state.json"),
            handoff: dir.path().join("handoff.json"),
        });

        Arc::new(store)
    }

    #[tokio::test]
    async fn handoff_exits_zero_once_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = configured_store(&dir);

        assert_eq!(handoff_or_abort(store, Duration::from_secs(5)).await, 0);
        assert!(dir.path().join("handoff.json").is_file());
    }

    /// Regression: a wedged state lock used to leave the daemon running until
    /// systemd killed it, losing the handoff and every session it carried.
    #[tokio::test]
    async fn handoff_times_out_while_the_state_lock_is_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = configured_store(&dir);
        let held = store.inner.lock().await;
        let started = Instant::now();

        assert_eq!(
            handoff_or_abort(store.clone(), Duration::from_millis(100)).await,
            1
        );

        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!dir.path().join("handoff.json").is_file());
        drop(held);
    }
}
