//! Freezer state of a flow owner's cgroup.
//!
//! Policyd freezes the whole sandbox while an approval is pending. Frozen
//! processes run no userspace code, so a deadline that waits on the client
//! must not count the time the owner spends frozen.

use std::{path::Path, time::Duration};

/// Whether a freeze is requested on the cgroup or an ancestor.
///
/// The request (`cgroup.freeze`) decides, not the `frozen` state in
/// `cgroup.events`: the kernel reports that only once every task stopped, and
/// a task waiting on a seccomp notification its frozen broker already
/// received never does. A cgroup that is gone or unreadable counts as
/// running.
#[must_use]
pub fn cgroup_frozen(cgroup: &Path) -> bool {
    cgroup.ancestors().any(|dir| {
        std::fs::read_to_string(dir.join("cgroup.freeze")).is_ok_and(|freeze| freeze.trim() == "1")
    })
}

/// Interval at which [`wait_unfrozen`] re-reads the freezer state; the budget
/// accounts for frozen time to this granularity, which keeps a short `poll`
/// from reading cgroup files on every tick.
const FREEZE_RECHECK: Duration = Duration::from_millis(100);

/// Poll `ready` every `poll` until it holds or `budget` runs out.
///
/// The budget counts only unfrozen time: time the owner's cgroup spends frozen
/// does not count; `None` counts every interval. Returns whether `ready`
/// held.
pub async fn wait_unfrozen(
    owner_cgroup: Option<&Path>,
    budget: Duration,
    poll: Duration,
    mut ready: impl FnMut() -> bool,
) -> bool {
    let mut unfrozen = Duration::ZERO;
    let mut frozen = false;
    let mut since_check = FREEZE_RECHECK;
    loop {
        if ready() {
            return true;
        }
        if unfrozen >= budget {
            return false;
        }
        tokio::time::sleep(poll).await;
        since_check += poll;
        if since_check >= FREEZE_RECHECK {
            frozen = owner_cgroup.is_some_and(cgroup_frozen);
            since_check = Duration::ZERO;
        }
        if !frozen {
            unfrozen += poll;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use super::{cgroup_frozen, wait_unfrozen};

    const POLL: Duration = Duration::from_millis(5);
    const BUDGET: Duration = Duration::from_millis(50);

    #[tokio::test]
    async fn budget_runs_out_when_the_owner_is_running() {
        assert!(!wait_unfrozen(None, BUDGET, POLL, || false).await);
    }

    #[tokio::test]
    async fn frozen_time_does_not_spend_the_budget() {
        let scope = tempfile::tempdir().expect("scope dir");
        let freeze = scope.path().join("cgroup.freeze");
        std::fs::write(&freeze, "1\n").expect("freeze requested");
        let ready = Arc::new(AtomicBool::new(false));
        let thaw = {
            let ready = Arc::clone(&ready);
            tokio::spawn(async move {
                // Longer than the budget: only unfrozen time may count.
                tokio::time::sleep(BUDGET * 6).await;
                std::fs::write(&freeze, "0\n").expect("thaw");
                ready.store(true, Ordering::SeqCst);
            })
        };
        let held = wait_unfrozen(Some(scope.path()), BUDGET, POLL, || {
            ready.load(Ordering::SeqCst)
        })
        .await;
        thaw.await.expect("thaw task");
        assert!(held, "a freeze longer than the budget must not time out");
    }

    #[test]
    fn freeze_request_on_cgroup_or_ancestor_counts_as_frozen() {
        let root = tempfile::tempdir().expect("tempdir");
        let child = root.path().join("scope");
        std::fs::create_dir(&child).expect("child dir");
        std::fs::write(child.join("cgroup.freeze"), "0\n").expect("child freeze");
        assert!(!cgroup_frozen(&child));

        std::fs::write(root.path().join("cgroup.freeze"), "1\n").expect("ancestor freeze");
        assert!(cgroup_frozen(&child), "ancestor freeze covers the child");

        std::fs::write(child.join("cgroup.freeze"), "1\n").expect("child freeze");
        std::fs::write(root.path().join("cgroup.freeze"), "0\n").expect("ancestor thaw");
        assert!(cgroup_frozen(&child));
    }

    #[test]
    fn missing_cgroup_counts_as_running() {
        let root = tempfile::tempdir().expect("tempdir");
        assert!(!cgroup_frozen(&root.path().join("gone")));
    }
}
