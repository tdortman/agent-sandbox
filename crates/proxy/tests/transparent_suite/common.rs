//! Helpers shared by the transparent acceptance scenario families.

use std::time::Duration;

use tokio::time::sleep;

use crate::support::TransparentHarness;

/// Assert the single observed release matches the claimed connection
/// identity and the fixed fake-policy token.
pub fn assert_release_matches_claim(events: &crate::support::PolicyEvents) {
    assert_eq!(events.releases.len(), 1);

    assert_eq!(
        events.releases[0].token,
        agent_sandbox_core::AttributionToken::from_bytes([2; 32])
    );

    assert_eq!(
        events.releases[0].connection_id,
        events.claims[0].connection_id
    );
}

pub async fn wait_for_release(harness: &TransparentHarness) {
    for _ in 0..100 {
        let released = !harness
            .policy_events()
            .lock()
            .expect("policy events lock")
            .releases
            .is_empty();

        if released {
            return;
        }

        sleep(Duration::from_millis(10)).await;
    }

    panic!(
        "proxy did not release flow ownership\nproxy log:\n{}",
        std::fs::read_to_string(&harness.proxy_log).unwrap_or_default()
    );
}
