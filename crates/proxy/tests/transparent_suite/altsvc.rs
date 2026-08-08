//! Alt-Svc scenarios: preservation, attribution, filtering, and clearing.

use crate::support::{IpVersion, TransparentHarness, loopback};

use std::time::Duration;
use tokio::time::sleep;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_alt_svc_preserved_and_attributed() {
    let harness = TransparentHarness::start_http3_with_alt(loopback(IpVersion::V4)).await;
    let alt_address = harness.h3_alt_address.expect("alternative endpoint");
    let origin_port = harness.h3_origin().address.port();

    // The origin advertises the alternative; the proxy preserves it because
    // transparent UDP interception covers its port.
    let response = harness
        .http3_request("/allow")
        .await
        .expect("main endpoint request");

    assert_eq!(response.status(), 200);

    let alt_svc = response
        .headers()
        .get("alt-svc")
        .expect("preserved alt-svc header")
        .to_str()
        .expect("alt-svc value");

    assert!(
        alt_svc.contains(&format!("h3=\":{}\"", alt_address.port())),
        "unexpected alt-svc: {alt_svc}"
    );

    assert_eq!(response.body().await, b"origin-response\n");

    // A later QUIC association at the alternative endpoint is attributed to
    // the original origin: the policy check and the upstream both use the
    // origin, not the alternative transport.
    let response = harness
        .http3_request_to(alt_address, "/allow")
        .await
        .expect("alternative endpoint request");

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"origin-response\n");

    // The main and alternative associations each claim and release their
    // own flow, so wait until both releases are recorded before pairing
    // each one with its claim.
    for _ in 0..100 {
        let released = harness
            .policy_events()
            .lock()
            .expect("policy events lock")
            .releases
            .len();

        if released == 2 {
            break;
        }

        sleep(Duration::from_millis(10)).await;
    }

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 2);

    assert_eq!(
        events.checks[1].url.to_string(),
        format!("https://localhost:{origin_port}/allow"),
        "alternative endpoint must keep the original origin identity"
    );

    assert_eq!(events.claims.len(), 2);
    assert_eq!(events.releases.len(), 2);

    for release in &events.releases {
        assert_eq!(
            release.token,
            agent_sandbox_core::AttributionToken::from_bytes([2; 32])
        );

        assert!(
            events
                .claims
                .iter()
                .any(|claim| claim.connection_id == release.connection_id),
            "each release must pair with its claim"
        );
    }

    drop(events);
    assert_eq!(harness.h3_origin().attempts(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_alt_endpoint_without_mapping_is_refused() {
    let harness = TransparentHarness::start_http3_with_alt(loopback(IpVersion::V4)).await;
    let alt_address = harness.h3_alt_address.expect("alternative endpoint");
    let result = harness.http3_request_to(alt_address, "/allow").await;

    assert!(
        result.is_err(),
        "an alternative endpoint without a recorded mapping must be refused"
    );

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");

    assert!(
        events.claims.is_empty(),
        "refused alternative endpoint must not be claimed"
    );

    assert!(events.releases.is_empty());
    assert!(events.checks.is_empty());
    drop(events);
    assert_eq!(harness.h3_origin().attempts(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_unvalidated_alt_svc_is_filtered() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    let response = harness
        .http3_request("/alt-svc-filtered")
        .await
        .expect("filtered alt-svc request");

    assert_eq!(response.status(), 200);

    assert!(
        !response.headers().contains_key("alt-svc"),
        "an alternative on an unintercepted port must be filtered"
    );

    assert_eq!(response.body().await, b"origin-response\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_alt_svc_clear_removes_mapping() {
    let harness = TransparentHarness::start_http3_with_alt(loopback(IpVersion::V4)).await;
    let alt_address = harness.h3_alt_address.expect("alternative endpoint");

    harness
        .http3_request("/allow")
        .await
        .expect("main endpoint request");

    assert!(
        harness
            .http3_request_to(alt_address, "/allow")
            .await
            .is_ok(),
        "mapped alternative endpoint must be served"
    );

    let response = harness
        .http3_request("/alt-svc-clear")
        .await
        .expect("clear request");

    assert_eq!(
        response
            .headers()
            .get("alt-svc")
            .and_then(|value| value.to_str().ok()),
        Some("clear"),
        "clear must pass through to the client"
    );

    assert!(
        harness
            .http3_request_to(alt_address, "/allow")
            .await
            .is_err(),
        "cleared mappings must not serve later alternative associations"
    );
}
