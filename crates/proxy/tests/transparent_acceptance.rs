#![cfg(debug_assertions)]

mod support;

use std::{sync::atomic::Ordering, time::Duration};
use support::{IpVersion, TransparentHarness, loopback};
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};

async fn wait_for_release(harness: &TransparentHarness) {
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
    panic!("proxy did not release flow ownership");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_allow_records_policy_and_upstream() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    let response = harness.request("/allow?raw=query").await;
    wait_for_release(&harness).await;

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"origin-response"));
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.claims.len(), 1);
    assert_eq!(events.checks.len(), 1);
    assert_eq!(events.decisions, [true]);
    assert_eq!(events.releases, [
        agent_sandbox_core::AttributionToken::from_bytes([2; 32])
    ]);
    assert_eq!(
        events.checks[0].url.to_string(),
        format!("http://localhost:{}/allow", harness.origin.address.port())
    );
    assert!(!events.checks[0].url.to_string().contains("raw=query"));
    drop(events);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_deny_does_not_open_upstream() {
    let harness = TransparentHarness::start(loopback(IpVersion::V6), 0).await;

    let response = harness.request("/deny").await;
    wait_for_release(&harness).await;

    assert!(response.starts_with(b"HTTP/1.1 403 Forbidden"));
    assert!(
        response
            .windows(b"blocked by agent-sandbox policy".len())
            .any(|window| { window == b"blocked by agent-sandbox policy" })
    );
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 1);
    assert_eq!(events.decisions, [false]);
    assert_eq!(events.releases, [
        agent_sandbox_core::AttributionToken::from_bytes([2; 32])
    ]);
    drop(events);
}

#[test]
fn transparent_https_deny_does_not_open_upstream() {
    let runtime = tokio::runtime::Runtime::new().expect("create runtime");
    runtime.block_on(async {
        let harness = TransparentHarness::start_tls(loopback(IpVersion::V4)).await;

        let response = harness.tls_request("/deny");
        wait_for_release(&harness).await;

        assert!(
            response
                .windows(b"HTTP/1.1 403 Forbidden".len())
                .any(|window| { window == b"HTTP/1.1 403 Forbidden" })
        );
        assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
        let events = harness.policy_events();
        let events = events.lock().expect("policy events lock");
        assert_eq!(events.decisions, [false]);
        assert_eq!(events.releases, [
            agent_sandbox_core::AttributionToken::from_bytes([2; 32])
        ]);
        drop(events);
    });
}

#[test]
fn transparent_https_allow_reaches_tls_origin() {
    let runtime = tokio::runtime::Runtime::new().expect("create runtime");
    runtime.block_on(async {
        let harness = TransparentHarness::start_tls(loopback(IpVersion::V4)).await;

        let response = harness.tls_request("/allow");
        wait_for_release(&harness).await;

        let status = response.starts_with(b"HTTP/1.0 200") || response.starts_with(b"HTTP/1.1 200");
        assert!(
            status,
            "unexpected HTTPS response: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            response
                .windows(b"<html>".len())
                .any(|window| window.eq_ignore_ascii_case(b"<html>")),
            "TLS origin body is missing"
        );
        let events = harness.policy_events();
        let events = events.lock().expect("policy events lock");
        assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(events.checks.len(), 1);
        assert_eq!(events.decisions, [true]);
        assert_eq!(events.releases, [
            agent_sandbox_core::AttributionToken::from_bytes([2; 32])
        ]);
        drop(events);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_streaming_response_reaches_client() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    let (first, rest) = harness.streaming_request("/stream").await;
    wait_for_release(&harness).await;

    assert!(
        first
            .windows(b"origin-response".len() / 2)
            .any(|window| { window == b"origin-" })
    );
    assert!(
        rest.windows(b"response".len())
            .any(|window| window == b"response")
    );
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_cancellation_resets_upstream_stream() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    harness.abort_streaming_request("/stream-abort").await;
    wait_for_release(&harness).await;

    timeout(Duration::from_secs(2), async {
        while harness.origin.resets.load(Ordering::SeqCst) == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("origin did not observe reset");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_udp_origin_covers_ipv6_datagrams() {
    let harness = TransparentHarness::start(loopback(IpVersion::V6), 0).await;
    let client = UdpSocket::bind((loopback(IpVersion::V6), 0))
        .await
        .expect("bind UDP client");
    client
        .send_to(b"datagram", harness.udp_origin.address)
        .await
        .expect("send UDP datagram");
    let mut response = [0; 64];
    let size = timeout(Duration::from_secs(2), client.recv(&mut response))
        .await
        .expect("UDP origin response timeout")
        .expect("receive UDP datagram");

    assert_eq!(&response[..size], b"datagram");
    assert_eq!(harness.udp_origin.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.udp_origin.received.lock().expect("UDP origin lock")[0],
        b"datagram"
    );
}
