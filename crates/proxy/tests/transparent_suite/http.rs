//! TCP relay and cleartext HTTP scenarios: allow/deny, HTTP/1.0, pooling,
//! policy and claim errors, and cancellation.

use crate::{
    support::{IpVersion, TransparentHarness, loopback},
    transparent_common::{assert_release_matches_claim, wait_for_release},
};

use nix::{
    libc,
    sys::socket::{setsockopt, sockopt::Linger},
};

use std::{os::fd::AsFd, sync::atomic::Ordering, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

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
    assert_release_matches_claim(&events);

    assert_eq!(
        events.checks[0].url.to_string(),
        format!("http://localhost:{}/allow", harness.origin.address.port())
    );

    assert!(!events.checks[0].url.to_string().contains("raw=query"));
    drop(events);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http10_hostless_request_reaches_origin() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let response = harness.http10_request("/allow").await;
    wait_for_release(&harness).await;
    assert!(response.starts_with(b"HTTP/1.0 200 OK"));

    assert!(
        !response
            .windows(b"transfer-encoding".len())
            .any(|window| { window.eq_ignore_ascii_case(b"transfer-encoding") })
    );

    assert!(response.ends_with(b"origin-response"));
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");

    assert_eq!(
        events.checks[0].url.to_string(),
        format!("http://127.0.0.1:{}/allow", harness.origin.address.port())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http10_origin_controls_upstream_version() {
    let harness = TransparentHarness::start_with_http10_origin(loopback(IpVersion::V4), 0).await;
    let response = harness.request("/allow").await;
    wait_for_release(&harness).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"origin-response"));
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);

    let heads = harness
        .origin
        .request_heads
        .lock()
        .expect("request heads lock");

    let head = heads[0].clone();
    drop(heads);

    assert!(
        head.starts_with("GET /allow HTTP/1.0"),
        "unexpected upstream request head: {head}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_reuses_same_origin_pool() {
    let harness = TransparentHarness::start_keep_alive(loopback(IpVersion::V4), 0).await;
    let (first, second) = harness.pooled_requests().await;
    wait_for_release(&harness).await;
    assert!(first.ends_with(b"origin-response"));
    assert!(second.ends_with(b"origin-response"));
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_conflicting_authorities_are_rejected() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "GET http://127.0.0.1:{}/allow HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        harness.origin.address.port(),
        harness.origin.address.port()
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("write conflicting request");

    let mut response = Vec::new();

    stream
        .read_to_end(&mut response)
        .await
        .expect("read conflicting response");

    wait_for_release(&harness).await;
    assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway"));
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_cleartext_http2_prior_knowledge_is_rejected() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("write HTTP/2 preface");

    let mut response = [0; 64];
    let _ = timeout(Duration::from_secs(2), stream.read(&mut response)).await;
    wait_for_release(&harness).await;
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
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
    assert_release_matches_claim(&events);
    drop(events);
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
async fn transparent_http_cancellation_releases_pending_check_and_claim() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "GET /cancel HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        harness.origin.address.port()
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("write client request");

    timeout(Duration::from_secs(2), async {
        while harness
            .policy_events()
            .lock()
            .expect("policy events lock")
            .checks
            .is_empty()
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("policy check never reached the fake policy");

    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };

    setsockopt(&stream.as_fd(), Linger, &linger).expect("set reset linger");
    drop(stream);

    timeout(Duration::from_secs(2), async {
        while harness
            .policy_events()
            .lock()
            .expect("policy events lock")
            .cancellations
            .is_empty()
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy never cancelled the dropped policy check");

    wait_for_release(&harness).await;
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 1);
    assert_eq!(events.cancellations.len(), 1);
    assert_release_matches_claim(&events);
    drop(events);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_policy_error_fails_closed_without_upstream() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let response = harness.request("/policy-error").await;
    wait_for_release(&harness).await;

    assert!(
        response.starts_with(b"HTTP/1.1 502"),
        "unexpected response: {}",
        String::from_utf8_lossy(&response)
    );

    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 1);
    assert_release_matches_claim(&events);
    drop(events);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_claim_error_closes_connection_without_upstream() {
    let harness = TransparentHarness::start_claim_error(loopback(IpVersion::V4), 0).await;

    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "GET /allow HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        harness.origin.address.port()
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("write client request");

    let mut buffer = [0; 64];
    let read = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;

    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "connection must close after a failed claim, got {read:?}"
    );

    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.claims.len(), 1);

    assert!(
        events.releases.is_empty(),
        "a failed claim must not be released"
    );

    drop(events);
}
