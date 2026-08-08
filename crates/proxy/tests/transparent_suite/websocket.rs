//! WebSocket upgrade scenarios over HTTP/1.1 and HTTP/3.

use crate::support::{Http3Client, IpVersion, TransparentHarness, loopback};
use crate::transparent_common::wait_for_release;
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_websocket_upgrade_reaches_origin() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let response = harness.websocket_request().await;
    wait_for_release(&harness).await;
    assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols"));
    assert!(response.ends_with(b"ping"));
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_websocket_reaches_upstream() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());

    let body = match client
        .websocket_probe(harness.proxy_address, "localhost", "/allow")
        .await
    {
        Ok(body) => body,
        Err(error) => panic!(
            "{error}\nproxy log:\n{}\norigin log:\n{}",
            std::fs::read_to_string(&harness.proxy_log).unwrap_or_default(),
            std::fs::read_to_string(harness.h3_origin().log_path()).unwrap_or_default()
        ),
    };

    assert_eq!(body, b"websocket-response\n");
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
    assert_eq!(harness.h3_origin().request_heads()[0], "CONNECT /allow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_websocket_upstream_missing_settings_fails_closed() {
    let harness = TransparentHarness::start_http3_rejecting_sessions(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());

    let result = client
        .websocket_probe(harness.proxy_address, "localhost", "/allow")
        .await;

    assert!(result.is_err());
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 0);
}
