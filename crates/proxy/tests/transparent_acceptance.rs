#![cfg(debug_assertions)]

mod support;
use nix::{
    libc,
    sys::socket::{setsockopt, sockopt::Linger},
};
use rama_core::{Service, extensions::ExtensionsRef, rt::Executor};
use rama_http::{Body, Request, StatusCode, Version, body::util::BodyExt, conn::TargetHttpVersion};
use rama_http_backend::client::HttpConnector;
use rama_net::{
    address::{Host, HostWithPort},
    client::{ConnectorService, ConnectorTarget, EstablishedClientConnection},
};
use rama_tcp::client::service::TcpConnector;
use rama_tls::client::{ServerVerifyMode, TlsClientConfig};
use rama_tls_boring::client::TlsConnector;
use std::{os::fd::AsFd, sync::atomic::Ordering, time::Duration};
use support::{IpVersion, TransparentHarness, loopback};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

/// Assert the single observed release matches the claimed connection
/// identity and the fixed fake-policy token.
fn assert_release_matches_claim(events: &support::PolicyEvents) {
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
async fn transparent_http_websocket_upgrade_reaches_origin() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let response = harness.websocket_request().await;
    wait_for_release(&harness).await;

    assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols"));
    assert!(response.ends_with(b"ping"));
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
        assert_release_matches_claim(&events);
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
        assert_release_matches_claim(&events);
        drop(events);
    });
}

#[test]
fn transparent_https_http10_hostless_request_uses_sni_authority() {
    let runtime = tokio::runtime::Runtime::new().expect("create runtime");

    runtime.block_on(async {
        let harness = TransparentHarness::start_tls(loopback(IpVersion::V4)).await;

        let response = harness.tls_http10_request("/allow");
        wait_for_release(&harness).await;

        assert!(
            response
                .windows(b"HTTP/1.0 200".len())
                .any(|window| window.eq_ignore_ascii_case(b"HTTP/1.0 200")),
            "unexpected HTTPS response: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);

        let events = harness.policy_events();
        let events = events.lock().expect("policy events lock");
        assert_eq!(
            events.checks[0].url.to_string(),
            format!("https://localhost:{}/allow", harness.origin.address.port())
        );
        drop(events);
    });
}

#[test]
fn transparent_https_conflicting_sni_and_host_are_rejected() {
    let runtime = tokio::runtime::Runtime::new().expect("create runtime");

    runtime.block_on(async {
        let harness = TransparentHarness::start_tls(loopback(IpVersion::V4)).await;

        let request = format!(
            "GET /allow HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            harness.origin.address.port()
        );

        let response = harness.tls_raw_request(&request, Some("localhost"));
        wait_for_release(&harness).await;

        assert!(
            response
                .windows(b"502".len())
                .any(|window| window == b"502"),
            "unexpected HTTPS response: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http2_downstream_falls_back_to_http11_upstream() {
    let harness = TransparentHarness::start_tls(loopback(IpVersion::V4)).await;
    let origin = format!("https://localhost:{}/allow", harness.origin.address.port());
    let proxy_target = ConnectorTarget(HostWithPort::new(
        Host::from(harness.proxy_address.ip()),
        harness.proxy_address.port(),
    ));

    let connector = TlsConnector::secure(TcpConnector::default()).with_base_config(
        TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
    );
    let connector = rama_http::layer::version_adapter::RequestVersionAdapter::new(connector)
        .with_default_version(Version::HTTP_11);
    let client = HttpConnector::new(connector, Executor::default());

    let request = Request::builder()
        .method("GET")
        .uri(origin)
        .version(Version::HTTP_2)
        .body(Body::empty())
        .expect("build HTTP/2 request");
    request.extensions().insert(proxy_target);
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));

    let connection = timeout(Duration::from_secs(5), client.connect(request))
        .await
        .expect("connect through proxy timed out")
        .expect("connect through proxy");
    let EstablishedClientConnection { input, conn } = connection;
    let response = timeout(Duration::from_secs(5), conn.serve(input))
        .await
        .expect("send HTTP/2 request timed out")
        .expect("send HTTP/2 request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "origin attempts: {}",
        harness.origin.attempts.load(Ordering::SeqCst)
    );
    assert_eq!(response.version(), Version::HTTP_2);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read response body");
    assert!(
        body.to_bytes()
            .windows(b"<html>".len())
            .any(|window| window.eq_ignore_ascii_case(b"<html>"))
    );
    drop(conn);

    wait_for_release(&harness).await;
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 2);
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 1);
    assert_eq!(events.decisions, [true]);
    assert_release_matches_claim(&events);
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
