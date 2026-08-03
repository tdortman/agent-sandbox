#![cfg(debug_assertions)]

mod support;
use bytes::Buf;
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
use support::{Http3Client, IpVersion, TransparentHarness, loopback};
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

    panic!(
        "proxy did not release flow ownership\nproxy log:\n{}",
        std::fs::read_to_string(&harness.proxy_log).unwrap_or_default()
    );
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
async fn transparent_http2_downstream_falls_back_to_http11_without_alpn() {
    let harness = TransparentHarness::start_tls_without_alpn(loopback(IpVersion::V4)).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_h3_client_reaches_standalone_origin() {
    let root = tempfile::tempdir().expect("temporary directory");
    let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate CA");
    let ca_cert = root.path().join("ca.pem");
    let ca_key = root.path().join("ca-key.pem");
    std::fs::write(&ca_cert, ca.cert.pem()).expect("write CA certificate");
    std::fs::write(&ca_key, ca.signing_key.serialize_pem()).expect("write CA key");

    let origin = support::Http3Origin::start(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        0,
        &ca_cert,
        &ca_key,
        root.path(),
        None,
    )
    .await;

    let client = support::Http3Client::new(&ca_cert);
    let response = client
        .request(origin.address, "localhost", "/allow")
        .await
        .expect("standalone origin request");

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"origin-response\n");
    assert_eq!(origin.attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_upstream_pool_reaches_standalone_origin() {
    let root = tempfile::tempdir().expect("temporary directory");
    let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate CA");
    let ca_cert = root.path().join("ca.pem");
    let ca_key = root.path().join("ca-key.pem");
    std::fs::write(&ca_cert, ca.cert.pem()).expect("write CA certificate");
    std::fs::write(&ca_key, ca.signing_key.serialize_pem()).expect("write CA key");

    let origin = support::Http3Origin::start(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        0,
        &ca_cert,
        &ca_key,
        root.path(),
        None,
    )
    .await;

    let pool = std::sync::Arc::new(
        agent_sandbox_proxy::http3::upstream::UpstreamPool::new(&ca_cert, None)
            .expect("upstream pool"),
    );

    let authority = format!("localhost:{}", origin.address.port());
    let connection = pool
        .connect("https", &authority)
        .await
        .expect("upstream connect");

    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{authority}/allow"))
        .body(())
        .expect("upstream request");

    let mut stream = connection
        .send_request(request)
        .await
        .expect("send upstream request");

    let response = stream.recv_response().await.expect("upstream response");
    assert_eq!(response.status().as_u16(), 200);

    let mut body = Vec::new();

    while let Some(mut chunk) = stream.recv_data().await.expect("upstream body") {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }

    assert_eq!(body, b"origin-response\n");
    assert_eq!(origin.attempts(), 1);
}

async fn wait_for_h3_condition(mut condition: impl FnMut() -> bool, timeout_seconds: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_seconds);

    while std::time::Instant::now() < deadline {
        if condition() {
            return;
        }

        sleep(Duration::from_millis(50)).await;
    }

    panic!("HTTP/3 harness condition was not met in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_allow_records_policy_and_upstream() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    let response = match harness.http3_request("/allow?raw=query").await {
        Ok(response) => response,
        Err(error) => {
            panic!(
                "HTTP/3 request failed: {error}\nproxy log:\n{}\norigin log:\n{}",
                std::fs::read_to_string(&harness.proxy_log).unwrap_or_default(),
                std::fs::read_to_string(harness.h3_origin().log_path()).unwrap_or_default()
            );
        }
    };
    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"origin-response\n");

    wait_for_release(&harness).await;

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");

    assert_eq!(events.claims.len(), 1);
    assert_eq!(
        events.claims[0].flow.protocol(),
        agent_sandbox_core::FlowProtocol::Udp
    );

    assert_eq!(events.claims[0].flow.source_ip(), loopback(IpVersion::V4));
    assert_eq!(
        events.claims[0].flow.destination_ip(),
        harness.h3_origin().address.ip()
    );
    assert_eq!(
        events.claims[0].flow.destination_port().get(),
        harness.h3_origin().address.port()
    );
    assert_eq!(events.checks.len(), 1);

    assert_eq!(
        events.checks[0].url.to_string(),
        format!(
            "https://localhost:{}/allow",
            harness.h3_origin().address.port()
        )
    );

    assert!(!events.checks[0].url.to_string().contains("raw=query"));
    assert_release_matches_claim(&events);
    drop(events);

    assert_eq!(harness.h3_origin().attempts(), 1);
    assert_eq!(harness.h3_origin().request_heads()[0], "GET /allow");
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
async fn transparent_http3_retries_approved_session_without_rechecking_policy() {
    let harness =
        TransparentHarness::start_http3_reconnecting_sessions(loopback(IpVersion::V4)).await;
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
    assert_eq!(harness.h3_origin().attempts(), 2);

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_reports_upstream_session_refusal() {
    let harness = TransparentHarness::start_http3_refusing_sessions(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    client
        .websocket_probe(harness.proxy_address, "localhost", "/allow")
        .await
        .expect_err("upstream session refusal must fail the session");

    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_webtransport_child_reaches_upstream() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let body = client
        .webtransport_probe(harness.proxy_address, "localhost", "/allow")
        .await
        .expect("WebTransport child stream");

    assert_eq!(body, b"webtransport-response\n");
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
    assert_eq!(harness.h3_origin().request_heads()[0], "CONNECT /allow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_retries_webtransport_session_without_rechecking_policy() {
    let harness =
        TransparentHarness::start_http3_reconnecting_sessions(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let body = client
        .webtransport_probe(harness.proxy_address, "localhost", "/allow")
        .await
        .expect("WebTransport session retry");

    assert_eq!(body, b"webtransport-response\n");
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 2);
    let events = harness.policy_events();
    assert_eq!(events.lock().expect("policy events lock").checks.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_rejects_unapproved_webtransport_session() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    client
        .webtransport_invalid_session_probe(harness.proxy_address, "localhost", "/allow")
        .await
        .expect_err("unapproved WebTransport session must reset");

    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_missing_datagram_setting_fails_closed() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let result = client
        .webtransport_probe_without_datagram(harness.proxy_address, "localhost", "/allow")
        .await;

    assert!(result.is_err());
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_upstream_missing_session_settings_fails_closed() {
    let harness = TransparentHarness::start_http3_rejecting_sessions(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let result = client
        .webtransport_probe(harness.proxy_address, "localhost", "/allow")
        .await;

    assert!(result.is_err());
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 0);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_connect_udp_relays_datagrams() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let body = match client
        .connect_udp_probe(harness.proxy_address, "localhost", "/allow")
        .await
    {
        Ok(body) => body,
        Err(error) => panic!(
            "{error}\nproxy log:\n{}\norigin log:\n{}",
            std::fs::read_to_string(&harness.proxy_log).unwrap_or_default(),
            std::fs::read_to_string(harness.h3_origin().log_path()).unwrap_or_default()
        ),
    };

    assert_eq!(body, b"connect-udp-probe");
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
    assert_eq!(harness.h3_origin().request_heads()[0], "CONNECT /allow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_relays_connect_udp_capsules() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let capsules = match client
        .connect_udp_capsule_probe(harness.proxy_address, "localhost", "/allow")
        .await
    {
        Ok(capsules) => capsules,
        Err(error) => panic!(
            "{error}\nproxy log:\n{}\norigin log:\n{}",
            std::fs::read_to_string(&harness.proxy_log).unwrap_or_default(),
            std::fs::read_to_string(harness.h3_origin().log_path()).unwrap_or_default()
        ),
    };

    assert_eq!(capsules, vec![
        (0, b"\0capsule-probe".to_vec()),
        (0x21, b"unknown-capsule".to_vec()),
    ]);
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_rejects_connect_udp_capsules_without_protocol() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    client
        .connect_udp_capsule_probe_without_protocol(harness.proxy_address, "localhost", "/allow")
        .await
        .expect_err("missing Capsule-Protocol must reset the session");

    wait_for_release(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_reuses_query_insensitive_approval() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let bodies = client
        .connect_udp_two_streams_probe(
            harness.proxy_address,
            "localhost",
            "/allow",
            "/allow?raw=query",
        )
        .await
        .expect("CONNECT-UDP approval reuse");

    assert_eq!(bodies, [b"route-0".to_vec(), b"route-1".to_vec()]);
    wait_for_release(&harness).await;

    let events = harness.policy_events();
    assert_eq!(events.lock().expect("policy events lock").checks.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_rejects_malformed_connect_udp_capsule() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());

    client
        .connect_udp_malformed_capsule_probe(harness.proxy_address, "localhost", "/allow")
        .await
        .expect("malformed CONNECT-UDP Capsule Protocol message must reset");

    wait_for_release(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_does_not_reuse_connect_udp_approval_for_another_target() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let result = client
        .connect_udp_two_streams_probe(harness.proxy_address, "localhost", "/allow", "/deny")
        .await;

    assert!(result.is_err(), "a different target needs a new approval");
    wait_for_release(&harness).await;

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 2);
    assert!(
        events
            .checks
            .iter()
            .any(|request| { request.url.to_string().ends_with("/allow") })
    );
    assert!(
        events
            .checks
            .iter()
            .any(|request| { request.url.to_string().ends_with("/deny") })
    );
    drop(events);
    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_retries_connect_udp_without_rechecking_policy() {
    let harness =
        TransparentHarness::start_http3_reconnecting_sessions(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let body = client
        .connect_udp_probe(harness.proxy_address, "localhost", "/allow")
        .await
        .expect("CONNECT-UDP session retry");

    assert_eq!(body, b"connect-udp-probe");
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 2);
    let events = harness.policy_events();
    assert_eq!(events.lock().expect("policy events lock").checks.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_routes_concurrent_connect_udp_streams() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    let bodies = match client
        .connect_udp_two_streams_probe(harness.proxy_address, "localhost", "/allow", "/allow-again")
        .await
    {
        Ok(bodies) => bodies,
        Err(error) => panic!(
            "{error}\nproxy log:\n{}\norigin log:\n{}",
            std::fs::read_to_string(&harness.proxy_log).unwrap_or_default(),
            std::fs::read_to_string(harness.h3_origin().log_path()).unwrap_or_default()
        ),
    };

    assert_eq!(bodies, [b"route-0".to_vec(), b"route-1".to_vec()]);
    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_rejects_invalid_connect_udp_context() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());
    client
        .connect_udp_invalid_context_probe(harness.proxy_address, "localhost", "/allow")
        .await
        .expect("invalid CONNECT-UDP context must reset the session");

    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_reuses_and_releases_upstream_associations() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    for path in ["/allow", "/allow-again"] {
        let response = harness.http3_request(path).await.expect("HTTP/3 request");
        assert_eq!(response.status(), 200);
        assert_eq!(response.body().await, b"origin-response\n");
    }

    wait_for_release(&harness).await;

    assert_eq!(harness.h3_origin().attempts(), 2);

    // Both exchanges reuse one upstream association, which the proxy then
    // releases once it idles out.
    assert_eq!(harness.h3_origin().connections_opened(), 1);

    wait_for_h3_condition(|| harness.h3_origin().connections_closed() >= 1, 25).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_denied_no_upstream() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    let result = harness.http3_request("/deny").await;
    assert!(
        result.is_err(),
        "denied request must be reset, not answered"
    );

    wait_for_release(&harness).await;

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.claims.len(), 1);
    assert_eq!(events.checks.len(), 1);
    assert!(events.checks[0].url.to_string().ends_with("/deny"));
    assert_release_matches_claim(&events);
    drop(events);

    assert_eq!(harness.h3_origin().attempts(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_streaming_is_bounded_and_ordered() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    let mut response = harness
        .http3_request("/stream")
        .await
        .expect("HTTP/3 request");
    assert_eq!(response.status(), 200);

    let first = timeout(Duration::from_secs(10), response.next_chunk())
        .await
        .expect("first chunk timeout")
        .expect("first chunk");
    assert_eq!(first, b"first-chunk");

    std::fs::write(harness.h3_stream_gate(), b"open").expect("open streaming gate");

    let rest = timeout(Duration::from_secs(5), response.body())
        .await
        .expect("remaining body timeout");
    assert_eq!(
        rest,
        b"second-chunk",
        "proxy log:\n{}\norigin log:\n{}",
        std::fs::read_to_string(&harness.proxy_log).unwrap_or_default(),
        std::fs::read_to_string(harness.h3_origin().log_path()).unwrap_or_default()
    );

    wait_for_release(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_migration_rebinds_policy_flow() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::with_local_ip(&harness.ca_file(), loopback(IpVersion::V4));
    let gate = harness.h3_stream_gate();
    let body = client
        .request_with_rebind(
            harness.proxy_address,
            "localhost",
            "/stream",
            loopback(IpVersion::V4),
            Some(&gate),
        )
        .await
        .expect("HTTP/3 migration request");
    assert_eq!(body, b"first-chunksecond-chunk");

    wait_for_release(&harness).await;

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.rebinds.len(), 1);
    assert_eq!(events.rebinds[0].source_ip(), loopback(IpVersion::V4));
    assert_eq!(
        events.rebinds[0].destination_ip(),
        harness.h3_origin().address.ip()
    );
    assert_eq!(
        events.rebinds[0].destination_port().get(),
        harness.h3_origin().address.port()
    );
    drop(events);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_ipv6_allow() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V6)).await;

    let response = harness
        .http3_request("/allow")
        .await
        .expect("IPv6 HTTP/3 request");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"origin-response\n");

    wait_for_release(&harness).await;

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.claims.len(), 1);
    assert_eq!(
        events.claims[0].flow.protocol(),
        agent_sandbox_core::FlowProtocol::Udp
    );

    assert_eq!(events.claims[0].flow.source_ip(), loopback(IpVersion::V6));
    assert_eq!(
        events.claims[0].flow.destination_ip(),
        harness.h3_origin().address.ip()
    );
    assert_eq!(
        events.claims[0].flow.destination_port().get(),
        harness.h3_origin().address.port()
    );
    assert_release_matches_claim(&events);
    drop(events);

    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_doh_ech_config_is_rewritten() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let expected = std::fs::read(harness.ech_state_dir().join("ech-config-list"))
        .expect("proxy ECH configuration");

    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "POST /doh-ech HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: \
         application/dns-message\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        harness.origin.address.port()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write DoH request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read DoH response");
    wait_for_release(&harness).await;

    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "unexpected DoH response: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response
            .windows(expected.len())
            .any(|window| window == expected),
        "rewritten DoH response must carry the proxy ECH configuration"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_doh_dnssec_response_is_rejected() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "POST /doh-dnssec HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: \
         application/dns-message\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        harness.origin.address.port()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write DoH request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read DoH response");
    wait_for_release(&harness).await;

    assert!(
        response.starts_with(b"HTTP/1.1 403 Forbidden"),
        "unexpected DoH response: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response
            .windows(b"blocked by agent-sandbox policy".len())
            .any(|window| window == b"blocked by agent-sandbox policy")
    );
}

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

    wait_for_release(&harness).await;

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 2);
    assert_eq!(
        events.checks[1].url.to_string(),
        format!("https://localhost:{origin_port}/allow"),
        "alternative endpoint must keep the original origin identity"
    );
    assert_release_matches_claim(&events);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_downstream_alpn_mismatch_fails_closed() {
    // The proxy advertises only h3; a client offering a different ALPN must
    // fail the handshake instead of falling back to an unadvertised
    // protocol.
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::with_alpn(&harness.ca_file(), b"http/1.1");

    let result = client
        .request(harness.proxy_address, "localhost", "/allow")
        .await;

    assert!(
        result.is_err(),
        "an ALPN mismatch must fail the QUIC handshake closed"
    );

    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_ordinary_tls_fallback_when_no_ech() {
    // The injected DNS serves no HTTPS record for the origin, so the proxy
    // uses ordinary TLS and the identity checks still pass.
    let dns = start_empty_dns().await;

    let harness = TransparentHarness::start_http3_with_ech_dns(loopback(IpVersion::V4), dns).await;

    let response = harness
        .http3_request("/allow")
        .await
        .expect("HTTP/3 request");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"origin-response\n");

    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_upstream_ech_fails_closed() {
    // The origin has no ECH support; an advertised ECH configuration must
    // make the handshake fail closed instead of downgrading to ordinary TLS.
    let root = tempfile::tempdir().expect("temporary directory");
    let state = root.path().join("ech");

    let init = std::process::Command::new(env!("CARGO_BIN_EXE_agent-sandbox-proxy"))
        .args(["--init-ech-state-only", "--ech-state-dir"])
        .arg(&state)
        .status()
        .expect("run ECH state init");
    assert!(init.success());

    let config = std::fs::read(state.join("ech-config-list")).expect("ECH configuration");
    let dns = start_ech_dns(config).await;

    let harness = TransparentHarness::start_http3_with_ech_dns(loopback(IpVersion::V4), dns).await;

    let result = harness.http3_request("/allow").await;
    assert!(
        result.is_err(),
        "ECH offered to a non-ECH origin must fail closed"
    );

    wait_for_release(&harness).await;

    assert_eq!(harness.h3_origin().attempts(), 0);
}

/// Serve an empty NOERROR answer for every query, so the proxy's upstream
/// ECH discovery concludes the origin does not advertise ECH.
async fn start_empty_dns() -> std::net::SocketAddr {
    let socket = UdpSocket::bind((loopback(IpVersion::V4), 0))
        .await
        .expect("bind empty DNS server");
    let address = socket.local_addr().expect("empty DNS address");

    tokio::spawn(async move {
        let packet = empty_dns_answer();
        let mut buffer = [0_u8; 2_048];

        loop {
            let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };

            let _ = socket.send_to(&packet, peer).await;
            let _ = size;
        }
    });

    address
}

fn empty_dns_answer() -> Vec<u8> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    let name = Name::from_ascii("localhost.").expect("valid name");

    let mut message = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::HTTPS));
    message.to_vec().expect("encode DNS answer")
}

/// Serve one canned HTTPS answer with the given ECH configuration for every
/// query, so the proxy's upstream ECH discovery finds it.
async fn start_ech_dns(config: Vec<u8>) -> std::net::SocketAddr {
    let socket = UdpSocket::bind((loopback(IpVersion::V4), 0))
        .await
        .expect("bind ECH DNS server");
    let address = socket.local_addr().expect("ECH DNS address");

    tokio::spawn(async move {
        let packet = https_answer_with_ech(&config);
        let mut buffer = [0_u8; 2_048];

        loop {
            let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };

            let _ = socket.send_to(&packet, peer).await;
            let _ = size;
        }
    });

    address
}

fn https_answer_with_ech(config: &[u8]) -> Vec<u8> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{
                HTTPS,
                svcb::{EchConfigList, SVCB, SvcParamKey, SvcParamValue},
            },
        },
    };

    let name = Name::from_ascii("localhost.").expect("valid name");
    let params = vec![(
        SvcParamKey::EchConfigList,
        SvcParamValue::EchConfigList(EchConfigList(config.to_vec())),
    )];

    let https = RData::HTTPS(HTTPS(SVCB::new(1, name.clone(), params)));

    let mut message = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), RecordType::HTTPS));
    message.add_answer(Record::from_rdata(name, 300, https));
    message.to_vec().expect("encode DNS answer")
}
