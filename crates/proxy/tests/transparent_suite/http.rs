//! TCP relay and cleartext HTTP scenarios: allow/deny, HTTP/1.0, pooling,
//! policy and claim errors, and cancellation.

use std::{os::fd::AsFd, sync::atomic::Ordering, time::Duration};

use nix::{
    libc,
    sys::socket::{setsockopt, sockopt::Linger},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::{
    support::{IpVersion, TransparentHarness, loopback},
    transparent_common::{assert_release_matches_claim, wait_for_release},
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
    let responses = harness.pooled_requests().await;
    wait_for_release(&harness).await;
    assert!(responses.first.ends_with(b"origin-response"));
    assert!(responses.second.ends_with(b"origin-response"));
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
async fn transparent_cleartext_http2_preface_disconnect_releases_claim() {
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
    drop(stream);
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
    let response = harness.streaming_request("/stream").await;
    wait_for_release(&harness).await;

    assert!(
        response
            .first
            .windows(b"origin-response".len() / 2)
            .any(|window| { window == b"origin-" })
    );

    assert!(
        response
            .rest
            .windows(b"response".len())
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

/// policyd admits a bounded number of connections for the proxy; a burst of
/// new client connections must queue their claims behind that budget instead
/// of opening one policy connection each and having the excess refused, which
/// would reset other clients' connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_http_burst_of_connections_stays_within_the_policy_connection_budget() {
    let harness = TransparentHarness::start_with_slow_claims(
        loopback(IpVersion::V4),
        0,
        Duration::from_millis(100),
    )
    .await;
    let request = format!(
        "GET /allow HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        harness.origin.address.port()
    );

    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..200 {
        let address = harness.proxy_address;
        let request = request.clone();
        clients.spawn(async move {
            let mut stream = TcpStream::connect(address).await.expect("connect proxy");
            stream
                .write_all(request.as_bytes())
                .await
                .expect("write request");
            let mut response = Vec::new();
            let _ = timeout(Duration::from_secs(30), stream.read_to_end(&mut response)).await;
            response.starts_with(b"HTTP/1.1 200 OK")
        });
    }
    let mut served = 0;
    while let Some(result) = clients.join_next().await {
        served += usize::from(result.expect("client task"));
    }

    assert_eq!(
        harness.policy.refused_connections.load(Ordering::SeqCst),
        0,
        "the proxy opened more policy connections than policyd admits"
    );
    assert_eq!(served, 200, "every connection of the burst is served");
}

/// A client that gives up on a request waiting for approval just closes its
/// socket: the kernel sends a FIN, not a reset. The pending check is
/// withdrawn, so a later approval cannot send the request upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_closing_the_socket_withdraws_the_pending_check() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "POST /cancel HTTP/1.1\r\nHost: localhost:{}\r\nContent-Length: 0\r\n\r\n",
        harness.origin.address.port()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

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

    // An ordinary close: FIN, no reset.
    drop(stream);

    timeout(Duration::from_secs(5), async {
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
    .expect("a closed client must withdraw the pending check");

    wait_for_release(&harness).await;
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
}

/// A client that shuts down its write side while its request waits for
/// approval keeps the check pending, and gets the response once approved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_half_closed_client_gets_the_response_after_approval() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "GET /pending HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        harness.origin.address.port()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stream.shutdown().await.expect("half-close the write side");

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

    // Long enough for the proxy to see the FIN and to poll the socket table
    // several times.
    sleep(Duration::from_millis(2500)).await;
    assert!(
        harness
            .policy_events()
            .lock()
            .expect("policy events lock")
            .cancellations
            .is_empty(),
        "a half-close must not withdraw the pending check"
    );

    harness.policy.approve_pending();

    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("the proxy must answer and close")
        .expect("read response");
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
    assert!(response.ends_with(b"origin-response"), "{response:?}");
    wait_for_release(&harness).await;
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

/// A client that shuts down its write side after a complete request still
/// gets the response through the peek-and-classify path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_answers_a_client_that_half_closes() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let mut stream = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");

    let request = format!(
        "GET /allow HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        harness.origin.address.port()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stream.shutdown().await.expect("half-close the write side");

    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("the proxy must answer and close")
        .expect("read response");

    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
    assert!(response.ends_with(b"origin-response"), "{response:?}");
    wait_for_release(&harness).await;
}

/// Connections past the cap are closed without a response, and a freed slot
/// admits the next one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_refuses_connections_beyond_the_cap() {
    let harness =
        TransparentHarness::start_with_connection_cap(loopback(IpVersion::V4), 0, 2).await;
    let partial_head = format!(
        "GET /allow HTTP/1.1\r\nHost: localhost:{}\r\n",
        harness.origin.address.port()
    );

    let mut held = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(harness.proxy_address)
            .await
            .expect("connect proxy");
        stream
            .write_all(partial_head.as_bytes())
            .await
            .expect("write partial head");
        held.push(stream);
    }

    // Both held connections are admitted once their flows are claimed.
    for _ in 0..500 {
        let claimed = harness
            .policy_events()
            .lock()
            .expect("policy events lock")
            .claims
            .len();
        if claimed >= 2 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    // The proxy admits a connection just after its claim is answered.
    sleep(Duration::from_millis(300)).await;

    let mut refused = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect proxy");
    let _ = refused.write_all(partial_head.as_bytes()).await;
    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(10), refused.read_to_end(&mut response))
        .await
        .expect("a refused connection is closed promptly");
    assert!(
        response.is_empty(),
        "a refused connection gets no response: {response:?}"
    );
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);

    // Ending a held connection frees its slot. A connection refused while the
    // slot is still held may be reset, so errors only mean "try again".
    drop(held.pop());
    let request = format!(
        "GET /allow HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        harness.origin.address.port()
    );
    let mut served = false;
    for _ in 0..100 {
        let mut stream = TcpStream::connect(harness.proxy_address)
            .await
            .expect("connect proxy");
        let _ = stream.write_all(request.as_bytes()).await;
        let mut response = Vec::new();
        let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
        if response.starts_with(b"HTTP/1.1 200 OK") {
            served = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(served, "a freed slot admits a new connection");
}
