//! HTTP/3 scenarios: QUIC policy flow, WebTransport, CONNECT-UDP,
//! streaming, migration, and upstream ECH discovery.

use std::{collections::BTreeSet, sync::atomic::Ordering, time::Duration};

use bytes::Buf;
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};

use crate::{
    support::{Http3Client, IpVersion, TransparentHarness, loopback},
    transparent_common::{assert_release_matches_claim, wait_for_release},
};

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

    let origin = crate::support::Http3Origin::start(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        0,
        &ca_cert,
        &ca_key,
        root.path(),
        None,
    )
    .await;

    let client = crate::support::Http3Client::new(&ca_cert);

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

    let origin = crate::support::Http3Origin::start(
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
        .connect(
            "https",
            &authority,
            Some(&agent_sandbox_core::AttributionToken::from_bytes([0; 32])),
        )
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

/// Strip ANSI escape sequences from captured proxy output.
///
/// The proxy pins its own formatter to plain text, but log parsing must not
/// depend on the colour configuration of whatever process spawned it.
fn strip_ansi(input: &str) -> String {
    let mut plain = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.next() == Some('[') {
            for ch in chars.by_ref() {
                if ch.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(ch);
        }
    }

    plain
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

/// The proxy must decrypt a downstream ECH offer using its own key material
/// (the same configuration the sandbox DNS rewrite distributes), so the
/// HTTP/3 policy section sees the inner server name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_ech_offer_is_decrypted() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    let response = match harness.http3_ech_request("/allow").await {
        Ok(response) => response,
        Err(error) => {
            panic!(
                "HTTP/3 ECH request failed: {error}\nproxy log:\n{}\norigin log:\n{}",
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
    assert_eq!(events.checks.len(), 1);

    // The policy URL carries the inner (real) server name, proving the
    // encrypted ClientHelloInner was decrypted before routing.
    assert_eq!(
        events.checks[0].url.to_string(),
        format!(
            "https://localhost:{}/allow",
            harness.h3_origin().address.port()
        )
    );

    assert_release_matches_claim(&events);
    drop(events);
    assert_eq!(harness.h3_origin().attempts(), 1);
    assert_eq!(harness.h3_origin().request_heads()[0], "GET /allow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_disables_0rtt() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::with_early_data(&harness.ca_file());

    let response = client
        .request(harness.proxy_address, "localhost", "/allow")
        .await
        .expect("initial HTTP/3 request");

    assert_eq!(response.body().await, b"origin-response\n");

    let zero_rtt = client
        .zero_rtt_is_accepted(harness.proxy_address, "localhost")
        .await
        .expect("0-RTT probe");

    assert!(
        zero_rtt.is_none(),
        "proxy must not issue a 0-RTT-capable session ticket"
    );

    wait_for_release(&harness).await;
    assert_eq!(harness.h3_origin().attempts(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_forwards_informational_responses() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());

    let (informational, response) = client
        .request_with_informational(harness.proxy_address, "localhost", "/informational")
        .await
        .unwrap_or_else(|error| panic!("HTTP/3 informational request failed: {error}"));

    assert_eq!(informational.len(), 1);
    assert_eq!(informational[0].status().as_u16(), 103);

    assert_eq!(
        informational[0]
            .headers()
            .get("link")
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload")
    );

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"origin-response\n");
    wait_for_release(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_rejects_excessive_informational_responses() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());

    let result = client
        .request_with_informational(
            harness.proxy_address,
            "localhost",
            "/informational-overflow",
        )
        .await;

    assert!(result.is_err());
    wait_for_release(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_gates_request_body_on_continue() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());

    let response = client
        .request_with_expect(harness.proxy_address, "localhost", "/expect")
        .await
        .unwrap_or_else(|error| panic!("HTTP/3 Expect request failed: {error}"));

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"request-body-ok\n");
    wait_for_release(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_forwards_request_trailers() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;
    let client = Http3Client::new(&harness.ca_file());

    let response = client
        .request_with_trailers(harness.proxy_address, "localhost", "/request-trailers")
        .await
        .unwrap_or_else(|error| panic!("HTTP/3 request trailers failed: {error}"));

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"request-body-ok\n");
    wait_for_release(&harness).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http3_forwards_response_trailers() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    let response = harness
        .http3_request("/trailers")
        .await
        .expect("HTTP/3 request");

    assert_eq!(response.status(), 200);
    let (body, trailers) = response.body_with_trailers().await;
    assert_eq!(body, b"origin-response\n");

    assert_eq!(
        trailers
            .get("x-origin-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("present")
    );

    wait_for_release(&harness).await;
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

    let response = harness
        .http3_request("/deny")
        .await
        .expect("denied request must be answered");

    assert_eq!(response.status(), 403);
    assert_eq!(response.body().await, b"blocked by agent-sandbox policy\n");
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
async fn transparent_http3_cancellation_closes_upstream_stream() {
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
    drop(response);
    std::fs::write(harness.h3_stream_gate(), b"open").expect("open streaming gate");
    wait_for_release(&harness).await;
    wait_for_h3_condition(|| harness.h3_origin().connections_closed() >= 1, 5).await;
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
async fn transparent_http3_tracks_authenticated_connection_ids() {
    let harness = TransparentHarness::start_http3(loopback(IpVersion::V4)).await;

    let response = harness
        .http3_request("/allow")
        .await
        .expect("HTTP/3 request");

    assert_eq!(response.status(), 200);
    assert_eq!(response.body().await, b"origin-response\n");
    wait_for_release(&harness).await;
    let log = strip_ansi(&std::fs::read_to_string(&harness.proxy_log).unwrap_or_default());

    let bound: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("QUIC connection ID bound to policy association"))
        .collect();

    let released: Vec<&str> = log
        .lines()
        .filter(|line| {
            line.contains("QUIC connection ID released from policy association")
                || line.contains("QUIC connection ID removed from policy association")
        })
        .collect();

    assert!(
        !bound.is_empty(),
        "proxy must record bound QUIC connection IDs\n{log}"
    );

    assert!(
        !released.is_empty(),
        "proxy must record QUIC connection-ID releases at teardown\n{log}"
    );

    let stable_ids: BTreeSet<&str> = bound
        .iter()
        .chain(&released)
        .filter_map(|line| line.split("stable_id=").nth(1)?.split_whitespace().next())
        .collect();

    assert_eq!(
        stable_ids.len(),
        1,
        "every CID event must map to one stable connection\n{log}"
    );

    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    let claim_id = format!("{}", events.claims[0].connection_id);
    drop(events);

    for line in &bound {
        assert!(
            line.contains(&format!("connection_id={claim_id}")),
            "bound CID must map to the claimed policy association: {line}"
        );
    }
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
