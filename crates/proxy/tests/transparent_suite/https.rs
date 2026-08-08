//! TLS termination and ECH scenarios: SNI routing, ALPN fallback, and
//! downstream ECH decryption.

use crate::{
    support::{IpVersion, TransparentHarness, loopback},
    transparent_common::{assert_release_matches_claim, wait_for_release},
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
use rama_tls_rustls::client::TlsConnector;
use rustls::pki_types::pem::PemObject as _;
use std::{sync::atomic::Ordering, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

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

/// A TLS client that offers ECH with the proxy's own configuration over TCP.
///
/// The proxy decrypts the offer and must route on the inner server name,
/// proving the rustls TCP accept terminates ECH end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_https_ech_offer_is_decrypted_over_tcp() {
    let harness = TransparentHarness::start_tls(loopback(IpVersion::V4)).await;

    let config_list = std::fs::read(harness.ech_state_dir().join("ech-config-list"))
        .expect("proxy ECH configuration");

    let pem = std::fs::read(harness.ca_file()).expect("harness CA");

    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse harness CA");

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(certificates);
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());

    let config = rustls::client::EchConfig::new(
        rustls::pki_types::EchConfigListBytes::from(config_list),
        agent_sandbox_proxy::http3::hpke::ECH_SUPPORTED_SUITES,
    )
    .expect("proxy ECH configuration is supported");

    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_ech(rustls::client::EchMode::Enable(config))
        .expect("ECH client mode")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let tcp = TcpStream::connect(harness.proxy_address)
        .await
        .expect("connect to proxy");

    let connector: rama_tls_rustls::dep::tokio_rustls::TlsConnector =
        std::sync::Arc::new(tls).into();

    let mut stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").expect("server name"),
            tcp,
        )
        .await
        .expect("TLS handshake");

    let request = format!(
        "GET /allow HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        harness.origin.address.port()
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("write TLS request");

    let mut response = Vec::new();

    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");

    // The handshake completed during the IO above; the offer must have been
    // accepted for the inner name to reach policy.
    assert_eq!(
        stream.get_ref().1.ech_status(),
        rustls::client::EchStatus::Accepted
    );

    let status = response.starts_with(b"HTTP/1.0 200") || response.starts_with(b"HTTP/1.1 200");

    assert!(
        status,
        "unexpected HTTPS response: {}",
        String::from_utf8_lossy(&response)
    );

    wait_for_release(&harness).await;
    let events = harness.policy_events();
    let events = events.lock().expect("policy events lock");
    assert_eq!(events.checks.len(), 1);

    // The policy URL carries the inner (real) server name, proving the
    // encrypted ClientHelloInner was decrypted before routing.
    assert_eq!(
        events.checks[0].url.to_string(),
        format!("https://localhost:{}/allow", harness.origin.address.port())
    );

    assert_release_matches_claim(&events);
    drop(events);
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 1);
}
