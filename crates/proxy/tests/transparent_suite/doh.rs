//! `DoH` scenarios: ECH configuration rewriting and DNSSEC rejection.

use crate::{
    support::{IpVersion, TransparentHarness, loopback},
    transparent_common::wait_for_release,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

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
