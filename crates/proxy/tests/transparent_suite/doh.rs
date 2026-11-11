//! `DoH` scenarios: ECH configuration rewriting, including DNSSEC-bearing
//! answers.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    support::{IpVersion, TransparentHarness, loopback},
    transparent_common::wait_for_release,
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
async fn transparent_doh_dnssec_response_is_rewritten_unauthenticated() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;

    let expected = std::fs::read(harness.ech_state_dir().join("ech-config-list"))
        .expect("proxy ECH configuration");

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
        response.starts_with(b"HTTP/1.1 200 OK"),
        "unexpected DoH response: {}",
        String::from_utf8_lossy(&response)
    );

    let body_start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response head")
        + 4;

    let message =
        hickory_proto::op::Message::from_vec(&response[body_start..]).expect("decode DoH response");

    assert!(
        !message.metadata.authentic_data,
        "rewritten DoH response must not claim DNSSEC authentication"
    );

    assert!(
        response
            .windows(expected.len())
            .any(|window| window == expected),
        "rewritten DoH response must carry the proxy ECH configuration"
    );
}
