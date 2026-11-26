//! Plaintext HTTP requests reach an address of the host that policy judged,
//! never the destination the client chose for a different host.

use std::{net::Ipv4Addr, sync::atomic::Ordering};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::{support::TransparentHarness, transparent_common::wait_for_release};

/// The client dials a decoy address while `Host` names `localhost`, which the
/// policy allows. The request must reach `localhost`, not the decoy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_http_host_mismatching_destination_is_not_delivered() {
    let decoy_ip = Ipv4Addr::new(127, 0, 0, 2);
    let harness = TransparentHarness::start(decoy_ip.into(), 0).await;
    let port = harness.origin.address.port();

    let resolved = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind resolved localhost listener");

    let resolved_task = tokio::spawn(async move {
        let (mut stream, _) = resolved.accept().await.expect("accept proxied request");
        let mut head = [0; 1024];
        let read = stream.read(&mut head).await.expect("read proxied request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nresolved")
            .await
            .expect("write response");
        String::from_utf8_lossy(&head[..read]).into_owned()
    });

    let response = harness.request("/allow").await;
    wait_for_release(&harness).await;

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"resolved"));
    assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
    let head = resolved_task.await.expect("resolved listener task");
    assert!(
        head.starts_with("GET /allow HTTP/1.1"),
        "unexpected head: {head}"
    );
}
