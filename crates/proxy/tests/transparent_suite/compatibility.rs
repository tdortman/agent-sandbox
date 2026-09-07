//! Wire checks for interim responses and cleartext HTTP/2.
use std::{sync::atomic::Ordering, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::support::{IpVersion, TransparentHarness, loopback};

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    timeout(Duration::from_secs(5), async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.expect("response head"));
        }
        head
    })
    .await
    .expect("response head timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn informational_heads_arrive_before_final_on_http1_and_h2c_upstreams() {
    for h2c in [false, true] {
        let harness = if h2c {
            TransparentHarness::start_h2c(loopback(IpVersion::V4)).await
        } else {
            TransparentHarness::start(loopback(IpVersion::V4), 0).await
        };
        let mut stream = TcpStream::connect(harness.proxy_address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /hints HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                    harness.origin.address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let head = read_head(&mut stream).await;
        assert!(
            head.starts_with(b"HTTP/1.1 103"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
        assert!(head.contains("link: </style.css>; rel=preload"));
        assert!(!head.contains("x-hop"));
        harness.origin.stream_gate.notify_one();
        let mut rest = Vec::new();
        timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.starts_with(b"HTTP/1.1 200"));
        assert!(rest.ends_with(b"origin-response"));
        assert_eq!(harness.policy_events().lock().unwrap().decisions, [true]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expect_continue_upload_and_early_rejection_finish() {
    for path in ["/continue-upload", "/reject-upload", "/deny-upload"] {
        let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
        let mut stream = TcpStream::connect(harness.proxy_address).await.unwrap();
        stream
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: localhost:{}\r\nExpect: \
                     100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                    harness.origin.address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = read_head(&mut stream).await;
        if head.starts_with(b"HTTP/1.1 100") {
            if path == "/continue-upload" {
                stream.write_all(b"ping").await.unwrap();
            }
            head = read_head(&mut stream).await;
        }
        let status = match path {
            "/continue-upload" => b"HTTP/1.1 200",
            "/reject-upload" => b"HTTP/1.1 413",
            _ => b"HTTP/1.1 403",
        };
        assert!(
            head.starts_with(status),
            "{}",
            String::from_utf8_lossy(&head)
        );
        if path == "/deny-upload" {
            assert_eq!(harness.origin.attempts.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_streaming_trailers_and_per_request_policy() {
    use bytes::Bytes;
    use rama_http::{HeaderMap, HeaderValue, Request};
    let harness = TransparentHarness::start_h2c(loopback(IpVersion::V4)).await;
    let socket = TcpStream::connect(harness.proxy_address).await.unwrap();
    let (mut client, connection) =
        rama_http_core::h2::client::handshake(rama_tcp::TcpStream::from(socket))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost:{}/echo",
            harness.origin.address.port()
        ))
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let (response, mut upload) = client.send_request(request, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"ping"), false)
        .unwrap();
    // The origin echoes each chunk before the request ends.
    let mut response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    let chunk = timeout(Duration::from_secs(5), response.body_mut().data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(chunk, b"ping"[..]);
    response
        .body_mut()
        .flow_control()
        .release_capacity(chunk.len())
        .unwrap();
    let mut trailers = HeaderMap::new();
    trailers.insert("x-request-trailer", HeaderValue::from_static("present"));
    upload.send_trailers(trailers).unwrap();
    assert!(response.body_mut().data().await.is_none());
    assert_eq!(
        response.body_mut().trailers().await.unwrap().unwrap()["grpc-status"],
        "0"
    );
    let request = Request::builder()
        .uri(format!(
            "http://localhost:{}/deny",
            harness.origin.address.port()
        ))
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        403
    );
    assert_eq!(harness.origin.request_heads.lock().unwrap().len(), 1);
    assert_eq!(harness.policy_events().lock().unwrap().decisions, [
        true, false
    ]);
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_downstream_receives_interim_heads_from_both_upstream_versions() {
    use rama_http::Request;
    for h2c in [false, true] {
        let harness = if h2c {
            TransparentHarness::start_h2c(loopback(IpVersion::V4)).await
        } else {
            TransparentHarness::start(loopback(IpVersion::V4), 0).await
        };
        let socket = TcpStream::connect(harness.proxy_address).await.unwrap();
        let (mut client, connection) =
            rama_http_core::h2::client::handshake(rama_tcp::TcpStream::from(socket))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .uri(format!(
                "http://localhost:{}/hints",
                harness.origin.address.port()
            ))
            .body(())
            .unwrap();
        let (mut response, _) = client.send_request(request, true).unwrap();
        let interim = timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| response.poll_informational(cx)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(interim.status(), 103);
        assert_eq!(interim.headers()["link"], "</style.css>; rel=preload");
        assert!(!interim.headers().contains_key("x-hop"));
        harness.origin.stream_gate.notify_one();
        assert_eq!(
            timeout(Duration::from_secs(5), response)
                .await
                .unwrap()
                .unwrap()
                .status(),
            200
        );
        driver.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn excessive_informational_responses_abort_the_request() {
    for h2c in [false, true] {
        let harness = if h2c {
            TransparentHarness::start_h2c(loopback(IpVersion::V4)).await
        } else {
            TransparentHarness::start(loopback(IpVersion::V4), 0).await
        };
        let mut stream = TcpStream::connect(harness.proxy_address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /hints-overflow HTTP/1.1\r\nHost: localhost:{}\r\nConnection: \
                     close\r\n\r\n",
                    harness.origin.address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&response).contains("200 OK"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http10_clients_do_not_receive_interim_heads() {
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    harness.origin.stream_gate.notify_one();
    let response = timeout(Duration::from_secs(5), harness.http10_request("/hints"))
        .await
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.0 200"));
    assert!(response.ends_with(b"origin-response"));
}

#[test]
fn configured_https_port_uses_tls_and_https_policy() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let harness = TransparentHarness::start_configured_tls_port(loopback(IpVersion::V4)).await;
        assert!(![443, 8443].contains(&harness.origin.address.port()));
        let response = harness.tls_raw_request(
            &format!(
                "GET /allow HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                harness.origin.address.port()
            ),
            Some("localhost"),
        );
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        let events = harness.policy_events();
        let events = events.lock().unwrap();
        assert_eq!(events.checks[0].url.scheme.as_str(), "https");
        assert_eq!(events.decisions, [true]);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_expect_continue_is_forwarded_before_upload() {
    use bytes::Bytes;
    use rama_http::Request;
    let harness = TransparentHarness::start(loopback(IpVersion::V4), 0).await;
    let socket = TcpStream::connect(harness.proxy_address).await.unwrap();
    let (mut client, connection) =
        rama_http_core::h2::client::handshake(rama_tcp::TcpStream::from(socket))
            .await
            .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost:{}/continue-upload",
            harness.origin.address.port()
        ))
        .header("expect", "100-continue")
        .header("content-length", "4")
        .body(())
        .unwrap();
    let (mut response, mut upload) = client.send_request(request, false).unwrap();
    let head = timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| response.poll_informational(cx)),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(head.status(), 100);
    upload.send_data(Bytes::from_static(b"ping"), true).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        200
    );
    driver.abort();
}
