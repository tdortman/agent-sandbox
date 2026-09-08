//! Non-consuming downstream peek for transparent routing.
//!
//! A TCP `SYN` carries no payload, so the routing decision cannot happen in
//! NFQUEUE: every TCP flow is accepted for the proxy, and the proxy peeks at
//! the first stream bytes to tell HTTP(S) apart from raw TCP. The peek uses
//! rama's fail-fast peek loop, which copies at most a bounded prefix into
//! memory and replays it to whichever path runs next, so the classified bytes
//! reach the HTTP stack or the passthrough splice unchanged.
//!
//! The peek stops as soon as the first bytes decide the protocol. Streams
//! whose first byte already rules out TLS and HTTP (`SSH-...`, Postgres, ...)
//! are decided immediately; TLS and HTTP need at most a few more bytes from
//! the first segment. Only server-first protocols (no client bytes) wait out
//! the deadline.

use std::time::Duration;

use agent_sandbox_core::{TcpSniff, sniff_tcp};
use rama_core::{
    bytes::Bytes,
    io::{
        PrefixedIo, ReplayReader,
        peek::{PeekVerdict, peek_input_until_verdict_with_options},
    },
};
use rama_tcp::TcpStream;

/// Bytes held back for classification: covers the longest HTTP method
/// prefix (`OPTIONS `, `CONNECT `) plus the TLS record header.
const PEEK_LEN: usize = 16;

/// How long to wait for client bytes before assuming a server-first raw
/// protocol (SMTP greeting, MySQL handshake, ...).
const PEEK_DEADLINE: Duration = Duration::from_millis(500);

/// Classify a downstream stream by peeking at its first bytes.
///
/// Returns the classification together with the stream whose peeked bytes are
/// replayed ahead of the socket. `TcpSniff::Unknown` means the deadline
/// expired with nothing classifiable, which the caller treats as raw
/// passthrough.
pub async fn peek_protocol(
    mut stream: TcpStream,
) -> (TcpSniff, PrefixedIo<ReplayReader, TcpStream>) {
    let mut buffer = [0_u8; PEEK_LEN];

    let output = peek_input_until_verdict_with_options(
        &mut stream,
        &mut buffer,
        0,
        Some(PEEK_DEADLINE),
        None,
        |prefix: &[u8]| match sniff_tcp(prefix) {
            TcpSniff::Tls => PeekVerdict::Match(TcpSniff::Tls),
            TcpSniff::Http => PeekVerdict::Match(TcpSniff::Http),
            TcpSniff::NeedMore => PeekVerdict::NeedMore,
            TcpSniff::Unknown => PeekVerdict::Reject,
        },
    )
    .await;

    let replay = ReplayReader::new(Bytes::copy_from_slice(&buffer[..output.peek_size]));

    (
        output.data.unwrap_or(TcpSniff::Unknown),
        PrefixedIo::new(replay, stream),
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use agent_sandbox_core::TcpSniff;
    use rama_tcp::TcpStream;
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    use super::{PEEK_DEADLINE, peek_protocol};

    async fn peeked(payload: &[u8]) -> TcpSniff {
        let payload = payload.to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            client.write_all(&payload).await.expect("write");
            client
        });
        let (downstream, _) = listener.accept().await.expect("accept");
        let (sniff, _) = peek_protocol(TcpStream::new(downstream)).await;
        let _ = client.await;
        sniff
    }

    #[tokio::test]
    async fn peek_detects_tls_and_http() {
        assert_eq!(peeked(&[0x16, 0x03, 0x01, 0x00, 0xC0]).await, TcpSniff::Tls);
        assert_eq!(
            peeked(b"GET / HTTP/1.1\r\nHost: x\r\n").await,
            TcpSniff::Http
        );
    }

    #[tokio::test]
    async fn peek_rejects_raw_protocols_without_waiting() {
        let started = Instant::now();
        assert_eq!(peeked(b"SSH-2.0-OpenSSH\r\n").await, TcpSniff::Unknown);
        assert!(
            started.elapsed() < PEEK_DEADLINE,
            "first-byte ruling must not wait out the deadline"
        );
    }

    #[tokio::test]
    async fn peek_times_out_to_unknown_for_server_first_protocols() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::spawn(async move {
            // Connect and stay silent, like an SMTP client awaiting its
            // greeting.
            let held = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(held);
        });
        let (downstream, _) = listener.accept().await.expect("accept");
        let started = Instant::now();
        let (sniff, _) = peek_protocol(TcpStream::new(downstream)).await;
        assert_eq!(sniff, TcpSniff::Unknown);
        assert!(
            started.elapsed() >= PEEK_DEADLINE,
            "silent streams wait out the deadline before passthrough"
        );
        client.abort();
    }

    #[tokio::test]
    async fn peek_handles_fragmented_http_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            client.write_all(b"GE").await.expect("write");
            tokio::time::sleep(Duration::from_millis(150)).await;
            client
                .write_all(b"T / HTTP/1.1\r\nHost: x\r\n")
                .await
                .expect("write");
            client
        });
        let (downstream, _) = listener.accept().await.expect("accept");
        let (sniff, _) = peek_protocol(TcpStream::new(downstream)).await;
        let _ = client.await;
        assert_eq!(sniff, TcpSniff::Http);
    }
}
