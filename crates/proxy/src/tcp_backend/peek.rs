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
//!
//! Time the owner's cgroup spends frozen does not count towards the deadline.
//! Policyd freezes the whole sandbox while an approval is pending, and a TLS
//! client whose connect completed just before the freeze cannot send its
//! `ClientHello` until the thaw. Counting that time would misroute its HTTPS
//! as raw TCP, splice it uninspected, and prompt for `tcp://host:443`.

use std::{path::Path, time::Duration};

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

/// How long a silent client may stay unfrozen before the stream is assumed
/// to carry a server-first raw protocol (SMTP greeting, MySQL handshake, ...).
const PEEK_DEADLINE: Duration = Duration::from_millis(500);

/// Interval between freezer state checks while the client stays silent.
const FREEZE_POLL: Duration = Duration::from_millis(50);

/// Classify a downstream stream by peeking at its first bytes.
///
/// `owner_cgroup` is the cgroup directory of the process that opened the
/// flow; silent time while it is frozen is not counted. Returns the
/// classification together with the stream whose peeked bytes are replayed
/// ahead of the socket. `TcpSniff::Unknown` means the deadline expired with
/// nothing classifiable, which the caller treats as raw passthrough.
pub async fn peek_protocol(
    mut stream: TcpStream,
    owner_cgroup: Option<&Path>,
) -> (TcpSniff, PrefixedIo<ReplayReader, TcpStream>) {
    let mut buffer = [0_u8; PEEK_LEN];

    if !client_spoke(&stream, owner_cgroup).await {
        let replay = ReplayReader::new(Bytes::new());
        return (TcpSniff::Unknown, PrefixedIo::new(replay, stream));
    }

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

/// Wait without consuming anything until the client sends data or closes.
/// Returns `false` once the client stayed silent for [`PEEK_DEADLINE`] of
/// time in which its owner was not frozen.
async fn client_spoke(stream: &TcpStream, owner_cgroup: Option<&Path>) -> bool {
    let mut silent = Duration::ZERO;

    while silent < PEEK_DEADLINE {
        if tokio::time::timeout(FREEZE_POLL, stream.stream.readable())
            .await
            .is_ok()
        {
            return true;
        }

        if !owner_cgroup.is_some_and(cgroup_frozen) {
            silent += FREEZE_POLL;
        }
    }

    false
}

/// Whether the cgroup is frozen, directly or through an ancestor. A cgroup
/// that is gone or unreadable counts as running.
fn cgroup_frozen(cgroup: &Path) -> bool {
    std::fs::read_to_string(cgroup.join("cgroup.events"))
        .is_ok_and(|events| events.lines().any(|line| line == "frozen 1"))
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
        let (sniff, _) = peek_protocol(TcpStream::new(downstream), None).await;
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
        let (sniff, _) = peek_protocol(TcpStream::new(downstream), None).await;
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
        let (sniff, _) = peek_protocol(TcpStream::new(downstream), None).await;
        let _ = client.await;
        assert_eq!(sniff, TcpSniff::Http);
    }

    #[tokio::test]
    async fn peek_waits_out_owner_freeze_before_timing_out() {
        let cgroup = tempfile::tempdir().expect("cgroup dir");
        let events = cgroup.path().join("cgroup.events");
        std::fs::write(&events, "populated 1\nfrozen 1\n").expect("frozen events");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::spawn(async move {
            // A TLS client frozen for an approval longer than the deadline
            // sends its ClientHello only after the thaw.
            let mut client = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            tokio::time::sleep(PEEK_DEADLINE * 3).await;
            std::fs::write(&events, "populated 1\nfrozen 0\n").expect("thawed events");
            client
                .write_all(&[0x16, 0x03, 0x01, 0x00, 0xC0])
                .await
                .expect("write");
            client
        });
        let (downstream, _) = listener.accept().await.expect("accept");
        let (sniff, _) = peek_protocol(TcpStream::new(downstream), Some(cgroup.path())).await;
        let _ = client.await;
        assert_eq!(sniff, TcpSniff::Tls);
    }
}
