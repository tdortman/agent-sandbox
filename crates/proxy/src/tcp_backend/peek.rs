//! Non-consuming downstream peek for transparent routing.
//!
//! A TCP `SYN` carries no payload, so the routing decision cannot happen in
//! NFQUEUE: every TCP flow is accepted for the proxy, and the proxy peeks at
//! the first stream bytes to tell HTTP(S) apart from raw TCP. The peek reads
//! at most a bounded prefix into memory and replays it to whichever path runs
//! next, so the classified bytes reach the HTTP stack or the passthrough
//! splice unchanged.
//!
//! The peek stops as soon as the leading bytes decide the protocol. Streams
//! whose first byte already rules out TLS and HTTP (Postgres, MySQL, RESP,
//! ...) are decided immediately; TLS and HTTP need a few more bytes, which a
//! client may deliver in separate segments. Only server-first protocols
//! (no client bytes) wait out the deadline. A stream that closes before
//! sending anything is reported as such: there is nothing left to route.
//!
//! Time the owner's cgroup spends frozen does not count towards the deadline,
//! whether the client is silent from the start or between segments. Policyd
//! freezes the whole sandbox while an approval is pending, and a TLS client
//! whose connect completed just before the freeze cannot send its
//! `ClientHello` until the thaw. Counting that time would misroute its HTTPS
//! as raw TCP, splice it uninspected, and prompt for `tcp://host:443`.

use std::{path::Path, time::Duration};

use agent_sandbox_core::{TcpSniff, sniff_tcp};
use rama_core::{
    bytes::Bytes,
    io::{PrefixedIo, ReplayReader},
};
use rama_tcp::TcpStream;
use tokio::io::AsyncReadExt;

/// Bytes held back for classification: leading empty lines, the longest
/// method token the sniffer considers, its space and an absolute-form target
/// opener (`https://`).
const PEEK_LEN: usize = 32;

/// How long a silent client may stay unfrozen before the stream is assumed
/// to carry a server-first raw protocol (SMTP greeting, MySQL handshake, ...).
const PEEK_DEADLINE: Duration = Duration::from_millis(500);

/// Interval between freezer state checks while the client stays silent.
const FREEZE_POLL: Duration = Duration::from_millis(50);

/// Classify a downstream stream by peeking at its first bytes.
///
/// `owner_cgroup` is the cgroup directory of the process that opened the
/// flow; silent time while it is frozen is not counted. Returns the outcome
/// together with the stream whose peeked bytes are replayed ahead of the
/// socket. `TcpSniff::Unknown` means the deadline expired, the prefix buffer
/// filled, or the stream closed mid-prefix without anything classifiable,
/// which the caller treats as raw passthrough.
pub async fn peek_protocol(mut stream: TcpStream, owner_cgroup: Option<&Path>) -> PeekedProtocol {
    let mut buffer = [0_u8; PEEK_LEN];
    let mut filled = 0;
    let mut silent = Duration::ZERO;

    let outcome = loop {
        let sniff = sniff_tcp(&buffer[..filled]);
        if sniff != TcpSniff::NeedMore {
            break PeekOutcome::Classified(sniff);
        }
        if filled == buffer.len() || silent >= PEEK_DEADLINE {
            break PeekOutcome::Classified(TcpSniff::Unknown);
        }

        // The read consumes into `buffer`: a plain socket peek would return
        // the same unread bytes again without waiting for the rest.
        match tokio::time::timeout(FREEZE_POLL, stream.read(&mut buffer[filled..])).await {
            Ok(Ok(read)) if read > 0 => filled += read,
            Ok(_) if filled == 0 => break PeekOutcome::ClosedEmpty,
            Ok(_) => break PeekOutcome::Classified(TcpSniff::Unknown),
            Err(_) => {
                if !owner_cgroup.is_some_and(cgroup_frozen) {
                    silent += FREEZE_POLL;
                }
            }
        }
    };

    let replay = ReplayReader::new(Bytes::copy_from_slice(&buffer[..filled]));

    PeekedProtocol {
        outcome,
        stream: PrefixedIo::new(replay, stream),
    }
}

/// What the first bytes of a downstream stream decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeekOutcome {
    /// The stream carries (or, for `Unknown`, does not carry) HTTP(S).
    Classified(TcpSniff),
    /// The client closed the connection, or the read failed, before sending
    /// a single byte.
    ClosedEmpty,
}

/// One peeked downstream stream with its replayed bytes.
pub struct PeekedProtocol {
    /// The protocol decision for the peeked bytes.
    pub outcome: PeekOutcome,
    /// The stream with peeked bytes replayed ahead of the socket.
    pub stream: PrefixedIo<ReplayReader, TcpStream>,
}

/// Whether a freeze is requested on the cgroup, directly or through an
/// ancestor. The request (`cgroup.freeze`) decides, not the `frozen` state in
/// `cgroup.events`: the kernel reports that only once every task stopped, and
/// a task waiting on a seccomp notification its frozen broker already
/// received never does. A cgroup that is gone or unreadable counts as
/// running.
fn cgroup_frozen(cgroup: &Path) -> bool {
    cgroup.ancestors().any(|dir| {
        std::fs::read_to_string(dir.join("cgroup.freeze")).is_ok_and(|freeze| freeze.trim() == "1")
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use agent_sandbox_core::TcpSniff;
    use rama_tcp::TcpStream;
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    use super::{PEEK_DEADLINE, PeekOutcome, peek_protocol};

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
        let outcome = peek_protocol(TcpStream::new(downstream), None)
            .await
            .outcome;
        let _ = client.await;
        classified(outcome)
    }

    fn classified(outcome: PeekOutcome) -> TcpSniff {
        match outcome {
            PeekOutcome::Classified(sniff) => sniff,
            PeekOutcome::ClosedEmpty => panic!("stream unexpectedly closed empty"),
        }
    }

    #[tokio::test]
    async fn peek_detects_tls_and_http() {
        assert_eq!(peeked(&[0x16, 0x03, 0x01, 0x00, 0xC0]).await, TcpSniff::Tls);
        assert_eq!(
            peeked(b"GET / HTTP/1.1\r\nHost: x\r\n").await,
            TcpSniff::Http
        );
        assert_eq!(
            peeked(b"\r\nPROPFIND /dav/ HTTP/1.1\r\nHost: x\r\n").await,
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
        let outcome = peek_protocol(TcpStream::new(downstream), None)
            .await
            .outcome;
        assert_eq!(classified(outcome), TcpSniff::Unknown);
        assert!(
            started.elapsed() >= PEEK_DEADLINE,
            "silent streams wait out the deadline before passthrough"
        );
        client.abort();
    }

    #[tokio::test]
    async fn peek_reports_a_stream_closed_before_any_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let started = Instant::now();
        drop(
            tokio::net::TcpStream::connect(address)
                .await
                .expect("connect"),
        );
        let (downstream, _) = listener.accept().await.expect("accept");
        let outcome = peek_protocol(TcpStream::new(downstream), None)
            .await
            .outcome;
        assert_eq!(outcome, PeekOutcome::ClosedEmpty);
        assert!(
            started.elapsed() < PEEK_DEADLINE,
            "a closed stream must not wait out the deadline"
        );
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
        let outcome = peek_protocol(TcpStream::new(downstream), None)
            .await
            .outcome;
        let _ = client.await;
        assert_eq!(classified(outcome), TcpSniff::Http);
    }

    #[tokio::test]
    async fn peek_waits_out_owner_freeze_before_timing_out() {
        // The state the kernel shows while one task cannot stop: the scope
        // has its freeze requested, yet `cgroup.events` never reports it
        // frozen. The owner sits in a child cgroup of that scope.
        let scope = tempfile::tempdir().expect("scope dir");
        let freeze = scope.path().join("cgroup.freeze");
        std::fs::write(&freeze, "1\n").expect("freeze requested");
        let owner = scope.path().join("child");
        std::fs::create_dir(&owner).expect("child cgroup");
        std::fs::write(owner.join("cgroup.freeze"), "0\n").expect("child freeze");
        std::fs::write(owner.join("cgroup.events"), "populated 1\nfrozen 0\n")
            .expect("child events");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::spawn(async move {
            // A TLS client frozen for an approval longer than the deadline
            // sends its ClientHello only after the thaw.
            let mut client = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            tokio::time::sleep(PEEK_DEADLINE * 3).await;
            std::fs::write(&freeze, "0\n").expect("thaw");
            client
                .write_all(&[0x16, 0x03, 0x01, 0x00, 0xC0])
                .await
                .expect("write");
            client
        });
        let (downstream, _) = listener.accept().await.expect("accept");
        let outcome = peek_protocol(TcpStream::new(downstream), Some(&owner))
            .await
            .outcome;
        let _ = client.await;
        assert_eq!(classified(outcome), TcpSniff::Tls);
    }

    #[tokio::test]
    async fn peek_waits_out_owner_freeze_between_header_segments() {
        // The first segment carries two bytes of the TLS record header, then
        // the freeze outlasts the deadline before the rest arrives.
        let scope = tempfile::tempdir().expect("scope dir");
        let freeze = scope.path().join("cgroup.freeze");
        std::fs::write(&freeze, "1\n").expect("freeze requested");
        let owner = scope.path().to_path_buf();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            client.write_all(&[0x16, 0x03]).await.expect("first write");
            tokio::time::sleep(PEEK_DEADLINE * 3).await;
            std::fs::write(&freeze, "0\n").expect("thaw");
            client
                .write_all(&[0x01, 0x00, 0xC0])
                .await
                .expect("second write");
            client
        });
        let (downstream, _) = listener.accept().await.expect("accept");
        let outcome = peek_protocol(TcpStream::new(downstream), Some(&owner))
            .await
            .outcome;
        let _ = client.await;
        assert_eq!(classified(outcome), TcpSniff::Tls);
    }
}
