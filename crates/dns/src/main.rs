//! DNS forwarder that records query→answer mappings for transport-layer policy
//! checks.
//!
//! Runs on the host, listens on the veth gateway address. Sandbox processes
//! send DNS here via resolv.conf. Forwards raw DNS queries to the configured
//! upstream resolver, records IP→hostname mappings from upstream responses for
//! NFQUEUE prompts, and returns the upstream bytes unchanged.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, mappings_from_response};
use clap::Parser;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tracing::{debug, info, warn};

/// Build a DNS `SERVFAIL` response for a parseable query packet.
///
/// Returns `None` when `query` is not a DNS query message. `handle_udp` sends
/// the returned bytes directly to the client; `handle_tcp` writes them with the
/// usual two-byte length prefix.
fn servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    let message = Message::from_vec(query).ok()?;
    if message.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut response = Message::new(
        message.metadata.id,
        MessageType::Response,
        message.metadata.op_code,
    );
    response.metadata.recursion_desired = message.metadata.recursion_desired;
    response.metadata.recursion_available = false;
    response.metadata.response_code = ResponseCode::ServFail;
    for question in &message.queries {
        response.add_query(question.clone());
    }
    response.to_vec().ok()
}

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-dns-forwarder")]
struct Args {
    #[arg(long, default_value = "169.254.100.1")]
    listen_host: String,

    #[arg(long, default_value_t = 53)]
    listen_port: u16,

    #[arg(long, default_value = DEFAULT_CACHE_PATH)]
    cache_path: PathBuf,

    #[arg(long, default_value_t = DEFAULT_MAX_TTL)]
    max_ttl: u32,

    #[arg(long, default_value = "/run/agent-sandbox/dns-push.sock")]
    push_socket: PathBuf,

    /// Cache DNS attribution only for clients from this exact IP address.
    ///
    /// When omitted, responses from every client are eligible for attribution
    /// for standalone deployments. Proxy-mode launches must set this to the
    /// sandbox namespace address so an unrelated DNS client cannot poison the
    /// policy cache.
    #[arg(long)]
    cache_client_ip: Option<IpAddr>,

    #[arg(long, default_value = "127.0.0.53:53")]
    forward_target: SocketAddr,

    #[arg(long, default_value_t = 5_000)]
    forward_timeout_ms: u64,

    #[arg(long)]
    verbose: bool,
}

#[derive(Clone)]
struct DnsForwarder {
    cache: Arc<std::sync::Mutex<DnsCache>>,
    max_ttl: u32,
    verbose: bool,
    push_socket: Arc<std::os::unix::net::UnixDatagram>,
    push_socket_path: PathBuf,
    cache_client_ip: Option<IpAddr>,
    forward_target: SocketAddr,
    forward_timeout: Duration,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sandbox_dns=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();
    let mut dns_cache = DnsCache::new(Some(&args.cache_path), args.max_ttl);
    dns_cache.reload();
    let cache = Arc::new(std::sync::Mutex::new(dns_cache));
    if let Some(parent) = args.push_socket.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    let push_socket = Arc::new(std::os::unix::net::UnixDatagram::unbound()?);
    let forwarder = DnsForwarder {
        cache,
        max_ttl: args.max_ttl,
        verbose: args.verbose,
        push_socket: push_socket.clone(),
        push_socket_path: args.push_socket.clone(),
        cache_client_ip: args.cache_client_ip,
        forward_target: args.forward_target,
        forward_timeout: Duration::from_millis(args.forward_timeout_ms),
    };

    let bind = format!("{}:{}", args.listen_host, args.listen_port);
    let udp = UdpSocket::bind(&bind).await?;
    let tcp = TcpListener::bind(&bind).await?;
    info!(
        %bind,
        cache = %args.cache_path.display(),
        forward = %args.forward_target,
        "dns forwarder listening"
    );

    let udp = Arc::new(udp);
    let udp_forwarder = forwarder.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_535];
        loop {
            let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                continue;
            };
            let data = buf[..len].to_vec();
            let sock = Arc::clone(&udp);
            let forwarder = udp_forwarder.clone();
            tokio::spawn(async move {
                if let Err(err) = forwarder.handle_udp(data, peer, sock).await {
                    warn!(%peer, error = %err, "dns udp error");
                }
            });
        }
    });

    let tcp_forwarder = forwarder.clone();
    let tcp_task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = tcp.accept().await else {
                continue;
            };
            let forwarder = tcp_forwarder.clone();
            tokio::spawn(async move {
                if let Err(err) = forwarder.handle_tcp(stream, peer).await {
                    warn!(%peer, error = %err, "dns tcp error");
                }
            });
        }
    });

    let _ = tokio::join!(udp_task, tcp_task);
    Ok(())
}

impl DnsForwarder {
    async fn handle_udp(
        &self,
        data: Vec<u8>,
        peer: SocketAddr,
        sock: Arc<UdpSocket>,
    ) -> std::io::Result<()> {
        let resp = match self.forward_udp(&data).await {
            Ok(resp) => resp,
            Err(err) => {
                if self.verbose {
                    warn!(error = %err, "dns upstream udp forward failed");
                }
                match servfail_response(&data) {
                    Some(resp) => resp,
                    None => return Ok(()),
                }
            }
        };
        self.record_mappings_from_response(&resp, peer);
        sock.send_to(&resp, peer).await?;
        Ok(())
    }

    async fn handle_tcp(&self, mut stream: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        loop {
            let len = match stream.read_u16().await {
                Ok(0) => continue,
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err.into()),
            };
            let mut data = vec![0_u8; usize::from(len)];
            if stream.read_exact(&mut data).await.is_err() {
                break;
            }
            let resp = match self.forward_tcp(&data).await {
                Ok(resp) => resp,
                Err(err) => {
                    if self.verbose {
                        warn!(error = %err, "dns upstream tcp forward failed");
                    }
                    match servfail_response(&data) {
                        Some(resp) => resp,
                        None => continue,
                    }
                }
            };
            self.record_mappings_from_response(&resp, peer);
            let resp_len = u16::try_from(resp.len()).unwrap_or(0);
            stream.write_u16(resp_len).await?;
            stream.write_all(&resp).await?;
        }
        Ok(())
    }

    async fn forward_udp(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let bind_addr = match self.forward_target.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let sock = UdpSocket::bind(bind_addr).await?;
        let forward_fut = async {
            sock.send_to(data, self.forward_target).await?;
            let mut buf = vec![0_u8; 65_535];
            let (len, _) = sock.recv_from(&mut buf).await?;
            Ok(buf[..len].to_vec())
        };
        tokio::time::timeout(self.forward_timeout, forward_fut)
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "dns upstream forward timed out",
                )
            })?
    }

    async fn forward_tcp(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut stream = tokio::time::timeout(
            self.forward_timeout,
            TcpStream::connect(self.forward_target),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "dns upstream forward timed out",
            )
        })??;
        let forward_fut = async {
            let len = u16::try_from(data.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "dns query too large for tcp framing",
                )
            })?;
            stream.write_u16(len).await?;
            stream.write_all(data).await?;
            let resp_len = stream.read_u16().await?;
            let mut resp = vec![0_u8; usize::from(resp_len)];
            stream.read_exact(&mut resp).await?;
            Ok(resp)
        };
        tokio::time::timeout(self.forward_timeout, forward_fut)
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "dns upstream forward timed out",
                )
            })?
    }

    fn record_mappings_from_response(&self, response: &[u8], peer: SocketAddr) {
        if let Some(expected) = self.cache_client_ip
            && peer.ip() != expected
        {
            debug!(
                %peer,
                %expected,
                "ignoring DNS response from an untrusted client peer"
            );
            return;
        }
        let mappings = mappings_from_response(response);
        if mappings.is_empty() {
            return;
        }
        {
            let mut cache = self.cache.lock().expect("dns cache lock");
            for mapping in &mappings {
                cache.remember(
                    &mapping.ip,
                    &mapping.hostname,
                    mapping.ttl.min(self.max_ttl),
                );
            }
        }
        if let Some(push_path) = self.push_socket_path.to_str() {
            for mapping in &mappings {
                let ttl = mapping.ttl.min(self.max_ttl);
                let payload = serde_json::json!({
                    "ip": &mapping.ip,
                    "host": &mapping.hostname,
                    "ttl": ttl,
                });
                if let Ok(mut line) = serde_json::to_string(&payload) {
                    line.push('\n');
                    let send_result = self.push_socket.send_to(line.as_bytes(), push_path);
                    if let Err(err) = send_result {
                        match err.kind() {
                            std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::ConnectionRefused => {
                                debug!(error = %err, "no nfq listener for push socket");
                            }
                            _ => {
                                warn!(error = %err, "push socket send failed");
                            }
                        }
                    }
                }
            }
        }
        if self.verbose {
            let addrs = mappings
                .iter()
                .map(|m| m.ip.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            if let Some(hostname) = mappings.first().map(|m| m.hostname.as_str()) {
                info!(%hostname, addrs = %addrs, "resolved");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RData, Record, RecordType, rdata::TXT},
    };

    use super::*;

    fn example_query(record_type: RecordType) -> Vec<u8> {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name, record_type));
        query.to_vec().expect("encode query")
    }

    fn test_forwarder(forward_target: SocketAddr) -> DnsForwarder {
        DnsForwarder {
            cache: Arc::new(std::sync::Mutex::new(DnsCache::new(
                None::<PathBuf>,
                DEFAULT_MAX_TTL,
            ))),
            max_ttl: DEFAULT_MAX_TTL,
            verbose: false,
            push_socket: Arc::new(
                std::os::unix::net::UnixDatagram::unbound().expect("unbound push socket"),
            ),
            push_socket_path: PathBuf::from("/nonexistent/dns-push.sock"),
            cache_client_ip: None,
            forward_target,
            forward_timeout: Duration::from_secs(2),
        }
    }

    fn upstream_txt_response() -> Vec<u8> {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.metadata.response_code = ResponseCode::NoError;
        message
            .add_query(Query::query(name.clone(), RecordType::TXT))
            .add_answer(Record::from_rdata(
                name,
                300,
                RData::TXT(TXT::new(vec!["sandbox-test".to_string()])),
            ));
        message.to_vec().expect("encode response")
    }

    #[tokio::test]
    async fn udp_forwarding_preserves_upstream_response() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let expected = upstream_txt_response();
        let expected_for_responder = expected.clone();

        let responder = tokio::spawn(async move {
            let mut buf = vec![0_u8; 65_535];
            let (len, peer) = upstream.recv_from(&mut buf).await.expect("recv query");
            upstream
                .send_to(&expected_for_responder, peer)
                .await
                .expect("send response");
            len
        });

        let forwarder = test_forwarder(upstream_addr);
        let query = example_query(RecordType::TXT);
        let result = forwarder.forward_udp(&query).await.expect("forward udp");
        assert_eq!(result, expected);
        responder.await.expect("responder task");
    }

    #[tokio::test]
    async fn tcp_forwarding_preserves_upstream_response() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().expect("upstream addr");
        let expected = upstream_txt_response();
        let expected_for_responder = expected.clone();

        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let len = stream.read_u16().await.expect("read len");
            let mut data = vec![0_u8; usize::from(len)];
            stream.read_exact(&mut data).await.expect("read query");
            let resp_len = u16::try_from(expected_for_responder.len()).expect("resp len");
            stream.write_u16(resp_len).await.expect("write len");
            stream
                .write_all(&expected_for_responder)
                .await
                .expect("write resp");
        });

        let forwarder = test_forwarder(upstream_addr);
        let query = example_query(RecordType::TXT);
        let result = forwarder.forward_tcp(&query).await.expect("forward tcp");
        assert_eq!(result, expected);
        responder.await.expect("responder task");
    }

    #[test]
    fn servfail_preserves_query_id_and_question() {
        let query = example_query(RecordType::A);
        let resp = servfail_response(&query).expect("servfail response");
        let message = Message::from_vec(&resp).expect("parse servfail");
        assert_eq!(message.metadata.id, 0x1234);
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(message.queries.len(), 1);
        assert_eq!(message.queries[0].name().to_ascii(), "example.com.");
        assert_eq!(message.queries[0].query_type(), RecordType::A);
    }

    #[tokio::test]
    async fn handle_udp_sends_servfail_on_upstream_failure() {
        let recv = UdpSocket::bind("127.0.0.1:0").await.expect("bind recv");
        let recv_addr = recv.local_addr().expect("recv addr");
        let send = UdpSocket::bind("127.0.0.1:0").await.expect("bind send");
        let forwarder = test_forwarder(SocketAddr::from(([127, 0, 0, 1], 1)));
        let query = example_query(RecordType::A);

        let task = tokio::spawn(async move {
            forwarder
                .handle_udp(query, recv_addr, Arc::new(send))
                .await
                .expect("handle udp");
        });

        let mut buf = vec![0_u8; 65_535];
        let (len, _) = recv.recv_from(&mut buf).await.expect("recv servfail");
        let message = Message::from_vec(&buf[..len]).expect("parse response");
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        task.await.expect("udp task");
    }

    #[tokio::test]
    async fn handle_tcp_writes_framed_servfail_on_upstream_failure() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind forwarder listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let forwarder = test_forwarder(SocketAddr::from(([127, 0, 0, 1], 1)));
        let query = example_query(RecordType::A);

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            forwarder
                .handle_tcp(stream, peer)
                .await
                .expect("handle tcp");
        });

        let mut client = TcpStream::connect(listener_addr)
            .await
            .expect("connect to forwarder");
        let query_len = u16::try_from(query.len()).expect("query len");
        client.write_u16(query_len).await.expect("write query len");
        client.write_all(&query).await.expect("write query");
        let resp_len = client.read_u16().await.expect("read resp len");
        let mut resp = vec![0_u8; usize::from(resp_len)];
        client.read_exact(&mut resp).await.expect("read resp");
        let message = Message::from_vec(&resp).expect("parse servfail");
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        // Close the client side so handle_tcp's read loop sees EOF and
        // returns, instead of blocking waiting for a second query frame.
        drop(client);
        server.await.expect("server task");
    }

    #[test]
    fn mappings_from_response_returns_all_addresses_for_example_com() {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
            ))
            .add_answer(Record::from_rdata(
                name,
                300,
                RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 35))),
            ));
        let resp = message.to_vec().expect("encode response");

        let mappings = mappings_from_response(&resp);
        assert_eq!(mappings.len(), 2);
        for m in &mappings {
            assert_eq!(m.hostname, "example.com");
        }
        assert_eq!(mappings[0].ip, "93.184.216.34");
        assert_eq!(mappings[1].ip, "93.184.216.35");
    }
    #[test]
    fn cache_client_ip_filters_attribution_to_exact_udp_and_tcp_peer() {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new(0x4321, MessageType::Response, OpCode::Query);
        message
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name,
                300,
                RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 20))),
            ));
        let response = message.to_vec().expect("encode response");

        let mut forwarder = test_forwarder(SocketAddr::from(([127, 0, 0, 1], 1)));
        let trusted = SocketAddr::from(([192, 0, 2, 10], 5353));
        let untrusted = SocketAddr::from(([192, 0, 2, 11], 5353));
        forwarder.cache_client_ip = Some(trusted.ip());

        forwarder.record_mappings_from_response(&response, untrusted);
        assert!(
            forwarder
                .cache
                .lock()
                .expect("cache lock")
                .lookup("192.0.2.20")
                .is_none(),
            "untrusted UDP/TCP peer must not mutate attribution"
        );

        forwarder.record_mappings_from_response(&response, trusted);
        assert_eq!(
            forwarder
                .cache
                .lock()
                .expect("cache lock")
                .lookup("192.0.2.20"),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn cli_defaults_preserve_standalone_fallbacks() {
        let args = Args::try_parse_from(["agent-sandbox-dns-forwarder"])
            .expect("standalone invocation has valid defaults");
        assert_eq!(args.listen_host, "169.254.100.1");
        assert_eq!(args.cache_path, PathBuf::from(DEFAULT_CACHE_PATH));
        assert_eq!(
            args.push_socket,
            PathBuf::from("/run/agent-sandbox/dns-push.sock")
        );
        assert_eq!(
            args.forward_target,
            "127.0.0.53:53"
                .parse::<SocketAddr>()
                .expect("valid default forward target")
        );
    }

    #[test]
    fn cli_accepts_nix_supplied_launch_facts() {
        let args = Args::try_parse_from([
            "agent-sandbox-dns-forwarder",
            "--listen-host",
            "192.0.2.10",
            "--cache-path",
            "/var/lib/test/dns-cache.json",
            "--push-socket",
            "/run/test/dns-push.sock",
            "--forward-target",
            "192.0.2.53:53",
        ])
        .expect("explicit launch facts parse");
        assert_eq!(args.listen_host, "192.0.2.10");
        assert_eq!(
            args.cache_path,
            PathBuf::from("/var/lib/test/dns-cache.json")
        );
        assert_eq!(args.push_socket, PathBuf::from("/run/test/dns-push.sock"));
        assert_eq!(
            args.forward_target,
            "192.0.2.53:53"
                .parse::<SocketAddr>()
                .expect("valid test forward target")
        );
    }
}
