//! DNS forwarder that records query→answer mappings for transport-layer policy checks.
//!
//! Runs on the host, listens on the veth gateway address. Sandbox processes
//! send DNS here via resolv.conf. Forwards raw DNS queries to the configured
//! upstream resolver, records IP→hostname mappings from upstream responses for
//! NFQUEUE prompts, and returns the upstream bytes unchanged.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_sandbox_core::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, mappings_from_response};
use clap::Parser;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// Build a DNS `SERVFAIL` response for a parseable query packet.
///
/// Returns `None` when `query` is not a DNS query message. `handle_udp` sends the
/// returned bytes directly to the client; `handle_tcp` writes them with the usual
/// two-byte length prefix.
fn servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    let message = Message::from_vec(query).ok()?;
    if message.header().message_type() != MessageType::Query {
        return None;
    }
    let mut response = Message::new();
    response
        .set_id(message.id())
        .set_message_type(MessageType::Response)
        .set_op_code(message.op_code())
        .set_recursion_desired(message.recursion_desired())
        .set_recursion_available(false)
        .set_response_code(ResponseCode::ServFail);
    for question in message.queries() {
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
    push_socket: Arc<std::sync::Mutex<Option<std::os::unix::net::UnixDatagram>>>,
    push_socket_path: PathBuf,
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
    let push_socket = match std::os::unix::net::UnixDatagram::unbound() {
        Ok(s) => Some(s),
        Err(err) => {
            warn!(error = %err, "failed to create unbound push datagram socket");
            None
        }
    };
    let push_socket = Arc::new(std::sync::Mutex::new(push_socket));
    let forwarder = DnsForwarder {
        cache,
        max_ttl: args.max_ttl,
        verbose: args.verbose,
        push_socket: push_socket.clone(),
        push_socket_path: args.push_socket.clone(),
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
                if let Err(err) = forwarder.handle_tcp(stream).await {
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
    ) -> Result<(), DnsForwarderError> {
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
        self.record_mappings_from_response(&resp);
        sock.send_to(&resp, peer).await?;
        Ok(())
    }

    async fn handle_tcp(&self, mut stream: TcpStream) -> Result<(), DnsForwarderError> {
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
            self.record_mappings_from_response(&resp);
            let resp_len = u16::try_from(resp.len()).unwrap_or(0);
            stream.write_u16(resp_len).await?;
            stream.write_all(&resp).await?;
        }
        Ok(())
    }

    async fn forward_udp(&self, data: &[u8]) -> Result<Vec<u8>, DnsForwarderError> {
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
            .map_err(|_| DnsForwarderError::Timeout)?
    }

    async fn forward_tcp(&self, data: &[u8]) -> Result<Vec<u8>, DnsForwarderError> {
        let mut stream = tokio::time::timeout(
            self.forward_timeout,
            TcpStream::connect(self.forward_target),
        )
        .await
        .map_err(|_| DnsForwarderError::Timeout)??;
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
            .map_err(|_| DnsForwarderError::Timeout)?
    }

    fn record_mappings_from_response(&self, response: &[u8]) {
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
                    let send_result = self.push_socket.lock().ok().and_then(|guard| {
                        guard
                            .as_ref()
                            .map(|s| s.send_to(line.as_bytes(), push_path))
                    });
                    if let Some(Err(err)) = send_result {
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

#[derive(Debug, thiserror::Error)]
enum DnsForwarderError {
    #[error("dns upstream forward timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    fn example_query(record_type: RecordType) -> Message {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut query = Message::new();
        query
            .set_id(0x1234)
            .set_recursion_desired(true)
            .add_query(Query::query(name, record_type));
        query
    }

    #[test]
    fn build_dns_response_preserves_query_with_hickory() {
        let query = example_query(RecordType::A);
        let resp = build_dns_response(&query, &[]).expect("response");
        let message = Message::from_vec(&resp).expect("parse response");

        assert_eq!(message.id(), 0x1234);
        assert_eq!(message.header().message_type(), MessageType::Response);
        assert!(message.recursion_desired());
        assert!(message.header().recursion_available());
        assert_eq!(message.queries().len(), 1);
        assert_eq!(message.queries()[0].name().to_ascii(), "example.com.");
        assert_eq!(message.queries()[0].query_type(), RecordType::A);
        assert!(message.answers().is_empty());
    }

    #[test]
    fn build_dns_response_filters_answers_by_query_type() {
        let query = example_query(RecordType::A);
        let ips = [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().expect("ipv6")),
        ];
        let resp = build_dns_response(&query, &ips).expect("response");
        let message = Message::from_vec(&resp).expect("parse response");

        assert_eq!(message.answers().len(), 1);
        assert_eq!(message.answers()[0].record_type(), RecordType::A);
        assert!(matches!(message.answers()[0].data(), Some(RData::A(_))));
    }

    #[test]
    fn mappings_from_response_returns_all_addresses_for_example_com() {
        let query = example_query(RecordType::A);
        let ips = [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
        ];
        let resp = build_dns_response(&query, &ips).expect("response");

        let mappings = agent_sandbox_core::mappings_from_response(&resp);
        assert_eq!(mappings.len(), 2);
        for m in &mappings {
            assert_eq!(m.hostname, "example.com");
        }
        assert_eq!(mappings[0].ip, "93.184.216.34");
        assert_eq!(mappings[1].ip, "93.184.216.35");
    }
}
