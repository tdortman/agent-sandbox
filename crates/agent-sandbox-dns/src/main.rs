//! DNS forwarder that records query→answer mappings for transport-layer policy checks.
//!
//! Runs on the host, listens on the veth gateway address. Sandbox processes
//! send DNS here via resolv.conf. Resolves via the host's system resolver
//! (getaddrinfo → systemd-resolved or whatever the host uses), records
//! IP→hostname mappings for NFQUEUE prompts, and returns DNS responses.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use agent_sandbox_core::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache};
use clap::Parser;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{info, warn};

const DEFAULT_TTL: u32 = 300;

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
    #[arg(long)]
    verbose: bool,
}

#[derive(Clone)]
struct DnsForwarder {
    cache: Arc<std::sync::Mutex<DnsCache>>,
    max_ttl: u32,
    verbose: bool,
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
    let forwarder = DnsForwarder {
        cache,
        max_ttl: args.max_ttl,
        verbose: args.verbose,
    };

    let bind = format!("{}:{}", args.listen_host, args.listen_port);
    let udp = UdpSocket::bind(&bind).await?;
    let tcp = TcpListener::bind(&bind).await?;
    info!(%bind, cache = %args.cache_path.display(), "dns forwarder listening");

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
        let Some(resp) = self.resolve_and_respond(&data) else {
            return Ok(());
        };
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
            if let Some(resp) = self.resolve_and_respond(&data) {
                let resp_len = u16::try_from(resp.len()).unwrap_or(0);
                stream.write_u16(resp_len).await?;
                stream.write_all(&resp).await?;
            }
        }
        Ok(())
    }

    /// Parse a DNS query, resolve via getaddrinfo, record mappings, return response.
    fn resolve_and_respond(&self, data: &[u8]) -> Option<Vec<u8>> {
        let query = Message::from_vec(data).ok()?;
        if query.header().message_type() != MessageType::Query {
            return None;
        }
        let question = query.queries().first()?;
        let hostname = question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_lowercase();

        let addrs = match resolve_via_libc(&hostname) {
            Ok(addrs) => addrs,
            Err(err) => {
                if self.verbose {
                    warn!(%hostname, error = %err, "resolve failed");
                }
                return build_dns_response(&query, &[]);
            }
        };

        {
            let ttl = self.max_ttl;
            let mut cache = self.cache.lock().expect("dns cache lock");
            for addr in &addrs {
                cache.remember(&addr.to_string(), &hostname, ttl);
            }
        }

        if self.verbose {
            info!(
                %hostname,
                addrs = %addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                "resolved"
            );
        }

        build_dns_response(&query, &addrs)
    }
}

fn resolve_via_libc(hostname: &str) -> std::io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<IpAddr> = format!("{hostname}:0")
        .to_socket_addrs()?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no addresses found",
        ));
    }
    Ok(addrs)
}

fn response_record(
    question_name: hickory_proto::rr::Name,
    query_type: RecordType,
    addr: IpAddr,
) -> Option<Record> {
    match (query_type, addr) {
        (RecordType::A, IpAddr::V4(ip)) => Some(Record::from_rdata(
            question_name,
            DEFAULT_TTL,
            RData::A(A(ip)),
        )),
        (RecordType::AAAA, IpAddr::V6(ip)) => Some(Record::from_rdata(
            question_name,
            DEFAULT_TTL,
            RData::AAAA(AAAA(ip)),
        )),
        _ => None,
    }
}

fn build_dns_response(query: &Message, addrs: &[IpAddr]) -> Option<Vec<u8>> {
    let question = query.queries().first()?.clone();
    let query_type = question.query_type();
    let question_name = question.name().clone();
    let mut response = Message::new();
    response
        .set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(query.op_code())
        .set_recursion_desired(query.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(ResponseCode::NoError)
        .add_query(question);
    for addr in addrs {
        if let Some(record) = response_record(question_name.clone(), query_type, *addr) {
            response.add_answer(record);
        }
    }
    response.to_vec().ok()
}

#[derive(Debug, thiserror::Error)]
enum DnsForwarderError {
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
