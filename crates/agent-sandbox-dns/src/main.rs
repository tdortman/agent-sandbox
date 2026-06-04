//! DNS forwarder that records query→answer mappings for transparent proxy hostname correlation.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_sandbox_core::{DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, mappings_from_response};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-dns-proxy")]
struct Args {
    #[arg(long, default_value = "169.254.100.1")]
    listen_host: String,
    #[arg(long, default_value_t = 53)]
    listen_port: u16,
    #[arg(long, default_value = "127.0.0.53:53")]
    upstream: String,
    #[arg(long, default_value = DEFAULT_CACHE_PATH)]
    cache_path: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_TTL)]
    max_ttl: u32,
    #[arg(long)]
    verbose: bool,
}

#[derive(Clone)]
struct DnsProxy {
    upstream: SocketAddr,
    cache: Arc<std::sync::Mutex<DnsCache>>,
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
    let upstream = parse_upstream(&args.upstream)?;
    let cache = Arc::new(std::sync::Mutex::new(DnsCache::new(
        Some(&args.cache_path),
        args.max_ttl,
    )));
    let proxy = DnsProxy {
        upstream,
        cache,
        verbose: args.verbose,
    };

    let bind = format!("{}:{}", args.listen_host, args.listen_port);
    let udp = UdpSocket::bind(&bind).await?;
    let tcp = TcpListener::bind(&bind).await?;
    info!(
        %bind,
        upstream = %upstream,
        cache = %args.cache_path.display(),
        "dns proxy listening"
    );

    let udp = Arc::new(udp);
    let proxy_udp = proxy.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_535];
        loop {
            let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                continue;
            };
            let data = buf[..len].to_vec();
            let sock = Arc::clone(&udp);
            let proxy = proxy_udp.clone();
            tokio::spawn(async move {
                if let Err(err) = proxy.handle_udp(data, peer, sock).await {
                    warn!(%peer, error = %err, "dns udp error");
                }
            });
        }
    });

    let proxy_tcp = proxy.clone();
    let tcp_task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = tcp.accept().await else {
                continue;
            };
            let proxy = proxy_tcp.clone();
            tokio::spawn(async move {
                if let Err(err) = proxy.handle_tcp(stream).await {
                    warn!(%peer, error = %err, "dns tcp client error");
                }
            });
        }
    });

    let _ = tokio::join!(udp_task, tcp_task);
    Ok(())
}

impl DnsProxy {
    async fn handle_udp(
        &self,
        data: Vec<u8>,
        peer: SocketAddr,
        sock: Arc<UdpSocket>,
    ) -> Result<(), DnsProxyError> {
        if data.is_empty() {
            return Ok(());
        }
        let resp = self.forward_udp(&data).await.map_err(|err| {
            warn!(upstream = %self.upstream, %peer, error = %err, "dns udp upstream failed");
            err
        })?;
        self.record_response(&resp);
        sock.send_to(&resp, peer).await?;
        Ok(())
    }

    async fn handle_tcp(&self, mut stream: TcpStream) -> Result<(), DnsProxyError> {
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
            let resp = self.forward_tcp(&data).await?;
            self.record_response(&resp);
            let resp_len = u16::try_from(resp.len()).unwrap_or(0);
            stream.write_u16(resp_len).await?;
            stream.write_all(&resp).await?;
        }
        Ok(())
    }

    fn record_response(&self, data: &[u8]) {
        let mappings = mappings_from_response(data);
        {
            let mut cache = self.cache.lock().expect("dns cache lock");
            for (ip, hostname, ttl) in &mappings {
                cache.remember(ip, hostname, *ttl);
            }
        }
        if self.verbose {
            for (ip, hostname, ttl) in mappings {
                info!(%ip, %hostname, ttl, "dns cache");
            }
        }
    }

    async fn forward_udp(&self, data: &[u8]) -> Result<Vec<u8>, DnsProxyError> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.send_to(data, self.upstream).await?;
        let mut buf = vec![0_u8; 65_535];
        let (len, _) = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
            .await
            .map_err(|_| DnsProxyError::Timeout)??;
        Ok(buf[..len].to_vec())
    }

    async fn forward_tcp(&self, data: &[u8]) -> Result<Vec<u8>, DnsProxyError> {
        let mut upstream =
            tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(self.upstream))
                .await
                .map_err(|_| DnsProxyError::Timeout)??;
        upstream
            .write_u16(u16::try_from(data.len()).unwrap_or(0))
            .await?;
        upstream.write_all(data).await?;
        let len = upstream.read_u16().await?;
        let mut resp = vec![0_u8; usize::from(len)];
        upstream.read_exact(&mut resp).await?;
        Ok(resp)
    }
}

fn parse_upstream(value: &str) -> Result<SocketAddr, DnsProxyError> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        let port: u16 = port.parse().map_err(|_| DnsProxyError::InvalidUpstream)?;
        return format!("{host}:{port}")
            .parse()
            .map_err(|_| DnsProxyError::InvalidUpstream);
    }
    format!("{value}:53")
        .parse()
        .map_err(|_| DnsProxyError::InvalidUpstream)
}

#[derive(Debug, thiserror::Error)]
enum DnsProxyError {
    #[error("upstream DNS timed out")]
    Timeout,
    #[error("invalid --upstream address")]
    InvalidUpstream,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
