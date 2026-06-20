//! Agent sandbox NFQUEUE, kernel-level packet policy enforcement.
//!
//! Runs inside the sandbox network namespace. nftables queues outbound TCP SYN
//! and UDP packets here. This daemon resolves the destination hostname from the
//! DNS forwarder's in-memory cache, asks policyd for a verdict, then accepts or
//! actively rejects the packet.

mod owner;
mod packet;
mod policy;
use agent_sandbox_core::{
    DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache, lookup_dns_cache, mappings_from_response,
};
use clap::Parser;
use nfq_updated::{Queue, Verdict};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Number of bytes to copy from each queued packet.
/// `u16::MAX` ensures the full UDP DNS response payload is available
/// for hickory-proto parsing (CNAME chains and multi-answer responses
/// routinely exceed the standard Ethernet MTU's 1500-byte segment).
const COPY_RANGE: u16 = u16::MAX;

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-nfq")]
struct Cli {
    /// NFQUEUE queue number (must match nftables `queue num` rule).
    #[arg(long, default_value_t = 0)]
    queue: u16,

    /// Policy daemon Unix socket path.
    #[arg(long, default_value = "/run/agent-sandbox/policy.sock")]
    policy_socket: String,

    /// Max seconds to wait for policyd per packet check.
    #[arg(long, default_value_t = 305.0)]
    policy_timeout: f64,

    /// Maximum number of packets the kernel may hold while waiting for verdicts.
    #[arg(long, default_value_t = 4096)]
    queue_len: u32,

    /// Path to nft binary for transient reject set management.
    #[arg(long, default_value = "nft")]
    nft_binary: String,
    /// DNS forwarder IP address (v4 or v6). Traffic to this IP on port 53 bypasses policy checks.
    #[arg(long, default_value = "169.254.100.1")]
    dns_server_ip: IpAddr,
}

struct NfqState {
    dns_cache: DnsCache,
    cache_path: Option<PathBuf>,
    dns_server_ip: IpAddr,
    nft_binary: String,
}

impl NfqState {
    fn new(cli: &Cli) -> Self {
        // Memory-only cache for sniffed DNS-response mappings.
        let dns_cache = DnsCache::new(None::<PathBuf>, DEFAULT_MAX_TTL);
        // Cache path for on-demand disk reloads from the DNS forwarder.
        let cache_path: Option<PathBuf> = std::env::var("AGENT_SANDBOX_DNS_CACHE").map_or_else(
            |_| Some(PathBuf::from(DEFAULT_CACHE_PATH)),
            |p| Some(PathBuf::from(p)),
        );
        Self {
            dns_cache,
            cache_path,
            dns_server_ip: cli.dns_server_ip,
            nft_binary: cli.nft_binary.clone(),
        }
    }

    /// Resolve an IP to a hostname.
    ///
    /// Tries the in-memory cache first. On miss, reloads from disk, the DNS
    /// forwarder has already written the mapping by the time the SYN arrives
    /// because the app cannot connect until DNS resolution completes. Returns
    /// the raw IP if the cache still has no entry (no PTR fallback).
    fn resolve_host(&mut self, ip: &str) -> String {
        if let Some(host) = self.dns_cache.lookup(ip) {
            return host;
        }
        if let Some(host) = lookup_dns_cache(ip, self.cache_path.as_deref()) {
            self.dns_cache
                .remember_ephemeral(ip, &host, DEFAULT_MAX_TTL);
            return host;
        }
        ip.to_string()
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sandbox_nfq=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    let timeout = Duration::from_secs_f64(cli.policy_timeout.max(1.0));

    let mut queue = match open_queue(cli.queue, cli.queue_len) {
        Ok(queue) => queue,
        Err(err) => {
            eprintln!(
                "agent-sandbox-nfq: failed to bind queue {}: {err}",
                cli.queue
            );
            std::process::exit(1);
        }
    };

    info!(queue = cli.queue, "nfqueue listening");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let mut state = NfqState::new(&cli);

    loop {
        let mut message = match queue.recv() {
            Ok(message) => message,
            Err(err) => {
                warn!(error = %err, "nfqueue recv error");
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };

        let verdict = handle_packet(&mut state, &cli.policy_socket, timeout, &message, &runtime);
        message.set_verdict(verdict);
        if let Err(err) = queue.verdict(message) {
            warn!(error = %err, "nfqueue verdict error");
        }
    }
}

fn open_queue(queue_num: u16, queue_len: u32) -> std::io::Result<Queue> {
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    queue.set_fail_open(queue_num, false)?;
    queue.set_recv_gso(queue_num, false)?;
    queue.set_copy_range(queue_num, COPY_RANGE)?;
    queue.set_queue_max_len(queue_num, queue_len)?;
    Ok(queue)
}

/// Whether a packet to the given destination should bypass policy checks entirely.
fn is_bypass_traffic(dst_ip: IpAddr, dst_port: u16, dns_server_ip: IpAddr) -> bool {
    // Loopback: 127.0.0.0/8 and ::1
    match dst_ip {
        IpAddr::V4(v4) if v4.octets()[0] == 127 => return true,
        IpAddr::V6(v6) if v6 == Ipv6Addr::LOCALHOST => return true,
        _ => {}
    }
    // DNS forwarder traffic on port 53
    if dst_ip == dns_server_ip && dst_port == 53 {
        return true;
    }
    false
}

/// Run the configured `nft` binary with the given args, returning the output.
fn run_nft_real(binary: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new(binary).args(args).output()
}

/// Add the destination IP and port to the transient nftables reject set, then
/// return `Verdict::Repeat` so nftables re-evaluates and rejects the packet.
///
/// Falls back to `Verdict::Drop` if nft add fails.
fn nft_reject_and_repeat(
    nft_binary: &str,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: packet::TransportProtocol,
) -> Verdict {
    nft_reject_and_repeat_inner(dst_ip, dst_port, protocol, |args| {
        run_nft_real(nft_binary, args)
    })
}

/// Inner reject helper with injectable command runner.
fn nft_reject_and_repeat_inner<F>(
    dst_ip: IpAddr,
    dst_port: u16,
    _protocol: packet::TransportProtocol,
    run_nft: F,
) -> Verdict
where
    F: FnOnce(&[&str]) -> std::io::Result<std::process::Output>,
{
    let set_name = match dst_ip {
        IpAddr::V4(_) => "reject_v4",
        IpAddr::V6(_) => "reject_v6",
    };
    let element = format!("{{ {dst_ip} . {dst_port} timeout 5s }}");
    let args = [
        "add",
        "element",
        "inet",
        "agent_sandbox",
        set_name,
        element.as_str(),
    ];
    let out = run_nft(&args);
    match out {
        Ok(o) if o.status.success() => {
            debug!(ip = %dst_ip, port = dst_port, "added transient reject element");
            Verdict::Repeat
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            warn!(
                ip = %dst_ip, port = dst_port, error = %stderr,
                "nft reject add failed (non-zero exit), falling back to Drop"
            );
            Verdict::Drop
        }
        Err(e) => {
            warn!(
                ip = %dst_ip, port = dst_port, error = %e,
                "nft reject add failed (exec error), falling back to Drop"
            );
            Verdict::Drop
        }
    }
}
/// Core packet handling logic, parameterized over the policy check function.
///
/// Seam for unit testing: inject a mock `check` to verify policy is consulted
/// on every call without a real policyd socket.
fn handle_packet_payload<F>(
    state: &mut NfqState,
    policy_socket: &str,
    timeout: Duration,
    payload: &[u8],
    check: &mut F,
) -> Verdict
where
    F: FnMut(
        &str,
        &str,
        &str,
        u16,
        packet::TransportProtocol,
        Option<u32>,
        Duration,
    ) -> std::io::Result<policy::PolicyResult>,
{
    // Try IPv4 first, then IPv6.
    let meta = packet::parse_ipv4(payload).or_else(|| packet::parse_ipv6(payload));
    let Some(meta) = meta else {
        warn!("dropping unparseable queued packet");
        return Verdict::Drop;
    };

    // UDP DNS responses: cache hostname mappings from the response and accept.
    if meta.protocol == packet::TransportProtocol::Udp && meta.src_port == 53 {
        if let Some(udp_data) = packet::udp_payload(payload, &meta) {
            let mappings = mappings_from_response(udp_data);
            for m in &mappings {
                state
                    .dns_cache
                    .remember_ephemeral(&m.ip, &m.hostname, m.ttl.min(DEFAULT_MAX_TTL));
            }
            if !mappings.is_empty() {
                debug!(count = mappings.len(), "cached DNS response mappings");
            }
        }
        return Verdict::Accept;
    }

    // DNS queries: accept without prompting.
    if meta.protocol == packet::TransportProtocol::Udp && meta.dst_port == 53 {
        return Verdict::Accept;
    }

    if !meta.is_policy_boundary() {
        return Verdict::Accept;
    }

    if is_bypass_traffic(meta.dst_ip, meta.dst_port, state.dns_server_ip) {
        debug!(ip = %meta.dst_ip, port = meta.dst_port, "bypass policy");
        return Verdict::Accept;
    }

    // Resolve hostname and ask policyd for every policy-boundary packet.
    // No long-lived per-host verdict cache: policy file edits take effect
    // on the next connection within the same daemon session.
    let hostname = state.resolve_host(&meta.dst_ip.to_string());
    let dst_ip = meta.dst_ip.to_string();
    let src_pid = owner::pid_from_src_port(meta.protocol, meta.src_ip, meta.src_port);
    let result = check(
        policy_socket,
        &hostname,
        &dst_ip,
        meta.dst_port,
        meta.protocol,
        src_pid,
        timeout,
    );

    let allowed = match result {
        Ok(result) => result.allowed,
        Err(err) => {
            warn!(
                protocol = meta.protocol.as_str(),
                host = %hostname,
                dst = %dst_ip,
                port = meta.dst_port,
                error = %err,
                "policy check failed"
            );
            false
        }
    };

    if allowed {
        info!(
            protocol = meta.protocol.as_str(),
            host = %hostname,
            dst = %dst_ip,
            port = meta.dst_port,
            "accept"
        );
        Verdict::Accept
    } else {
        info!(
            protocol = meta.protocol.as_str(),
            host = %hostname,
            dst = %dst_ip,
            port = meta.dst_port,
            "reject (policy)"
        );
        // Add a transient nft reject element so the client fails fast instead
        // of hanging. Falls back to Drop if nft add fails.
        nft_reject_and_repeat(&state.nft_binary, meta.dst_ip, meta.dst_port, meta.protocol)
    }
}

/// Production wrapper: calls `policy::check_destination` via the tokio runtime.
fn handle_packet(
    state: &mut NfqState,
    policy_socket: &str,
    timeout: Duration,
    message: &nfq_updated::Message,
    runtime: &tokio::runtime::Runtime,
) -> Verdict {
    let payload = message.get_payload();
    let mut check = |socket: &str,
                     hostname: &str,
                     dst_ip: &str,
                     dst_port: u16,
                     protocol: packet::TransportProtocol,
                     src_pid: Option<u32>,
                     to: Duration| {
        runtime.block_on(policy::check_destination(
            socket, hostname, dst_ip, dst_port, protocol, src_pid, to,
        ))
    };
    handle_packet_payload(state, policy_socket, timeout, payload, &mut check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    const DNS_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 100, 1));
    fn state_for_tests() -> NfqState {
        NfqState {
            dns_cache: DnsCache::new(None::<PathBuf>, DEFAULT_MAX_TTL),
            cache_path: None,
            dns_server_ip: DNS_IP,
            nft_binary: "false".to_string(),
        }
    }

    #[test]
    fn bypass_loopback_127_0_0_1() {
        assert!(is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            DNS_IP
        ));
    }

    #[test]
    fn bypass_loopback_any_port() {
        assert!(is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            DNS_IP
        ));
    }

    #[test]
    fn bypass_loopback_range_127_255_255_255() {
        assert!(is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255)),
            53,
            DNS_IP
        ));
    }

    #[test]
    fn bypass_ipv6_loopback() {
        assert!(is_bypass_traffic(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            80,
            DNS_IP
        ));
    }

    #[test]
    fn bypass_dns_server_port_53() {
        assert!(is_bypass_traffic(DNS_IP, 53, DNS_IP));
    }

    #[test]
    fn no_bypass_dns_server_non_dns_port() {
        // DNS server IP on port other than 53 still needs policy
        assert!(!is_bypass_traffic(DNS_IP, 443, DNS_IP));
    }

    #[test]
    fn no_bypass_regular_traffic() {
        assert!(!is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            DNS_IP
        ));
        assert!(!is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            DNS_IP
        ));
    }

    #[test]
    fn no_bypass_different_dns_ip() {
        let other_dns = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(is_bypass_traffic(other_dns, 53, other_dns));
        assert!(!is_bypass_traffic(other_dns, 53, DNS_IP));
    }

    #[test]
    fn no_bypass_non_loopback() {
        assert!(!is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            22,
            DNS_IP
        ));
    }

    #[test]
    fn repeated_destination_always_consults_policy() {
        let mut state = state_for_tests();
        state
            .dns_cache
            .remember_ephemeral("93.184.216.34", "example.com", 300);

        let pkt = build_udp_data_packet(443);

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        // First check: policy consulted.
        let v1 = handle_packet_payload(&mut state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v1, Verdict::Accept);
        assert_eq!(call_count.get(), 1);

        // Second check: policy consulted again (no NFQ-side verdict cache).
        let v2 = handle_packet_payload(&mut state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v2, Verdict::Accept);
        assert_eq!(call_count.get(), 2);
    }

    #[test]
    fn nft_reject_returns_repeat_when_insertion_succeeds() {
        // Mock a successful nft command.
        let mock_run = |_args: &[&str]| -> std::io::Result<std::process::Output> {
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        };
        let v = nft_reject_and_repeat_inner(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            packet::TransportProtocol::Tcp,
            mock_run,
        );
        assert_eq!(v, Verdict::Repeat);
    }

    #[test]
    fn nft_reject_falls_back_to_drop_on_failure() {
        // Mock a failing nft command.
        let mock_run = |_args: &[&str]| -> std::io::Result<std::process::Output> {
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(1),
                stdout: Vec::new(),
                stderr: b"nft: no such file".to_vec(),
            })
        };
        let v = nft_reject_and_repeat_inner(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            packet::TransportProtocol::Tcp,
            mock_run,
        );
        assert_eq!(v, Verdict::Drop);
    }

    fn build_dns_response_packet() -> Vec<u8> {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new();
        message
            .set_id(0x1234)
            .set_message_type(MessageType::Response)
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name,
                60,
                RData::A(A::new(93, 184, 216, 34)),
            ));
        let dns_payload = message.to_vec().expect("encode DNS response");
        let udp_len = 8 + dns_payload.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0_u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(
            &u16::try_from(total_len)
                .expect("packet length")
                .to_be_bytes(),
        );
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src_ip
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst_ip
        pkt[20..22].copy_from_slice(&53_u16.to_be_bytes()); // src_port=53 (DNS response)
        pkt[22..24].copy_from_slice(&53000_u16.to_be_bytes()); // dst_port
        pkt[24..26].copy_from_slice(&u16::try_from(udp_len).expect("udp length").to_be_bytes());
        pkt[28..].copy_from_slice(&dns_payload);
        pkt
    }

    fn build_dns_query_packet() -> Vec<u8> {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new();
        message
            .set_id(1)
            .set_recursion_desired(true)
            .add_query(Query::query(name, RecordType::A));
        let dns_payload = message.to_vec().expect("encode DNS query");
        let udp_len = 8 + dns_payload.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0_u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(
            &u16::try_from(total_len)
                .expect("packet length")
                .to_be_bytes(),
        );
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src_ip
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]); // dst_ip=8.8.8.8
        pkt[20..22].copy_from_slice(&43000_u16.to_be_bytes()); // src_port
        pkt[22..24].copy_from_slice(&53_u16.to_be_bytes()); // dst_port=53 (DNS query)
        pkt[24..26].copy_from_slice(&u16::try_from(udp_len).expect("udp length").to_be_bytes());
        pkt[28..].copy_from_slice(&dns_payload);
        pkt
    }

    fn build_udp_data_packet(dst_port: u16) -> Vec<u8> {
        let payload = b"hello";
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0_u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(
            &u16::try_from(total_len)
                .expect("packet length")
                .to_be_bytes(),
        );
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&50000_u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&u16::try_from(udp_len).expect("udp length").to_be_bytes());
        pkt[28..28 + payload.len()].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn dns_response_caches_hostname_mapping() {
        let mut state = state_for_tests();
        let pkt = build_dns_response_packet();

        let meta = packet::parse_ipv4(&pkt).expect("parse IPv4");
        assert_eq!(meta.protocol, packet::TransportProtocol::Udp);
        assert_eq!(meta.src_port, 53);

        let udp_data = packet::udp_payload(&pkt, &meta).expect("udp payload");
        let mappings = mappings_from_response(udp_data);
        assert_eq!(mappings.len(), 1);

        for m in &mappings {
            state
                .dns_cache
                .remember_ephemeral(&m.ip, &m.hostname, m.ttl.min(DEFAULT_MAX_TTL));
        }

        // Verify the IP is now cached to the hostname.
        let cached = state.dns_cache.lookup("93.184.216.34");
        assert_eq!(cached.as_deref(), Some("example.com"));
    }

    #[test]
    fn large_dns_response_over_128_bytes_still_maps_ip_to_hostname() {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new();
        message
            .set_id(0x1234)
            .set_message_type(MessageType::Response)
            .add_query(Query::query(name.clone(), RecordType::A));
        let ips: [[u8; 4]; 10] = [
            [93, 184, 216, 34],
            [93, 184, 216, 35],
            [93, 184, 216, 36],
            [93, 184, 216, 37],
            [93, 184, 216, 38],
            [93, 184, 216, 39],
            [93, 184, 216, 40],
            [93, 184, 216, 41],
            [93, 184, 216, 42],
            [93, 184, 216, 43],
        ];
        for &ip in &ips {
            message.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A::new(ip[0], ip[1], ip[2], ip[3])),
            ));
        }
        let dns_payload = message.to_vec().expect("encode DNS response");
        assert!(
            dns_payload.len() > 128,
            "DNS payload ({} bytes) must exceed 128 for this test",
            dns_payload.len()
        );

        let udp_len = 8 + dns_payload.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0_u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(
            &u16::try_from(total_len)
                .expect("packet length")
                .to_be_bytes(),
        );
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src_ip
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst_ip
        pkt[20..22].copy_from_slice(&53_u16.to_be_bytes()); // src_port=53 (DNS response)
        pkt[22..24].copy_from_slice(&53000_u16.to_be_bytes()); // dst_port
        pkt[24..26].copy_from_slice(&u16::try_from(udp_len).expect("udp length").to_be_bytes());
        pkt[28..].copy_from_slice(&dns_payload);

        let meta = packet::parse_ipv4(&pkt).expect("parse IPv4");
        assert_eq!(meta.src_port, 53);

        let udp_data = packet::udp_payload(&pkt, &meta).expect("udp payload");
        let mappings = mappings_from_response(udp_data);
        assert_eq!(mappings.len(), ips.len());
        for m in &mappings {
            assert_eq!(m.hostname, "example.com");
        }
    }

    #[test]
    fn dns_dst_port_53_is_parseable_as_dns_query() {
        let pkt = build_dns_query_packet();
        let meta = packet::parse_ipv4(&pkt).expect("parse IPv4");
        assert_eq!(meta.protocol, packet::TransportProtocol::Udp);
        assert_eq!(meta.dst_port, 53);
        assert!(meta.is_policy_boundary());
    }

    #[test]
    fn non_dns_udp_has_no_cached_mapping() {
        let state = state_for_tests();
        let pkt = build_udp_data_packet(443);

        let meta = packet::parse_ipv4(&pkt).expect("parse IPv4");
        assert_eq!(meta.protocol, packet::TransportProtocol::Udp);
        assert_ne!(meta.src_port, 53);
        assert_ne!(meta.dst_port, 53);
        assert!(meta.is_policy_boundary());

        assert!(state.dns_cache.lookup("93.184.216.34").is_none());
    }

    #[test]
    fn resolve_host_cache_miss_returns_raw_ip_no_ptr() {
        let mut state = state_for_tests();
        let result = state.resolve_host("93.184.216.34");
        assert_eq!(result, "93.184.216.34");
    }

    #[test]
    fn resolve_host_uses_in_memory_cache() {
        let mut state = state_for_tests();
        state
            .dns_cache
            .remember_ephemeral("93.184.216.34", "example.com", 300);
        let result = state.resolve_host("93.184.216.34");
        assert_eq!(result, "example.com");
    }

    #[test]
    fn resolve_host_uses_forwarder_cache_file() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agent-sandbox-nfq-dns-cache-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let mut writer = DnsCache::new(Some(&path), DEFAULT_MAX_TTL);
        writer.remember("104.20.23.154", "example.com", 300);
        let mut state = state_for_tests();
        state.cache_path = Some(path.clone());

        let result = state.resolve_host("104.20.23.154");

        assert_eq!(result, "example.com");
        assert_eq!(
            state.dns_cache.lookup("104.20.23.154").as_deref(),
            Some("example.com")
        );
        let _ = std::fs::remove_file(path);
    }
}
