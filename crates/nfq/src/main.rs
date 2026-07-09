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
    APPROVED_BINDINGS_PATH, ApprovedBindings, DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache,
    lookup_dns_cache, mappings_from_response,
};
use clap::Parser;
use nfq_updated::{Queue, Verdict};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Number of bytes to copy from each queued packet.
/// `u16::MAX` ensures the full UDP DNS response payload is available
/// for hickory-proto parsing (CNAME chains and multi-answer responses
/// routinely exceed the standard Ethernet MTU's 1500-byte segment).
const COPY_RANGE: u16 = u16::MAX;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-nfq",
    version,
    about = "NFQUEUE-based packet policy enforcer for the sandbox network namespace",
    long_about = "NFQUEUE packet interceptor that runs inside the agent-sandbox network \
        namespace. nftables queues outbound TCP SYN packets and all UDP packets here. \
        For each queued packet the daemon resolves the destination hostname from the \
        DNS forwarder in-memory cache (or the on-disk fallback), asks policyd for a \
        verdict, and either accepts the packet or actively rejects it via a transient \
        nftables set. Traffic to the local DNS forwarder on port 53 always bypasses \
        policyd so name resolution can never be blocked.\n\n\
        EXAMPLES:\n\
        # Run inside the sandbox netns with the default nftables queue number.\n\
        agent-sandbox-nfq\n\n\
        # Bind to a different NFQUEUE and accept a larger kernel-side queue.\n\
        agent-sandbox-nfq --queue 1 --queue-len 8192\n\n\
        # Point at a custom policyd and DNS push socket.\n\
        agent-sandbox-nfq \\\n\
            --policy-socket /run/agent-sandbox/policy.sock \\\n\
            --push-socket /run/agent-sandbox/dns-push.sock"
)]
struct Cli {
    /// NFQUEUE queue number. Must match the nftables "queue num" rule installed in the sandbox netns. 0 (the default) is the convention used by the NixOS module.
    #[arg(long, value_name = "NUM", default_value_t = 0)]
    queue: u16,

    /// Unix domain socket path used to ask policyd for a verdict on each queued packet.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    policy_socket: String,

    /// Max seconds to wait for a policyd verdict per packet check. Fractional values are accepted. The effective wait is clamped to at least 1 second. Larger values tolerate slow policyd startups but delay packet release.
    #[arg(long, value_name = "SECONDS", default_value_t = 305.0)]
    policy_timeout: f64,

    /// Maximum number of packets the kernel may hold while waiting for verdicts. Increase this if bursts of new outbound connections are getting dropped under load. 4096 is enough for typical agent traffic.
    #[arg(long, value_name = "PACKETS", default_value_t = 4096)]
    queue_len: u32,

    /// Path to the "nft" binary used to add destination IPs to the transient reject set. Override this for testing or non-standard installations.
    #[arg(long, value_name = "PATH", default_value = "nft")]
    nft_binary: String,

    /// DNS forwarder IP address (v4 or v6). Packets to this IP on port 53 are passed straight through without consulting policyd so the agent can always resolve names. 169.254.100.1 is the link-local address used by the default NixOS module.
    #[arg(long, value_name = "IP", default_value = "169.254.100.1")]
    dns_server_ip: IpAddr,

    /// Unix datagram socket path the DNS forwarder pushes fresh "{ip,host,ttl}" mappings to. If absent or unbindable the daemon falls back to the on-disk cache only.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/dns-push.sock"
    )]
    push_socket: PathBuf,

    /// Only accept DNS push frames from this peer uid (default: root / the host DNS forwarder).
    #[arg(long, value_name = "UID", default_value_t = 0)]
    push_trusted_uid: u32,
}
struct NfqState {
    dns_cache: Arc<std::sync::Mutex<DnsCache>>,
    approved_bindings: Arc<std::sync::Mutex<ApprovedBindings>>,
    #[allow(dead_code)]
    approved_bindings_path: PathBuf,
    cache_path: Option<PathBuf>,
    dns_server_ip: IpAddr,
    nft_binary: String,
}

impl NfqState {
    fn new(cli: &Cli) -> Self {
        // Memory-only cache for sniffed DNS-response mappings. Wrapped in a
        // Mutex so the push-socket listener thread can insert without
        // contending with the NFQUEUE recv loop.
        let dns_cache = DnsCache::new(None::<PathBuf>, DEFAULT_MAX_TTL);
        // Cache path for on-demand disk reloads from the DNS forwarder.
        let cache_path: Option<PathBuf> = std::env::var("AGENT_SANDBOX_DNS_CACHE").map_or_else(
            |_| Some(PathBuf::from(DEFAULT_CACHE_PATH)),
            |p| Some(PathBuf::from(p)),
        );
        let approved_bindings_path = std::env::var("AGENT_SANDBOX_APPROVED_BINDINGS")
            .map_or_else(|_| PathBuf::from(APPROVED_BINDINGS_PATH), PathBuf::from);
        let approved_bindings = ApprovedBindings::load(&approved_bindings_path);
        Self {
            dns_cache: Arc::new(std::sync::Mutex::new(dns_cache)),
            approved_bindings: Arc::new(std::sync::Mutex::new(approved_bindings)),
            approved_bindings_path,
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
    fn resolve_host(&self, ip: &str) -> String {
        if let Ok(cache) = self.dns_cache.lock()
            && let Some(host) = cache.lookup(ip)
        {
            return host;
        }
        let Some(host) = lookup_dns_cache(ip, self.cache_path.as_deref()) else {
            return ip.to_string();
        };
        if let Ok(mut cache) = self.dns_cache.lock() {
            cache.remember_ephemeral(ip, &host, DEFAULT_MAX_TTL);
        }
        host
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

    let state = NfqState::new(&cli);
    spawn_push_socket_listener(&cli.push_socket, cli.push_trusted_uid, &state);

    loop {
        let mut message = match queue.recv() {
            Ok(message) => message,
            Err(err) => {
                warn!(error = %err, "nfqueue recv error");
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let verdict = handle_packet(&state, &cli.policy_socket, timeout, &message, &runtime);
        message.set_verdict(verdict);
        if let Err(err) = queue.verdict(message) {
            warn!(error = %err, "nfqueue verdict error");
        }
    }
}

/// Background thread that consumes `{"ip","host","ttl"}` lines from the DNS
/// forwarder's push socket and inserts them into the in-memory cache. The
/// socket is optional: if `push_socket` does not exist or cannot be bound,
/// the daemon falls back to the on-disk cache only.
fn spawn_push_socket_listener(push_socket: &Path, trusted_uid: u32, state: &NfqState) {
    if !push_socket.exists()
        && let Some(parent) = push_socket.parent()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    // Remove any stale socket file so bind succeeds. The forwarder is a
    // client and does not own the socket file, so we always unlink before
    // binding.
    let _ = std::fs::remove_file(push_socket);
    let listener = match std::os::unix::net::UnixDatagram::bind(push_socket) {
        Ok(s) => s,
        Err(err) => {
            warn!(socket = %push_socket.display(), error = %err, "push socket bind failed");
            return;
        }
    };
    if let Err(err) = restrict_push_socket_permissions(push_socket) {
        warn!(socket = %push_socket.display(), error = %err, "push socket chmod failed");
    }
    if let Err(err) = enable_passcred(&listener) {
        warn!(socket = %push_socket.display(), error = %err, "push socket SO_PASSCRED failed");
        return;
    }
    info!(socket = %push_socket.display(), trusted_uid, "push socket listener bound");
    let cache = Arc::clone(&state.dns_cache);
    std::thread::Builder::new()
        .name("dns-push-listener".to_string())
        .spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, cred)) = recv_datagram_with_creds(&listener, &mut buf) else {
                    continue;
                };
                if cred.uid != trusted_uid {
                    warn!(
                        peer_uid = cred.uid,
                        peer_pid = cred.pid,
                        trusted_uid,
                        "push socket rejected untrusted peer"
                    );
                    continue;
                }
                let line = match std::str::from_utf8(&buf[..n]) {
                    Ok(s) => s,
                    Err(err) => {
                        debug!(error = %err, "push socket non-utf8 frame");
                        continue;
                    }
                };
                let line = line.trim_end_matches(['\n', '\r', '\0']);
                let parsed: Result<PushMapping, _> = serde_json::from_str(line);
                let Ok(entry) = parsed else {
                    debug!(line, "push socket malformed JSON");
                    continue;
                };
                apply_push_mapping(&cache, &entry);
            }
        })
        .expect("spawn push socket listener");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixPeerCred {
    pid: u32,
    uid: u32,
    gid: u32,
}

fn restrict_push_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn enable_passcred(sock: &std::os::unix::net::UnixDatagram) -> std::io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt::PassCred};

    setsockopt(sock, PassCred, &true).map_err(std::io::Error::from)
}

fn recv_datagram_with_creds(
    sock: &std::os::unix::net::UnixDatagram,
    buf: &mut [u8],
) -> std::io::Result<(usize, UnixPeerCred)> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::io::IoSliceMut;
    use std::os::unix::io::AsRawFd;

    let mut cmsg = [0u8; 128];
    let mut iov = [IoSliceMut::new(buf)];
    let msg: nix::sys::socket::RecvMsg<'_, '_, ()> = recvmsg(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    let cred = msg
        .cmsgs()?
        .find_map(|cmsg| match cmsg {
            ControlMessageOwned::ScmCredentials(cred) => Some(UnixPeerCred {
                pid: u32::try_from(cred.pid()).unwrap_or(u32::MAX),
                uid: cred.uid(),
                gid: cred.gid(),
            }),
            _ => None,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "push socket frame missing SCM_CREDENTIALS",
            )
        })?;
    Ok((msg.bytes, cred))
}

/// Apply a validated push mapping to the in-memory DNS cache.
fn apply_push_mapping(cache: &Arc<std::sync::Mutex<DnsCache>>, entry: &PushMapping) {
    if entry.host.is_empty() {
        return;
    }
    if let Ok(mut cache) = cache.lock() {
        cache.remember_ephemeral(&entry.ip, &entry.host, entry.ttl.min(DEFAULT_MAX_TTL));
    }
}

#[derive(serde::Deserialize)]
struct PushMapping {
    ip: String,
    host: String,
    #[serde(default)]
    ttl: u32,
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
    // DNS forwarder traffic on port 53 only
    dst_ip == dns_server_ip && dst_port == 53
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
fn handle_packet_payload<F>(
    state: &NfqState,
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
        &[String],
        Duration,
    ) -> std::io::Result<policy::PolicyResult>,
{
    // Try IPv4 first, then IPv6.
    let meta = packet::parse_ipv4(payload).or_else(|| packet::parse_ipv6(payload));
    let Some(meta) = meta else {
        warn!("dropping unparseable queued packet");
        return Verdict::Drop;
    };

    // UDP DNS responses: cache hostname mappings from the response and accept
    // only when the source is the configured forwarder. Responses from any
    // other source fall through to the policy-boundary path. A forged UDP/53
    // response from a non-forwarder source must not poison the IP->hostname
    // cache.
    if meta.protocol == packet::TransportProtocol::Udp
        && meta.src_port == 53
        && meta.src_ip == state.dns_server_ip
        && let Some(udp_data) = packet::udp_payload(payload, &meta)
    {
        let mappings = mappings_from_response(udp_data);
        if !mappings.is_empty() {
            if let Ok(mut cache) = state.dns_cache.lock() {
                for m in &mappings {
                    cache.remember_ephemeral(&m.ip, &m.hostname, m.ttl.min(DEFAULT_MAX_TTL));
                }
            }
            debug!(count = mappings.len(), "cached DNS response mappings");
        }
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
    let aliases = state
        .approved_bindings
        .lock()
        .map(|bindings| bindings.aliases(&dst_ip))
        .unwrap_or_default();
    let src_pid = owner::pid_from_src_port(meta.protocol, meta.src_ip, meta.src_port);
    let result = check(
        policy_socket,
        &hostname,
        &dst_ip,
        meta.dst_port,
        meta.protocol,
        src_pid,
        &aliases,
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
        if let Ok(mut bindings) = state.approved_bindings.lock() {
            bindings.record(&hostname, &dst_ip);
            let _ = bindings.save();
        }
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
    state: &NfqState,
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
                     aliases: &[String],
                     to: Duration| {
        runtime.block_on(policy::check_destination(
            socket,
            policy::CheckDestinationArgs {
                hostname,
                dst_ip,
                dst_port,
                protocol,
                src_pid,
                aliases,
            },
            to,
        ))
    };
    handle_packet_payload(state, policy_socket, timeout, payload, &mut check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    const DNS_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 100, 1));
    fn state_for_tests() -> NfqState {
        let mut approved_bindings_path = std::env::temp_dir();
        approved_bindings_path.push(format!(
            "agent-sandbox-nfq-bindings-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        NfqState {
            dns_cache: Arc::new(std::sync::Mutex::new(DnsCache::new(
                None::<PathBuf>,
                DEFAULT_MAX_TTL,
            ))),
            approved_bindings: Arc::new(std::sync::Mutex::new(ApprovedBindings::load(
                &approved_bindings_path,
            ))),
            approved_bindings_path,
            cache_path: None,
            dns_server_ip: DNS_IP,
            nft_binary: "false".to_string(),
        }
    }

    #[test]
    fn loopback_127_0_0_1_is_policy_bound() {
        assert!(!is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            DNS_IP
        ));
    }

    #[test]
    fn loopback_any_port_is_policy_bound() {
        assert!(!is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            DNS_IP
        ));
    }

    #[test]
    fn loopback_range_127_255_255_255_is_policy_bound() {
        assert!(!is_bypass_traffic(
            IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255)),
            53,
            DNS_IP
        ));
    }

    #[test]
    fn loopback_ipv6_is_policy_bound() {
        assert!(!is_bypass_traffic(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            80,
            DNS_IP
        ));
    }

    #[test]
    fn loopback_tcp_syn_invokes_policy_check() {
        let state = state_for_tests();
        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("127.0.0.1", "localhost", 300);
        let pkt = build_loopback_tcp_syn_packet();

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            call_count.get(),
            1,
            "loopback must go through policy check, not bypass"
        );
    }

    #[test]
    fn loopback_ipv6_tcp_syn_invokes_policy_check() {
        let state = state_for_tests();
        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("::1", "localhost", 300);
        let pkt = build_ipv6_loopback_tcp_syn_packet();

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            call_count.get(),
            1,
            "loopback IPv6 must go through policy check, not bypass"
        );
    }

    #[test]
    fn bypass_dns_server_port_53() {
        assert!(is_bypass_traffic(DNS_IP, 53, DNS_IP));
    }

    #[test]
    fn no_bypass_dns_server_non_dns_port() {
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
        let state = state_for_tests();
        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "example.com", 300);

        let pkt = build_udp_data_packet(443);

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        // First check: policy consulted.
        let v1 = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v1, Verdict::Accept);
        assert_eq!(call_count.get(), 1);

        // Second check: policy consulted again (no NFQ-side verdict cache).
        let v2 = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
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

    fn build_dns_response_packet(src_ip: [u8; 4]) -> Vec<u8> {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message
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
        pkt[12..16].copy_from_slice(&src_ip); // src_ip
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst_ip
        pkt[20..22].copy_from_slice(&53_u16.to_be_bytes()); // src_port=53 (DNS response)
        pkt[22..24].copy_from_slice(&53000_u16.to_be_bytes()); // dst_port
        pkt[24..26].copy_from_slice(&u16::try_from(udp_len).expect("udp length").to_be_bytes());
        pkt[28..].copy_from_slice(&dns_payload);
        pkt
    }

    fn build_dns_query_packet(dst_ip: [u8; 4]) -> Vec<u8> {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(name, RecordType::A));
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
        pkt[16..20].copy_from_slice(&dst_ip); // dst_ip
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

    fn build_loopback_tcp_syn_packet() -> Vec<u8> {
        let total_len: u16 = 40; // 20 IP + 20 TCP
        let mut pkt = vec![0_u8; usize::from(total_len)];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src_ip
        pkt[16..20].copy_from_slice(&[127, 0, 0, 1]); // dst_ip = loopback
        pkt[20..22].copy_from_slice(&50000_u16.to_be_bytes()); // src_port
        pkt[22..24].copy_from_slice(&80_u16.to_be_bytes()); // dst_port
        pkt[32] = 0x50; // data offset = 5 (20 bytes) << 4
        pkt[33] = 0x02; // SYN flag
        pkt
    }

    fn build_ipv6_loopback_tcp_syn_packet() -> Vec<u8> {
        // IPv6 header (40 bytes) + TCP header (20 bytes) = 60 bytes
        let total_len: u16 = 60;
        let mut pkt = vec![0_u8; usize::from(total_len)];
        pkt[0] = 0x60; // IPv6, version=6, traffic class=0, flow label=0
        // payload length: TCP header 20 bytes
        pkt[4..6].copy_from_slice(&20_u16.to_be_bytes());
        pkt[6] = 6; // next header = TCP
        pkt[7] = 64; // hop limit
        // src_ip = ::1 (loopback)
        pkt[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst_ip = ::1 (loopback)
        pkt[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[40..42].copy_from_slice(&50001_u16.to_be_bytes()); // src_port
        pkt[42..44].copy_from_slice(&443_u16.to_be_bytes()); // dst_port
        pkt[52] = 0x50; // data offset = 5
        pkt[53] = 0x02; // SYN flag
        pkt
    }

    #[test]
    fn dns_response_caches_hostname_mapping() {
        let state = state_for_tests();
        let pkt = build_dns_response_packet([169, 254, 100, 1]);

        let meta = packet::parse_ipv4(&pkt).expect("parse IPv4");
        assert_eq!(meta.protocol, packet::TransportProtocol::Udp);
        assert_eq!(meta.src_port, 53);

        let udp_data = packet::udp_payload(&pkt, &meta).expect("udp payload");
        let mappings = mappings_from_response(udp_data);
        assert_eq!(mappings.len(), 1);

        for m in &mappings {
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .remember_ephemeral(&m.ip, &m.hostname, m.ttl.min(DEFAULT_MAX_TTL));
        }

        // Verify the IP is now cached to the hostname.
        let cached = state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .lookup("93.184.216.34");
        assert_eq!(cached.as_deref(), Some("example.com"));
    }

    #[test]
    fn large_dns_response_over_128_bytes_still_maps_ip_to_hostname() {
        let name = Name::from_ascii("example.com.").expect("valid name");
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
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
        pkt[12..16].copy_from_slice(&[169, 254, 100, 1]); // src_ip
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
        let pkt = build_dns_query_packet([8, 8, 8, 8]);
        let meta = packet::parse_ipv4(&pkt).expect("parse IPv4");
        assert_eq!(meta.protocol, packet::TransportProtocol::Udp);
        assert_eq!(meta.dst_port, 53);
        assert!(meta.is_policy_boundary());
    }

    #[test]
    fn non_dns_udp_has_no_cached_mapping() {
        let state = state_for_tests();
        let _pkt = build_udp_data_packet(443);

        assert!(
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("93.184.216.34")
                .is_none()
        );
    }

    #[test]
    fn resolve_host_cache_miss_returns_raw_ip_no_ptr() {
        let state = state_for_tests();
        let result = state.resolve_host("93.184.216.34");
        assert_eq!(result, "93.184.216.34");
    }

    #[test]
    fn resolve_host_uses_in_memory_cache() {
        let state = state_for_tests();
        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
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
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("104.20.23.154")
                .as_deref(),
            Some("example.com")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn forged_dns_response_from_wrong_src_ip_does_not_cache_mapping() {
        let state = state_for_tests();
        let pkt = build_dns_response_packet([10, 0, 0, 2]);

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            call_count.get(),
            1,
            "forged DNS response must invoke the policy check"
        );
        assert!(
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("93.184.216.34")
                .is_none(),
            "forged DNS response must not populate the cache"
        );
    }

    #[test]
    fn dns_response_from_forwarder_caches_mapping() {
        let state = state_for_tests();
        let pkt = build_dns_response_packet([169, 254, 100, 1]);

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            call_count.get(),
            0,
            "legitimate forwarder response must not invoke policy check"
        );
        assert_eq!(
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("93.184.216.34")
                .as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn udp_53_to_non_forwarder_invokes_policy_check() {
        let state = state_for_tests();
        let pkt = build_dns_query_packet([8, 8, 8, 8]);

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            call_count.get(),
            1,
            "UDP/53 to non-forwarder must invoke policy check"
        );
    }

    #[test]
    fn udp_53_to_forwarder_bypasses_policy_check() {
        let state = state_for_tests();
        let pkt = build_dns_query_packet([169, 254, 100, 1]);

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            call_count.get(),
            0,
            "UDP/53 to forwarder must bypass policy check"
        );
    }

    #[test]
    fn approved_binding_aliases_passed_to_policy_check() {
        let state = state_for_tests();
        {
            let mut bindings = state.approved_bindings.lock().expect("lock bindings");
            bindings.record("chatgpt.com", "93.184.216.34");
        }
        let pkt = build_udp_data_packet(443);
        let aliases_seen = std::cell::RefCell::new(Vec::<String>::new());
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         aliases: &[String],
                         _: Duration| {
            *aliases_seen.borrow_mut() = aliases.to_vec();
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            aliases_seen.borrow().as_slice(),
            &["chatgpt.com".to_string()],
            "approved bindings aliases should be passed to policy check"
        );
    }

    #[test]
    fn push_mapping_applies_to_cache() {
        let state = state_for_tests();
        let entry = PushMapping {
            ip: "93.184.216.34".to_string(),
            host: "example.com".to_string(),
            ttl: 300,
        };
        apply_push_mapping(&state.dns_cache, &entry);
        assert_eq!(
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("93.184.216.34")
                .as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn push_socket_rejects_untrusted_peer_uid() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let socket_path = std::env::temp_dir().join(format!(
            "agent-sandbox-nfq-push-{}-{stamp}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = std::os::unix::net::UnixDatagram::bind(&socket_path).expect("bind listener");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod push socket");
        enable_passcred(&listener).expect("SO_PASSCRED");

        let state = state_for_tests();
        let cache = Arc::clone(&state.dns_cache);
        let listener_path = socket_path.clone();
        let listener_thread = std::thread::spawn(move || {
            let mut buf = [0_u8; 512];
            let Ok((n, cred)) = recv_datagram_with_creds(&listener, &mut buf) else {
                return false;
            };
            if cred.uid != 0 {
                return false;
            }
            let line = std::str::from_utf8(&buf[..n]).expect("utf8");
            let entry: PushMapping = serde_json::from_str(line.trim()).expect("json");
            apply_push_mapping(&cache, &entry);
            true
        });

        let sender = std::os::unix::net::UnixDatagram::unbound().expect("unbound sender");
        sender
            .send_to(
                br#"{"ip":"1.2.3.4","host":"evil.com","ttl":60}"#,
                &listener_path,
            )
            .expect("send push frame");
        let accepted = listener_thread.join().expect("listener thread");
        assert!(!accepted, "untrusted peer uid must not apply push mappings");
        assert!(
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .lookup("1.2.3.4")
                .is_none()
        );
        let _ = std::fs::remove_file(socket_path);
    }

    #[test]
    fn successful_accept_records_approved_binding() {
        let state = state_for_tests();
        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "example.com", 300);
        let pkt = build_udp_data_packet(443);

        let mut check =
            |_: &str,
             _: &str,
             _: &str,
             _: u16,
             _: packet::TransportProtocol,
             _: Option<u32>,
             _: &[String],
             _: Duration| Ok(policy::PolicyResult { allowed: true });

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        let aliases = state
            .approved_bindings
            .lock()
            .expect("lock bindings")
            .aliases("93.184.216.34");
        assert_eq!(aliases, vec!["example.com".to_string()]);
    }
    #[test]
    fn loopback_udp_53_invokes_policy_check() {
        let state = state_for_tests();
        let pkt = build_dns_query_packet([127, 0, 0, 1]);

        let call_count = std::cell::Cell::new(0u32);
        let mut check = |_: &str,
                         _: &str,
                         _: &str,
                         _: u16,
                         _: packet::TransportProtocol,
                         _: Option<u32>,
                         _: &[String],
                         _: Duration| {
            call_count.set(call_count.get() + 1);
            Ok(policy::PolicyResult { allowed: true })
        };

        let v = handle_packet_payload(&state, "", Duration::from_secs(1), &pkt, &mut check);
        assert_eq!(v, Verdict::Accept);
        assert_eq!(
            call_count.get(),
            1,
            "UDP/53 to loopback must invoke policy check"
        );
    }
    #[test]
    fn cli_defaults_preserve_standalone_fallbacks() {
        let cli = Cli::try_parse_from(["agent-sandbox-nfq"])
            .expect("standalone invocation has valid defaults");
        assert_eq!(cli.queue, 0);
        assert_eq!(cli.policy_socket, "/run/agent-sandbox/policy.sock");
        assert!((cli.policy_timeout - 305.0).abs() < f64::EPSILON);
        assert_eq!(cli.nft_binary, "nft");
        assert_eq!(
            cli.dns_server_ip,
            "169.254.100.1"
                .parse::<IpAddr>()
                .expect("valid default gateway")
        );
        assert_eq!(
            cli.push_socket,
            PathBuf::from("/run/agent-sandbox/dns-push.sock")
        );
    }

    #[test]
    fn cli_accepts_nix_supplied_launch_facts() {
        let cli = Cli::try_parse_from([
            "agent-sandbox-nfq",
            "--queue",
            "7",
            "--policy-socket",
            "/run/test/policy.sock",
            "--policy-timeout",
            "12.5",
            "--nft-binary",
            "/bin/nft-test",
            "--dns-server-ip",
            "192.0.2.1",
            "--push-socket",
            "/run/test/dns-push.sock",
        ])
        .expect("explicit launch facts parse");
        assert_eq!(cli.queue, 7);
        assert_eq!(cli.policy_socket, "/run/test/policy.sock");
        assert!((cli.policy_timeout - 12.5).abs() < f64::EPSILON);
        assert_eq!(cli.nft_binary, "/bin/nft-test");
        assert_eq!(
            cli.dns_server_ip,
            "192.0.2.1".parse::<IpAddr>().expect("valid test gateway")
        );
        assert_eq!(cli.push_socket, PathBuf::from("/run/test/dns-push.sock"));
    }
}
