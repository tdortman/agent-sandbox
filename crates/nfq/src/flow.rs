//! Flow handling: policy-boundary classification, the approved-flow fast
//! path, proxy flow registration, and the per-packet verdict decision.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    APPROVED_BINDINGS_PATH, ApprovedBindings, DEFAULT_CACHE_PATH, DEFAULT_MAX_TTL, DnsCache,
    FlowContext, FlowOwner, FlowRegistration, NetworkFlowKey, NetworkOwnership,
    NormalizedPolicyHost, OwnerSnapshot, SandboxPaths, SocketIdentity, lookup_dns_cache,
    mappings_from_response, sandbox_session_id_from_pid,
};
use nfq_updated::{Message, Verdict};
use tracing::{debug, info, warn};

use crate::{args::Cli, attribution, owner, packet, policy, policy::TransportCheck};

/// Packet mark used by the transparent proxy's local routing table.
const PROXY_MARK: u32 = 51820;

/// How long a registered proxy flow stays on the verdict fast path.
///
/// QUIC sends its opening burst of datagrams before the first packet's
/// registration RPC can confirm the conntrack entry, so the burst would
/// otherwise queue behind the serialised verdict loop.
const APPROVED_FLOW_TTL: Duration = Duration::from_secs(30);

/// Upper bound for the approved-flow fast path.
const MAX_APPROVED_FLOWS: usize = 4096;

struct ApprovedFlow {
    owner: SocketIdentity,
    inserted: Instant,
}

pub struct NfqState {
    pub(crate) dns_cache: Arc<std::sync::Mutex<DnsCache>>,
    attribution: Arc<Mutex<attribution::SessionAttribution>>,
    pub(crate) approved_bindings: Arc<std::sync::Mutex<ApprovedBindings>>,
    approved_flows: Arc<std::sync::Mutex<HashMap<NetworkFlowKey, ApprovedFlow>>>,
    cache_path: PathBuf,
    dns_server_ip: IpAddr,
    pub(crate) nft_binary: String,
    ownership: NetworkOwnership,
}

impl NfqState {
    pub(crate) fn new(cli: &Cli) -> Self {
        // Memory-only cache for sniffed DNS-response mappings. Wrapped in a
        // Mutex so the push-socket listener thread can insert without
        // contending with the NFQUEUE recv loop.
        let dns_cache = DnsCache::new(None::<PathBuf>, DEFAULT_MAX_TTL);

        // Cache path for on-demand disk reloads from the DNS forwarder.
        let cache_path = std::env::var_os("AGENT_SANDBOX_DNS_CACHE")
            .map_or_else(|| PathBuf::from(DEFAULT_CACHE_PATH), PathBuf::from);

        let approved_bindings_path = std::env::var("AGENT_SANDBOX_APPROVED_BINDINGS")
            .map_or_else(|_| PathBuf::from(APPROVED_BINDINGS_PATH), PathBuf::from);

        let approved_bindings = ApprovedBindings::load(&approved_bindings_path);

        Self {
            dns_cache: Arc::new(std::sync::Mutex::new(dns_cache)),
            approved_bindings: Arc::new(std::sync::Mutex::new(approved_bindings)),
            approved_flows: Arc::new(std::sync::Mutex::new(HashMap::new())),
            cache_path,
            attribution: Arc::new(Mutex::new(attribution::SessionAttribution::load(
                attribution::SESSION_ATTRIBUTION_PATH,
            ))),
            dns_server_ip: cli.dns_server_ip,
            nft_binary: cli.nft_binary.clone(),
            ownership: NetworkOwnership {
                proxy_mode: cli.proxy_mode,
                udp_proxy_ports: cli
                    .udp_proxy_ports
                    .split(',')
                    .filter_map(|port| port.trim().parse::<u16>().ok())
                    .collect(),
            },
        }
    }

    fn remember_attribution(&self, session_id: &str, ip: &str, hostname: &str) {
        let Ok(mut attribution) = self.attribution.lock() else {
            return;
        };

        if let Err(error) = attribution.remember(session_id, ip, hostname) {
            warn!(
                session_id,
                ip,
                hostname,
                error = %error,
                "failed to persist session hostname attribution"
            );
        }
    }

    /// Resolve an IP to a hostname.
    ///
    /// Tries the in-memory cache first. On miss, reloads from disk, the DNS
    /// forwarder has already written the mapping by the time the SYN arrives
    /// because the app cannot connect until DNS resolution completes. Returns
    /// the raw IP if the cache still has no entry (no PTR fallback).
    pub(crate) fn resolve_host_for_session(&self, ip: &str, session_id: Option<&str>) -> String {
        if let Ok(cache) = self.dns_cache.lock()
            && let Some(host) = cache.lookup(ip)
        {
            if let Some(session_id) = session_id {
                self.remember_attribution(session_id, ip, &host);
            }

            return host;
        }

        if let Some(session_id) = session_id
            && let Ok(attribution) = self.attribution.lock()
            && let Some(host) = attribution.lookup(session_id, ip)
        {
            return host.to_owned();
        }

        let Some(host) = lookup_dns_cache(ip, Some(&self.cache_path)) else {
            return ip.to_string();
        };

        if let Ok(mut cache) = self.dns_cache.lock() {
            cache.remember_ephemeral(ip, &host, DEFAULT_MAX_TTL);
        }

        if let Some(session_id) = session_id {
            self.remember_attribution(session_id, ip, &host);
        }

        host
    }
}

/// Mark an accepted configured HTTP/3 datagram so NFQUEUE reinjection reroutes
/// it locally.
pub fn mark_accepted_proxy_udp(
    state: &NfqState,
    message: &mut Message,
    verdict: Verdict,
    meta: Option<packet::PacketMeta>,
) {
    if verdict != Verdict::Accept {
        return;
    }

    if !state.ownership.proxy_mode {
        return;
    }

    // Reuse the metadata parsed by handle_packet; do not re-parse the payload.
    let Some(meta) = meta else {
        return;
    };

    let dns_response = meta.protocol == packet::TransportProtocol::Udp
        && meta.src_ip == state.dns_server_ip
        && meta.src_port == 53;

    if !dns_response
        && matches!(
            state
                .ownership
                .flow_owner(packet::TransportProtocol::Udp, meta.dst_ip, meta.dst_port),
            FlowOwner::ProxyBackend
        )
    {
        message.set_nfmark(PROXY_MARK);
    }
}

/// Whether this flow was registered recently and can skip the verdict RPCs.
///
/// The cache covers the QUIC opening burst: every datagram of a flow is a
/// policy boundary, but only the first one needs the owner snapshot and the
/// policyd registration round trip.
fn is_approved_flow(
    state: &NfqState,
    meta: packet::PacketMeta,
    owner: Option<SocketIdentity>,
) -> bool {
    let Some(owner) = owner else {
        return false;
    };

    let protocol = meta.protocol;

    let Ok(flow) = NetworkFlowKey::try_new(
        protocol,
        meta.src_ip,
        meta.src_port,
        meta.dst_ip,
        meta.dst_port,
    ) else {
        return false;
    };

    state.approved_flows.lock().is_ok_and(|flows| {
        flows.get(&flow).is_some_and(|approved| {
            approved.owner == owner && approved.inserted.elapsed() < APPROVED_FLOW_TTL
        })
    })
}

/// Remember a registered flow on the verdict fast path, pruning expired
/// entries so the cache stays bounded.
fn remember_approved_flow(state: &NfqState, key: &NetworkFlowKey, owner: SocketIdentity) -> bool {
    let Ok(mut flows) = state.approved_flows.lock() else {
        return false;
    };

    flows.retain(|_, approved| approved.inserted.elapsed() < APPROVED_FLOW_TTL);

    if flows.len() >= MAX_APPROVED_FLOWS {
        return false;
    }

    flows.insert(key.clone(), ApprovedFlow {
        owner,
        inserted: Instant::now(),
    });
    true
}

fn register_proxy_flow(
    state: &NfqState,
    meta: packet::PacketMeta,
    owner: Option<OwnerSnapshot>,
    register: &mut dyn FnMut(FlowRegistration) -> std::io::Result<bool>,
) -> Verdict {
    let Some(owner) = owner else {
        warn!(
            src = %meta.src_ip,
            port = meta.src_port,
            protocol = meta.protocol.as_str(),
            "proxy flow has no unique socket owner"
        );

        return Verdict::Drop;
    };

    let session_id = sandbox_session_id_from_pid(owner.pid_value());
    let dst_ip = meta.dst_ip.to_string();
    let hostname = state.resolve_host_for_session(&dst_ip, session_id.as_deref());

    let Ok(policy_host) = NormalizedPolicyHost::parse(&hostname) else {
        warn!(host = %hostname, "dropping proxy flow with invalid policy host");
        return Verdict::Drop;
    };

    let protocol = meta.protocol;

    let Ok(flow) = NetworkFlowKey::try_new(
        protocol,
        meta.src_ip,
        meta.src_port,
        meta.dst_ip,
        meta.dst_port,
    ) else {
        warn!(
            src = %meta.src_ip,
            src_port = meta.src_port,
            dst = %meta.dst_ip,
            dst_port = meta.dst_port,
            "proxy flow has an invalid typed tuple"
        );

        return Verdict::Drop;
    };

    let registration = FlowRegistration::new(
        flow.clone(),
        owner.identity(),
        policy_host,
        FlowContext::new(SandboxPaths::default(), session_id),
    );

    match register(registration) {
        Ok(true) if remember_approved_flow(state, &flow, owner.identity()) => {
            info!(
                protocol = meta.protocol.as_str(),
                src = %meta.src_ip,
                src_port = meta.src_port,
                dst = %meta.dst_ip,
                dst_port = meta.dst_port,
                "registered proxy flow"
            );
            Verdict::Accept
        }

        Ok(true) => {
            warn!("dropping proxy flow because the approval cache is full");
            Verdict::Drop
        }

        Ok(false) => {
            warn!("policyd rejected proxy flow registration");
            Verdict::Drop
        }

        Err(error) => {
            warn!(%error, "proxy flow registration failed");
            Verdict::Drop
        }
    }
}

/// Core packet handling logic, parameterized over policy and proxy
/// registration.
///
/// Seam for unit testing: inject a mock `check` to verify policy is consulted.
/// Returns the verdict and the parsed packet metadata, so callers can apply
/// side effects (such as the proxy nfmark) without re-parsing the payload.
pub fn handle_packet_payload_with_registration(
    state: &NfqState,
    payload: &[u8],
    check: &mut dyn FnMut(policy::CheckDestinationArgs<'_>) -> std::io::Result<bool>,
    register: Option<&mut dyn FnMut(FlowRegistration) -> std::io::Result<bool>>,
) -> (Verdict, Option<packet::PacketMeta>) {
    // Try IPv4 first, then IPv6.
    let meta = packet::parse_ipv4(payload).or_else(|| packet::parse_ipv6(payload));

    let Some(meta) = meta else {
        warn!("dropping unparseable queued packet");
        return (Verdict::Drop, None);
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

        return (Verdict::Accept, Some(meta));
    }

    if policy::is_bypass_traffic(meta.dst_ip, meta.dst_port, state.dns_server_ip) {
        debug!(ip = %meta.dst_ip, port = meta.dst_port, "bypass policy");
        return (Verdict::Accept, Some(meta));
    }

    info!(
        protocol = meta.protocol.as_str(),
        src = %meta.src_ip,
        src_port = meta.src_port,
        dst = %meta.dst_ip,
        dst_port = meta.dst_port,
        policy_boundary = meta.is_policy_boundary(),
        "inspected policy packet"
    );

    if !meta.is_policy_boundary() {
        return (Verdict::Accept, Some(meta));
    }

    // Loopback traffic never traverses the transparent proxy route. Proxy-mode
    // flows are registered and accepted here so the proxy can decode them and
    // enforce HTTP policy per request. All other destinations stay on the
    // ordinary kernel route and are checked synchronously below.

    let source_owner = owner::owner_snapshot(meta.protocol, meta.src_ip, meta.src_port);
    let src_pid = source_owner.map(OwnerSnapshot::pid_value);

    let session_id = src_pid.and_then(sandbox_session_id_from_pid);

    let proxy_flow = matches!(
        state
            .ownership
            .flow_owner(meta.protocol, meta.dst_ip, meta.dst_port),
        FlowOwner::ProxyBackend
    );

    // QUIC sends its opening burst of datagrams before the first packet's
    // verdict can confirm the flow, so already-registered flows skip the
    // verdict RPCs entirely.
    if proxy_flow && is_approved_flow(state, meta, source_owner.map(OwnerSnapshot::identity)) {
        return (Verdict::Accept, Some(meta));
    }

    if proxy_flow {
        let Some(register) = register else {
            warn!("proxy mode has no registration RPC handler");
            return (Verdict::Drop, Some(meta));
        };

        // Proxy-owned flows are classified by decoded HTTP requests. The
        // initial HTTP/3 packet must not use network.direct, or HTTP/3 would
        // need a second transport policy rule before reaching HTTP policy.
        let verdict = register_proxy_flow(state, meta, source_owner, register);
        return (verdict, Some(meta));
    }

    let allowed = match policy::transport_check(
        state,
        meta,
        src_pid,
        session_id.as_deref(),
        source_owner.map(OwnerSnapshot::identity),
        check,
    ) {
        TransportCheck::Rejected(verdict) => return (verdict, Some(meta)),
        TransportCheck::Allowed(destination) => destination,
    };

    info!(
        protocol = meta.protocol.as_str(),
        host = %allowed.hostname,
        dst = %allowed.dst_ip,
        port = meta.dst_port,
        "accept"
    );

    (Verdict::Accept, Some(meta))
}

/// Production wrapper: calls `policy::check_destination` via the tokio runtime.
pub fn handle_packet(
    state: &NfqState,
    policy_socket: &str,
    timeout: Duration,
    message: &nfq_updated::Message,
    runtime: &tokio::runtime::Runtime,
) -> (Verdict, Option<packet::PacketMeta>) {
    let payload = message.get_payload();

    let mut check = |args: policy::CheckDestinationArgs<'_>| {
        runtime.block_on(policy::check_destination(policy_socket, args, timeout))
    };

    let mut register = |registration: FlowRegistration| {
        runtime.block_on(policy::register_network_flow(
            policy_socket,
            registration,
            timeout,
        ))
    };

    handle_packet_payload_with_registration(state, payload, &mut check, Some(&mut register))
}

#[cfg(test)]
pub mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        path::{Path, PathBuf},
        time::Duration,
    };

    use agent_sandbox_core::FlowProtocol;
    use clap::Parser;
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };

    use super::*;

    pub const DNS_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 100, 1));

    pub fn state_for_tests() -> NfqState {
        state_for_tests_with_attribution_path(None)
    }

    fn state_for_tests_with_attribution_path(attribution_path: Option<&Path>) -> NfqState {
        let mut approved_bindings_path = std::env::temp_dir();

        approved_bindings_path.push(format!(
            "agent-sandbox-nfq-bindings-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));

        let attribution = attribution_path.map_or_else(
            attribution::SessionAttribution::new,
            attribution::SessionAttribution::load,
        );

        NfqState {
            dns_cache: Arc::new(std::sync::Mutex::new(DnsCache::new(
                None::<PathBuf>,
                DEFAULT_MAX_TTL,
            ))),
            attribution: Arc::new(Mutex::new(attribution)),
            approved_bindings: Arc::new(std::sync::Mutex::new(ApprovedBindings::load(
                &approved_bindings_path,
            ))),
            approved_flows: Arc::new(std::sync::Mutex::new(HashMap::new())),
            cache_path: PathBuf::from(DEFAULT_CACHE_PATH),
            dns_server_ip: DNS_IP,
            nft_binary: "false".to_string(),
            ownership: NetworkOwnership {
                proxy_mode: false,
                udp_proxy_ports: vec![443],
            },
        }
    }

    #[test]
    fn udp_proxy_ports_are_configurable() {
        let state = NfqState::new(&Cli::parse_from([
            "nfq",
            "--proxy-mode",
            "--udp-proxy-ports",
            "443,4444",
        ]));

        assert_eq!(
            state.ownership.flow_owner(
                packet::TransportProtocol::Udp,
                "93.184.216.34".parse().expect("public IP"),
                4444
            ),
            FlowOwner::ProxyBackend
        );
        assert_eq!(
            state.ownership.flow_owner(
                packet::TransportProtocol::Udp,
                "93.184.216.34".parse().expect("public IP"),
                8443
            ),
            FlowOwner::DirectPolicy
        );
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

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

        assert_eq!(v, Verdict::Accept);

        assert_eq!(
            call_count.get(),
            1,
            "loopback must go through policy check, not bypass"
        );
    }

    #[test]
    fn proxy_mode_registers_public_flow_without_transport_check() {
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");

        let listener_addr = listener.local_addr().expect("listener address");
        let client = std::net::TcpStream::connect(listener_addr).expect("connect client");
        let (_server, _) = listener.accept().expect("accept client");
        let client_addr = client.local_addr().expect("client address");
        let mut state = state_for_tests();
        state.ownership.proxy_mode = true;

        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "example.test", DEFAULT_MAX_TTL);

        state.nft_binary = "true".to_string();
        let mut packet = build_loopback_tcp_syn_packet();

        packet[12..16].copy_from_slice(
            &client_addr
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .expect("IPv4 client")
                .octets(),
        );

        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        packet[20..22].copy_from_slice(&client_addr.port().to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        let check_count = std::cell::Cell::new(0_u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            check_count.set(check_count.get() + 1);
            Ok(true)
        };

        let registration = std::cell::RefCell::new(None);

        let mut register = |flow: FlowRegistration| {
            assert_eq!(
                check_count.get(),
                0,
                "proxy registration must precede transport fallback checks"
            );

            *registration.borrow_mut() = Some(flow);
            Ok(true)
        };

        let (verdict, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(verdict, Verdict::Accept);

        assert_eq!(
            check_count.get(),
            0,
            "proxy mode must defer transport checks to decoded HTTP or fallback"
        );

        let registration = registration
            .into_inner()
            .expect("proxy mode must register the flow");

        assert_eq!(registration.flow.protocol, FlowProtocol::Tcp);
        assert_eq!(registration.flow.source_ip, client_addr.ip());

        assert_eq!(
            registration.flow.destination_ip,
            "93.184.216.34".parse::<Ipv4Addr>().expect("valid IPv4")
        );

        assert_eq!(registration.policy_host.to_string(), "example.test");
    }

    #[test]
    fn proxy_mode_udp_flow_registers_without_transport_check() {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind udp socket");

        let client_addr = socket.local_addr().expect("socket address");
        let mut state = state_for_tests();
        state.ownership.proxy_mode = true;

        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "example.test", DEFAULT_MAX_TTL);

        state.nft_binary = "true".to_string();
        let mut packet = build_udp_data_packet(443);

        packet[12..16].copy_from_slice(
            &client_addr
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .expect("IPv4 client")
                .octets(),
        );

        packet[20..22].copy_from_slice(&client_addr.port().to_be_bytes());
        let check_count = std::cell::Cell::new(0_u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            check_count.set(check_count.get() + 1);
            Ok(false)
        };

        let registration = std::cell::RefCell::new(None);

        let mut register = |flow: FlowRegistration| {
            assert_eq!(
                check_count.get(),
                0,
                "UDP proxy registration must bypass the transport check"
            );

            *registration.borrow_mut() = Some(flow);
            Ok(true)
        };

        let (verdict, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(verdict, Verdict::Accept);
        assert_eq!(
            check_count.get(),
            0,
            "HTTP/3 must reach decoded HTTP policy without network.direct"
        );

        let registration = registration
            .into_inner()
            .expect("UDP proxy flow must register before HTTP policy");

        assert_eq!(registration.flow.protocol, FlowProtocol::Udp);
        assert_eq!(registration.flow.source_ip, client_addr.ip());
        assert_eq!(
            registration.flow.destination_ip,
            "93.184.216.34".parse::<Ipv4Addr>().expect("valid IPv4")
        );
    }

    #[test]
    fn proxy_mode_udp_flow_without_owner_drops_before_transport_check() {
        let source_ip = Ipv4Addr::new(192, 0, 2, 1);
        let source_port: u16 = 49152;
        let mut state = state_for_tests();
        state.ownership.proxy_mode = true;

        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "example.test", DEFAULT_MAX_TTL);

        let mut packet = build_udp_data_packet(443);
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());

        assert!(
            owner::owner_snapshot(
                packet::TransportProtocol::Udp,
                source_ip.into(),
                source_port
            )
            .is_none(),
            "test tuple must not have a socket owner"
        );

        let check_count = std::cell::Cell::new(0_u32);
        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            check_count.set(check_count.get() + 1);
            Ok(true)
        };

        let registration_count = std::cell::Cell::new(0_u32);
        let mut register = |_: FlowRegistration| {
            registration_count.set(registration_count.get() + 1);
            Ok(true)
        };

        let (verdict, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(verdict, Verdict::Drop);
        assert_eq!(
            check_count.get(),
            0,
            "unowned HTTP/3 flows must not use network.direct"
        );
        assert_eq!(registration_count.get(), 0);
    }

    #[test]
    fn proxy_mode_udp_flow_fast_path_skips_verdict_rpcs() {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind udp socket");

        let client_addr = socket.local_addr().expect("socket address");
        let mut state = state_for_tests();
        state.ownership.proxy_mode = true;
        state.nft_binary = "true".to_string();

        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "example.test", DEFAULT_MAX_TTL);

        let mut packet = build_udp_data_packet(443);

        packet[12..16].copy_from_slice(
            &client_addr
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .expect("IPv4 client")
                .octets(),
        );

        packet[20..22].copy_from_slice(&client_addr.port().to_be_bytes());
        let check_count = std::cell::Cell::new(0_u32);
        let registration_count = std::cell::Cell::new(0_u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            check_count.set(check_count.get() + 1);
            Ok(true)
        };

        let mut register = |_: FlowRegistration| {
            registration_count.set(registration_count.get() + 1);
            Ok(true)
        };

        // First packet of the flow: registration without a transport check.
        let (first, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(first, Verdict::Accept);
        assert_eq!(check_count.get(), 0);
        assert_eq!(registration_count.get(), 1);

        // QUIC opening burst: the same flow skips both callbacks on the fast path.
        let (second, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(second, Verdict::Accept);
        assert_eq!(check_count.get(), 0);
        assert_eq!(registration_count.get(), 1);
    }

    #[test]
    fn proxy_mode_udp_flow_registration_denial_drops() {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind udp socket");

        let client_addr = socket.local_addr().expect("socket address");
        let mut state = state_for_tests();
        state.ownership.proxy_mode = true;

        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "denied.test", DEFAULT_MAX_TTL);

        state.nft_binary = "true".to_string();
        let mut packet = build_udp_data_packet(443);

        packet[12..16].copy_from_slice(
            &client_addr
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .expect("IPv4 client")
                .octets(),
        );

        packet[20..22].copy_from_slice(&client_addr.port().to_be_bytes());
        let check_count = std::cell::Cell::new(0_u32);
        let registration_count = std::cell::Cell::new(0_u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            check_count.set(check_count.get() + 1);
            Ok(false)
        };

        let mut register = |_: FlowRegistration| {
            registration_count.set(registration_count.get() + 1);
            Ok(false)
        };

        let (verdict, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(verdict, Verdict::Drop);
        assert_eq!(
            check_count.get(),
            0,
            "HTTP/3 registration denial must not run network.direct"
        );
        assert_eq!(
            registration_count.get(),
            1,
            "denied HTTP/3 flow must be rejected by registration"
        );

        assert!(
            state
                .approved_flows
                .lock()
                .expect("lock approved flows")
                .is_empty(),
            "denied UDP proxy flow must not enter the approved-flow fast path"
        );
    }

    #[test]
    fn proxy_mode_drops_when_approval_cache_cannot_mark_flow() {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind udp socket");
        let client_addr = socket.local_addr().expect("socket address");
        let mut state = state_for_tests();
        state.ownership.proxy_mode = true;

        {
            let mut flows = state.approved_flows.lock().expect("lock approved flows");
            let owner = owner::owner_snapshot(
                packet::TransportProtocol::Udp,
                client_addr.ip(),
                client_addr.port(),
            )
            .expect("test owner");
            for port in 1..=MAX_APPROVED_FLOWS {
                let flow = NetworkFlowKey::try_new(
                    FlowProtocol::Udp,
                    Ipv4Addr::new(192, 0, 2, 1).into(),
                    port.try_into().expect("test port fits"),
                    Ipv4Addr::new(198, 51, 100, 1).into(),
                    443,
                )
                .expect("valid test flow");
                flows.insert(flow, ApprovedFlow {
                    owner: owner.identity(),
                    inserted: Instant::now(),
                });
            }
        }

        let mut packet = build_udp_data_packet(443);
        packet[12..16].copy_from_slice(
            &client_addr
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .expect("IPv4 client")
                .octets(),
        );
        packet[20..22].copy_from_slice(&client_addr.port().to_be_bytes());

        let mut check = |_args: policy::CheckDestinationArgs<'_>| Ok(true);

        let mut register = |_: FlowRegistration| Ok(true);

        let (verdict, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(
            verdict,
            Verdict::Drop,
            "an accepted registration without a route mark must fail closed"
        );
    }

    #[test]
    fn proxy_mode_checks_loopback_transport_without_proxy_registration() {
        let state = {
            let mut state = state_for_tests();
            state.ownership.proxy_mode = true;
            state
                .dns_cache
                .lock()
                .expect("lock dns cache")
                .remember_ephemeral("127.0.0.1", "localhost", DEFAULT_MAX_TTL);
            state
        };

        let packet = build_loopback_tcp_syn_packet();
        let check_count = std::cell::Cell::new(0_u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            check_count.set(check_count.get() + 1);
            Ok(false)
        };

        let registration_count = std::cell::Cell::new(0_u32);

        let mut register = |_: FlowRegistration| {
            registration_count.set(registration_count.get() + 1);
            Ok(true)
        };

        let (verdict, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(verdict, Verdict::Drop);

        assert_eq!(
            check_count.get(),
            1,
            "proxy mode must check loopback transport"
        );

        assert_eq!(
            registration_count.get(),
            0,
            "loopback must not register for proxy interception"
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

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

        assert_eq!(v, Verdict::Accept);

        assert_eq!(
            call_count.get(),
            1,
            "loopback IPv6 must go through policy check, not bypass"
        );
    }

    #[test]
    fn proxy_mode_checks_ipv6_loopback_transport_without_proxy_registration() {
        let mut state = state_for_tests();
        state.ownership.proxy_mode = true;

        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("::1", "localhost", DEFAULT_MAX_TTL);

        let packet = build_ipv6_loopback_tcp_syn_packet();
        let check_count = std::cell::Cell::new(0_u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            check_count.set(check_count.get() + 1);
            Ok(false)
        };

        let registration_count = std::cell::Cell::new(0_u32);

        let mut register = |_: FlowRegistration| {
            registration_count.set(registration_count.get() + 1);
            Ok(true)
        };

        let (verdict, _) = handle_packet_payload_with_registration(
            &state,
            &packet,
            &mut check,
            Some(&mut register),
        );

        assert_eq!(verdict, Verdict::Drop);

        assert_eq!(
            check_count.get(),
            1,
            "proxy mode must check IPv6 loopback transport"
        );

        assert_eq!(
            registration_count.get(),
            0,
            "IPv6 loopback must not register for proxy interception"
        );
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

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        // First check: policy consulted.
        let (v1, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

        assert_eq!(v1, Verdict::Accept);
        assert_eq!(call_count.get(), 1);

        // Second check: policy consulted again (no NFQ-side verdict cache).
        let (v2, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

        assert_eq!(v2, Verdict::Accept);
        assert_eq!(call_count.get(), 2);
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

    pub fn build_udp_data_packet(dst_port: u16) -> Vec<u8> {
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
        let result = state.resolve_host_for_session("93.184.216.34", None);
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

        let result = state.resolve_host_for_session("93.184.216.34", None);
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
        state.cache_path = path.clone();
        let result = state.resolve_host_for_session("104.20.23.154", None);
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
    fn disk_mapping_survives_dns_cache_expiry_only_for_attributed_session() {
        let mut path = std::env::temp_dir();

        path.push(format!(
            "agent-sandbox-nfq-dns-attribution-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));

        let mut writer = DnsCache::new(Some(&path), DEFAULT_MAX_TTL);
        writer.remember("104.20.23.154", "example.com", 300);
        let mut state = state_for_tests();
        state.cache_path = path.clone();

        assert_eq!(
            state.resolve_host_for_session("104.20.23.154", Some("session-a")),
            "example.com"
        );

        let _ = std::fs::remove_file(&path);

        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("104.20.23.154", "temporary.example", 1);

        std::thread::sleep(Duration::from_millis(1_100));

        assert_eq!(
            state.resolve_host_for_session("104.20.23.154", Some("session-a")),
            "example.com"
        );

        assert_eq!(
            state.resolve_host_for_session("104.20.23.154", Some("session-b")),
            "104.20.23.154"
        );

        assert_eq!(
            state.resolve_host_for_session("104.20.23.154", None),
            "104.20.23.154"
        );
    }

    #[test]
    fn resolve_host_uses_persisted_attribution_after_nfqueue_restart() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();

        let attribution_path = std::env::temp_dir().join(format!(
            "agent-sandbox-nfq-restart-attribution-{}-{stamp}.json",
            std::process::id()
        ));

        let mut writer = attribution::SessionAttribution::load(&attribution_path);

        writer
            .remember("session-a", "93.184.216.34", "example.com")
            .expect("persist attribution");

        let restarted = state_for_tests_with_attribution_path(Some(&attribution_path));

        assert_eq!(
            restarted.resolve_host_for_session("93.184.216.34", Some("session-a")),
            "example.com"
        );

        assert_eq!(
            restarted.resolve_host_for_session("93.184.216.34", Some("session-b")),
            "93.184.216.34"
        );

        std::fs::remove_file(attribution_path).expect("remove attribution state");
    }

    #[test]
    fn forged_dns_response_from_wrong_src_ip_does_not_cache_mapping() {
        let state = state_for_tests();
        let pkt = build_dns_response_packet([10, 0, 0, 2]);
        let call_count = std::cell::Cell::new(0u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

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

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

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

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

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

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

        assert_eq!(v, Verdict::Accept);

        assert_eq!(
            call_count.get(),
            0,
            "UDP/53 to forwarder must bypass policy check"
        );
    }

    #[test]
    fn loopback_udp_53_invokes_policy_check() {
        let state = state_for_tests();
        let pkt = build_dns_query_packet([127, 0, 0, 1]);
        let call_count = std::cell::Cell::new(0u32);

        let mut check = |_args: policy::CheckDestinationArgs<'_>| {
            call_count.set(call_count.get() + 1);
            Ok(true)
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);

        assert_eq!(v, Verdict::Accept);

        assert_eq!(
            call_count.get(),
            1,
            "UDP/53 to loopback must invoke policy check"
        );
    }
}
