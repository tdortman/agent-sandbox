//! Persistent policy RPCs, sequential within each NFQUEUE worker. Failed
//! requests are never replayed.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use agent_sandbox_core::{
    FlowRegistration, PersistentRpcClient, RequestContext, RpcReply, RpcRequest, VerdictSource,
    attach_check_aliases, daemon_context, persist_session_paths, verdict_map::VERDICT_DENY,
};
use nfq_updated::Verdict;
use tracing::{debug, info, warn};

use crate::{flow::NfqState, packet, packet::TransportProtocol};

/// Inputs for a single policy check, grouped to keep the call signature small.
pub struct CheckDestinationArgs<'a> {
    pub hostname: &'a str,
    pub dst_ip: &'a str,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    pub src_pid: Option<u32>,
    pub aliases: &'a [String],
}

/// Outcome of one policyd transport decision, keeping the source so the
/// verdict cache can tell replayable static verdicts from consumable
/// approvals.
pub struct DestinationVerdict {
    /// Whether policyd allowed the destination.
    pub allowed: bool,
    /// Source reported by policyd, or `None` when the denial is a local
    /// fail-closed (malformed reply) rather than a policyd decision.
    pub source: Option<VerdictSource>,
}

impl DestinationVerdict {
    /// Allowed verdict with the given source.
    #[must_use]
    pub const fn allowed(source: VerdictSource) -> Self {
        Self {
            allowed: true,
            source: Some(source),
        }
    }

    /// Denied verdict with the given source.
    #[must_use]
    pub const fn denied(source: VerdictSource) -> Self {
        Self {
            allowed: false,
            source: Some(source),
        }
    }

    /// Local fail-closed deny: never published, as it records a transient
    /// error rather than a decision.
    #[must_use]
    pub const fn fail_closed() -> Self {
        Self {
            allowed: false,
            source: None,
        }
    }
}

/// Check whether a destination is allowed by policy.
///
/// `hostname` should be pre-resolved by the caller (DNS cache or PTR).
/// Blocks until policyd responds (which may wait for user approval).
pub async fn check_destination(
    client: &mut PersistentRpcClient,
    args: CheckDestinationArgs<'_>,
    timeout: Duration,
) -> DestinationVerdict {
    let ctx = daemon_context(args.src_pid);
    persist_session_paths(&ctx.paths);
    let scheme = args.protocol.as_str();
    let hostname = args.hostname.to_string();
    let dst_port = args.dst_port;
    let url = format!("{scheme}://{hostname}:{dst_port}");

    let req = RpcRequest::Check {
        host: Some(hostname.clone()),
        connect_host: Some(args.dst_ip.to_string()),
        port: Some(args.dst_port),
        scheme: scheme.to_string(),
        url: attach_check_aliases(Some(url), args.aliases),
        ctx: RequestContext::from(&ctx),
    };

    let result = client.request(req, timeout).await;
    let Ok(resp) = result.inspect_err(|error| {
        warn!(
            host = %hostname,
            port = dst_port,
            %error,
            "destination check failed; failing closed"
        );
    }) else {
        return DestinationVerdict::fail_closed();
    };

    if let RpcReply::Check(check) = resp {
        if check.verdict.allowed {
            DestinationVerdict::allowed(check.verdict.source)
        } else {
            DestinationVerdict::denied(check.verdict.source)
        }
    } else {
        client.invalidate();
        DestinationVerdict::fail_closed()
    }
}

/// Register one owner-identified flow with policyd before proxy forwarding.
///
/// Asks policyd to validate the typed owner snapshot and stores the flow for
/// the transparent proxy to claim later. Any malformed reply is an RPC failure
/// and must be treated as a failed registration by callers.
pub async fn register_network_flow(
    client: &mut PersistentRpcClient,
    registration: FlowRegistration,
    owner_fd_hint: Option<u32>,
    timeout: Duration,
) -> std::io::Result<bool> {
    let response = client
        .request(
            RpcRequest::RegisterNetworkFlow {
                registration,
                owner_fd_hint,
            },
            timeout,
        )
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    match response {
        RpcReply::Simple(reply) => Ok(reply.ok),

        RpcReply::Error(error) => {
            client.invalidate();
            Err(std::io::Error::other(error.error))
        }

        _ => {
            client.invalidate();
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "policyd returned an unexpected reply for RegisterNetworkFlow",
            ))
        }
    }
}

/// Whether a packet to the given destination should bypass policy checks
/// entirely.
pub fn is_bypass_traffic(dst_ip: IpAddr, dst_port: u16, dns_server_ip: IpAddr) -> bool {
    // DNS forwarder traffic on port 53 only
    dst_ip == dns_server_ip && dst_port == 53
}

/// The destination policy judges. The loopback bridge readdresses host-bound
/// localhost flows to the handoff addresses `127.0.0.2` and `::2` (see
/// `loopback/redirect.bpf.c`); policy sees the localhost the client dialled.
#[must_use]
pub const fn policy_destination(dst_ip: IpAddr) -> IpAddr {
    const HANDOFF_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    const HANDOFF_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2);

    match dst_ip {
        IpAddr::V4(HANDOFF_V4) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(HANDOFF_V6) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    }
}

/// Add the destination IP and port to the transient nftables reject set, then
/// return `Verdict::Repeat` so nftables re-evaluates and rejects the packet.
///
/// Falls back to `Verdict::Drop` if nft add fails.
pub fn nft_reject_and_repeat(nft_binary: &str, dst_ip: IpAddr, dst_port: u16) -> Verdict {
    let set_name = match dst_ip {
        IpAddr::V4(_) => "reject_v4",
        IpAddr::V6(_) => "reject_v6",
    };

    let element = format!("{{ {dst_ip} . {dst_port} timeout 5s }}");

    let out = std::process::Command::new(nft_binary)
        .args([
            "add",
            "element",
            "inet",
            "agent_sandbox",
            set_name,
            element.as_str(),
        ])
        .output();

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

pub struct AllowedDestination {
    pub(crate) hostname: String,
    pub(crate) dst_ip: String,
}

/// Result of a transport policy check for one packet.
pub enum TransportCheck {
    Rejected(Verdict),
    Allowed(AllowedDestination),
}

/// Run the destination policy check for one packet and apply its side
/// effects.
///
/// Approved destinations are recorded in the on-disk bindings cache so later
/// packets resolve faster. When the verdict cache holds a current entry for
/// this destination, its verdict is reused without consulting policyd; a
/// miss behaves exactly as without the cache.
pub fn transport_check(
    state: &NfqState,
    meta: packet::PacketMeta,
    src_pid: Option<u32>,
    session_id: Option<&str>,
    check: &mut dyn FnMut(CheckDestinationArgs<'_>) -> DestinationVerdict,
) -> TransportCheck {
    let dst_ip = policy_destination(meta.dst_ip).to_string();

    if let Some(cached) = state.cached_transport_verdict(meta) {
        if cached == VERDICT_DENY {
            info!(
                protocol = meta.protocol.as_str(),
                dst = %dst_ip,
                port = meta.dst_port,
                "reject (policy cache)"
            );

            // Same fail-fast verdict the RPC path produces below.
            return TransportCheck::Rejected(nft_reject_and_repeat(
                &state.nft_binary,
                meta.dst_ip,
                meta.dst_port,
            ));
        }

        info!(
            protocol = meta.protocol.as_str(),
            dst = %dst_ip,
            port = meta.dst_port,
            "accept (policy cache)"
        );
        return TransportCheck::Allowed(AllowedDestination {
            hostname: dst_ip.clone(),
            dst_ip,
        });
    }

    let hostname = state.resolve_host_for_session(&dst_ip, session_id);

    let aliases = state
        .approved_bindings
        .lock()
        .map(|bindings| bindings.aliases(&dst_ip))
        .unwrap_or_default();

    let result = check(CheckDestinationArgs {
        hostname: &hostname,
        dst_ip: &dst_ip,
        dst_port: meta.dst_port,
        protocol: meta.protocol,
        src_pid,
        aliases: &aliases,
    });

    let (allowed, source) = (result.allowed, result.source);

    state.publish_transport_verdict(meta, allowed, source.as_ref(), &hostname, &dst_ip);

    if !allowed {
        info!(
            protocol = meta.protocol.as_str(),
            host = %hostname,
            dst = %dst_ip,
            port = meta.dst_port,
            "reject (policy)"
        );

        // Add a transient nft reject element so the client fails fast instead
        // of hanging. Falls back to Drop if nft add fails.
        return TransportCheck::Rejected(nft_reject_and_repeat(
            &state.nft_binary,
            meta.dst_ip,
            meta.dst_port,
        ));
    }

    if let Ok(mut bindings) = state.approved_bindings.lock() {
        bindings.record(&hostname, &dst_ip);
    }

    state.notify_approved_bindings();
    TransportCheck::Allowed(AllowedDestination { hostname, dst_ip })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use agent_sandbox_core::{
        ApprovalScope, VerdictSource,
        verdict_map::{DestKey, VERDICT_ALLOW, VERDICT_DENY},
    };

    use super::*;
    use crate::{
        flow::{
            handle_packet_payload_with_registration,
            tests::{DNS_IP, build_udp_data_packet, policy_allow, policy_deny, state_for_tests},
        },
        verdict_cache::{VerdictCache, dest_key},
    };

    /// Network namespace cookie the injected cache is keyed by. The value is
    /// arbitrary: the fake cache never reaches a kernel map.
    const TEST_NETNS: u64 = 4242;

    /// Key the fake cache replays: namespace cookie, protocol, address, port.
    type FakeKey = (u64, u8, [u8; 16], u16);

    /// Cached verdict and the generation it was published under.
    type FakeEntry = (u8, u32);

    /// In-memory [`VerdictCache`] for decision-contract tests: no kernel maps.
    #[derive(Debug)]
    struct FakeVerdictCache {
        generation: std::sync::Mutex<u32>,
        entries: std::sync::Mutex<HashMap<FakeKey, FakeEntry>>,
    }

    impl FakeVerdictCache {
        fn with_generation(generation: u32) -> Self {
            Self {
                generation: std::sync::Mutex::new(generation),
                entries: std::sync::Mutex::new(HashMap::new()),
            }
        }

        fn insert(&self, key: &DestKey, verdict: u8, generation: u32) {
            self.entries.lock().expect("lock fake entries").insert(
                (key.netns_cookie, key.proto, key.ip, key.port()),
                (verdict, generation),
            );
        }

        fn get(&self, key: &DestKey) -> Option<(u8, u32)> {
            self.entries
                .lock()
                .expect("lock fake entries")
                .get(&(key.netns_cookie, key.proto, key.ip, key.port()))
                .copied()
        }
    }

    impl VerdictCache for FakeVerdictCache {
        fn cached_verdict(&self, key: &DestKey) -> Option<u8> {
            let generation = *self.generation.lock().expect("lock fake generation");
            self.get(key)
                .filter(|(_, entry_generation)| *entry_generation == generation)
                .map(|(verdict, _)| verdict)
        }

        fn publish_verdict(&self, key: &DestKey, verdict: u8) {
            let generation = *self.generation.lock().expect("lock fake generation");
            self.insert(key, verdict, generation);
        }

        fn clear_verdict(&self, key: &DestKey) {
            self.entries.lock().expect("lock fake entries").remove(&(
                key.netns_cookie,
                key.proto,
                key.ip,
                key.port(),
            ));
        }

        fn invalidate(&self) {
            let mut generation = self.generation.lock().expect("lock fake generation");
            *generation = generation.wrapping_add(1);
        }
    }

    fn tcp_meta(dst_ip: IpAddr, dst_port: u16) -> packet::PacketMeta {
        packet::PacketMeta {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip,
            src_port: 54321,
            dst_port,
            protocol: packet::TransportProtocol::Tcp,
            tcp_syn: true,
            transport_offset: 20,
        }
    }

    fn example_meta() -> packet::PacketMeta {
        tcp_meta(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)
    }

    fn state_with_cache(cache: Arc<FakeVerdictCache>) -> NfqState {
        let mut state = state_for_tests();
        state.verdict_cache = Some(cache);
        state.verdict_netns = TEST_NETNS;
        // Resolve the test destination to itself so allow-publishability never
        // depends on the machine's on-disk DNS cache.
        state
            .dns_cache
            .lock()
            .expect("lock dns cache")
            .remember_ephemeral("93.184.216.34", "93.184.216.34", 300);
        state
    }

    #[test]
    fn verdict_cache_hit_skips_policyd_rpc() {
        let cache = Arc::new(FakeVerdictCache::with_generation(1));
        let state = state_with_cache(Arc::clone(&cache));
        let meta = example_meta();
        cache.insert(&dest_key(TEST_NETNS, meta), VERDICT_ALLOW, 1);

        let calls = Cell::new(0_u32);
        let mut check = |_: CheckDestinationArgs<'_>| {
            calls.set(calls.get() + 1);
            policy_allow()
        };

        let outcome = transport_check(&state, meta, None, None, &mut check);
        assert!(
            matches!(outcome, TransportCheck::Allowed(_)),
            "cache hit must return the cached allow"
        );
        assert_eq!(calls.get(), 0, "cache hit must skip the policyd RPC");
    }

    #[test]
    fn verdict_cache_miss_calls_policyd_and_publishes_literal_allow() {
        let cache = Arc::new(FakeVerdictCache::with_generation(1));
        let state = state_with_cache(Arc::clone(&cache));
        let meta = example_meta();

        let calls = Cell::new(0_u32);
        let mut check = |_: CheckDestinationArgs<'_>| {
            calls.set(calls.get() + 1);
            policy_allow()
        };

        let outcome = transport_check(&state, meta, None, None, &mut check);
        assert!(
            matches!(outcome, TransportCheck::Allowed(_)),
            "cache miss must return the policyd verdict"
        );
        assert_eq!(calls.get(), 1, "cache miss must consult policyd");
        assert_eq!(
            cache.get(&dest_key(TEST_NETNS, meta)),
            Some((VERDICT_ALLOW, 1)),
            "IP-literal static allow must be published under the current generation"
        );
    }

    #[test]
    fn verdict_cache_generation_mismatch_is_miss() {
        let cache = Arc::new(FakeVerdictCache::with_generation(2));
        let state = state_with_cache(Arc::clone(&cache));
        let meta = example_meta();
        cache.insert(&dest_key(TEST_NETNS, meta), VERDICT_ALLOW, 1);

        let calls = Cell::new(0_u32);
        let mut check = |_: CheckDestinationArgs<'_>| {
            calls.set(calls.get() + 1);
            policy_deny()
        };

        let outcome = transport_check(&state, meta, None, None, &mut check);
        assert!(
            matches!(outcome, TransportCheck::Rejected(_)),
            "stale entry must not shadow the fresh policyd verdict"
        );
        assert_eq!(calls.get(), 1, "stale entry must consult policyd");
        assert_eq!(
            cache.get(&dest_key(TEST_NETNS, meta)),
            Some((VERDICT_DENY, 2)),
            "fresh denial must replace the stale entry under the new generation"
        );
    }

    #[test]
    fn verdict_cache_deny_hit_rejects_without_rpc() {
        let cache = Arc::new(FakeVerdictCache::with_generation(1));
        let mut state = state_with_cache(Arc::clone(&cache));
        state.nft_binary = "true".to_string();
        let meta = example_meta();
        cache.insert(&dest_key(TEST_NETNS, meta), VERDICT_DENY, 1);

        let calls = Cell::new(0_u32);
        let mut check = |_: CheckDestinationArgs<'_>| {
            calls.set(calls.get() + 1);
            policy_allow()
        };

        let outcome = transport_check(&state, meta, None, None, &mut check);
        assert!(
            matches!(outcome, TransportCheck::Rejected(Verdict::Repeat)),
            "deny hit must produce the reject verdict"
        );
        assert_eq!(calls.get(), 0, "deny hit must skip the policyd RPC");
    }

    #[test]
    fn verdict_cache_once_allow_is_not_published() {
        let cache = Arc::new(FakeVerdictCache::with_generation(1));
        let state = state_with_cache(Arc::clone(&cache));
        let meta = example_meta();

        let mut check = |_: CheckDestinationArgs<'_>| {
            DestinationVerdict::allowed(VerdictSource::Scope(ApprovalScope::Once))
        };

        let outcome = transport_check(&state, meta, None, None, &mut check);
        assert!(
            matches!(outcome, TransportCheck::Allowed(_)),
            "one-time approval must still allow this flow"
        );
        assert_eq!(
            cache.get(&dest_key(TEST_NETNS, meta)),
            None,
            "consumable approval must never become a replayable entry"
        );
    }

    #[test]
    fn verdict_cache_fresh_approval_clears_stale_deny() {
        let cache = Arc::new(FakeVerdictCache::with_generation(2));
        let state = state_with_cache(Arc::clone(&cache));
        let meta = example_meta();
        cache.insert(&dest_key(TEST_NETNS, meta), VERDICT_DENY, 1);

        let calls = Cell::new(0_u32);
        let mut check = |_: CheckDestinationArgs<'_>| {
            calls.set(calls.get() + 1);
            DestinationVerdict::allowed(VerdictSource::Scope(ApprovalScope::Session))
        };

        let outcome = transport_check(&state, meta, None, None, &mut check);
        assert!(
            matches!(outcome, TransportCheck::Allowed(_)),
            "fresh approval must allow this flow"
        );
        assert_eq!(calls.get(), 1, "stale entry must consult policyd");
        assert_eq!(
            cache.get(&dest_key(TEST_NETNS, meta)),
            None,
            "unpublishable approval must erase the stale deny it supersedes"
        );
    }

    #[test]
    fn verdict_cache_rpc_error_leaves_cache_untouched() {
        let cache = Arc::new(FakeVerdictCache::with_generation(1));
        let state = state_with_cache(Arc::clone(&cache));
        let meta = example_meta();
        cache.insert(&dest_key(TEST_NETNS, meta), VERDICT_DENY, 0);

        let mut check = |_: CheckDestinationArgs<'_>| DestinationVerdict::fail_closed();

        let outcome = transport_check(&state, meta, None, None, &mut check);
        assert!(
            matches!(outcome, TransportCheck::Rejected(_)),
            "RPC error must fail closed"
        );
        assert_eq!(
            cache.get(&dest_key(TEST_NETNS, meta)),
            Some((VERDICT_DENY, 0)),
            "transient error must neither publish nor clear"
        );
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
    fn nft_reject_returns_repeat_when_insertion_succeeds() {
        let v = nft_reject_and_repeat("true", IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        assert_eq!(v, Verdict::Repeat);
    }

    #[test]
    fn nft_reject_falls_back_to_drop_on_failure() {
        let v = nft_reject_and_repeat("false", IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        assert_eq!(v, Verdict::Drop);
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

        let mut check = |args: CheckDestinationArgs<'_>| {
            *aliases_seen.borrow_mut() = args.aliases.to_vec();
            policy_allow()
        };

        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);
        assert_eq!(v, Verdict::Accept);

        assert_eq!(
            aliases_seen.borrow().as_slice(),
            &["chatgpt.com".to_string()],
            "approved bindings aliases should be passed to policy check"
        );
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
        let mut check = |_: CheckDestinationArgs<'_>| policy_allow();
        let (v, _) = handle_packet_payload_with_registration(&state, &pkt, &mut check, None);
        assert_eq!(v, Verdict::Accept);

        let aliases = state
            .approved_bindings
            .lock()
            .expect("lock bindings")
            .aliases("93.184.216.34");

        assert_eq!(aliases, vec!["example.com".to_string()]);
    }
}
