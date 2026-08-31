//! Policy RPC client for NFQUEUE, calls policyd's `Check` endpoint.

use std::{
    fs,
    net::IpAddr,
    os::unix::fs::MetadataExt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use agent_sandbox_core::{
    CgroupIdentity, FlowRegistration, NetworkFlowKey, NfqEvidence, OperationIdentity,
    RequestContext, RoleEvidenceRequest, RpcReply, RpcRequest, SocketIdentity, SubcheckIdentity,
    attach_check_aliases, daemon_context, persist_session_paths, policy_rpc,
};
use nfq_updated::Verdict;
use tracing::{debug, info, warn};

use crate::{flow::NfqState, packet, packet::TransportProtocol};

static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(1);

fn nfq_evidence(
    meta: packet::PacketMeta,
    owner: Option<SocketIdentity>,
) -> Option<RoleEvidenceRequest> {
    let owner = owner?;
    let pid = owner.pid().get();
    let cgroup_content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let cgroup_path = cgroup_content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?;
    let cgroup = CgroupIdentity::new(
        fs::metadata(format!("/sys/fs/cgroup{cgroup_path}"))
            .ok()?
            .ino(),
    )
    .ok()?;
    let flow = NetworkFlowKey::try_new(
        meta.protocol,
        meta.src_ip,
        meta.src_port,
        meta.dst_ip,
        meta.dst_port,
    )
    .ok()?;
    let operation_id =
        OperationIdentity::new(NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed).max(1)).ok()?;
    let subcheck_id = SubcheckIdentity::new(1).ok()?;
    Some(RoleEvidenceRequest::Nfq {
        request_id: operation_id.get(),
        evidence: NfqEvidence {
            operation_id,
            subcheck_id,
            flow,
            owner,
            cgroup,
        },
    })
}

/// Inputs for a single policy check, grouped to keep the call signature small.
pub struct CheckDestinationArgs<'a> {
    pub hostname: &'a str,
    pub dst_ip: &'a str,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
    pub src_pid: Option<u32>,
    pub aliases: &'a [String],
    pub evidence: Option<RoleEvidenceRequest>,
}

/// Check whether a destination is allowed by policy.
///
/// `hostname` should be pre-resolved by the caller (DNS cache or PTR).
/// Blocks until policyd responds (which may wait for user approval).
pub async fn check_destination(
    socket: &str,
    args: CheckDestinationArgs<'_>,
    timeout: Duration,
) -> std::io::Result<bool> {
    let Some(evidence) = args.evidence else {
        return Err(std::io::Error::other("NFQ owner evidence is unavailable"));
    };
    let ctx = daemon_context(args.src_pid);
    persist_session_paths(&ctx.paths);
    let scheme = args.protocol.as_str();
    let url = format!("{scheme}://{}:{}", args.hostname, args.dst_port);

    let req = RpcRequest::Check {
        host: Some(args.hostname.to_string()),
        connect_host: Some(args.dst_ip.to_string()),
        port: Some(args.dst_port),
        scheme: scheme.to_string(),
        url: attach_check_aliases(Some(url), args.aliases),
        ctx: RequestContext::from(&ctx),
        evidence: Some(evidence),
    };

    let resp = policy_rpc(socket, req, timeout)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;

    let allowed = matches!(resp, RpcReply::Check(check) if check.allowed);
    Ok(allowed)
}

/// Register one owner-identified flow with policyd before proxy forwarding.
///
/// Asks policyd to validate the typed owner snapshot and stores the flow for
/// the transparent proxy to claim later. Any malformed reply is an RPC failure
/// and must be treated as a failed registration by callers.
pub async fn register_network_flow(
    socket: &str,
    registration: FlowRegistration,
    timeout: Duration,
) -> std::io::Result<bool> {
    let response = policy_rpc(
        socket,
        RpcRequest::RegisterNetworkFlow { registration },
        timeout,
    )
    .await
    .map_err(|error| std::io::Error::other(error.to_string()))?;

    match response {
        RpcReply::Simple(reply) => Ok(reply.ok),
        RpcReply::Error(error) => Err(std::io::Error::other(error.error)),

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "policyd returned an unexpected reply for RegisterNetworkFlow",
        )),
    }
}

/// Whether a packet to the given destination should bypass policy checks
/// entirely.
pub fn is_bypass_traffic(dst_ip: IpAddr, dst_port: u16, dns_server_ip: IpAddr) -> bool {
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
fn nft_reject_and_repeat(nft_binary: &str, dst_ip: IpAddr, dst_port: u16) -> Verdict {
    nft_reject_and_repeat_inner(dst_ip, dst_port, |args| run_nft_real(nft_binary, args))
}

/// Inner reject helper with injectable command runner.
fn nft_reject_and_repeat_inner<F>(dst_ip: IpAddr, dst_port: u16, run_nft: F) -> Verdict
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
/// packets resolve faster.
pub fn transport_check(
    state: &NfqState,
    meta: packet::PacketMeta,
    src_pid: Option<u32>,
    session_id: Option<&str>,
    owner: Option<SocketIdentity>,
    check: &mut dyn FnMut(CheckDestinationArgs<'_>) -> std::io::Result<bool>,
) -> TransportCheck {
    let dst_ip = meta.dst_ip.to_string();
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
        evidence: nfq_evidence(meta, owner),
    });

    let allowed = result.unwrap_or_else(|err| {
        warn!(
            protocol = meta.protocol.as_str(),
            host = %hostname,
            dst = %dst_ip,
            port = meta.dst_port,
            error = %err,
            "policy check failed"
        );

        false
    });

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
        let _ = bindings.save();
    }

    TransportCheck::Allowed(AllowedDestination { hostname, dst_ip })
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::unix::process::ExitStatusExt,
    };

    use super::*;
    use crate::flow::{
        handle_packet_payload_with_registration,
        tests::{DNS_IP, build_udp_data_packet, state_for_tests},
    };

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
        // Mock a successful nft command.
        let mock_run = |_args: &[&str]| -> std::io::Result<std::process::Output> {
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        };

        let v =
            nft_reject_and_repeat_inner(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443, mock_run);

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

        let v =
            nft_reject_and_repeat_inner(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443, mock_run);

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
            Ok(true)
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

        let mut check = |_: CheckDestinationArgs<'_>| Ok(true);

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
