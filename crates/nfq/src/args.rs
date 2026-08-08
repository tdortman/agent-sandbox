//! Command-line arguments for the nfq daemon.

use clap::Parser;

use std::{net::IpAddr, path::PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-nfq",
    version,
    about = "NFQUEUE-based packet policy enforcer for the sandbox network namespace",
    long_about = r"NFQUEUE packet interceptor that runs inside the agent-sandbox network namespace.
nftables queues outbound TCP SYN packets and all UDP packets here.
For each queued packet the daemon resolves the destination hostname from the DNS forwarder in-memory cache (or the on-disk fallback), asks policyd for a verdict, and either accepts the packet or actively rejects it via a transient nftables set.
Traffic to the local DNS forwarder on port 53 always bypasses policyd so name resolution can never be blocked.

EXAMPLES:
# Run inside the sandbox netns with the default nftables queue number.
agent-sandbox-nfq

# Bind to a different NFQUEUE and accept a larger kernel-side queue.
agent-sandbox-nfq --queue 1 --queue-len 8192

# Point at a custom policyd and DNS push socket.
agent-sandbox-nfq \
    --policy-socket /run/agent-sandbox/policy.sock \
    --push-socket /run/agent-sandbox/dns-push.sock"
)]
pub struct Cli {
    /// NFQUEUE queue number. Must match the nftables "queue num" rule installed
    /// in the sandbox netns. 0 (the default) is the convention used by the
    /// NixOS module.
    #[arg(long, value_name = "NUM", default_value_t = 0)]
    pub(crate) queue: u16,

    /// Unix domain socket path used to ask policyd for a verdict on each queued
    /// packet.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/policy.sock"
    )]
    pub(crate) policy_socket: String,

    /// Max seconds to wait for a policyd verdict per packet check. Fractional
    /// values are accepted. The effective wait is clamped to at least 1 second.
    /// Larger values tolerate slow policyd startups but delay packet release.
    #[arg(long, value_name = "SECONDS", default_value_t = 305.0)]
    pub(crate) policy_timeout: f64,

    /// Maximum number of packets the kernel may hold while waiting for
    /// verdicts. Increase this if bursts of new outbound connections are
    /// getting dropped under load. 4096 is enough for typical agent traffic.
    #[arg(long, value_name = "PACKETS", default_value_t = 4096)]
    pub(crate) queue_len: u32,

    /// Path to the "nft" binary used to add destination IPs to the transient
    /// reject set. Override this for testing or non-standard installations.
    #[arg(long, value_name = "PATH", default_value = "nft")]
    pub(crate) nft_binary: String,

    /// DNS forwarder IP address (v4 or v6). Packets to this IP on port 53 are
    /// passed straight through without consulting policyd so the agent can
    /// always resolve names. 169.254.100.1 is the link-local address used by
    /// the default NixOS module.
    #[arg(long, value_name = "IP", default_value = "169.254.100.1")]
    pub(crate) dns_server_ip: IpAddr,

    /// Unix datagram socket path the DNS forwarder pushes fresh "{ip,host,ttl}"
    /// mappings to. If absent or unbindable the daemon falls back to the
    /// on-disk cache only.
    #[arg(
        long,
        value_name = "SOCKET",
        default_value = "/run/agent-sandbox/dns-push.sock"
    )]
    pub(crate) push_socket: PathBuf,

    /// Register owner-identified TCP and configured HTTP/3 UDP flows for the
    /// transparent proxy. Direct mode leaves proxy flow registration disabled.
    #[arg(long)]
    pub(crate) proxy_mode: bool,

    /// UDP ports whose flows are registered for the transparent HTTP/3
    /// proxy instead of being transport-checked. Comma-separated.
    #[arg(long, value_name = "PORTS", default_value = "443")]
    pub(crate) udp_proxy_ports: String,

    /// Readiness marker written only after NFQUEUE bind succeeds. The marker
    /// contains the systemd `INVOCATION_ID` so stale daemon state cannot be
    /// mistaken for the current queue owner.
    #[arg(long, value_name = "PATH")]
    pub(crate) ready_file: Option<PathBuf>,

    /// Only accept DNS push frames from this peer uid (default: root / the host
    /// DNS forwarder).
    #[arg(long, value_name = "UID", default_value_t = 0)]
    pub(crate) push_trusted_uid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

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
