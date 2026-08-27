#!/usr/bin/env bash
# Host-side NAT + INPUT rules for the agent-sandbox veth (mirrors vpn-run / interface-run).
set -euo pipefail

HOST_IF="@vethHost@"
DNS_TARGET_HOST="@dnsTargetHost@"
ENABLE_LOOPBACK="@enableLoopback@"
LOOPBACK_HANDOFF_IP6="@loopbackHandoffIp6@"

# Same sysctl as interface-run/veth-setup.sh. Without rp_filter=0, replies to 169.254.100.1
# from the netns are dropped and DNS connections time out.
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w "net.ipv4.conf.${HOST_IF}.rp_filter=0"
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w "net.ipv6.conf.${HOST_IF}.forwarding=1"

if [[ "$DNS_TARGET_HOST" == 127.* || "$ENABLE_LOOPBACK" == 1 ]]; then
  sysctl -w net.ipv4.conf.all.route_localnet=1
  sysctl -w "net.ipv4.conf.${HOST_IF}.route_localnet=1"
  echo "agent-sandbox-host-nat: route_localnet enabled for ${HOST_IF}" >&2
fi

if [[ "$ENABLE_LOOPBACK" == 1 ]]; then
  ip -6 route replace local "${LOOPBACK_HANDOFF_IP6}/128" dev lo
fi

# Recreate host tables so INPUT uses priority filter - 200 (before NixOS firewall drops).
create_family_table() {
  local family="$1"
  local prerouting_rules="${2:-}"
  local output_rules="${3:-}"
  local postrouting_rules="${4:-}"
  nft delete table "$family" agent_sandbox_host 2>/dev/null || true

  nft -f - <<EOF
table $family agent_sandbox_host {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    $prerouting_rules
  }
  chain output {
    type nat hook output priority dstnat; policy accept;
    $output_rules
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    $postrouting_rules
  }
  chain input {
    type filter hook input priority filter - 200; policy accept;
    iifname "${HOST_IF}" tcp dport 53 accept
    iifname "${HOST_IF}" udp dport 53 accept
  }
}
EOF
}

create_family_table ip \
  @hostLoopbackPreroutingRule@ \
  @hostLoopbackOutputRule@ \
  @hostLoopbackPostroutingRule@
create_family_table ip6 \
  @hostLoopbackPreroutingRule6@ \
  @hostLoopbackOutputRule6@ \
  @hostLoopbackPostroutingRule6@

echo "agent-sandbox-host-nat: INPUT on ${HOST_IF} accepts DNS (53)" >&2
echo "agent-sandbox-host-nat: IPv6 host table created (NAT66 + IPv6 DNS input on ${HOST_IF})" >&2
