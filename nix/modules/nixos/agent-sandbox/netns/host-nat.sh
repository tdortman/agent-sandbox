#!/usr/bin/env bash
# Host-side NAT + INPUT rules for the agent-sandbox veth (mirrors vpn-run / interface-run).
set -euo pipefail

HOST_IF="@vethHost@"
DNS_TARGET_HOST="@dnsTargetHost@"

# Same sysctl as interface-run/veth-setup.sh. Without rp_filter=0, replies to 169.254.100.1
# from the netns are dropped and DNS connections time out.
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w "net.ipv4.conf.${HOST_IF}.rp_filter=0"
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w "net.ipv6.conf.${HOST_IF}.forwarding=1"

if [[ "$DNS_TARGET_HOST" == 127.* ]]; then
  sysctl -w net.ipv4.conf.all.route_localnet=1
  sysctl -w "net.ipv4.conf.${HOST_IF}.route_localnet=1"
  echo "agent-sandbox-host-nat: route_localnet enabled for ${HOST_IF}" >&2
fi

# Recreate host tables so INPUT uses priority filter - 200 (before NixOS firewall drops).
create_family_table() {
  local family="$1"
  nft delete table "$family" agent_sandbox_host 2>/dev/null || true
  nft -f - <<EOF
table $family agent_sandbox_host {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
  }
  chain input {
    type filter hook input priority filter - 200; policy accept;
    iifname "${HOST_IF}" tcp dport 53 accept
    iifname "${HOST_IF}" udp dport 53 accept
  }
}
EOF
}

create_family_table ip
create_family_table ip6

echo "agent-sandbox-host-nat: INPUT on ${HOST_IF} accepts DNS (53)" >&2
echo "agent-sandbox-host-nat: IPv6 host table created (NAT66 + IPv6 DNS input on ${HOST_IF})" >&2
