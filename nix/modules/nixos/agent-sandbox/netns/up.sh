#!/usr/bin/env bash
set -euo pipefail

NETNS="@netnsName@"
HOST_IF="@vethHost@"
NS_IF="@vethNetns@"
NETNS_IP="@netnsIp@"
HOST_IP="@hostIp@"
NETNS_IP_CIDR="@netnsIp@/30"
HOST_IP6="@hostIp6@"
HOST_IP6_CIDR="@hostIp6Cidr@"
NETNS_IP6_CIDR="@netnsIp6Cidr@"

if ! ip netns exec "$NETNS" true 2>/dev/null; then
  ip netns del "$NETNS" 2>/dev/null || rm -f "/run/netns/$NETNS"
  # Keep TCP ownership scans off the host-sized shared hash table. The temporary
  # parent changes only its own sysctl; the named child retains its private table.
  # ponytail: 4096 buckets, increase if concurrent sandbox TCP flows outgrow this.
  unshare --net "$BASH" -euc '
    if [[ -e /proc/sys/net/ipv4/tcp_child_ehash_entries ]]; then
      printf "4096\n" > /proc/sys/net/ipv4/tcp_child_ehash_entries
    fi
    exec ip netns add "$1"
  ' -- "$NETNS"
fi

ip link del "$HOST_IF" 2>/dev/null || true
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip link set "$NS_IF" netns "$NETNS"
ip addr add "@hostIpCidr@" dev "$HOST_IF"
ip -6 addr add "$HOST_IP6_CIDR" dev "$HOST_IF"
ip link set "$HOST_IF" up

ip netns exec "$NETNS" ip addr add "$NETNS_IP_CIDR" dev "$NS_IF"
ip netns exec "$NETNS" ip -6 addr add "$NETNS_IP6_CIDR" dev "$NS_IF"
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip link set "$NS_IF" up
ip netns exec "$NETNS" ip route replace default via "$HOST_IP"
ip netns exec "$NETNS" ip -6 route replace default via "$HOST_IP6"

@loopbackRoutingSetup@

ip netns exec "$NETNS" nft -f - <<EOF
@nftRules@
EOF

@proxyUidElement@

"@hostNatBin@"

nft add rule ip agent_sandbox_host postrouting \
  ip saddr "$NETNS_IP" masquerade 2>/dev/null || true

nft list table ip agent_sandbox_fwd >/dev/null 2>&1 \
  || nft add table ip agent_sandbox_fwd

nft list chain ip agent_sandbox_fwd forward >/dev/null 2>&1 \
  || nft add chain ip agent_sandbox_fwd forward \
    '{ type filter hook forward priority -20; policy accept; }'

nft add rule ip agent_sandbox_fwd forward iifname "$HOST_IF" accept 2>/dev/null || true
nft add rule ip agent_sandbox_fwd forward oifname "$HOST_IF" accept 2>/dev/null || true

# IPv6 NAT66 masquerade
nft add rule ip6 agent_sandbox_host postrouting \
  ip6 saddr "$NETNS_IP6_CIDR" masquerade 2>/dev/null || true

# IPv6 forward table
nft list table ip6 agent_sandbox_fwd >/dev/null 2>&1 \
  || nft add table ip6 agent_sandbox_fwd

nft list chain ip6 agent_sandbox_fwd forward >/dev/null 2>&1 \
  || nft add chain ip6 agent_sandbox_fwd forward \
    '{ type filter hook forward priority -20; policy accept; }'

nft add rule ip6 agent_sandbox_fwd forward iifname "$HOST_IF" accept 2>/dev/null || true
nft add rule ip6 agent_sandbox_fwd forward oifname "$HOST_IF" accept 2>/dev/null || true
