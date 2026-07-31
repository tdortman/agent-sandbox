#!/usr/bin/env bash
set -euo pipefail

listen_port="$1"
route_table="$2"
mark="$3"
nft_table="$4"
queue_number="$5"
proxy_uid="$(id -u "$6")"
proxy_unit="$7"
nfq_unit="$8"
proxy_ready="$9"
nfq_ready="${10}"
udp_port="${11:-0}"
action="${12:-up}"

ports='80,443,8008,8080,8443'

systemctl_ready() {
  local unit="$1"
  local marker="$2"
  local invocation
  invocation="$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)"
  [[ "$invocation" =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ -f "$marker" && ! -L "$marker" ]] || return 1
  [[ "$(cat -- "$marker")" == "$invocation" ]]
}

remove_rules() {
  while ip rule del priority 100 fwmark "$mark" table "$route_table" 2>/dev/null; do :; done
  while ip -6 rule del priority 100 fwmark "$mark" table "$route_table" 2>/dev/null; do :; done
  ip route flush table "$route_table" 2>/dev/null || true
  ip -6 route flush table "$route_table" 2>/dev/null || true
  nft delete table inet "$nft_table" 2>/dev/null || true
}

fail_closed() {
  remove_rules

  nft -f - <<EOF
 table inet $nft_table {
   chain output {
     type route hook output priority mangle; policy accept;
     meta skuid $proxy_uid return
     tcp dport { $ports } reject with tcp reset
     tcp dport 853 reject with tcp reset
     udp dport { 443, 853 } reject
   }
   chain prerouting {
     type filter hook prerouting priority mangle; policy accept;
     tcp dport { $ports } reject with tcp reset
     tcp dport 853 reject with tcp reset
     udp dport { 443, 853 } reject
   }
 }
EOF
}

if [[ "$action" == cleanup ]]; then
  fail_closed
  exit 0
fi

fail_closed
trap fail_closed EXIT HUP INT TERM

for _attempt in $(seq 1 60); do
  if systemctl_ready "$proxy_unit" "$proxy_ready" && systemctl_ready "$nfq_unit" "$nfq_ready"; then
    break
  fi

  [[ "$_attempt" -lt 60 ]] || {
    echo "agent-sandbox tproxy route: readiness markers are missing or stale" >&2
    exit 1
  }

  sleep 0.5
done

ip rule add priority 100 fwmark "$mark" table "$route_table"
ip -6 rule add priority 100 fwmark "$mark" table "$route_table"
ip route replace local 0.0.0.0/0 dev lo table "$route_table"
ip -6 route replace local ::/0 dev lo table "$route_table"

nft -f - <<EOF
 delete table inet $nft_table
 table inet $nft_table {
   chain output {
     type route hook output priority mangle; policy accept;
     meta skuid $proxy_uid return
     # Queue before local TPROXY routing so the policy daemon sees the
     # original sandbox socket tuple.
     tcp dport 853 reject with tcp reset
     ${
       if [[ "$udp_port" != 0 ]]; then
         echo "udp dport 853 reject"
       else
         echo "udp dport { 443, 853 } reject"
       fi
     }
     tcp dport { $ports } counter meta mark set $mark queue num $queue_number
     ${
       if [[ "$udp_port" != 0 ]]; then
         # Queue only the first packet of each UDP flow. QUIC sends many
         # datagrams per flow (handshake, data, ACKs); checking every packet
         # against policyd serialises the NFQUEUE at tens of milliseconds per
         # packet. Established flows keep the kernel path and reach the proxy
         # directly, so the policy check runs once per destination.
         echo "udp dport $udp_port ct state new,untracked counter meta mark set $mark queue num $queue_number"
       fi
     }
   }
   chain prerouting {
     type filter hook prerouting priority mangle; policy accept;
     tcp dport 853 reject with tcp reset
     ${
       if [[ "$udp_port" != 0 ]]; then
         echo "udp dport 853 reject"
       else
         echo "udp dport { 443, 853 } reject"
       fi
     }
     tcp dport { $ports } counter tproxy to :$listen_port meta mark set $mark
     ${
       if [[ "$udp_port" != 0 ]]; then
         echo "udp dport $udp_port counter tproxy to :$udp_port meta mark set $mark"
       fi
     }
   }
   chain output_redirect {
     type nat hook output priority 5; policy accept;
     meta skuid $proxy_uid return
     tcp dport { $ports } redirect to :$listen_port
   }
 }
EOF

trap - EXIT HUP INT TERM
