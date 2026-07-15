#!/usr/bin/env bash
set -euo pipefail
ROUTE_TABLE=51820
PROXY_RULE_PRIORITY=100

# IANA HTTP service ports: http (80), https (443), http-alt (8008/8080),
# and the commonly used HTTPS alternate (8443). HTTP/3 uses UDP/443.
proxy_ports() {
  local action="$1"
  local family="$2"
  for protocol_port in "tcp 80" "tcp 443" "tcp 8008" "tcp 8080" "tcp 8443" "udp 443"; do
    read -r protocol port <<< "$protocol_port"
    if [[ "$family" == 6 ]]; then
      while ip -6 rule del priority "$PROXY_RULE_PRIORITY" \
        ipproto "$protocol" dport "$port" table "$ROUTE_TABLE" 2>/dev/null; do
        :
      done
      if [[ "$action" == add ]]; then
        ip -6 rule add priority "$PROXY_RULE_PRIORITY" \
          ipproto "$protocol" dport "$port" table "$ROUTE_TABLE"
      fi
    else
      while ip rule del priority "$PROXY_RULE_PRIORITY" \
        ipproto "$protocol" dport "$port" table "$ROUTE_TABLE" 2>/dev/null; do
        :
      done
      if [[ "$action" == add ]]; then
        ip rule add priority "$PROXY_RULE_PRIORITY" \
          ipproto "$protocol" dport "$port" table "$ROUTE_TABLE"
      fi
    fi
  done
}



interface="$1"
client_address="$2"
endpoint_address="$3"
wireguard_port="$4"
wireguard_config="$5"
proxy_unit="$6"
nfq_unit="$7"
proxy_ready="$8"
nfq_ready="$9"
gateway="${10}"
action="${11:-up}"

cleanup() {
  local failed=0
  local endpoint_routes
  if [[ "$endpoint_address" != "$gateway" ]]; then
    if ! endpoint_routes="$(ip route show exact "$endpoint_address/32")"; then
      failed=1
    elif [[ "$endpoint_routes" == *" via $gateway "* ]] \
      && ! ip route del "$endpoint_address/32" via "$gateway"; then
      failed=1
    fi
  fi
  if ! ip route replace blackhole default table "$ROUTE_TABLE"; then
    failed=1
  fi
  if ! ip -6 route replace blackhole default table "$ROUTE_TABLE"; then
    failed=1
  fi
  proxy_ports add 4
  proxy_ports add 6
  if ip link show "$interface" >/dev/null 2>&1; then
    if ! ip link del "$interface"; then
      failed=1
    fi
  fi
  if (( failed )); then
    echo "agent-sandbox proxy route: cleanup failed" >&2
    return 1
  fi
  return 0
}

if [[ "$action" == cleanup ]]; then
  cleanup
  exit 0
fi

start_second="$(date +%s)"
# Remove stale WireGuard and per-port routes before every generation. The
# cleanup path leaves designated ports pointed at the fail-closed table.
cleanup
trap cleanup EXIT HUP INT TERM

systemctl_ready() {
  local unit="$1"
  local marker="$2"
  local invocation
  invocation="$(systemctl show --property=InvocationID --value "$unit" 2>/dev/null || true)"
  [[ "$invocation" =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ -f "$marker" && ! -L "$marker" ]] || return 1
  [[ "$(cat -- "$marker")" == "$invocation" ]] || return 1
}
# WireGuard reports handshake timestamps with one-second resolution, so a
# handshake in the setup second is already fresh for this interface.
fresh_handshake() {
  local handshake="$1"
  local start_second="$2"
  [[ "$handshake" =~ ^[0-9]+$ && "$handshake" -ge "$start_second" ]]
}


ready_for_route() {
  systemctl_ready "$proxy_unit" "$proxy_ready" && systemctl_ready "$nfq_unit" "$nfq_ready"
}

for _attempt in $(seq 1 60); do
  if ready_for_route; then
    break
  fi
  [[ "$_attempt" -lt 60 ]] || {
    echo "agent-sandbox proxy route: readiness markers are missing or stale" >&2
    exit 1
  }
  sleep 0.5
done

server_key_tmp="$(mktemp)"
client_key_tmp="$(mktemp)"
trap 'rm -f -- "$server_key_tmp"; [[ -z "${client_key_tmp:-}" ]] || rm -f -- "$client_key_tmp"; cleanup' EXIT HUP INT TERM
jq -er .server_key "$wireguard_config" > "$server_key_tmp"
jq -er .client_key "$wireguard_config" > "$client_key_tmp"
server_public="$(wg pubkey < "$server_key_tmp")"
wg pubkey < "$client_key_tmp" >/dev/null

ip link add "$interface" type wireguard
ip addr add "$client_address/32" dev "$interface"
ip link set "$interface" up
if [[ "$endpoint_address" != "$gateway" ]]; then
  ip route replace "$endpoint_address/32" via "$gateway"
fi
# The private client key is supplied only on stdin and removed immediately;
# neither key is interpolated into a command or logged.
wg set "$interface" private-key /dev/stdin \
  peer "$server_public" \
  endpoint "${endpoint_address}:${wireguard_port}" \
  allowed-ips 0.0.0.0/0,::/0 \
  persistent-keepalive 1 < "$client_key_tmp"
rm -f -- "$client_key_tmp"
client_key_tmp=""

for _attempt in $(seq 1 60); do
  if ! ready_for_route; then
    echo "agent-sandbox proxy route: readiness was lost" >&2
    exit 1
  fi
  handshake="$(wg show "$interface" latest-handshakes | awk 'NR == 1 { print $2 }')"
  if fresh_handshake "$handshake" "$start_second"; then
    # Route only HTTP(S) service ports through WireGuard. All other
    # destinations keep the namespace's ordinary kernel route.
    ip route replace default dev "$interface" table "$ROUTE_TABLE"
    ip -6 route replace default dev "$interface" table "$ROUTE_TABLE"
    proxy_ports add 4
    proxy_ports add 6
    trap - EXIT HUP INT TERM
    rm -f -- "$server_key_tmp"
    exit 0
  fi
  sleep 0.5
done

echo "agent-sandbox proxy route: no fresh WireGuard handshake" >&2
exit 1
