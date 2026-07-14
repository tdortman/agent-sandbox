#!/usr/bin/env bash
set -euo pipefail

proxy_user="$1"
proxy_group="$2"
proxy_host_ip="$3"
dns_server_ip="$4"
wireguard_port="$5"
cidrs_file="$6"
table_name="$7"
action="${8:-apply}"

proxy_uid="$(id -u "$proxy_user")"
proxy_gid="$(id -g "$proxy_group")"
[[ "$proxy_uid" =~ ^[1-9][0-9]*$ ]] || { echo "agent-sandbox proxy: invalid proxy UID" >&2; exit 1; }
[[ "$proxy_gid" =~ ^[1-9][0-9]*$ ]] || { echo "agent-sandbox proxy: invalid proxy GID" >&2; exit 1; }

table_state() {
  if nft list table inet "$table_name" >/dev/null 2>&1; then
    return 0
  fi
  nft list tables >/dev/null 2>&1 || return 2
  return 1
}

cleanup() {
  local state
  if table_state; then
    state=0
  else
    state=$?
  fi
  if (( state == 2 )); then
    echo "agent-sandbox proxy firewall: cannot inspect nftables" >&2
    return 1
  fi
  if (( state == 0 )); then
    nft delete table inet "$table_name"
  fi
}

if [[ "$action" == cleanup ]]; then
  cleanup
  exit 0
fi

rules_file="$(mktemp)"
apply_file="$rules_file"
trap 'rm -f "$rules_file" "$apply_file"' EXIT
{
  printf 'table inet %s {\n' "$table_name"
  printf ' chain output { type filter hook output priority 10; policy accept; meta skuid %s jump proxy_egress; }\n' "$proxy_uid"
  printf ' chain proxy_egress {\n'
  printf '  ct state established,related accept\n'
  printf '  ip daddr %s udp dport 53 accept\n' "$dns_server_ip"
  printf '  ip daddr %s tcp dport 53 accept\n' "$dns_server_ip"
  printf '  ip daddr %s udp dport %s accept\n' "$proxy_host_ip" "$wireguard_port"
  while IFS= read -r cidr; do
    [[ -n "$cidr" ]] || continue
    case "$cidr" in
      *:*) printf '  ip6 daddr %s accept\n' "$cidr" ;;
      *) printf '  ip daddr %s accept\n' "$cidr" ;;
    esac
  done < <(jq -r '.[]' "$cidrs_file")
  printf '  fib daddr type local reject\n'
  # Permit public upstream destinations, while keeping private and reserved
  # address ranges fail-closed unless explicitly listed above.
  printf '  ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } accept\n'
  printf '  ip6 daddr != { ::/128, ::1/128, ::ffff:0:0/96, 100::/64, 2001:2::/48, 2001:10::/28, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 } accept\n'
  printf '  reject\n'
  printf ' }\n}\n'
} > "$rules_file"

# Validate before applying. If malformed or out-of-range CIDRs are supplied,
# fail closed without leaving a partially updated live table.
if table_state; then
  apply_file="$(mktemp)"
  {
    printf 'delete table inet %s\n' "$table_name"
    cat "$rules_file"
  } > "$apply_file"
else
  table_status=$?
  if (( table_status == 2 )); then
    echo "agent-sandbox proxy firewall: cannot inspect nftables" >&2
    exit 1
  fi
fi
nft -c -f "$apply_file"
nft -f "$apply_file"
