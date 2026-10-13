#!/usr/bin/env bash
set -euo pipefail

ip netns del @netnsName@ 2>/dev/null || true
ip link del @vethHost@ 2>/dev/null || true
ip -6 route del local @loopbackHandoffIp6@/128 dev lo 2>/dev/null || true
ip rule del from @netnsIp@ lookup @egressRouteTable@ 2>/dev/null || true
ip -6 rule del from @netnsIp6@ lookup @egressRouteTable@ 2>/dev/null || true
ip route flush table @egressRouteTable@ 2>/dev/null || true
ip -6 route flush table @egressRouteTable@ 2>/dev/null || true
