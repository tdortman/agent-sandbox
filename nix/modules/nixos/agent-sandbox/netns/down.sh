#!/usr/bin/env bash
set -euo pipefail

ip netns del @netnsName@ 2>/dev/null || true
ip link del @vethHost@ 2>/dev/null || true
