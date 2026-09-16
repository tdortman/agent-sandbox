#!/usr/bin/env bash
set -euo pipefail

# Pinned under the global bpffs, like loopback/bpf.sh: a private bpffs mount
# here would live on a distinct superblock that nfq cannot rely on seeing
# from its own service, so this script never mounts or unmounts anything.
pin_root=@verdictMapDir@
cgroup=/sys/fs/cgroup

detach() {
    local attach_type="$1"
    local program="$2"
    [[ -e "$pin_root/$program" ]] || return 0
    bpftool cgroup detach "$cgroup" "$attach_type" pinned "$pin_root/$program" 2>/dev/null || true
}

cleanup() {
    detach cgroup_inet4_connect asbx_gate_connect4
    detach cgroup_inet6_connect asbx_gate_connect6
    rm -f \
        "$pin_root/asbx_gate_connect4" \
        "$pin_root/asbx_gate_connect6"
    rm -f "$pin_root/verdicts" "$pin_root/namespace_state"
    rmdir "$pin_root" 2>/dev/null || true
}

if [[ "${1:-up}" == cleanup ]]; then
    cleanup
    exit 0
fi

fail_soft() {
    echo "agent-sandbox verdict gate: $1; continuing without kernel-side denial" >&2
    cleanup
    exit 0
}

cleanup
mkdir -p "$pin_root" || fail_soft "cannot create pin directory $pin_root"

if ! bpftool prog loadall @bpfObject@ "$pin_root" pinmaps "$pin_root"; then
    fail_soft "bpftool prog loadall failed"
fi
if ! bpftool cgroup attach "$cgroup" cgroup_inet4_connect pinned "$pin_root/asbx_gate_connect4" multi; then
    fail_soft "cgroup_inet4_connect attach failed"
fi
if ! bpftool cgroup attach "$cgroup" cgroup_inet6_connect pinned "$pin_root/asbx_gate_connect6" multi; then
    fail_soft "cgroup_inet6_connect attach failed"
fi
