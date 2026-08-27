#!/usr/bin/env bash
set -euo pipefail

pin_root=/sys/fs/bpf/agent-sandbox-loopback
programs="$pin_root/programs"
maps="$pin_root/maps"
cgroup=/sys/fs/cgroup

detach() {
    local attach_type="$1"
    local program="$2"
    [[ -e "$programs/$program" ]] || return 0
    bpftool cgroup detach "$cgroup" "$attach_type" pinned "$programs/$program" 2>/dev/null || true
}

cleanup() {
    detach cgroup_inet4_connect asbx_connect4
    detach cgroup_udp4_sendmsg asbx_sendmsg4
    detach cgroup_inet4_getpeername asbx_peername4
    detach cgroup_udp4_recvmsg asbx_recvmsg4
    detach cgroup_inet6_bind asbx_bind6
    detach cgroup_inet6_connect asbx_connect6
    detach cgroup_udp6_sendmsg asbx_sendmsg6
    detach cgroup_inet6_getpeername asbx_peername6
    detach cgroup_udp6_recvmsg asbx_recvmsg6
    detach cgroup_inet6_getsockname asbx_sockname6
    rm -f \
        "$programs/asbx_connect4" \
        "$programs/asbx_sendmsg4" \
        "$programs/asbx_peername4" \
        "$programs/asbx_recvmsg4" \
        "$programs/asbx_bind6" \
        "$programs/asbx_connect6" \
        "$programs/asbx_sendmsg6" \
        "$programs/asbx_peername6" \
        "$programs/asbx_recvmsg6" \
        "$programs/asbx_sockname6"
    rm -f "$maps/managed_netns"
    rmdir "$programs" "$maps" "$pin_root" 2>/dev/null || true
}

if [[ "${1:-up}" == cleanup ]]; then
    cleanup
    exit 0
fi

cleanup
mkdir -p "$programs" "$maps"
trap cleanup ERR

bpftool prog loadall @bpfObject@ "$programs" pinmaps "$maps"
read -r -a host_endpoint <<<"$(@helperBin@ endpoint @hostIp6@)"
read -r -a sandbox_endpoint <<<"$(ip netns exec @netnsName@ @helperBin@ endpoint @netnsIp6@)"
bpftool map update pinned "$maps/managed_netns" key hex 00 00 00 00 value hex "${host_endpoint[@]}"
bpftool map update pinned "$maps/managed_netns" key hex 01 00 00 00 value hex "${sandbox_endpoint[@]}"
bpftool cgroup attach "$cgroup" cgroup_inet4_connect pinned "$programs/asbx_connect4" multi
bpftool cgroup attach "$cgroup" cgroup_udp4_sendmsg pinned "$programs/asbx_sendmsg4" multi
bpftool cgroup attach "$cgroup" cgroup_inet4_getpeername pinned "$programs/asbx_peername4" multi
bpftool cgroup attach "$cgroup" cgroup_udp4_recvmsg pinned "$programs/asbx_recvmsg4" multi
bpftool cgroup attach "$cgroup" cgroup_inet6_bind pinned "$programs/asbx_bind6" multi
bpftool cgroup attach "$cgroup" cgroup_inet6_connect pinned "$programs/asbx_connect6" multi
bpftool cgroup attach "$cgroup" cgroup_udp6_sendmsg pinned "$programs/asbx_sendmsg6" multi
bpftool cgroup attach "$cgroup" cgroup_inet6_getpeername pinned "$programs/asbx_peername6" multi
bpftool cgroup attach "$cgroup" cgroup_udp6_recvmsg pinned "$programs/asbx_recvmsg6" multi
bpftool cgroup attach "$cgroup" cgroup_inet6_getsockname pinned "$programs/asbx_sockname6" multi

trap - ERR
