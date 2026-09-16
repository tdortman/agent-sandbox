// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define VERDICT_PROTO_TCP 6
#define VERDICT_PROTO_UDP 17
#define VERDICT_DENY 0

/* Byte-identical to the `DestKey` encoding in
 * `crates/core/src/verdict_map.rs`. IPv4 destinations use the v4-mapped form
 * so the key needs no family field. */
struct dest_key {
    __u64 netns_cookie;
    __u8 proto;
    __u8 pad[3];
    __u8 ip[16];
    __be16 port;
    __u16 pad2;
};

/* Byte-identical to `VerdictValue`. */
struct verdict_value {
    __u8 verdict;
    __u8 pad[3];
    __u32 generation;
};

/* Byte-identical to `NamespaceState`. */
struct namespace_state {
    __u32 generation;
    __u32 blocked;
    __u32 proxy_uid;
    __u32 reserved;
};

_Static_assert(sizeof(struct dest_key) == 32, "dest_key must match the DestKey encoding");
_Static_assert(sizeof(struct verdict_value) == 8, "verdict_value must match VerdictValue");
_Static_assert(sizeof(struct namespace_state) == 16, "namespace_state must match NamespaceState");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dest_key);
    __type(value, struct verdict_value);
} verdicts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct namespace_state);
} namespace_state SEC(".maps");

static __always_inline int gate_decision(struct bpf_sock_addr* ctx, int is_v6) {
    struct namespace_state* state;
    struct verdict_value* verdict;
    struct dest_key key = {};
    __u64 cookie = bpf_get_netns_cookie(ctx);

    /* Attached at the root cgroup, so bail out cheaply for every process
     * outside a gated sandbox. */
    state = bpf_map_lookup_elem(&namespace_state, &cookie);
    if (!state) return 1;

    /* Revocation flag: while set, no new flows leave this namespace. */
    if (state->blocked) return 0;

    /* The trusted proxy connects from inside the same namespace, so its own
     * upstream sockets are exempt from its sandbox's denials. */
    if ((__u32)bpf_get_current_uid_gid() == state->proxy_uid) return 1;

    key.netns_cookie = cookie;
    if (ctx->type == SOCK_STREAM) {
        key.proto = VERDICT_PROTO_TCP;
    } else if (ctx->type == SOCK_DGRAM) {
        key.proto = VERDICT_PROTO_UDP;
    } else {
        return 1;
    }

    if (is_v6) {
        __builtin_memcpy(key.ip, ctx->user_ip6, sizeof(key.ip));
    } else {
        __u32 addr = ctx->user_ip4;
        key.ip[10] = 0xff;
        key.ip[11] = 0xff;
        __builtin_memcpy(&key.ip[12], &addr, sizeof(addr));
    }
    key.port = ctx->user_port;

    verdict = bpf_map_lookup_elem(&verdicts, &key);
    /* A stale entry never denies: on a generation mismatch the flow falls
     * through to the ordinary userspace policy path, exactly as if the gate
     * were absent. */
    if (verdict && verdict->generation == state->generation && verdict->verdict == VERDICT_DENY) {
        return 0;
    }
    return 1;
}

/* Returning 0 fails the connect with EPERM before any packet exists, so a
 * cached deny skips the whole NFQUEUE leg and the per-denial nft spawn. */
SEC("cgroup/connect4")
int asbx_gate_connect4(struct bpf_sock_addr* ctx) {
    return gate_decision(ctx, 0);
}

SEC("cgroup/connect6")
int asbx_gate_connect6(struct bpf_sock_addr* ctx) {
    return gate_decision(ctx, 1);
}

char LICENSE[] SEC("license") = "GPL";
