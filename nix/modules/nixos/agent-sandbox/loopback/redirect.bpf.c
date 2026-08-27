// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define LOOPBACK bpf_htonl(0x7f000001U)
#define HANDOFF bpf_htonl(0x7f000002U)
#define LOOPBACK6_LAST bpf_htonl(1U)
#define HANDOFF6_LAST bpf_htonl(2U)
#ifndef TCP_PORT_MATCH
    #define TCP_PORT_MATCH 0
#endif
#ifndef UDP_PORT_MATCH
    #define UDP_PORT_MATCH 0
#endif

struct managed_namespace {
    __u64 cookie;
    __u32 local_ip6[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct managed_namespace);
} managed_netns SEC(".maps");

static __always_inline struct managed_namespace* find_namespace(__u64 cookie) {
    __u32 key = 0;
    struct managed_namespace* namespace = bpf_map_lookup_elem(&managed_netns, &key);

    if (namespace && namespace->cookie == cookie) return namespace;

    key = 1;
    namespace = bpf_map_lookup_elem(&managed_netns, &key);
    if (namespace && namespace->cookie == cookie) return namespace;

    return 0;
}

static __always_inline int namespace_is_managed(struct bpf_sock_addr* ctx) {
    return find_namespace(bpf_get_netns_cookie(ctx)) != 0;
}

static __always_inline int tcp_port_is_shared(__u16 port) {
    return TCP_PORT_MATCH;
}

static __always_inline int udp_port_is_shared(__u16 port) {
    return UDP_PORT_MATCH;
}

static __always_inline int socket_port_is_shared(const struct bpf_sock_addr* ctx) {
    __u16 port = bpf_ntohs(ctx->user_port);

    if (ctx->type == SOCK_STREAM) return tcp_port_is_shared(port);
    if (ctx->type == SOCK_DGRAM) return udp_port_is_shared(port);
    return 0;
}

static __always_inline int ipv6_is(const __u32 address[4], __u32 last_word) {
    return !address[0] && !address[1] && !address[2] && address[3] == last_word;
}

static __always_inline int ipv6_equal(const __u32 left[4], const __u32 right[4]) {
    if (left[0] != right[0]) return 0;
    if (left[1] != right[1]) return 0;
    if (left[2] != right[2]) return 0;
    return left[3] == right[3];
}

static __always_inline void ipv6_copy(__u32 destination[4], const __u32 source[4]) {
    destination[0] = source[0];
    destination[1] = source[1];
    destination[2] = source[2];
    destination[3] = source[3];
}

/* Outgoing IPv4 connections: use 127.0.0.2 only when localhost has no listener. */
static __always_inline int has_local_listener4(struct bpf_sock_addr* ctx) {
    struct bpf_sock_tuple tuple = {};
    struct bpf_sock* sk;
    int found;

    tuple.ipv4.daddr = LOOPBACK;
    tuple.ipv4.dport = ctx->user_port;

    if (ctx->type == SOCK_STREAM) {
        sk = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else {
        sk = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    }

    if (!sk) return 0;

    found =
        sk->src_port == bpf_ntohs(ctx->user_port) && (sk->src_ip4 == LOOPBACK || sk->src_ip4 == 0);
    bpf_sk_release(sk);
    return found;
}

static __always_inline int redirect_if_remote4(struct bpf_sock_addr* ctx) {
    if (!namespace_is_managed(ctx)) return 1;
    if (ctx->user_family != AF_INET || ctx->user_ip4 != LOOPBACK) return 1;
    if (!socket_port_is_shared(ctx) || has_local_listener4(ctx)) return 1;

    ctx->user_ip4 = HANDOFF;
    return 1;
}

SEC("cgroup/connect4")
int asbx_connect4(struct bpf_sock_addr* ctx) {
    return redirect_if_remote4(ctx);
}

SEC("cgroup/sendmsg4")
int asbx_sendmsg4(struct bpf_sock_addr* ctx) {
    return redirect_if_remote4(ctx);
}

static __always_inline int restore_localhost4(struct bpf_sock_addr* ctx) {
    if (!namespace_is_managed(ctx)) return 1;
    if (ctx->user_family != AF_INET || ctx->user_ip4 != HANDOFF) return 1;
    if (!socket_port_is_shared(ctx)) return 1;

    ctx->user_ip4 = LOOPBACK;
    return 1;
}

SEC("cgroup/getpeername4")
int asbx_peername4(struct bpf_sock_addr* ctx) {
    return restore_localhost4(ctx);
}

SEC("cgroup/recvmsg4")
int asbx_recvmsg4(struct bpf_sock_addr* ctx) {
    return restore_localhost4(ctx);
}

/* IPv6 listeners use the namespace's private veth address internally. */

SEC("cgroup/bind6")
int asbx_bind6(struct bpf_sock_addr* ctx) {
    struct managed_namespace* namespace;

    if (ctx->user_family != AF_INET6 || !ipv6_is(ctx->user_ip6, LOOPBACK6_LAST)) return 1;
    if (!socket_port_is_shared(ctx)) return 1;

    namespace = find_namespace(bpf_get_netns_cookie(ctx));
    if (!namespace) return 1;

    ipv6_copy(ctx->user_ip6, namespace->local_ip6);
    return 1;
}

/* IPv6 connects prefer this namespace's listener, then use the remote handoff. */

static __always_inline int has_listener6(struct bpf_sock_addr* ctx, const __u32 address[4]) {
    struct bpf_sock_tuple tuple = {};
    struct bpf_sock* sk;
    int address_is_local;
    int found;

    ipv6_copy(tuple.ipv6.daddr, address);
    tuple.ipv6.dport = ctx->user_port;

    if (ctx->type == SOCK_STREAM) {
        sk = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
    } else {
        sk = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
    }

    if (!sk) return 0;

    address_is_local = ipv6_equal(sk->src_ip6, address) || ipv6_is(sk->src_ip6, 0);
    found = sk->src_port == bpf_ntohs(ctx->user_port) && address_is_local;
    bpf_sk_release(sk);
    return found;
}

static __always_inline int redirect_if_remote6(struct bpf_sock_addr* ctx) {
    struct managed_namespace* namespace;

    if (ctx->user_family != AF_INET6 || !ipv6_is(ctx->user_ip6, LOOPBACK6_LAST)) return 1;
    if (!socket_port_is_shared(ctx)) return 1;

    namespace = find_namespace(bpf_get_netns_cookie(ctx));
    if (!namespace) return 1;

    /* Keep listeners that were already bound when this program was attached working locally. */
    if (has_listener6(ctx, ctx->user_ip6)) return 1;

    if (has_listener6(ctx, namespace->local_ip6)) {
        ipv6_copy(ctx->user_ip6, namespace->local_ip6);
        return 1;
    }

    ctx->user_ip6[3] = HANDOFF6_LAST;
    return 1;
}

SEC("cgroup/connect6")
int asbx_connect6(struct bpf_sock_addr* ctx) {
    return redirect_if_remote6(ctx);
}

SEC("cgroup/sendmsg6")
int asbx_sendmsg6(struct bpf_sock_addr* ctx) {
    return redirect_if_remote6(ctx);
}

static __always_inline int restore_localhost6(struct bpf_sock_addr* ctx) {
    struct managed_namespace* namespace;

    if (ctx->user_family != AF_INET6) return 1;
    if (!socket_port_is_shared(ctx)) return 1;

    namespace = find_namespace(bpf_get_netns_cookie(ctx));
    if (!namespace) return 1;
    if (!ipv6_is(ctx->user_ip6, HANDOFF6_LAST) && !ipv6_equal(ctx->user_ip6, namespace->local_ip6))
        return 1;

    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = 0;
    ctx->user_ip6[3] = LOOPBACK6_LAST;
    return 1;
}

SEC("cgroup/getpeername6")
int asbx_peername6(struct bpf_sock_addr* ctx) {
    return restore_localhost6(ctx);
}

SEC("cgroup/recvmsg6")
int asbx_recvmsg6(struct bpf_sock_addr* ctx) {
    return restore_localhost6(ctx);
}

SEC("cgroup/getsockname6")
int asbx_sockname6(struct bpf_sock_addr* ctx) {
    return restore_localhost6(ctx);
}

char LICENSE[] SEC("license") = "GPL";
