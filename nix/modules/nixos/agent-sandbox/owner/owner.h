#ifndef AGENT_SANDBOX_OWNER_H
#define AGENT_SANDBOX_OWNER_H

#include "kernel_types.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <stdbool.h>

#define AF_INET 2
#define AF_INET6 10
/* Kernel-internal file mode, not exposed by the UAPI headers. */
#define FMODE_PATH (1U << 14)

/* Wire layout shared with socket_owner/kernel.rs. Addresses and remote_port
 * use network byte order; the other fields use native byte order. */
struct owner_query {
    __u64 nonce;
    __u32 local_addr[4];
    __u32 remote_addr[4];
    __u16 local_port;
    __u16 remote_port;
    __u16 family;
    __u16 protocol;
};

_Static_assert(sizeof(struct owner_query) == 48, "owner query ABI");

static __always_inline bool read_socket_protocol(const struct sock *sk, __u64 *protocol) {
    /* sk_protocol was a bitfield on older kernels. Keep libbpf's extraction
     * semantics, but propagate the probe error instead of accepting zero. */
    *protocol = 0;
    if (__CORE_BITFIELD_PROBE_READ(protocol, sk, sk_protocol)) {
        return false;
    }

    *protocol <<= __CORE_RELO(sk, sk_protocol, LSHIFT_U64);
    *protocol >>= __CORE_RELO(sk, sk_protocol, RSHIFT_U64);
    return true;
}

static __always_inline bool read_socket_addresses(const struct sock *sk, __u16 family,
                                                  __u32 local_addr[4], __u32 remote_addr[4]) {
    switch (family) {
    case AF_INET:
        return !BPF_CORE_READ_INTO(&local_addr[0], sk, __sk_common.skc_rcv_saddr) &&
               !BPF_CORE_READ_INTO(&remote_addr[0], sk, __sk_common.skc_daddr);
    case AF_INET6:
        return !bpf_core_read(local_addr, 16, &sk->__sk_common.skc_v6_rcv_saddr) &&
               !bpf_core_read(remote_addr, 16, &sk->__sk_common.skc_v6_daddr);
    default:
        return false;
    }
}

static __always_inline bool address_is_unspecified(const __u32 address[4]) {
    return !address[0] && !address[1] && !address[2] && !address[3];
}

static __always_inline bool addresses_equal(const __u32 left[4], const __u32 right[4]) {
    return __builtin_memcmp(left, right, 16) == 0;
}

/* False means the credentials could not be read. A successful read reports
 * membership separately, so an incompatible holder is never silently skipped. */
static __always_inline bool read_uid_membership(const struct task_struct *task, __u32 uid,
                                                bool *matches) {
    const struct cred *cred = NULL;
    __u32 real_uid;
    __u32 effective_uid;
    __u32 saved_uid;
    __u32 filesystem_uid;

    if (BPF_CORE_READ_INTO(&cred, task, cred) || !cred ||
        BPF_CORE_READ_INTO(&real_uid, cred, uid.val) ||
        BPF_CORE_READ_INTO(&effective_uid, cred, euid.val) ||
        BPF_CORE_READ_INTO(&saved_uid, cred, suid.val) ||
        BPF_CORE_READ_INTO(&filesystem_uid, cred, fsuid.val)) {
        return false;
    }

    *matches = uid == real_uid || uid == effective_uid || uid == saved_uid || uid == filesystem_uid;
    return true;
}

#endif
