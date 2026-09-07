/* Resolve every live holder of a socket tuple. Partial scans are never valid. */
#include "owner.h"

struct bpf_iter_meta {
    struct seq_file *seq;
    __u64 session_id;
    __u64 seq_num;
};

struct bpf_iter__task_file {
    struct bpf_iter_meta *meta;
    struct task_struct *task;
    __u32 fd;
    struct file *file;
};

enum holder_status {
    HOLDER_VALID,
    HOLDER_INCOMPATIBLE_UID,
    HOLDER_READ_FAILED,
};

/* Wire layout consumed by KernelOwnerResolver::parse. A completion record has
 * complete=1 and no identity fields; all other records describe one holder. */
struct owner_record {
    __u64 nonce;
    __u64 inode;
    __u64 start_boot_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 fd;
    __u32 complete;
    __u32 status;
};

_Static_assert(sizeof(struct owner_record) == 48, "owner record ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct owner_query);
} queries SEC(".maps");

enum socket_match {
    SOCKET_READ_FAILED = -1,
    SOCKET_NO_MATCH,
    SOCKET_MATCH,
};

static __always_inline enum socket_match match_socket(const struct sock *sk,
                                                      const struct owner_query *query) {
    struct task_struct *reader = (void *)bpf_get_current_task();
    struct net *socket_net = NULL;
    struct net *reader_net = NULL;
    __u64 protocol;
    __u16 family;
    __u16 local_port;
    __u16 remote_port;
    __u32 local_addr[4] = {};
    __u32 remote_addr[4] = {};

    if (!read_socket_protocol(sk, &protocol)) {
        return SOCKET_READ_FAILED;
    }
    if (protocol != query->protocol) {
        return SOCKET_NO_MATCH;
    }

    if (BPF_CORE_READ_INTO(&socket_net, sk, __sk_common.skc_net.net) ||
        BPF_CORE_READ_INTO(&reader_net, reader, nsproxy, net_ns) || !socket_net || !reader_net) {
        return SOCKET_READ_FAILED;
    }
    if (socket_net != reader_net) {
        return SOCKET_NO_MATCH;
    }

    if (BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family) ||
        BPF_CORE_READ_INTO(&local_port, sk, __sk_common.skc_num)) {
        return SOCKET_READ_FAILED;
    }
    if (family != query->family || local_port != query->local_port) {
        return SOCKET_NO_MATCH;
    }

    if (BPF_CORE_READ_INTO(&remote_port, sk, __sk_common.skc_dport)) {
        return SOCKET_READ_FAILED;
    }
    if (query->remote_port && remote_port != query->remote_port) {
        return SOCKET_NO_MATCH;
    }

    if (!read_socket_addresses(sk, family, local_addr, remote_addr)) {
        return SOCKET_READ_FAILED;
    }
    if (!address_is_unspecified(local_addr) && !addresses_equal(local_addr, query->local_addr)) {
        return SOCKET_NO_MATCH;
    }
    if (query->remote_port && !addresses_equal(remote_addr, query->remote_addr)) {
        return SOCKET_NO_MATCH;
    }

    return SOCKET_MATCH;
}

static __always_inline enum holder_status read_holder(const struct task_struct *task,
                                                      const struct inode *inode,
                                                      const struct sock *sk,
                                                      struct owner_record *record) {
    struct task_struct *leader = NULL;
    bool uid_matches;

    if (BPF_CORE_READ_INTO(&leader, task, group_leader) || !leader ||
        BPF_CORE_READ_INTO(&record->inode, inode, i_ino) ||
        BPF_CORE_READ_INTO(&record->pid, task, tgid) ||
        BPF_CORE_READ_INTO(&record->tid, task, pid) ||
        BPF_CORE_READ_INTO(&record->start_boot_ns, leader, start_boottime) ||
        BPF_CORE_READ_INTO(&record->uid, sk, sk_uid.val) ||
        !read_uid_membership(task, record->uid, &uid_matches)) {
        return HOLDER_READ_FAILED;
    }

    return uid_matches ? HOLDER_VALID : HOLDER_INCOMPATIBLE_UID;
}

static __always_inline int emit_record(struct bpf_iter__task_file *ctx,
                                       const struct owner_record *record) {
    return bpf_seq_write(ctx->meta->seq, record, sizeof(*record)) ? 1 : 0;
}

static __always_inline int emit_read_failure(struct bpf_iter__task_file *ctx,
                                             const struct owner_query *query) {
    struct owner_record record = {
        .nonce = query->nonce,
        .fd = ctx->fd,
        .status = HOLDER_READ_FAILED,
    };

    return emit_record(ctx, &record);
}

SEC("iter/task_file")
int asbx_owners(struct bpf_iter__task_file *ctx) {
    __u32 key = 0;
    const struct owner_query *query = bpf_map_lookup_elem(&queries, &key);
    if (!query) {
        return 0;
    }

    struct owner_record record = {.nonce = query->nonce};
    struct task_struct *task = ctx->task;
    if (!task) {
        record.complete = 1;
        return emit_record(ctx, &record);
    }

    struct file *file = ctx->file;
    if (!file) {
        return 0;
    }

    /* The iterator holds a file reference, which also pins its inode. */
    struct inode *inode = file->f_inode;
    if (!inode) {
        return emit_read_failure(ctx, query);
    }
    if ((inode->i_mode & S_IFMT) != S_IFSOCK || (file->f_mode & FMODE_PATH)) {
        return 0;
    }

    struct socket *socket = NULL;
    struct sock *sk = NULL;
    if (BPF_CORE_READ_INTO(&socket, file, private_data) || !socket ||
        BPF_CORE_READ_INTO(&sk, socket, sk)) {
        return emit_read_failure(ctx, query);
    }
    if (!sk) {
        return 0;
    }

    switch (match_socket(sk, query)) {
    case SOCKET_READ_FAILED:
        return emit_read_failure(ctx, query);
    case SOCKET_NO_MATCH:
        return 0;
    case SOCKET_MATCH:
        record.fd = ctx->fd;
        record.status = read_holder(task, inode, sk, &record);
        return emit_record(ctx, &record);
    }

    return emit_read_failure(ctx, query);
}

char LICENSE[] SEC("license") = "GPL";
