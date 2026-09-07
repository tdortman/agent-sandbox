/* A connect hint plus live descriptor proof, never a policy grant. */
#include "owner.h"

#define MAX_TRACKED_ENTRIES 65536
#define MAX_FD_SCAN 4096

extern struct task_struct *bpf_task_from_pid(__s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
extern void *bpf_rdonly_cast(const void *obj, __u32 btf_id) __ksym;

struct process_identity {
    __u64 start_boot_ns;
    __u32 pid;
    __u32 pad;
};

struct endpoint {
    __u64 netns;
    __u32 local_addr[4];
    __u32 remote_addr[4];
    __u16 local_port;
    __u16 remote_port;
    __u16 family;
    __u16 pad;
};

struct connect_hint {
    struct process_identity owner;
    __u64 inode;
    __u32 tid;
    __u32 fd;
};

/* Wire layout consumed by socket_owner/hint.rs. valid remains zero until the
 * entire live proof succeeds. A hint alone cannot produce a valid result. */
struct hint_result {
    __u64 nonce;
    __u64 inode;
    __u64 start_boot_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 fd;
    __u32 valid;
    __u32 pad;
};

_Static_assert(sizeof(struct hint_result) == 48, "hint result ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct owner_query);
} queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hint_result);
} results SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} scope SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_ENTRIES);
    __type(key, __u64);
    __type(value, struct process_identity);
} clean_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_ENTRIES);
    __type(key, struct endpoint);
    __type(value, struct connect_hint);
} hints SEC(".maps");

/* These maps start empty. Existing tables remain unknown. A newly copied table
 * belongs only to the new process, and a cross-process CLONE_FILES invalidates
 * it before copy_files can expose it. Eviction and failed insertion only lose
 * eligibility. No event can re-enable a still-live tainted table. */
SEC("raw_tp/sched_process_fork")
int owner_new_files(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *parent = (void *)ctx->args[0];
    struct task_struct *child = (void *)ctx->args[1];
    struct files_struct *files = NULL;
    struct files_struct *parent_files = NULL;
    struct process_identity owner = {};

    if (BPF_CORE_READ_INTO(&files, child, files) ||
        BPF_CORE_READ_INTO(&parent_files, parent, files) ||
        BPF_CORE_READ_INTO(&owner.pid, child, tgid) ||
        BPF_CORE_READ_INTO(&owner.start_boot_ns, child, group_leader, start_boottime) || !files ||
        !parent_files || !owner.pid || !owner.start_boot_ns || files == parent_files) {
        return 0;
    }

    __u64 key = (__u64)files;
    bpf_map_update_elem(&clean_files, &key, &owner, BPF_ANY);
    return 0;
}

SEC("lsm/task_alloc")
int owner_share_files(__u64 *ctx) {
    int ret = ctx[2];
    if (ret) {
        return ret;
    }

    unsigned long flags = ctx[1];
    if ((flags & CLONE_FILES) && !(flags & CLONE_THREAD)) {
        struct task_struct *task = (void *)bpf_get_current_task_btf();
        __u64 key = (__u64)task->files;
        bpf_map_delete_elem(&clean_files, &key);
    }
    return ret;
}

static __always_inline bool read_endpoint(const struct sock *sk, struct endpoint *endpoint) {
    __u64 protocol;
    __u32 netns;
    if (!read_socket_protocol(sk, &protocol) || protocol != IPPROTO_TCP) {
        return false;
    }
    if (BPF_CORE_READ_INTO(&netns, sk, __sk_common.skc_net.net, ns.inum) ||
        BPF_CORE_READ_INTO(&endpoint->family, sk, __sk_common.skc_family) ||
        BPF_CORE_READ_INTO(&endpoint->local_port, sk, __sk_common.skc_num) ||
        BPF_CORE_READ_INTO(&endpoint->remote_port, sk, __sk_common.skc_dport) || !netns ||
        !endpoint->local_port || !endpoint->remote_port) {
        return false;
    }
    endpoint->netns = netns;
    return read_socket_addresses(sk, endpoint->family, endpoint->local_addr, endpoint->remote_addr);
}

struct fd_search {
    struct file **fds;
    struct file *target;
    __u32 max_fds;
    __u32 found_plus_one;
};

static long find_fd(__u32 fd, void *ctx) {
    struct fd_search *search = ctx;
    if (fd >= search->max_fds) {
        return 1;
    }

    struct file *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), &search->fds[fd])) {
        return 1;
    }
    if (file == search->target) {
        search->found_plus_one = fd + 1;
        return 1;
    }
    return 0;
}

static __always_inline bool capture_hint(struct task_struct *task, struct sock *sk,
                                         struct connect_hint *hint) {
    struct file *file = NULL;
    struct fdtable *table = NULL;
    if (BPF_CORE_READ_INTO(&file, sk, sk_socket, file) || !file ||
        BPF_CORE_READ_INTO(&table, task, files, fdt) || !table) {
        return false;
    }

    struct fd_search search = {.target = file};
    if (BPF_CORE_READ_INTO(&search.fds, table, fd) || !search.fds ||
        BPF_CORE_READ_INTO(&search.max_fds, table, max_fds)) {
        return false;
    }
    /* ponytail: descriptors above MAX_FD_SCAN use the full ownership iterator. */
    if (bpf_loop(MAX_FD_SCAN, find_fd, &search, 0) < 0 || !search.found_plus_one) {
        return false;
    }

    hint->fd = search.found_plus_one - 1;
    if (BPF_CORE_READ_INTO(&hint->owner.pid, task, tgid) ||
        BPF_CORE_READ_INTO(&hint->owner.start_boot_ns, task, group_leader, start_boottime) ||
        BPF_CORE_READ_INTO(&hint->inode, file, f_inode, i_ino) ||
        BPF_CORE_READ_INTO(&hint->tid, task, pid)) {
        return false;
    }
    return hint->inode && hint->owner.pid && hint->owner.start_boot_ns && hint->tid;
}

SEC("fentry/tcp_connect")
int owner_connect(__u64 *ctx) {
    struct sock *sk = (void *)ctx[0];
    struct endpoint key = {};
    if (!sk || !read_endpoint(sk, &key)) {
        return 0;
    }

    __u32 zero = 0;
    __u64 *netns = bpf_map_lookup_elem(&scope, &zero);
    if (!netns || *netns != key.netns) {
        return 0;
    }
    bpf_map_delete_elem(&hints, &key);

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    struct connect_hint hint = {};
    if (capture_hint(task, sk, &hint)) {
        bpf_map_update_elem(&hints, &key, &hint, BPF_ANY);
    }
    return 0;
}

static __always_inline bool files_are_private(struct files_struct *files,
                                              const struct process_identity *expected) {
    __u64 key = (__u64)files;
    const struct process_identity *owner = bpf_map_lookup_elem(&clean_files, &key);
    return owner && owner->pid == expected->pid && owner->start_boot_ns == expected->start_boot_ns;
}

static __always_inline struct file *read_descriptor(struct fdtable *table, __u32 fd) {
    struct file *file = NULL;
    if (fd >= table->max_fds || bpf_probe_read_kernel(&file, sizeof(file), &table->fd[fd])) {
        return NULL;
    }
    return file;
}

static __always_inline bool has_single_reference(const struct file *file) {
    /* file_ref_t encodes one live reference as zero. Any duplicate descriptor,
     * transferred descriptor or temporary external reference takes fallback. */
    return __atomic_load_n(&file->f_ref.refcnt.counter, __ATOMIC_ACQUIRE) == 0;
}

static __always_inline bool prove_hint(struct task_struct *task, const struct connect_hint *hint,
                                       const struct endpoint *expected, __u32 *uid) {
    __u64 start_boot_ns;
    if (task->tgid != hint->owner.pid ||
        BPF_CORE_READ_INTO(&start_boot_ns, task, group_leader, start_boottime) ||
        start_boot_ns != hint->owner.start_boot_ns) {
        return false;
    }

    struct files_struct *files = task->files;
    if (!files || !files_are_private(files, &hint->owner)) {
        return false;
    }
    struct fdtable *table = files->fdt;
    if (!table) {
        return false;
    }
    struct file *file = read_descriptor(table, hint->fd);
    if (!file) {
        return false;
    }
    file = bpf_rdonly_cast(file, bpf_core_type_id_kernel(struct file));
    if (!has_single_reference(file) || (file->f_mode & FMODE_PATH)) {
        return false;
    }

    __u64 inode;
    struct socket *socket = NULL;
    struct sock *sk = NULL;
    if (BPF_CORE_READ_INTO(&inode, file, f_inode, i_ino) || inode != hint->inode ||
        BPF_CORE_READ_INTO(&socket, file, private_data) || !socket ||
        BPF_CORE_READ_INTO(&sk, socket, sk) || !sk) {
        return false;
    }
    struct endpoint live = {};
    if (!read_endpoint(sk, &live) || __builtin_memcmp(&live, expected, sizeof(live))) {
        return false;
    }
    bool uid_matches;
    if (BPF_CORE_READ_INTO(uid, sk, sk_uid.val) || !read_uid_membership(task, *uid, &uid_matches) ||
        !uid_matches) {
        return false;
    }

    if (task->files != files || files->fdt != table || read_descriptor(table, hint->fd) != file ||
        !has_single_reference(file)) {
        return false;
    }
    /* Re-look up after the proof; a concurrent share permanently removed it. */
    return files_are_private(files, &hint->owner);
}

SEC("raw_tp")
int owner_hint(struct bpf_raw_tracepoint_args *ctx) {
    __u32 zero = 0;
    const struct owner_query *query = bpf_map_lookup_elem(&queries, &zero);
    struct hint_result *out = bpf_map_lookup_elem(&results, &zero);
    if (!query || !out) {
        return 0;
    }
    *out = (struct hint_result){.nonce = query->nonce};
    if (query->protocol != IPPROTO_TCP || !query->remote_port) {
        return 0;
    }

    struct task_struct *reader = (void *)bpf_get_current_task_btf();
    struct endpoint key = {
        .family = query->family,
        .local_port = query->local_port,
        .remote_port = query->remote_port,
    };
    __u32 netns;
    if (BPF_CORE_READ_INTO(&netns, reader, nsproxy, net_ns, ns.inum) || !netns) {
        return 0;
    }
    key.netns = netns;
    __builtin_memcpy(key.local_addr, query->local_addr, sizeof(key.local_addr));
    __builtin_memcpy(key.remote_addr, query->remote_addr, sizeof(key.remote_addr));

    const struct connect_hint *stored = bpf_map_lookup_elem(&hints, &key);
    if (!stored) {
        return 0;
    }
    struct connect_hint hint = *stored;
    struct task_struct *task = bpf_task_from_pid(hint.tid);
    if (!task) {
        return 0;
    }

    __u32 uid;
    if (prove_hint(task, &hint, &key, &uid)) {
        *out = (struct hint_result){
            .nonce = query->nonce,
            .inode = hint.inode,
            .start_boot_ns = hint.owner.start_boot_ns,
            .pid = hint.owner.pid,
            .tid = hint.tid,
            .uid = uid,
            .fd = hint.fd,
            .valid = 1,
        };
    }
    bpf_task_release(task);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
