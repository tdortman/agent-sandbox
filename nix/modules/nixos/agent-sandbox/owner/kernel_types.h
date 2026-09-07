#ifndef AGENT_SANDBOX_OWNER_KERNEL_TYPES_H
#define AGENT_SANDBOX_OWNER_KERNEL_TYPES_H

#include <linux/bpf.h>

/* Minimal views of kernel types. CO-RE relocates the fields we access; these
 * declarations do not describe their actual size or field order in memory. */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct inode {
    unsigned short i_mode;
    unsigned long i_ino;
};

typedef struct {
    long counter;
} atomic_long_t;

typedef struct {
    atomic_long_t refcnt;
} file_ref_t;

struct file {
    struct inode *f_inode;
    void *private_data;
    unsigned int f_mode;
    file_ref_t f_ref;
};

struct fdtable {
    unsigned int max_fds;
    struct file **fd;
};

struct files_struct {
    struct fdtable *fdt;
};

struct in6_addr {
    unsigned int addr[4];
};

typedef struct {
    unsigned int val;
} kuid_t;

struct ns_common {
    unsigned int inum;
};

struct net {
    struct ns_common ns;
};

typedef struct {
    struct net *net;
} possible_net_t;

struct sock_common {
    unsigned int skc_daddr;
    unsigned int skc_rcv_saddr;
    unsigned short skc_dport;
    unsigned short skc_num;
    unsigned short skc_family;
    possible_net_t skc_net;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
    struct sock_common __sk_common;
    kuid_t sk_uid;
    unsigned short sk_protocol;
    struct socket *sk_socket;
};

struct socket {
    struct sock *sk;
    struct file *file;
};

struct cred {
    kuid_t uid;
    kuid_t euid;
    kuid_t suid;
    kuid_t fsuid;
};

struct nsproxy {
    struct net *net_ns;
};

struct task_struct {
    int pid;
    int tgid;
    unsigned long long start_boottime;
    struct task_struct *group_leader;
    const struct cred *cred;
    struct nsproxy *nsproxy;
    struct files_struct *files;
};

#pragma clang attribute pop

#endif
