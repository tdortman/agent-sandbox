/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef AGENT_SANDBOX_TIMENS_H
#define AGENT_SANDBOX_TIMENS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define AGENT_SANDBOX_TIMENS_IOC_MAGIC 0xB7

/*
 * Subtracts nanoseconds from a time namespace's CLOCK_MONOTONIC and
 * CLOCK_BOOTTIME offsets, so the clocks its tasks see do not advance for that
 * long. Needs CAP_SYS_TIME in the initial user namespace.
 *
 * The namespace must be owned by the initial user namespace, have been entered
 * by a task, and not be the initial one. The cgroup named by cgroup_fd must
 * have a freeze requested, and every task of the namespace must live in it or
 * in a descendant and have the freeze requested. A requested freeze does not
 * mean the task has stopped yet: the caller must pass only time during which
 * every task of the namespace was stopped, or a clock inside it can go
 * backwards.
 *
 * Errors: EBADF (ns_fd, or cgroup_fd not a cgroup2 directory), EINVAL (flags
 * or reserved set, nanoseconds out of range, namespace not rewindable), EAGAIN
 * (no freeze requested on the cgroup), EXDEV (a task of the namespace lives
 * outside the cgroup), EBUSY (a task of the namespace has no freeze requested
 * yet), ERANGE (a clock would become negative). A request code of another
 * module version fails with ENOTTY.
 */
struct agent_sandbox_timens_rewind {
    __s32 ns_fd;       /* open fd of /proc/<pid>/ns/time */
    __s32 cgroup_fd;   /* open fd of the frozen cgroup directory */
    __u32 flags;       /* must be 0 */
    __u32 reserved;    /* must be 0 */
    __u64 nanoseconds; /* 1 ..= 2^32 * 10^9 */
};

#define AGENT_SANDBOX_TIMENS_REWIND \
    _IOW(AGENT_SANDBOX_TIMENS_IOC_MAGIC, 2, struct agent_sandbox_timens_rewind)

#endif
