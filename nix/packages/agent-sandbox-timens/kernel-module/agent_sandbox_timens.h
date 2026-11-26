/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef AGENT_SANDBOX_TIMENS_H
#define AGENT_SANDBOX_TIMENS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define AGENT_SANDBOX_TIMENS_IOC_MAGIC 0xB7

/*
 * Subtracts whole seconds from a time namespace's CLOCK_MONOTONIC and
 * CLOCK_BOOTTIME offsets, so the clocks its tasks see do not advance for that
 * long. Needs CAP_SYS_TIME in the initial user namespace.
 *
 * The namespace must be owned by the initial user namespace, have been entered
 * by a task, and not be the initial one. The cgroup named by cgroup_fd must
 * have a freeze requested, every task of the namespace must live in it or in
 * a descendant, and every one of them must be trapped by the cgroup freezer.
 *
 * Errors: EBADF (ns_fd, or cgroup_fd not a cgroup2 directory), EINVAL (flags
 * or reserved set, seconds out of range, namespace not rewindable), EAGAIN (no
 * freeze requested on the cgroup), EXDEV (a task of the namespace lives
 * outside the cgroup), EBUSY (a task of the namespace is not trapped yet),
 * ERANGE (a clock would become negative).
 */
struct agent_sandbox_timens_rewind {
	__s32 ns_fd; /* open fd of /proc/<pid>/ns/time */
	__s32 cgroup_fd; /* open fd of the frozen cgroup directory */
	__u32 flags; /* must be 0 */
	__u32 reserved; /* must be 0 */
	__u64 seconds; /* 1 ..= 2^32 */
};

#define AGENT_SANDBOX_TIMENS_REWIND             \
	_IOW(AGENT_SANDBOX_TIMENS_IOC_MAGIC, 1, \
	     struct agent_sandbox_timens_rewind)

#endif
