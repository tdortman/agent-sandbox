/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef AGENT_SANDBOX_TIMENS_H
#define AGENT_SANDBOX_TIMENS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define AGENT_SANDBOX_TIMENS_IOC_MAGIC 0xB7

/*
 * Subtracts whole seconds from a time namespace's CLOCK_MONOTONIC and
 * CLOCK_BOOTTIME offsets, so the clocks its tasks see do not advance for that
 * long. Every task in the namespace must be trapped by the cgroup freezer.
 */
struct agent_sandbox_timens_rewind {
    __s32 ns_fd;   /* open fd of /proc/<pid>/ns/time */
    __u32 flags;   /* must be 0 */
    __u64 seconds; /* 1 ..= 2^32 */
};

#define AGENT_SANDBOX_TIMENS_REWIND \
    _IOW(AGENT_SANDBOX_TIMENS_IOC_MAGIC, 1, struct agent_sandbox_timens_rewind)

#endif
