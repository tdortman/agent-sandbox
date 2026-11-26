// SPDX-License-Identifier: GPL-2.0
/*
 * Rewinds the CLOCK_MONOTONIC and CLOCK_BOOTTIME offsets of a time namespace
 * so a frozen sandbox does not see the freeze as elapsed time once it thaws.
 * The caller names the cgroup it froze. The module rewinds only when that
 * cgroup has a freeze requested and every task of the namespace lives in it
 * (or a descendant) and has the freeze requested too, so a caller that picked
 * the wrong namespace, for instance through a recycled pid, cannot rewind a
 * namespace it did not freeze. A freeze request does not mean the task has
 * stopped; the caller is responsible for passing only time during which every
 * task was stopped.
 */

#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/overflow.h>
#include <linux/proc_ns.h>
#include <linux/rcupdate.h>
#include <linux/sched/jobctl.h>
#include <linux/sched/signal.h>
#include <linux/time64.h>
#include <linux/time_namespace.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <vdso/datapage.h>

#include "agent_sandbox_timens.h"

#ifndef CONFIG_TIME_NS
#error "agent_sandbox_timens needs CONFIG_TIME_NS"
#endif
#ifndef CONFIG_CGROUPS
#error "agent_sandbox_timens needs CONFIG_CGROUPS"
#endif
#ifndef CONFIG_64BIT
#error "agent_sandbox_timens relies on single 64-bit stores"
#endif

#define MAX_REWIND_NSEC (BIT_ULL(32) * NSEC_PER_SEC)

static DEFINE_MUTEX(rewind_lock);

/*
 * 0 when every task of @ns is in @cgrp or a descendant and has the freeze
 * requested; -EXDEV when one lives elsewhere, else -EBUSY when one has no
 * freeze requested yet.
 */
static int check_members(const struct time_namespace *ns, struct cgroup *cgrp)
{
	struct task_struct *p, *t;
	bool untrapped = false;
	int ret = 0;

	rcu_read_lock();
	for_each_process_thread(p, t) {
		struct nsproxy *nsproxy;

		task_lock(t);
		nsproxy = t->nsproxy;
		if (nsproxy && nsproxy->time_ns == ns) {
			if (!cgroup_is_descendant(task_dfl_cgroup(t), cgrp))
				ret = -EXDEV;
			else if (!(READ_ONCE(t->jobctl) & JOBCTL_TRAP_FREEZE))
				untrapped = true;
		}
		task_unlock(t);
		if (ret)
			goto out;
	}
	if (untrapped)
		ret = -EBUSY;
out:
	rcu_read_unlock();
	return ret;
}

#ifdef CONFIG_TIME_NS_VDSO
/* Same clocks as timens_setup_vdso_clock_data(). */
static void rewrite_vdso_clock(struct vdso_clock *vc,
			       const struct timespec64 *monotonic,
			       const struct timespec64 *boottime)
{
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC].sec, monotonic->tv_sec);
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC].nsec, monotonic->tv_nsec);
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC_RAW].sec, monotonic->tv_sec);
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC_RAW].nsec, monotonic->tv_nsec);
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC_COARSE].sec, monotonic->tv_sec);
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC_COARSE].nsec, monotonic->tv_nsec);
	WRITE_ONCE(vc->offset[CLOCK_BOOTTIME].sec, boottime->tv_sec);
	WRITE_ONCE(vc->offset[CLOCK_BOOTTIME].nsec, boottime->tv_nsec);
	WRITE_ONCE(vc->offset[CLOCK_BOOTTIME_ALARM].sec, boottime->tv_sec);
	WRITE_ONCE(vc->offset[CLOCK_BOOTTIME_ALARM].nsec, boottime->tv_nsec);
}
#endif

/*
 * The seconds and nanoseconds of an offset are separate stores. Every task of
 * @ns has the freeze requested, so none runs user code or reads a clock
 * while the offsets change; a task still in a kernel wait (one that waits for
 * a seccomp notification) reads no clock either. A task joining the namespace
 * during the update could see one clock off by up to a second for one read.
 */
static void rewrite_offsets(struct time_namespace *ns, u64 nsec)
{
	struct timespec64 rewind = ns_to_timespec64(nsec);
	struct timespec64 monotonic =
		timespec64_sub(ns->offsets.monotonic, rewind);
	struct timespec64 boottime =
		timespec64_sub(ns->offsets.boottime, rewind);

	WRITE_ONCE(ns->offsets.monotonic.tv_sec, monotonic.tv_sec);
	WRITE_ONCE(ns->offsets.monotonic.tv_nsec, monotonic.tv_nsec);
	WRITE_ONCE(ns->offsets.boottime.tv_sec, boottime.tv_sec);
	WRITE_ONCE(ns->offsets.boottime.tv_nsec, boottime.tv_nsec);

#ifdef CONFIG_TIME_NS_VDSO
	{
		struct vdso_time_data *vdata = page_address(ns->vvar_page);
		unsigned int i;

		for (i = 0; i < CS_BASES; i++)
			rewrite_vdso_clock(&vdata->clock_data[i], &monotonic,
					   &boottime);

		if (IS_ENABLED(CONFIG_POSIX_AUX_CLOCKS)) {
			for (i = 0; i < ARRAY_SIZE(vdata->aux_clock_data); i++)
				rewrite_vdso_clock(&vdata->aux_clock_data[i],
						   &monotonic, &boottime);
		}
	}
#endif
}

/* True when a clock now at @now plus @offset would read below zero after @nsec. */
static bool clock_would_go_negative(const struct timespec64 *now,
				    const struct timespec64 *offset, u64 nsec)
{
	s64 now_ns = timespec64_to_ns(now);
	s64 offset_ns = timespec64_to_ns(offset);
	s64 reading;

	if (check_add_overflow(now_ns, offset_ns, &reading))
		return offset_ns < 0;

	return reading < 0 || (u64)reading < nsec;
}

static long rewind_time_ns(struct time_namespace *ns, struct cgroup *cgrp,
			   u64 nsec)
{
	struct timespec64 monotonic, boottime;
	long ret;

	if (!READ_ONCE(cgrp->freezer.e_freeze))
		return -EAGAIN;

	mutex_lock(&rewind_lock);

	ret = check_members(ns, cgrp);
	if (ret)
		goto out;

	ktime_get_ts64(&monotonic);
	ktime_get_boottime_ts64(&boottime);
	if (clock_would_go_negative(&monotonic, &ns->offsets.monotonic, nsec) ||
	    clock_would_go_negative(&boottime, &ns->offsets.boottime, nsec)) {
		ret = -ERANGE;
		goto out;
	}

	rewrite_offsets(ns, nsec);
	pr_debug("rewound time namespace %u by %llu ns\n", ns->ns.inum, nsec);
out:
	mutex_unlock(&rewind_lock);
	return ret;
}

/* The time namespace behind @file, or NULL when @file is not one this module may rewind. */
static struct time_namespace *rewindable_time_ns(const struct file *file)
{
	struct ns_common *common;
	struct time_namespace *ns;

	if (file_inode(file)->i_sb->s_magic != NSFS_MAGIC)
		return NULL;

	common = get_proc_ns(file_inode(file));
	if (!common || common->ns_type != CLONE_NEWTIME ||
	    common->inum == PROC_TIME_INIT_INO)
		return NULL;

	ns = to_time_ns(common);
	if (ns->user_ns != &init_user_ns || !READ_ONCE(ns->frozen_offsets))
		return NULL;

	return ns;
}

static long rewind_fd(const struct agent_sandbox_timens_rewind *req)
{
	struct time_namespace *ns;
	struct cgroup *cgrp;
	struct file *file;
	long ret;

	file = fget(req->ns_fd);
	if (!file)
		return -EBADF;

	/* The open file keeps the namespace alive. */
	ns = rewindable_time_ns(file);
	if (!ns) {
		ret = -EINVAL;
		goto out_file;
	}

	cgrp = cgroup_get_from_fd(req->cgroup_fd);
	if (IS_ERR(cgrp)) {
		ret = PTR_ERR(cgrp);
		goto out_file;
	}

	ret = rewind_time_ns(ns, cgrp, req->nanoseconds);
	cgroup_put(cgrp);
out_file:
	fput(file);
	return ret;
}

static long agent_sandbox_timens_ioctl(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	struct agent_sandbox_timens_rewind req;

	if (cmd != AGENT_SANDBOX_TIMENS_REWIND)
		return -ENOTTY;

	if (!capable(CAP_SYS_TIME))
		return -EPERM;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	if (req.flags || req.reserved || !req.nanoseconds ||
	    req.nanoseconds > MAX_REWIND_NSEC)
		return -EINVAL;

	return rewind_fd(&req);
}

static const struct file_operations agent_sandbox_timens_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = agent_sandbox_timens_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice agent_sandbox_timens_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "agent-sandbox-timens",
	.fops = &agent_sandbox_timens_fops,
	.mode = 0600,
};

static int __init agent_sandbox_timens_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct agent_sandbox_timens_rewind) != 24);

	ret = misc_register(&agent_sandbox_timens_device);

	if (!ret)
		pr_info("loaded\n");
	return ret;
}

static void __exit agent_sandbox_timens_exit(void)
{
	misc_deregister(&agent_sandbox_timens_device);
}

module_init(agent_sandbox_timens_init);
module_exit(agent_sandbox_timens_exit);

MODULE_DESCRIPTION("Rewinds a frozen time namespace's clock offsets");
MODULE_LICENSE("GPL");
