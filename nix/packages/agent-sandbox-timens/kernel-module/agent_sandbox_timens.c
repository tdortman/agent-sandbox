// SPDX-License-Identifier: GPL-2.0
/*
 * Rewinds the CLOCK_MONOTONIC and CLOCK_BOOTTIME offsets of a time namespace
 * whose tasks are all trapped by the cgroup freezer, so a frozen sandbox does
 * not see the freeze as elapsed time once it thaws.
 */

#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
#include <linux/rcupdate.h>
#include <linux/sched/jobctl.h>
#include <linux/sched/signal.h>
#include <linux/time_namespace.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <vdso/datapage.h>

#include "agent_sandbox_timens.h"

#ifndef CONFIG_TIME_NS
#error "agent_sandbox_timens needs CONFIG_TIME_NS"
#endif
#ifndef CONFIG_64BIT
#error "agent_sandbox_timens relies on single 64-bit stores"
#endif

#define MAX_REWIND_SECONDS (1ULL << 32)

static DEFINE_MUTEX(rewind_lock);

/* True when a task of @ns is not trapped by the cgroup freezer. */
static bool has_unfrozen_member(const struct time_namespace *ns)
{
	struct task_struct *p, *t;
	bool unfrozen = false;

	rcu_read_lock();
	for_each_process_thread(p, t) {
		struct nsproxy *nsproxy;

		task_lock(t);
		nsproxy = t->nsproxy;
		unfrozen = nsproxy && nsproxy->time_ns == ns &&
			   !(READ_ONCE(t->jobctl) & JOBCTL_TRAP_FREEZE);
		task_unlock(t);
		if (unfrozen)
			goto out;
	}
out:
	rcu_read_unlock();
	return unfrozen;
}

#ifdef CONFIG_TIME_NS_VDSO
/* Same clocks as timens_setup_vdso_clock_data(). */
static void rewrite_vdso_clock(struct vdso_clock *vc, s64 monotonic_sec,
			       s64 boottime_sec)
{
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC].sec, monotonic_sec);
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC_RAW].sec, monotonic_sec);
	WRITE_ONCE(vc->offset[CLOCK_MONOTONIC_COARSE].sec, monotonic_sec);
	WRITE_ONCE(vc->offset[CLOCK_BOOTTIME].sec, boottime_sec);
	WRITE_ONCE(vc->offset[CLOCK_BOOTTIME_ALARM].sec, boottime_sec);
}
#endif

/*
 * Every task of @ns is trapped by the freezer, so none runs user code or
 * enters a time syscall while the offsets change. Only whole seconds change
 * and each one is a single 64-bit store, so a reader that still races
 * (a task that joins the namespace now) sees the old or the new offset,
 * never a torn one.
 */
static void rewrite_offsets(struct time_namespace *ns, u64 seconds)
{
	s64 monotonic_sec = ns->offsets.monotonic.tv_sec - seconds;
	s64 boottime_sec = ns->offsets.boottime.tv_sec - seconds;

	WRITE_ONCE(ns->offsets.monotonic.tv_sec, monotonic_sec);
	WRITE_ONCE(ns->offsets.boottime.tv_sec, boottime_sec);

#ifdef CONFIG_TIME_NS_VDSO
	{
		struct vdso_time_data *vdata = page_address(ns->vvar_page);
		unsigned int i;

		for (i = 0; i < CS_BASES; i++)
			rewrite_vdso_clock(&vdata->clock_data[i], monotonic_sec,
					   boottime_sec);

		if (IS_ENABLED(CONFIG_POSIX_AUX_CLOCKS)) {
			for (i = 0; i < ARRAY_SIZE(vdata->aux_clock_data); i++)
				rewrite_vdso_clock(&vdata->aux_clock_data[i],
						   monotonic_sec, boottime_sec);
		}
	}
#endif
}

static long rewind_time_ns(struct time_namespace *ns, u64 seconds)
{
	struct timespec64 monotonic, boottime;
	long ret = 0;

	mutex_lock(&rewind_lock);

	if (has_unfrozen_member(ns)) {
		ret = -EBUSY;
		goto out;
	}

	ktime_get_ts64(&monotonic);
	ktime_get_boottime_ts64(&boottime);
	if (monotonic.tv_sec + ns->offsets.monotonic.tv_sec - (s64)seconds < 0 ||
	    boottime.tv_sec + ns->offsets.boottime.tv_sec - (s64)seconds < 0) {
		ret = -ERANGE;
		goto out;
	}

	rewrite_offsets(ns, seconds);
	pr_debug("rewound time namespace %u by %llu s\n", ns->ns.inum, seconds);
out:
	mutex_unlock(&rewind_lock);
	return ret;
}

static long rewind_fd(const struct agent_sandbox_timens_rewind *req)
{
	struct time_namespace *ns;
	struct ns_common *common;
	struct file *file;
	long ret;

	file = fget(req->ns_fd);
	if (!file)
		return -EBADF;

	ret = -EINVAL;
	if (file_inode(file)->i_sb->s_magic != NSFS_MAGIC)
		goto out;

	common = get_proc_ns(file_inode(file));
	if (common->ns_type != CLONE_NEWTIME || common->inum == PROC_TIME_INIT_INO)
		goto out;

	/* The open file keeps the namespace alive. */
	ns = to_time_ns(common);
	if (ns->user_ns != &init_user_ns || !READ_ONCE(ns->frozen_offsets))
		goto out;

	ret = rewind_time_ns(ns, req->seconds);
out:
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
	if (req.flags || !req.seconds || req.seconds > MAX_REWIND_SECONDS)
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
	int ret = misc_register(&agent_sandbox_timens_device);

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

MODULE_DESCRIPTION("Rewinds a frozen time namespace's monotonic and boottime offsets");
MODULE_LICENSE("GPL");
