// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <trace/events/preemptirq.h>


/*
 * These are helper functions to hook to tracepoints without
 * refering to their internal structure.
 *
 * They can be removed if the tracer becomes part of the kernel.
 * In that case, the tracefs could be used instead of debugfs.
 */
struct tp_and_name {
	struct tracepoint *tp;
	void *probe;
	char *name;
	int registered;
};

/*
 * This is the callback that compares tracepoint by their names,
 * and get the tracepoint structure.
 *
 * See get_struct_tracepoint().
 */
static void fill_tp_by_name(struct tracepoint *ktp, void *priv)
{
	struct tp_and_name *tp  = priv;

	if (!strcmp(ktp->name, tp->name))
		tp->tp = ktp;
}
/*
 * get_struct_tracepoint: search a tracepoint by its name.
 *
 * Returns the tracepoint structure of given tracepoint name,
 * or NULL.
 */
static struct tracepoint *get_struct_tracepoint(char *name)
{
	struct tp_and_name tp = {
		.name = name,
		.tp = NULL
	};

	for_each_kernel_tracepoint(fill_tp_by_name, &tp);
	return tp.tp;
}
/*
 * register_tracepoints: register a vector of tracepoints.
 *
 * Receives a vector of tp_and_name, search for their given tracepoint
 * structure by the tp name, and register the probe (when possible).
 *
 * It also keeps note of the registered tracepoints, so it can
 * known which ones to disable later.
 *
 */
static int register_tracepoints(struct tp_and_name *tracepoints, int count)
{
	int retval;
	int i;

	for (i = 0; i < count; i++) {
		tracepoints[i].tp = get_struct_tracepoint(tracepoints[i].name);

		if (!tracepoints[i].tp)
			goto out_err;

		tracepoints[i].registered = 1;

		retval = tracepoint_probe_register(tracepoints[i].tp,
						   tracepoints[i].probe, NULL);
		if (retval)
			goto out_err;
	}

	return 0;

out_err:
	for (i = 0; i < count; i++) {
		if (!tracepoints[i].registered)
			continue;

		tracepoint_probe_unregister(tracepoints[i].tp,
					    tracepoints[i].probe, NULL);
	}
	return -EINVAL;
}
/*
 * unregister_tracepoints: unregister tracepoints
 *
 * See register_tracepoints().
 */
static void unregister_tracepoints(struct tp_and_name *tracepoints, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		if (!tracepoints[i].registered)
			continue;

		tracepoint_probe_unregister(tracepoints[i].tp,
					    tracepoints[i].probe, NULL);

		tracepoints[i].registered = 0;
	}

	return;
}

static struct timespec64 disable_local_irq_time; // 上次关中断的时间
static unsigned long nsec_limit = 1000000;
static bool has_off_record = false;
// 关中断
static void irqoff_handler(void *none, unsigned long ip, unsigned long parent_ip) {
	ktime_get_real_ts64(&disable_local_irq_time);
    has_off_record = true;
}
// 开中断
static void irqon_handler(void *none, unsigned long ip, unsigned long parent_ip) {
	static struct timespec64 enable_local_irq_time;
	ktime_get_real_ts64(&enable_local_irq_time);
	if (likely(has_off_record)) {
		if ((enable_local_irq_time.tv_sec - disable_local_irq_time.tv_sec) * 1000000000ll + \
			enable_local_irq_time.tv_nsec - disable_local_irq_time.tv_nsec > nsec_limit) {
			// TODO：读取进程信息
			pr_info("Last pid is %d, name is %s\n", get_current()->pid, get_current()->comm);
		}
	}
	has_off_record = false;
}
#define TP_NUM 2
static struct tp_and_name tps[TP_NUM] = {
    {
		.probe = irqoff_handler,
		.name = "irq_disable",
		.registered = 0
	},
	{
		.probe = irqon_handler,
		.name = "irq_enable",
		.registered = 0
	}
};

static int start_trace(void) {
    return register_tracepoints(tps, TP_NUM);
}

static void exit_trace(void) {
    unregister_tracepoints(tps, TP_NUM);
    pr_info("Realtime probe module exit\n");
}