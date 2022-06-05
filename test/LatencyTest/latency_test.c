// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * 此模块用来短暂地关闭一会儿中断，以便测试
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/sched/signal.h>
#include <linux/fdtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QunChuWoLao");

// 从 cat /proc/interrupts 中选一个不重要的中断号 eg：USB
static int num = 18;

static int __init start_latency(void)
{
    int i;
    pr_info("Disabling IRQ.\n");
    for (i = 0; i < 100; ++i) {
        disable_irq_nosync(num); // 屏蔽指定的中断号
        mdelay(100); // 忙等待
        enable_irq(num); // 重新打开
        msleep(50); // 休眠，可以调度走
    }
    // 循环 100 次以检测是否有内存泄露
    pr_info("Disable IRQ test finished.\n");
    return 0;
}
static void __exit end_latency(void)
{
    pr_info("Module exit.\n");
}
module_init(start_latency);
module_exit(end_latency);
