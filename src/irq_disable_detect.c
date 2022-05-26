// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/fdtable.h>

// 抓取单一中断的关闭
static struct kprobe disable_irq_nosync_probe = {
    .symbol_name = "disable_irq_nosync"
};
static struct kprobe disable_irq_probe = {
    .symbol_name = "disable_irq"
};
static struct kprobe enable_irq_probe = {
    .symbol_name = "enable_irq"
};

static unsigned long nsec_limit = 1000000; // 以纳秒为单位的关闭时间
static struct timespec64 close_time; // 关闭的时间

static int MAX_STACK_TRACE_DEPTH = 64;
struct stack_trace trace;
unsigned long *entries; // 关中断时的堆栈信息
struct files_struct* files; // 文件

static int MASK_ID = 18;
static bool is_disabled = false;

static void get_data(void) {
    // 检查，如果链表非空，则输出
    unsigned i = 0;
    for (i = 0; i < trace.nr_entries; ++i) {
        pr_info("[<%p>] %pS\n", (void*)entries[i], (void*)entries[i]);
    }
    for (i = 0; i < NR_OPEN_DEFAULT; ++i) {
        char file_name[256];
        dentry_path_raw(files->fd_array[i]->f_path.dentry, file_name, 256);
        pr_info("File name: %s\n", file_name);
        // TODO：完善输出
    }
}

static void clear(void) {
    // TODO：检查，如果链表非空，则回收
    kfree(entries);
}

static int pre_handler_disable_irq(struct kprobe *p, struct pt_regs *regs) {
    pr_info("IRQ %lu disabled\n", regs->di);
    // 抓取函数的第一个参数（x86_64 把它放在 rdi 寄存器中），即中断号
    if (regs->di != MASK_ID) {
        return 0;
    }
    ktime_get_real_ts64(&close_time); // 记录关中断的时间
    
    entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(*entries), GFP_KERNEL);
    if (entries) {
        trace.nr_entries = 0;
        trace.max_entries = MAX_STACK_TRACE_DEPTH;
        trace.entries = entries;
        trace.skip = 0;
        save_stack_trace_tsk(get_current(), &trace);
    }
    is_disabled = true;
    return 0;
}
static int pre_handler_enable_irq(struct kprobe *p, struct pt_regs *regs) {
    static struct timespec64 open_time;
    if (regs->di != MASK_ID) {
        return 0;
    }
    if (is_disabled) {
        ktime_get_ts64(&open_time);
        if ((open_time.tv_sec - close_time.tv_sec) * 100000000ll + open_time.tv_nsec - close_time.tv_nsec > nsec_limit) {
            // 获取打开的文件等 https://www.kernel.org/doc/html/latest/translations/zh_CN/core-api/irq/irqflags-tracing.html
            int i = 0;
            struct fdtable *files_table;
            files_table = files_fdtable(get_current()->files);
            while (files_table->fd[i] != NULL) {
                char *file_name = kmalloc(256 * sizeof(char), GFP_KERNEL);
                const char *path = d_path(&files_table->fd[i++]->f_path, file_name, 256);
                // TODO：将 path 和 file_name 加入链表中，并要记得回收（如果不及时复制的话，万一进程删除了文件怎么办呢？）
            }
            // 加入链表中（把指针挂入）
            get_data();
        }
    }
    is_disabled = false;
    return 0;
}


static int start_probe(void) {
    int ret;
    disable_irq_nosync_probe.pre_handler = pre_handler_disable_irq;
    disable_irq_probe.pre_handler = pre_handler_disable_irq;
    enable_irq_probe.pre_handler = pre_handler_enable_irq;
    
    ret = register_kprobe(&disable_irq_nosync_probe);
    if (ret < 0) {
        pr_err("can't register disable_irq_nosync_probe, ret=%d\n", ret);
        return ret;
    }
    ret = register_kprobe(&disable_irq_probe);
    if (ret < 0) {
        pr_err("can't register disable_irq_probe, ret=%d\n", ret);
        return ret;
    }
    ret = register_kprobe(&enable_irq_probe);
    if (ret < 0) {
        pr_err("can't register enable_irq_probe, ret=%d\n", ret);
        return ret;
    }
    pr_info("Planted kprobes finished.\n");
    return 0;
}
static void exit_probe(void) {
    unregister_kprobe(&disable_irq_nosync_probe);
    unregister_kprobe(&disable_irq_probe);
    unregister_kprobe(&enable_irq_probe);
    clear();
    pr_info("kprobes removed.\n");
}
