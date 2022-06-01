// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fdtable.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <trace/events/preemptirq.h>
#include <asm/atomic.h>

#include "irq_disable.h"

// https://github.com/bristot/rtsl
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

DEFINE_PER_CPU(struct timespec64, disable_local_irq_time); // 上次关中断的时间
static time64_t nsec_limit = 1000000;
DEFINE_PER_CPU(bool, has_off_record) = false;

// 链表
// 头结点数据域不使用
DEFINE_PER_CPU(struct process_info, local_list_head);
DEFINE_PER_CPU(unsigned int, local_list_length) = 0; // 链表长度
#define LENGTH_LIMIT 20

// 原子操作，标记是否已在操作链表
DEFINE_PER_CPU(atomic_t, local_list_mark);

// 标记是否已经在执行回调函数，以忽略掉模块自身执行产生的关中断
DEFINE_PER_CPU(bool, local_tracing);

// 关中断回调函数，经测试正常情况下此函数执行时中断已被关闭
static void irqoff_handler(void *none, unsigned long ip, unsigned long parent_ip) {
    // 需要保证排除自己触发的关中断
    if (*this_cpu_ptr(&local_tracing)) return;
    *this_cpu_ptr(&local_tracing) = true;
    if (preemptible()) {
        pr_warn("IRQ OFF can preempt!\n"); // 调试用，这不该发生
    }
    ktime_get_ts64(this_cpu_ptr(&disable_local_irq_time));
    *this_cpu_ptr(&has_off_record) = true;
    *this_cpu_ptr(&local_tracing) = false;
}
// 开中断，经测试正常情况下此函数执行时中断仍在关闭中
static void irqon_handler(void *none, unsigned long ip, unsigned long parent_ip) {
    static struct timespec64 enable_local_irq_time;
    if (*this_cpu_ptr(&local_tracing)) return;
    *this_cpu_ptr(&local_tracing) = true;
    if (preemptible()) {
        pr_warn("IRQ ON can preempt!\n");
    }
    if (likely(*this_cpu_ptr(&has_off_record))) {
        time64_t local_duration;
        ktime_get_ts64(&enable_local_irq_time);
        local_duration = (enable_local_irq_time.tv_sec - *this_cpu_ptr(&disable_local_irq_time.tv_sec)) * 1000000000ll + \
            enable_local_irq_time.tv_nsec - *this_cpu_ptr(&disable_local_irq_time.tv_nsec);
        if (local_duration  > nsec_limit) {
            int i = 0;
            struct fdtable *files_table;
            struct file_node **next_file;
            struct task_struct *on_irq_task = get_current();
            // 记录关中断的进程信息
            struct process_info *local_list_node = kmalloc(sizeof(struct process_info), GFP_ATOMIC);
            local_list_node->cpu = on_irq_task->cpu;
            local_list_node->pid = on_irq_task->pid;
            memcpy(local_list_node->comm, on_irq_task->comm, TASK_COMM_LEN);
            local_list_node->duration = local_duration;
            // 保存堆栈
            local_list_node->entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(unsigned long), GFP_ATOMIC);
            if (likely(local_list_node->entries)) {
                static struct stack_trace local_trace;
                local_trace.nr_entries = 0;
                local_trace.max_entries = MAX_STACK_TRACE_DEPTH;
                local_trace.entries = local_list_node->entries;
                local_trace.skip = 2;
                save_stack_trace_tsk(on_irq_task, &local_trace);
                local_list_node->nr_entries = local_trace.nr_entries;
            }

            local_list_node->files_list = NULL;
            // 获取打开的文件等 http://tuxthink.blogspot.in/2012/05/module-to-print-open-files-of-process.html
            // 经测试，此值可能为 NULL
            // pr_warn("E: nullptr found at PID=%d, comm=%s\n", on_irq_task->pid, on_irq_task->comm);
            if (on_irq_task->files != NULL) {
                files_table = files_fdtable(on_irq_task->files);
                next_file = &local_list_node->files_list;
                while (likely(files_table->fd[i] != NULL)) {
                    *next_file = kmalloc(sizeof(struct file_node), GFP_ATOMIC);
                    // 将 path 和 buffer 加入链表中（如果不及时复制的话，万一文件被删除，可能再也无法获取文件名）
                    if (*next_file == NULL) {
                        pr_warn("E! Can't alloc memory for next_file.\n");
                    }
                    (*next_file)->buffer = kmalloc(256 * sizeof(char), GFP_ATOMIC);
                    if ((*next_file)->buffer == NULL) {
                        pr_warn("E! Can't alloc memory for buffer.\n");
                    }
                    (*next_file)->path = d_path(&files_table->fd[i++]->f_path, (*next_file)->buffer, 256);
                    (*next_file)->next = NULL;
                    next_file = &(*next_file)->next;
                }
            }
            // 加入链表中（把指针挂入）
            INIT_LIST_HEAD(&local_list_node->list);
            // 这里不可以使用 spin_lock，因为 spin_unlock 时必然会打开抢占，不管在执行 spin_lock 时是否已关闭抢占
            while (!atomic_cmpxchg(this_cpu_ptr(&local_list_mark), 1, 0)) ;
            list_add_tail(&local_list_node->list, this_cpu_ptr(&local_list_head.list));
            if (*this_cpu_ptr(&local_list_length) >= LENGTH_LIMIT) {
                // 如果链表长度超过上限，删除最老的元素
                // 但是，会不会保留关中断时间最长的更合理？
                struct list_head *local_to_delete = *this_cpu_ptr(&local_list_head.list.next);
                list_del(local_to_delete);
                clear_node(list_entry(local_to_delete, struct process_info, list));
            } else {
                ++*this_cpu_ptr(&local_list_length);
            }
            atomic_set(this_cpu_ptr(&local_list_mark), 1);
            
        }
    }
    *this_cpu_ptr(&has_off_record) = false;
    *this_cpu_ptr(&local_tracing) = false;
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

static void local_irq_disable_output(void)
{
    unsigned int cpu;
    preempt_disable();
    for_each_present_cpu(cpu)
    {
        pr_info("On CPU %u:\n", cpu);
        // 如果访问的不是当前 CPU，要先看 local_list_mark 的值
        if (cpu != smp_processor_id())
        {
            while (!atomic_cmpxchg(per_cpu_ptr(&local_list_mark, cpu), 1, 0)) ;
            print_list(per_cpu_ptr(&local_list_head.list, cpu));
            atomic_set(per_cpu_ptr(&local_list_mark, cpu), 1);
        }
        else
        {
            // 如果访问的是当前 CPU 的，不需要用 local_list_mark 保护
            print_list(per_cpu_ptr(&local_list_head.list, cpu));
        }
        pr_info("----\n");
    }
    preempt_disable();
}

static int start_trace(void) {
    unsigned int cpu;
    // 访问 per_cpu 时禁止调度
    preempt_disable();
    for_each_present_cpu(cpu)
    {
        atomic_set(per_cpu_ptr(&local_list_mark, cpu), 1);
        // 初始化链表
        INIT_LIST_HEAD(per_cpu_ptr(&local_list_head.list, cpu));
        *per_cpu_ptr(&local_tracing, cpu) = false;
    }
    preempt_enable();
    return register_tracepoints(tps, TP_NUM);
}

static void exit_trace(void) {
    unsigned int cpu;
    unregister_tracepoints(tps, TP_NUM);

    for_each_present_cpu(cpu)
    {
        // 回收链表
        while (!atomic_cmpxchg(per_cpu_ptr(&local_list_mark, cpu), 1, 0)) ;
        clear(per_cpu_ptr(&local_list_head.list, cpu));
        atomic_set(per_cpu_ptr(&local_list_mark, cpu), 1);
        pr_info("----\n");
    }
    pr_info("Realtime probe module exit\n");
}