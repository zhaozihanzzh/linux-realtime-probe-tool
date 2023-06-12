// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fdtable.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/version.h>
#include <trace/events/preemptirq.h>
#include <asm/atomic.h>

#include "irq_disable.h"
#include "user_spinlock.h"

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
DEFINE_PER_CPU(bool, has_off_record) = false;

// 链表
// 头结点数据域不使用
DEFINE_PER_CPU(struct process_info, local_list_head);
DEFINE_PER_CPU(unsigned int, local_list_length) = 0; // 链表长度
#define LENGTH_LIMIT 20
// 缓存
DEFINE_PER_CPU(struct kmem_cache *, file_node_cache);

// 标记是否已在操作链表
DEFINE_PER_CPU(uspinlock_t, local_list_lock);
DEFINE_PER_CPU(unsigned long, local_irq_flag);

// 标记是否已经在执行回调函数，以忽略掉模块自身执行产生的关中断
DEFINE_PER_CPU(bool, local_tracing);

// 关中断回调函数，经测试正常情况下此函数执行时中断已被关闭
static void irqoff_handler(void *none, unsigned long ip, unsigned long parent_ip) {
    smp_mb();
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
    smp_mb();
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
            struct process_info *local_list_node;
            local_irq_save(*this_cpu_ptr(&local_irq_flag)); // 验证是否可以被删除【这样设计不够合理】
            preempt_disable();
            if (!uspin_trylock(this_cpu_ptr(&local_list_lock))) {
                // 如果已经持有锁，直接不记录（此时可能正在查看信息）
                preempt_enable();
                local_irq_restore(*this_cpu_ptr(&local_irq_flag));
                *this_cpu_ptr(&has_off_record) = false;
                *this_cpu_ptr(&local_tracing) = false;
                smp_mb();
                return;
            }
            if (likely(*this_cpu_ptr(&local_list_length) >= LENGTH_LIMIT)) {
                // 如果链表长度超过上限，删除最老的记录并将其存储空间让给新记录
                // 但是，会不会保留关中断时间最长的更合理？
                struct list_head *local_to_delete = *this_cpu_ptr(&local_list_head.list.next);
                struct file_node *file_item;
                local_list_node = list_entry(local_to_delete, struct process_info, list);
                file_item = local_list_node->files_list;
                list_del(local_to_delete);
                --*this_cpu_ptr(&local_list_length);
                // 回收最老的记录的文件列表
                while (file_item != NULL) {
                    struct file_node *next = file_item->next;
                    kmem_cache_free(*this_cpu_ptr(&file_node_cache), file_item);
                    file_item = next;
                }
                kfree(local_list_node->entries);
            } else {
                local_list_node = kmalloc(sizeof(struct process_info), GFP_ATOMIC);
            }
            local_list_node->cpu = on_irq_task->cpu;
            local_list_node->pid = on_irq_task->pid;
            memcpy(local_list_node->comm, on_irq_task->comm, TASK_COMM_LEN);
            local_list_node->duration = local_duration;
            // 保存堆栈
            local_list_node->entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(unsigned long), GFP_ATOMIC);
            if (likely(local_list_node->entries)) {
                #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,21)
                local_list_node->nr_entries = stack_trace_save(local_list_node->entries, MAX_STACK_TRACE_DEPTH, 0);
                #else
                static struct stack_trace local_trace;
                local_trace.nr_entries = 0;
                local_trace.max_entries = MAX_STACK_TRACE_DEPTH;
                local_trace.entries = local_list_node->entries;
                local_trace.skip = 2;
                save_stack_trace_tsk(on_irq_task, &local_trace);
                local_list_node->nr_entries = local_trace.nr_entries;
                #endif
            }

            local_list_node->files_list = NULL;
            // 获取打开的文件等 http://tuxthink.blogspot.in/2012/05/module-to-print-open-files-of-process.html
            // 经测试，此值可能为 NULL
            // pr_warn("E: nullptr found at PID=%d, comm=%s\n", on_irq_task->pid, on_irq_task->comm);
            if (on_irq_task->files != NULL) {
                files_table = files_fdtable(on_irq_task->files);
                next_file = &local_list_node->files_list;
                while (likely(files_table->fd[i] != NULL)) {
                    *next_file = kmem_cache_alloc(*this_cpu_ptr(&file_node_cache), GFP_ATOMIC);
                    // 将 path 和 buffer 加入链表中（如果不及时复制的话，万一文件被删除，可能再也无法获取文件名）
                    (*next_file)->path = d_path(&files_table->fd[i++]->f_path, (*next_file)->buffer, 256);
                    (*next_file)->next = NULL;
                    next_file = &(*next_file)->next;
                }
            }
            // 加入链表中（把指针挂入）
            INIT_LIST_HEAD(&local_list_node->list);
            list_add_tail(&local_list_node->list, this_cpu_ptr(&local_list_head.list));
            ++*this_cpu_ptr(&local_list_length);
            uspin_unlock(this_cpu_ptr(&local_list_lock));
            local_irq_restore(*this_cpu_ptr(&local_irq_flag));
            preempt_enable();
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

int start_trace(void) {
    unsigned int cpu;
    // 访问 per_cpu 时禁止调度
    preempt_disable();
    for_each_present_cpu(cpu)
    {
        uspin_lock_init(per_cpu_ptr(&local_list_lock, cpu));
        // 初始化链表
        INIT_LIST_HEAD(per_cpu_ptr(&local_list_head.list, cpu));
        *per_cpu_ptr(&local_tracing, cpu) = false;
        *per_cpu_ptr(&file_node_cache, cpu) = kmem_cache_create("file_node_cache", \
            sizeof(struct file_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    }
    preempt_enable();
    return register_tracepoints(tps, TP_NUM);
}

void exit_trace(void) {
    unsigned int cpu;
    unregister_tracepoints(tps, TP_NUM);

    for_each_present_cpu(cpu)
    {
        // 回收链表
        local_irq_save(*per_cpu_ptr(&local_irq_flag, cpu));
        preempt_disable();
        uspin_lock(per_cpu_ptr(&local_list_lock, cpu));
        clear(per_cpu_ptr(&local_list_head.list, cpu), *per_cpu_ptr(&file_node_cache, cpu));
        uspin_unlock(per_cpu_ptr(&local_list_lock, cpu));
        local_irq_restore(*per_cpu_ptr(&local_irq_flag, cpu));
        preempt_enable();
        *per_cpu_ptr(&local_list_length, cpu) = 0;
        INIT_LIST_HEAD(per_cpu_ptr(&local_list_head.list, cpu)); // 头结点指向自己
        kmem_cache_destroy(*per_cpu_ptr(&file_node_cache, cpu));
    }
    pr_info("Exit local irq disable trace.\n");
}