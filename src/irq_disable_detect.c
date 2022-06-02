// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/fdtable.h>
#include <linux/list.h>

#include "irq_disable.h"
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

static struct timespec64 close_time; // 关闭的时间

unsigned int nr_entries;
unsigned long *entries; // 关中断时的堆栈信息
struct files_struct* files; // 文件

static bool is_disabled = false;

// 链表
// 头结点数据域不使用
struct process_info single_list_head = 
{
    .list = LIST_HEAD_INIT(single_list_head.list),
};
unsigned int length = 0; // 链表长度
#define LENGTH_LIMIT 20


static int pre_handler_disable_irq(struct kprobe *p, struct pt_regs *regs) {
    // 抓取函数的第一个参数（x86_64 把它放在 rdi 寄存器中），即中断号
    if (regs->di != MASK_ID) {
        return 0;
    }
    ktime_get_ts64(&close_time); // 记录关中断的时间
    
    entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(*entries), GFP_KERNEL);
    if (entries) {
        struct stack_trace trace;
        trace.nr_entries = 0;
        trace.max_entries = MAX_STACK_TRACE_DEPTH;
        trace.entries = entries;
        trace.skip = 0;
        save_stack_trace_tsk(get_current(), &trace);
        nr_entries = trace.nr_entries;
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
        time64_t duration;
        ktime_get_ts64(&open_time);
        duration = (open_time.tv_sec - close_time.tv_sec) * 1000000000ll + open_time.tv_nsec - close_time.tv_nsec;
        if (duration > nsec_limit) {
            int i = 0;
            struct fdtable *files_table;
            struct file_node **next_file;
            // 记录关中断的进程信息
            struct process_info *single_list_node = kmalloc(sizeof(struct process_info), GFP_KERNEL);
            single_list_node->cpu = get_current()->cpu;
            single_list_node->pid = get_current()->pid;
            memcpy(single_list_node->comm, get_current()->comm, TASK_COMM_LEN);
            single_list_node->duration = duration;
            single_list_node->entries = entries;
            single_list_node->nr_entries = nr_entries;
            single_list_node->files_list = NULL;

            // 获取打开的文件等 http://tuxthink.blogspot.in/2012/05/module-to-print-open-files-of-process.html
            files_table = files_fdtable(get_current()->files);
            next_file = &single_list_node->files_list;
            while (likely(files_table->fd[i] != NULL)) {
                *next_file = kmalloc(sizeof(struct file_node), GFP_KERNEL);
                (*next_file)->buffer = kmalloc(256 * sizeof(char), GFP_KERNEL);
                (*next_file)->path = d_path(&files_table->fd[i++]->f_path, (*next_file)->buffer, 256);
                (*next_file)->next = NULL;
                next_file = &(*next_file)->next;
                // 将 path 和 file_name 加入链表中（如果不及时复制的话，万一文件被删除，可能再也无法获取文件名）
            }
            INIT_LIST_HEAD(&single_list_node->list);
            // 加入链表中（把指针挂入）
            list_add_tail(&single_list_node->list, &single_list_head.list);
            if (length >= LENGTH_LIMIT) {
                // 如果链表长度超过上限，删除最老的元素
                struct list_head *to_delete = single_list_head.list.next;
                list_del(to_delete);
                clear_node(list_entry(to_delete, struct process_info, list));
            } else {
                ++length;
            }
        } else {
            kfree(entries);
        }
    }
    is_disabled = false;
    return 0;
}


int start_probe(void) {
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
void exit_probe(void) {
    unregister_kprobe(&disable_irq_nosync_probe);
    unregister_kprobe(&disable_irq_probe);
    unregister_kprobe(&enable_irq_probe);
    if (length == 0)
    {
        pr_info("No IRQ disable traced.\n");
    }
    clear(&single_list_head.list);
    INIT_LIST_HEAD(&single_list_head.list); // 头结点指向自己
    pr_info("Stop probe IRQ disable.\n");
}
