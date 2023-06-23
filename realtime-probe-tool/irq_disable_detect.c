// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/fdtable.h>
#include <linux/list.h>
#include <linux/version.h>

#include "irq_disable.h"
#include "user_spinlock.h"

static struct timespec64 close_time; // 关闭的时间

unsigned int nr_entries;
unsigned long *entries = NULL; // 关中断时的堆栈信息
struct files_struct* files; // 文件
static struct kmem_cache *file_node_cache;

static bool is_disabled = false;

// 链表
// 头结点数据域不使用
struct process_info single_list_head = 
{
    .list = LIST_HEAD_INIT(single_list_head.list),
};
unsigned int length = 0; // 链表长度
#define LENGTH_LIMIT 20

// 操作链表前先获取
//spinlock_t single_list_lock;
uspinlock_t single_list_lock;
unsigned long single_irq_flag;

static struct kprobe* probe_irqs[3] = {NULL, NULL, NULL};
static int pre_handler_disable_irq(struct kprobe *p, struct pt_regs *regs) {
    // 抓取函数的第一个参数（x86_64 把它放在 rdi 寄存器中），即中断号
    if (regs->di != MASK_ID) {
        return 0;
    }
    ktime_get_ts64(&close_time); // 记录关中断的时间
    
    entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(*entries), GFP_ATOMIC);
    if (entries) {
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,21)
        nr_entries = stack_trace_save(entries, MAX_STACK_TRACE_DEPTH, 0);
        #else
        struct stack_trace trace;
        trace.nr_entries = 0;
        trace.max_entries = MAX_STACK_TRACE_DEPTH;
        trace.entries = entries;
        trace.skip = 0;
        save_stack_trace_tsk(get_current(), &trace);
        nr_entries = trace.nr_entries;
        #endif
    }
    is_disabled = true;
    return 0;
}
static int pre_handler_enable_irq(struct kprobe *p, struct pt_regs *regs) {
    struct timespec64 open_time;
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
            struct process_info *single_list_node;
            local_irq_save(single_irq_flag);
            preempt_disable();
            uspin_lock(&single_list_lock);
            //spin_lock_irqsave(&single_list_lock, single_irq_flag);
            
            if (length >= LENGTH_LIMIT) {
                // 如果链表长度超过上限，删除最老的记录并将其存储空间让给新记录
                struct list_head *to_delete = single_list_head.list.next;
                struct file_node *file_item;
                single_list_node = list_entry(to_delete, struct process_info, list);
                file_item = single_list_node->files_list;
                list_del(to_delete);
                --length;
                // 回收最老的记录的文件列表
                while (file_item != NULL) {
                    struct file_node *next = file_item->next;
                    kmem_cache_free(file_node_cache, file_item);
                    file_item = next;
                }
                kfree(single_list_node->entries);
            } else {
                single_list_node = kmalloc(sizeof(struct process_info), GFP_ATOMIC);
            }
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
                *next_file = kmem_cache_alloc(file_node_cache, GFP_ATOMIC);
                (*next_file)->path = d_path(&files_table->fd[i++]->f_path, (*next_file)->buffer, 256);
                (*next_file)->next = NULL;
                next_file = &(*next_file)->next;
                // 将 path 和 file_name 加入链表中（如果不及时复制的话，万一文件被删除，可能再也无法获取文件名）
            }
            // 加入链表中（把指针挂入）
            INIT_LIST_HEAD(&single_list_node->list);
            list_add_tail(&single_list_node->list, &single_list_head.list);
            ++length;
            uspin_unlock(&single_list_lock);
            local_irq_restore(single_irq_flag);
            preempt_enable();
            //spin_unlock_irqrestore(&single_list_lock, single_irq_flag);
        } else {
            kfree(entries);
        }
        entries = NULL;
    }
    is_disabled = false;
    return 0;
}

void clear_single(void) {
    // 获取锁
    local_irq_save(single_irq_flag);
    preempt_disable();
    uspin_lock(&single_list_lock);
    //spin_lock_irqsave(&single_list_lock, single_irq_flag);
    // 释放链表内存，让头结点指向自己，更新长度
    clear(&single_list_head.list, file_node_cache);
    INIT_LIST_HEAD(&single_list_head.list);
    length = 0;
    uspin_unlock(&single_list_lock);
    local_irq_restore(single_irq_flag);
    preempt_enable();
    //spin_unlock_irqrestore(&single_list_lock, single_irq_flag);
}

int start_probe(void) {
    int ret;
    struct kprobe *disable_irq_nosync_probe = NULL, *disable_irq_probe = NULL, *enable_irq_probe = NULL;
    file_node_cache = kmem_cache_create("file_node_cache", sizeof(struct file_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    if(file_node_cache == NULL) {
        pr_err("create file_node_cache failed!\n");
        return -ENOMEM;
	}

    // 抓取单一中断的关闭
    disable_irq_nosync_probe = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
    disable_irq_probe = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
    enable_irq_probe = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
    if (!disable_irq_nosync_probe || !disable_irq_probe || !enable_irq_probe) {
        kfree(disable_irq_nosync_probe);
        kfree(disable_irq_probe);
        kfree(enable_irq_probe);
        return -ENOMEM;
    }
    disable_irq_nosync_probe->symbol_name = "disable_irq_nosync";
    disable_irq_nosync_probe->pre_handler = pre_handler_disable_irq;
    disable_irq_probe->symbol_name = "disable_irq";
    disable_irq_probe->pre_handler = pre_handler_disable_irq;
    enable_irq_probe->symbol_name = "enable_irq";
    enable_irq_probe->pre_handler = pre_handler_enable_irq;
    probe_irqs[0] = disable_irq_nosync_probe;
    probe_irqs[1] = disable_irq_probe;
    probe_irqs[2] = enable_irq_probe;
    ret = register_kprobes(probe_irqs, 3);
    if (ret < 0) {
        int i;
        for (i = 0; i < 3; ++i) {
            kfree(probe_irqs[i]);
            probe_irqs[i] = NULL;
        }
        pr_err("can't register probe_irqs, ret=%d\n", ret);
        return ret;
    }
    uspin_lock_init(&single_list_lock);
    pr_info("Start probe IRQ disable.\n");
    return 0;
}
void exit_probe(void) {
    int i;
    unregister_kprobes(probe_irqs, 3);
    for (i = 0; i < 3; ++i) {
        kfree(probe_irqs[i]);
        probe_irqs[i] = NULL;
    }

    clear(&single_list_head.list, file_node_cache);
    INIT_LIST_HEAD(&single_list_head.list); // 头结点指向自己
    kmem_cache_destroy(file_node_cache);
    length = 0;
    pr_info("Stop probe IRQ disable.\n");
}
