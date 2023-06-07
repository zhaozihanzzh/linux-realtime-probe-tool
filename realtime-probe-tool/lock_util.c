// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <asm/atomic.h>

#include "lock_util.h"
#include "user_spinlock.h"

DEFINE_HASHTABLE(lock_table, LOCK_TABLE_BITS);
int hash_table_load_num = 0;
uspinlock_t table_lock;
DEFINE_PER_CPU(atomic_t, in_prober[4]); // 如果 spin_lock 追踪时触发了 spin_lock_irqsave，不会再去记录 spin_lock_irqsave，否则会死锁

struct radix_tree_root pid_tree;

static struct kprobe* probe_locks[4] = {NULL, NULL, NULL, NULL};

/** 对不同的锁分开记录，直接使用不同的哈希表，增强并发能力
 *@param 还没写完
 */
static void add_into_hashtable(unsigned long lock_addr) {
    bool is_shared;
    struct lock_info *current_lock_info;
    struct task_struct *on_lock_task;
    on_lock_task = get_current();
    is_shared = false;
    if (preemptible()) {
        pr_err("PREEMPTIBLE!\n");
        return;
    }
    if (uspin_trylock(&table_lock)) {
        pr_err("NotLocked!\n");
        return;
    }
    if (!irqs_disabled()) {
        pr_err("IRQON!\n");
        return;
    }
    hash_for_each_possible(lock_table, current_lock_info, node, lock_addr) {
        // current_lock_info 一定不为 NULL
        if (current_lock_info->lock_address == lock_addr) {
            bool has_same_pid;
            struct lock_process_stack *pos;
            // struct list_head *pos;
            int i;
            is_shared = true;
            has_same_pid = false;
            i = 0;
            //current_lock_info->lock_type = lock_type;
            // 遍历进程链表
            //
            // pos = list_first_entry(&current_lock_info->process_list_head, typeof(*pos), process_list_node);
            // (&pos->process_list_node == (&current_lock_info->process_list_head))
            // pos = list_next_entry(pos, process_list_node))
            // 原版
            // list_for_each(pos, &current_lock_info->process_list_head) {
            //     if (list_entry(pos, struct lock_process_stack, process_list_node)->pid == get_current()->pid) {
            //         has_same_pid = true;
            //         break;
            //     }
            //     if (i++ >= current_lock_info->process_list_len) {
            //         pr_info("Warning! List traversal error.\n");
            //         break;
            //     }
            // }
            // 链表试验版
            for (pos = current_lock_info->begin; pos != NULL; pos = pos->next) {
                if (pos->canary1 != 0xdeadbeef) {
                    pr_err_ratelimited("iter pos->canary1=%x\n", pos->canary1);
                }
                if (pos->canary2 != 0xdeadbeef) {
                    pr_err_ratelimited("iter pos->canary2=%x\n", pos->canary2);
                }
                if (pos->pid == on_lock_task->pid) {
                    has_same_pid = true;
                    break;
                }
            }

            // list_for_each_entry(pos, &current_lock_info->process_list_head, process_list_node) {
            //     // Pos 是 NULL
            //     // if (pos == NULL) {
            //     //     pr_err("Pos is NULL!\n");
            //     // }
            //     if (pos->pid == get_current()->pid) {
            //         has_same_pid = true;
            //         break;
            //     }
            // }
            //break;// 与此实际上无关
            if (!has_same_pid) {
                #if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,21)
                struct stack_trace lock_trace;
                #endif
                struct lock_process_stack *new_node;
                struct pid_array *pid_array_ptr;
                //ktime_get_ts64(&before_alloc);

                new_node = kmalloc(sizeof(struct lock_process_stack), GFP_ATOMIC);
                //ktime_get_ts64(&after_alloc);
                //pr_info("Alloc cost %lld ns\n", (after_alloc.tv_sec - before_alloc.tv_sec) * 1000000000ll + after_alloc.tv_nsec - before_alloc.tv_nsec);
                if (new_node == NULL) {
                    pr_err("Can't alloc mem!\n");
                }
                new_node->canary1 = new_node->canary2 = 0xdeadbeef;
                new_node->lock_addr = lock_addr;
                // INIT_LIST_HEAD(&new_node->process_list_node);
                /*链表试验版*/ new_node->next = current_lock_info->begin;
                // 获取 PID 与 comm
                new_node->pid = on_lock_task->pid;
                memcpy(new_node->comm, on_lock_task->comm, TASK_COMM_LEN * sizeof(char));
                // 获取调用栈
                #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,21)
                new_node->nr_entries = stack_trace_save(new_node->entries, MAX_LOCK_STACK_TRACE_DEPTH, 0);
                #else
                lock_trace.nr_entries = 0;
                lock_trace.max_entries = MAX_LOCK_STACK_TRACE_DEPTH;
                lock_trace.entries = new_node->entries;
                lock_trace.skip = 0;// 复制过来时是 2
                save_stack_trace_tsk(on_lock_task, &lock_trace);
                new_node->nr_entries = lock_trace.nr_entries;
                #endif
                if (preemptible()) {
                    pr_err("107PREEMPTIBLE!\n");
                    return;
                }
                if (uspin_trylock(&table_lock)) {
                    pr_err("111NotLocked!\n");
                    return;
                }
                if (!irqs_disabled()) {
                    pr_err("115IRQON\n");
                    return;
                }
                if (new_node->canary1 != 0xdeadbeef) {
                    pr_err("canary1 is %u in line 99!", new_node->canary1);
                }
                if (new_node->canary2 != 0xdeadbeef) {
                    pr_err("canary2 is %u in line 102!", new_node->canary2);
                }
                // 加入链表（之前用的是 list_add,实验tail）
                // list_add_tail(&new_node->process_list_node, &current_lock_info->process_list_head);
                current_lock_info->begin = new_node;
                current_lock_info->process_list_len++;
                pid_array_ptr = radix_tree_lookup(&pid_tree, new_node->pid);
                if (pid_array_ptr) {
                    pid_array_ptr->pid_list[pid_array_ptr->ring_index++ % MAX_PID_LIST_SIZE] = new_node;
                } else {
                    int ret;
                    pid_array_ptr = kmalloc(sizeof(struct pid_array), GFP_ATOMIC);
                    pid_array_ptr->pid_list[0] = new_node;
                    pid_array_ptr->ring_index = 1;
                    ret = radix_tree_insert(&pid_tree, new_node->pid, pid_array_ptr);
                    if (ret) {
                        pr_err("Can't insert PID %d into radix tree, return %d\n", new_node->pid, ret);
                    }
                }
            }
            break;
        }
    }
    if (!is_shared) {
        #if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,21)
        struct stack_trace lock_trace;
        #endif
        struct lock_process_stack *new_node;
        struct pid_array *pid_array_ptr;
        new_node = kmalloc(sizeof(struct lock_process_stack), GFP_ATOMIC);
        if (new_node == NULL) {
            pr_err("Can't alloc mem for new_node!\n");
        }
        new_node->lock_addr = lock_addr;
        new_node->canary1 = new_node->canary2 = 0xdeadbeef;
        current_lock_info = kmalloc(sizeof(struct lock_info), GFP_ATOMIC);
        if (current_lock_info == NULL) {
            pr_err("Can't alloc mem for current_lock_info!\n");
        }
        
        // 抓取函数的第一个参数（x86_64 把它放在 rdi 寄存器中），即锁的地址
        current_lock_info->lock_address = lock_addr;
        INIT_HLIST_NODE(&current_lock_info->node);
        new_node->pid = on_lock_task->pid;
        new_node->next = NULL;
        memcpy(new_node->comm, on_lock_task->comm, TASK_COMM_LEN * sizeof(char));
        current_lock_info->process_list_len = 1;

        // 保存栈
        // INIT_LIST_HEAD(&new_node->process_list_node);
        /*链表试验版*/
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,21)
        new_node->nr_entries = stack_trace_save(new_node->entries, MAX_LOCK_STACK_TRACE_DEPTH, 0);
        #else
        lock_trace.nr_entries = 0;
        lock_trace.max_entries = MAX_LOCK_STACK_TRACE_DEPTH;
        lock_trace.entries = new_node->entries;
        lock_trace.skip = 0; // 复制过来时是 2
        save_stack_trace_tsk(on_lock_task, &lock_trace);
        new_node->nr_entries = lock_trace.nr_entries;
        #endif
        if (preemptible()) {
            pr_err("174PREEMPTIBLE!\n");
            return;
        }
        if (uspin_trylock(&table_lock)) {
            pr_err("178NotLocked!\n");
            return;
        }
        if (!irqs_disabled()) {
            pr_err("185IRQON\n");
            return;
        }
        if (new_node->canary1 != 0xdeadbeef) {
            pr_err("canary1 is %u in line 159!", new_node->canary1);
        }
        if (new_node->canary2 != 0xdeadbeef) {
            pr_err("canary2 is %u in line 162!", new_node->canary2);
        }
        // list_add_tail(&new_node->process_list_node, &current_lock_info->process_list_head);
        current_lock_info->begin = new_node;

        hash_add(lock_table, &current_lock_info->node, current_lock_info->lock_address);
        ++hash_table_load_num;

        /*pid_array_ptr = radix_tree_lookup(&pid_tree, new_node->pid);
        if (pid_array_ptr) {
            pid_array_ptr->pid_list[pid_array_ptr->ring_index++ % MAX_PID_LIST_SIZE] = new_node;
        } else {
            int ret;
            pid_array_ptr = kmalloc(sizeof(struct pid_array), GFP_ATOMIC);
            pid_array_ptr->pid_list[0] = new_node;
            pid_array_ptr->ring_index = 1;
            ret = radix_tree_insert(&pid_tree, new_node->pid, pid_array_ptr);
            if (ret) {
                pr_err("Can't insert PID %d into radix tree, return %d\n", new_node->pid, ret);
            }
        }*/
    }
}
static int pre_handler_spin_lock_irqsave(struct kprobe *p, struct pt_regs *regs) {
    unsigned long irq_flags;
    local_irq_save(irq_flags);
    preempt_disable();
    smp_mb();
    if (atomic_cmpxchg(this_cpu_ptr(&in_prober[0]), 0, 1)) {
        smp_mb();
        local_irq_restore(irq_flags);
        preempt_enable();
        return 0;
    }
    uspin_lock(&table_lock);
    smp_mb();
    add_into_hashtable(regs->di);
    uspin_unlock(&table_lock);
    atomic_set(this_cpu_ptr(&in_prober[0]), false);
    smp_mb();
    local_irq_restore(irq_flags);
    preempt_enable();

    return 0;
}
static int pre_handler_spin_lock(struct kprobe *p, struct pt_regs *regs) {
    unsigned long irq_flags;
    local_irq_save(irq_flags);
    preempt_disable();
    smp_mb();
    if (atomic_cmpxchg(this_cpu_ptr(&in_prober[1]), 0, 1)) {
        smp_mb();
        local_irq_restore(irq_flags);
        preempt_enable();
        return 0;
    }
    uspin_lock(&table_lock);
    add_into_hashtable(regs->di);
    uspin_unlock(&table_lock);
    atomic_set(this_cpu_ptr(&in_prober[1]), false);
    smp_mb();
    local_irq_restore(irq_flags);
    preempt_enable();

    return 0;
}
static int pre_handler_spin_lock_irq(struct kprobe *p, struct pt_regs *regs) {
    unsigned long irq_flags;
    local_irq_save(irq_flags);
    preempt_disable();
    smp_mb();
    if (atomic_cmpxchg(this_cpu_ptr(&in_prober[2]), 0, 1)) {
        smp_mb();
        local_irq_restore(irq_flags);
        preempt_enable();
        return 0;
    }
    uspin_lock(&table_lock);
    smp_mb();
    add_into_hashtable(regs->di);
    uspin_unlock(&table_lock);
    atomic_set(this_cpu_ptr(&in_prober[2]), false);
    smp_mb();
    local_irq_restore(irq_flags);
    preempt_enable();
    return 0;
}
static int pre_handler_spin_lock_bh(struct kprobe *p, struct pt_regs *regs) {
    unsigned long irq_flags;
    local_irq_save(irq_flags);
    preempt_disable();
    smp_mb();
    if (atomic_cmpxchg(this_cpu_ptr(&in_prober[3]), 0, 1)) {
        smp_mb();
        local_irq_restore(irq_flags);
        preempt_enable();
        return 0;
    }
    uspin_lock(&table_lock);
    smp_mb();
    add_into_hashtable(regs->di);
    uspin_unlock(&table_lock);
    atomic_set(this_cpu_ptr(&in_prober[3]), false);
    smp_mb();
    local_irq_restore(irq_flags);
    preempt_enable();
    return 0;
}

int start_lock_trace(void)
{
    int ret, cpu;
    struct kprobe *probe_spin_lock_irqsave, *probe_spin_lock, *probe_spin_lock_irq, *probe_spin_lock_bh;
    uspin_lock_init(&table_lock);
    hash_init(lock_table);//这行没必要,重复了;在重新建立时才有必要
    INIT_RADIX_TREE(&pid_tree, GFP_ATOMIC); // RADIX TREE 里面居然含有 SPIN LOCK!!!
    //RADIX_TREE_INIT(pid_tree, GFP_ATOMIC);
    for_each_present_cpu(cpu) {
        atomic_set(per_cpu_ptr(&in_prober[0], cpu), 0);
        atomic_set(per_cpu_ptr(&in_prober[1], cpu), 0);
        atomic_set(per_cpu_ptr(&in_prober[2], cpu), 0);
        atomic_set(per_cpu_ptr(&in_prober[3], cpu), 0);
    }
    smp_mb();
    // 由于某些原因，最好动态分配 KProbe 结构体，否则 unregister 后无法 re-register
    // 见：https://lore.kernel.org/all/20210114092525.5a2e78b404602fa82d6d6353@kernel.org/
    // https://stackoverflow.com/questions/46498699/register-kprobe-returns-einval-without-additional-memory-on-containing-struct
    probe_spin_lock_irqsave = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
    probe_spin_lock = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
    probe_spin_lock_irq = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
    probe_spin_lock_bh = kzalloc(sizeof(struct kprobe), GFP_ATOMIC);
    if (!probe_spin_lock_irqsave || !probe_spin_lock || !probe_spin_lock_irq || !probe_spin_lock_bh) {
        kfree(probe_spin_lock_irqsave);
        kfree(probe_spin_lock);
        kfree(probe_spin_lock_irq);
        kfree(probe_spin_lock_bh);
        return -ENOMEM;
    }
    probe_spin_lock_irqsave->symbol_name = "_raw_spin_lock_irqsave";
    probe_spin_lock_irqsave->pre_handler = pre_handler_spin_lock_irqsave;
    probe_spin_lock->symbol_name = "_raw_spin_lock";
    probe_spin_lock->pre_handler = pre_handler_spin_lock;
    probe_spin_lock_irq->symbol_name = "_raw_spin_lock_irq";
    probe_spin_lock_irq->pre_handler = pre_handler_spin_lock_irq;
    probe_spin_lock_bh->symbol_name = "_raw_spin_lock_bh";
    probe_spin_lock_bh->pre_handler = pre_handler_spin_lock_bh;

    probe_locks[0] = probe_spin_lock_irqsave;
    probe_locks[1] = probe_spin_lock;
    probe_locks[2] = probe_spin_lock_irq;
    probe_locks[3] = probe_spin_lock_bh;
    ret = register_kprobes(probe_locks, 4);
    if (ret < 0) {
        int i;
        for (i = 0; i < 4; ++i) {
            kfree(probe_locks[i]);
            probe_locks[i] = NULL;
        }
        pr_err("Can't register probe_locks, ret=%d\n", ret);
        return ret;
    }
    pr_info("Registered probe_locks.\n");
    return 0;
}
void stop_lock_trace(void)
{
    int cpu, i;
    struct lock_info *current_lock_info;
    struct hlist_node *tmp;
    void __rcu **slot;
    struct radix_tree_iter iter;
    unsigned long bkt, irq_flags;
    pr_info("Prepare to unregister.\n");
    unregister_kprobes(probe_locks, 4);
    for (i = 0; i < 4; ++i) {
        kfree(probe_locks[i]);
        probe_locks[i] = NULL;
    }
    for_each_present_cpu(cpu) {
        smp_mb();
        pr_info("CPU %d in_prober[0]=%d\n", cpu, atomic_read(per_cpu_ptr(&in_prober[0], cpu)));
        smp_mb();
        atomic_set(per_cpu_ptr(&in_prober[0], cpu), 1);
        smp_mb();
        pr_info("CPU %d in_prober[1]=%d\n", cpu, atomic_read(per_cpu_ptr(&in_prober[1], cpu)));
        smp_mb();
        atomic_set(per_cpu_ptr(&in_prober[1], cpu), 1);
        smp_mb();
        pr_info("CPU %d in_prober[2]=%d\n", cpu, atomic_read(per_cpu_ptr(&in_prober[2], cpu)));
        smp_mb();
        atomic_set(per_cpu_ptr(&in_prober[2], cpu), 1);
        smp_mb();
        pr_info("CPU %d in_prober[3]=%d\n", cpu, atomic_read(per_cpu_ptr(&in_prober[3], cpu)));
        smp_mb();
        atomic_set(per_cpu_ptr(&in_prober[3], cpu), 1);
        smp_mb();
    }
    // unregister_kprobe(&probe_spin_lock_irqsave);
    // unregister_kprobe(&probe_spin_lock);
    // unregister_kprobe(&probe_spin_lock_irq);
    // unregister_kprobe(&probe_spin_lock_bh);
    pr_info("Unregister done.\n");
    // in_prober = true;
    // 先关中断，再关抢占，最后持有锁
    local_irq_save(irq_flags);
    preempt_disable();
    uspin_lock(&table_lock);
    //hlist_for_each_entry_safe()
    //          name bkt obj number
    // hash_for_each(lock_table, bkt, current_lock_info, node){}
    /*while (atomic_read(this_cpu_ptr(&in_prober[0])) != 0) {}
    while (atomic_read(this_cpu_ptr(&in_prober[1])) != 0) {}
    while (atomic_read(this_cpu_ptr(&in_prober[2])) != 0) {}
    while (atomic_read(this_cpu_ptr(&in_prober[3])) != 0) {}*/
    hash_for_each_safe(lock_table, bkt, tmp, current_lock_info, node) {
        // if (current_lock_info != NULL) { // 不需要,上一行已包含判断
        struct lock_process_stack *pos;
        struct lock_process_stack *n;
        // if (current_lock_info->called_num > 1) {
            // pr_info("lock %p \n", current_lock_info->lock_address);
        // }
        // pr_err("iter%p,bkt%lu", current_lock_info, bkt);
        if (preemptible()) {
            pr_err("DELPREEMPTIBLE!\n");
            return;
        }
        if (uspin_trylock(&table_lock)) {
            pr_err("DELNotLocked!\n");
            return;
        }
        //if (current_lock_info->process_node.process_list.next != &current_lock_info->process_node.process_list) {
        // /* 原版 */list_for_each_entry_safe(pos, n, &current_lock_info->process_list_head, process_list_node) {
        pos = current_lock_info->begin; // ADD
        while (pos != NULL) { // ADD
            int i, j;
            struct pid_array *same_pid;
            n = pos->next; // ADD
            if (pos->canary1 != 0xdeadbeef) {
                pr_err_ratelimited("pos->canary1=%x\n", pos->canary1);
            }
            if (pos->canary2 != 0xdeadbeef) {
                pr_err_ratelimited("pos->canary2=%x\n", pos->canary2);
            }
            // pr_info("PID %d, comm %s, Backtrace: \n", pos->pid, pos->comm);
            // same_pid = radix_tree_lookup(&pid_tree, pos->pid);
            // if (same_pid) {
                // pr_info("Pid holds %d lock.\n", same_pid->ring_index);
            // } else {
                // pr_info("Can't find locks about this PID in radix tree!\n");
            // }m

            // list_del(&pos->process_list_node);
            // pr_err("-->tofree%p,next%p\n", pos, n);
            kfree(pos);
            pos = n; // ADD
        }
        //}
        current_lock_info->begin = NULL;
        hash_del(&current_lock_info->node);
        // pr_info("tofree%p\n", current_lock_info);
        kfree(current_lock_info);
    }
    pr_info("Deleting radix trees.\n");
    radix_tree_for_each_slot(slot, &pid_tree, &iter, 0) {
        void *this_slot = radix_tree_deref_slot(slot);
        kfree(this_slot);
        radix_tree_delete(&pid_tree, iter.index);
    }
    // 先释放锁，再开中断，最后开抢占
    uspin_unlock(&table_lock);
    local_irq_restore(irq_flags);
    preempt_enable();
    pr_info("Stop trace locks, hash table load num is %d\n", hash_table_load_num);
    hash_table_load_num = 0;
}
