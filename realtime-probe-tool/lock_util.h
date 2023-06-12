// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef LOCK_UTIL_H
#define LOCK_UTIL_H
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/radix-tree.h>
#include <linux/sched.h>

// 假设 PID 不会用完
// 栈深度
#define MAX_LOCK_STACK_TRACE_DEPTH 32
// Hash Table，key 为地址
#define LOCK_TABLE_BITS 14

extern DECLARE_HASHTABLE(lock_table, LOCK_TABLE_BITS);
DECLARE_PER_CPU(atomic_t, in_prober[4]);
extern struct radix_tree_root pid_tree;

struct lock_process_stack {
    // struct list_head process_list_node;
    struct lock_process_stack *next;
    unsigned long lock_addr;
    pid_t pid;
    char comm[TASK_COMM_LEN];
    unsigned int nr_entries;
    unsigned long entries[MAX_LOCK_STACK_TRACE_DEPTH];
};
struct lock_info {
    // struct list_head process_list_head;
    struct lock_process_stack *begin;
    unsigned long lock_address;
    unsigned int process_list_len;
    // unsigned int lock_type;
    struct hlist_node node;
};
#define MAX_PID_LIST_SIZE 32
struct pid_array {
    struct lock_process_stack *pid_list[MAX_PID_LIST_SIZE];
    int ring_index; // 下次要写入的位置
};

extern int start_lock_trace(void);
extern void stop_lock_trace(void);
#endif /* LOCK_UTIL_H */