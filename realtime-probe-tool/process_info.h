// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/slab.h>
#include <linux/sched.h>
// 链表结点
struct process_info
{
    pid_t pid; // 进程 PID
    char comm[TASK_COMM_LEN];
    unsigned int cpu; // 运行在哪个 CPU 上
    unsigned int nr_entries;
    unsigned long *entries; // 关中断时的堆栈信息
    time64_t duration; // 关中断的纳秒数
    // 链表：文件名
    // 链表：存放文件名所用内存的指针
    struct file_node *files_list;
    struct list_head list;
};

// 用于记录进程打开的文件，这里我们没有用内核链表，因为我们对链表所作的操作很简单
struct file_node
{
    char buffer[256];
    char *path;
    struct file_node *next;
};