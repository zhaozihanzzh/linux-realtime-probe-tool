// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/list.h>
// 目前，只能在检测关所有中断和屏蔽指定中断号之间二选一
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

    struct list_head list;
};

// TODO：输出至 procfs
static void print_list(struct list_head *head)
{
    unsigned int i;
    struct process_info *pos;
    list_for_each_entry(pos, head, list)
    {
        pr_info("pid=%d, name is %s\n", pos->pid, pos->comm);
        for (i = 0; i < pos->nr_entries; ++i) {
            pr_info("[<%p>] %pS\n", (void*)pos->entries[i], (void*)pos->entries[i]);
        }
    }
}

static void clear(struct list_head *head) {
    // 回收链表
    struct process_info *pos;
    struct process_info *n;
    list_for_each_entry_safe(pos, n, head, list)
    {
        kfree(pos->entries);
        kfree(pos);
    }
}