// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/list.h>
// 目前，只能在检测关所有中断和屏蔽指定中断号之间二选一
// 用于记录进程打开的文件，这里我们没有用内核链表，因为我们对链表所作的操作很简单
struct file_node
{
    char *buffer;
    char *path;
    struct file_node *next;
};
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

// TODO：输出至 procfs
static void print_list(struct list_head *head)
{
    unsigned int i;
    struct process_info *pos;
    list_for_each_entry(pos, head, list)
    {
        struct file_node *file_item = pos->files_list;
        pr_info("IRQ disabled %lldns on cpu %u by pid %d, comm %s\n", (long long)pos->duration, pos->cpu, pos->pid, pos->comm);
        pr_info("Backtrace:\n");
        for (i = 0; i < pos->nr_entries; ++i) {
            pr_info("   [<%p>] %pS\n", (void*)pos->entries[i], (void*)pos->entries[i]);
        }
        pr_info("Files:\n");
        while (file_item != NULL) {
            pr_info("   %s\n", file_item->path);
            file_item = file_item->next;
        }
        pr_info("-- End item --\n");
    }
}

static void clear(struct list_head *head) {
    // 回收链表
    struct process_info *pos;
    struct process_info *n;
    list_for_each_entry_safe(pos, n, head, list)
    {
        struct file_node *file_item = pos->files_list;
        while (file_item != NULL) {
            struct file_node *next = file_item->next;
            kfree(file_item->buffer);
            kfree(file_item);
            file_item = next;
        }
        kfree(pos->entries);
        kfree(pos);
    }
}

static void clear_node(struct process_info *node) {
    // 回收单一结点
    struct file_node *file_item = node->files_list;
    while (file_item != NULL) {
        struct file_node *next = file_item->next;
        kfree(file_item->buffer);
        kfree(file_item);
        file_item = next;
    }
    kfree(node->entries);
    kfree(node);
}