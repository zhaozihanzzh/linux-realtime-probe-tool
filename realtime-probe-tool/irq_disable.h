// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/list.h>

#include "process_info.h"
// 目前，只能在检测关所有中断和屏蔽指定中断号之间二选一
extern int MASK_ID;
extern time64_t nsec_limit;

#define MAX_STACK_TRACE_DEPTH 64


static void clear(struct list_head *head, struct kmem_cache *file_node_cache) {
    // 回收链表
    struct process_info *pos;
    struct process_info *n;
    list_for_each_entry_safe(pos, n, head, list)
    {
        struct file_node *file_item;
        if (pos == NULL)
        {
            continue;
        }
        file_item = pos->files_list;
        while (file_item != NULL) {
            struct file_node *next = file_item->next;
            kmem_cache_free(file_node_cache, file_item);
            file_item = next;
        }
        kfree(pos->entries);
        pos->entries = NULL;
        kfree(pos);
    }
}
