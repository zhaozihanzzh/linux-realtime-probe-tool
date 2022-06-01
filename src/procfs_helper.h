// SPDX-License-Identifier: AGPL-3.0-or-later
extern int start_probe(void);
extern void exit_probe(void);
extern ssize_t print_list(struct list_head *head, char __user *buf, size_t size, loff_t *ppos);
extern struct process_info single_list_head;