// SPDX-License-Identifier: AGPL-3.0-or-later
extern int start_probe(void);
extern void exit_probe(void);
extern void clear_single(void);
extern ssize_t print_list(struct list_head *head, char __user *buf, size_t size, loff_t *ppos);
extern struct process_info single_list_head;

extern int start_trace(void);
extern void exit_trace(void);
extern int local_irq_disable_output(void);
extern atomic_t local_list_mark;
extern struct process_info local_list_head;