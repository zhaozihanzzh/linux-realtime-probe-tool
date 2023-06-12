// SPDX-License-Identifier: AGPL-3.0-or-later
extern int start_probe(void);
extern void exit_probe(void);
extern void clear_single(void);
extern struct process_info single_list_head;

extern int start_trace(void);
extern void exit_trace(void);
extern int local_irq_disable_output(void);
extern uspinlock_t local_list_lock;
extern unsigned long local_irq_flag;
extern struct process_info local_list_head;

DECLARE_PER_CPU(unsigned int, local_list_length);