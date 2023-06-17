// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/version.h>

#include "user_spinlock.h"
#include "process_info.h"
#include "procfs_helper.h"
#include "lock_util.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QunChuWoLao");

int list_size = 0;

// 3个参数：开关、中断号、时长阈值 
static int enable = 0; // 0 - 关闭（默认）；1 - 全局； 2 - 某一中断号
module_param(enable, int, 0644);
MODULE_PARM_DESC(enable, "Module on/off");
int MASK_ID;
static int irq = 18;
module_param(irq, int, 0644);
MODULE_PARM_DESC(irq, "Interrupt number");
static long latency = 1000000; // 以纳秒为单位的关闭时间
module_param(latency, long, 0644);
MODULE_PARM_DESC(latency, "Max lasting time(ns) when interrupt is closed that we can tolerate");
time64_t nsec_limit;

// 记录输出 process_info 时当前的 CPU 序号
static int cpu_in_process_info;

// 输出到 seq_file
void print_list(struct list_head *head, struct seq_file *m)
{
    unsigned int i;
    struct process_info *pos;
    struct file_node *file_item;
	struct pid_array *pid_locks;
	pos = list_entry(head, struct process_info, list);
    if (pos == NULL)
    {
		pr_info("pos is null!\n");
		return;
    }
    file_item = pos->files_list;
	seq_printf(m, "IRQ disabled %lldns on cpu %u by pid %d, comm %s\n", (long long)pos->duration, pos->cpu, pos->pid, pos->comm);
	seq_printf(m, "Backtrace:\n");
	for (i = 0; i < pos->nr_entries; ++i) {
		seq_printf(m, "   [<%p>] %pS\n", (void*)pos->entries[i], (void*)pos->entries[i]);
	}
	seq_printf(m, "File descriptors:\n");
	while (file_item != NULL) {
		seq_printf(m, "   %s\n", file_item->path);

		file_item = file_item->next;
	}
	pid_locks = radix_tree_lookup(&pid_tree, pos->pid);
	if (pid_locks) {
		struct lock_info *current_lock_info;
		seq_printf(m, "Locks call trace:\n");

		if (pid_locks->ring_index != 0) {
			int len;
			if (pid_locks->ring_index <= MAX_LOCK_STACK_TRACE_DEPTH) {
				i = 0;
				len = pid_locks->ring_index;
			} else {
				i = pid_locks->ring_index % MAX_LOCK_STACK_TRACE_DEPTH;
				len = MAX_LOCK_STACK_TRACE_DEPTH;
			}
			while (len-- > 0) {
				int j;
				struct lock_process_stack *lock_node = pid_locks->pid_list[i];
				seq_printf(m, "Lock address <%p>, stack: \n", (void *)lock_node->lock_addr);
				for (j = 0; j < lock_node->nr_entries; ++j) {
					seq_printf(m, "   [<%p>] %pS\n", (void*)lock_node->entries[j], (void*)lock_node->entries[j]);
				}
				hash_for_each_possible(lock_table, current_lock_info, node, lock_node->lock_addr) {
					struct lock_process_stack *current_process;
					if (current_lock_info->lock_address != lock_node->lock_addr)
						continue;
					for (current_process = READ_ONCE(current_lock_info->begin); current_process != NULL; current_process = current_process->next) {
						if (current_process->pid == pos->pid) {
							continue;
						}
						seq_printf(m, "   Lock also held by pid %d, comm %s\n", current_process->pid, current_process->comm);
					}
				}
				i = (i + 1) % MAX_LOCK_STACK_TRACE_DEPTH;
			}
		}
	}
	seq_printf(m, "-- End item --\n");
}

// 用户写enable文件，以修改enable参数 
static ssize_t proc_enable_write(struct file *file,
		const char __user *buf,
		size_t size,
		loff_t *offset)
{
	char tmp[16] = {0};
	
	if(copy_from_user(&tmp, buf, size))
		return -EFAULT;
		
	if(tmp[strlen(tmp)] == '\n')
		tmp[strlen(tmp)] = 0x00;
	if(tmp[strlen(tmp)-1] == '\n')
		tmp[strlen(tmp)-1] = 0x00;
			
	if(strcmp("0", tmp) == 0){
		if (enable == 1) {
			// local disable
			stop_lock_trace();
			exit_trace();
		} else if (enable == 2) {
			stop_lock_trace();
			exit_probe();
		}
		enable = 0;
		printk(KERN_INFO "module disabled. enable == %d\n", enable);
	} else if(strcmp("1", tmp) == 0) {
		if (enable == 0) {
			// local enable
			int ret = start_trace();
			if (ret < 0) {
				pr_err("Error: can't register tracepoints, ret=%d.\n", ret);
				pr_err("Maybe you don't have CONFIG_TRACE_IRQFLAGS enabled in your kernel.\n");
				return ret;
			}
			ret = start_lock_trace();
			if (ret < 0) {
				exit_trace();
				return ret;
			}
		} else if (enable == 2) {
			int ret;
			stop_lock_trace();
			exit_probe();
			// local enable
			ret = start_trace();
			if (ret < 0) {
				pr_err("Error: can't register tracepoints, ret=%d.\n", ret);
				pr_err("Maybe you don't have CONFIG_TRACE_IRQFLAGS enabled in your kernel.\n");
				enable = 0;
				return ret;
			}
			ret = start_lock_trace();
			if (ret < 0) {
				exit_trace();
				enable = 0;
				return ret;
			}
		}
		enable = 1;
	} else if(strcmp("2", tmp) == 0) {
		if (enable == 0) {
			int ret = start_probe();
			if (ret < 0) {
				return ret;
			}
			ret = start_lock_trace();
			if (ret < 0) {
				exit_probe();
				return ret;
			}
		} else if (enable == 1) {
			int ret;
			// local disable
			stop_lock_trace();
			exit_trace();
			ret = start_probe();
			if (ret < 0) {
				enable = 0;
				return ret;
			}
			ret = start_lock_trace();
			if (ret < 0) {
				enable = 0;
				exit_probe();
				return ret;
			}
		}
		enable = 2;
	}
	else {
		return -EINVAL;
	}
	return size;
}

// 用户读enable文件，以获取enable的值 
static ssize_t proc_enable_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[16] = {0};
	int len = 0;
	
	len=snprintf(tmp_buf, 16, "%d\n", enable);
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

// 用户写irq文件，以修改irq参数 
static ssize_t proc_irq_write(struct file *file,
		const char __user *buf,
		size_t size,
		loff_t *offset)
{
	char tmp[16] = {0};
	char *it;
	int i, c;
	
	if(copy_from_user(&tmp, buf, size))
		return -EFAULT;
		
	if(tmp[strlen(tmp)] == '\n')
		tmp[strlen(tmp)] = 0x00;
	if(tmp[strlen(tmp)-1] == '\n')
		tmp[strlen(tmp)-1] = 0x00;
		
	if(*tmp == 0x00)
		return -EINVAL;
	it = tmp;
	for (i = 0; (c = *it) != 0x00 ; ++it) {
		if ('0' <= c && c <= '9') {
			i = i*10 + c - '0';
		} else {
			return -EINVAL;
		}
	}
	if (MASK_ID != i && enable == 2) {
		// 此时追踪的中断号已经变化，需要清除原有链表再重新开始
		stop_lock_trace();
		exit_probe();
		MASK_ID = i;
		start_probe();
		start_lock_trace();
	} else {
		MASK_ID = i;
	}
	// irq 变更
	printk(KERN_INFO "irq changed. irq == %d\n", MASK_ID);
	return size;
}

// 用户读irq文件，以获取irq的值 
static ssize_t proc_irq_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[16] = {0};
	int len = 0;
	
	len=snprintf(tmp_buf, 16, "%d\n", MASK_ID);
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

// 用户写latency文件，以修改latency参数 
static ssize_t proc_latency_write(struct file *file,
		const char __user *buf,
		size_t size,
		loff_t *offset)
{
	char tmp[16] = {0};
	char c, *it;
	time64_t i;
	
	if(copy_from_user(&tmp, buf, size))
		return -EFAULT;
		
	if(tmp[strlen(tmp)] == '\n')
		tmp[strlen(tmp)] = 0x00;
	if(tmp[strlen(tmp)-1] == '\n')
		tmp[strlen(tmp)-1] = 0x00;
		
	if(*tmp == 0x00)
		return -EINVAL;
	it = tmp;
	for (i = 0; (c = *it) != 0x00 ; ++it) {
		if ('0' <= c && c <= '9') {
			i = i*10 + c - '0';
		} else {
			return -EINVAL;
		}
	}
	if (i == 0) return -EINVAL;
	nsec_limit = i;
	// latency 变更
	printk(KERN_INFO "latency changed. latency == %lld\n", nsec_limit);
	
	return size;
}

// 用户读latency文件，以获取latency的值 
static ssize_t proc_latency_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[20] = {0};
	int len = 0;
	len=snprintf(tmp_buf, 20, "%lld\n", nsec_limit);
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

// 用户写process_info文件，以清空process_info
static ssize_t proc_process_info_write(struct file *file,
		const char __user *buf,
		size_t size,
		loff_t *offset)
{
	char tmp[16] = {0};
	
	if(copy_from_user(&tmp, buf, size))
		return -EFAULT;
		
	if(tmp[strlen(tmp)] == '\n')
		tmp[strlen(tmp)] = 0x00;
	if(tmp[strlen(tmp)-1] == '\n')
		tmp[strlen(tmp)-1] = 0x00;
			
	if(strcmp("0", tmp) == 0) {
		if (enable == 1) {
			// clear global
			stop_lock_trace();
			exit_trace();
			start_trace();
			start_lock_trace();
		} else if (enable == 2) {
			stop_lock_trace();
			clear_single();
			start_lock_trace();
		}
		printk(KERN_INFO "process_info cleared.");
	} else {
		return -EINVAL;
	}
	return size;
}

static void *process_info_seq_start(struct seq_file *s, loff_t *pos) {
	unsigned int cpu;	
	if (enable == 1) {
		pr_info("Printing CPU %u:\n", cpu_in_process_info);
		if (cpu_in_process_info == -1) {
			// 临时禁止记录
			for_each_present_cpu(cpu)
			{
				uspin_lock(per_cpu_ptr(&in_prober[0], cpu));
				smp_mb();
				uspin_lock(per_cpu_ptr(&in_prober[1], cpu));
				smp_mb();
				uspin_lock(per_cpu_ptr(&in_prober[2], cpu));
				smp_mb();
				uspin_lock(per_cpu_ptr(&in_prober[3], cpu));
				smp_mb();
			}
			cpu_in_process_info = 0;
			uspin_lock(per_cpu_ptr(&local_list_lock, cpu_in_process_info));
		} else {
			if (*pos == *per_cpu_ptr(&local_list_length, cpu_in_process_info)) {
				*pos = 0;
				uspin_unlock(per_cpu_ptr(&local_list_lock, cpu_in_process_info));
				if (cpu_in_process_info == num_present_cpus() - 1) {
					for_each_present_cpu(cpu)
					{
						uspin_unlock(per_cpu_ptr(&in_prober[0], cpu));
						smp_mb();
						uspin_unlock(per_cpu_ptr(&in_prober[1], cpu));
						smp_mb();
						uspin_unlock(per_cpu_ptr(&in_prober[2], cpu));
						smp_mb();
						uspin_unlock(per_cpu_ptr(&in_prober[3], cpu));
						smp_mb();
					}
					cpu_in_process_info = -1;
					return NULL;
				}
				pr_info("Print CPU %u finished.\n", cpu_in_process_info);
				++cpu_in_process_info;
				uspin_lock(per_cpu_ptr(&local_list_lock, cpu_in_process_info));
				// 这样设计会带锁离开内核态，但应该不会死锁，因为我们只 trylock
			}
		}
		return seq_list_start(per_cpu_ptr(&local_list_head.list, cpu_in_process_info), *pos);
	} else if (enable == 2) {
		for_each_present_cpu(cpu)
		{
			uspin_lock(per_cpu_ptr(&in_prober[0], cpu));
			smp_mb();
			uspin_lock(per_cpu_ptr(&in_prober[1], cpu));
			smp_mb();
			uspin_lock(per_cpu_ptr(&in_prober[2], cpu));
			smp_mb();
			uspin_lock(per_cpu_ptr(&in_prober[3], cpu));
			smp_mb();
		}
		return seq_list_start(&single_list_head.list, *pos);
	}
	return 0;
}

static void *process_info_seq_next(struct seq_file *s, void *v, loff_t *pos) {
	if (enable == 1) {
		return seq_list_next(v, per_cpu_ptr(&local_list_head.list, cpu_in_process_info), pos);
	}
	if (enable == 2) {
		return seq_list_next(v, &single_list_head.list, pos);
	}
	return NULL;
}

static void process_info_seq_stop(struct seq_file *s, void *v) {
	unsigned int cpu;
	if (enable == 1) {
		if (cpu_in_process_info == -1) {
			return;
		}
	} else if (enable == 2) {
		for_each_present_cpu(cpu)
		{
			uspin_unlock(per_cpu_ptr(&in_prober[0], cpu));
			smp_mb();
			uspin_unlock(per_cpu_ptr(&in_prober[1], cpu));
			smp_mb();
			uspin_unlock(per_cpu_ptr(&in_prober[2], cpu));
			smp_mb();
			uspin_unlock(per_cpu_ptr(&in_prober[3], cpu));
			smp_mb();
		}
	}
}

static int process_info_seq_show(struct seq_file *s, void *v) {
	print_list(v, s);
	return 0;
}

static struct seq_operations process_info_seq_ops = {
	.start = process_info_seq_start,
	.next = process_info_seq_next,
	.stop = process_info_seq_stop,
	.show = process_info_seq_show
};

static int process_info_open(struct inode *inode, struct file *file) {
	return seq_open(file, &process_info_seq_ops);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static struct file_operations enable_fops = {
	.write = proc_enable_write,
	.read = proc_enable_read,
};

static struct file_operations latency_fops = {
	.write = proc_latency_write,
	.read = proc_latency_read,
};

static struct file_operations irq_fops = {
	.write = proc_irq_write,
	.read = proc_irq_read,
};

static struct file_operations process_info_fops = {
	.open = process_info_open,
	.release = seq_release,
	.llseek = seq_lseek,
	.write = proc_process_info_write,
	.read = seq_read
};
#else
static struct proc_ops enable_fops = {
	.proc_write = proc_enable_write,
	.proc_read = proc_enable_read,
};

static struct proc_ops latency_fops = {
	.proc_write = proc_latency_write,
	.proc_read = proc_latency_read,
};

static struct proc_ops irq_fops = {
	.proc_write = proc_irq_write,
	.proc_read = proc_irq_read,
};

static struct proc_ops process_info_fops = {
	.proc_open = process_info_open,
	.proc_release = seq_release,
	.proc_lseek = seq_lseek,
	.proc_write = proc_process_info_write,
	.proc_read = seq_read
};
#endif

static int __init start_module(void)
{
	struct proc_dir_entry *parent_dir;
	// 检查参数是否合法
	if (irq < 0) return -EINVAL;
	if (latency <= 0) return -EINVAL;
	MASK_ID = irq;
	nsec_limit = latency;

	// 在/proc下创建 realtime_probe_tool目录 
	parent_dir = proc_mkdir("realtime_probe_tool", NULL);
	if(parent_dir == NULL){
    	printk(KERN_ERR "create parent_dir failed\n");
    	return -ENOMEM;
	}
	// 在/proc/realtime_probe_tool下创建4个文件
    if(!proc_create("enable", 0744, parent_dir, &enable_fops)) {
    	printk(KERN_ERR "create enable failed\n");
    	return -ENOMEM;
	}
    if(!proc_create("latency", 0744, parent_dir, &latency_fops)) {
    	printk(KERN_ERR "create latency failed\n");
    	return -ENOMEM;
	}
    if(!proc_create("irq", 0744, parent_dir, &irq_fops)) {
    	printk(KERN_ERR "create irq failed\n");
    	return -ENOMEM;
	}
	if(!proc_create("process_info", 0744, parent_dir, &process_info_fops)) {
    	printk(KERN_ERR "create process_info failed\n");
    	return -ENOMEM;
	}
	cpu_in_process_info = -1; // 无效值
	if (enable == 1) {
		int ret = start_trace();
		if (ret < 0) {
			pr_err("Error: can't register tracepoints, ret=%d.\n", ret);
			pr_err("Maybe you don't have CONFIG_TRACE_IRQFLAGS enabled in your kernel.\n");
			return ret;
		}
		ret = start_lock_trace();
		if (ret < 0) {
			exit_trace();
			return ret;
		}
	} else if (enable == 2) {
		int ret = start_probe();
		if (ret < 0) {
			return ret;
		}
		ret = start_lock_trace();
		if (ret < 0) {
			exit_probe();
			return ret;
		}
	} else if (enable != 0) {
		return -EINVAL;
	}
	printk(KERN_INFO "Module init, enable == %d, irq == %d, latency == %lld\n", enable, MASK_ID, nsec_limit);
    return 0;
}

static void __exit exit_module(void)
{
	remove_proc_subtree("realtime_probe_tool", NULL);
	if (enable == 1) {
		stop_lock_trace();
		exit_trace();
	} else if (enable == 2) {
		stop_lock_trace();
		exit_probe();
	}
    printk(KERN_INFO "Module exit.\n");
}
module_init(start_module);
module_exit(exit_module);