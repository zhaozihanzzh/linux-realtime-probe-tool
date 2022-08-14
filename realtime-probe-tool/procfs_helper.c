// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/list.h>

#include "irq_disable.h"
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

// 修改自内核函数 simple_read_from_buffer 为固定一个 to，ppos 不再在 from 中浮动，而是在 to 中浮动
ssize_t simple_read_from_multi_buffer(void __user *to, size_t count, loff_t *ppos,
				const void *from, size_t available)
{
	loff_t pos = *ppos;
	size_t ret;

	if (pos < 0)
		return -EINVAL;
	if (pos >= count || !count)
		return 0;
	count -= pos; // to 中当前剩余的
	if (count > available)
		count = available;
	ret = copy_to_user(to + pos, from, count);
	if (ret == count)
		return -EFAULT;
	count -= ret;
	*ppos = pos + count;
	return count;
}

// 输出至 procfs
ssize_t print_list(struct list_head *head, char __user *buf, size_t size, loff_t *ppos)
{
    unsigned int i;
	ssize_t char_count = 0, curr_count = 0;
    struct process_info *pos;
    list_for_each_entry(pos, head, list)
    {
        struct file_node *file_item;
        static char buffer[256];
		struct pid_array *pid_locks;
        if (pos == NULL)
        {
            continue;
        }
        file_item = pos->files_list;
        curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, \
			"IRQ disabled %lldns on cpu %u by pid %d, comm %s\n", (long long)pos->duration, pos->cpu, pos->pid, pos->comm));
		if (curr_count < 0) {
			pr_warn("Read failed=%ld\n",curr_count);
			return curr_count;
		} else char_count += curr_count;
        curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, "Backtrace:\n"));
        if (curr_count < 0) {
			pr_warn("Read failed=%ld\n",curr_count);
			return curr_count;
		} else char_count += curr_count;
		for (i = 0; i < pos->nr_entries; ++i) {
            curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, \
				"   [<%p>] %pS\n", (void*)pos->entries[i], (void*)pos->entries[i]));
			if (curr_count < 0) {
				pr_warn("Read failed=%ld\n",curr_count);
				return curr_count;
			} else char_count += curr_count;
        }
        curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, "File descriptors:\n"));
		if (curr_count < 0) {
			pr_warn("Read failed=%ld\n",curr_count);
			return curr_count;
		} else char_count += curr_count;
        while (file_item != NULL) {
            curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, "   %s\n", file_item->path));
			if (curr_count < 0) {
				pr_warn("Read failed=%ld\n",curr_count);
				return curr_count;
			} else char_count += curr_count;
            file_item = file_item->next;
        }
		pid_locks = radix_tree_lookup(&pid_tree, pos->pid);
		if (pid_locks) {
			struct lock_info *current_lock_info;
			curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, "Locks call trace:\n"));
			if (curr_count < 0) {
				pr_warn("Read failed=%ld\n",curr_count);
				return curr_count;
			} else char_count += curr_count;
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
					curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, \
						"Lock address <%p>, stack: \n", (void *)lock_node->lock_addr));
					if (curr_count < 0) {
						pr_warn("Read failed=%ld\n",curr_count);
						return curr_count;
					} else char_count += curr_count;
					for (j = 0; j < lock_node->nr_entries; ++j) {
        			    curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, \
							"   [<%p>] %pS\n", (void*)lock_node->entries[j], (void*)lock_node->entries[j]));
						if (curr_count < 0) {
							pr_warn("Read failed=%ld\n",curr_count);
							return curr_count;
						} else char_count += curr_count;
        			}
					hash_for_each_possible(lock_table, current_lock_info, node, lock_node->lock_addr) {
						struct lock_process_stack *current_process;
						if (current_lock_info->lock_address != lock_node->lock_addr)
							continue;
						for (current_process = current_lock_info->begin; current_process != NULL; current_process = current_process->next) {
							if (current_process->pid == pos->pid) {
								continue;
							}
							curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, \
								"   Lock also held by pid %d, comm %s\n", current_process->pid, current_process->comm));
							if (curr_count < 0) {
								pr_warn("Read failed=%ld\n",curr_count);
								return curr_count;
							} else char_count += curr_count;
						}
					}
					i = (i + 1) % MAX_LOCK_STACK_TRACE_DEPTH;
				}
			}
        }
        curr_count = simple_read_from_multi_buffer(buf, size, ppos, buffer, snprintf(buffer, 256, "-- End item --\n"));
		if (curr_count < 0) {
			pr_warn("Read failed=%ld\n",curr_count);
			return curr_count;
		} else char_count += curr_count;
    }
    return char_count;
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

// 用户读process_info文件，以获取进程信息
static ssize_t proc_process_info_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	ssize_t ret = 0;
    unsigned int cpu;
	if (*ppos) return 0;
	if (enable == 1) {
    	preempt_disable();
		// 临时禁止记录锁
		for_each_present_cpu(cpu)
		{
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[0], cpu), 0, 1)) ;
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[1], cpu), 0, 1)) ;
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[2], cpu), 0, 1)) ;
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[3], cpu), 0, 1)) ;
		}
    	for_each_present_cpu(cpu)
    	{
    	    pr_info("Printing CPU %u:\n", cpu);
    	    // 如果访问的不是当前 CPU，要先看 local_list_lock 的值
    	    if (cpu != smp_processor_id())
    	    {
				spin_lock_irqsave(per_cpu_ptr(&local_list_lock, cpu), *per_cpu_ptr(&local_irq_flag, cpu));
    	        ret += print_list(per_cpu_ptr(&local_list_head.list, cpu), buf, size, ppos);
				spin_unlock_irqrestore(per_cpu_ptr(&local_list_lock, cpu), *per_cpu_ptr(&local_irq_flag, cpu));

    	    }
    	    else
    	    {
    	        // 如果访问的是当前 CPU 的，不需要用 local_list_lock 保护
    	        ret += print_list(per_cpu_ptr(&local_list_head.list, cpu), buf, size, ppos);
    	    }
    	    pr_info("Print CPU %u finished.\n", cpu);
    	}
    	preempt_enable();
		for_each_present_cpu(cpu)
		{
			atomic_set(per_cpu_ptr(&in_prober[0], cpu), 0) ;
			atomic_set(per_cpu_ptr(&in_prober[1], cpu), 0) ;
			atomic_set(per_cpu_ptr(&in_prober[2], cpu), 0) ;
			atomic_set(per_cpu_ptr(&in_prober[3], cpu), 0) ;
		}
		return ret;
	}
	if (enable == 2) {
		for_each_present_cpu(cpu)
		{
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[0], cpu), 0, 1)) ;
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[1], cpu), 0, 1)) ;
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[2], cpu), 0, 1)) ;
			while (atomic_cmpxchg(per_cpu_ptr(&in_prober[3], cpu), 0, 1)) ;
		}
		ret += print_list(&single_list_head.list, buf, size, ppos);
		for_each_present_cpu(cpu)
		{
			atomic_set(per_cpu_ptr(&in_prober[0], cpu), 0) ;
			atomic_set(per_cpu_ptr(&in_prober[1], cpu), 0) ;
			atomic_set(per_cpu_ptr(&in_prober[2], cpu), 0) ;
			atomic_set(per_cpu_ptr(&in_prober[3], cpu), 0) ;
		}
		return ret;
	}
	return 0;
}


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
	.write = proc_process_info_write,
	.read = proc_process_info_read,
};

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