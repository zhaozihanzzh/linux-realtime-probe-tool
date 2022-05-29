// SPDX-License-Identifier: AGPL-3.0-or-later
#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QunChuWoLao");

struct data{
	struct list_head list;
	char number[16];
};
struct data data1;
int list_size = 0;

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

struct kmem_cache *my_cachep = NULL;

// 3个参数：开关、中断号、时长阈值 
static int enable = 1;
module_param(enable, int, 0644);
MODULE_PARM_DESC(enable, "Module on/off");
static int irq = 0;
module_param(irq, int, 0644);
MODULE_PARM_DESC(irq, "Interrupt number");
static int latence = 0;
module_param(latence, int, 0644);
MODULE_PARM_DESC(latence, "Max lasting time(us) when interrupt is closed that we can tolerate");

// 用户调整参数后调用此函数 （待完善） 
void parameter_adjust(void)
{
	enable = 0;
}

// 用户写overwrite_disck文件，记录用户输入的字符串 
static ssize_t proc_overwrite_switch_write(struct file *file,
		const char __user *buf,
		size_t size,
		loff_t *offset)
{
	char tmp[16] = {0};
	struct data *p = (struct data*)kmem_cache_zalloc(my_cachep, GFP_KERNEL);
	
	if(copy_from_user(&tmp, buf, size))
		return -EFAULT;
		
	if(tmp[strlen(tmp)] == '\n')
		tmp[strlen(tmp)] = 0x00;
	if(tmp[strlen(tmp)-1] == '\n')
		tmp[strlen(tmp)-1] = 0x00;
			
	strcpy(p->number, tmp);
	list_add_tail(&p->list, &data1.list);
	++list_size;
		
	return size;
}

// 用户读overwrite_disck文件，以读取先前写入的字符串 
static ssize_t proc_overwrite_switch_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[100] = "overwrite_disck:";
	int len = 0;
	struct data *pos;
	
	if(list_size == 0){
		len=snprintf(tmp_buf, 100, "%s", "Empty.\n");
		return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
	}		
		
	list_for_each_entry(pos, &data1.list, list){
		len = snprintf(tmp_buf, 100, "%s\n%s", tmp_buf, pos->number);
		printk("len == %d  strlen == %lu\n", len, strlen(tmp_buf));
	}
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
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
		parameter_adjust();
		printk("module disabled. enable == %d\n", enable);
	} else if(strcmp("1", tmp) == 0) {
		enable = 1;
		printk("module enabled. enable == %d\n", enable);
	} else {
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
	
	len=snprintf(tmp_buf, 16, "%d", enable);
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
		if ('0' <= (c = *it) && c <= '9') {
			i = i*10 + c - '0';
		} else {
			return -EINVAL;
		}
	}
	irq = i;
	printk("irq changed. irq == %d\n", irq);
		
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
	
	len=snprintf(tmp_buf, 16, "%d", irq);
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

// 用户写latence文件，以修改latence参数 
static ssize_t proc_latence_write(struct file *file,
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
		if ('0' <= (c = *it) && c <= '9') {
			i = i*10 + c - '0';
		} else {
			return -EINVAL;
		}
	}
	latence = i;
	printk("latence changed. latence == %d\n", latence);
		
	return size;
}

// 用户读latence文件，以获取latence的值 
static ssize_t proc_latence_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[16] = {0};
	int len = 0;
	
	len=snprintf(tmp_buf, 16, "%d", latence);
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

// 用户读process_info文件，以获取进程信息 
// TODO: 获取链表头指针head 
static ssize_t proc_process_info_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[1000] = "process info:\n";
	int len = 0;
	int i;
	struct process_info *pos;
	struct list_head *head;
			
	list_for_each_entry(pos, head, list){
		len = snprintf(tmp_buf, 1000, "%spid=%d, name is %s\n", tmp_buf, pos->pid, pos->comm);
		for (i = 0; i < pos->nr_entries; ++i) {
			len = snprintf(tmp_buf, 1000, "%s[<%p>] %pS\n", tmp_buf, (void*)pos->entries[i], (void*)pos->entries[i]);
        }
	}

	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

static struct file_operations s_st_overwrite_switch_fops = {
	.write = proc_overwrite_switch_write,
	.read = proc_overwrite_switch_read,
};

static struct file_operations enable_fops = {
	.write = proc_enable_write,
	.read = proc_enable_read,
};

static struct file_operations latence_fops = {
	.write = proc_latence_write,
	.read = proc_latence_read,
};

static struct file_operations irq_fops = {
	.write = proc_irq_write,
	.read = proc_irq_read,
};

static struct file_operations process_info_fops = {
	.read = proc_process_info_read,
};

static int __init start_module(void)
{
	struct proc_dir_entry *parent_dir;
	
    printk(KERN_ALERT "Module init.\n");
    printk("enable == %d\n", enable);
    printk("irq == %d\n", irq);
    printk("latence == %d\n", latence);
    
    my_cachep = kmem_cache_create("my_cache", sizeof(struct data), 0, SLAB_HWCACHE_ALIGN, NULL);
    if(my_cachep == NULL ){
    	printk("create my_cache failed!\n");
    	return -ENOMEM;
	}
	// 在/proc下创建 realtime_probe_tool目录 
	parent_dir = proc_mkdir("realtime_probe_tool", NULL);
	if(parent_dir == NULL){
    	printk("create parent_dir failed\n");
    	return -ENOMEM;
	}
	// 在/proc/realtime_probe_tool下创建4个文件 
    if(!proc_create("overwrite_disck", 0744, parent_dir, &s_st_overwrite_switch_fops)){
    	printk("create overwrite_disck failed\n");
    	return -ENOMEM;
	}
    if(!proc_create("enable", 0744, parent_dir, &enable_fops)) {
    	printk("create enable failed\n");
    	return -ENOMEM;
	}
    if(!proc_create("latence", 0744, parent_dir, &latence_fops)) {
    	printk("create latence failed\n");
    	return -ENOMEM;
	}
    if(!proc_create("irq", 0744, parent_dir, &irq_fops)) {
    	printk("create irq failed\n");
    	return -ENOMEM;
	}
	if(!proc_create("process_info", 0744, parent_dir, &process_info_fops)) {
    	printk("create process_info failed\n");
    	return -ENOMEM;
	}
    
	INIT_LIST_HEAD(&data1.list);
    return 0;
}

static void __exit exit_module(void)
{
	struct data *pos;
	struct data *n;
	// 回收链表 
	list_for_each_entry_safe(pos, n, &data1.list, list){
		list_del(&pos->list);
		kmem_cache_free(my_cachep, pos);
	}
	kmem_cache_destroy(my_cachep);
	remove_proc_subtree("realtime_probe_tool", NULL);
    printk(KERN_ALERT "Module exit.\n");
}
module_init(start_module);
module_exit(exit_module);