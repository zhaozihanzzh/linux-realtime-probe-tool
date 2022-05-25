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

struct kmem_cache *my_cachep = NULL;

static int enable = 0;
module_param(enable, int, 0644);
MODULE_PARM_DESC(enable, "Module on/off");
static int irq = 0;
module_param(irq, int, 0644);
MODULE_PARM_DESC(irq, "Interrupt number");
static int latence = 0;
module_param(latence, int, 0644);
MODULE_PARM_DESC(latence, "Max lasting time(us) when interrupt is closed that we can tolerate");

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

static ssize_t proc_overwrite_switch_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[16] = {0};
	int len;
	struct data *first;
	
	if(list_size == 0){
		len=snprintf(tmp_buf, 16, "%s", "Empty.\n");
		return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
	}		
	--list_size;
	first = list_first_entry(&data1.list, struct data, list);
	list_del(&first->list);
	printk("GHTEST: overwrite disck == %s\n", first->number);
	len=snprintf(tmp_buf, 16, "%s", first->number);
	kmem_cache_free(my_cachep, first);
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

static struct file_operations s_st_overwrite_switch_fops = {
	.write = proc_overwrite_switch_write,
	.read = proc_overwrite_switch_read,
};

static int __init start_module(void)
{
	struct proc_dir_entry *s_pst_proc_overwrite_flag = NULL;
	
    printk(KERN_ALERT "Module init.\n");
    printk("enable == %d\n", enable);
    printk("irq == %d\n", irq);
    printk("latence == %d\n", latence);
    
    my_cachep = kmem_cache_create("my_cache", sizeof(struct data), 0, SLAB_HWCACHE_ALIGN, NULL);
    if(my_cachep == NULL ){
    	printk("create my_cache failed!\n");
    	return -ENOMEM;
	}
    s_pst_proc_overwrite_flag = proc_create("overwrite_disck", 0744, NULL, &s_st_overwrite_switch_fops);
    if(s_pst_proc_overwrite_flag == NULL){
    	printk("create overwrite_disck failed\n");
    	return -ENOMEM;
	}
	INIT_LIST_HEAD(&data1.list);
    return 0;
}
static void __exit exit_module(void)
{
	struct data *pos;
	struct data *n;
	list_for_each_entry_safe(pos, n, &data1.list, list){
		list_del(&pos->list);
		kmem_cache_free(my_cachep, pos);
	}
	kmem_cache_destroy(my_cachep);
	remove_proc_entry("overwrite_disck", NULL);
    printk(KERN_ALERT "Module exit.\n");
}
module_init(start_module);
module_exit(exit_module);