#include <linux/module.h>
#include<linux/string.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include<linux/uaccess.h>
#include<linux/list.h>
#include<linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QunChuWoLao");

struct data{
	struct list_head list;
	char number[16];
};
struct data data1;
int overwrite_disck;

static ssize_t proc_overwrite_switch_write(struct file *file,
		const char __user *buf,
		size_t size,
		loff_t *offset);
		
static ssize_t proc_overwrite_switch_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos);

static struct file_operations s_st_overwrite_switch_fops = {
	.write = proc_overwrite_switch_write,
	.read = proc_overwrite_switch_read,
};

static ssize_t proc_overwrite_switch_write(struct file *file,
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
		
//	if(strcmp(tmp, "1") && strcmp(tmp, "0"))
//		return -EINVAL;
		
	struct data *p = kmalloc(sizeof(struct data), GFP_KERNEL);
	strcpy(p->number, tmp);
	list_add(&p->list, &data1.list);
		
//	overwrite_disck = tmp[0] - '0';
//	printk("GHTEST: overwrite disck == %d\n", overwrite_disck);
	return size;
}

static ssize_t proc_overwrite_switch_read(struct file *file,
		char __user *buf,
		size_t size,
		loff_t *ppos)
{
	char tmp_buf[16] = {0};
	int len;
	
	struct data *pos;
//	list_for_each_entry(pos, &data1.list, list){
//		//pos->number;
//	}
	struct data *first;
	first = list_first_entry(&data1.list, struct data, list);
	list_del(&first->list);
	printk("GHTEST: overwrite disck == %s\n", first->number);
	len=snprintf(tmp_buf, 16, "%s", first->number);
//	kfree(first);
	return simple_read_from_buffer(buf, size, ppos, tmp_buf, len);
}

static int __init start_module(void)
{
    printk(KERN_ALERT "Module init.\n");
    struct proc_dir_entry *s_pst_proc_overwrite_flag = NULL;
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
	remove_proc_entry("overwrite_disck", NULL);
    printk(KERN_ALERT "Module exit.\n");
}
module_init(start_module);
module_exit(exit_module);
