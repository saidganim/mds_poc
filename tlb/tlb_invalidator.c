#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "tlb.h"
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include <asm/paravirt.h>
#include <asm/pgtable_types.h>
#include <asm/page_types.h>
#include <asm/tlbflush.h>



static __inline void invlpg(void *addr)
{
    __asm __volatile("invlpg (%0)" : : "r" (addr) : "memory");
}

//  This is the simplest interface between
//  userspace and kernelspace, which is introduced by the misc device file.
//  Simply, write operation either clear access bit of the page address, which is passeds
//  within buf parameter. If NULL is passed, driver just flush all tlb levels.

MODULE_AUTHOR("Saidgani Musaev <TUD SE/chair>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Misc Device Driver for tlb_flush_all and clear_accessed_bit interfaces");

//void (*flush_tlb_all)(void) = NULL;

static void do_flush_tlb_all(void *info)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH_RECEIVED);
	__flush_tlb_all();
}


void flush_tlb_all(void)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
	on_each_cpu(do_flush_tlb_all, NULL, 1);
}
const int offsetg = 16;
volatile char* ptr = 0x0;
volatile char* ptrf = 0x0;

ssize_t __attribute((optimize("O1")))read_op(struct file* filep, char __user * buf, size_t len, loff_t *offset){
	int i;
	//memset(ptrf, (char)0xfb, 0x2000);
	//for( i = 0; i < 0x2000; ++i)
	ptr[offsetg] = 0xfb;
//	invlpg(ptr);
	//invlpg(ptr);
	//printk("charged SB with address %px\n", &ptr[offsetg]);
//	ptr[offsetg+1] = (char)0x0;
	//for( i = 0; i < 0x2000; ++i){
		//if(i == offsetg)
		//	continue;
	//	copy_to_user(&buf[i], &ptrf[i], 1);
	//}
//	copy_to_user(&buf[offsetg], &ptr[offsetg], 1);
	//invlpg(buf);
    	return 0;
}

ssize_t write_op(struct file* filep, const char __user * buf, size_t len, loff_t *offset){
    pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
    pte_t new_pte;
    unsigned long vaddr = (unsigned long)buf;
    if(!buf){
	flush_tlb_all();
        goto ret_;
    }
	pgd =  pgd_offset(current->mm, vaddr);// + pgd_index(vaddr);
	if (pgd_none(*pgd)) {
		BUG();
		return -EINVAL;
	}
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) {
		BUG();
		return -EINVAL;
	}
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) {
		BUG();
		return -EINVAL;
	}
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		BUG();
		return -EINVAL;
	}
	pte = pte_offset_kernel(pmd, vaddr);
    new_pte.pte = pte->pte & ~_PAGE_ACCESSED;
    set_pte_at(current->mm, vaddr, pte, new_pte);
ret_:
    return len;
}
int open_op(struct inode * inode, struct file *filep){
    try_module_get(THIS_MODULE);
    return 0;
};

int release(struct inode* inode, struct file* filep){
    module_put(THIS_MODULE);
    return 0;
}

struct file_operations my_dev_fops = {
    .owner = THIS_MODULE,
    .read = &read_op,
    .write = &write_op,
    .open = &open_op,
    .release = &release,
};

 
struct miscdevice my_dev = {
    .minor = MY_DEV_MINOR,
    .fops = &my_dev_fops,
    .name = "tlb_invalidator",
    .mode = 0666,
};


int __init my_dev_reg(void){
    int res = 0;
    //flush_tlb_all = (void*)kallsyms_lookup_name("flush_tlb_all");
    res = misc_register(&my_dev);
    ptrf = kmalloc(0x2000, GFP_KERNEL);
    ptr = (char*)((uint64_t)(&(ptrf[0x1000]) ) & ~0xFFF);
    printk("Address %llu : %llu\n", ptr, ptrf);
    printk("Address2 %px : %px\n", ptr, ptrf);
    printk("Address3 %px : %px\n", &ptr[offsetg], &ptrf[offsetg]);
    if(res)
        pr_err("Cannot misc_register\n");
    return res;
}

void __exit release_dev(void){
   //kfree(ptrf);
   misc_deregister(&my_dev);
}

module_init(my_dev_reg);
module_exit(release_dev);
