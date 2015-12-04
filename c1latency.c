#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/ctype.h>
#include <linux/syscore_ops.h>
#include <trace/events/sched.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/mwait.h>

#define C1LATENCY_LOOP 9901

unsigned long *c1_tsc;

static unsigned long __inline__ use_rdtscp(void)
{
  unsigned int tickl, tickh;
  __asm__ __volatile__("rdtscp":"=a"(tickl),"=d"(tickh)::"%ecx");
  return ((unsigned long)tickh << 32)|tickl;
}


static long c1latency_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{

  c1_tsc[1] = use_rdtscp();
  __monitor((void *)c1_tsc, 0, 0);
  __sti_mwait(0,0);
  c1_tsc[2] = use_rdtscp();
  //  printk(KERN_INFO "write to %p(%lx),%p(%lx)\n",&(c1_tsc[0]),__pa(&(c1_tsc[0])), &(c1_tsc[1]), __pa(&(c1_tsc[1])));
  //  printk(KERN_INFO "%lx,%lx\n", c1_tsc[0], c1_tsc[1]);
  return 0;
}

static const struct file_operations c1latency_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = c1latency_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice c1latency_miscdev = {
  MISC_DYNAMIC_MINOR,
  "c1latency",
  &c1latency_fops
};


static int c1latency_init(void)
{
  int err;
  printk(KERN_INFO "Init the miscdev\n");
  c1_tsc = (unsigned long *)__get_free_page(GFP_KERNEL|__GFP_ZERO);
  if (!c1_tsc){
    pr_err("can't alloc 4K buffer\n");
    return -ENOMEM;
  }
  err = misc_register(&c1latency_miscdev);
  if (err < 0) {
    pr_err("Cannot register c1latency device\n");
    return err;
  }
  printk(KERN_INFO "c1latency virt:%p phy:%lx\n", c1_tsc, __pa(c1_tsc));
  return 0;
}




static void c1latency_exit(void)
{
  misc_deregister(&c1latency_miscdev);
  if (c1_tsc != NULL)
    free_page((unsigned long)c1_tsc);
}

module_init(c1latency_init);
module_exit(c1latency_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Xi Yang");
