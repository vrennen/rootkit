#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Breno Nascimento");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");

// static asmlinkage long (*orig_mkdir)(const struct pt_regs *);

// asmlinkage int hook_mkdir(const struct pt_regs *regs)
// {
//     char __user *pathname = (char *)regs->di;
//     char dir_name[NAME_MAX] = {0};
//
//     long error = strncpy_from_user(dir_name, pathname, NAME_MAX);
//
//     if (error > 0)
//         printk(KERN_INFO "rootkit: trying to create directory with name: %s\n", dir_name);
//
//     orig_mkdir(regs);
//     return 0;
// }

unsigned long* lookup_kallsyms_lookup_name(void) {
    struct kprobe kp;
    unsigned long addr;

    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kp) < 0) {
        return 0;
    }
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return (unsigned long*)addr;
}


static int __init rootkit_init(void) {
    unsigned long addr;
    // addr = kallsyms_lookup_name("vfs_mkdir");
    unsigned long (*kln)(const char*) = (unsigned long(*)(const char*))lookup_kallsyms_lookup_name();
    addr = kln("vfs_mkdir");
    kln("vfs_mkdir");
    if (!addr) {
        printk(KERN_ERR "rootkit: simbolo nao resolvido\n");
        return -ENOENT;
    }
    printk(KERN_INFO "Endereco de vfs_mkdir: %lx", addr);

    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "rootkit: descarregado\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
