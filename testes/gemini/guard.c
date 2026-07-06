#include <asm-generic/errno.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Engenharia de Computacao");
MODULE_DESCRIPTION("PoC EDR: Intermediador Ativo (Proxy) via Ftrace IPModify");

#define TARGET_FILE "secreto.txt"
#define TARGET_FUNC "do_sys_openat2"

// -------------------------------------------------------------------
// 1. A FUNÇÃO ESCUDO
// Esta é a função fantasma. Ela tem a mesma assinatura da original,
// mas o único trabalho dela é dizer "Não" e devolver um erro.
// -------------------------------------------------------------------
asmlinkage long escudo_sys_openat2(int dfd, const char __user *filename, void *how)
{
    // EACCES = Erro 13 (Permission denied)
    return -EDEADLK; 
}

// -------------------------------------------------------------------
// 2. O HOOK DO FTRACE
// -------------------------------------------------------------------
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static void notrace handler_ftrace(unsigned long ip, unsigned long parent_ip, 
                                   struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    // API moderna para Kernel 7.0+
    const char __user *user_filename = (const char __user *)ftrace_regs_get_argument(fregs, 1);
    struct pt_regs *regs = ftrace_get_regs(fregs);
#else
static void notrace handler_ftrace(unsigned long ip, unsigned long parent_ip, 
                                   struct ftrace_ops *op, struct pt_regs *regs)
{
    if (!regs) return;
    const char __user *user_filename = (const char __user *)regs->si;
#endif

    char *filename;
    long copied;

    filename = kmalloc(256, GFP_KERNEL);
    if (!filename) return;

    copied = strncpy_from_user(filename, user_filename, 255);
    
    if (copied > 0) {
        filename[copied] = '\0';

        if (strstr(filename, TARGET_FILE) != NULL) {
            printk(KERN_ALERT "[EDR PROXY] Acesso bloqueado silenciosamente: %s\n", filename);
            
            // A MÁGICA DO SEQUESTRO ACONTECE AQUI:
            // Nós reescrevemos o Instruction Pointer da CPU.
            // O Ftrace vai pegar esse valor e forçar a CPU a pular para o nosso Escudo.
            regs->ip = (unsigned long)escudo_sys_openat2;
        }
        // Se NÃO for o arquivo alvo, nós não tocamos no regs->ip.
        // O Ftrace vai perceber que o IP está intacto e pulará para a função 
        // original do Kernel naturalmente. Fim da recursão!
    }
    
    kfree(filename);
}

// -------------------------------------------------------------------
// 3. REGISTRO COM IPMODIFY
// -------------------------------------------------------------------
static struct ftrace_ops my_ops = {
    .func = handler_ftrace,
    // SAVE_REGS: Necessário para acessar argumentos.
    // IPMODIFY: Habilita o superpoder de sequestrar o ponteiro de instrução!
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION,
};

static int __init proxy_init(void)
{
    int ret;

    ret = ftrace_set_filter(&my_ops, TARGET_FUNC, strlen(TARGET_FUNC), 0);
    if (ret) {
        printk(KERN_ERR "[EDR PROXY] Filtro falhou: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&my_ops);
    if (ret) {
        printk(KERN_ERR "[EDR PROXY] Registro falhou: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[EDR PROXY] Proxy Ativo! Protegendo %s.\n", TARGET_FILE);
    return 0;
}

static void __exit proxy_exit(void)
{
    unregister_ftrace_function(&my_ops);
    printk(KERN_INFO "[EDR PROXY] Proxy Desativado.\n");
}

module_init(proxy_init);
module_exit(proxy_exit);
