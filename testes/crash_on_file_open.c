#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Breno Nascimento");
MODULE_DESCRIPTION("Prova de conceito de rootkit");

#define TARGET_FILE "temp350"

static struct kprobe kp = {
    .symbol_name = "do_sys_openat2",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    char *filename;
    long copied;

    const char __user *user_filename = (const char __user *)regs->si;

    filename = kmalloc(256, GFP_KERNEL);
    if (!filename) return 0;

    copied = strncpy_from_user(filename, user_filename, 255);

    if (copied > 0) {
        filename[copied] = '\0';

        if (strstr(filename, TARGET_FILE) != NULL) {
            printk(KERN_ALERT "[GUARD] ALERTA CRITICO DE SEGURANCA!!!\n");
            printk(KERN_ALERT "[GUARD] Processo ofensor: '%s' (PID: %d)\n", current->comm, current->pid);
            printk(KERN_ALERT "[GUARD] Tentativa de acessar o arquivo: %s\n", filename);
            printk(KERN_ALERT "[GUARD] Neutralizando processo no Ring 0...\n");

            // send_sig(SIGKILL, current, 0);
            panic("Alvo neutralizado");
        }
    }

    kfree(filename);

    return 0;
}

static int __init inicializar(void) {
    int ret;
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);

    if (ret < 0) {
        printk(KERN_ERR "[GUARD] Falha ao registrar kprobe, erro %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[GUARD] Protecao ativa. Monitorando acessos a '%s'...\n", TARGET_FILE);
    return 0;
}

static void __exit saida(void) {
    unregister_kprobe(&kp);
    
    printk(KERN_INFO "[GUARD] Protecao desativada. Kprobe removido.\n");
}

module_init(inicializar);
module_exit(saida);
