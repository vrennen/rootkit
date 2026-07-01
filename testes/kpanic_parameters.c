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
MODULE_INFO(difficulty, "VERY EASY");

static int value = 0;

module_param(value, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(value, "valor numerico secreto");

static int __init poc_init(void) {
    printk(KERN_INFO "[Rootkit] Modulo carregado na memoria.\n");

    if (value == 69) panic("FUNCIONOU CARAIO");
    else printk(KERN_INFO "[Rootkit] Carregado com valor %d.\n", value);

    return 0;
}

static void __exit poc_exit(void) {
    printk(KERN_INFO "[Rootkit] Modulo descarregado.\n");
}

module_init(poc_init);
module_exit(poc_exit);
