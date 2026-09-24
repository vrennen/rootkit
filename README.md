# Rootkit: Kernel-Level File Hiding and Syscall intercepter

Este repositório contém a prova de conceito de um driver de kernel que atua como um [Rootkit](https://pt.wikipedia.org/wiki/Rootkit), interceptando as chamadas de sistema (syscalls) para ocultar arquivos, pastas e até processos do espaço do usuário.

>  **AVISO LEGAL E TERMO DE RESPONSABILIDADE** 
> 
> **Este projeto foi desenvolvido ESTRITAMENTE para propósitos acadêmicos e educacionais** no escopo da disciplina de Interface Hardware/Software.
> 
> * **NÃO** execute este código em sua máquina física principal ou em servidores de produção.
> * Execute **APENAS** em Máquinas Virtuais (VMs) isoladas ou em ambientes onde você possui autorização explícita para testes de kernel.
> * O autor **NÃO se responsabiliza** por Kernel Panics, corrupção de dados, perda de acesso, ex-namorados stalkers ou quaisquer danos diretos ou indiretos causados pelo uso ou modificação deste código. O uso é de sua inteira responsabilidade.

---

## Funcionamento: O Bypass de Syscalls

Em vez de utilizar técnicas legadas e instáveis de *hooking* (como a sobrescrita direta da `sys_call_table`), este projeto utiliza a infraestrutura moderna do **Ftrace** com a flag `IPMODIFY` para sequestrar o fluxo de execução de forma nativa e segura.
Em vez de utilizar técnicas de hooking instáveis, como a sobrescrita direta da `sys_call_table`, este projeto usa a infraestrutura moderna do Ftrace com a flag `IPMODIFY` para desviar o fluxo de execução da syscall para uma função alternativa.

O mecanismo de bypass funciona da seguinte maneira:
1. O Ftrace é configurado para monitorar a chamada de sistema interna do kernel desejada (e.g. `sys_getdents64` para a chamada de busca de arquivos de programas como `ls`)
2. Quando um processo em *User Space* tentar abrir um arquivo, o kernel desvia a execução para nossa função *hook*.
3. A função de hook lê os registradores salvos na pilha (`struct ftrace_regs`) para extrair os argumentos da função original e alterar o *Instruction Pointer* para nossa função modificada.
4. Após verificar ou modificar o valor dos registradores, podemos usar a função de kernel `kallsyms_lookup_name()` para pegar o endereço da função original e assim devolver o fluxo de execução para ela como se nunca tivesse ocorrido alguma modificação.
---

## Como Reproduzir

Este projeto foi testado em Arch Linux com kernel 7.0.14-arch1-1. Pode não funcionar corretamente em outro sistema operacional ou em uma versão do kernel diferente.

**1. Clone este repositório**

**2. Compile o Módulo do Kernel:**

```bash
make

```

*(Isso irá gerar o arquivo `rootkit.ko` no diretório).*

**3. Em outro terminal, abra o monitor de logs do kernel:**

```bash
sudo dmesg -w

```

**4. Instale o Módulo (Ative o Escudo):**

```bash
sudo insmod rootkit.ko

```

Verifique no `dmesg` se a mensagem de módulo carregado apareceu.

**5. Teste o Bloqueio:**
Crie um arquivo `arquivo_secreto` e tente encontrar ele com o ls:

```bash
touch arquivo_secreto
ls

```

**Resultado Esperado:** No terminal do `dmesg`, você verá o alerta em vermelho do módulo logando a interceptação do arquivo e o `ls` não vai mostrar o arquivo.

**6. Desinstale o Módulo (Limpeza):**
Para desativar o escudo e remover o módulo do Kernel:

```bash
sudo rmmod rootkit
make clean
```

---

## Funcionalidades
Para mudar o nome do arquivo ou pasta a esconder, é necessário mudar ROOTKIT_FILE no código e recompilar o mesmo.

Além de ocultar arquivos, é possível ocultar também processos em execução (pois programas como `ps` apenas listam o conteúdo da pasta virtual `/proc`). Basta carregar o módulo com o parâmetro `pid="PID_do_processo"`.

O módulo também intercepta a syscall `sys_kill` para implementar sinais novos e comportamentos distintos em espaço de kernel. Usando sinal 42 (basta executar `kill -42 1` no terminal. O PID é necessário pra chamada, mas está sendo ignorado), o módulo alterna entre ocultar sua existência do `lsmod` e do sistema ou mostrar de volta. Com o sinal 64, o sistema dá um Kernel Panic.
