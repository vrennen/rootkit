#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void handle_signal(int signum) {
    printf("Sinal recebido: %d\n", signum);
}

int main() {
    signal(SIGINT, handle_signal);
    kill(1, 64);
    signal(64, handle_signal);
    do {} while(9);
    return 0;
}
