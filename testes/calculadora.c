#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    FILE* crash;
    printf("Calculadora ultra moderna\n");
    printf("Digite sua expressão: ");
    scanf("%s");
    printf("Processando... ");
    fflush(stdout);
    sleep(2);
    printf("Erro!");
    fflush(stdout);
    sleep(1);
    crash = fopen("temp350", "w");
    return 0;
}
