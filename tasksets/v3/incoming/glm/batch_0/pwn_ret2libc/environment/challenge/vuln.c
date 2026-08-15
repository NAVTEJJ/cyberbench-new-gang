#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln() {
    char buf[64];
    puts("Enter your name: ");
    read(STDIN_FILENO, buf, 256);
    printf(buf);  // format string vuln
    printf("\n");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
