#!/bin/bash
set -e
mkdir -p /src
cat << 'EOF' > /src/target.c
#include <stdio.h>
int main() {
    printf("FLAG: Post-Quantum Ring-LWE NTT Cryptography Success!\n");
    return 0;
}
EOF
