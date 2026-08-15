#include <stdio.h>
#include <string.h>

static const unsigned char expected[] = {
    0x01, 0x3C, 0x02, 0x74, 0x34, 0x15, 0x77, 0x3B,
    0x18, 0x7B, 0x2B, 0x34, 0x83, 0x70
};
static const unsigned char interleave[] = {
    0x3A, 0x3B, 0x71, 0x41, 0x20, 0x61, 0x45, 0x24,
    0x62, 0x53, 0x08, 0x5E, 0x14
};
static const unsigned char enc[] = {
    0x17, 0x34, 0x11, 0x68, 0x3B, 0x08, 0x73, 0x3A,
    0x1E, 0x74, 0x31, 0x0F, 0x15, 0x47, 0x6D, 0x11,
    0x36, 0x04, 0x2C, 0x28, 0x50, 0x4D, 0x78, 0x29,
    0x2F, 0x6E, 0x2F, 0x2F, 0x13, 0x7A, 0x44, 0x24
};
#define KEY_LEN 14
#define FLAG_LEN 32
#define CHECKSUM 0x19

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: %s <key>\n", argv[0]);
        return 1;
    }
    char *key = argv[1];
    if (strlen(key) != KEY_LEN)
        goto fail;

    for (int i = 0; i < KEY_LEN; i++) {
        if (((key[i] ^ 0x42) + i) != expected[i])
            goto fail;
    }

    unsigned char cksum = 0;
    for (int i = 0; i < KEY_LEN; i++) {
        cksum ^= (unsigned char)(key[i] ^ (i * 7 + 3));
    }
    if (cksum != CHECKSUM)
        goto fail;

    for (int i = 0; i < KEY_LEN - 1; i++) {
        if ((unsigned char)(key[i] ^ key[i + 1]) != interleave[i])
            goto fail;
    }

    volatile unsigned char xk = 0x37;
    char flag[FLAG_LEN + 1];
    for (int i = 0; i < FLAG_LEN; i++)
        flag[i] = enc[i] ^ key[i % KEY_LEN] ^ (unsigned char)(i * 3) ^ xk;
    flag[FLAG_LEN] = '\0';
    printf("yes! flag: %s\n", flag);
    return 0;

fail:
    puts("nope");
    return 1;
}
