#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define GUARD 0x5a17c0d3cafef00dULL
#define MAGIC 0x434f44455857494eULL
#define OPEN_TOKEN "VAULT_OK:guarded-vector-8406"

struct frame {
    char name[72];
    uint64_t guard;
    uint64_t magic;
};

int main(void) {
    struct frame f;
    memset(&f, 0, sizeof(f));
    f.guard = GUARD;
    f.magic = 0;
    puts("vault input:");
    fflush(stdout);
    read(STDIN_FILENO, f.name, 192);
    if (f.guard != GUARD) {
        puts("guard changed");
        return 1;
    }
    if (f.magic == MAGIC) {
        puts(OPEN_TOKEN);
        return 0;
    }
    puts("stored");
    return 0;
}
