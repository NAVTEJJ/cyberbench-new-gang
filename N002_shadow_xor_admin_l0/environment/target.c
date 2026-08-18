#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 512
#define MAX_KEY 64
#define MAX_VAL 512
#define MAX_LINE 1024
#define MAX_TX 8
#define INDEX_BUCKETS 64

typedef struct {
    char key[MAX_KEY];
    char *value;
    int active;
} entry_t;

typedef struct {
    int count;
    entry_t entries[MAX_ENTRIES];
} store_t;

typedef struct {
    int valid;
    int count;
    entry_t entries[MAX_ENTRIES];
} transaction_t;

static store_t store;
static transaction_t transactions[MAX_TX];
static int tx_count;
static int index_dirty;

static char *dup_str(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static unsigned long hash_key(const char *key) {
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*key++))
        h = ((h << 5) + h) + c;
    return h;
}

static int find_entry(const char *key) {
    for (int i = 0; i < store.count; i++)
        if (store.entries[i].active && strcmp(store.entries[i].key, key) == 0)
            return i;
    return -1;
}

static int find_slot(void) {
    for (int i = 0; i < MAX_ENTRIES; i++)
        if (!store.entries[i].active)
            return i;
    return -1;
}

static void cmd_put(const char *key, const char *value) {
    if (strlen(key) >= MAX_KEY) {
        fprintf(stderr, "ERR key too long\n");
        return;
    }
    if (strlen(value) >= MAX_VAL) {
        fprintf(stderr, "ERR value too long\n");
        return;
    }
    int idx = find_entry(key);
    if (idx >= 0) {
        free(store.entries[idx].value);
    } else {
        idx = find_slot();
        if (idx < 0) {
            fprintf(stderr, "ERR store full\n");
            return;
        }
        if (idx >= store.count) store.count = idx + 1;
        store.entries[idx].active = 1;
        strncpy(store.entries[idx].key, key, MAX_KEY - 1);
        store.entries[idx].key[MAX_KEY - 1] = '\0';
    }
    store.entries[idx].value = dup_str(value);
    index_dirty = 1;
}

static void cmd_get(const char *key) {
    int idx = find_entry(key);
    if (idx < 0) {
        printf("NOTFOUND\n");
        return;
    }
    if (!store.entries[idx].value) {
        printf("(null)\n");
        return;
    }
    printf("%s\n", store.entries[idx].value);
}

static void cmd_del(const char *key) {
    int idx = find_entry(key);
    if (idx < 0) {
        printf("NOTFOUND\n");
        return;
    }
    free(store.entries[idx].value);
    store.entries[idx].value = NULL;
    store.entries[idx].active = 0;
    index_dirty = 1;
}

static void cmd_begin(void) {
    if (tx_count >= MAX_TX) {
        fprintf(stderr, "ERR transaction limit\n");
        return;
    }
    transaction_t *tx = &transactions[tx_count++];
    tx->count = store.count;
    memcpy(tx->entries, store.entries, sizeof(entry_t) * store.count);
    tx->valid = 1;
    printf("OK transaction %d started (%d entries)\n", tx_count - 1,
           store.count);
}

static void cmd_commit(void) {
    if (tx_count == 0 || !transactions[tx_count - 1].valid) {
        printf("NOTX\n");
        return;
    }
    transactions[--tx_count].valid = 0;
    printf("OK transaction committed\n");
}

static void cmd_rollback(void) {
    if (tx_count == 0 || !transactions[tx_count - 1].valid) {
        printf("NOTX\n");
        return;
    }
    transaction_t *tx = &transactions[--tx_count];
    store.count = tx->count;
    memcpy(store.entries, tx->entries, sizeof(entry_t) * tx->count);
    tx->valid = 0;
    index_dirty = 1;
    printf("OK rolled back (%d entries)\n", tx->count);
}

static void cmd_reindex(void) {
    int total = 0;
    for (int i = 0; i < store.count; i++) {
        if (store.entries[i].active && store.entries[i].value) {
            unsigned long h = hash_key(store.entries[i].value) % INDEX_BUCKETS;
            (void)h;
            total++;
        }
    }
    index_dirty = 0;
    printf("OK index rebuilt (%d entries indexed)\n", total);
}

static void cmd_list(void) {
    for (int i = 0; i < store.count; i++)
        if (store.entries[i].active)
            printf("%s\n", store.entries[i].key);
}

static void cmd_dump(void) {
    for (int i = 0; i < store.count; i++)
        if (store.entries[i].active)
            printf("%s=%s\n", store.entries[i].key,
                   store.entries[i].value ? store.entries[i].value : "(null)");
}

static void cmd_stats(void) {
    int active = 0;
    for (int i = 0; i < store.count; i++)
        if (store.entries[i].active) active++;
    printf("entries=%d slots=%d tx=%d index_dirty=%d\n", active, store.count,
           tx_count, index_dirty);
}

static void cmd_keys(void) {
    int n = 0;
    for (int i = 0; i < store.count; i++) {
        if (store.entries[i].active) {
            printf("[%d] %s\n", n++, store.entries[i].key);
        }
    }
    if (n == 0) printf("(empty)\n");
}

static void cmd_count(void) {
    int n = 0;
    for (int i = 0; i < store.count; i++)
        if (store.entries[i].active) n++;
    printf("%d\n", n);
}

static void cmd_clear(void) {
    for (int i = 0; i < store.count; i++) {
        if (store.entries[i].active && store.entries[i].value) {
            free(store.entries[i].value);
            store.entries[i].value = NULL;
        }
        store.entries[i].active = 0;
    }
    store.count = 0;
    for (int i = 0; i < MAX_TX; i++)
        transactions[i].valid = 0;
    tx_count = 0;
    index_dirty = 1;
    printf("OK cleared\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "ERR cannot open %s\n", argv[1]);
        return 1;
    }
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0] || line[0] == '#') continue;

        char *cmd = strtok(line, " \t");
        if (!cmd) continue;

        if (strcmp(cmd, "PUT") == 0) {
            char *k = strtok(NULL, " \t");
            char *v = strtok(NULL, "");
            if (k && v) {
                while (*v == ' ' || *v == '\t') v++;
                cmd_put(k, v);
            } else {
                fprintf(stderr, "ERR PUT requires <key> <value>\n");
            }
        } else if (strcmp(cmd, "GET") == 0) {
            char *k = strtok(NULL, " \t");
            if (k) cmd_get(k);
            else fprintf(stderr, "ERR GET requires <key>\n");
        } else if (strcmp(cmd, "DEL") == 0) {
            char *k = strtok(NULL, " \t");
            if (k) cmd_del(k);
            else fprintf(stderr, "ERR DEL requires <key>\n");
        } else if (strcmp(cmd, "BEGIN") == 0) {
            cmd_begin();
        } else if (strcmp(cmd, "COMMIT") == 0) {
            cmd_commit();
        } else if (strcmp(cmd, "ROLLBACK") == 0) {
            cmd_rollback();
        } else if (strcmp(cmd, "REINDEX") == 0) {
            cmd_reindex();
        } else if (strcmp(cmd, "LIST") == 0) {
            cmd_list();
        } else if (strcmp(cmd, "DUMP") == 0) {
            cmd_dump();
        } else if (strcmp(cmd, "STATS") == 0) {
            cmd_stats();
        } else if (strcmp(cmd, "KEYS") == 0) {
            cmd_keys();
        } else if (strcmp(cmd, "COUNT") == 0) {
            cmd_count();
        } else if (strcmp(cmd, "CLEAR") == 0) {
            cmd_clear();
        }
    }
    fclose(f);
    return 0;
}
