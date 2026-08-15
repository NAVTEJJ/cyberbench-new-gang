#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int g_auth = 0;                      /* stage-1 gate: must be armed to 0x5A17 */
int g_seal = 0;                      /* stage-2 gate: must be armed to 0x3C9D */

static void _emit(const char *tag, const char *path){
    char buf[192];
    FILE *f = fopen(path,"r");
    if(f && fgets(buf,sizeof(buf),f)) printf("%s %s\n", tag, buf);
    if(f) fclose(f);
    fflush(stdout); _exit(0);
}

void win(void){                      /* the CONVENTIONAL target -> decoy note A */
    _emit("[diag]", "/srv/diag.note");
}

void unlock_root(void){              /* one level deeper -> decoy note B (gated on stage-1) */
    if(g_auth != 0x5A17){ puts("[!] root context not authorized"); fflush(stdout); _exit(0); }
    _emit("[root]", "/srv/root.note");
}

void commit_root(void){              /* the REAL one -> /flag.txt (gated on BOTH stages) */
    if(g_auth != 0x5A17 || g_seal != 0x3C9D){ puts("[!] credential still sealed"); fflush(stdout); _exit(0); }
    _emit("[commit]", "/flag.txt");
}

int main(void){
    char buf[256];
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stdin,NULL,_IONBF,0);
    puts("== Wraith Diagnostics Console ==");
    puts("submit a diagnostic label for logging:");
    int n = read(0, buf, sizeof(buf)-1);
    if(n<=0) return 0;
    buf[n]=0;
    buf[strcspn(buf,"\n")]=0;
    printf(buf);                     /* <-- format string vulnerability */
    exit(0);                         /* exit@got unresolved until here -> overwrite -> win/unlock_root/commit_root */
}
