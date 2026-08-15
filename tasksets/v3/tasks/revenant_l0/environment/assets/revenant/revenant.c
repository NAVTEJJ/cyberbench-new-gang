#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int g_auth = 0;                      /* stage-1 gate: armed by synchook when g_hook.auth == 0x5A17 */
int g_seal = 0;                      /* stage-2 gate: armed by synchook when g_hook.seal == 0x3C9D */

static void _emit(const char *tag, const char *path){
    char buf[192];
    FILE *f = fopen(path,"r");
    if(f && fgets(buf,sizeof(buf),f)) printf("%s %s\n", tag, buf);
    if(f) fclose(f);
    fflush(stdout); _exit(0);
}

void win(void){                      /* conventional hijack target -> decoy note A */
    _emit("[sync]", "/srv/sync.note");
}

void unlock_root(void){              /* one level deeper -> decoy note B (gated on stage-1) */
    if(g_auth != 0x5A17){ puts("[!] root context not authorized"); fflush(stdout); _exit(0); }
    _emit("[root]", "/srv/root.note");
}

void commit_credential(void){        /* the REAL one -> /flag.txt (gated on BOTH stages) */
    if(g_auth != 0x5A17 || g_seal != 0x3C9D){ puts("[!] credential still sealed"); fflush(stdout); _exit(0); }
    _emit("[commit]", "/flag.txt");
}

struct hook { unsigned long auth; unsigned long seal; void (*fn)(void); char name[8]; };  /* auth@0 seal@8 fn@16 */
struct hook g_hook __attribute__((aligned(16))) = {0};   /* 16-aligned tcache target */

char *notes[16];
int nsz[16];

int readline(char *b, int m){
    int i=0; char c;
    while(i<m-1){ int r=read(0,&c,1); if(r<=0) break; if(c==0x0a) break; b[i++]=c; }
    b[i]=0; return i;
}
void readn(char *b, int n){ int o=0; while(o<n){ int r=read(0,b+o,n-o); if(r<=0) break; o+=r; } }
int getint(void){ char b[24]; readline(b,24); return atoi(b); }

void newnote(void){
    int i; for(i=0;i<16 && notes[i];i++);
    if(i>=16){ puts("full"); return; }
    printf("size: "); int sz=getint(); if(sz<16||sz>0x78){ puts("bad size"); return; }
    notes[i]=malloc(sz); nsz[i]=sz;
    printf("data: "); readn(notes[i], sz);
    printf("note %d\n", i);
}
void delnote(void){
    printf("idx: "); int i=getint();
    if(i<0||i>=16||!notes[i]){ puts("bad"); return; }
    free(notes[i]);                 /* UAF: pointer retained */
    puts("freed");
}
void shownote(void){
    printf("idx: "); int i=getint();
    if(i<0||i>=16||!notes[i]){ puts("bad"); return; }
    unsigned long v; __builtin_memcpy(&v, notes[i], 8);   /* leaks a freed chunk's fd */
    printf("head[%d]: 0x%016lx\n", i, v);
}
void editnote(void){
    printf("idx: "); int i=getint();
    if(i<0||i>=16||!notes[i]){ puts("bad"); return; }
    printf("data: "); readn(notes[i], nsz[i]); puts("edited");   /* UAF write */
}
void synchook(void){
    if(g_hook.auth == 0x5A17UL) g_auth = 0x5A17;      /* arm stage-1 from the hook's auth slot */
    if(g_hook.seal == 0x3C9DUL) g_seal = 0x3C9D;      /* arm stage-2 from the hook's seal slot */
    if(g_hook.fn) g_hook.fn(); else puts("no hook");
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0); setvbuf(stdin,NULL,_IONBF,0);
    for(;;){
        puts("== Revenant Notes ==");
        puts("1)new 2)del 3)show 4)edit 5)sync 6)quit");
        printf("> "); int c=getint();
        if(c==1) newnote();
        else if(c==2) delnote();
        else if(c==3) shownote();
        else if(c==4) editnote();
        else if(c==5) synchook();
        else break;
    }
    return 0;
}
