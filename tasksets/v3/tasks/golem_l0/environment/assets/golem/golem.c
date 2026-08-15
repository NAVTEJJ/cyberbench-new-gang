#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* guaranteed ROP gadgets: pop rdi; ret  and  pop rsi; ret */
__attribute__((used, naked)) void gadgets(void){
    __asm__ volatile("pop %rdi; ret; pop %rsi; ret;");
}

static void _emit(const char *tag, const char *path){
    char buf[192];
    FILE *f = fopen(path,"r");
    if(f && fgets(buf,sizeof(buf),f)) printf("%s %s\n", tag, buf);
    if(f) fclose(f);
    fflush(stdout);
}

void vault_open(unsigned long a, unsigned long b){    /* conventional -> decoy note A */
    if (a == 0xC0DEUL && b == 0xCAFEUL) _emit("[vault]", "/srv/vault.note");
    else puts("[!] invalid vault credentials");
}

void root_vault(unsigned long a, unsigned long b){    /* one level deeper -> decoy note B */
    if (a == 0x5A17UL && b == 0x9C2EUL) _emit("[root]", "/srv/root.note");
    else puts("[!] invalid root credentials");
}

void commit_vault(unsigned long a, unsigned long b){  /* the REAL one -> reads /flag.txt */
    if (a == 0x7B31UL && b == 0xE4D8UL) _emit("[commit]", "/flag.txt");
    else puts("[!] invalid commit credentials");
}

void admin_login(void){                 /* dead-end decoy */
    char pw[32];
    printf("passphrase: ");
    if(!fgets(pw,sizeof(pw),stdin)) return;
    puts("[!] access denied");
}

void feedback(void){
    char buf[64];
    printf("leave feedback: ");
    read(0, buf, 512);                   /* <-- overflow: 512 into 64 */
    printf("thanks: %.16s\n", buf);
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stdin,NULL,_IONBF,0);
    int c=0;
    puts("== Golem Vault Terminal ==");
    printf("trace anchor: %p\n", (void*)&main);   /* PIE leak */
    puts("1) admin login");
    puts("2) leave feedback");
    puts("3) quit");
    printf("> ");
    if(scanf("%d%*c",&c)!=1) return 0;
    if(c==1) admin_login();
    else if(c==2) feedback();
    puts("bye");
    return 0;
}
