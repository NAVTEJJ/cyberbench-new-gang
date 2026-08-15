bits 16

_start:
    mov ax, 0
    mov es, ax
    mov bx, 0x1000

    mov cx, 2
    mov ax, 0x202
    dec ax
    xor dh, dh
    mov dl, 0x80
    int 0x13

    mov dx, 0x3f8
loop:
    mov al, [bx]
    out dx, al
    inc bx
    jmp loop
