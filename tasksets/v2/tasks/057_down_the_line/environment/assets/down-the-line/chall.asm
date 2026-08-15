bits 16
org 0x7c00

%DEFINE COM1            0x3f8
%DEFINE COM2            0x2f8
%DEFINE COM3            0x3e8
%DEFINE COM4            0x2e8
%DEFINE COM4LSR         0x2ed

%DEFINE STACK           0x9000 

%DEFINE N               8
%DEFINE CACHE_SEG       0xffff
%DEFINE CACHE_OFF       0x10
%DEFINE UNINITIALIZED   0


_start:
    mov sp, STACK

.main:
    mov ax, CHOICE_PROMPT
    call interact

    cmp ax, 1
    je .alloc
    cmp ax, 2
    je .edit
    cmp ax, 3
    je .read
    jmp .main


.alloc:
    cmp byte [INDEX], N
    je _end

    mov ax, SIZE_PROMPT
    call interact
    
    push ax
    call save_ptr  
    pop ax  
    call save_size

    inc byte [INDEX]
    jmp .main

.edit:
    mov ax, INDEX_PROMPT
    call interact
    cmp ax, [INDEX]
    jae _end
    mov [BUFF], ax

    mov ax, DATA_PROMPT
    call puts

    mov ax, [BUFF]
    mov bx, [SIZES]
    call read_array
    push ax

    mov ax, [BUFF]
    mov bx, [PTRS]
    call read_array

    mov es, ax
    pop cx
    shl cx, 4

    xor di, di
.edit_loop:
    cmp cx, di
    je .main
    call getc
    mov [es:di], al
    inc di
    jmp .edit_loop

.read:
    mov ax, INDEX_PROMPT
    call interact
    cmp ax, [INDEX]
    jae _end
    mov [BUFF], ax

    mov ax, PORT_PROMPT
    call interact

    cmp ax, 4
    ja _end

    cmp ax, 1
    je .com1
    cmp ax, 2
    je .com2
    cmp ax, 3
    je .com3
    cmp ax, 4
    je .com4
    ; fallthrough, ax == 0

.cache:
    mov ax, CACHE_SEG
    mov es, ax
    mov di, CACHE_OFF
    mov dx, [es:di]
    cmp dx, UNINITIALIZED
    je _end

    jmp .print_data
.com1:
    mov dx, COM1
    jmp .print_data
.com2:
    mov dx, COM2
    jmp .print_data
.com3:
    mov dx, COM3
    jmp .print_data
.com4:
    mov dx, COM4
    ; fallthrough

.print_data:
    mov bx, CACHE_SEG
    mov es, bx
    mov di, CACHE_OFF
    mov [es:di], dx

    mov ax, [BUFF]
    mov bx, [SIZES]
    call read_array
    push ax

    mov ax, [BUFF]
    mov bx, [PTRS]
    call read_array

    mov es, ax
    pop cx
    shl cx, 4

    xor di, di
.print_loop:
    cmp cx, di
    je .main
    mov al, [es:di]
    out dx, al
    inc di
    jmp .print_loop


_end:
    jmp _end

; ------------------------------------

write_array: ; write_array(index, arr, val)
    mov es, bx
    shl ax, 1
    mov di, ax
    mov [es:di], cx
    ret

read_array: ; word read_array(index, arr)
    mov es, bx
    shl ax, 1
    mov di, ax
    mov ax, [es:di]
    ret

; ------------------------------------

get_chunk: ; void* get_chunk(size)
    mov bx, [HEAP]
    push bx

    add bx, ax
    jc _end
    mov [HEAP], bx

    pop ax
    ret

save_ptr: ; save_ptr(size)
    push ax

    cmp word [PTRS], 0
    jne .skip_ptr
  
    mov ax, 1
    call get_chunk
    mov [PTRS], ax
.skip_ptr: 
    pop ax
    call get_chunk

    mov cx, ax
    mov ax, [INDEX]
    mov bx, [PTRS]
    call write_array
    ret

save_size:  ; save_size(size)
    push ax
    cmp word [SIZES], 0
    jne .skip_size

    mov ax, 1
    call get_chunk
    mov [SIZES], ax
.skip_size:
    pop ax
    mov cx, ax
    mov ax, [INDEX]
    mov bx, [SIZES]
    call write_array
    ret

; ------------------------------------

interact: ; word interact()
    call puts
    call read_dec
    push ax
    mov al, 0xa
    call putc
    pop ax
    ret

; ------------------------------------

puts:
    mov bp, ax
    puts_loop:
        mov al, byte [bp]
        cmp al, 0
        je end_puts
        call putc
        inc bp
        jmp puts_loop
    end_puts:
    ret

read_dec: ; word read_dec()
    xor bp, bp
    xor ax, ax

.read_loop:
    call getc

    cmp al, 0xd
    je .done

    cmp al, '0'
    jb _end
    cmp al, '9'
    ja _end

    sub al, '0'
    
    mov dx, bp
    shl bp, 1
    shl dx, 3
    add bp, dx

    add bp, ax
    jmp .read_loop

.done:
    mov ax, bp
    ret

; ------------------------------------

getc: ; char getc()
    mov dx, COM4LSR          ; because of the multiplexer in the qemu setup, we have to read stdin from COM4
    in al, dx
    bt ax, 0
    jnc getc
    sub dl, 5
    in al, dx

putc: ; void putc(char)
    mov dx, COM1
    out dx, al
    ret

; ------------------------------------

CHOICE_PROMPT db 0xa, "choice> ", 0
SIZE_PROMPT db "size> ", 0
INDEX_PROMPT db "index> ", 0
DATA_PROMPT db "data> ", 0
PORT_PROMPT db "port> ", 0


BUFF dw 0
HEAP dw 0x1000
PTRS dw 0
SIZES dw 0
INDEX dw 0

times 510-($-$$) db 0
dw 0xAA55

db "TRX{d0wn_7h3_a20_l1n3_f7w}"
times 512 - (($-$$) - 512) db 0