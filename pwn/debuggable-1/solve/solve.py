from pwn import *

data = b64e(open("./test", "rb").read()).encode()
p = remote("localhost", 5000)

p.sendlineafter(b": ", data)

p.interactive()