from pwn import *

os.system("./build.sh")
data = b64e(open("main", "rb").read())

p = remote("localhost", 5000)
p.sendlineafter(b":", data)
p.interactive()