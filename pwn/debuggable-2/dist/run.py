#!/usr/bin/python3

from base64 import b64decode
from os import memfd_create, getpid, write, environ
from subprocess import run
import builtins

def print(*args, **kwargs):
    builtins.print(*args, **kwargs, flush=True)

data = input("elf: ").strip()
elf = b64decode(data)
print("got elf")

pid = getpid()
fd = memfd_create("elf")

write(fd, elf)
tmp = f"/proc/{pid}/fd/{fd}"

env = environ.copy()
env["HOME"] = "/home/ubuntu"
handle = run(["gdb", tmp, "-ex", "q"], capture_output=True, check=True, encoding="utf-8", env=env, input="")
print(handle.stdout)

print("bye")