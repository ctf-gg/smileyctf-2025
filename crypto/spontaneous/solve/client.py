from pwn import process, remote
from base64 import b64encode
import gzip
import json
from Prover import Prover
from fft import fft, ifft
p = Prover()
poly = [0] * (2**14)
def compress(data: bytes):
    return b64encode(gzip.compress(data))

ser_proof = compress(open("solve.json", "rb").read())
#conn = process(["python3", "server.py"])
conn = remote("localhost", 5000)
conn.sendline(ser_proof)
conn.recvuntil(b".;,;.")
flag = ".;,;." + conn.recvline().decode().strip()
print(flag)
