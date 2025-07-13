from Crypto.Util.number import *
from pwn import *
from math import isqrt
from sympy.ntheory.modular import crt

def send(length):
    io.recvuntil(b"Yes? ")
    io.sendline(b"yes")
    io.recvuntil(b"Length: ")
    io.sendline(str(length).encode())

def get_sequence(p):
    lens = []
    for i in range(p):
        send(10001+8*i)
        io.recvuntil(b"p multiple 1 bits: ")
        lens.append(int(io.recvline().strip()))
    diffs = []
    for i in range(p-1):
        diffs.append(lens[i+1]-lens[i])
    return tuple(diffs)

def get_sequences(p, seq):
    seqs = {}
    for i in range(p):
        seqs[i] = []
        s = long_to_bytes(i) + b"a" * ((1 + math.ceil(10001/8)) % (p-1))
        s_temp = bytes_to_long(s)
        s_temp = s_temp - s_temp % p
        prev = (s_temp//p).bit_count()
        for j in range(p-1):
            s = s + b"a"
            s_temp = bytes_to_long(s)
            s_temp = s_temp - s_temp % p
            seqs[i].append((s_temp//p).bit_count() - prev)
            
            prev = (s_temp//p).bit_count()
    
    assert [tuple(i) for i in seqs.values()].count(seq) == 1
    return {tuple(j):i for i,j in seqs.items()}[seq]

io = process(['python3', 'main.py'])
for guess in range(40, 10000, 40):
    send(guess)
    io.recvuntil(b"65537 ")
    if(io.recvline().strip() == b"65536"):
        flaglength = (guess - 40)//40
        break

print(flaglength)

ps = set()
ms = []
rs = []

while len(ps) < flaglength:
    send(9)
    io.recvuntil(b"65537 ")
    p = isqrt(int(io.recvline().strip()))
    if p in ps:
        continue
    try:
        rs.append(get_sequences(p, get_sequence(p)))
        ms.append(p)
        ps.add(p)
    except:
        continue

print(long_to_bytes(crt(ms, rs)[0]))

