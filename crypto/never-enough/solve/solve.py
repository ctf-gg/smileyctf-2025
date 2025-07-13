from gf2bv import LinearSystem
w=32
n=624
m=397
r=31
a=0x9908B0DF
u=11
d=0xFFFFFFFF
s=7
b=0x9D2C5680
t=15
c=0xEFC60000
l=18
w1 = (1 << w) - 1
lmsk = w1 & ((1 << r) - 1)
umsk = w1 ^ lmsk
a = 0x9908B0DF

def twist(f, mti1, mtim):
    y = f ^ (mti1 & lmsk)
    sel = (f ^ (mti1 & lmsk)).broadcast(0, 32) & a
    return mtim ^ (y >> 1) ^ sel

def temper(y):
    y ^= (y >> u) & d
    y ^= (y << s) & w1 & b
    y ^= (y << t) & w1 & c
    y ^= y >> l
    return y

def valid_pair_f(f,si,sm,st):
    lin = LinearSystem([32] * 3)
    vs = lin.gens()
    zeros = [
        temper(twist(vs[0] & umsk, untemper(vs[1]), untemper(vs[2]))) >> 12 ^ st,
        vs[0] & lmsk,
        vs[0] >> 31 ^ f,
        vs[1] >> 12 ^ si,
        vs[2] >> 12 ^ sm,
    ]
    sols = lin.solve_all(zeros, max_dimension=17)
    x = [*sols,]
    c1 = len(x) != 0
    if not c1:
        return False
    vs1 = x[0][1]
    return True, vs1

def valid_pair(si, sm, st):
    if res:=valid_pair_f(0, si, sm, st):
        return res
    if res:=valid_pair_f(1, si, sm, st):
        return res
    return False



# https://github.com/StackeredSAS/python-random-playground/blob/main/functions.py
def unshiftRight(x, shift):
    res = x
    for i in range(32):
        res = x ^ res >> shift
    return res


def unshiftLeft(x, shift, mask):
    res = x
    for i in range(32):
        res = x ^ (res << shift & mask)
    return res


def untemper(v):
    v = unshiftRight(v, 18)
    v = unshiftLeft(v, 15, 0xefc60000)
    v = unshiftLeft(v, 7, 0x9d2c5680)
    v = unshiftRight(v, 11)
    return v

#################################################################################

data = open("out.txt", "r").read().strip().split("\n")
from ast import literal_eval as eval
given = eval(data[0])

for i in range(len(given)):
    try:
        given[i+1] = valid_pair(given[i+1], given[m+i], given[n+i])[1] % 2**12
    except:
        break

ct = bytes.fromhex(data[1])
from Crypto.Cipher import AES
from hashlib import sha256
def try_dec(x, given=given):
    given = given[:]
    given[0] = x
    key = "".join(map(str, given))[:100]
    key = sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        return cipher.decrypt(ct).strip(b"\x00")
    except:
        return None
    
for i in range(2**12):
    res = try_dec(i)
    if res and b".;,;.{" in res:
        print("Flag:", res.decode())
        break
