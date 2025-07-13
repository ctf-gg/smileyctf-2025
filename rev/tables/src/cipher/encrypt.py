import math
import random

random.seed(0xe2d567609c367432)

flag = b'mayb3_i_us3d_a_b1t_t0o_m4ny_lookup_t4bl3s_5ee159e93528'
n_bits = len(flag) * 8
print(n_bits)
modulus = 1 << n_bits
mask = modulus - 1

def gen_multiple(n: int) -> int:
    return random.randint(0, modulus // n) * n

def factors_of_2(n: int) -> int:
    r = 0
    while (n & 1) == 0:
        n >>= 1
        r += 1
    return r

def rol(a: int, b: int) -> int:
    a &= mask
    return ((a << b) | (a >> (n_bits - b))) & mask

def ror(a: int, b: int) -> int:
    a &= mask
    return ((a >> b) | (a << (n_bits - b))) & mask

p = []
k = []
c = []
t = 0
while t < 24:
    x = random.randint(0, modulus)
    p.append(x)
    k.append(factors_of_2(x))
    t += factors_of_2(x)
for i in range(len(p)):
    c.append(random.randint(0, modulus))
print(len(p), t)
print(k)

open('p.txt', 'w').write('\n'.join(map(str, p)))
open('c.txt', 'w').write('\n'.join(map(str, c)))

def encrypt(pt: bytes) -> bytes:
    ct = int.from_bytes(pt, 'little')
    for i, x in enumerate(p):
        ct = rol(ct, 383)
        ct = ((ct - 6) * x) & mask
        ct ^= c[i]
        ct = rol(ct, 97)
        ct *= 3
        ct &= mask
    return ct.to_bytes(n_bits // 8, 'little')

flag_n = int.from_bytes(flag, 'little')

# mayb3_i_us3d_a_b1t_t0o_m4ny_lookup_t4bl3s_5ee159e93528
# ct = rol(flag_n, 383)
# ct = (ct - 6) & mask
# ct = (ct * p[0]) & mask
# ct ^= c[0]
# ct = rol(ct, 97)
# ct = (ct * 3) & mask
# print(hex(ct & ((1 << 64) - 1)))

# print(flag[:16])
# print(int.from_bytes(flag, 'little'))
print(encrypt(flag).hex())
