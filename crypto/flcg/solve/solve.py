from gmpy2 import gcd, mpz
from tqdm import tqdm
from Crypto.Cipher import AES

val = int([*open('out.txt')][0].strip().split()[-1], 16)

vals = []

while val:
    i = val%2**64
    vals.append(i * pow(5096758240909312, -1, 2**64-59)%(2**64-59))
    val >>= 64

vals = vals[::-1]

print([i.bit_length() for i in vals])

"""
vals = [586040767847558, 4915406609433538, 5960141492724448, 1789623283241104]
"""

"""
v = Matrix([[586040767847558*8, 4915406609433538, 5960141492724448]]).T
m = block_matrix([[1, v]])
print(m.LLL())
"""

vec1 = [ -59833*8,  116304,  -48852,  -32656]
vec2 = [ -44001*8,   96911,  -45312,  216878]

unit = 1<<(1023-54 - (512-53)) # used 54, could be like 52-57 within reason. just changed the value until it worked.

a1 = []
a2 = []
b1 = vec1[0] * (-vals[1]) + vec1[1] * (-vals[2]) + vec1[2] * (-vals[3])
b2 = vec2[0] * (-vals[1]) + vec2[1] * (-vals[2]) + vec2[2] * (-vals[3])

b12 = b1**2
b22 = b2**2
unit2 = unit**2

a10 = []

for i in range(2**20):
    i2 = i**2
    a1.append(mpz(unit2*i2 - b12))
    a2.append(mpz(unit2*i2 - b22))
    a10.append(mpz(unit*i + b1))
    a10.append(mpz(unit*i - b1))

a20 = a2.copy()
a3 = []

for i in range(20):
    if i == 10:
        a100 = a1.copy()
    if i == 10:
        a200 = a2.copy()
        a3.append(a200)
    
    if i < 10:
        a3.append(a2)
    a_temp = []
    a2_temp = []
    for j in range(len(a1)):
        if j % 2 == 0:
            a_temp.append(a1[j])
            a2_temp.append(a2[j])
        else:
            a_temp[-1] *= a1[j]
            a2_temp[-1] *= a2[j]
    a1 = a_temp
    a2 = a2_temp

assert len(a1) == len(a2) == 1
a1 = a1[0]
a2 = a2[0]

print("done computing products, computing gcds")

g = gcd(a1, a2)

print("done computing gcds, bit length", g.bit_length())

def check(q, k): # i wrote a dfs in hopes of speed but it doesn't really do much unfortunately. (2h -> 2h runtime skull)
    def recurse(depth, index, r):
        
        node = a3[depth][index]
        r = gcd(node, r)
        
        if r.bit_length() > 52:
            if depth == 0:
                print(r)
            else:
                recurse(depth - 1, 2 * index, r)
                recurse(depth - 1, 2 * index + 1, r)

    recurse(len(a3)-1, k, q)

for i in tqdm(range(2**10)):
    h = gcd(g, a100[i])
    for j in range(2**11):
        if (q:=gcd(h, a10[i*1024*2+j])).bit_length() > 52:
            for k in range(len(a200)):
                check(q, k)

# it outputs 739016460436115888 quite early on, inspecting prime factors we can divide by 13*8 to yield the real upper 53 bits of the prime.
p = 7105927504193422
vals = [586040767847558, 4915406609433538, 5960141492724448, 1789623283241104]



for i in range(10):
    unit = 1<<(1023-52-i - (512-53))
    val1 = [((pow(p//2, -1, unit//2) * (-val//2)) % (unit//2)) * p + val for val in vals]
    for j in range(len(val1)):
        if (unit << 53) - val1[j] > p * unit:
            val1[j] += p*unit
        if (unit << 53) - val1[j] > p * unit//2:
            val1[j] += p*unit//2
    
    a_s = []
    for a,b in zip(vals, val1[1:]):
        a_s.append(b/a)
    
    
    unit = 1<<(1023-52-i - (512-53))
    val1 = [((pow(p//2, -1, unit//2) * (-val//2)) % (unit//2)) * p + val for val in vals]
    for j in range(len(val1)):
        if (unit << 53) - val1[j] > p * unit:
            val1[j] += p*unit
        if (unit << 53) - val1[j] > p * unit//2:
            val1[j] += p*unit//2
        val1[j] -= p*unit//2
    
    for a,b in zip(vals, val1[1:]):
        a_s.append(b/a)
    

    print(a_s)

# use your eyes and check for common values (ok im way too lazy to do a set intersection i dont trust those)
# anyways the value it gives is below

a = int(1.0520996911217391e+153)
for i,j in zip(vals, vals[1:]):
    assert int(float(i * a)) % p == j

def guess_prev(cur):
    candidates = []
    for i in range(10):
        unit = 1<<(1023-52-i - (512-53))
        s = ((pow(p//2, -1, unit//2) * (-cur//2)) % (unit//2)) * p + cur
        if (unit << 53) - s > p * unit:
            s += p*unit
        if (unit << 53) - s > p * unit//2:
            s += p*unit//2
        candidates.append(int(s/a))
        candidates.append(int((s - p*unit//2)/a))
    return candidates

for i in guess_prev(vals[0]):
    for j in guess_prev(i):

        i1 = i << (512-53)
        i1 %= 2**64 - 59

        j1 = j << (512-53)
        j1 %= 2**64 - 59
        

        cipher = AES.new(j1.to_bytes(8, 'big') + i1.to_bytes(8, 'big'), AES.MODE_ECB)
        if b".;,;." in (f:=cipher.decrypt(bytes.fromhex("5c285fcff21cadb30a6ec92d445e5d75898f83fc31ff395cb43fb8be319d464895cf9aed809c20f92eb6f79f6bd36fc8d3091725b54c889a22850179ec26f89c"))):
            print(f)
            exit()