from pwn import *
from functions import *
from tqdm import tqdm
p = remote("localhost", 5000)

p.send(b"""0
0
0
y
1
1
""")
def split_chunks(n):
    return [n >> (i*32) & 0xffffffff for i in range(8)]


p.recvuntil(b"challenge: ")
r1 = int(p.recvline().decode().split(",")[1].strip()[:-1])
cr1 = split_chunks(r1)
p.send(b"0\n0\n0\nn\n"*27)
for _ in tqdm(range(27)):
    p.recvuntil(b"Bye")

p.send(b"""0
0
0
y
1
1
""")
p.recvuntil(b"challenge: ")
r2 = int(p.recvline().decode().split(",")[1].strip()[:-1])
cr2 = split_chunks(r2)

data = cr1[0:4] + cr2[3:7]
S = [untemper(d) for d in data]
    
I_227_, I_228 = invertStep(S[0], S[4])
I_228_, I_229 = invertStep(S[1], S[5])
I_229_, I_230 = invertStep(S[2], S[6])
I_230_, I_231 = invertStep(S[3], S[7])

I_228 += I_228_
I_229 += I_229_
I_230 += I_230_

seed_h = recover_Kj_from_Ii(I_230, I_229, I_228, 230) - 1
seed_l1 = recover_Kj_from_Ii(I_231, I_230, I_229, 231)
seed_l2 = recover_Kj_from_Ii(I_231+0x80000000, I_230, I_229, 231)

seed1 = (seed_h << 32) + seed_l1
seed2 = (seed_h << 32) + seed_l2
import random
random.seed(seed1)
if random.getrandbits(256) == r1:
    seed = seed1
else:
    seed = seed2

random.seed(seed)
for _ in range(29):
    random.getrandbits(256)

p.recvuntil(b"Polynomial: ")

poly = eval(p.recvline().decode())



from polynomial import MVLinear
P = 2**256 - 189
poly = MVLinear(10, poly, P)
rs = [random.randint(0, P) for _ in range(10)]
points = {}
for i in range(10):
    points[i] = rs[i]

final_sum = poly.eval(points)



from sage.all import GF, Ideal
F = GF(P)[",".join(f'p{x}_0, p{x}_1' for x in range(10))]
gens = F.gens()
gens = list(gens)
for i in range(9):
    gens[2*i] = 1337

expect = 1337
constraints = []
rsc = rs.copy()

def talk(p0: int, p1: int):
    global expect, constraints, rsc

    constraints.append((p0 + p1) - expect)
    r = rsc.pop(0)
    pr = (p0 + r * (p1 - p0))
    expect = pr
    if not rsc:
        constraints.append(pr - final_sum)

for i in range(10):
    talk(gens[2*i], gens[2*i+1])

I = Ideal(constraints)
gb = I.groebner_basis()
for eq in gb:
    gens[gens.index(eq.variable(0))] = (-int(eq - eq.variable(0)))%P

p.sendline(b"1337")
p.sendline(str(gens[0]).encode())
p.sendline(str(gens[1]).encode())
p.sendline(b"y")
for i in gens[2:]:
    p.sendline(str(i).encode())

p.recvuntil(b"Flag: ")
flag = p.recvline().decode().strip()
print(flag)