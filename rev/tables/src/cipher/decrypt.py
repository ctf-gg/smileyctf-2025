ct = int.from_bytes(bytes.fromhex('aeb4c6ac2e9732cf5eb2fe2a303818b173b031518ca9b2ce73b144f75bc349219c274c3245ec54a3c2682066d922739a82aea4ce3ba8'), 'little')

n_bits = 432
modulus = 1 << n_bits
mask = modulus - 1

p = [int(x.strip()) for x in open('p.txt').readlines()]
c = [int(x.strip()) for x in open('c.txt').readlines()]

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

inv_3 = pow(3, -1, modulus)
k = [factors_of_2(x) for x in p]
m_prime = [modulus >> x for x in k]
p_prime = [x >> y for x, y in zip(p, k)]
p_prime_inv = [pow(x, -1, m) for x, m in zip(p_prime, m_prime)]

n = 0
def search(x: int, depth: int):
    global n

    if depth == -1:
        return

    x = (x * inv_3) & mask
    x = ror(x, 97)
    x ^= c[depth]

    d = 1 << k[depth]
    a = (p_prime_inv[depth] * (x >> k[depth])) & (m_prime[depth] - 1)
    for i in range(d):
        x = (a + 6) & mask
        x = ror(x, 383)
        if depth == 0:
            n += 1
            b = x.to_bytes(54, 'little')
            if b.startswith(b'mayb3_i_us3d_a_b'):
                print(n, b)
        search(x, depth - 1)

        a = (a + m_prime[depth]) & mask

search(ct, len(p) - 1)
print(n)
