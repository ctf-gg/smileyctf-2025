import hashlib

enc_flag = bytes.fromhex("3d2276bcefce8c3360b2f5fa87405d1d6da92b896fb746fa343439692a2d57e8")
hint = bytes.fromhex("1f6a6b1f1b50442274155c3d496b0a0342536e5242107b32041b34583e801c160c746b45851d003d0b3e57815d7115347e01183728023c6a0166425a4779048027285b3e0d5a3a053a401d6421195422441628345346452e8046690b326d52761310494c164e7c076d563f4f01616d647640760602350b27144d522d6363376d742b7f802b51241d71131a463c1a1619181b0f205459026d0a28317d32530e480c41694f0a046867365f171d172c345b6a7b7d460e79451d617a628329803045")

p = 41385045268803457687081702183

F.<x> = GF(p)[]
Fp = GF(p^2, 'b', modulus=x^2 + 1)
I = Fp.gen()
a = 7677443135906757371086239158 + 1202973425456014711302222902*I

out = list(hint)
out_diffs = []
for i in range(len(out)//2 - 1):
    out_diffs.append(out[2*i + 2] - out[2*i])
    out_diffs.append(out[2*i + 3] - out[2*i + 1])

n = len(out_diffs)//2

bits = 96
missing = bits - 8

A1 = []
for i in range(n):
    A1.append(a^i)
A1 = vector(A1)
A2 = A1*I

total = [A1, A2]

M = Matrix(ZZ, 2 + 2*n, 2*len(A1))
for i in range(2):
    for j in range(0,2*len(A1),2):
        M[i, j] = total[i][j//2][0]
        M[i, j+1] = total[i][j//2][1]

for i in range(2*n - 2):
    M[i + 2, i + 2] = p

mid = []
for i in range(len(out_diffs)):
    mid.append(((out_diffs[i] << missing) + ((out_diffs[i] + 1) << missing))//2)
mid = vector(mid)

def cvp(B, t):
    t = vector(ZZ, t)
    B = B.LLL()
    S = B[-1].norm().round()+1
    L = block_matrix([
        [B,         0],
        [matrix(t), S]
    ])
    for v in L.LLL():
        if abs(v[-1]) == S:
            return t - v[:-1]*sign(v[-1])
    raise ValueError('cvp failed?!')

res = cvp(M, mid)
seed = res[-2] + res[-1]*I

found = False
for i in range(2**6):
    for j in range(2**6):
        l_diff = seed
        l_y = (out[-2] << 88) + (out[-1] << 88)*I
        l_y = l_y + (i << 82) + (j << 82)*I

        predicts = []
        for _ in range(8 + 1):
            l_diff = (a * l_diff)
            l_y = l_diff + l_y

            predicts.append(l_y[0])
            predicts.append(l_y[1])

        predicts = predicts[2:]

        actuals = []
        for i in range(len(predicts)):
            actuals.append(int(predicts[i]) >> 88)

        enc_key = hashlib.sha256(bytes(actuals)).digest()
        flag = bytes([a ^^ b for a,b in zip(enc_flag, enc_key)])
        
        try:
            flag = ".;,;.{" + flag.decode() + "}"
            print(flag)
            found = True
            break
        except:
            continue
    if found:
        break