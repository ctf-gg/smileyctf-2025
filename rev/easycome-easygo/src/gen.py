import random

flag = b'.;,;.{goh3m1an_rh4p50dy}'
n = len(flag)

idxs = list(range(n))
random.shuffle(idxs)

print(','.join(map(str, idxs)))

key1 = random.randbytes(n)
key2 = random.randbytes(n)

print(','.join(map(str, key1)))
print(','.join(map(str, key2)))

enc = [0] * n
for i in range(n):
    enc[i] = flag[i] ^ key1[idxs[i]] ^ key2[i]

print(','.join(map(str, enc)))