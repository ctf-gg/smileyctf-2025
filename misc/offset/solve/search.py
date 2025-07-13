p = 4
def check(x):
    x = x.encode()
    cond = all(i % 2 != j % 2 for i,j in enumerate(x))
    cond *= all(j % ((i % p) + 1) == 0 for i,j in enumerate(x))
    return cond
# while True:
#     x = input("hi. ")
#     if check(x):
#         exec(x)

from string import printable
from unicodedata import normalize
#print(len(printable))
c = {}
runstr = ""
#runstrs = '\t\n\t\x0c#\x0c# \t\n'

while len(c) < p:
    c[len(c)] = [[], set()]
    for i in range(0x110000):
        j = normalize("NFKC", chr(i))
        if len(runstr) < len(c)-1:
            # runstr += runstrs[len(c)-2]
            runstr += c[len(c)-2][0][0][0]
        if len(j) == 1 and j.lower() in printable:
            if j.lower() in "abcdefghijklmnopqrstuvwxyz":
                try:
                    exec(chr(i) + "aaa=1")
                except:
                    continue
            assert len(runstr) == len(c) - 1
            if (i < 256 or j.lower() in "abcdefghijklmnopqrstuvwxyz") and check(runstr+chr(i)):
                # if len(chr(i).encode()) > 1:
                c[len(c)-1][0].append((chr(i), j, len(chr(i).encode())))
                c[len(c)-1][1].add(j)
    print(f"{runstr = }")
for j,i in enumerate(c.keys()):
    x = list(c[i][1])
    x.sort()
    print(f"{j}: {''.join(x).encode()}")
    print(str(c[i][0]).replace("[('","").replace(")]","").replace('"', "'").replace("), ('", "\n").replace("', '", " ").replace("',", ""))



print(c.keys())
cc = {}
for i in c:
    cc[i] = {}
    for _, char, length in c[i][0]:
        if char not in cc[i]:
            cc[i][char] = set()
        cc[i][char].add(length)
    
keys = set()
keys.update(set(__builtins__.__dict__.keys()))
# keys.update(set(str.__dict__.keys()))
# keys.update(set(int.__dict__.keys()))
# keys.update(set(list.__dict__.keys()))
# keys.update(set(dict.__dict__.keys()))
# keys.update(set(set.__dict__.keys()))
# keys.update(set(tuple.__dict__.keys()))
#keys.update(set(__import__('sys').__dict__.keys()))
#keys.update(set(__import__('os').__dict__.keys()))
# keys.update(set(type.__dict__.keys()))
#keys.update(set(__import__('abc').__dict__.keys()))
# keys.update(set(__import__('abc').__dict__.keys()))
keys.add("check")
keys.update(set(dir(open("/etc/passwd"))))


valid = []
# print(cc)

def search(i, target):
    if target == "": return True

    nxt = target[0]
    if nxt not in cc[i]: return False

    for length in cc[i][nxt]:
        if search((i + length) % p, target[1:]):
            return True
        
    return False

for key in keys:
    for i in range(p):
        if search(i, key):
            valid.append((key, i))
            print(f"{key} -> {i}")


