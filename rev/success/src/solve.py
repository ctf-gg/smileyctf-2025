from z3 import *
import re
import operator

data = open('success.hs', 'r').readlines()[13:]
data = [line.strip().split('if ')[1].split(' then do')[0].strip() for line in data if line.strip() and 'if ' in line]

ops = {
    '(+)': operator.add,
    '(-)': operator.sub,
    '(*)': operator.mul,
    'xor': operator.xor,
    '(.&.)': operator.and_,
    '(.|.)': operator.or_,
}

flag = [BitVec(f'c{i}', 32) for i in range(39)]

conds = []
for line in data:
    op, *rest = line.split()
    op = ops[op]
    numbers = [int(x) for x in re.findall(r'-?\d+', line)]
    i, j, *rest = numbers
    res = 0
    const = None
    if len(rest) == 2:
        const, res = rest
    else:
        res = rest[0]
    
    lhs = op(flag[i], flag[j])
    if const is not None:
        lhs = op(lhs, const)
    
    conds.append(lhs == res)

s = Solver()
s.add(conds)
s.add([c >= 32 for c in flag])
s.add([c <= 126 for c in flag])

if s.check() == sat:
    m = s.model()
    flag = ''.join(chr(m[c].as_long()) for c in flag)
    print(flag)
else:
    print('No solution found')
