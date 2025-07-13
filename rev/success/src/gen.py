import random
from collections import Counter
import operator

flag = b'.;,;.{imagine_if_i_made_it_compiled!!!}'
print(len(flag))

ops = [
    ('+', operator.add),
    ('+', operator.add),
    ('+', operator.add),
    ('+', operator.add),
    ('-', operator.sub),
    ('*', operator.mul),
    ('*', operator.mul),
    ('*', operator.mul),
    ('*', operator.mul),
    ('^', operator.xor),
    ('^', operator.xor),
    ('&', operator.and_),
    ('|', operator.or_),
]

checks = []
seen = Counter()

while len(seen) != len(flag) and any(seen[c] < 3 for c in flag):
    i, j = random.sample(range(len(flag)), 2)
    if seen[i] >= 3 or seen[j] >= 3:
        continue
    op, func = random.choice(ops)
    has_const = random.random() < 0.1

    if has_const:
        const = random.randint(0, 255)
        res = func(func(flag[i], flag[j]), const)
        checks.append((i, j, const, op, res))
    else:
        res = func(flag[i], flag[j])
        checks.append((i, j, op, res))
    
    seen[i] += 1
    seen[j] += 1

haskell_op = {
    '+': '(+)',
    '-': '(-)',
    '*': '(*)',
    '^': 'xor',
    '&': '(.&.)',
    '|': '(.|.)',
}

pad = '    ' * 3
with open('checks.txt', 'w') as f:
    for i, j, *rest in checks:
        if len(rest) == 3:
            const, op, res = rest
            f.write(pad + f'if {haskell_op[op]} ({haskell_op[op]} (chars !! {i}) (chars !! {j})) {const} == {res} then do\n')
        else:
            op, res = rest
            f.write(pad + f'if {haskell_op[op]} (chars !! {i}) (chars !! {j}) == {res} then do\n')
        
        pad += '    '

    f.write(pad + 'putStrLn "yea go submit the flag"\n')
    f.write(pad + 'exitSuccess\n')

    for *_, res in checks[::-1]:
        pad = pad[:-4]
        f.write(pad + 'else do\n')
        f.write(pad + f'    putStrLn "no thats not {res}"\n')
        f.write(pad + '    exitFailure\n')