import random
import ctypes

flag = b'.;,;.{PPPerfect_pr3c15e_p4rT1Ti0ning}'
base = 64

flag = int.from_bytes(flag, 'little')

def to_base(n, b):
    if n == 0:
        return '0'
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits

def from_base(s, b):
    n = 0
    for digit in s:
        n = n * b + int(digit)
    return n

flag = to_base(flag, base)
print(flag)

fruits = []
for i in flag:
    fruit = [random.getrandbits(31) for _ in range(base - 1)]
    left = sum(fruit[:i])
    right = sum(fruit[i:])
    left = ctypes.c_uint32(left).value
    right = ctypes.c_uint32(right).value
    diff = ctypes.c_uint32(left - right).value
    fruit.append(diff)
    
    left = ctypes.c_uint32(sum(fruit[:i])).value
    right = ctypes.c_uint32(sum(fruit[i:])).value
    assert left == right

    for j in range(base):
        if i == j:
            continue
        left = ctypes.c_uint32(sum(fruit[:j])).value
        right = ctypes.c_uint32(sum(fruit[j:])).value
        assert left != right

    fruits.append(fruit)

code = f'''unsigned int fruits[][{base}]'''
code += ' = {'
for i, fruit in enumerate(fruits):
    code += '{' + ', '.join(map(str, fruit)) + '}'
    if i < len(fruits) - 1:
        code += ', '
code += '};'

main = open('main.c', 'r').read()
main = main.replace('uint fruits[][1] = {{1}};', code)
open('gen.c', 'w').write(main)

# gcc -o main gen.c