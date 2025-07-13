import re
import capstone as cs
from enum import Enum

def _count_trailing_zeros(n: int) -> int:
    count = 0
    while n > 0 and n & 1 == 0:
        count += 1
        n >>= 1
    return count

class Operand(Enum):
    INPUT = 0
    MEM = 1

class Opcode(Enum):
    ADD = (0, 2, [4, 4], 256, 16, lambda a, b: (a + b) & 15)
    SUB = (1, 2, [4, 4], 256, 16, lambda a, b: (a - b) & 15)
    XOR = (2, 2, [4, 4], 256, 16, lambda a, b: a ^ b)
    OR = (3, 2, [4, 4], 256, 16, lambda a, b: a | b)
    SHL_1 = (4, 2, [4, 4], 256, 16, lambda a, b: (b << 1 | a >> 3) & 15)
    SHL_2 = (5, 2, [4, 4], 256, 16, lambda a, b: (b << 2 | a >> 2) & 15)
    SHL_3 = (6, 2, [4, 4], 256, 16, lambda a, b: (b << 3 | a >> 1) & 15)
    SUB_GET_BORROW = (7, 2, [4, 4], 256, 2, lambda a, b: 1 if a < b else 0)
    SUB_BIT = (8, 2, [4, 1], 32, 16, lambda a, b: (a - b) & 15)
    SUB_BIT_GET_BORROW = (9, 2, [4, 1], 32, 2, lambda a, b: 1 if a < b else 0)
    SBC = (10, 3, [4, 4, 1], 512, 16, lambda a, b, c: (a - b - c) & 15)
    SBC_GET_BORROW = (11, 3, [4, 4, 1], 512, 2, lambda a, b, c: 1 if a < b + c else 0)
    ADD_GET_OVERFLOW = (12, 2, [4, 4], 256, 2, lambda a, b: 1 if a + b > 15 else 0)
    ADC = (13, 3, [4, 4, 1], 512, 16, lambda a, b, c: (a + b + c) & 15)
    ADC_GET_OVERFLOW = (14, 3, [4, 4, 1], 512, 2, lambda a, b, c: 1 if a + b + c > 15 else 0)

    def n_operands(self) -> int:
        return self.value[1]
    
    def operand_n_bits(self) -> list[int]:
        return self.value[2]
    
    def n_elems(self) -> int:
        return self.value[3]
    
    def output_size(self) -> int:
        return self.value[4]

    def func(self):
        return self.value[5]

table_ptr = 0
var_name_counter = 0
slots = {}

class SBox:
    def __init__(self, table: list[int]):
        self.table = table
        self.inverse = [0] * len(table)
        for i, v in enumerate(table):
            self.inverse[v] = i

    @classmethod
    def identity(cls, n: int):
        return cls(list(range(n)))

    def encrypt(self, byte: int) -> int:
        return self.table[byte]
    
    def decrypt(self, byte: int) -> int:
        return self.inverse[byte]

def insn_to_str(insn: cs.CsInsn) -> str:
    if insn.op_str:
        return f'{insn.mnemonic} {insn.op_str}'
    else:
        return insn.mnemonic
    
def operand_to_str(operand: tuple[SBox, Operand, int]) -> str:
    if operand[1] == Operand.INPUT:
        _, _, index = operand
        return f'input[{index}]'
    elif operand[1] == Operand.MEM:
        _, _, name = operand
        return f'v{name}'

    
def print_table(table: list[int], elem_size: int, operands: list[tuple[SBox, Operand, int]]) -> None:
    args = [0] * len(operands)
    for i in range(len(table)):
        for j, operand in enumerate(operands):
            args[j] = i & (len(operand[0].table) - 1)
            i //= len(operand[0].table)

        enc_i = 0
        for arg, operand in reversed(list(zip(args, operands))):
            enc_i *= len(operand[0].table)
            enc_i |= operand[0].encrypt(arg)

        result = table[enc_i]

        if len(operands) == 2:
            if args[0] == 0:
                print(f'(0, {args[1]}): ', end='\t')
            print(result, end='\t')
            if args[0] == len(operands[0][0].table) - 1:
                print()
        else:
            print(f'{args} -> {result}')
    
def is_opcode(opcode: Opcode, table: list[int], operands: list[tuple[SBox, Operand]]) -> SBox | None:
    if len(operands) != opcode.n_operands() or len(table) != opcode.n_elems():
        return None
    
    # try to reconstruct the output sbox assuming the opcode is correct
    out_sbox = [None] * opcode.output_size()
    args = [0] * opcode.n_operands()
    for i in range(opcode.n_elems()):
        arg_i = i
        for j, operand in enumerate(operands):
            args[j] = operand[0].decrypt(arg_i & ((1 << opcode.operand_n_bits()[j]) - 1))
            arg_i >>= opcode.operand_n_bits()[j]
        result = opcode.func()(*args)
        if out_sbox[result] is None:
            out_sbox[result] = table[i]
        elif out_sbox[result] != table[i]:
            # we have run into a condradiction, so the opcode is not correct
            return None
    return SBox(out_sbox)

def detect_opcode(table: list[int], operands: list[tuple[SBox, Operand]]) -> tuple[Operand, SBox]:
    for opcode in Opcode:
        sbox = is_opcode(opcode, table, operands)
        if sbox is not None:
            return opcode, sbox
    return None
 
def disasm_insn() -> str:
    global table_ptr, var_name_counter

    assert insn_to_str(next(it)) == 'xor rbx, rbx'
    s = insn_to_str(next(it))
    operands = []
    n_elems = 1
    # parse operands
    while s != 'mov rcx, rbx' and s != 'mov rax, rbx':
        if s == 'mov cl, byte ptr [rdi]':
            inp_byte = 0
            high_nibble = int(re.match(r'^and rcx, (.*)$', insn_to_str(next(it))).group(1), 0) == 0xf0
            operands.append((SBox.identity(16), Operand.INPUT, inp_byte*2 + high_nibble))
            n_elems *= 16
        elif match := re.match(r'^mov cl, byte ptr \[rdi \+ (.*)\]$', s):
            inp_byte = int(match.group(1), 0)
            high_nibble = int(re.match(r'^and rcx, (.*)$', insn_to_str(next(it))).group(1), 0) == 0xf0
            operands.append((SBox.identity(16), Operand.INPUT, inp_byte*2 + high_nibble))
            n_elems *= 16
        elif match := re.match(r'^mov (?:rcx|cl), (.*)$', s):
            inp_reg = match.group(1)
            insn = next(it)
            s = insn_to_str(insn)
            if insn.mnemonic == 'and':
                reg_and = int(re.match(r'^and rcx, (.*)$', s).group(1), 0)
            elif insn.mnemonic == 'movabs':
                reg_and = int(re.match(r'^movabs rsi, (.*)$', s).group(1), 0)
                next(it)    # and ##, rsi
            else:
                assert False
            inp_shift = _count_trailing_zeros(reg_and)

            key = (inp_reg, inp_shift)
            assert key in slots
            slot = slots[key]
            operands.append(slot)
            n_elems *= len(slot[0].table)
        else:
            print(s, next(it))
            assert False

        insn = next(it)
        if insn.mnemonic != 'lea':
            insn = next(it)    # shl/shr rcx, ##
        assert insn_to_str(insn) == f'lea rbx, [rbx + rcx]'

        s = insn_to_str(next(it))

    if s == 'mov rax, rbx':
        print(f'ret {operand_to_str(operands[0])}')
        return False

    rcx_and = int(re.match(r'^and rcx, (.*)$', insn_to_str(next(it))).group(1), 0)
    elem_n_bits = 8 // (rcx_and + 1)

    next(it)    # lea rsi, [rip + ####]
    next(it)    # shr rbx, ##
    assert insn_to_str(next(it)) == 'lea rsi, [rsi + rbx]'
    assert insn_to_str(next(it)) == 'mov bl, byte ptr [rsi]'
    insn = next(it)
    if insn.mnemonic == 'shl':
        insn = next(it)
    assert insn_to_str(insn) == 'shr rbx, cl'
    next(it)    # and rbx, ##

    insn = next(it)
    if insn.mnemonic == 'and':
        output_shift = 0
    else:
        output_shift = int(re.match(r'^shl rbx, (.*)$', insn_to_str(insn)).group(1), 0)
        insn = next(it)

    if insn.mnemonic == 'movabs':
        insn = next(it)    # movabs rsi, #####
    # note: stack slots will also be treated as "registers" here, its just
    # that the "registers" name will be something like "byte ptr [rsp + 0x10]"
    output_reg = re.match(r'^and (.*), .*$', insn_to_str(insn)).group(1)
    next(it)    # or ###, rbx

    n_bytes = n_elems * elem_n_bits // 8
    table_bytes = memoryview(tables)[table_ptr:table_ptr + n_bytes]
    table_ptr += n_bytes
    table = []
    for i in range(n_bytes):
        elems = table_bytes[i]
        for _ in range(0, 8, elem_n_bits):
            elem = elems & ((1 << elem_n_bits) - 1)
            elems >>= elem_n_bits
            table.append(elem)

    res = detect_opcode(table, operands)
    if res is None:
        print('Unknown opcode')
        print_table(table, 1 << elem_n_bits, operands)
        return
    
    opcode, sbox = res
    var_name = var_name_counter
    var_name_counter += 1
    print(f'v{var_name} = {opcode.name.lower()} {", ".join(operand_to_str(op) for op in operands)}')

    slots[(output_reg, output_shift)] = (sbox, Operand.MEM, var_name)
    return True

f = open('../build/main', 'rb')

# to disasm part 1:
# f.seek(0x401181 - 0x400000)
# code = f.read(0x10000)

# f.seek(0x2666004 - 0x400000)
# tables = f.read(0x10000)

# to disasm part 2:
f.seek(0x40202b - 0x400000)
code = f.read(0x400000)     # replace with however many bytes you want to disassemble

f.seek(0x2667784 - 0x400000)
tables = f.read(0x400000)   # replace with however many bytes you want to disassemble

md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
it = md.disasm(code, 0)
while disasm_insn():
    pass
