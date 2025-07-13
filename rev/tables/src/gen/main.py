import random
from sbox import *
from codegen import *
from assembler import *

random.seed(0xa3bbc16c5e43c15f)

codegen = CodeGen()

table_out = open('../build/table.s', 'w', buffering=1024*1024)
insn_out = open('../build/insn.s', 'w', buffering=1024*1024)

insn_out.write('; auto-generated\n\n')
table_out.write('; auto-generated\n\n')
insn_out.write('section .rodata\n%include "table.s"\n\nsection .note.GNU-stack noalloc noexec nowrite progbits\n\nsection .text\nglobal check_flag_1, check_flag_2\n')
gp_reg = [Register.RDX, Register.RBP, Register.R8, Register.R9, Register.R10, Register.R11, Register.R12, Register.R13, Register.R14, Register.R15]
callee_saved = [Register.RBX, Register.RBP, Register.R12, Register.R13, Register.R14, Register.R15]
codegen.set_table_out(table_out)\
    .set_insn_out(insn_out)\
    .set_gp_reg(gp_reg)\
    .set_callee_saved(callee_saved)\
    .set_randomize_slots(True)\
    .set_randomize_tables(False)

input_sboxes = [SBox.identity(16) for _ in range(124)]

# flag = b'mayb3_i_us3d_a_b1t_t0o_m4ny_lookup_t4bl3s_' + random.randbytes(6).hex().encode('ascii')
flag = b'mayb3_i_us3d_a_b1t_t0o_m4ny_lookup_t4bl3s_5ee159e93528'
print(flag)
print(len(flag), flag[:16], flag[16:])

asm = Assembler(codegen)
asm.randomize_sboxes = True
asm.input_sboxes = input_sboxes

codegen.start_method('check_flag_1')
res = None
for i in range(8):
    a_expected, b_expected = flag[i] & 0x0f, flag[i] >> 4
    sum_expected = (a_expected + b_expected) & 0x0f
    diff_expected = (a_expected - b_expected) & 0x0f
    sum_expected = asm.input_nibble(sum_expected)
    diff_expected = asm.input_nibble(diff_expected)

    a, b = asm.input_nibble(16 + i*2), asm.input_nibble(16 + i*2 + 1)
    sum_ = asm.add_nibble(a, b)
    diff = asm.sub_nibble(a, b)
    
    sum_res = asm.xor_nibble(sum_, sum_expected)
    res = sum_res if res is None else asm.or_nibble(res, sum_res)

    diff_res = asm.xor_nibble(diff, diff_expected)
    res = asm.or_nibble(res, diff_res, SBox.identity(16) if i == 7 else None)
asm.ret_nibble(res)
codegen.emit_method()

codegen.start_method('check_flag_2')
inp = asm.input(16, 432)
p = [int(x.strip()) for x in open('../cipher/p.txt').readlines()]
c = [int(x.strip()) for x in open('../cipher/c.txt').readlines()]
ct = inp
for i in range(len(p)):
    ct = asm.rol_imm(ct, 383)
    ct = asm.sub_ext_nibble(ct, asm.input_nibble(6))
    ct = asm.mul_imm_naf(ct, p[i])
    ct = asm.xor(ct, asm.const(c[i], 432))
    ct = asm.rol_imm(ct, 97)
    ct_old = ct
    ct = asm.add(asm.add(ct_old, ct_old, 0), ct_old, 0)

ct_expected = bytes.fromhex('aeb4c6ac2e9732cf5eb2fe2a303818b173b031518ca9b2ce73b144f75bc349219c274c3245ec54a3c2682066d922739a82aea4ce3ba8')
res = None
for i, byte in enumerate(ct_expected):
    for j in range(2):
        nibble = (byte >> (4 * j)) & 0x0f
        xor_res = asm.xor_nibble(ct.nibbles[i*2 + j], asm.input_nibble(nibble))
        res_sbox = SBox.identity(16) if i == len(ct_expected) - 1 and j == 1 else None
        res = xor_res if res is None else asm.or_nibble(res, xor_res, res_sbox)
asm.ret_nibble(res)
codegen.emit_method()
