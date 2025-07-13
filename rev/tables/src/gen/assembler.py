from codegen import *

def _warn_impossible():
    print('warning: operation impossible to reverse-engineer')

def _naf(n):
    naf = []
    while n > 0:
        if n & 1:
            z = 2 - (n & 3)
            naf.append(z)
            n -= z
        else:
            naf.append(0)
        n >>= 1
    return naf

class ValueExt:
    def __init__(self, nibbles: list[Value]):
        self.nibbles = nibbles

    def bit_len(self) -> int:
        return len(self.nibbles) * 4
    
    def subvalue(self, start_bits: int, end_bits: int) -> 'ValueExt':
        assert 0 <= start_bits < end_bits <= self.bit_len()
        assert start_bits % 4 == 0 and end_bits % 4 == 0
        return ValueExt(self.nibbles[start_bits // 4:end_bits // 4])

class Assembler:
    def __init__(self, codegen: CodeGen):
        self.codegen = codegen
        self.randomize_sboxes = False
        self.input_sboxes: list[SBox] = []

    def _sbox(self, n: int):
        if self.randomize_sboxes:
            return SBox.random(n)
        else:
            return SBox.identity(n)

    def input_nibble(self, index: int) -> Value:
        assert 0 <= index < len(self.input_sboxes)
        return InputU4(self.input_sboxes[index], index)
    
    def input(self, index: int, n_bits: int) -> ValueExt:
        assert n_bits % 4 == 0
        return ValueExt([self.input_nibble(index + i) for i in range(n_bits // 4)])
    
    def decode_nibble(self, a: Value) -> Value:
        _warn_impossible()
        return self.codegen.add(Insn(4, SBox.identity(16), lambda x: x, a))
    
    def decode(self, a: ValueExt) -> ValueExt:
        _warn_impossible()
        return ValueExt([self.decode_nibble(n) for n in a.nibbles])
    
    def add_nibble(self, a: Value, b: Value) -> Value:
        return self.codegen.add(Insn(4, self._sbox(16), lambda x, y: (x + y) & 15, a, b))
    
    # Output bit size is that of the first input (a)
    def add(self, a: ValueExt, b: ValueExt, b_shift_bits: int) -> ValueExt:
        assert b_shift_bits % 4 == 0
        b_shift = b_shift_bits // 4
        assert a.bit_len() <= b.bit_len() + b_shift // 4
        res = []
        for i in range(b_shift):
            res.append(a.nibbles[i])
        res.append(self.codegen.add(Insn(4, self._sbox(16), lambda x, y: (x + y) & 15, a.nibbles[b_shift], b.nibbles[0])))
        carry = self.codegen.add(Insn(1, self._sbox(2), lambda x, y: (x + y) >> 4, a.nibbles[b_shift], b.nibbles[0]))
        for i in range(b_shift + 1, len(a.nibbles)):
            sum_nibble = self.codegen.add(Insn(4, self._sbox(16), lambda x, y, c: (x + y + c) & 15, a.nibbles[i], b.nibbles[i - b_shift], carry))
            res.append(sum_nibble)
            if i != len(a.nibbles) - 1:
                carry = self.codegen.add(Insn(1, self._sbox(2), lambda x, y, c: (x + y + c) >> 4, a.nibbles[i], b.nibbles[i - b_shift], carry))
        return ValueExt(res)
    
    def sub_nibble(self, a: Value, b: Value) -> Value:
        return self.codegen.add(Insn(4, self._sbox(16), lambda x, y: (x - y) & 15, a, b))
    
    def sub_ext_nibble(self, a: ValueExt, b: Value) -> ValueExt:
        assert a.bit_len() % 4 == 0
        assert isinstance(b, Value)
        res = []
        res.append(self.codegen.add(Insn(4, self._sbox(16), lambda x, y: (x - y) & 15, a.nibbles[0], b)))
        borrow = self.codegen.add(Insn(1, self._sbox(2), lambda x, y: 1 if x < y else 0, a.nibbles[0], b))
        for i in range(1, len(a.nibbles)):
            res.append(self.codegen.add(Insn(4, self._sbox(16), lambda x, y: (x - y) & 15, a.nibbles[i], borrow)))
            if i != len(a.nibbles) - 1:
                borrow = self.codegen.add(Insn(1, self._sbox(2), lambda x, y: 1 if x < y else 0, a.nibbles[i], borrow))
        return ValueExt(res)
    
    # Output bit size is that of the first input (a)
    def sub(self, a: ValueExt, b: ValueExt, b_shift_bits: int) -> ValueExt:
        assert b_shift_bits % 4 == 0
        b_shift = b_shift_bits // 4
        assert a.bit_len() <= b.bit_len() + b_shift // 4
        res = []
        for i in range(b_shift):
            res.append(a.nibbles[i])
        res.append(self.codegen.add(Insn(4, self._sbox(16), lambda x, y: (x - y) & 15, a.nibbles[b_shift], b.nibbles[0])))
        borrow = self.codegen.add(Insn(1, self._sbox(2), lambda x, y: 1 if x < y else 0, a.nibbles[b_shift], b.nibbles[0]))
        for i in range(b_shift + 1, len(a.nibbles)):
            sub_nibble = self.codegen.add(Insn(4, self._sbox(16), lambda x, y, b: (x - y - b) & 15, a.nibbles[i], b.nibbles[i - b_shift], borrow))
            res.append(sub_nibble)
            if i != len(a.nibbles) - 1:
                borrow = self.codegen.add(Insn(1, self._sbox(2), lambda x, y, b: 1 if x < y + b else 0, a.nibbles[i], b.nibbles[i - b_shift], borrow))
        return ValueExt(res)
    
    def mul_imm(self, a: ValueExt, b: int) -> ValueExt:
        a_shifts = [a, None, None, None]
        res = None
        i = 0
        while b != 0:
            if b & 1:
                shift_mod_4 = i % 4
                if a_shifts[shift_mod_4] is None:
                    a_shifts[shift_mod_4] = self.shl_imm(a, shift_mod_4)
                a_shift_mod_4: ValueExt = a_shifts[shift_mod_4]
                shift_nibbles = i // 4
                
                if res is None:
                    res = ValueExt([self.input_nibble(0)] * shift_nibbles + a_shift_mod_4.nibbles[:len(a_shift_mod_4.nibbles) - shift_nibbles])
                else:
                    res = self.add(res, a_shift_mod_4, shift_nibbles * 4)
            i += 1
            b >>= 1
        assert res is not None
        return res
    
    def mul_imm_naf(self, a: ValueExt, b: int) -> ValueExt:
        b_naf = _naf(b)
        a_shifts = [a, None, None, None]
        res = None
        i = 0
        for i, bit in reversed(list(enumerate(b_naf))):
            if bit != 0:
                shift_mod_4 = i % 4
                if a_shifts[shift_mod_4] is None:
                    a_shifts[shift_mod_4] = self.shl_imm(a, shift_mod_4)
                a_shift_mod_4: ValueExt = a_shifts[shift_mod_4]
                shift_nibbles = i // 4
            
            if bit == 1:
                if res is None:
                    res = ValueExt([self.input_nibble(0)] * shift_nibbles + a_shift_mod_4.nibbles[:len(a_shift_mod_4.nibbles) - shift_nibbles])
                else:
                    res = self.add(res, a_shift_mod_4, shift_nibbles * 4)
            elif bit == -1:
                assert res is not None
                res = self.sub(res, a_shift_mod_4, shift_nibbles * 4)
        assert res is not None
        return res
    
    def or_nibble(self, a: Value, b: Value, out: SBox = None) -> Value:
        if out is None:
            out = self._sbox(16)
        return self.codegen.add(Insn(4, out, lambda x, y: x | y, a, b))
    
    def rol_imm(self, a: ValueExt, b: int) -> ValueExt:
        assert 0 <= b < a.bit_len()
        nibbles = [a.nibbles[(i - b // 4) % len(a.nibbles)] for i in range(len(a.nibbles))]
        nibble_rol = b % 4
        if nibble_rol == 0:
            return ValueExt(nibbles)
        
        res = []
        for i in range(len(nibbles)):
            res.append(self.codegen.add(Insn(4, self._sbox(16), lambda x, y: ((y << nibble_rol) | (x >> (4 - nibble_rol))) & 15, nibbles[i-1], nibbles[i])))
        return ValueExt(res)
    
    def shl_imm(self, a: ValueExt, b: int) -> ValueExt:
        assert 0 < b < 4
        res = []
        for i in range(len(a.nibbles)):
            prev = self.input_nibble(0) if i == 0 else a.nibbles[i-1]
            res.append(self.codegen.add(Insn(4, self._sbox(16), lambda x, y: ((y << b) | (x >> (4 - b))) & 15, prev, a.nibbles[i])))
        return ValueExt(res)
    
    def xor_nibble(self, a: Value, b: Value) -> Value:
        return self.codegen.add(Insn(4, self._sbox(16), lambda x, y: x ^ y, a, b))
    
    def xor(self, a: ValueExt, b: ValueExt) -> ValueExt:
        assert a.bit_len() == b.bit_len()
        return ValueExt([self.xor_nibble(a.nibbles[i], b.nibbles[i]) for i in range(len(a.nibbles))])
    
    def const(self, val: int, n_bits: int) -> ValueExt:
        assert n_bits % 4 == 0
        nibbles = []
        for _ in range(n_bits // 4):
            nibbles.append(self.input_nibble(val & 0x0f))
            val >>= 4
        return ValueExt(nibbles)
    
    def ret_nibble(self, val: Value):
        self.codegen.add(RetInsn([val]))
    
    def ret(self, val: ValueExt):
        self.codegen.add(RetInsn(val.nibbles))
