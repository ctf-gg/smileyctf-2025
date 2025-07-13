import io
import random
from enum import Enum
from sbox import *
from typing import Callable, Optional
from tqdm import tqdm

def _next_power_of_two(n: int) -> int:
    if n == 0:
        return 1
    return 1 << (n.bit_length() - (1 if (n & (n - 1)) == 0 else 0))

def _is_power_of_two(n: int) -> bool:
    return n != 0 and (n & (n - 1)) == 0

def _log_2(n: int) -> int:
    if n == 0:
        return 0
    return n.bit_length() - 1

def _align(n: int, align: int) -> int:
    return (n + align - 1) & ~(align - 1)

def _u64_to_s64(n: int) -> int:
    assert 0 <= n < (1 << 64), 'out of bounds u64'
    return n if n < (1 << 63) else n - (1 << 64)

def _u32_to_s32(n: int) -> int:
    assert 0 <= n < (1 << 32), 'out of bounds u32'
    return n if n < (1 << 31) else n - (1 << 32)

def _is_s32(n: int) -> bool:
    return -0x80000000 <= _u64_to_s64(n) < 0x80000000
    

class Value:
    def __init__(self, n_bits: int, sbox: SBox):
        assert 0 < n_bits <= 4, 'max 4-bit value'
        assert len(sbox.table) == 1 << n_bits, 'sbox must be 2^n_bits'
        self.n_bits = n_bits
        self.sbox = sbox

    def srcs(self) -> list['Value']:
        return []

    def src_insns(self) -> list['Insn']:
        return filter(lambda x: isinstance(x, Insn), self.srcs())
    
class InputU4(Value):
    def __init__(self, sbox: SBox, index: int):
        super().__init__(4, sbox)
        self.index = index

class Insn(Value):
    def __init__(self, n_bits: int, sbox: SBox, op: Callable, *args: Value):
        if type(self) is not RetInsn and not len(args) >= 2:
            print('warning: insn may be impossible to reverse-engineer')
        super().__init__(n_bits, sbox)
        self.op = op
        self.args = args
        self.deps: list[Insn] = []

    def srcs(self) -> list[Value]:
        return self.args

class RetInsn(Insn):
    def __init__(self, args: list[Value]):
        assert len(args) <= 16, 'max 64-bit return value'
        super().__init__(4, SBox.identity(16), None, *args)

class Register(Enum):
    RDI = ('rdi', 'dil')
    RSI = ('rsi', 'sil')
    RAX = ('rax', 'al')
    RBX = ('rbx', 'bl')
    RCX = ('rcx', 'cl')
    RDX = ('rdx', 'dl')
    RBP = ('rbp', 'bpl')
    R8 = ('r8', 'r8b')
    R9 = ('r9', 'r9b')
    R10 = ('r10', 'r10b')
    R11 = ('r11', 'r11b')
    R12 = ('r12', 'r12b')
    R13 = ('r13', 'r13b')
    R14 = ('r14', 'r14b')
    R15 = ('r15', 'r15b')

    def qword(self) -> str:
        return self.value[0]

    def byte(self) -> str:
        return self.value[1]
    
class CodeGen:
    def __init__(self):
        self._var_count = 0
        self._table_count = 0
        self._insns: list[Insn] = []

        self._table_out: Optional[io.TextIOBase] = None
        self._insn_out: Optional[io.TextIOBase] = None
        self._input_reg: Register = Register.RDI
        self._table_ptr: Register = Register.RSI
        self._table_idx: Register = Register.RBX
        self._tmp_reg: Register = Register.RCX
        self._gp_reg: list[Register] = []
        self._callee_saved: list[Register] = []
        self._randomize_slots = False
        self._randomize_tables = False

        self._insn_alloc: dict[Insn, int] = {}
        self._slots: list[tuple[Register, int]] = []
        self._table_lines: list[str] = []
    
    def _next_table_label(self) -> str:
        label = f't{self._table_count}'
        self._table_count += 1
        return label

    def add(self, insn: Insn) -> Insn:
        self._insns.append(insn)
        return insn
    


    def set_table_out(self, table_out: io.TextIOBase) -> 'CodeGen':
        self._table_out = table_out
        return self
    
    def set_insn_out(self, insn_out: io.TextIOBase) -> 'CodeGen':
        self._insn_out = insn_out
        return self
    
    def set_input_reg(self, input_reg: Register) -> 'CodeGen':
        self._input_reg = input_reg
        return self
    
    def set_table_ptr(self, table_ptr: Register) -> 'CodeGen':
        self._table_ptr = table_ptr
        return self
    
    def set_table_idx(self, table_idx: Register) -> 'CodeGen':
        self._table_idx = table_idx
        return self
    
    def set_tmp_reg(self, tmp_reg: Register) -> 'CodeGen':
        self._tmp_reg = tmp_reg
        return self
    
    def set_gp_reg(self, gp_reg: list[Register]) -> 'CodeGen':
        self._gp_reg = gp_reg
        return self
    
    def set_callee_saved(self, callee_saved: list[Register]) -> 'CodeGen':
        self._callee_saved = callee_saved
        return self
    
    def set_randomize_slots(self, randomize_slots: bool) -> 'CodeGen':
        self._randomize_slots = randomize_slots
        return self
    
    def set_randomize_tables(self, randomize_tables: bool) -> 'CodeGen':
        self._randomize_tables = randomize_tables
        return self



    def start_method(self, name: str):
        self._insn_out.write(f'{name}:\n')
        self._insns = []
        self._insn_alloc = {}
        self._slots = []
        self._table_lines = []

    def _analyze_deps(self):
        for insn in self._insns:
            for src in insn.src_insns():
                src.deps.append(insn)

    def _analyze_liveness(self):
        live_slots: list[int] = []
        insn_alloc: dict[Insn, int] = {}
        for insn in self._insns:
            if len(insn.deps) != 0:
                # Allocate a new slot for this instruction
                try:
                    index = live_slots.index(0)
                except ValueError:
                    index = len(live_slots)
                    live_slots.append(0)
                insn_alloc[insn] = index
                live_slots[index] = len(insn.deps)

            for src in insn.src_insns():
                assert src in insn_alloc, 'src must be allocated'
                live_slots[insn_alloc[src]] -= 1
        assert all((n == 0 for n in live_slots)), 'all slots must be empty'

        n_slots = len(live_slots)
        if self._randomize_slots:
            # Need to redo the allocation to randomize the indices
            live_slots = [0] * n_slots
            insn_alloc = {}
            for insn in self._insns:
                if len(insn.deps) != 0:
                    # Allocate a new random slot for this instruction
                    index = random.choice([i for i, n in enumerate(live_slots) if n == 0])
                    insn_alloc[insn] = index
                    live_slots[index] = len(insn.deps)

                for src in insn.src_insns():
                    assert src in insn_alloc, 'src must be allocated'
                    live_slots[insn_alloc[src]] -= 1
            assert all((n == 0 for n in live_slots)), 'all slots must be empty'

        return n_slots, insn_alloc
    
    def _emit_table(self, table_name: str, insn: Insn):
        line = f'{table_name} db '

        total_bits = sum((x.n_bits for x in insn.args))
        table_size = 1 << total_bits
        table_align_bits = _next_power_of_two(insn.n_bits)
        results_per_byte = 8 // table_align_bits

        table_byte = 0
        table_byte_n = 0

        args = [0] * len(insn.args)
        for i in range(table_size):
            for j, arg in enumerate(insn.args):
                args[j] = arg.sbox.decrypt(i & ((1 << arg.n_bits) - 1))
                i >>= arg.n_bits
            result = insn.sbox.encrypt(insn.op(*args))

            table_byte |= result << (table_byte_n * table_align_bits)
            table_byte_n += 1
            if table_byte_n == results_per_byte:
                line += f'{table_byte},'
                table_byte = 0
                table_byte_n = 0
        
        line += '\n'
        if self._randomize_tables:
            self._table_lines.append(line)
        else:
            self._table_out.write(line)

    def _emit_ptr_byte_load(self, dst: Register, src: Register, offset: int):
        if offset == 0:
            self._insn_out.write(f'mov {dst.byte()},[{src.qword()}]\n')
        else:
            self._insn_out.write(f'mov {dst.byte()},[{src.qword()}+{offset}]\n')

    def _emit_table_idx_shift_mask_add(self, reg: Register, start_shift: int, end_shift: int, n_bits: int):
        assert reg != self._table_ptr, 'table_ptr must not be used as a tmp reg'
        mask = ((1 << n_bits) - 1) << start_shift
        if _is_s32(mask):
            self._insn_out.write(f'and {reg.qword()},{_u32_to_s32(mask & 0xffffffff):#x}\n')
        else:
            self._insn_out.write(f'mov {self._table_ptr.qword()},{mask:#x}\n')
            self._insn_out.write(f'and {reg.qword()},{self._table_ptr.qword()}\n')
        shift = end_shift - start_shift
        if shift > 0:
            if shift < 4:
                self._insn_out.write(f'lea {self._table_idx.qword()},[{self._table_idx.qword()}+{reg.qword()}*{1 << shift}]\n')
            else:
                self._insn_out.write(f'shl {reg.qword()}, {shift}\n')
                self._insn_out.write(f'lea {self._table_idx.qword()},[{self._table_idx.qword()}+{reg.qword()}]\n')
        elif shift == 0:
            self._insn_out.write(f'lea {self._table_idx.qword()},[{self._table_idx.qword()}+{reg.qword()}]\n')
        elif shift < 0:
            self._insn_out.write(f'shr {reg.qword()}, {-shift}\n')
            self._insn_out.write(f'lea {self._table_idx.qword()},[{self._table_idx.qword()}+{reg.qword()}]\n')

    def _emit_load_value(self, value: Value, shift: int):
        if isinstance(value, InputU4):
            self._emit_ptr_byte_load(self._tmp_reg, self._input_reg, value.index // 2)
            self._emit_table_idx_shift_mask_add(self._tmp_reg, (value.index & 1) * 4, shift, value.n_bits)
        elif isinstance(value, Insn):
            slot_index = self._insn_alloc[value]
            if slot_index < len(self._slots):
                # Register load
                reg, reg_shift = self._slots[slot_index]
                self._insn_out.write(f'mov {self._tmp_reg.qword()},{reg.qword()}\n')
                self._emit_table_idx_shift_mask_add(self._tmp_reg, reg_shift, shift, value.n_bits)
            else:
                # Stack load
                stack_slot = slot_index - len(self._slots)
                byte = stack_slot // 2
                stack_shift = (stack_slot & 1) * 4
                self._insn_out.write(f'mov {self._tmp_reg.byte()},[rsp+{byte}]\n')
                self._emit_table_idx_shift_mask_add(self._tmp_reg, stack_shift, shift, value.n_bits)


    def _emit_lookup(self, table_name: str, insn: Insn):
        self._insn_out.write(f'xor {self._table_idx.qword()},{self._table_idx.qword()}\n')
        shift = 0
        for arg in insn.args:
            self._emit_load_value(arg, shift)
            shift += arg.n_bits

        table_align_bits = _next_power_of_two(insn.n_bits)
        results_per_byte = 8 // table_align_bits

        # Save lower bits of table index
        self._insn_out.write(f'mov {self._tmp_reg.qword()},{self._table_idx.qword()}\n')
        self._insn_out.write(f'and {self._tmp_reg.qword()},{results_per_byte - 1}\n')

        # Index into table
        self._insn_out.write(f'lea {self._table_ptr.qword()},[rel {table_name}]\n')
        self._insn_out.write(f'shr {self._table_idx.qword()},{_log_2(results_per_byte)}\n')
        self._insn_out.write(f'lea {self._table_ptr.qword()},[{self._table_ptr.qword()}+{self._table_idx.qword()}]\n')
        self._insn_out.write(f'mov {self._table_idx.byte()},[{self._table_ptr.qword()}]\n')

        # Mask out bits based off lower bits of table index
        assert self._tmp_reg == Register.RCX, 'tmp_reg must be RCX'
        if _is_power_of_two(table_align_bits):
            if table_align_bits != 1:
                self._insn_out.write(f'shl {self._tmp_reg.qword()},{_log_2(table_align_bits)}\n')
        else:
            self._insn_out.write(f'imul {self._tmp_reg.qword()},{table_align_bits}\n')
        self._insn_out.write(f'shr {self._table_idx.qword()},{self._tmp_reg.byte()}\n')
        self._insn_out.write(f'and {self._table_idx.qword()},{(1 << table_align_bits) - 1}\n')

        if len(insn.deps) == 0:
            # Insn is a sink, no need to store
            return

        # Now we have the result in _table_idx, write back to memory
        slot_index = self._insn_alloc[insn]
        if slot_index < len(self._slots):
            # Register store
            reg, shift = self._slots[slot_index]
            if shift != 0:
                self._insn_out.write(f'shl {self._table_idx.qword()},{shift}\n')
            mask = (~(((1 << insn.n_bits) - 1) << shift)) & ((1 << 64) - 1)
            if _is_s32(mask):
                self._insn_out.write(f'and {reg.qword()},{_u32_to_s32(mask & 0xffffffff):#x}\n')
            else:
                self._insn_out.write(f'mov {self._table_ptr.qword()},{mask:#x}\n')
                self._insn_out.write(f'and {reg.qword()},{self._table_ptr.qword()}\n')
            self._insn_out.write(f'or {reg.qword()},{self._table_idx.qword()}\n')
        else:
            # Stack store
            stack_slot = slot_index - len(self._slots)
            byte = stack_slot // 2
            shift = (stack_slot & 1) * 4
            if shift != 0:
                self._insn_out.write(f'shl {self._table_idx.qword()},{shift}\n')
            mask = (~(((1 << insn.n_bits) - 1) << shift)) & ((1 << 8) - 1)
            self._insn_out.write(f'and byte[rsp+{byte}],{mask}\n')
            self._insn_out.write(f'or[rsp+{byte}],{self._table_idx.byte()}\n')

    def emit_method(self):
        assert len({self._input_reg, self._table_ptr, self._table_idx, self._tmp_reg} & set(self._gp_reg)) == 0,\
            'table_ptr, table_idx, and tmp_reg must be different from gp_reg'
        assert Register.RAX not in self._callee_saved, 'return register (RAX) must not be callee saved'
        assert Register.RAX not in self._gp_reg, 'return register (RAX) must not be used as a general-purpose register'

        self._analyze_deps()
        n_slots, self._insn_alloc = self._analyze_liveness()

        used_regs: list[Register] = [self._table_ptr, self._table_idx, self._tmp_reg]
        self._slots = []
        for reg in self._gp_reg:
            for i in range(0, 64, 4):
                if len(self._slots) == n_slots:
                    break
                self._slots.append((reg, i))
                if reg not in used_regs:
                    used_regs.append(reg)
            if len(self._slots) == n_slots:
                break
        
        stack_slots = n_slots - len(self._slots)
        if stack_slots > 0:
            print(f'not enough registers, spilling {stack_slots} slots to stack')

        for reg in self._callee_saved:
            if reg not in used_regs:
                continue
            self._insn_out.write(f'push {reg.qword()}\n')
        if stack_slots > 0:
            self._insn_out.write(f'sub rsp,{_align((stack_slots + 1) // 2, 8)}\n')

        ret_val = None
        for insn in tqdm(self._insns):
            if isinstance(insn, RetInsn):
                ret_val = insn
                break

            if len(insn.deps) != 0:
                table_name = self._next_table_label()
                self._emit_table(table_name, insn)
                self._emit_lookup(table_name, insn)

        assert ret_val is not None, 'no return instruction found'
        self._insn_out.write(f'xor {self._table_idx.qword()},{self._table_idx.qword()}\n')
        for i, res in enumerate(ret_val.args):
            self._emit_load_value(res, i * 4)
        if self._table_idx != Register.RAX:
            self._insn_out.write(f'mov rax,{self._table_idx.qword()}\n')

        if stack_slots > 0:
            self._insn_out.write(f'add rsp,{_align((stack_slots + 1) // 2, 8)}\n')
        for reg in reversed(self._callee_saved):
            if reg not in used_regs:
                continue
            self._insn_out.write(f'pop {reg.qword()}\n')

        self._insn_out.write('ret\n')

        if self._randomize_tables:
            random.shuffle(self._table_lines)
            self._table_out.writelines(self._table_lines)
        