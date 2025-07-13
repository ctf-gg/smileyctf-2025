from pathlib import Path
import json
from hashlib import md5
from subprocess import run
import log
import os
from unicorn import (
    Uc,
    UC_ARCH_RISCV,
    UC_MODE_RISCV32,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_ALL,
)
from unicorn import riscv_const


class Testcase:
    def __init__(self, path: Path):
        self.path = path
        self.files = fuzz_dir / path.stem
        self.rom = self.files / "rom_file.mem"
        self.ram = self.files / "ram_file.mem"
        with open(self.path, "r") as fp:
            self.contents = fp.read().strip()
        self.hash = md5(
            str(self.path).encode() + b"/" + self.contents.encode()
        ).hexdigest()


class Results:
    def __init__(self, regs: list[int], mem: bytes):
        self.regs = regs
        self.mem = mem


def parse_mem(mem: list[str]):
    res = bytearray()

    for line in mem:
        if line.startswith("@"):
            offset = int(line[1:], 16)
        else:
            chunk = [int(part, 16).to_bytes(4, "little") for part in line.split()]
            chunk = b"".join(chunk)
            size = len(chunk)
            res = res.ljust(offset + size, b"\0")
            res[offset : offset + size] = chunk
            offset += size

    return bytes(res)


def execute_unicorn(case: Testcase):
    with open(case.rom, "r") as fp:
        code = parse_mem(fp.readlines())

    cpu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
    cpu.mem_map(CODE_ADDR, 0x1000)
    cpu.mem_map(RAM_ADDR, RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    cpu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    cpu.mem_write(CODE_ADDR, code.ljust(CODE_SIZE, b"\0"))
    cpu.mem_write(RAM_ADDR, b"\x00" * RAM_SIZE)
    cpu.mem_write(STACK_ADDR, b"\xcc" * STACK_SIZE)

    cpu.mem_protect(CODE_ADDR, CODE_SIZE, CODE_PERM)

    for reg in REGS:
        cpu.reg_write(reg, 0)

    cpu.emu_start(0, 128 * 4)
    # print(f"{cpu.reg_read(riscv_const.UC_RISCV_REG_PC) = :#x}")

    regs = [cpu.reg_read(reg) for reg in REGS]
    return Results(regs, b"")


def execute_verilator(case: Testcase):
    handle = run(
        [root / "obj_dir" / "TestBench"],
        cwd=case.files,
        capture_output=True,
        encoding="utf-8",
    )

    if handle.returncode != 0:
        return None

    output = handle.stdout.splitlines()
    regs = [None] * 32
    for line in output:
        if line.startswith("x"):
            reg, val = line.split(" = ")
            regs[int(reg[1:])] = int(val, 16)
    return Results(regs, b"")


root = Path(__file__).parent.parent
fuzz_dir = root / Path("fuzz")
hash_file = fuzz_dir / "hashes"
cc_environ = os.environ
cc_environ.setdefault("CFLAGS", "")
cc_environ["CFLAGS"] += " -mno-unaligned-access -O1 "

REG_NAMES = [f"UC_RISCV_REG_X{i}" for i in range(32)]
REGS = [getattr(riscv_const, name) for name in REG_NAMES]
PAGE_SIZE = 0x1000
CODE_ADDR = PAGE_SIZE * 0
CODE_SIZE = PAGE_SIZE
CODE_PERM = UC_PROT_READ | UC_PROT_EXEC
RAM_ADDR = PAGE_SIZE * 1
RAM_SIZE = PAGE_SIZE * 1
STACK_SIZE = PAGE_SIZE * 0x2
STACK_ADDR = PAGE_SIZE * 0x10 - STACK_SIZE

testcases_dir = root / "testcases"
testfiles = [*testcases_dir.glob("*.s"), *testcases_dir.glob("*.c")]
testcases = [Testcase(path) for path in testfiles]

fuzz_dir.mkdir(exist_ok=True)
for case in testcases:
    case.files.mkdir(exist_ok=True)

try:
    with open(hash_file, "r") as fp:
        hashes = set(json.load(fp))
except FileNotFoundError:
    hashes = set()

new_hashes: set[str] = set()
modified_testcases: list[Testcase] = []

for case in testcases:
    if case.hash not in hashes:
        modified_testcases.append(case)

    new_hashes.add(case.hash)

for case in modified_testcases:
    log.info(f"recompiling {case.path.name}")
    if case.path.suffix == ".c":
        env = cc_environ
    else:
        env = os.environ

    handle = run(
        ["python3", root / "tools" / "rom.py", case.path, case.rom, case.ram],
        capture_output=True,
        encoding="utf-8",
        env=env,
    )

    if handle.returncode != 0:
        log.warn(f"failed to compile {case.path.name}")
        print(handle.stderr)
        new_hashes.remove(case.hash)
        testcases.remove(case)

with open(hash_file, "w+") as fp:
    json.dump(list(new_hashes), fp)

log.info("recompiling verilator simulation")
handle = run(
    [
        "verilator",
        "--binary",
        "+1800-2017ext+sv",
        "CPU.h.sv",
        root / "src" / "Benches" / "BenchCPU.sv",
        "-DSIMULATION",
        "-Isrc",
        "-o",
        "TestBench",
        "--trace",
        "-j",
        "4",
    ],
    cwd=root,
    capture_output=True,
    encoding="utf-8",
)

if handle.returncode != 0:
    log.warn("failed to compile test bench")
    print(handle.stderr)
    exit(1)

log.info("done compiling verilator simulation")

for case in testcases:
    log.info(f"executing {case.path.name}")
    unicorn_results = execute_unicorn(case)
    verilator_results = execute_verilator(case)

    if unicorn_results is None:
        log.warn("unicorn failed to run")
        continue

    if verilator_results is None:
        log.warn("verilator failed to run")
        continue

    passing = True

    if unicorn_results.regs != verilator_results.regs:
        log.warn("\tregister mismatch!")
        for i, a, b in zip(
            range(len(REGS)), unicorn_results.regs, verilator_results.regs
        ):
            name = f"x{i}"
            if a != b:
                log.info(f"\t{name:<8} mismatch: 0x{a:08x} != 0x{b:08x}")
        passing = False

    if passing:
        log.info("\ttest passed!")
    else:
        log.info("\ttest failed!")
