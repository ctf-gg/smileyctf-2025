import log
from lief import ELF
from argparse import ArgumentParser, BooleanOptionalAction
from subprocess import run
from pathlib import Path
import os

"""
This is a small utility to convert assembly to verilog compatible mem files
"""


def write_memfile(path: str, start: int, data: bytes):
    with open(path, "w+") as fp:
        fp.write(f"@{start:08x}\n")

        words = [
            int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)
        ]
        words = [f"{word:08x}" for word in words]
        words = " ".join(words)
        fp.write(words)
        fp.write("\n")


parser = ArgumentParser(
    prog="rom",
)
parser.add_argument("file", type=str)
parser.add_argument("romfile", type=str)
parser.add_argument("ramfile", type=str)
# technically its an elf...
parser.add_argument("--elf", help="output elf binary", action=BooleanOptionalAction)
parser.add_argument("--zig", help="path to zig binary", type=str)
parser.add_argument(
    "--len", help="maximum number of instructions", type=int, default=4096
)

args = parser.parse_args()
file = Path(args.file)
romfile = Path(args.romfile)
ramfile = Path(args.ramfile)
zig = args.zig or "zig"
flags = os.environ.get("CFLAGS", "")

if not file.exists():
    log.error(f"{str(file)!r} does not exist!")

log.info("assembling to an elf file")

run(
    f"{zig} cc {str(file)} -mcpu=baseline_rv32-m-a-d-f-c-zicsr -target riscv32-freestanding -o {str(romfile)} {flags}",
    check=True,
    shell=True,
)

log.info("assembling done")

if args.elf:
    log.info("stopping after machine code emitted")
    exit(0)

log.info("extracting raw machine code")

elf = ELF.parse(romfile)
if elf is None:
    log.error("failed to parse ELF file, something is very wrong")

text = elf.get_section(".text")
initram = elf.get_section(".initram")
code = text.content

if len(code) % 4 != 0:
    log.error("code size is not a multiple of 4")

nop = b"\x13\x00\x00\x00"
missing = args.len - len(code) // 4
if missing < 0:
    log.error(f"code is longer than maximum length of {args.len}")
code = code.tobytes() + nop * missing

log.info("emitting verilog mem rom file")
write_memfile(romfile, 0, code)

if initram:
    data = initram.content.tobytes()
    adjusted = len(data) + 3 & ~3
    data = data.ljust(adjusted, b"\0")
else:
    data = b""

log.info("emitting verilog mem ram file")
log.info(f"0x{len(data):08x} bytes")
if len(data) >= 36 * 125 * 30:
    log.error("initram file is too large")
write_memfile(ramfile, 0, data)

log.info("finished")

# start = 0
# with open(outfile, "w+") as fp:
#     fp.write(f"@{start:08x}\n")

#     words = [int.from_bytes(code[i : i + 4], "little") for i in range(0, len(code), 4)]
#     words = [f"{word:08x}" for word in words]
#     words = " ".join(words)
#     fp.write(words)
#     fp.write("\n")
