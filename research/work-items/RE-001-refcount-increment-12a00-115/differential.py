"""Unicorn differential for the RE-001-refcount-increment-12a00-115
packet: run the real 9 bytes of routine 0x5f12a00 from the
digest-verified work binary against the Python model
(tools/refcount_increment_12a00_115.py) on structured boundary
counts and randomised object images.

Per case: a 4 KiB object page is filled with random bytes, the
dword at +0x40 is set to the case count, every general-purpose
register except rsp/rdi is set to a random 64-bit value, and the
routine is emulated from its entry to its ret (a sentinel return
address). The differential then compares, byte for byte:

  * the whole object page -- it must equal the original image
    with exactly one change: the dword at +0x40 replaced by
    (count + 1) modulo 2**32 computed by the model;
  * every general-purpose register except rsp/rip -- the
    routine writes no register, so all of them (rax included)
    must be preserved exactly.

Run with a Python that has unicorn available, from the
repository root:

    python3 research/work-items/RE-001-refcount-increment-12a00-115/differential.py

Prints the case count and DIFFERENTIAL PASSED on success.
"""

import hashlib
import random
import struct
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT / "tools"))
from refcount_increment_12a00_115 import refcount_increment  # noqa: E402

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP,
)

ROUTINE = 0x5F12A00
ROUTINE_SIZE = 9
CODE_BASE = 0x5F12000
CODE_PAGE = 0x1000
OBJ_BASE = 0x40000000
OBJ_OFF = 0x200
OBJ_PAGE = 0x1000
STACK_BASE = 0x7F000000
STACK_PAGE = 0x1000
SENTINEL = 0x90000000

GP_REGS = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
           UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RBP,
           UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
           UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
           UC_X86_REG_R14, UC_X86_REG_R15]


def run_case(routine_bytes, image, count, reg_values, rng):
    obj_addr = OBJ_BASE + OBJ_OFF
    expected = bytearray(image)
    struct.pack_into("<I", expected, OBJ_OFF + 0x40,
                     refcount_increment(count))
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_BASE, CODE_PAGE)
    uc.mem_map(OBJ_BASE, OBJ_PAGE)
    uc.mem_map(STACK_BASE, STACK_PAGE)
    uc.mem_map(SENTINEL, 0x1000)
    uc.mem_write(CODE_BASE, bytes(CODE_PAGE))
    uc.mem_write(ROUTINE, routine_bytes)
    uc.mem_write(OBJ_BASE, bytes(image))
    stack_top = STACK_BASE + STACK_PAGE - 0x10
    uc.mem_write(stack_top, struct.pack("<Q", SENTINEL))
    for reg, value in reg_values.items():
        uc.reg_write(reg, value)
    uc.reg_write(UC_X86_REG_RDI, obj_addr)
    uc.reg_write(UC_X86_REG_RSP, stack_top)
    uc.emu_start(ROUTINE, SENTINEL)
    actual = uc.mem_read(OBJ_BASE, OBJ_PAGE)
    if bytes(actual) != bytes(expected):
        diff = [i for i in range(OBJ_PAGE)
                if actual[i] != expected[i]]
        raise AssertionError(
            "object page mismatch for count %#x at page offsets %s"
            % (count, [hex(d) for d in diff[:8]]))
    for reg, value in reg_values.items():
        if uc.reg_read(reg) != value:
            raise AssertionError(
                "register %s not preserved for count %#x" % (reg, count))
    if uc.reg_read(UC_X86_REG_RIP) != SENTINEL:
        raise AssertionError("routine did not return to the sentinel")


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit("work binary digest mismatch")
    routine_bytes = data[ROUTINE - 0x1000:ROUTINE - 0x1000 + ROUTINE_SIZE]
    if routine_bytes != bytes.fromhex("f30f1efa83474001c3"):
        raise SystemExit("routine bytes mismatch: %s"
                         % routine_bytes.hex())
    rng = random.Random(0x12A00)
    boundary = [0, 1, 2, 3, 0x40, 0x7FFFFFFF, 0x80000000,
                0x80000001, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF]
    cases = []
    for count in boundary:
        for _ in range(4):
            cases.append(count)
    for _ in range(660):
        cases.append(rng.getrandbits(32))
    for i, count in enumerate(cases):
        image = bytearray(rng.getrandbits(8) for _ in range(OBJ_PAGE))
        struct.pack_into("<I", image, OBJ_OFF + 0x40, count)
        reg_values = {reg: rng.getrandbits(64) for reg in GP_REGS}
        run_case(routine_bytes, image, count, reg_values, rng)
    print("%d cases, 0 mismatches" % len(cases))
    print("DIFFERENTIAL PASSED")


if __name__ == "__main__":
    main()
