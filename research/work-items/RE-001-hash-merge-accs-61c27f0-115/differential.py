"""Unicorn differential for RE-001-hash-merge-accs-61c27f0-115.

Usage (requires the real work binary materialized at
work/hl-node-115.bin, digest
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

    python3 research/work-items/RE-001-hash-merge-accs-61c27f0-115/differential.py

Maps the binary page containing the merge-accumulators body
(0x61c27f0, 152 bytes, no calls of any kind, so nothing needs
stubbing), builds the accumulator and secret windows in a
data region, and runs the body to a stack sentinel for every
case. Reported per case family and in total; any mismatch
aborts with the differing case.

Compared per case:
  * rax equals the Python model
    (tools/hash_merge_accs_61c27f0_115.py) exactly;
  * the whole data region is byte-identical afterwards (the
    body writes neither window);
  * the stack is byte-identical apart from the 8-byte slot
    the push %r12 writes (which must hold the r12 fill value
    afterwards), rsp is restored, and every callee-saved
    register survives (r12 in particular: the body pushes and
    pops it without ever writing it).

Case families: the golden vectors observed from the real
bytes (including both callers' exact +11 secret-pointer
geometry), a structured grid over accumulator / secret /
start patterns, a seeded random sweep, and read-extent
guards that place a window so it ends exactly at the end of
the mapped data region -- one byte of over-read in either
window would fault the emulation.
"""

import random
import struct
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
)

from hash_merge_accs_61c27f0_115 import (  # noqa: E402
    PRIME64_1, ROUTINE, merge_accs,
)
from test_hash_merge_accs_61c27f0_115 import (  # noqa: E402
    ACC_241, ACC_1024, ACC_2048, CUSTOM_WIN, DEFAULT_WIN,
)

MASK = 0xFFFFFFFFFFFFFFFF
BINARY = ROOT / "work" / "hl-node-115.bin"
CODE_PAGE = 0x61C2000
DATA = 0x40000000
DATA_SIZE = 0x10000
STACK = 0x7F000000
STACK_SIZE = 0x2000
SENTINEL = 0x90000000
R12_FILL = 0xA5A5A5A5A5A5A5A5
GP_REGS = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
           UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
           UC_X86_REG_RBP, UC_X86_REG_R8, UC_X86_REG_R9,
           UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
           UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
CALLEE_SAVED = [UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]

data = BINARY.read_bytes()
_raw = random.Random(0x61C27F0)


def rnd(nbytes):
    return bytes(_raw.getrandbits(8) for _ in range(nbytes))


def run_case(acc, secret_window, start, acc_off=0x0000,
             secret_off=0x1000, label=""):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_PAGE, 0x1000)
    uc.mem_write(CODE_PAGE, data[CODE_PAGE - 0x1000:CODE_PAGE - 0x1000 + 0x1000])
    region = bytearray(rnd(DATA_SIZE))
    region[acc_off:acc_off + 64] = b"".join(
        w.to_bytes(8, "little") for w in acc)
    region[secret_off:secret_off + 64] = bytes(secret_window)
    uc.mem_map(DATA, DATA_SIZE)
    uc.mem_write(DATA, bytes(region))
    stack = bytearray((i * 7 + 3) & 0xFF for i in range(STACK_SIZE))
    top = STACK + STACK_SIZE - 0x10
    stack[STACK_SIZE - 0x10:STACK_SIZE - 0x8] = struct.pack("<Q", SENTINEL)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_write(STACK, bytes(stack))
    uc.mem_map(SENTINEL, 0x1000)
    fills = {}
    for reg in GP_REGS:
        value = int.from_bytes(rnd(8), "little")
        fills[reg] = value
        uc.reg_write(reg, value)
    uc.reg_write(UC_X86_REG_R12, R12_FILL)
    fills[UC_X86_REG_R12] = R12_FILL
    uc.reg_write(UC_X86_REG_RDI, DATA + acc_off)
    uc.reg_write(UC_X86_REG_RSI, DATA + secret_off)
    uc.reg_write(UC_X86_REG_RDX, start)
    uc.reg_write(UC_X86_REG_RSP, top)
    uc.emu_start(ROUTINE, SENTINEL)

    want = merge_accs(tuple(acc), bytes(secret_window), start)
    got = uc.reg_read(UC_X86_REG_RAX)
    assert got == want, (label, hex(got), hex(want))
    assert bytes(uc.mem_read(DATA, DATA_SIZE)) == bytes(region), \
        (label, "data region written")
    after_stack = bytes(uc.mem_read(STACK, STACK_SIZE))
    want_stack = bytearray(stack)
    want_stack[STACK_SIZE - 0x18:STACK_SIZE - 0x10] = \
        struct.pack("<Q", R12_FILL)
    assert after_stack == bytes(want_stack), (label, "stack disturbed")
    assert uc.reg_read(UC_X86_REG_RSP) == top + 8, (label, "rsp")
    for reg in CALLEE_SAVED:
        assert uc.reg_read(reg) == fills[reg], (label, "callee-saved")
    return 1


def main():
    cases = 0
    # Golden vectors, observed from the real bytes; the 'u'
    # variants hand the secret pointer 11 bytes into a
    # 192-byte secret buffer, the exact caller geometry.
    golden = [
        (ACC_241, CUSTOM_WIN, (241 * PRIME64_1) & MASK, "golden-241"),
        (ACC_1024, CUSTOM_WIN, (1024 * PRIME64_1) & MASK, "golden-1024"),
        (ACC_2048, DEFAULT_WIN, (241 * PRIME64_1) & MASK, "golden-default"),
        ((0,) * 8, bytes(64), 0, "golden-zero"),
        (tuple(range(8)), bytes(range(64)), 1, "golden-counting"),
        ((MASK,) * 8, b"\xff" * 64, MASK, "golden-ones"),
        ((0,) * 8, bytes(64), PRIME64_1, "golden-start-only"),
    ]
    for acc, window, start, label in golden:
        cases += run_case(acc, window, start, label=label)
    for acc, window, start, label in (golden[0], golden[2]):
        buf = rnd(11) + bytes(window) + rnd(117)
        cases += run_case(acc, buf[11:75], start, secret_off=0x2000 + 11,
                          label=label + "-unaligned11")
        # The buffer around the window differs per run; the
        # model only ever sees the 64 bytes at the pointer.
    print("golden + caller geometry: %d cases" % cases)

    grid = 0
    acc_patterns = [
        (0,) * 8,
        (MASK,) * 8,
        tuple(range(8)),
        tuple(int.from_bytes(rnd(8), "little") for _ in range(8)),
    ]
    secret_patterns = [bytes(64), b"\xff" * 64, bytes(range(64)), rnd(64)]
    starts = [0, 1, PRIME64_1, MASK,
              int.from_bytes(rnd(8), "little")]
    for acc in acc_patterns:
        for window in secret_patterns:
            for start in starts:
                grid += run_case(acc, window, start, label="grid")
    cases += grid
    print("structured grid: %d cases" % grid)

    sweep = 0
    for i in range(200):
        acc = tuple(int.from_bytes(rnd(8), "little") for _ in range(8))
        window = rnd(64)
        start = int.from_bytes(rnd(8), "little")
        sweep += run_case(acc, window, start, label="sweep-%d" % i)
    cases += sweep
    print("random sweep: %d cases" % sweep)

    guards = 0
    acc = tuple(int.from_bytes(rnd(8), "little") for _ in range(8))
    window = rnd(64)
    guards += run_case(acc, window, 5, acc_off=DATA_SIZE - 64,
                       secret_off=0x1000, label="guard-acc-end")
    guards += run_case(acc, window, 5, acc_off=0x0000,
                       secret_off=DATA_SIZE - 64, label="guard-secret-end")
    guards += run_case(acc, window, 5, acc_off=DATA_SIZE - 64,
                       secret_off=DATA_SIZE - 192, label="guard-both-end")
    guards += run_case(acc, window, 5, acc_off=0x40,
                       secret_off=0x1040, label="guard-unaligned")
    cases += guards
    print("read-extent guards: %d cases" % guards)

    print("total: %d cases, 0 mismatches" % cases)


if __name__ == "__main__":
    main()
