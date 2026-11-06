"""Unicorn differential for RE-001-hash-callee-61c3530-115.

Runs the window's real bytes (0x61c3530..0x61c389d) under Unicorn
and compares rax against the Python model in
tools/hash_callee_61c3530_115.py, case by case. The two delegation
targets (0x61c3230 for lengths 129..240, 0x61c2cb0 for 241+) are
replaced in the emulated image by marker stubs (mov rax, marker;
ret), so the differential also pins the delegation boundaries and
targets exactly; the stubbed bodies themselves are not emulated.

Also checked per case: the input buffer is byte-identical after
the call, and the callee-saved registers rbx, rbp, r12-r15 keep
their sentinel values.

Requires the unicorn package (not part of the plain-python3 packet
checker); run from the repository root with a python that has it:

    python3 research/work-items/RE-001-hash-callee-61c3530-115/differential.py

Prints per-class case counts and DIFFERENTIAL PASSED or the first
mismatches.
"""

import importlib.util
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")

FUNC = 0x61C3530
FUNC_END = 0x61C389D
DELEGATE_MID = 0x61C3230
DELEGATE_LONG = 0x61C2CB0
MARK_MID = 0xD31E000000000001
MARK_LONG = 0xD31E000000000002

DATA = 0x2000000
STACK = 0x3000000
SENTINEL = 0x7FFFF000

spec = importlib.util.spec_from_file_location(
    "hash_callee_model",
    os.path.join(ROOT, "tools", "hash_callee_61c3530_115.py"))
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


def stub(marker):
    return b"\x48\xb8" + struct.pack("<Q", marker) + b"\xc3"


def build_image():
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RDI,
        UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RSP,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15)
    data = open(BIN, "rb").read()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # code: 0x61c2000..0x61c4000 covers all three FDEs of the family
    uc.mem_map(0x61C2000, 0x2000)
    off = 0x61C2000 - 0x1000  # .text file offset = VA - 0x1000
    uc.mem_write(0x61C2000, data[off:off + 0x2000])
    # stub the two delegation targets (bodies cited by contract)
    uc.mem_write(DELEGATE_MID, stub(MARK_MID))
    uc.mem_write(DELEGATE_LONG, stub(MARK_LONG))
    uc.mem_map(DATA, 0x10000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(SENTINEL & ~0xFFF, 0x1000)
    regs = dict(rax=UC_X86_REG_RAX, rbx=UC_X86_REG_RBX,
                rbp=UC_X86_REG_RBP, rdi=UC_X86_REG_RDI,
                rsi=UC_X86_REG_RSI, rdx=UC_X86_REG_RDX,
                rsp=UC_X86_REG_RSP, r12=UC_X86_REG_R12,
                r13=UC_X86_REG_R13, r14=UC_X86_REG_R14,
                r15=UC_X86_REG_R15)
    return uc, regs


SAVED = ("rbx", "rbp", "r12", "r13", "r14", "r15")
SENTINELS = {name: 0x5EED000000000000 + i for i, name in enumerate(SAVED)}


def run_case(uc, regs, payload, seed, data_ptr=None):
    buf = bytes(payload)
    uc.mem_write(DATA, buf + b"\xa5" * 64)
    rsp = STACK + 0x8000
    uc.mem_write(rsp, struct.pack("<Q", SENTINEL))
    uc.reg_write(regs["rsp"], rsp)
    uc.reg_write(regs["rdi"], DATA if data_ptr is None else data_ptr)
    uc.reg_write(regs["rsi"], len(buf))
    uc.reg_write(regs["rdx"], seed)
    for name in SAVED:
        uc.reg_write(regs[name], SENTINELS[name])
    uc.emu_start(FUNC, SENTINEL, count=200000)
    rax = uc.reg_read(regs["rax"])
    after = uc.mem_read(DATA, len(buf) + 64)
    if bytes(after) != buf + b"\xa5" * 64:
        return rax, "input buffer modified"
    for name in SAVED:
        if uc.reg_read(regs[name]) != SENTINELS[name]:
            return rax, "callee-saved %s clobbered" % name
    return rax, None


def main():
    uc, regs = build_image()
    rng = random.Random(0x61C3530)
    cases = []  # (label, payload, seed, data_ptr)
    fixed_seeds = [0, 1, 0xD28AAD72F49BD50B, 0xA5155AE5E937AA16,
                   0x77A00858DDD37F21, 0xFFFFFFFFFFFFFFFF]
    # every in-window length 0..128 under two seeds, random payloads
    for n in range(0, 129):
        for seed in (0, 0xD28AAD72F49BD50B):
            cases.append(("len-sweep", bytes(rng.randrange(256)
                                             for _ in range(n)), seed,
                          None))
    # structured payloads at band boundaries under all fixed seeds
    bounds = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33,
              47, 48, 63, 64, 65, 95, 96, 97, 127, 128]
    for n in bounds:
        for seed in fixed_seeds:
            for pat in ("zero", "ff", "incr"):
                if pat == "zero":
                    payload = bytes(n)
                elif pat == "ff":
                    payload = b"\xff" * n
                else:
                    payload = bytes((i * 7 + 1) & 0xFF for i in range(n))
                cases.append(("boundary-%s" % pat, payload, seed, None))
    # caller-seed shapes: the four fold seeds on slice-like inputs
    for seed in fixed_seeds[2:]:
        for n in (1, 8, 13, 40):
            cases.append(("fold-seed", bytes(rng.randrange(256)
                                             for _ in range(n)), seed,
                          None))
    # random fuzz inside the window
    for _ in range(300):
        n = rng.randrange(0, 129)
        cases.append(("fuzz", bytes(rng.randrange(256) for _ in range(n)),
                      rng.randrange(1 << 64), None))
    # length 0 with a null data pointer (never dereferenced)
    cases.append(("len0-null-ptr", b"", 0xA5155AE5E937AA16, 0))

    total = 0
    mismatches = []
    for label, payload, seed, ptr in cases:
        total += 1
        rax, err = run_case(uc, regs, payload, seed, ptr)
        want = model.hash_callee(payload, seed)
        if err or rax != want:
            mismatches.append((label, len(payload), hex(seed),
                               hex(rax), hex(want), err))
            if len(mismatches) >= 5:
                break

    # delegation: lengths above the window must land on the stubs
    deleg = 0
    for n in (129, 130, 200, 239, 240, 241, 242, 300, 1024, 8192):
        payload = bytes(rng.randrange(256) for _ in range(n))
        rax, err = run_case(uc, regs, payload, 7)
        want = MARK_MID if n <= 240 else MARK_LONG
        deleg += 1
        if err or rax != want:
            mismatches.append(("delegate", n, "7", hex(rax),
                               hex(want), err))
    print("in-window cases: %d, delegation cases: %d" % (total, deleg))
    if mismatches:
        for m in mismatches:
            print("MISMATCH:", m)
        print("DIFFERENTIAL FAILED")
        return 1
    print("DIFFERENTIAL PASSED (%d cases, 0 mismatches)"
          % (total + deleg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
