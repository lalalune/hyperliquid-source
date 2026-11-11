"""Unicorn differential for RE-001-hash-delegate-c3230-115.

Runs the window's real bytes (0x61c3230..0x61c3491) under Unicorn
and compares rax against the Python model in
tools/hash_delegate_c3230_115.py, case by case, over the whole
contract range (lengths 129..240 — the lengths the parent hash
callee at 0x61c3530 delegates here). The body is a leaf: it makes
no calls, so nothing is stubbed; the emulated image carries the
real .rodata secret table at 0x97df00 that the middle loop reads.

Also checked per case: the input buffer is byte-identical after
the call, the callee-saved registers rbx, rbp, r12-r15 keep their
sentinel values, and every memory read lands inside
[data, data+len), the secret table [0x97df00, 0x97dfc0), or the
stack page (the return address and the saved registers).

Requires the unicorn package (not part of the plain-python3 packet
checker); run from the repository root with a python that has it:

    python3 research/work-items/RE-001-hash-delegate-c3230-115/differential.py

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

FUNC = 0x61C3230
SECRET = 0x97DF00
SECRET_END = 0x97DFC0

DATA = 0x2000000
STACK = 0x3000000
SENTINEL = 0x7FFFF000

spec = importlib.util.spec_from_file_location(
    "hash_delegate_model",
    os.path.join(ROOT, "tools", "hash_delegate_c3230_115.py"))
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


def build_image():
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RDI,
        UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RSP,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15)
    data = open(BIN, "rb").read()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # code: 0x61c2000..0x61c4000 covers the window and both callers
    uc.mem_map(0x61C2000, 0x2000)
    off = 0x61C2000 - 0x1000  # .text file offset = VA - 0x1000
    uc.mem_write(0x61C2000, data[off:off + 0x2000])
    # .rodata: VA equals file offset in this image; the secret
    # table the middle loop reads lives at 0x97df00..0x97dfc0
    uc.mem_map(0x97D000, 0x2000)
    uc.mem_write(0x97D000, data[0x97D000:0x97D000 + 0x2000])
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

READS = []


def run_case(uc, regs, payload, seed):
    from unicorn import UC_HOOK_MEM_READ
    buf = bytes(payload)
    uc.mem_write(DATA, buf + b"\xa5" * 64)
    rsp = STACK + 0x8000
    uc.mem_write(rsp, struct.pack("<Q", SENTINEL))
    uc.reg_write(regs["rsp"], rsp)
    uc.reg_write(regs["rdi"], DATA)
    uc.reg_write(regs["rsi"], len(buf))
    uc.reg_write(regs["rdx"], seed)
    for name in SAVED:
        uc.reg_write(regs[name], SENTINELS[name])
    del READS[:]

    def on_read(uc_, access, address, size, value, user):
        READS.append((address, size))

    hook = uc.hook_add(UC_HOOK_MEM_READ, on_read)
    uc.emu_start(FUNC, SENTINEL, count=200000)
    uc.hook_del(hook)
    rax = uc.reg_read(regs["rax"])
    after = uc.mem_read(DATA, len(buf) + 64)
    if bytes(after) != buf + b"\xa5" * 64:
        return rax, "input buffer modified"
    for name in SAVED:
        if uc.reg_read(regs[name]) != SENTINELS[name]:
            return rax, "callee-saved %s clobbered" % name
    for addr, size in READS:
        ok = (DATA <= addr and addr + size <= DATA + len(buf)) or \
            (SECRET <= addr and addr + size <= SECRET_END) or \
            (STACK <= addr and addr + size <= STACK + 0x10000)
        if not ok:
            return rax, "read outside input/secret/stack: %s+%d" % (
                hex(addr), size)
    return rax, None


def main():
    uc, regs = build_image()
    rng = random.Random(0x61C3230)
    cases = []  # (label, payload, seed)
    fixed_seeds = [0, 1, 0xD28AAD72F49BD50B, 0xA5155AE5E937AA16,
                   0x77A00858DDD37F21, 0xFFFFFFFFFFFFFFFF]
    # every contract length 129..240 under two seeds, random payloads
    for n in range(129, 241):
        for seed in (0, 0xD28AAD72F49BD50B):
            cases.append(("len-sweep", bytes(rng.randrange(256)
                                             for _ in range(n)), seed))
    # structured payloads at the structural boundaries: the range
    # ends, the loop gate 143/144, and every stripe-count edge
    bounds = [129, 130, 143, 144, 145, 159, 160, 161, 175, 176,
              191, 192, 207, 208, 223, 224, 239, 240]
    for n in bounds:
        for seed in fixed_seeds:
            for pat in ("zero", "ff", "incr"):
                if pat == "zero":
                    payload = bytes(n)
                elif pat == "ff":
                    payload = b"\xff" * n
                else:
                    payload = bytes((i * 7 + 1) & 0xFF for i in range(n))
                cases.append(("boundary-%s" % pat, payload, seed))
    # seed 0 through the sibling entry's shape (seed forced to 0)
    for n in bounds:
        cases.append(("seed0", bytes(rng.randrange(256)
                                     for _ in range(n)), 0))
    # random fuzz inside the contract range
    for _ in range(300):
        n = rng.randrange(129, 241)
        cases.append(("fuzz", bytes(rng.randrange(256) for _ in range(n)),
                      rng.randrange(1 << 64)))

    total = 0
    mismatches = []
    for label, payload, seed in cases:
        total += 1
        rax, err = run_case(uc, regs, payload, seed)
        want = model.hash_delegate(payload, seed)
        if err or rax != want:
            mismatches.append((label, len(payload), hex(seed),
                               hex(rax), hex(want), err))
            if len(mismatches) >= 5:
                break
    print("cases: %d" % total)
    if mismatches:
        for m in mismatches:
            print("MISMATCH:", m)
        print("DIFFERENTIAL FAILED")
        return 1
    print("DIFFERENTIAL PASSED (%d cases, 0 mismatches)" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
