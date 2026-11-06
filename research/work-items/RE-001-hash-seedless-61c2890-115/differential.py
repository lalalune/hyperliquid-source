"""Unicorn differential for RE-001-hash-seedless-61c2890-115.

Runs the window's real bytes (0x61c2890..0x61c2cad) under Unicorn
and compares rax against the Python model in
tools/hash_seedless_61c2890_115.py, case by case, over the whole
contract range (lengths 241 and up — the lengths both entry tail
jumps gate on). The body's one call, to the merge routine at
0x61c27f0, executes for real inside the emulated image, as do the
stack-canary reads (the emulated page at address 0 carries the
canary value at offset 0x28, where %fs:0x28 resolves).

Also checked per case: the 64 accumulator bytes the body leaves
in its stack frame match the model's final_acc exactly, the
input buffer is byte-identical after the call, the callee-saved
registers rbx, rbp, r12-r15 keep their sentinel values, the
third argument register is ignored (a dedicated case class runs
one payload under four rdx values), and every memory read lands
inside [data, data+len), the secret table [0x97df00, 0x97dfc0),
the .rodata constant region the body's baked-in vectors live in,
the stack page, or the canary page.

Requires the unicorn package (not part of the plain-python3
packet checker); run from the repository root with a python that
has it:

    python3 research/work-items/RE-001-hash-seedless-61c2890-115/differential.py

Prints the case count and DIFFERENTIAL PASSED or the first
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

FUNC = 0x61C2890
SECRET = 0x97DF00
SECRET_END = 0x97DFC0
CONST_LO, CONST_HI = 0x450000, 0x458000

DATA = 0x2000000
STACK = 0x3000000
SENTINEL = 0x7FFFF000
CANARY = 0xC0FFEE1234567890

spec = importlib.util.spec_from_file_location(
    "hash_seedless_model",
    os.path.join(ROOT, "tools", "hash_seedless_61c2890_115.py"))
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
    # code: 0x61c2000..0x61c4000 covers the window and the merge
    # routine at 0x61c27f0 that it calls
    uc.mem_map(0x61C2000, 0x2000)
    off = 0x61C2000 - 0x1000  # .text file offset = VA - 0x1000
    uc.mem_write(0x61C2000, data[off:off + 0x2000])
    # .rodata: VA equals file offset in this image; the secret
    # table lives at 0x97df00..0x97dfc0 and the body's baked-in
    # constant vectors in the 0x450000..0x458000 region
    uc.mem_map(0x97D000, 0x2000)
    uc.mem_write(0x97D000, data[0x97D000:0x97D000 + 0x2000])
    uc.mem_map(CONST_LO, CONST_HI - CONST_LO)
    uc.mem_write(CONST_LO, data[CONST_LO:CONST_HI])
    # stack canary: %fs:0x28 resolves to linear address 0x28
    uc.mem_map(0x0, 0x1000)
    uc.mem_write(0x28, struct.pack("<Q", CANARY))
    uc.mem_map(DATA, 0x20000)
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


def run_case(uc, regs, payload, rdx_val):
    from unicorn import UC_HOOK_MEM_READ
    buf = bytes(payload)
    uc.mem_write(DATA, buf + b"\xa5" * 64)
    rsp = STACK + 0x8000
    uc.mem_write(rsp, struct.pack("<Q", SENTINEL))
    uc.reg_write(regs["rsp"], rsp)
    uc.reg_write(regs["rdi"], DATA)
    uc.reg_write(regs["rsi"], len(buf))
    uc.reg_write(regs["rdx"], rdx_val)
    for name in SAVED:
        uc.reg_write(regs[name], SENTINELS[name])
    del READS[:]

    def on_read(uc_, access, address, size, value, user):
        READS.append((address, size))

    hook = uc.hook_add(UC_HOOK_MEM_READ, on_read)
    try:
        uc.emu_start(FUNC, SENTINEL, count=5000000)
    finally:
        uc.hook_del(hook)
    rax = uc.reg_read(regs["rax"])
    after = uc.mem_read(DATA, len(buf) + 64)
    if bytes(after) != buf + b"\xa5" * 64:
        return rax, None, "input buffer modified"
    for name in SAVED:
        if uc.reg_read(regs[name]) != SENTINELS[name]:
            return rax, None, "callee-saved %s clobbered" % name
    for addr, size in READS:
        ok = (DATA <= addr and addr + size <= DATA + len(buf)) or \
            (SECRET <= addr and addr + size <= SECRET_END) or \
            (CONST_LO <= addr and addr + size <= CONST_HI) or \
            (STACK <= addr and addr + size <= STACK + 0x10000) or \
            (0 <= addr and addr + size <= 0x1000)
        if not ok:
            return rax, None, "read outside allowed: %s+%d" % (
                hex(addr), size)
    frame = uc.mem_read(rsp - 0x58, 64)
    acc_native = list(struct.unpack("<8Q", bytes(frame)))
    return rax, acc_native, None


def main():
    uc, regs = build_image()
    rng = random.Random(0x61C2890)
    cases = []  # (label, payload, rdx)

    def rnd(n):
        return bytes(rng.randrange(256) for _ in range(n))

    # every contract length 241..600, random payloads
    for n in range(241, 601):
        cases.append(("len-sweep", rnd(n), 0))
    # structural boundaries: the length % 64 == 0 lengths where
    # no final stripe runs, every remainder-stripe count, the
    # first full block and its scramble, multi-block lengths
    bounds = [241, 242, 255, 256, 257, 319, 320, 321, 383, 384, 385,
              447, 448, 512, 576, 640, 704, 768, 832, 896, 960,
              1023, 1024, 1025, 1087, 1088, 1089, 1152, 1216,
              2047, 2048, 2049, 2112, 2113, 3072, 4096, 4103, 8192]
    for n in bounds:
        for pat in ("zero", "ff", "incr", "pat"):
            if pat == "zero":
                payload = bytes(n)
            elif pat == "ff":
                payload = b"\xff" * n
            elif pat == "incr":
                payload = bytes((i & 0xFF) for i in range(n))
            else:
                payload = bytes(((i * 31 + n) & 0xFF) for i in range(n))
            cases.append(("boundary-%s" % pat, payload, 0))
    # the third argument register is never read: one payload
    # under four rdx values must give one result
    base = rnd(500)
    for rdxv in (0, 1, 0xDEADBEEFCAFEF00D, 0xFFFFFFFFFFFFFFFF):
        cases.append(("rdx-ignored", base, rdxv))
    # random fuzz across the contract range
    for _ in range(300):
        n = rng.randrange(241, 5001)
        cases.append(("fuzz", rnd(n), 0))

    total = 0
    mismatches = []
    for label, payload, rdxv in cases:
        total += 1
        rax, acc_native, err = run_case(uc, regs, payload, rdxv)
        want = model.hash_seedless(payload)
        want_acc = model.final_acc(payload)
        if err or rax != want or acc_native != want_acc:
            mismatches.append((label, len(payload), hex(rdxv),
                               hex(rax), hex(want),
                               acc_native == want_acc, err))
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
