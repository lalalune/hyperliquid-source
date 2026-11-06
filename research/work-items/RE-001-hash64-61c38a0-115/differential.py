"""Unicorn differential for RE-001-hash64-61c38a0-115.

Runs the window's real bytes (0x61c38a0..0x61c3bb9) under Unicorn
and compares rax against the Python model in
tools/hash64_61c38a0_115.py, case by case, over the lengths the
body finishes itself (0..128). The body makes no calls on those
arms, so nothing is stubbed.

Also checked per inline case: the input buffer is byte-identical
after the call, the callee-saved registers rbx, rbp, r12-r15
keep their sentinel values, rsp is balanced at the return, and
every memory read lands inside [data, data+len) or the stack
page. A separate page-edge class places the input so it ends
exactly at the end of a mapped page (the next page unmapped):
any read past data+len would fault the emulation.

For lengths 129..240 and 241+ the body never returns: it tail-
jumps out. Those cases stop the emulation at the jump target
and check the contract from this side: the target is
0x61c3230 with rdx zeroed (lengths 129..240) or 0x61c2890 with
the argument registers untouched (lengths 241+), with rdi/rsi
unchanged in both. The target bodies themselves are pinned by
their own packets (RE-001-hash-delegate-c3230-115 and the
contract cited in RE-001-hash-long-seed-61c2cb0-115) and are
not emulated here.

Requires the unicorn package (not part of the plain-python3
packet checker); run from the repository root with a python
that has it:

    python3 research/work-items/RE-001-hash64-61c38a0-115/differential.py

Prints per-class case counts and DIFFERENTIAL PASSED or the
first mismatches.
"""

import importlib.util
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")

FUNC = 0x61C38A0
DELEGATE = 0x61C3230
SEEDLESS = 0x61C2890

DATA = 0x2000000
STACK = 0x3000000
SENTINEL = 0x7FFFF000

spec = importlib.util.spec_from_file_location(
    "hash64_model",
    os.path.join(ROOT, "tools", "hash64_61c38a0_115.py"))
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
    # code: 0x61c2000..0x61c5000 covers the window and both
    # delegation targets' entry points
    uc.mem_map(0x61C2000, 0x3000)
    off = 0x61C2000 - 0x1000  # .text file offset = VA - 0x1000
    uc.mem_write(0x61C2000, data[off:off + 0x3000])
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


def _setup(uc, regs, payload, data_addr, rdx_value, pad=64):
    buf = bytes(payload)
    uc.mem_write(data_addr, buf + b"\xa5" * pad)
    rsp = STACK + 0x8000
    uc.mem_write(rsp, struct.pack("<Q", SENTINEL))
    uc.reg_write(regs["rsp"], rsp)
    uc.reg_write(regs["rdi"], data_addr)
    uc.reg_write(regs["rsi"], len(buf))
    uc.reg_write(regs["rdx"], rdx_value)
    for name in SAVED:
        uc.reg_write(regs[name], SENTINELS[name])
    return rsp


def run_inline(uc, regs, payload):
    from unicorn import UC_HOOK_MEM_READ
    buf = bytes(payload)
    rsp0 = _setup(uc, regs, buf, DATA, 0x1111111111111111)
    del READS[:]

    def on_read(uc_, access, address, size, value, user):
        READS.append((address, size))

    hook = uc.hook_add(UC_HOOK_MEM_READ, on_read)
    try:
        uc.emu_start(FUNC, SENTINEL, count=100000)
    finally:
        uc.hook_del(hook)
    rax = uc.reg_read(regs["rax"])
    if uc.reg_read(regs["rsp"]) != rsp0 + 8:
        return rax, "rsp not balanced at return"
    after = uc.mem_read(DATA, len(buf) + 64)
    if bytes(after) != buf + b"\xa5" * 64:
        return rax, "input buffer modified"
    for name in SAVED:
        if uc.reg_read(regs[name]) != SENTINELS[name]:
            return rax, "callee-saved %s clobbered" % name
    for addr, size in READS:
        ok = (DATA <= addr and addr + size <= DATA + len(buf)) or \
            (STACK <= addr and addr + size <= STACK + 0x10000)
        if not ok:
            return rax, "read outside input/stack: %s+%d" % (
                hex(addr), size)
    return rax, None


def run_edge(payload):
    """Fresh emulator with the input flush against a guard page."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RDI,
        UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RSP,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15)
    data = open(BIN, "rb").read()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x61C2000, 0x3000)
    off = 0x61C2000 - 0x1000
    uc.mem_write(0x61C2000, data[off:off + 0x3000])
    page = 0x4000000
    uc.mem_map(page, 0x1000)  # one page; the next page is unmapped
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(SENTINEL & ~0xFFF, 0x1000)
    regs = dict(rax=UC_X86_REG_RAX, rbx=UC_X86_REG_RBX,
                rbp=UC_X86_REG_RBP, rdi=UC_X86_REG_RDI,
                rsi=UC_X86_REG_RSI, rdx=UC_X86_REG_RDX,
                rsp=UC_X86_REG_RSP, r12=UC_X86_REG_R12,
                r13=UC_X86_REG_R13, r14=UC_X86_REG_R14,
                r15=UC_X86_REG_R15)
    buf = bytes(payload)
    addr = page + 0x1000 - len(buf)  # input ends at the page end
    _setup(uc, regs, buf, addr, 0, pad=0)
    try:
        uc.emu_start(FUNC, SENTINEL, count=100000)
    except Exception as exc:  # unmapped read/write = out-of-window access
        return None, "emulation fault at page edge: %s" % exc
    return uc.reg_read(regs["rax"]), None


def run_delegation(uc, regs, n, want_target, want_rdx):
    buf = bytes((i * 13 + 7) & 0xFF for i in range(n))
    rdx0 = 0xDEADBEEFCAFEF00D
    _setup(uc, regs, buf, DATA, rdx0)
    from unicorn.x86_const import UC_X86_REG_RIP
    uc.emu_start(FUNC, want_target, count=100000)
    if uc.reg_read(UC_X86_REG_RIP) != want_target:
        return "did not stop at the delegation target"
    if uc.reg_read(regs["rdi"]) != DATA:
        return "rdi changed before the jump"
    if uc.reg_read(regs["rsi"]) != n:
        return "rsi changed before the jump"
    got_rdx = uc.reg_read(regs["rdx"])
    if want_rdx == "zero" and got_rdx != 0:
        return "rdx not zeroed for the delegate: %s" % hex(got_rdx)
    if want_rdx == "untouched" and got_rdx != rdx0:
        return "rdx written on the seedless exit: %s" % hex(got_rdx)
    return None


def main():
    uc, regs = build_image()
    rng = random.Random(0x61C38A0)
    cases = []  # (label, payload)
    # every inline length under four structured payloads
    for n in range(0, 129):
        for pat in ("zero", "ff", "incr", "pat"):
            if pat == "zero":
                payload = bytes(n)
            elif pat == "ff":
                payload = b"\xff" * n
            elif pat == "incr":
                payload = bytes(i & 0xFF for i in range(n))
            else:
                payload = bytes((i * 31 + n) & 0xFF for i in range(n))
            cases.append(("len-sweep-%s" % pat, payload))
    # every inline length under two random payloads
    for n in range(0, 129):
        for _ in range(2):
            cases.append(("len-random", bytes(
                rng.randrange(256) for _ in range(n))))
    # high-bit / sign-sensitive payloads at the band edges
    for n in (1, 2, 3, 4, 5, 8, 9, 16, 17, 32, 33, 64, 65, 96, 97, 128):
        cases.append(("highbit", bytes(
            (0x80 | (i & 0x7F)) for i in range(n))))
        cases.append(("desc", bytes(
            (255 - i) & 0xFF for i in range(n))))
    # random fuzz inside the inline range
    for _ in range(300):
        n = rng.randrange(0, 129)
        cases.append(("fuzz", bytes(rng.randrange(256) for _ in range(n))))

    total = 0
    mismatches = []
    for label, payload in cases:
        total += 1
        rax, err = run_inline(uc, regs, payload)
        want = model.hash64(payload)
        if err or rax != want:
            mismatches.append((label, len(payload), hex(rax),
                               hex(want), err))
            if len(mismatches) >= 5:
                break
    print("inline cases: %d" % total)
    if mismatches:
        for m in mismatches:
            print("MISMATCH:", m)
        print("DIFFERENTIAL FAILED")
        return 1

    # page-edge class: the largest length of each band flush
    # against the end of a mapped page
    edge_total = 0
    for n in (1, 3, 8, 16, 32, 64, 96, 128):
        payload = bytes((i * 17 + 3) & 0xFF for i in range(n))
        edge_total += 1
        rax, err = run_edge(payload)
        if err or rax != model.hash64(payload):
            print("EDGE MISMATCH:", n, err)
            print("DIFFERENTIAL FAILED")
            return 1
    print("page-edge cases: %d" % edge_total)

    # delegation class: the two tail-jump exits
    deleg_total = 0
    for n in (129, 130, 143, 144, 200, 239, 240):
        deleg_total += 1
        err = run_delegation(uc, regs, n, DELEGATE, "zero")
        if err:
            print("DELEGATION MISMATCH:", n, err)
            print("DIFFERENTIAL FAILED")
            return 1
    for n in (241, 242, 300, 1024):
        deleg_total += 1
        err = run_delegation(uc, regs, n, SEEDLESS, "untouched")
        if err:
            print("DELEGATION MISMATCH:", n, err)
            print("DIFFERENTIAL FAILED")
            return 1
    print("delegation cases: %d" % deleg_total)
    print("DIFFERENTIAL PASSED (%d inline + %d page-edge + %d "
          "delegation cases, 0 mismatches)"
          % (total, edge_total, deleg_total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
