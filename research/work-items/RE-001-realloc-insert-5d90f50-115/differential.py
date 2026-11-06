"""Unicorn differential for RE-001-realloc-insert-5d90f50-115.

Runs the real binary window 0x5d90f50 under Unicorn against the
digest-verified work binary, with the PLT externals replaced by
deterministic oracles (operator new hands out addresses from a
fixed arena, operator delete only logs, memcpy/memmove perform the
real byte copy, __throw_length_error records its message string),
and compares the observable outcome with the Python model in
tools/realloc_insert_5d90f50_115.py: the ordered external-effect
log (new / delete / length-error), the three container fields after
the call, and the full contents of the freshly allocated buffer.

Run with a Python that has unicorn installed:
    python3 research/work-items/RE-001-realloc-insert-5d90f50-115/differential.py
Prints a per-case line and a summary; exit status 1 on any mismatch.
"""

import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from realloc_insert_5d90f50_115 import (  # noqa: E402
    LengthError, MAX_ELEMENTS, allocation_bytes, new_capacity_for_size)

BIN_PATH = os.path.join(ROOT, "work", "hl-node-115.bin")
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

GROW = 0x5D90F50
RET_ADDR = 0x64FF000

OBJ = 0x10080000          # the 24-byte container
VAL = 0x10090000          # the value slot (rdx)
BUF = 0x10100000          # the old element buffer
STACK_TOP = 0x7F0FF008
ALLOC_BASE = 0x40000000

PLT = {
    0x63F0A60: "memcpy",
    0x63F0A70: "memmove",
    0x63F0DD0: "new",
    0x63F0D80: "delete",
    0x63F0DE0: "throw_length",
}

SEGMENTS = ((0x0, 0x0, 0x1418254),
            (0x1418300, 0x1419300, 0x4FD88A0),
            (0x63F0BA0, 0x63F2BA0, 0x0FBE80),
            (0x64ECA20, 0x64EFA20, 0x0103E8))


class Oracle:
    """Deterministic allocator shared by both sides."""

    def __init__(self):
        self.log = []
        self.alloc_next = ALLOC_BASE

    def alloc(self, nbytes):
        addr = self.alloc_next
        self.alloc_next += max(0x1000, (nbytes + 0xFFF) & ~0xFFF)
        return addr


def model_run(spec, oracle):
    """Expected (outcome, log, container, new_buffer_bytes)."""
    elements, index, value, cap_elems, begin_null = spec
    size = len(elements)
    begin = 0 if begin_null else BUF
    end = begin + size * 8
    cap_end = begin + cap_elems * 8
    try:
        new_cap = new_capacity_for_size(size)
    except LengthError:
        return (("throw", "length_error"),
                [("length_message", "vector::_M_realloc_insert"),
                 ("throw", "length_error")],
                (begin, end, cap_end), None)
    alloc = allocation_bytes(new_cap)
    newbuf = oracle.alloc(alloc)
    oracle.log.append(("new", alloc))
    prefix = index * 8
    suffix = (size - index) * 8
    body = b"".join(struct.pack("<Q", e) for e in elements)
    new_body = (body[:prefix] + struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
                + body[prefix:])
    if begin != 0:
        oracle.log.append(("delete", begin, cap_end - begin))
    container = (newbuf, newbuf + prefix + 8 + suffix, newbuf + alloc)
    return ("return", oracle.log, container, new_body)


class Emu:
    def __init__(self, data):
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x0, 0x6800000)
        for off, va, sz in SEGMENTS:
            for k in range(0, sz, 0x100000):
                uc.mem_write(va + k, data[off + k:off + k + 0x100000])
        uc.mem_map(0x10000000, 0x200000)
        uc.mem_map(0x40000000, 0x200000)
        uc.mem_map(0x7F000000, 0x100000)
        uc.hook_add(UC_HOOK_CODE, self._hook)
        self.uc = uc
        self.status = None

    def _ret(self, uc):
        from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP
        rsp = uc.reg_read(UC_X86_REG_RSP)
        (target,) = struct.unpack("<Q", uc.mem_read(rsp, 8))
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    def _hook(self, uc, address, size, _):
        from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RDI,
                                       UC_X86_REG_RDX, UC_X86_REG_RIP,
                                       UC_X86_REG_RSI)
        if address == RET_ADDR:
            self.status = "return"
            uc.emu_stop()
            return
        name = PLT.get(address)
        if name is None:
            return
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        if name in ("memcpy", "memmove"):
            uc.mem_write(rdi, bytes(uc.mem_read(rsi, rdx)))
            uc.reg_write(UC_X86_REG_RAX, rdi)
            self._ret(uc)
        elif name == "new":
            self.oracle.log.append(("new", rdi))
            uc.reg_write(UC_X86_REG_RAX, self.oracle.alloc(rdi))
            self._ret(uc)
        elif name == "delete":
            self.oracle.log.append(("delete", rdi, rsi))
            self._ret(uc)
        elif name == "throw_length":
            raw = bytes(uc.mem_read(rdi, 64))
            msg = raw.split(b"\0")[0].decode()
            self.oracle.log.append(("length_message", msg))
            self.oracle.log.append(("throw", "length_error"))
            self.status = ("throw", "length_error")
            uc.emu_stop()

    def run(self, spec, oracle, force_size=None):
        from unicorn.x86_const import (UC_X86_REG_RDI, UC_X86_REG_RDX,
                                       UC_X86_REG_RIP, UC_X86_REG_RSI,
                                       UC_X86_REG_RSP)
        elements, index, value, cap_elems, begin_null = spec
        size = len(elements) if force_size is None else force_size
        uc = self.uc
        self.oracle = oracle
        self.status = None
        begin = 0 if begin_null else BUF
        end = begin + (size * 8) % (1 << 64)
        cap_end = begin + cap_elems * 8
        uc.mem_write(OBJ, struct.pack("<QQQ", begin, end, cap_end))
        if not begin_null:
            uc.mem_write(BUF, b"".join(struct.pack("<Q", e)
                                       for e in elements))
        uc.mem_write(VAL, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))
        uc.mem_write(STACK_TOP - 8, struct.pack("<Q", RET_ADDR))
        uc.reg_write(UC_X86_REG_RSP, STACK_TOP - 8)
        uc.reg_write(UC_X86_REG_RDI, OBJ)
        uc.reg_write(UC_X86_REG_RSI, begin + index * 8)
        uc.reg_write(UC_X86_REG_RDX, VAL)
        uc.emu_start(GROW, RET_ADDR, count=100000)
        if self.status is None:
            from unicorn.x86_const import UC_X86_REG_RIP
            if uc.reg_read(UC_X86_REG_RIP) == RET_ADDR:
                self.status = "return"
        container = struct.unpack("<QQQ", uc.mem_read(OBJ, 24))
        new_body = None
        if self.status == "return":
            new_body = bytes(uc.mem_read(container[0],
                                         (size + 1) * 8))
        return self.status, oracle.log, container, new_body


def build_cases():
    cases = [
        ("empty null begin", ([], 0, 0x1122334455667788, 0, True)),
        ("empty allocated begin", ([], 0, 7, 8, False)),
        ("append 3", ([10, 20, 30], 3, 40, 3, False)),
        ("middle 4", ([10, 20, 30, 40], 1, 99, 4, False)),
        ("front 2", ([10, 20], 0, 5, 2, False)),
        ("single append", ([1], 1, 2, 1, False)),
        ("single front", ([1], 0, 2, 1, False)),
        ("spare capacity still reallocates", ([1, 2, 3], 2, 9, 16, False)),
        ("17 elements middle", (list(range(100, 117)), 9, 0xDEADBEEF,
                                 17, False)),
    ]
    rng = random.Random(0x5D90F50)
    for i in range(24):
        n = rng.randrange(0, 25)
        elems = [rng.getrandbits(64) for _ in range(n)]
        idx = rng.randrange(0, n + 1) if n else 0
        cap = n if rng.random() < 0.5 else n + rng.randrange(0, 5)
        cases.append(("random %02d (n=%d idx=%d)" % (i, n, idx),
                      (elems, idx, rng.getrandbits(64), cap, False)))
    return [(name, spec, False) for name, spec in cases]


def main():
    import hashlib
    data = open(BIN_PATH, "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        print("BINARY DIGEST MISMATCH")
        return 1
    emu = Emu(data)
    failures = 0
    total = 0
    for name, spec, _ in build_cases():
        total += 1
        moracle = Oracle()
        want = model_run(spec, moracle)
        eoracle = Oracle()
        got = emu.run(spec, eoracle)
        ok = (got[0] == "return" and want[0] == "return"
              and got[1] == want[1] and got[2] == want[2]
              and got[3] == want[3])
        print("%-38s %s" % (name, "ok" if ok else "MISMATCH"))
        if not ok:
            failures += 1
            print("  want:", want)
            print("  got: ", got)
    # The length-error arm: a container whose (end - begin) >> 3 is
    # exactly the maximum element count. Only the three fields are
    # set up; the helper throws before touching any element.
    total += 1
    name = "length error at maximum size"
    spec = ([], 0, 1, 0, False)
    eoracle = Oracle()
    got = emu.run(spec, eoracle, force_size=MAX_ELEMENTS)
    want = (("throw", "length_error"),
            [("length_message", "vector::_M_realloc_insert"),
             ("throw", "length_error")],
            (BUF, BUF + (MAX_ELEMENTS * 8) % (1 << 64), BUF), None)
    ok = (got[0] == want[0] and got[1] == want[1] and got[2] == want[2])
    print("%-38s %s" % (name, "ok" if ok else "MISMATCH"))
    if not ok:
        failures += 1
        print("  want:", want)
        print("  got: ", got)
    print("%d cases, %d mismatches" % (total, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
