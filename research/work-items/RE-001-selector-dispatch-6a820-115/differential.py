#!/usr/bin/env python3
"""Unicorn differential for the RE-001 selector dispatch packet.

Runs the native window 0x5f6a820..0x5f6abac from work/hl-node-115.bin
under Unicorn against tools/selector_dispatch_6a820_115.py over directed
and seeded-random cases. The native callees are supplied at the exact
boundaries the packet states:

  * the compare oracle is installed behind both native routes: the
    fast route (user comparator vtable slot +0xd0 == 0x5d48410, calling
    [[cmp+0x20]+0x10] with (cmp+0x20, a, b)) and the slow route (the
    slot value itself, called with (cmp, a, 1, b, 1); the harness
    asserts the two literal 1 arguments on every slow call);
  * the key builder 0x5eaa060 is emulated at its entry with the
    contract pinned in the packet (append the record bytes, then the
    8 footer bytes ((packed << 8) | tag) little-endian, with the
    0x3fffffffffffffff capacity guard), maintaining the std::string
    object's data/size fields the native code reads back;
  * the find helper 0x5f69d00 is emulated at its entry returning the
    case's chosen index (its result is an oracle input, as in the
    model; its own 49 bytes and its division identity are pinned in
    the packet records);
  * std::string::_M_dispose (PLT) is a no-op: the emulated string
    buffer is harness scratch.

Usage: differential.py [seed] [random_cases]
Requires the unicorn package; exits nonzero on any mismatch.
"""
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from selector_dispatch_6a820_115 import SelectorDispatch  # noqa: E402

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_RSP, UC_X86_REG_RIP,
    UC_X86_REG_FS_BASE)

FUNC, FUNC_END = 0x5F6A820, 0x5F6ABAC
BUILDER, FIND = 0x5EAA060, 0x5F69D00
PLT_DISPOSE, PLT_CHKFAIL = 0x63F0DB0, 0x63F0D70
GUARD_SLOT = 0x64ECFB0
THUNK = 0x5D48410
STRING_MAX = 0x3FFFFFFFFFFFFFFF

HOOK_PAGE = 0x11110000
HOOK_FAST, HOOK_SLOW, EXIT = HOOK_PAGE, HOOK_PAGE + 0x10, HOOK_PAGE + 0x20
SCRATCH, SCRATCH_SIZE = 0x20000000, 0x200000
STACK, STACK_SIZE = 0x70000000, 0x100000
TLS = 0x40000000
CANARY = 0x1122334455667788


def bytewise(left, right):
    if left == right:
        return 0
    return -1 if left < right else 1


class LengthHit(Exception):
    pass


class Harness:
    def __init__(self, data):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc = self.uc
        uc.mem_map(FUNC & ~0xFFF, 0x2000)
        uc.mem_write(FUNC, data[FUNC - 0x1000:FUNC_END - 0x1000])
        # The find arm loads its footer tag byte from rodata 0x9702ab
        # (.rodata VMA == file offset there).
        uc.mem_map(0x970000, 0x1000)
        uc.mem_write(0x970000, data[0x970000:0x971000])
        for page in (BUILDER & ~0xFFF, FIND & ~0xFFF, PLT_DISPOSE & ~0xFFF,
                     GUARD_SLOT & ~0xFFF, HOOK_PAGE, SCRATCH, STACK, TLS):
            try:
                uc.mem_map(page, 0x100000 if page in (SCRATCH, STACK)
                           else 0x1000)
            except Exception:
                pass
        uc.mem_write(HOOK_PAGE, b"\xc3" * 0x100)
        uc.mem_write(GUARD_SLOT, struct.pack("<Q", THUNK))
        uc.mem_write(TLS + 0x28, struct.pack("<Q", CANARY))
        uc.reg_write(UC_X86_REG_FS_BASE, TLS)
        self.bump = SCRATCH + 0x1000
        self.strings = {}
        self.find_index = 0
        self.slow_args_ok = True
        uc.hook_add(UC_HOOK_CODE, self._hook)

    def alloc(self, size, align=16):
        ptr = (self.bump + align - 1) & ~(align - 1)
        self.bump = ptr + size
        return ptr

    def w64(self, addr, value):
        self.uc.mem_write(addr, struct.pack("<Q", value & (1 << 64) - 1))

    def r64(self, addr):
        return struct.unpack("<Q", self.uc.mem_read(addr, 8))[0]

    def _ret(self, uc):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = self.r64(rsp)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    def _slice(self, uc, ptr):
        data = self.r64(ptr)
        length = self.r64(ptr + 8)
        if length > (1 << 21):
            raise AssertionError("oracle slice too long: %#x" % length)
        return bytes(uc.mem_read(data, length))

    def _hook(self, uc, address, size, _ud):
        if address == EXIT:
            uc.emu_stop()
        elif address == BUILDER:
            self._build(uc)
            self._ret(uc)
        elif address == FIND:
            uc.reg_write(UC_X86_REG_RAX, self.find_index)
            self._ret(uc)
        elif address == HOOK_FAST:
            a = self._slice(uc, uc.reg_read(UC_X86_REG_RSI))
            b = self._slice(uc, uc.reg_read(UC_X86_REG_RDX))
            uc.reg_write(UC_X86_REG_RAX, bytewise(a, b) % (1 << 64))
            self._ret(uc)
        elif address == HOOK_SLOW:
            if uc.reg_read(UC_X86_REG_RDX) != 1 or \
                    uc.reg_read(UC_X86_REG_R8) != 1:
                self.slow_args_ok = False
            a = self._slice(uc, uc.reg_read(UC_X86_REG_RSI))
            b = self._slice(uc, uc.reg_read(UC_X86_REG_RCX))
            r = bytewise(a, b)
            uc.reg_write(UC_X86_REG_RAX, r % (1 << 64))
            self._ret(uc)
        elif address == PLT_DISPOSE:
            self._ret(uc)
        elif address == PLT_CHKFAIL:
            raise AssertionError("__stack_chk_fail reached")

    def _build(self, uc):
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        data, length = self.r64(rsi), self.r64(rsi + 8)
        packed, tag = self.r64(rsi + 0x10), uc.mem_read(rsi + 0x18, 1)[0]
        cur = self.strings.get(rdi, b"")
        if length > STRING_MAX - len(cur):
            raise LengthHit()
        body = bytes(uc.mem_read(data, length)) if length else b""
        if 8 > STRING_MAX - (len(cur) + length):
            raise LengthHit()
        built = cur + body + struct.pack(
            "<Q", ((packed << 8) | tag) & (1 << 64) - 1)
        buf = self.alloc(max(len(built), 1))
        uc.mem_write(buf, built)
        self.w64(rdi, buf)
        self.w64(rdi + 8, len(built))
        self.strings[rdi] = built

    def run_case(self, case):
        uc = self.uc
        self.bump = SCRATCH + 0x1000
        self.strings = {}
        self.slow_args_ok = True
        self.find_index = case["find_index"]
        cmpobj = self.alloc(0x40)
        userc = self.alloc(0x100)
        vt1 = self.alloc(0x100)
        vt2 = self.alloc(0x40)
        self.w64(cmpobj + 8, userc)
        self.w64(userc, vt1)
        self.w64(vt1 + 0xD0, THUNK if case["fast"] else HOOK_SLOW)
        self.w64(userc + 0x20, vt2)
        self.w64(vt2 + 0x10, HOOK_FAST)
        brief = self.alloc(0x10)
        entries_base = self.alloc(0x50 * max(case["count"], 1))
        self.w64(brief, case["count"])
        self.w64(brief + 8, entries_base)
        for i, (ka, kb) in enumerate(case["entries"]):
            entry = entries_base + i * 0x50
            for off, (buf, size) in ((0x30, ka), (0x40, kb)):
                ptr = self.alloc(max(len(buf), 1))
                if buf:
                    uc.mem_write(ptr, buf)
                self.w64(entry + off, ptr)
                self.w64(entry + off + 8, size)

        def slice_ptr(value):
            if value is None:
                return 0
            buf, length = value
            ptr = self.alloc(max(len(buf), 1))
            if buf:
                uc.mem_write(ptr, buf)
            rec = self.alloc(0x10)
            self.w64(rec, ptr)
            self.w64(rec + 8, length)
            return rec

        rsp = STACK + STACK_SIZE - 0x1000
        self.w64(rsp, EXIT)
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.reg_write(UC_X86_REG_RDI, cmpobj)
        uc.reg_write(UC_X86_REG_RSI, case["flag"])
        uc.reg_write(UC_X86_REG_RDX, brief)
        uc.reg_write(UC_X86_REG_RCX, slice_ptr(case["smallest"]))
        uc.reg_write(UC_X86_REG_R8, slice_ptr(case["largest"]))
        uc.emu_start(FUNC, EXIT, count=400000)
        if not self.slow_args_ok:
            raise AssertionError("slow-route literal arguments not (1, 1)")
        return uc.reg_read(UC_X86_REG_RAX) & (1 << 32) - 1


def model_result(case):
    def oracle(a, b):
        return bytewise(a[0][:a[1]], b[0][:b[1]])

    def find(_built):
        return case["find_index"]

    entries = [((ka[0], ka[1]), (kb[0], kb[1]))
               for ka, kb in case["entries"]]
    return SelectorDispatch(case["flag"], case["count"], entries,
                            case["smallest"], case["largest"],
                            oracle, find).run()


def gen_cases(rng, n_random):
    cases = []

    def key(user):
        return (user + bytes(rng.randrange(256) for _ in range(8)),
                len(user) + 8)

    def sl(user):
        return (user, len(user))

    directed = [
        dict(flag=0, count=0, entries=[], smallest=sl(b"a"),
             largest=sl(b"z"), find_index=0, fast=True),
        dict(flag=0, count=1, entries=[(key(b"b"), key(b"d"))],
             smallest=sl(b"d"), largest=sl(b"b"), find_index=0, fast=True),
        dict(flag=0, count=1, entries=[(key(b"b"), key(b"d"))],
             smallest=sl(b"d"), largest=sl(b"b"), find_index=0, fast=False),
        dict(flag=0, count=1, entries=[(key(b"m"), key(b"p"))],
             smallest=None, largest=None, find_index=0, fast=True),
        dict(flag=0, count=2,
             entries=[(key(b"m"), key(b"p")), (key(b"b"), key(b"d"))],
             smallest=None, largest=sl(b"a"), find_index=0, fast=False),
        dict(flag=1, count=1, entries=[(key(b"b"), key(b"d"))],
             smallest=sl(b"a"), largest=None, find_index=0, fast=True),
        dict(flag=2, count=1, entries=[(key(b"b"), key(b"d"))],
             smallest=sl(b"a"), largest=None, find_index=0, fast=False),
        dict(flag=1, count=2,
             entries=[(key(b"m"), key(b"p")), (key(b"b"), key(b"d"))],
             smallest=None, largest=sl(b"c"), find_index=0, fast=True),
        dict(flag=1, count=1, entries=[(key(b"b"), key(b"d"))],
             smallest=sl(b"a"), largest=sl(b"z"), find_index=5, fast=True),
        dict(flag=1, count=0, entries=[], smallest=sl(b"a"),
             largest=sl(b"z"), find_index=0, fast=False),
    ]
    cases.extend(directed)
    alphabet = b"abcdefgh"
    for _ in range(n_random):
        count = rng.randrange(0, 6)
        entries = []
        for _i in range(count):
            def uk():
                return bytes(rng.choice(alphabet)
                             for _ in range(rng.randrange(0, 5)))
            entries.append((key(uk()), key(uk())))

        def maybe_slice():
            if rng.random() < 0.25:
                return None
            user = bytes(rng.choice(alphabet)
                         for _ in range(rng.randrange(0, 5)))
            return (user, len(user))

        cases.append(dict(
            flag=rng.choice([0, 0, 1, 1, 2, 7]),
            count=count, entries=entries,
            smallest=maybe_slice(), largest=maybe_slice(),
            find_index=rng.randrange(0, count + 3),
            fast=rng.random() < 0.5))
    return cases


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 20261106
    n_random = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    data = open(os.path.join(ROOT, "work", "hl-node-115.bin"), "rb").read()
    harness = Harness(data)
    rng = random.Random(seed)
    cases = gen_cases(rng, n_random)
    for i, case in enumerate(cases):
        want = model_result(case)
        got = harness.run_case(case)
        if got != want:
            print("MISMATCH case %d: native=%r model=%r case=%r"
                  % (i, got, want, case))
            return 1
    print("DIFFERENTIAL OK: %d cases" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
