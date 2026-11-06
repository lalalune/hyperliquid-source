"""Tests for tools/two_flag_callback_exits_115.py (node #115
callback exits 0x606a170 and 0x606a650).

Run with pytest, or directly: ``python3 tests/test_two_flag_callback_exits_115.py``
prints ALL TESTS PASSED when every check passes.

The first part pins the model against expectations read off the
disassembly by hand. The second part, when the ``unicorn`` package
is importable, differentially runs the real binary bytes for the
same cases plus randomised ones and compares the event log, the
final memory image and the outcome against the model; it prints
how many differential cases ran (zero when unicorn is absent).
"""

import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from two_flag_callback_exits_115 import (
    KNOWN_CHAIN_FN, KNOWN_NOTIFY_FN, NOTIFY_CALLS, CalleeThrow, Mem,
    ThrowSystemError, free_mem_with_cache, maybe_end_write_stall,
)

PACKET_DIR = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / "RE-001-two-flag-callback-exits-115"

ARENA = 0x10000000
MEM_SIZE = 0x40000
MASK64 = (1 << 64) - 1

# 0x606a170 layout: the holder, then five chain objects with their
# vtables. Object fields: +0x00 vtable, +0x18 mutex, +0x40 next.
THIS = ARENA + 0x0000
CHAIN = [ARENA + 0x1000 * (i + 1) for i in range(5)]
VTBL = [ARENA + 0x8000 + 0x100 * i for i in range(5)]
FAKE = [0x50000100 + 0x100 * i for i in range(5)]
OUT_PTR = ARENA + 0x9000

# 0x606a650 layout: the holder with its embedded list, elements and
# 0x18-byte nodes. Element fields: +0x00 vtable, +0x68 flag dword.
THIS2 = ARENA + 0x20000
ELEM = [ARENA + 0x21000 + 0x100 * i for i in range(4)]
EVTBL = [ARENA + 0x23000 + 0x100 * i for i in range(4)]
NODE = [ARENA + 0x22000 + 0x100 * i for i in range(4)]
LOCAL_HEAD = 0x20007FA8  # difftest: STACK_TOP - 0x58 (see below)


def build_170(flavours, total=100):
    """flavours: the +0x10 virtual of each chain object's vtable."""
    mem = Mem(ARENA, MEM_SIZE)
    mem.setq(THIS + 0x10, total)
    mem.setq(THIS + 0x20, CHAIN[0])
    for i, obj in enumerate(CHAIN):
        mem.setq(obj + 0x00, VTBL[i])
        mem.setq(VTBL[i] + 0x10, flavours[i])
        if i + 1 < len(CHAIN):
            mem.setq(obj + 0x40, CHAIN[i + 1])
    return mem


def build_650(flag98=1, flag99=1, total=5, limit=10, flavours=()):
    """flavours: one per list element; len(flavours) = list length."""
    mem = Mem(ARENA, MEM_SIZE)
    mem.setq(THIS2 + 0x00, limit)
    mem.setq(THIS2 + 0x10, total)
    mem.setbyte(THIS2 + 0x98, flag98)
    mem.setbyte(THIS2 + 0x99, flag99)
    sentinel = THIS2 + 0x58
    n = len(flavours)
    if n == 0:
        mem.setq(THIS2 + 0x58, sentinel)
        mem.setq(THIS2 + 0x60, sentinel)
        mem.setq(THIS2 + 0x68, 0)
        return mem
    mem.setq(THIS2 + 0x58, NODE[0])
    mem.setq(THIS2 + 0x60, NODE[n - 1])
    mem.setq(THIS2 + 0x68, n)
    for i in range(n):
        mem.setq(NODE[i] + 0x00, NODE[i + 1] if i + 1 < n else sentinel)
        mem.setq(NODE[i] + 0x08, NODE[i - 1] if i > 0 else sentinel)
        mem.setq(NODE[i] + 0x10, ELEM[i])
        mem.setq(ELEM[i] + 0x00, EVTBL[i])
        mem.setq(EVTBL[i] + 0x18, flavours[i])
    return mem


# ----------------------------------------------------------------
# 0x606a170 fixed cases
# ----------------------------------------------------------------

def test_170_l1_mismatch():
    mem = build_170([FAKE[0], KNOWN_CHAIN_FN, KNOWN_CHAIN_FN,
                     KNOWN_CHAIN_FN, KNOWN_CHAIN_FN])
    log = []
    ret = free_mem_with_cache(mem, log, THIS, 30)
    assert ret == 70
    assert mem.q(THIS + 0x10) == 70
    assert log == [("lock", THIS + 0x30, 0),
                   ("vcall", FAKE[0], CHAIN[0], 70),
                   ("unlock", THIS + 0x30)], log


def test_170_l2_mismatch_with_delete():
    mem = build_170([KNOWN_CHAIN_FN, FAKE[1], KNOWN_CHAIN_FN,
                     KNOWN_CHAIN_FN, KNOWN_CHAIN_FN])

    def chain_call(fn, out, obj, total):
        out.setq(0x08, OUT_PTR)
    log = []
    free_mem_with_cache(mem, log, THIS, 30, chain_call=chain_call)
    assert log == [("lock", THIS + 0x30, 0),
                   ("lock", CHAIN[0] + 0x18, 0),
                   ("vcall", FAKE[1], CHAIN[1], 70),
                   ("unlock", CHAIN[0] + 0x18),
                   ("delete_array", OUT_PTR),
                   ("unlock", THIS + 0x30)], log


def test_170_l4_mismatch():
    mem = build_170([KNOWN_CHAIN_FN] * 3 + [FAKE[3], KNOWN_CHAIN_FN])
    log = []
    free_mem_with_cache(mem, log, THIS, 30)
    assert log == [("lock", THIS + 0x30, 0),
                   ("lock", CHAIN[0] + 0x18, 0),
                   ("lock", CHAIN[1] + 0x18, 0),
                   ("lock", CHAIN[2] + 0x18, 0),
                   ("vcall", FAKE[3], CHAIN[3], 70),
                   ("unlock", CHAIN[2] + 0x18),
                   ("unlock", CHAIN[1] + 0x18),
                   ("unlock", CHAIN[0] + 0x18),
                   ("unlock", THIS + 0x30)], log


def test_170_full_descent():
    mem = build_170([KNOWN_CHAIN_FN] * 4 + [FAKE[4]])
    mem.setq(CHAIN[4] + 0x40, 0xDEADBEEF000)  # never dereferenced
    log = []
    free_mem_with_cache(mem, log, THIS, 30)
    assert log == [("lock", THIS + 0x30, 0),
                   ("lock", CHAIN[0] + 0x18, 0),
                   ("lock", CHAIN[1] + 0x18, 0),
                   ("lock", CHAIN[2] + 0x18, 0),
                   ("lock", CHAIN[3] + 0x18, 0),
                   ("vcall", FAKE[4], CHAIN[4], 70),
                   ("unlock", CHAIN[3] + 0x18),
                   ("unlock", CHAIN[2] + 0x18),
                   ("unlock", CHAIN[1] + 0x18),
                   ("unlock", CHAIN[0] + 0x18),
                   ("unlock", THIS + 0x30)], log


def test_170_outer_lock_fail():
    mem = build_170([FAKE[0]] + [KNOWN_CHAIN_FN] * 4)
    log = []
    try:
        free_mem_with_cache(mem, log, THIS, 30,
                            lock_fail={THIS + 0x30: 11})
        raise AssertionError("expected ThrowSystemError")
    except ThrowSystemError as exc:
        assert exc.code == 11
    assert log == [("lock", THIS + 0x30, 11), ("throw", 11)], log
    assert mem.q(THIS + 0x10) == 100  # subtract never ran


def test_170_l2_lock_fail():
    mem = build_170([KNOWN_CHAIN_FN] * 5)
    log = []
    try:
        free_mem_with_cache(mem, log, THIS, 30,
                            lock_fail={CHAIN[1] + 0x18: 22})
        raise AssertionError("expected ThrowSystemError")
    except ThrowSystemError as exc:
        assert exc.code == 22
    assert log == [("lock", THIS + 0x30, 0),
                   ("lock", CHAIN[0] + 0x18, 0),
                   ("lock", CHAIN[1] + 0x18, 22),
                   ("throw", 22),
                   ("unlock", CHAIN[0] + 0x18),
                   ("unlock", THIS + 0x30)], log
    assert mem.q(THIS + 0x10) == 70  # subtract already applied


def test_170_l4_lock_fail():
    mem = build_170([KNOWN_CHAIN_FN] * 4 + [FAKE[4]])
    log = []
    try:
        free_mem_with_cache(mem, log, THIS, 30,
                            lock_fail={CHAIN[3] + 0x18: 33})
        raise AssertionError("expected ThrowSystemError")
    except ThrowSystemError as exc:
        assert exc.code == 33
    assert log == [("lock", THIS + 0x30, 0),
                   ("lock", CHAIN[0] + 0x18, 0),
                   ("lock", CHAIN[1] + 0x18, 0),
                   ("lock", CHAIN[2] + 0x18, 0),
                   ("lock", CHAIN[3] + 0x18, 33),
                   ("throw", 33),
                   ("unlock", CHAIN[2] + 0x18),
                   ("unlock", CHAIN[1] + 0x18),
                   ("unlock", CHAIN[0] + 0x18),
                   ("unlock", THIS + 0x30)], log


def test_170_wrap():
    mem = build_170([FAKE[0]] + [KNOWN_CHAIN_FN] * 4, total=5)
    log = []
    ret = free_mem_with_cache(mem, log, THIS, 10)
    assert ret == (5 - 10) & MASK64
    assert log[1] == ("vcall", FAKE[0], CHAIN[0], (5 - 10) & MASK64)


def test_170_vcall_throw_l3():
    mem = build_170([KNOWN_CHAIN_FN, KNOWN_CHAIN_FN, FAKE[2],
                     KNOWN_CHAIN_FN, KNOWN_CHAIN_FN])

    def chain_call(fn, out, obj, total):
        raise CalleeThrow()
    log = []
    try:
        free_mem_with_cache(mem, log, THIS, 30, chain_call=chain_call)
        raise AssertionError("expected CalleeThrow")
    except CalleeThrow:
        pass
    assert log == [("lock", THIS + 0x30, 0),
                   ("lock", CHAIN[0] + 0x18, 0),
                   ("lock", CHAIN[1] + 0x18, 0),
                   ("vcall", FAKE[2], CHAIN[2], 70),
                   ("unlock", CHAIN[1] + 0x18),
                   ("unlock", CHAIN[0] + 0x18),
                   ("unlock", THIS + 0x30)], log


# ----------------------------------------------------------------
# 0x606a650 fixed cases
# ----------------------------------------------------------------

def test_650_gated_flag():
    mem = build_650(flag98=0, flavours=[KNOWN_NOTIFY_FN])
    log = []
    assert maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD) == \
        "gated_flag"
    assert log == []


def test_650_gated_total():
    for total, limit in [(10, 10), (11, 10), (MASK64, 1)]:
        mem = build_650(total=total, limit=limit,
                        flavours=[KNOWN_NOTIFY_FN])
        log = []
        assert maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD) == \
            "gated_total"
        assert log == []


def test_650_idle():
    mem = build_650(flag99=0, flavours=[KNOWN_NOTIFY_FN])
    log = []
    assert maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD) == "idle"
    assert log == [("lock", THIS2 + 0x70, 0),
                   ("unlock", THIS2 + 0x70)], log
    assert mem.q(THIS2 + 0x58) == NODE[0]  # list untouched
    assert mem.q(THIS2 + 0x68) == 1


def test_650_drain_empty():
    mem = build_650(flavours=[])
    log = []
    assert maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD) == \
        "drained"
    assert log == [("lock", THIS2 + 0x70, 0),
                   ("unlock", THIS2 + 0x70)], log
    assert mem.byte(THIS2 + 0x99) == 0


def test_650_drain_three():
    mem = build_650(flavours=[KNOWN_NOTIFY_FN, FAKE[0], KNOWN_NOTIFY_FN])
    log = []
    assert maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD) == \
        "drained"
    n0, n1, n2 = NOTIFY_CALLS
    e0, e1, e2 = ELEM[0], ELEM[1], ELEM[2]
    assert log == [("lock", THIS2 + 0x70, 0),
                   ("ncall", n0, e0 + 0x08), ("ncall", n1, e0 + 0x08),
                   ("ncall", n2, e0 + 0x30),
                   ("vcall1", FAKE[0], e1),
                   ("ncall", n0, e2 + 0x08), ("ncall", n1, e2 + 0x08),
                   ("ncall", n2, e2 + 0x30),
                   ("unlock", THIS2 + 0x70),
                   ("delete", NODE[0], 0x18), ("delete", NODE[1], 0x18),
                   ("delete", NODE[2], 0x18)], log
    assert mem.dword(ELEM[0] + 0x68) == 1
    assert mem.dword(ELEM[1] + 0x68) == 0
    assert mem.dword(ELEM[2] + 0x68) == 1
    assert mem.byte(THIS2 + 0x99) == 0
    sentinel = THIS2 + 0x58
    assert mem.q(THIS2 + 0x58) == sentinel
    assert mem.q(THIS2 + 0x60) == sentinel
    assert mem.q(THIS2 + 0x68) == 0
    assert mem.q(NODE[2] + 0x00) == LOCAL_HEAD  # splice relinks
    assert mem.q(NODE[0] + 0x08) == LOCAL_HEAD


def test_650_lock_fail():
    mem = build_650(flavours=[KNOWN_NOTIFY_FN])
    log = []
    try:
        maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD,
                              lock_fail={THIS2 + 0x70: 11})
        raise AssertionError("expected ThrowSystemError")
    except ThrowSystemError as exc:
        assert exc.code == 11
    assert log == [("lock", THIS2 + 0x70, 11), ("throw", 11)], log
    assert mem.byte(THIS2 + 0x99) == 1  # flag clear never ran


def test_650_vcall_throw():
    mem = build_650(flavours=[KNOWN_NOTIFY_FN, FAKE[0]])

    def notify_call(fn, elem):
        raise CalleeThrow()
    log = []
    try:
        maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD,
                              notify_call=notify_call)
        raise AssertionError("expected CalleeThrow")
    except CalleeThrow:
        pass
    assert log[-1] == ("unlock", THIS2 + 0x70)
    assert not any(e[0] == "delete" for e in log)
    assert mem.byte(THIS2 + 0x99) == 0  # cleared before the walk
    assert mem.q(THIS2 + 0x58) == NODE[0]  # list not spliced
    assert mem.q(THIS2 + 0x68) == 2


# ----------------------------------------------------------------
# Unicorn differential (runs only when unicorn is importable)
# ----------------------------------------------------------------

STACK_TOP = 0x20008000
STOP_ADDR = 0x40000000
PLT_LOCK = 0x63F0B60
PLT_UNLOCK = 0x63F0B70
PLT_DELETE_ARRAY = 0x63F0DC0
PLT_DELETE = 0x63F0D80
PLT_THROW = 0x63F0F90
PLT_CHK_FAIL = 0x63F0D70
FAKE_LO, FAKE_HI = 0x50000000, 0x50010000


def _model_170(spec):
    mem = build_170(spec["flavours"], total=spec["total"])

    def chain_call(fn, out, obj, total):
        if spec.get("vcall_throw_at") == fn:
            raise CalleeThrow()
        if spec.get("vcall_out8"):
            out.setq(0x08, spec["vcall_out8"])
    log = []
    try:
        free_mem_with_cache(mem, log, THIS, spec["size"],
                            lock_fail=spec.get("lock_fail"),
                            chain_call=chain_call)
        outcome = "returned"
    except ThrowSystemError as exc:
        outcome = ("throw", exc.code)
    except CalleeThrow:
        outcome = "callee_throw"
    return mem, log, outcome


def _model_650(spec):
    mem = build_650(flag98=spec["flag98"], flag99=spec["flag99"],
                    total=spec["total"], limit=spec["limit"],
                    flavours=spec["flavours"])

    def notify_call(fn, elem):
        if spec.get("vcall_throw_elem") == elem:
            raise CalleeThrow()

    def direct_call(target, arg):
        if spec.get("ncall_throw") == target:
            raise CalleeThrow()
    log = []
    try:
        maybe_end_write_stall(mem, log, THIS2, LOCAL_HEAD,
                              lock_fail=spec.get("lock_fail"),
                              notify_call=notify_call,
                              direct_call=direct_call)
        outcome = "returned"
    except ThrowSystemError as exc:
        outcome = ("throw", exc.code)
    except CalleeThrow:
        outcome = "callee_throw"
    return mem, log, outcome


class _Emu:
    def __init__(self):
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
        from unicorn.x86_const import (
            UC_X86_REG_FS_BASE, UC_X86_REG_RAX, UC_X86_REG_RDI,
            UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSI,
            UC_X86_REG_RSP)
        self.consts = dict(RAX=UC_X86_REG_RAX, RDI=UC_X86_REG_RDI,
                           RSI=UC_X86_REG_RSI, RDX=UC_X86_REG_RDX,
                           RIP=UC_X86_REG_RIP, RSP=UC_X86_REG_RSP)
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc = uc
        data = (Path(__file__).resolve().parents[1] / "work" /
                "hl-node-115.bin").read_bytes()
        uc.mem_map(0, 0x6600000)
        uc.mem_write(0x1000, data)
        uc.mem_write(0x64ECE40, struct.pack("<Q", KNOWN_CHAIN_FN))
        uc.mem_write(0x64ED568, struct.pack("<Q", KNOWN_NOTIFY_FN))
        uc.mem_map(ARENA, MEM_SIZE)
        uc.mem_map(0x20000000, 0x10000)
        uc.mem_map(STOP_ADDR, 0x1000)
        uc.mem_map(0x30000000, 0x1000)
        uc.mem_write(0x30000028, struct.pack("<Q", 0x1122334455667788))
        uc.reg_write(UC_X86_REG_FS_BASE, 0x30000000)
        uc.mem_map(FAKE_LO, FAKE_HI - FAKE_LO)
        self.st = {}
        uc.hook_add(UC_HOOK_CODE, self._hook)

    def _ret(self):
        uc, c = self.uc, self.consts
        rsp = uc.reg_read(c["RSP"])
        rip = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(c["RSP"], rsp + 8)
        uc.reg_write(c["RIP"], rip)

    def _unwind_stop(self):
        st = self.st
        for addr in reversed(st["held"]):
            st["log"].append(("unlock", addr))
        st["outcome"] = "callee_throw"
        self.uc.emu_stop()

    def _hook(self, uc, pc, size, _ud):
        c, st = self.consts, self.st
        if pc == STOP_ADDR:
            st["outcome"] = "returned"
            uc.emu_stop()
        elif pc == PLT_LOCK:
            rdi = uc.reg_read(c["RDI"])
            rc = st["lock_fail"].get(rdi, 0)
            st["log"].append(("lock", rdi, rc))
            if rc == 0:
                st["held"].append(rdi)
            uc.reg_write(c["RAX"], rc)
            self._ret()
        elif pc == PLT_UNLOCK:
            rdi = uc.reg_read(c["RDI"])
            st["log"].append(("unlock", rdi))
            if rdi in st["held"]:
                st["held"].remove(rdi)
            uc.reg_write(c["RAX"], 0)
            self._ret()
        elif pc == PLT_DELETE_ARRAY:
            st["log"].append(("delete_array", uc.reg_read(c["RDI"])))
            self._ret()
        elif pc == PLT_DELETE:
            st["log"].append(("delete", uc.reg_read(c["RDI"]),
                              uc.reg_read(c["RSI"])))
            self._ret()
        elif pc == PLT_THROW:
            code = uc.reg_read(c["RDI"]) & 0xFFFFFFFF
            st["log"].append(("throw", code))
            # The LSDA row for each throw call site assigns a pad
            # that unlocks exactly the mutexes held at that point,
            # in reverse acquisition order (none for the outer
            # mutex's own failure, whose row has no pad).
            for addr in reversed(st["held"]):
                st["log"].append(("unlock", addr))
            st["outcome"] = ("throw", code)
            uc.emu_stop()
        elif pc == PLT_CHK_FAIL:
            st["outcome"] = "canary_fail"
            uc.emu_stop()
        elif pc in NOTIFY_CALLS:
            st["log"].append(("ncall", pc, uc.reg_read(c["RDI"])))
            if st.get("ncall_throw") == pc:
                self._unwind_stop()
            else:
                self._ret()
        elif FAKE_LO <= pc < FAKE_HI:
            if st["mode"] == 170:
                st["log"].append(("vcall", pc, uc.reg_read(c["RSI"]),
                                  uc.reg_read(c["RDX"])))
                if st.get("vcall_throw_at") == pc:
                    self._unwind_stop()
                    return
                if st.get("vcall_out8"):
                    uc.mem_write(uc.reg_read(c["RDI"]) + 8,
                                 struct.pack("<Q", st["vcall_out8"]))
            else:
                st["log"].append(("vcall1", pc, uc.reg_read(c["RDI"])))
                if st.get("vcall_throw_elem") == \
                        uc.reg_read(c["RDI"]):
                    self._unwind_stop()
                    return
            self._ret()

    def run(self, mode, spec, init_image, entry, arg2=0):
        uc, c = self.uc, self.consts
        uc.mem_write(ARENA, init_image)
        uc.mem_write(STACK_TOP - 0x200, bytes(0x200))
        uc.mem_write(STACK_TOP, struct.pack("<Q", STOP_ADDR))
        st = {"mode": mode, "log": [], "held": [], "outcome": None,
              "lock_fail": spec.get("lock_fail") or {},
              "vcall_throw_at": spec.get("vcall_throw_at"),
              "vcall_out8": spec.get("vcall_out8"),
              "vcall_throw_elem": spec.get("vcall_throw_elem"),
              "ncall_throw": spec.get("ncall_throw")}
        self.st = st
        uc.reg_write(c["RSP"], STACK_TOP)
        uc.reg_write(c["RDI"], THIS if mode == 170 else THIS2)
        uc.reg_write(c["RSI"], arg2)
        try:
            uc.emu_start(entry, STOP_ADDR, count=400000)
        except Exception as exc:  # unicorn.UcError
            st["outcome"] = "crash: %s" % exc
        if st["outcome"] is None and \
                uc.reg_read(c["RIP"]) == STOP_ADDR:
            st["outcome"] = "returned"
        return bytes(uc.mem_read(ARENA, MEM_SIZE)), st["log"], \
            st["outcome"]


def _check_case(emu, mode, spec):
    if mode == 170:
        mem, log, outcome = _model_170(spec)
        init = bytes(build_170(spec["flavours"],
                               total=spec["total"]).buf)
        image, elog, eoutcome = emu.run(170, spec, init, 0x606A170,
                                        arg2=spec["size"])
    else:
        mem, log, outcome = _model_650(spec)
        init = bytes(build_650(flag98=spec["flag98"],
                               flag99=spec["flag99"],
                               total=spec["total"],
                               limit=spec["limit"],
                               flavours=spec["flavours"]).buf)
        image, elog, eoutcome = emu.run(650, spec, init, 0x606A650)
    assert elog == log, (mode, spec, elog, log)
    assert eoutcome == outcome, (mode, spec, eoutcome, outcome)
    assert image == bytes(mem.buf), (mode, spec, "memory diverged")


def differential_cases():
    try:
        import unicorn  # noqa: F401
    except ImportError:
        return 0
    emu = _Emu()
    count = 0
    fixed170 = [
        dict(flavours=[FAKE[0]] + [KNOWN_CHAIN_FN] * 4, total=100,
             size=30),
        dict(flavours=[KNOWN_CHAIN_FN, FAKE[1]] + [KNOWN_CHAIN_FN] * 3,
             total=100, size=30, vcall_out8=OUT_PTR),
        dict(flavours=[KNOWN_CHAIN_FN] * 3 + [FAKE[3], KNOWN_CHAIN_FN],
             total=100, size=30),
        dict(flavours=[KNOWN_CHAIN_FN] * 4 + [FAKE[4]], total=100,
             size=30),
        dict(flavours=[FAKE[0]] + [KNOWN_CHAIN_FN] * 4, total=100,
             size=30, lock_fail={THIS + 0x30: 11}),
        dict(flavours=[KNOWN_CHAIN_FN] * 5, total=100, size=30,
             lock_fail={CHAIN[1] + 0x18: 22}),
        dict(flavours=[KNOWN_CHAIN_FN] * 5, total=100, size=30,
             lock_fail={CHAIN[3] + 0x18: 33}),
        dict(flavours=[FAKE[0]] + [KNOWN_CHAIN_FN] * 4, total=5,
             size=10),
        dict(flavours=[KNOWN_CHAIN_FN, KNOWN_CHAIN_FN, FAKE[2],
                       KNOWN_CHAIN_FN, KNOWN_CHAIN_FN], total=100,
             size=30, vcall_throw_at=FAKE[2]),
        dict(flavours=[KNOWN_CHAIN_FN] * 4 + [FAKE[4]], total=100,
             size=30, vcall_throw_at=FAKE[4]),
    ]
    for spec in fixed170:
        _check_case(emu, 170, spec)
        count += 1
    fixed650 = [
        dict(flag98=0, flag99=1, total=5, limit=10,
             flavours=[KNOWN_NOTIFY_FN]),
        dict(flag98=1, flag99=1, total=10, limit=10,
             flavours=[KNOWN_NOTIFY_FN]),
        dict(flag98=1, flag99=0, total=5, limit=10,
             flavours=[KNOWN_NOTIFY_FN]),
        dict(flag98=1, flag99=1, total=5, limit=10, flavours=[]),
        dict(flag98=1, flag99=1, total=5, limit=10,
             flavours=[KNOWN_NOTIFY_FN, FAKE[0], KNOWN_NOTIFY_FN]),
        dict(flag98=1, flag99=1, total=5, limit=10,
             flavours=[KNOWN_NOTIFY_FN], lock_fail={THIS2 + 0x70: 11}),
        dict(flag98=1, flag99=1, total=5, limit=10,
             flavours=[KNOWN_NOTIFY_FN, FAKE[0]],
             vcall_throw_elem=ELEM[1]),
        dict(flag98=1, flag99=1, total=5, limit=10,
             flavours=[KNOWN_NOTIFY_FN], ncall_throw=NOTIFY_CALLS[0]),
        dict(flag98=1, flag99=1, total=5, limit=10,
             flavours=[KNOWN_NOTIFY_FN], ncall_throw=NOTIFY_CALLS[2]),
    ]
    for spec in fixed650:
        _check_case(emu, 650, spec)
        count += 1
    rng = random.Random(20261106)
    for _ in range(140):
        depth = rng.randrange(0, 6)
        flavours = [KNOWN_CHAIN_FN] * 5
        if depth < 5:
            flavours[depth] = FAKE[depth]
        else:
            flavours[4] = FAKE[4]
        spec = dict(flavours=flavours,
                    total=rng.randrange(0, 1 << 64),
                    size=rng.randrange(0, 1 << 64))
        roll = rng.random()
        if roll < 0.25:
            addrs = [THIS + 0x30] + [CHAIN[i] + 0x18
                                     for i in range(min(depth, 4))]
            spec["lock_fail"] = {rng.choice(addrs):
                                 rng.choice([11, 22, 35])}
        elif roll < 0.45:
            spec["vcall_throw_at"] = flavours[depth if depth < 5
                                              else 4]
        elif roll < 0.7:
            spec["vcall_out8"] = OUT_PTR
        _check_case(emu, 170, spec)
        count += 1
    for _ in range(140):
        n = rng.randrange(0, 5)
        flavours = [rng.choice([KNOWN_NOTIFY_FN, FAKE[0], FAKE[1]])
                    for _ in range(n)]
        total = rng.randrange(0, 20)
        spec = dict(flag98=rng.choice([0, 1, 1]),
                    flag99=rng.choice([0, 1]),
                    total=total,
                    limit=total + rng.choice([0, 0, 1, 5])
                    if rng.random() < 0.7 else rng.randrange(0, 20),
                    flavours=flavours)
        roll = rng.random()
        if roll < 0.15:
            spec["lock_fail"] = {THIS2 + 0x70: 11}
        elif roll < 0.35 and n:
            unknown = [ELEM[i] for i in range(n)
                       if flavours[i] != KNOWN_NOTIFY_FN]
            known = [i for i in range(n)
                     if flavours[i] == KNOWN_NOTIFY_FN]
            if unknown and rng.random() < 0.5:
                spec["vcall_throw_elem"] = rng.choice(unknown)
            elif known:
                spec["ncall_throw"] = rng.choice(
                    [NOTIFY_CALLS[0], NOTIFY_CALLS[2]])
        _check_case(emu, 650, spec)
        count += 1
    return count


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print("ok %s" % name)
    n = differential_cases()
    print("differential cases run: %d" % n)
    records = json.loads((PACKET_DIR / "records.json").read_text())
    assert records["artifact_sha256"] == \
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
