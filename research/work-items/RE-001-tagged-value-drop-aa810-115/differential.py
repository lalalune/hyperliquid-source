#!/usr/bin/env python3
"""Unicorn differential for the 0x57aa810 destructor model.

Runs the real function bytes from the digest-verified binary under
Unicorn and compares the observable effect sequence with the pure
model in tools/tagged_value_drop_aa810_115.py.

The callees are not emulated: the twin destructor 0x5b20680 is
hooked at entry, its argument recorded, and the call returned from
immediately (its body is a second instantiation of the same table,
pinned structurally in the packet). The sized-deallocation entry
0x635de30 (reached through GOT slot 0x64df4a0) is hooked the same
way: (pointer, size, third argument) are recorded and the tail
transfer is completed by hand. Entries into 0x57aa810 after the
first are recorded as recursion events. Any other call target
(pair glue 0x5b0ad70, panic shim 0x1680cab, _Unwind_Resume) fails
the case. Writes to value/buffer heap pages are recorded and must
be none: the routine itself stores nothing.
"""
import os
import random
import struct
import sys
from pathlib import Path

ROOT = Path(os.environ.get(
    "PKT_ROOT", Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(ROOT))

try:
    from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
                         UC_MODE_64, Uc)
    from unicorn.x86_const import (UC_X86_REG_RDI, UC_X86_REG_RDX,
                                   UC_X86_REG_RIP, UC_X86_REG_RSI,
                                   UC_X86_REG_RSP)
except ImportError:
    print("unicorn is not installed; the differential did NOT run "
          "(a skip is not a pass)")
    sys.exit(2)

from tools.tagged_value_drop_aa810_115 import Value, drop

BIN = ROOT / "work/hl-node-115.bin"
DATA = BIN.read_bytes()

FUNC = 0x57AA810
FUNC_END = 0x57AA9CD
TWIN = 0x5B20680
PAIR_GLUE = 0x5B0AD70
JUMP_TABLE = 0x9317A4
SLOT_DEALLOC = 0x64DF4A0
SLOT_PANIC = 0x64DF4C0
DEALLOC = 0x635DE30
PANIC_SHIM = 0x1680CAB

CODE_BASE = 0x57AA000
CODE_SIZE = 0x2000           # the function's own page range
RODATA_BASE = 0x930000
RODATA_SIZE = 0x2000
GOT_BASE = 0x64DF000
GOT_SIZE = 0x1000
HEAP = 0x10000000
HEAP_SIZE = 0x100000
STACK = 0x7F000000
STACK_SIZE = 0x100000
STOP = 0x6000000
HOOK_STUB = 0x6100000        # dealloc/panic slot targets land here


def va_bytes(va, size):
    # .text file offset = VA - 0x1000; .rodata offset = VA.
    if va >= 0x1419300:
        off = va - 0x1000
    else:
        off = va
    return DATA[off:off + size]


class Case:
    def __init__(self, top, children):
        self.top = top            # Value at HEAP
        self.children = children  # addr -> Value


def run_case(case):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_BASE, CODE_SIZE)
    uc.mem_map(RODATA_BASE, RODATA_SIZE)
    uc.mem_map(GOT_BASE, GOT_SIZE)
    uc.mem_map(HEAP, HEAP_SIZE)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_map(STOP & ~0xFFF, 0x2000)
    uc.mem_map(HOOK_STUB & ~0xFFF, 0x1000)
    # Pages whose entry addresses are intercepted by the code hook;
    # they only need to be fetchable, never executed.
    for target in (TWIN, PAIR_GLUE, PANIC_SHIM, DEALLOC):
        uc.mem_map(target & ~0xFFF, 0x1000)
    uc.mem_write(FUNC, va_bytes(FUNC, FUNC_END - FUNC))
    uc.mem_write(JUMP_TABLE, va_bytes(JUMP_TABLE, 21 * 4))
    uc.mem_write(SLOT_DEALLOC, struct.pack("<Q", HOOK_STUB))
    uc.mem_write(SLOT_PANIC, struct.pack("<Q", HOOK_STUB + 0x10))

    def put(addr, v):
        uc.mem_write(addr, struct.pack("<B", v.tag) + b"\0" * 7
                     + struct.pack("<QQQ", v.a, v.b, v.c))

    put(HEAP, case.top)
    for addr, v in case.children.items():
        put(addr, v)
    # Deterministic filler in the buffer area so element bytes exist.
    uc.mem_write(HEAP + 0x10000, bytes(range(256)) * 64)

    events = []
    writes = []
    state = {"entries": 0, "bad": None}

    def hook_code(uc, address, size, _):
        if address == TWIN:
            events.append(("twin", uc.reg_read(UC_X86_REG_RDI)))
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret)
        elif address == FUNC:
            state["entries"] += 1
            if state["entries"] > 1:
                events.append(("self", uc.reg_read(UC_X86_REG_RDI)))
        elif address == HOOK_STUB:
            events.append(("dealloc", uc.reg_read(UC_X86_REG_RDI),
                           uc.reg_read(UC_X86_REG_RSI)))
            if uc.reg_read(UC_X86_REG_RDX) != 0:
                state["bad"] = "dealloc third argument nonzero"
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret)
        elif address in (HOOK_STUB + 0x10, PAIR_GLUE, PANIC_SHIM):
            state["bad"] = f"unexpected transfer to {address:#x}"
            uc.emu_stop()
        elif address == STOP:
            uc.emu_stop()

    def hook_write(uc, access, address, size, value, _):
        if HEAP <= address < HEAP + HEAP_SIZE:
            writes.append((address, size, value))

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
    rsp = STACK + STACK_SIZE // 2
    uc.mem_write(rsp, struct.pack("<Q", STOP))
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RDI, HEAP)
    uc.emu_start(FUNC, STOP, count=200000)
    return events, writes, state["bad"]


def model_events(case):
    heap = {HEAP: case.top, **case.children}
    return drop(case.top, lambda ptr: heap[ptr])


def check(case, label):
    got, writes, bad = run_case(case)
    want = model_events(case)
    assert bad is None, f"{label}: {bad}"
    assert writes == [], f"{label}: unexpected writes {writes[:3]}"
    assert got == want, f"{label}:\n  emu  {got}\n  model {want}"


def main():
    buf = HEAP + 0x10000
    child = HEAP + 0x8000
    grandchild = HEAP + 0x8040
    n = 0

    # Every tag class against a spread of field shapes.
    shapes = [(0, 0), (0, 3), (5, 0), (5, 3), (1, 1), (2, 2), (7, 6)]
    for tag in list(range(0, 22)) + [22, 100, 255]:
        if tag in (17, 19):
            continue
        for a, c in shapes:
            check(Case(Value(tag, a=a, b=buf, c=c), {}), f"tag{tag}/{a}/{c}")
            n += 1

    # Box arms: scalar child, vector child, nested box.
    for tag in (17, 19):
        check(Case(Value(tag, a=child), {child: Value(3)}), f"box{tag}")
        check(Case(Value(tag, a=child),
                   {child: Value(20, a=2, b=buf, c=1)}), f"box-vec{tag}")
        check(Case(Value(tag, a=child),
                   {child: Value(17, a=grandchild),
                    grandchild: Value(12, a=9, b=buf, c=0)}),
              f"box-nested{tag}")
        n += 3

    # Random fuzz over tags and small shapes.
    rng = random.Random(0xAA810)
    for i in range(600):
        tag = rng.randrange(0, 256)
        a = rng.randrange(0, 8)
        c = rng.randrange(0, 7)
        if tag in (17, 19):
            kid_tag = rng.choice([0, 5, 12, 20, 21])
            kid = Value(kid_tag, a=rng.randrange(0, 4), b=buf,
                        c=rng.randrange(0, 3))
            check(Case(Value(tag, a=child), {child: kid}), f"fuzz{i}")
        else:
            check(Case(Value(tag, a=a, b=buf, c=c), {}), f"fuzz{i}")
        n += 1

    print(f"differential: {n} cases, 0 mismatches")


if __name__ == "__main__":
    main()
