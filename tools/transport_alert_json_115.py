#!/usr/bin/env python3
"""Reconstruct the node #115 AlertConfig pretty-JSON writer (0x4783f20) and the byte-sink helpers it runs.

The rate-limiter alert configuration is written as a pretty printed JSON object with one u64 member, "bucket_limit_mult_threshold".
Five bodies run as real x86-64 code in a small evaluator (the evaluator is the one in tools/funding_rate115.py): the object writer
0x4783f20, the member writer 0x4777cc0 (separator, indent, escaped key, ": ", decimal value), the u64 decimal formatter 0x4779320,
the amortised Vec<u8> growth 0x4787e90 and its allocation front end 0x4787da0. Only the allocator and panic entry points behind the
GOT are recording stubs. A separately written rule list (the Spec* functions below) predicts every output byte, every capacity,
every growth request and every allocator call; named wrong readings must be refused, every reached jump and immediate of the five
bodies is edited, and the container checks are corrupted. Nothing is parsed from objdump or readelf and the binary is never run.
Standard library only.

    python3 tools/transport_alert_json_115.py --out <dir>
"""

import argparse
import collections
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import funding_rate115 as core  # noqa: E402
from funding_rate115 import (EvidenceError, Halt, Image, Machine, Panicked, decode_range, load_image, MASK,  # noqa: E402
                             RAX, RCX, RDX, RSI, RDI, R8, R9, R14, HEAP_BASE, HEAP_SIZE)

SHA256 = core.SHA256
ALERT, ENTRY, ITOA, GROW, FINISH = 0x4783F20, 0x4777CC0, 0x4779320, 0x4787E90, 0x4787DA0
BODIES = ((ALERT, "alert_object"), (ENTRY, "member_entry"), (ITOA, "u64_decimal"), (GROW, "vec_grow"), (FINISH, "finish_grow"))

# GOT slots reached by the five bodies, with the role this reconstruction gives each (arguments are checked in the stubs)
SLOT_MEMCPY, SLOT_RAW_ERROR, SLOT_EXPECT, SLOT_OVERFLOW, SLOT_UNDERFLOW = 0x64DF508, 0x64DF498, 0x64DF730, 0x64DF520, 0x64DF848
SLOT_MALLOC, SLOT_REALLOC, SLOT_ALIGNED_REALLOC, SLOT_ALIGNED_MALLOC = 0x64DF480, 0x64DF588, 0x64DF580, 0x64DF590
SLOT_ESCAPE, SLOT_HEX = 0x64E13D8, 0x64E13E0
CALL_SLOTS = {"memcpy": SLOT_MEMCPY, "raw_vec_error": SLOT_RAW_ERROR, "expect_failed": SLOT_EXPECT, "add_overflow": SLOT_OVERFLOW,
              "sub_overflow": SLOT_UNDERFLOW, "malloc": SLOT_MALLOC, "realloc": SLOT_REALLOC, "aligned_realloc": SLOT_ALIGNED_REALLOC,
              "aligned_malloc": SLOT_ALIGNED_MALLOC}
DATA_SLOTS = {"escape_table": SLOT_ESCAPE, "hex_digits": SLOT_HEX}
MARK_BASE = 0x0E0E000000000000

KEY = b"bucket_limit_mult_threshold"
KEY_LEN = 0x1B

# Fixed layout inside the evaluator heap
S_AT, VEC_AT, CELL_AT, COMP_AT, INDENT_AT, KEY_AT, SCRATCH_AT, OUT_AT, BUF_AT, ALLOC_AT = (
    HEAP_BASE + off for off in (0x000, 0x040, 0x080, 0x100, 0x200, 0x300, 0x400, 0x500, 0x1000, 0x4000))
VIRTUAL_BASE = 0x500000000
BACKED_LIMIT = 0x2000
U64 = MASK[8]


class SpecPanic(Exception):
    pass


# --- rule list (written from the bytes, independent of the evaluator) -----------------------------------------------------------

def spec_escape_table():
    table = bytearray(256)
    for byte in range(0x20):
        table[byte] = ord("u")
    for byte, name in ((8, "b"), (9, "t"), (10, "n"), (12, "f"), (13, "r")):
        table[byte] = ord(name)
    table[0x22], table[0x5C] = 0x22, 0x5C
    return bytes(table)


def spec_escape_table_tampered():
    table = bytearray(spec_escape_table())
    table[0x2F] = ord("/")
    return bytes(table)


class SpecVec:
    """Vec<u8> with the observed reserve rule: a write of n bytes grows when cap - len < n."""

    def __init__(self, cap, data, fail_at, flags):
        self.cap, self.buf, self.log, self.allocs, self.fail_at, self.flags = cap, bytearray(data), [], 0, fail_at, flags

    def put(self, data):
        if self.cap - len(self.buf) < len(data):
            self.cap = spec_grow_target(self, len(self.buf), len(data))
        self.buf += data


def spec_min_cap(esize, flags=frozenset()):
    if "min_four" in flags:
        return 4
    return 8 if esize == 1 else (4 if esize <= 1024 else 1)


def spec_grow_target(vec, length, add):
    new = max((2 * vec.cap) & U64, length + add, 0 if "no_floor" in vec.flags else spec_min_cap(1, vec.flags))
    if "no_double" in vec.flags:
        new = max(length + add, spec_min_cap(1, vec.flags))
    vec.log.append(("malloc" if vec.cap == 0 else "realloc", new))
    if vec.fail_at is not None and vec.allocs == vec.fail_at:
        raise SpecPanic("raw_vec_error:1,%d" % new)
    vec.allocs += 1
    return new


def spec_decimal(value, flags=frozenset()):
    text = str(value).encode()
    return text.rjust(20, b"0") if "zero_pad" in flags else text


def spec_entry_into(vec, state, first, depth, indent, key, value, flags=frozenset()):
    if state & 0xFF == 1:
        raise SpecPanic("expect:40")
    hexd = b"0123456789ABCDEF" if "upper_hex" in flags else b"0123456789abcdef"
    table = bytearray(spec_escape_table())
    if "escape_del" in flags:
        table[0x7F] = ord("u")
    if "newline_u" in flags:
        table[10] = ord("u")
    if "no_slash_escape" in flags:
        table[0x5C] = 0
    vec.put(b"\n" if first == 1 and "comma_first" not in flags else b",\n")
    if indent and not ("skip_indent" in flags):
        for _ in range(depth):
            vec.put(indent)
    vec.put(b'"')
    run = bytearray()
    for byte in key:
        cls = table[byte]
        if cls == 0:
            run.append(byte)
            continue
        vec.put(bytes(run))
        run = bytearray()
        vec.put(b"\\u00" + bytes((hexd[byte >> 4], hexd[byte & 15])) if cls == ord("u") else b"\\" + bytes((cls,)))
    vec.put(bytes(run))
    vec.put(b'"')
    vec.put(b":" if "tight_colon" in flags else b": ")
    vec.put(spec_decimal(value, flags))
    return 2


def spec_alert_into(vec, depth, indent, value, flags=frozenset()):
    if depth == U64:
        raise SpecPanic("overflow")
    vec.put(b"{")
    spec_entry_into(vec, 0, 1, depth + 1, indent, KEY, value, flags)
    vec.put(b"\n")
    if depth != 0 and "no_close_indent" not in flags:
        for _ in range(depth):
            vec.put(indent)
    vec.put(b"}")


def spec_grow(cap, length, add, align, esize, flags=frozenset()):
    """Return ("ok", new capacity, requested bytes) or ("panic", message)."""
    if esize == 0 or length + add > U64:
        return ("panic", "raw_vec_error:0")
    new = max((2 * cap) & U64, length + add)
    new = max(new, spec_min_cap(esize, flags))
    return ("grow", new)


def spec_finish(oldcap, newcap, align, esize, flags=frozenset()):
    """Return (tag, second word, third word or None, allocator call or None)."""
    size = esize * newcap
    limit = (1 << 63) - align
    if size > U64 or size > (limit if "off_by_one_limit" not in flags else limit - 1):
        return (1, 0, None, None)
    ctz = (align & -align).bit_length() - 1 if align else 64
    plain = (align < 0x11 and align <= size) or ctz == 0
    if "always_plain" in flags:
        plain = True
    if oldcap:
        call = ("realloc", size) if plain else ("aligned_realloc", size, ctz)
        return (0, "fresh", size, call)
    if size == 0:
        return (0, align, 0, None)
    call = ("malloc", size) if plain else ("aligned_malloc", size, ctz)
    return (0, "fresh", size, call)


# --- evaluator harness -----------------------------------------------------------------------------------------------------------

class Harness:
    def __init__(self, image, patches=None, hooks=True):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(address for address, _ in BODIES)
        statics = machine.memory.statics
        if hooks:
            for name, slot in CALL_SLOTS.items():
                statics[slot] = MARK_BASE + slot
                machine.slots[MARK_BASE + slot] = getattr(self, "on_" + name)
        relative = image.relative()
        for slot in DATA_SLOTS.values():
            statics[slot] = relative[slot]
        machine.step_limit = 400000
        self.log, self.live, self.bump, self.virtual, self.fail_at, self.allocs, self.last = [], {}, ALLOC_AT, VIRTUAL_BASE, None, 0, None

    # -- stubs
    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_raw_vec_error(self, machine):
        regs = machine.regs
        raise Panicked("raw_vec_error:%d" % regs[RDI] + ("" if regs[RDI] == 0 else ",%d" % regs[RSI]))

    def on_expect_failed(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == 0x7E178D, "expect message address")
        raise Panicked("expect:%d" % regs[RSI])

    def on_add_overflow(self, machine):
        raise Panicked("overflow")

    def on_sub_overflow(self, machine):
        raise Panicked("underflow")

    def allocate(self, size):
        index, self.allocs = self.allocs, self.allocs + 1
        if self.fail_at is not None and index == self.fail_at:
            return 0
        if size > BACKED_LIMIT:
            ptr, self.virtual = self.virtual, self.virtual + size + 64
        else:
            ptr = (self.bump + 63) & ~63
            self.bump = ptr + size
            self.expect(self.bump < HEAP_BASE + HEAP_SIZE, "heap exhausted")
        self.live[ptr] = size
        self.last = ptr
        return ptr

    def on_malloc(self, machine):
        size = machine.regs[RDI]
        self.log.append(("malloc", size))
        machine.regs[RAX] = self.allocate(size)

    def on_aligned_malloc(self, machine):
        size, flags = machine.regs[RDI], machine.regs[RSI]
        self.log.append(("aligned_malloc", size, flags))
        machine.regs[RAX] = self.allocate(size)

    def resize(self, machine, name, extra):
        regs = machine.regs
        old, size = regs[RDI], regs[RSI]
        self.log.append((name, size) + extra)
        self.expect(old in self.live or old >= 1, "realloc of an unknown block")
        before = self.live.get(old, 0)
        new = self.allocate(size)
        if new and before and min(before, size) and size <= BACKED_LIMIT and before <= BACKED_LIMIT:
            machine.memory.copy(new, old, min(before, size))
        regs[RAX] = new

    def on_realloc(self, machine):
        self.resize(machine, "realloc", ())

    def on_aligned_realloc(self, machine):
        self.resize(machine, "aligned_realloc", (machine.regs[RDX],))

    # -- memory images
    def fresh(self, fail_at=None):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        self.log, self.live, self.bump, self.virtual, self.fail_at, self.allocs, self.last = [], {}, ALLOC_AT, VIRTUAL_BASE, fail_at, 0, None
        memory.put_bytes(HEAP_BASE, bytes((index * 29 + 5) & 0xFF for index in range(0x1000)))

    def build_vec(self, cap, data):
        memory = self.machine.memory
        ptr = BUF_AT if cap else 1
        if cap:
            memory.put_bytes(BUF_AT, bytes(0xD0 + (index & 7) for index in range(cap)))
            memory.put_bytes(BUF_AT, data)
        for offset, value in ((0, cap), (8, ptr), (0x10, len(data))):
            memory.write(VEC_AT + offset, 8, value)
        self.live[ptr] = cap

    def build_serializer(self, vec_cap, data, indent, depth, has_value):
        memory = self.machine.memory
        self.build_vec(vec_cap, data)
        memory.put_bytes(INDENT_AT, indent)
        for offset, value in ((0, VEC_AT), (8, INDENT_AT), (0x10, len(indent)), (0x18, depth), (0x20, has_value)):
            memory.write(S_AT + offset, 8, value)

    def vec_state(self):
        memory = self.machine.memory
        cap, ptr, length = (memory.read(VEC_AT + offset, 8) for offset in (0, 8, 0x10))
        return cap, ptr, length, memory.bytes_at(ptr, length) if length else b""

    # -- one case
    def run_case(self, case):
        kind = case.kind
        self.fresh(case.fail_at)
        memory = self.machine.memory
        try:
            if kind == "alert":
                self.build_serializer(case.cap, case.data, case.indent, case.depth, case.has_value)
                memory.write(CELL_AT, 8, case.value)
                rax = self.machine.run(ALERT, {RDI: CELL_AT, RSI: S_AT})
                return ("ok", rax) + self.sink_result(case)
            if kind == "entry":
                self.build_serializer(case.cap, case.data, case.indent, case.depth, case.has_value)
                memory.write(CELL_AT, 8, case.value)
                memory.put_bytes(KEY_AT, case.key)
                memory.write(COMP_AT, 1, case.state)
                memory.write(COMP_AT + 1, 1, case.first)
                memory.write(COMP_AT + 8, 8, S_AT)
                rax = self.machine.run(ENTRY, {RDI: COMP_AT, RSI: KEY_AT, RDX: len(case.key), RCX: CELL_AT})
                return ("ok", rax) + self.sink_result(case) + (memory.read(COMP_AT, 1), memory.read(COMP_AT + 1, 1))
            if kind == "itoa":
                memory.put_bytes(SCRATCH_AT, bytes([0xC3]) * 32)
                rax = self.machine.run(ITOA, {RDI: case.value, RSI: SCRATCH_AT})
                rdx = self.machine.regs[RDX]
                return ("ok", rax - SCRATCH_AT, rdx, memory.bytes_at(rax, rdx), memory.bytes_at(SCRATCH_AT, 32))
            if kind == "grow":
                self.build_vec(case.cap, b"")
                memory.write(VEC_AT + 0x10, 8, 0)
                rax = self.machine.run(GROW, {RDI: VEC_AT, RSI: case.length, RDX: case.add, RCX: case.align, R8: case.esize})
                cap, ptr, _, _ = self.vec_state()
                return ("ok", cap, "fresh" if ptr == self.last else ptr, tuple(self.log))
            if kind == "finish":
                memory.put_bytes(OUT_AT, bytes([0xC3]) * 24)
                saved, self.fail_at = self.fail_at, None
                oldptr = self.allocate(min(case.oldcap * case.esize, 64)) if case.oldcap else 1
                self.allocs, self.log, self.fail_at, self.last = 0, [], saved, None
                self.machine.run(FINISH, {RDI: OUT_AT, RSI: case.oldcap, RDX: oldptr, RCX: case.newcap, R8: case.align, R9: case.esize})
                tag, second, third = (memory.read(OUT_AT + offset, 8) for offset in (0, 8, 0x10))
                third = None if (tag, second) == (1, 0) else third
                return ("ok", tag, "fresh" if second == self.last else second, third, tuple(self.log))
        except Panicked as panic:
            return ("panic", str(panic), tuple(self.log))
        raise Halt("unknown case kind")

    def sink_result(self, case):
        cap, ptr, length, data = self.vec_state()
        memory = self.machine.memory
        moved = ptr != BUF_AT
        return (data, cap, moved, memory.read(S_AT + 0x18, 8), memory.read(S_AT + 0x20, 1), tuple(self.log))


class Case:
    __slots__ = ("kind", "cap", "data", "indent", "depth", "has_value", "value", "key", "state", "first", "fail_at",
                 "length", "add", "align", "esize", "oldcap", "newcap")

    def __init__(self, kind, **fields):
        self.kind = kind
        for name in self.__slots__[1:]:
            setattr(self, name, fields.get(name, 0 if name not in ("fail_at", "key", "data", "indent") else (None if name == "fail_at" else b"")))


def spec_case(case, flags=frozenset()):
    kind = case.kind
    try:
        if kind in ("alert", "entry"):
            vec = SpecVec(case.cap, case.data, case.fail_at, flags)
            if kind == "alert":
                spec_alert_into(vec, case.depth, case.indent, case.value, flags)
                return ("ok", 0, bytes(vec.buf), vec.cap, bool(vec.log), case.depth, 1, tuple(vec.log))
            spec_entry_into(vec, case.state, case.first, case.depth, case.indent, case.key, case.value, flags)
            return ("ok", 0, bytes(vec.buf), vec.cap, bool(vec.log), case.depth, 1, tuple(vec.log), case.state, 2)
        if kind == "itoa":
            digits = spec_decimal(case.value, flags)
            scratch = bytearray([0xC3]) * 32
            scratch[20 - len(digits):20] = digits
            return ("ok", 20 - len(digits), len(digits), digits, bytes(scratch))
        if kind == "grow":
            result = spec_grow(case.cap, case.length, case.add, case.align, case.esize, flags)
            if result[0] == "panic":
                return ("panic", result[1], ())
            fin = spec_finish(case.cap, result[1], case.align, case.esize, flags)
            if fin[0] == 1:
                return ("panic", "raw_vec_error:0" if fin[1] == 0 else "raw_vec_error:%d,%d" % (fin[1], fin[2]), ())
            ptr = 1 if (fin[3] is None and not case.cap) else fin[1]
            log = () if fin[3] is None else (fin[3],)
            if fin[3] is not None and case.fail_at == 0:
                return ("panic", "raw_vec_error:%d,%d" % (case.align, fin[2]), log)
            return ("ok", result[1], "fresh" if ptr == "fresh" else ptr, log)
        fin = spec_finish(case.oldcap, case.newcap, case.align, case.esize, flags)
        if fin[3] is not None and case.fail_at == 0:
            return ("ok", 1, case.align, fin[2], (fin[3],))
        return ("ok",) + fin[:3] + ((() if fin[3] is None else (fin[3],)),)
    except SpecPanic as panic:
        return ("panic", str(panic), tuple(vec.log) if kind in ("alert", "entry") else ())


# --- case generation -------------------------------------------------------------------------------------------------------------

def lcg(seed):
    state = seed & U64
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & U64
        yield state >> 11


def draw_value(stream):
    pick = next(stream) % 6
    if pick == 0:
        return next(stream) % 12
    if pick == 1:
        return 10 ** (next(stream) % 20) + (next(stream) % 3) - 1
    if pick == 2:
        return U64 - next(stream) % 3
    if pick == 3:
        return (1 << (next(stream) % 64)) - (next(stream) % 2)
    return next(stream) & U64 >> (next(stream) % 64)


def draw_bytes(stream, count, wild):
    pool = b'"\\\x00\x01\x08\x09\n\x0c\r\x1f\x7f\x80\xffaz_/' if wild else b"abcdefghijklmnopqrstuvwxyz_"
    return bytes(pool[next(stream) % len(pool)] if next(stream) % 3 == 0 else (next(stream) % 256 if wild and next(stream) % 4 == 0
                                                                              else 0x61 + next(stream) % 26) for _ in range(count))


def draw_sink(stream):
    """Initial Vec contents: a capacity and a prefix that fits it."""
    cap = (0, 1, 2, 7, 8, 31, 64, 200)[next(stream) % 8] if next(stream) % 2 else next(stream) % 260
    length = 0 if cap == 0 else (next(stream) % (cap + 1) if next(stream) % 3 else cap - min(cap, next(stream) % 4))
    return cap, bytes(0x41 + (index % 26) for index in range(length))


def draw_indent(stream):
    return bytes([0x20, 0x09, 0x2D, 0x78][next(stream) % 4] for _ in range((0, 1, 2, 2, 3, 4, 8)[next(stream) % 7]))


def draw_fail(stream):
    return next(stream) % 3 if next(stream) % 8 == 0 else None


def alert_cases(count, seed=0xA1E27C0F):
    stream = lcg(seed)
    for _ in range(count):
        cap, data = draw_sink(stream)
        depth = (U64 if next(stream) % 40 == 0 else next(stream) % 6)
        yield Case("alert", cap=cap, data=data, indent=draw_indent(stream), depth=depth, has_value=(0, 1, 0x55)[next(stream) % 3],
                   value=draw_value(stream), fail_at=draw_fail(stream))


def entry_cases(count, seed=0xE27213D1):
    stream = lcg(seed)
    for _ in range(count):
        cap, data = draw_sink(stream)
        yield Case("entry", cap=cap, data=data, indent=draw_indent(stream), depth=next(stream) % 6, has_value=next(stream) % 2,
                   value=draw_value(stream), key=draw_bytes(stream, next(stream) % 40, next(stream) % 3 != 0),
                   state=(0, 0, 0, 0, 0, 0, 0, 1)[next(stream) % 8], first=(0, 1, 1, 2)[next(stream) % 4], fail_at=draw_fail(stream))


def itoa_cases(count, seed=0x17A0B5):
    stream = lcg(seed)
    for _ in range(count):
        yield Case("itoa", value=draw_value(stream))


def grow_cases(count, seed=0x640B1):
    stream = lcg(seed)
    for _ in range(count):
        cap = (0, 0, 1, 8, 100, 4096)[next(stream) % 6] if next(stream) % 2 else next(stream) % 200
        length = cap if next(stream) % 2 else min(cap, next(stream) % 8)
        add = (1, 2, 6, 1, 4000, 0)[next(stream) % 6] if next(stream) % 3 else next(stream) % 300
        yield Case("grow", cap=cap, length=length, add=add, align=1, esize=(1, 1, 1, 2, 8, 1024, 1025, 0)[next(stream) % 8],
                   fail_at=draw_fail(stream))


def finish_cases(count, seed=0xF1B15):
    stream = lcg(seed)
    for _ in range(count):
        newcap = (0, 1, 8, 100, 1 << 40, 1 << 62, (1 << 63) - 1, U64)[next(stream) % 8] if next(stream) % 2 else next(stream) % 5000
        yield Case("finish", oldcap=(0, 0, 3, 40)[next(stream) % 4], newcap=newcap, align=(1, 1, 2, 8, 16, 17, 32, 64, 4096)[next(stream) % 9],
                   esize=(1, 1, 1, 2, 8, 24, 0)[next(stream) % 7], fail_at=draw_fail(stream))


def named_cases():
    cases = []
    for depth in (0, 1, 2):
        for indent in (b"", b"  "):
            cases.append(Case("alert", cap=0, data=b"", indent=indent, depth=depth, value=0, has_value=0))
            cases.append(Case("alert", cap=512, data=b"", indent=indent, depth=depth, value=U64, has_value=1))
    cases.append(Case("alert", cap=64, data=b"", indent=b"  ", depth=U64, value=1, has_value=0))
    cases.append(Case("entry", cap=64, data=b"", indent=b"  ", depth=1, value=7, key=b"a\"b\\c\n\x01\x7f", state=1, first=1))
    cases.append(Case("entry", cap=0, data=b"", indent=b"\t", depth=2, value=10 ** 19, key=b"k", state=0, first=0))
    cases.append(Case("entry", cap=300, data=b"", indent=b"\t", depth=2, value=10 ** 19, key=bytes(range(32)) + b'"\\', state=0, first=1))
    for value in (0, 9, 10, 99, 100, 9999, 10000, 99999999, 100000000, 10 ** 19, U64):
        cases.append(Case("itoa", value=value))
    cases.append(Case("grow", cap=0, length=0, add=0, align=1, esize=0))
    cases.append(Case("grow", cap=0, length=U64, add=1, align=1, esize=1))
    cases.append(Case("finish", oldcap=0, newcap=1 << 63, align=1, esize=1))
    cases.append(Case("finish", oldcap=0, newcap=(1 << 63) - 1, align=1, esize=1))
    cases.append(Case("finish", oldcap=0, newcap=(1 << 63) - 4096, align=4096, esize=1))
    cases.append(Case("finish", oldcap=3, newcap=100, align=64, esize=1))
    cases.append(Case("finish", oldcap=0, newcap=100, align=64, esize=1))
    return cases


def all_cases(per_kind):
    yield from named_cases()
    for maker, share in ((alert_cases, 4), (entry_cases, 4), (itoa_cases, 3), (grow_cases, 2), (finish_cases, 2)):
        yield from maker(per_kind * share // 15)


# --- checking --------------------------------------------------------------------------------------------------------------------

def check_stream(harness, cases, flags=frozenset(), keep=0, hits=None, first_only=False):
    stats = {"cases": 0, "mismatches": 0, "first": None, "kinds": collections.Counter()}
    sample = []
    for index, case in enumerate(cases):
        got = harness.run_case(case)
        want = spec_case(case, flags)
        stats["cases"] += 1
        stats["kinds"][(case.kind, got[0])] += 1
        if hits is not None:
            hits.update(harness.machine.seen)
            harness.machine.seen.clear()
        if got != want:
            stats["mismatches"] += 1
            if stats["first"] is None:
                stats["first"] = index
            if first_only:
                break
        if len(sample) < keep and index % 97 == 0:
            sample.append((index, case.kind, got[0], hashlib.sha256(repr(got).encode()).hexdigest()[:16]))
    return stats, sample


VARIANTS = (
    ("member written with a comma first", {"comma_first"}),
    ("indent omitted", {"skip_indent"}),
    ("upper-case hex digits in \\u escapes", {"upper_hex"}),
    ("DEL escaped", {"escape_del"}),
    ("newline escaped as \\u000a", {"newline_u"}),
    ("backslash left raw", {"no_slash_escape"}),
    ("colon without a space", {"tight_colon"}),
    ("decimal zero padded to 20", {"zero_pad"}),
    ("closing brace without outer indent", {"no_close_indent"}),
    ("growth to the exact need", {"no_double"}),
    ("growth without the minimum of 8", {"no_floor"}),
    ("minimum non-zero capacity 4 for bytes", {"min_four"}),
    ("allocation limit off by one", {"off_by_one_limit"}),
    ("aligned allocator never used", {"always_plain"}),
)


def edits_of(image, reached):
    """One edit for every reached conditional jump, one-byte and four-byte immediate and structure displacement."""
    out = []
    for entry, _ in BODIES:
        for row in decode_range(image, *image.exact_fde(entry)):
            if row.va not in reached:
                continue
            data = bytes(row.data)
            if row.op == "jcc":
                at = 0 if 0x70 <= data[0] <= 0x7F else 1
                out.append((row.va, "condition", row.va + at, data[at], data[at] ^ 1))
                continue
            if row.imm_at is not None and row.imm_size in (1, 4) and row.op not in ("call", "jmp"):
                out.append((row.va, "immediate", row.va + row.imm_at, data[row.imm_at], data[row.imm_at] ^ 1))
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and 0x8 <= abs(operand[4]) < 0x200 and operand[4] % 8 == 0:
                    packed = struct.pack("<i", operand[4]) if abs(operand[4]) >= 128 else struct.pack("<b", operand[4])
                    spot = data.find(packed)
                    if spot >= 0 and data.count(packed) == 1:
                        out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def run_edits(image, edits, cases):
    rows = []
    for va, kind, at, old, new in edits:
        harness = Harness(image, {at: new})
        harness.machine.step_limit = 20000
        killed, first = False, ""
        for index, case in enumerate(cases):
            try:
                got = harness.run_case(case)
            except (Halt, Panicked, EvidenceError, struct.error, ValueError, OverflowError):
                got = ("error",)
            if got != spec_case(case):
                killed, first = True, str(index)
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, harness, cases):
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    pick = next(case for case in cases if case.kind == "alert" and case.cap > 100 and case.fail_at is None and case.depth < 4 and case.indent)
    raises("wrong image digest", lambda: load_image(core.BINARY, "0" * 64), EvidenceError)
    for entry, name in BODIES:
        raises("mid-function address of %s is not an FDE start" % name, lambda entry=entry: image.exact_fde(entry + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window ending inside the writer", lambda: decode_range(image, ALERT, image.exact_fde(ALERT)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: Image(bytes(image.blob[:48])), Exception)
    stripped = Harness(image)
    del stripped.machine.slots[MARK_BASE + SLOT_MEMCPY]
    raises("memcpy slot without a model", lambda: stripped.run_case(pick), Halt)
    plain = Harness(image)
    plain.machine.real = frozenset()
    raises("callees not run as real code", lambda: plain.run_case(pick), Halt)
    trapped = Harness(image, {ALERT: 0xCC})
    raises("writer entry byte replaced by int3", lambda: trapped.run_case(pick), Halt)
    trapped = Harness(image, {ENTRY: 0xCC})
    raises("member writer entry byte replaced by int3", lambda: trapped.run_case(pick), Halt)
    odd = Harness(image)
    odd.machine.memory.statics[SLOT_ESCAPE] = image.relative()[SLOT_ESCAPE] + 1
    out.append(("escape table pointer shifted by one", odd.run_case(Case("entry", cap=64, key=b"\n", indent=b"", state=0, first=1, value=1))
                != spec_case(Case("entry", cap=64, key=b"\n", indent=b"", state=0, first=1, value=1)), "mismatch"))
    shifted = Harness(image)
    shifted.machine.memory.statics[SLOT_HEX] = image.relative()[SLOT_HEX] + 1
    ctl = Case("entry", cap=64, key=b"\x01", indent=b"", state=0, first=1, value=1)
    out.append(("hex digit table pointer shifted by one", shifted.run_case(ctl) != spec_case(ctl), "mismatch"))
    short = Harness(image)
    short.machine.step_limit = 5
    raises("step budget exhausted inside the writer", lambda: short.run_case(pick), Halt)
    raises("decoder refuses a window ending inside the decimal formatter", lambda: decode_range(image, ITOA, image.exact_fde(ITOA)[1] - 1), EvidenceError)
    out.append(("escape table rule list tampered", image_table(image) != spec_escape_table_tampered(), "mismatch"))
    return out


def image_table(image):
    start = image.offset(image.relative()[SLOT_ESCAPE])
    return bytes(image.blob[start:start + 256])


# --- evidence tables -------------------------------------------------------------------------------------------------------------

def slot_rows(image):
    rows = []
    wanted = {slot: name for name, slot in list(CALL_SLOTS.items()) + list(DATA_SLOTS.items())}
    for slot, kind, addend, symbol in image.relocations():
        if slot in wanted:
            rows.append(("%#x" % slot, wanted[slot], kind, "%#x" % addend, symbol))
    return sorted(rows)


def function_rows(image, hits):
    rows = []
    for entry, name in BODIES:
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            rows.append((name, "%#x" % row.va, row.size, row.op, hits.get(row.va, 0)))
    return rows


def caller_rows(image, targets):
    rows = []
    base, text = image.text_bytes()
    for target in targets:
        for at in range(len(text) - 5):
            if text[at] in (0xE8, 0xE9) and base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                owner = max(start for start in image.starts if start <= base + at)
                rows.append(("%#x" % (base + at), "call" if text[at] == 0xE8 else "jmp", "%#x" % target, "%#x" % owner))
    return sorted(rows)


def analyse(per_kind=15000, mutate=True):
    image = load_image()
    harness = Harness(image)
    cases = list(all_cases(per_kind))
    reached = collections.Counter()
    stats, sample = check_stream(harness, cases, keep=40, hits=reached)
    caught = {}
    subset = [case for index, case in enumerate(cases) if index % 7 == 0]
    for name, flags in VARIANTS:
        refused, first = check_stream(Harness(image), subset, frozenset(flags), first_only=True)[0], None
        caught[name] = (refused["mismatches"], refused["first"])
    result = {"image": image, "stats": stats, "sample": sample, "reached": reached, "caught": caught, "cases": len(cases)}
    result["structural"] = structural_controls(image, harness, cases)
    result["edits"] = []
    if mutate:
        picked = cases[:len(named_cases())] + cases[len(named_cases())::max(1, len(cases) // 400)]
        result["edits"] = run_edits(image, edits_of(image, reached), picked)
    return result


def render(result):
    image, stats = result["image"], result["stats"]
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"

    tsv("pointer-slots.tsv", ("slot", "role", "reloc_type", "addend", "symbol"), slot_rows(image))
    tsv("direct-callers.tsv", ("site", "kind", "target", "owner"), caller_rows(image, [entry for entry, _ in BODIES]))
    tsv("function-rows.tsv", ("function", "address", "size", "op", "cases_reaching"), function_rows(image, result["reached"]))
    tsv("outcomes.tsv", ("kind", "outcome", "cases"), [(k, o, n) for (k, o), n in sorted(stats["kinds"].items())])
    tsv("cases-sample.tsv", ("index", "kind", "outcome", "digest"), result["sample"])
    tsv("escape-table.tsv", ("byte", "class"), [("%#04x" % b, "%#04x" % c) for b, c in enumerate(image_table(image)) if c])
    tsv("variants.tsv", ("deviation", "cases_refused", "first_refusing_case"),
        [(n, refused, "" if first is None else first) for n, (refused, first) in sorted(result["caught"].items())])
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["structural"]])
    tsv("edits.tsv", ("address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % va, kind, "%#x" % at, old, new, int(killed), first) for va, kind, at, old, new, killed, first in result["edits"]])
    controls = len(result["caught"]) + len(result["structural"])
    detected = sum(1 for refused, _ in result["caught"].values() if refused) + sum(1 for _, d, _ in result["structural"] if d)
    killed = sum(1 for row in result["edits"] if row[5])
    evidence = {"binary_sha256": SHA256, "bodies": {name: "%#x" % entry for entry, name in BODIES}, "cases": stats["cases"],
                "mismatches": stats["mismatches"], "first_mismatch": stats["first"], "instructions_reached": len(result["reached"]),
                "edits": len(result["edits"]), "edits_killed": killed}
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": controls, "negative_detected": detected,
                                        "mismatches": stats["mismatches"], "edits": len(result["edits"]), "edits_killed": killed},
                                       indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = analyse()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text)
    print(render(result)["measure.json"], end="")
    return 0 if result["stats"]["mismatches"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
