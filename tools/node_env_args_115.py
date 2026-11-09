#!/usr/bin/env python3
"""Reconstruct node #115 process-argument iteration (std::env::args): collector, next, UTF-8 validator and Vec<String> drop run from the ELF bytes.

The startup initializer stores argc/argv in two .bss cells (0x6500000 / 0x6500008). Four bodies turn them into checked strings:
the collector 0x5c9a530 builds an owning iterator over a Vec of (capacity, pointer, length) strings, next 0x5caa830 pops one and
validates it, the validator 0x16815e0 is core::str::from_utf8 and the drop 0x5c73990 frees a Vec of strings. The real bytes run in a
small x86-64 evaluator (shared with the BOLE rate packet) with libc-style stubs that record every call; a separately written rule
list predicts results, memory effects and call logs. Every reached conditional and immediate of the four bodies is edited to prove
the comparison notices. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/node_env_args_115.py --out <dir>
"""

import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_rate115 as core  # noqa: E402
from bole_rate115 import (EvidenceError, Halt, Panicked, RAX, RDI, RDX, RSI, RCX, R8, HEAP_BASE, MASK)  # noqa: E402

COLLECT, NEXT, VALIDATE, DROP = 0x5C9A530, 0x5CAA830, 0x16815E0, 0x5C73990
FUNCTIONS = (("collect", COLLECT), ("next", NEXT), ("validate", VALIDATE), ("drop", DROP))
ARGC_CELL, ARGV_CELL = 0x6500000, 0x6500008
SLOT_ALLOC_ERROR, SLOT_MALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_STRLEN, SLOT_UNWRAP, SLOT_GROW, SLOT_VALIDATOR = (
    0x64DF498, 0x64DF480, 0x64DF4A0, 0x64DF508, 0x64DF698, 0x64DF6A0, 0x64EB000, 0x64DFCA8)
SLOT_ROLES = (
    (SLOT_MALLOC, "allocate(size)"), (SLOT_FREE, "deallocate(ptr, size, align)"), (SLOT_ALLOC_ERROR, "handle_alloc_error(align, size)"),
    (SLOT_MEMCPY, "memcpy(dst, src, len)"), (SLOT_STRLEN, "strlen(ptr)"), (SLOT_UNWRAP, "Result::unwrap_failed(msg, len, err, vtable, location)"),
    (SLOT_GROW, "RawVec grow (never reached)"), (SLOT_VALIDATOR, "str::from_utf8 (relocated to the validator body)"))
MARK = 0x5A00000000
NONE_TAG = 1 << 63
MAX_COUNT = 0x555555555555555
UNWRAP_MESSAGE = b"called `Result::unwrap()` on an `Err` value"
UNWRAP_MESSAGE_AT, UNWRAP_LOCATION, UNWRAP_VTABLE = 0x949294, 0x64C3240, 0x64C3290

ARGV_AT = HEAP_BASE + 0x100
STRINGS_AT = HEAP_BASE + 0x400
ALLOC_AT = HEAP_BASE + 0x2000
ALLOC_END = HEAP_BASE + 0x6000
OUT_AT = HEAP_BASE + 0x7E00
ITER_AT = HEAP_BASE + 0x7F00
VEC_AT = HEAP_BASE + 0x7F80
USED = 0x8000
OUT_SIZE = 0x40


class Case:
    __slots__ = ("kind", "argv", "argc", "null_argv", "fail", "elements", "cursor", "raw")

    def __init__(self, kind, argv=(), argc=None, null_argv=False, fail=-1, elements=(), cursor=0, raw=b""):
        self.kind, self.argv, self.null_argv, self.fail = kind, tuple(argv), null_argv, fail
        self.argc = len(self.argv) if argc is None else argc
        self.elements, self.cursor, self.raw = tuple(elements), cursor, raw


# ---- the written rule list -------------------------------------------------------------------------------------------------------

def utf8_error(data):
    """Rust str::from_utf8 rule: (valid_up_to, error_len) with error_len None for a truncated tail, or None when valid."""
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b < 0x80:
            i += 1
            continue
        if 0xC2 <= b <= 0xDF:
            need, lo, hi = 1, 0x80, 0xBF
        elif 0xE0 <= b <= 0xEF:
            need, lo, hi = 2, (0xA0 if b == 0xE0 else 0x80), (0x9F if b == 0xED else 0xBF)
        elif 0xF0 <= b <= 0xF4:
            need, lo, hi = 3, (0x90 if b == 0xF0 else 0x80), (0x8F if b == 0xF4 else 0xBF)
        else:
            return i, 1
        j = i + 1
        for step in range(need):
            if j >= n:
                return i, None
            c = data[j]
            if not (lo if step == 0 else 0x80) <= c <= (hi if step == 0 else 0xBF):
                return i, j - i
            j += 1
        i = j
    return None


class Spec:
    """Predicts the evaluator's state after one top-level call; allocation is the stub's bump rule."""

    def __init__(self, case):
        self.case = case
        self.top = ALLOC_AT
        self.index = 0
        self.log = []

    def address(self, i):
        return STRINGS_AT + sum(len(e) + 1 for e in self.case.argv[:i] if e is not None)

    def malloc(self, size):
        index, self.index = self.index, self.index + 1
        self.log.append(("malloc", size))
        if index == self.case.fail or size > 0x4000 or self.top + size > ALLOC_END:
            return 0
        at = self.top
        self.top += (size + 15) & ~15
        return at

    def collect(self):
        case = self.case
        argc = case.argc
        if case.null_argv:
            return ("ok", (8, 8, 0, 8), (), self.log)
        size = argc * 24
        if argc > MAX_COUNT:
            self.log.append(("alloc_error", 0, size & MASK[8]))
            return ("panic", self.log)
        if size == 0:
            buf, cap = 8, 0
        else:
            buf = self.malloc(size)
            if buf == 0:
                self.log.append(("alloc_error", 8, size))
                return ("panic", self.log)
            cap = argc
        rows = []
        for i in range(argc):
            entry = case.argv[i] if i < len(case.argv) else None
            if entry is None:
                break
            self.log.append(("strlen", self.address(i)))
            n = len(entry)
            if n == 0:
                ptr = 1
            else:
                ptr = self.malloc(n)
                if ptr == 0:
                    self.log.append(("alloc_error", 1, n))
                    return ("panic", self.log)
                self.log.append(("memcpy", ptr, n))
            rows.append((n, ptr, n, entry))
        return ("ok", (buf, buf, cap, buf + 24 * len(rows)), tuple(rows), self.log)

    def next(self):
        case = self.case
        if case.cursor >= len(case.elements):
            return ("none", case.cursor)
        cap, ptr, n, data = case.elements[case.cursor]
        if cap == NONE_TAG:
            return ("none", case.cursor + 1)
        if utf8_error(data) is None:
            return ("some", case.cursor + 1, (cap, ptr, n))
        return ("panic", case.cursor + 1, (cap, ptr, n), UNWRAP_MESSAGE_AT, len(UNWRAP_MESSAGE), UNWRAP_VTABLE, UNWRAP_LOCATION)

    def validate(self):
        error = utf8_error(self.case.raw)
        return ("ok",) if error is None else ("err", error)

    def drop(self):
        frees = [("free", ptr, cap, 0) for cap, ptr, _, _ in self.case.elements if cap]
        if self.case.cursor:
            frees.append(("free", ("buffer",), self.case.cursor * 24, 0))
        return ("ok", frees)


# ---- the evaluator harness -------------------------------------------------------------------------------------------------------

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = core.Machine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        for slot, _ in SLOT_ROLES:
            statics[slot] = MARK + slot
        if image.relative().get(SLOT_VALIDATOR) != VALIDATE:
            raise EvidenceError("validator slot does not resolve to the validator body")
        statics[SLOT_VALIDATOR] = VALIDATE
        machine.slots.update({
            MARK + SLOT_MALLOC: self.on_malloc, MARK + SLOT_FREE: self.on_free, MARK + SLOT_ALLOC_ERROR: self.on_alloc_error,
            MARK + SLOT_MEMCPY: self.on_memcpy, MARK + SLOT_STRLEN: self.on_strlen, MARK + SLOT_UNWRAP: self.on_unwrap,
            MARK + SLOT_GROW: self.on_grow})
        machine.real = frozenset({DROP, VALIDATE})
        machine.calls[DROP] = None
        self.case = None
        self.log = []
        self.top = ALLOC_AT
        self.mallocs = 0
        self.extent = 0

    def on_malloc(self, machine):
        size = machine.regs[RDI]
        index, self.mallocs = self.mallocs, self.mallocs + 1
        self.log.append(("malloc", size))
        if index == self.case.fail or size > 0x4000 or self.top + size > ALLOC_END:
            machine.regs[RAX] = 0
            return
        machine.regs[RAX] = self.top
        self.top += (size + 15) & ~15

    def on_free(self, machine):
        regs = machine.regs
        self.log.append(("free", regs[RDI], regs[RSI], regs[RDX] & MASK[4]))

    def on_alloc_error(self, machine):
        self.log.append(("alloc_error", machine.regs[RDI] & MASK[8], machine.regs[RSI]))
        raise Panicked("alloc_error")

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        self.log.append(("memcpy", regs[RDI], regs[RDX]))
        machine.regs[RAX] = regs[RDI]

    def on_strlen(self, machine):
        at, count = machine.regs[RDI], 0
        while machine.memory.bytes_at(at + count, 1) != b"\0":
            count += 1
        self.log.append(("strlen", at))
        machine.regs[RAX] = count

    def on_unwrap(self, machine):
        regs = machine.regs
        payload = tuple(machine.memory.read(regs[RDX] + 8 * k, 8) for k in range(3))
        self.log.append(("unwrap", regs[RDI], regs[RSI], payload, regs[RCX], regs[R8]))
        raise Panicked("unwrap")

    def on_grow(self, machine):
        raise Halt("RawVec grow reached")

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [core.POISON | core.POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes(((i * 7) ^ (i >> 8)) & 0xFF or 1 for i in range(USED)))
        self.case, self.log, self.top, self.mallocs, self.extent = case, [], ALLOC_AT, 0, 0
        memory.put_bytes(OUT_AT, bytes(0x70 + i for i in range(OUT_SIZE)))
        memory.put_bytes(ITER_AT, bytes(0x30 + i for i in range(0x40)))
        return bytes(memory.heap[:USED])

    def lay_strings(self, entries):
        """Write NUL-terminated argv entries and return (argv array address, pointers)."""
        memory = self.machine.memory
        at, pointers = STRINGS_AT, []
        for entry in entries:
            if entry is None:
                pointers.append(0)
                continue
            memory.put_bytes(at, entry + b"\0")
            pointers.append(at)
            at += len(entry) + 1
        memory.put_bytes(ARGV_AT, b"".join(struct.pack("<Q", p) for p in pointers) + bytes(8))
        return pointers

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        statics = memory.statics
        try:
            result = self.dispatch(case, memory, statics)
        except Panicked:
            if case.kind == COLLECT:
                result = ("panic", self.log)
            else:
                entry = self.log[-1]
                cursor = (struct.unpack("<Q", memory.bytes_at(ITER_AT + 8, 8))[0] - ALLOC_AT) // 24
                result = ("panic", cursor, entry[3], entry[1], entry[2], entry[4], entry[5])
        after = bytes(memory.heap[:USED])
        self.check_untouched(before, after, case)
        return before, result

    def after_next(self):
        return struct.unpack("<Q", self.machine.memory.bytes_at(ITER_AT + 8, 8))[0]

    def check_untouched(self, before, after, case):
        top = max(self.top, ALLOC_AT + self.extent) - HEAP_BASE
        if before[:0x100] != after[:0x100] or before[top:ALLOC_END - HEAP_BASE] != after[top:ALLOC_END - HEAP_BASE]:
            raise Halt("state changed outside the result")

    def dispatch(self, case, memory, statics):
        machine = self.machine
        if case.kind == COLLECT:
            entries = list(case.argv)
            if case.null_argv:
                statics[ARGV_CELL] = 0
            else:
                self.lay_strings(entries)
                statics[ARGV_CELL] = ARGV_AT
            statics[ARGC_CELL] = case.argc
            ret = machine.run(COLLECT, {RDI: OUT_AT})
            if ret != OUT_AT:
                raise Halt("result pointer")
            words = struct.unpack("<4Q", memory.bytes_at(OUT_AT, 32))
            rows = []
            count = (words[3] - words[0]) // 24 if words[0] > 8 else 0
            for k in range(count):
                cap, ptr, n = struct.unpack("<3Q", memory.bytes_at(words[0] + 24 * k, 24))
                rows.append((cap, ptr, n, memory.bytes_at(ptr, n) if n else b""))
            return ("ok", words, tuple(rows), self.log)
        if case.kind == NEXT:
            base = ALLOC_AT
            blob = b"".join(struct.pack("<3Q", cap, ptr, n) for cap, ptr, n, _ in case.elements)
            for cap, ptr, n, data in case.elements:
                if n and cap != NONE_TAG:
                    memory.put_bytes(ptr, data)
            memory.put_bytes(base, blob)
            self.extent = len(blob)
            end = base + len(blob)
            memory.put_bytes(ITER_AT, struct.pack("<4Q", base, base + 24 * case.cursor, len(case.elements), end))
            ret = machine.run(NEXT, {RDI: OUT_AT, RSI: ITER_AT})
            cursor = (struct.unpack("<Q", memory.bytes_at(ITER_AT + 8, 8))[0] - base) // 24
            first = struct.unpack("<Q", memory.bytes_at(OUT_AT, 8))[0]
            if ret != OUT_AT:
                raise Halt("result pointer")
            if first == NONE_TAG:
                return ("none", cursor)
            return ("some", cursor, struct.unpack("<3Q", memory.bytes_at(OUT_AT, 24)))
        if case.kind == VALIDATE:
            at = STRINGS_AT + (sum(case.raw) & 7)
            memory.put_bytes(at, case.raw)
            ret = machine.run(VALIDATE, {RDI: OUT_AT, RSI: at, RDX: len(case.raw)})
            if ret != OUT_AT:
                raise Halt("result pointer")
            raw = memory.bytes_at(OUT_AT, 24)
            if raw[0] == 0:
                return ("ok",)
            return ("err", (struct.unpack_from("<Q", raw, 8)[0], raw[17] if raw[16] else None))
        if case.kind == DROP:
            base = ALLOC_AT
            blob = b"".join(struct.pack("<3Q", cap, ptr, n) for cap, ptr, n, _ in case.elements)
            memory.put_bytes(base, blob)
            self.extent = len(blob)
            memory.put_bytes(VEC_AT, struct.pack("<3Q", case.cursor, base, len(case.elements)))
            machine.run(DROP, {RDI: VEC_AT})
            frees = []
            for entry in self.log:
                if entry[1] == base:
                    frees.append(("free", ("buffer",), entry[2], entry[3]))
                else:
                    frees.append(entry)
            return ("ok", frees)
        raise Halt("unknown case kind")


def spec_run(case):
    spec = Spec(case)
    if case.kind == COLLECT:
        return spec.collect()
    return {NEXT: spec.next, VALIDATE: spec.validate, DROP: spec.drop}[case.kind]()


# ---- deterministic case streams -------------------------------------------------------------------------------------------------

class Lcg:
    def __init__(self, seed):
        self.state = seed & MASK[8]

    def next(self, bound):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (self.state >> 33) % bound


EDGE = (0x61, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFF)
WORDS = (b"hl-node", b"--chain", b"Mainnet", b"run-app", b"/x/y/cham/release", b"--", b"-", b"a", b"/cham/", b"run-client")


def random_bytes(rng):
    mode = rng.next(6)
    if mode == 0:
        return WORDS[rng.next(len(WORDS))]
    if mode == 1:
        return bytes(0x61 + rng.next(26) for _ in range(rng.next(24)))
    if mode == 2:
        return "".join(chr((0x80, 0x800, 0x3FFF, 0x1F600)[rng.next(4)] + rng.next(0x40)) for _ in range(rng.next(5))).encode()
    if mode == 3:
        data = bytearray("".join(chr(0x3B1 + rng.next(20)) for _ in range(rng.next(6))).encode())
        if data:
            data[rng.next(len(data))] = EDGE[rng.next(len(EDGE))]
        return bytes(data)
    if mode == 4:
        return bytes(EDGE[rng.next(len(EDGE))] for _ in range(rng.next(7)))
    return bytes(1 + rng.next(255) for _ in range(rng.next(12)))


def collect_case(rng):
    pick = rng.next(20)
    if pick == 0:
        return Case(COLLECT, null_argv=True, argc=rng.next(4))
    if pick == 1:
        return Case(COLLECT, argc=MAX_COUNT + 1 + rng.next(1 << 30))
    if pick == 2:
        return Case(COLLECT, argv=[None], argc=1 + rng.next(1 << 20) * 2 + 0x2000)
    count = rng.next(8)
    argv = [random_bytes(rng).replace(b"\0", b"\1") for _ in range(count)]
    argc = count
    if pick == 3 and count:
        argv[rng.next(count)] = None
    if pick == 4:
        argc = count + 1 + rng.next(3)
    fail = rng.next(count + 2) if pick in (5, 6, 7) else -1
    return Case(COLLECT, argv=argv, argc=argc, fail=fail)


def next_case(rng):
    elements, at = [], STRINGS_AT
    for _ in range(rng.next(6)):
        data = random_bytes(rng)
        cap = len(data) + rng.next(3) * rng.next(4)
        elements.append((NONE_TAG if rng.next(9) == 0 else cap, at, len(data), data))
        at += len(data) + 1
    return Case(NEXT, elements=elements, cursor=rng.next(len(elements) + 1))


def drop_case(rng):
    elements, at = [], STRINGS_AT
    for _ in range(rng.next(6)):
        elements.append((0 if rng.next(3) == 0 else 1 + rng.next(40), at, 0, b""))
        at += 64
    return Case(DROP, elements=elements, cursor=rng.next(9))


def long_validate_case(rng):
    """A long ASCII run with at most one odd byte group, to reach the word-at-a-time and tail arms of the validator."""
    data = bytearray(0x61 + rng.next(26) for _ in range(8 + rng.next(80)))
    if rng.next(4):
        at = rng.next(len(data))
        group = (bytes([EDGE[rng.next(len(EDGE))]]), "\u00e9".encode(), "\u20ac".encode(), "\U0001f600".encode(), b"\xe2\x82")[rng.next(5)]
        data[at:at + len(group)] = group
    return Case(VALIDATE, raw=bytes(data))


def validate_edge_cases():
    for byte in range(256):
        yield Case(VALIDATE, raw=bytes([byte]))
    for first in EDGE:
        for second in EDGE:
            yield Case(VALIDATE, raw=bytes([first, second]))
            for third in EDGE:
                yield Case(VALIDATE, raw=bytes([first, second, third]))
    for first in (0xF0, 0xF4, 0xE0, 0xED):
        for second in EDGE:
            for third in (0x80, 0xBF, 0x90):
                yield Case(VALIDATE, raw=bytes([0x61, first, second, third, 0x80]))


def case_stream(total, seed=0x115A9C5):
    """Yield `total` cases: a fixed prefix of three kinds, then boundary validator cases, then the mixed random tail."""
    rng = Lcg(seed)
    produced = 0
    for builder in (collect_case, next_case, drop_case):
        for _ in range(40):
            yield builder(rng)
            produced += 1
    for argc in (MAX_COUNT - 1, MAX_COUNT, MAX_COUNT + 1, 0x4000 // 24, 0x4000 // 24 + 1):
        yield Case(COLLECT, argv=[b"x"] * 3, argc=argc)
        produced += 1
    for _ in range(60):
        yield long_validate_case(rng)
        produced += 1
    for case in validate_edge_cases():
        if produced >= total:
            return
        yield case
        produced += 1
    builders = (collect_case, next_case, drop_case, lambda r: Case(VALIDATE, raw=random_bytes(r)))
    while produced < total:
        yield builders[rng.next(4)](rng)
        produced += 1


# ---- analysis --------------------------------------------------------------------------------------------------------------------

CASE_TOTAL = 12000
DETECT_STEP = 15
DETECT_PREFIX = 190
MUTANT_STEP_LIMIT = 30000
VARIANTS = (
    "utf8-allow-overlong-e0", "utf8-allow-surrogate-ed", "utf8-allow-f4-overflow", "utf8-accept-c0-c1", "utf8-error-len-plus-one",
    "next-none-tag-keeps-cursor", "drop-frees-zero-capacity", "drop-skips-buffer", "collect-capacity-is-length-plus-one",
    "collect-size-is-sixteen", "collect-ignores-null-entry", "unwrap-message-short", "collect-null-argv-allocates",
    "next-validates-nothing", "drop-wrong-buffer-size")


def digest_of(value):
    return hashlib.sha256(repr(value).encode("ascii")).hexdigest()


def spec_variant(case, variant):
    """The rule list with one deliberately wrong rule; every variant must disagree with the evaluator somewhere."""
    global utf8_error
    saved = utf8_error
    try:
        if variant.startswith("utf8-"):
            utf8_error = lambda data: variant_utf8(data, variant)  # noqa: E731
        spec = Spec(case)
        if case.kind == COLLECT:
            result = spec.collect()
            if variant == "collect-capacity-is-length-plus-one" and result[0] == "ok" and result[2]:
                result = ("ok", (result[1][0], result[1][1], result[1][2] + 1, result[1][3]), result[2], result[3])
            if variant == "collect-size-is-sixteen" and result[0] == "ok" and result[3]:
                result = ("ok", result[1], result[2], [("malloc", 16 * case.argc)] + result[3][1:])
            if variant == "collect-ignores-null-entry" and None in case.argv and result[0] == "ok":
                result = ("ok", result[1], result[2] + ((0, 1, 0, b""),), result[3])
            if variant == "collect-null-argv-allocates" and case.null_argv:
                result = ("ok", (ALLOC_AT, ALLOC_AT, 0, ALLOC_AT), (), [])
            return result
        if case.kind == NEXT:
            result = spec.next()
            if variant == "next-none-tag-keeps-cursor" and result[0] == "none" and case.cursor < len(case.elements):
                result = ("none", case.cursor)
            if variant == "unwrap-message-short" and result[0] == "panic":
                result = result[:4] + (len(UNWRAP_MESSAGE) - 1,) + result[5:]
            if variant == "next-validates-nothing" and result[0] == "panic":
                cap, ptr, n, _ = case.elements[case.cursor]
                result = ("some", case.cursor + 1, (cap, ptr, n))
            return result
        if case.kind == DROP:
            result = spec.drop()
            frees = list(result[1])
            if variant == "drop-frees-zero-capacity":
                frees = [("free", ptr, cap, 0) for cap, ptr, _, _ in case.elements] + frees[len([e for e in case.elements if e[0]]):]
            if variant == "drop-skips-buffer":
                frees = [f for f in frees if f[1] != ("buffer",)]
            if variant == "drop-wrong-buffer-size":
                frees = [(f[0], f[1], f[2] + 24, f[3]) if f[1] == ("buffer",) else f for f in frees]
            return ("ok", frees)
        return spec.validate()
    finally:
        utf8_error = saved


def variant_utf8(data, variant):
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b < 0x80:
            i += 1
            continue
        low_lead = 0xC0 if variant == "utf8-accept-c0-c1" else 0xC2
        if low_lead <= b <= 0xDF:
            need, lo, hi = 1, 0x80, 0xBF
        elif 0xE0 <= b <= 0xEF:
            need, lo, hi = 2, (0xA0 if b == 0xE0 and variant != "utf8-allow-overlong-e0" else 0x80), (0x9F if b == 0xED and variant != "utf8-allow-surrogate-ed" else 0xBF)
        elif 0xF0 <= b <= 0xF4:
            need, lo, hi = 3, (0x90 if b == 0xF0 else 0x80), (0x8F if b == 0xF4 and variant != "utf8-allow-f4-overflow" else 0xBF)
        else:
            return i, 1
        j = i + 1
        for step in range(need):
            if j >= n:
                return i, None
            c = data[j]
            if not (lo if step == 0 else 0x80) <= c <= (hi if step == 0 else 0xBF):
                return i, j - i + (1 if variant == "utf8-error-len-plus-one" else 0)
            j += 1
        i = j
    return None


def survey(image, total=CASE_TOTAL):
    harness = Harness(image)
    machine = harness.machine
    counts = {name: 0 for name, _ in FUNCTIONS}
    outcomes = {}
    seen_by = {name: set() for name, _ in FUNCTIONS}
    stream = hashlib.sha256()
    samples, detect = [], []
    names = {COLLECT: "collect", NEXT: "next", VALIDATE: "validate", DROP: "drop"}
    for index, case in enumerate(case_stream(total)):
        machine.seen = set()
        _, got = harness.run(case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("evaluator and rule list disagree at case %d (%s)" % (index, names[case.kind]))
        counts[names[case.kind]] += 1
        seen_by[names[case.kind]] |= machine.seen
        kind = got[0]
        outcomes[(names[case.kind], kind)] = outcomes.get((names[case.kind], kind), 0) + 1
        stream.update(repr(want).encode("ascii"))
        if index < DETECT_PREFIX or index % DETECT_STEP == 0:
            detect.append((case, got))
        if len(samples) < 160 and (index < 190 or index % 40 == 0):
            samples.append((index, names[case.kind], kind, digest_of(want)[:16]))
    return counts, outcomes, seen_by, stream.hexdigest(), samples, detect


def function_rows(image):
    table = {}
    for name, va in FUNCTIONS:
        start, end = image.exact_fde(va)
        table[name] = (start, end, core.decode_range(image, start, end))
    return table


def agrees(harness, case, expected):
    try:
        _, got = harness.run(case)
    except (Halt, Panicked, EvidenceError, KeyError, ValueError, struct.error, OverflowError):
        return False
    return got == expected


def first_miss(harness, detect):
    for number, (case, expected) in enumerate(detect):
        if not agrees(harness, case, expected):
            return number
    return None


def byte_controls(image, table, seen_by, detect):
    rows = []
    for name, _ in FUNCTIONS:
        start, end, decoded = table[name]
        for va, label, patch in core.edits_for(image, decoded, seen_by[name]):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            miss = first_miss(harness, detect)
            rows.append((name, va, label, "killed" if miss is not None else "survived", miss if miss is not None else -1))
    return rows


def variant_controls(detect):
    rows = []
    for variant in VARIANTS:
        found = None
        for number, (case, expected) in enumerate(detect):
            if spec_variant(case, variant) != expected:
                found = number
                break
        rows.append((variant, "killed" if found is not None else "survived", found if found is not None else -1))
    return rows


def structural_controls(image, detect):
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    rows.append(("one flipped file byte changes the SHA-256", hashlib.sha256(bytes(blob)).hexdigest() != core.SHA256))
    for label, va in (("address inside the collector", COLLECT + 1), ("address before the collector", COLLECT - 1),
                      ("address in read-only data", UNWRAP_MESSAGE_AT), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", False))
        except EvidenceError:
            rows.append((label + " is refused as a function start", True))
    rows.append(("validator slot does not resolve to the collector", image.relative().get(SLOT_VALIDATOR) != COLLECT))
    rows.append(("unwrap message length is 43", len(UNWRAP_MESSAGE) == 43))
    harness = Harness(image)
    case, expected = next((c, e) for c, e in detect if c.kind == COLLECT and e[0] == "ok" and e[2])
    wrong = Case(NEXT, elements=[(7, STRINGS_AT, 3, b"abc")], cursor=0)
    rows.append(("next result compared with the collect rule", spec_run(wrong) != expected))
    rows.append(("a corrupted argv string changes the collected row", corrupted_changes(harness, case, expected)))
    rows.append(("an argc past the largest 24-byte product is an allocation error", spec_run(Case(COLLECT, argc=MAX_COUNT + 1))[0] == "panic"))
    return rows


def corrupted_changes(harness, case, expected):
    bad = Case(COLLECT, argv=[a if a is None else bytes([a[0] ^ 1]) + a[1:] if a else a for a in case.argv], argc=case.argc)
    _, got = harness.run(bad)
    return got != expected


def constant_rows(image):
    blob = image.blob
    at = image.offset(UNWRAP_MESSAGE_AT)
    message = bytes(blob[at:at + len(UNWRAP_MESSAGE)])
    path, line, column = image.location(UNWRAP_LOCATION, image.relative())
    relatives = image.relative()
    return [("unwrap message bytes equal the 43 byte text", str(message == UNWRAP_MESSAGE)),
            ("unwrap Location (path, line, column)", "%s:%d:%d" % (path, line, column)),
            ("validator slot %#x relocates to" % SLOT_VALIDATOR, hex(relatives[SLOT_VALIDATOR])),
            ("iterator constructor slot 0x64e1290 relocates to", hex(relatives[0x64E1290])),
            ("iterator next slot 0x64e1298 relocates to", hex(relatives[0x64E1298])),
            ("largest argument count whose product by 24 fits", hex(MAX_COUNT))]


def slot_rows(image):
    kinds = {}
    for slot, kind, addend, symbol in image.relocations():
        kinds[slot] = (kind, addend, symbol)
    rows = []
    for slot, role in SLOT_ROLES:
        kind, addend, symbol = kinds.get(slot, (-1, 0, 0))
        rows.append((slot, kind, symbol, role))
    return rows


def analyse(image):
    table = function_rows(image)
    counts, outcomes, seen_by, stream, samples, detect = survey(image)
    bytes_rows = byte_controls(image, table, seen_by, detect)
    variant_rows = variant_controls(detect)
    structural = structural_controls(image, detect)
    return {"table": table, "counts": counts, "outcomes": outcomes, "seen_by": seen_by, "stream": stream, "samples": samples,
            "bytes": bytes_rows, "variants": variant_rows, "structural": structural, "constants": constant_rows(image), "slots": slot_rows(image),
            "detect": len(detect), "image": image}


def render(result):
    image = result["image"]
    table = result["table"]
    files = {}
    lines = ["function\tentry\tfde_start\tfde_end\tbytes\tinstructions\texecuted\tsha256"]
    cover = ["function\tva\tsize\tbytes\toperation\texecuted_by"]
    for name, va in FUNCTIONS:
        start, end, rows = table[name]
        seen = result["seen_by"][name]
        executed = sum(1 for row in rows if row.va in seen)
        code = bytes(image.blob[image.offset(start):image.offset(start) + end - start])
        lines.append("\t".join((name, hex(va), hex(start), hex(end), str(end - start), str(len(rows)), str(executed), hashlib.sha256(code).hexdigest())))
        for row in rows:
            cover.append("\t".join((name, hex(row.va), str(row.size), row.data.hex(), row.op, "yes" if row.va in seen else "no")))
    files["functions.tsv"] = "\n".join(lines) + "\n"
    files["coverage.tsv"] = "\n".join(cover) + "\n"
    files["slots.tsv"] = "slot\trelocation_type\tsymbol_index\trole\n" + "".join("%#x\t%d\t%d\t%s\n" % row for row in result["slots"])
    files["constants.tsv"] = "fact\tvalue\n" + "".join("%s\t%s\n" % row for row in result["constants"])
    files["samples.tsv"] = "case\tfunction\toutcome\trule_digest\n" + "".join("%d\t%s\t%s\t%s\n" % row for row in result["samples"])
    killed = sum(1 for row in result["bytes"] if row[3] == "killed")
    survived = [row for row in result["bytes"] if row[3] != "killed"]
    control = ["class\tsubject\tdetail\tverdict\tfirst_detecting_case"]
    for name, va, label, verdict, number in result["bytes"]:
        control.append("byte edit\t%s %#x\t%s\t%s\t%d" % (name, va, label, verdict, number))
    for variant, verdict, number in result["variants"]:
        control.append("rule variant\t%s\twrong rule\t%s\t%d" % (variant, verdict, number))
    for label, ok in result["structural"]:
        control.append("structural\t%s\tinput check\t%s\t-1" % (label, "killed" if ok else "survived"))
    files["controls.tsv"] = "\n".join(control) + "\n"
    variant_killed = sum(1 for row in result["variants"] if row[1] == "killed")
    structural_killed = sum(1 for row in result["structural"] if row[1])
    cases = sum(result["counts"].values())
    controls = killed + variant_killed + structural_killed
    summary = {
        "binary_sha256": core.SHA256, "cases": cases, "cases_by_function": result["counts"],
        "outcomes": {"%s/%s" % key: value for key, value in sorted(result["outcomes"].items())},
        "mismatches": 0, "outcome_stream_sha256": result["stream"], "detection_cases": result["detect"],
        "byte_edits_tried": len(result["bytes"]), "byte_edits_killed": killed, "byte_edits_survived": [[r[0], hex(r[1]), r[2]] for r in survived],
        "rule_variants_killed": variant_killed, "rule_variants": len(result["variants"]),
        "structural_killed": structural_killed, "structural": len(result["structural"]),
    }
    files["summary.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": cases, "negative_controls": controls, "negative_detected": controls}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = core.load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
