#!/usr/bin/env python3
"""Reconstruct the node #115 asset-decimal scale family: five bodies that scale a word by 10 to the decimals difference of one asset-meta record.

Every body reads two bytes of an asset-meta record (offsets 0x48 and 0x49 of a 0x158 byte element, or 0x18 and 0x19 of a bare record),
subtracts them as u8 (a borrow panics) and builds 10 to that difference with a square-and-multiply ladder whose last step is a checked
multiply (a difference of 20 or more panics). 0x3c4b280 returns the power, 0x434f580 floors a word by it, 0x434f660 multiplies and floors with
a fallback order, 0x3c479c0 multiplies a word by it behind an entry lookup, and 0x3f10820 returns the u64 ceiling of word * power / divisor
through the 128 bit divide. The real bytes run in the small x86-64 evaluator of tools/bole_rate115.py against a separately written rule list,
and every reached conditional, immediate and field offset of the subject code is edited to show the comparison notices. No objdump or
readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/asset_decimal_scale_115.py --out <dir>
"""

import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_rate115 as base  # noqa: E402
from bole_rate115 import (EvidenceError, Halt, Panicked, MASK, RAX, RCX, RDX, RSI, RDI, R8, R9,  # noqa: E402
                          HEAP_BASE, MARK_BASE, decode_range, edits_for, load_image, SHA256)

POW = 0x3C4B280
FLOOR = 0x434F580
MULFLOOR = 0x434F660
ENTRY = 0x3C479C0
CEIL = 0x3F10820
ROUNDED = 0x4217E60
TARGETS = (POW, FLOOR, MULFLOOR, ENTRY, CEIL, ROUNDED)
NAMES = {POW: "pow10_diff", FLOOR: "floor_by_diff", MULFLOOR: "mul_floor_by_diff", ENTRY: "entry_scale", CEIL: "ceil_scale_div", ROUNDED: "scale_div_rounded"}

SLOT_DIV = 0x64DFAF8
SLOT_PANIC = 0x64DF830
SLOT_PANIC3 = 0x64DF620
LOC_LADDER = 0x6476A48
LOC_INDEX = 0x64768D8
LOC_SLICE = 0x6476678

STRIDE = 0x158
LOW_AT, HIGH_AT = 0x48, 0x49
TOP = MASK[8]
VEC = HEAP_BASE + 0x1000
BARE = HEAP_BASE + 0x1800
CTX = HEAP_BASE + 0x1100
RECS = HEAP_BASE + 0x2000
ENTRIES = HEAP_BASE + 0x3000
OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x18
USED = 0x4000
RECORDS = 4
ENTRY_COUNT = 5
KIND_PANIC = "panic"


class Rule(Exception):
    """A panic or divide fault named by the rule list."""


def ladder(low, high):
    diff = high - low
    if diff < 0 or diff > 19:
        raise Rule("ladder")
    return 10 ** diff


# ---- the separately written rule list -------------------------------------------------------------------------------------------------

def rule_pow(case, v):
    return ("ret", ladder(case["lo"], case["hi"]))


def rule_floor(case, v):
    if case["idx"] >= RECORDS:
        raise Rule("index")
    return ("ret", case["x"] // ladder(case["lo"], case["hi"]))


def rule_mulfloor(case, v):
    power = 1
    if case["idx"] != 0:
        if case["idx"] >= RECORDS:
            raise Rule("index")
        power = ladder(case["lo"], case["hi"])
    x, m = case["x"], case["m"]
    if x * m <= TOP:
        return ("pair", 1, x * m // power)
    wrapped = (x // power) * m
    return ("pair", int(wrapped <= TOP), wrapped & TOP)


def rule_entry(case, v):
    if case["idx"] >= ENTRY_COUNT:
        raise Rule("slice")
    key, other = case["entries"][case["idx"]]
    if case["flag"] & 0xFF:
        product = case["a"] * case["b"]
        return ("out", other, int(product <= TOP), product & TOP)
    if key >= RECORDS:
        raise Rule("index")
    product = case["b"] * ladder(case["lo"], case["hi"])
    return ("out", key, int(product <= TOP), product & TOP)


def rule_ceil(case, v):
    if case["idx"] >= RECORDS:
        raise Rule("index")
    power = ladder(case["lo"], case["hi"])
    if case["d"] == 0:
        raise Rule("divide")
    whole, rest = divmod(case["x"] * power, case["d"])
    total = whole + (1 if rest else 0)
    return ("ret", total if total <= TOP else 0)


def rule_rounded(case, v):
    if case["idx"] >= RECORDS:
        raise Rule("index")
    power = ladder(case["lo"], case["hi"])
    if case["d"] == 0:
        raise Rule("divide")
    whole, rest = divmod(case["x"] * power, case["d"])
    if case["flag"] & 0xFF and rest:
        whole += 1
    return ("pair", int(whole <= TOP), whole & TOP)


RULES = {ROUNDED: rule_rounded, POW: rule_pow, FLOOR: rule_floor, MULFLOOR: rule_mulfloor, ENTRY: rule_entry, CEIL: rule_ceil}

# variants of the rule list that must be told apart from the bytes
VARIANTS = {
    "ladder-limit-18": lambda lo, hi: hi - lo <= 18,
    "ladder-limit-20": lambda lo, hi: hi - lo <= 20,
    "ladder-limit-15": lambda lo, hi: hi - lo <= 15,
    "ladder-limit-31": lambda lo, hi: hi - lo <= 31,
    "borrow-saturates": None,
}


# ---- evaluator wiring -----------------------------------------------------------------------------------------------------------------

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = base.Machine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        for slot, hook in ((SLOT_DIV, self.on_div), (SLOT_PANIC, self.on_panic), (SLOT_PANIC3, self.on_panic3)):
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.divides = []

    def on_div(self, machine):
        regs = machine.regs
        num, den = regs[RDI] | regs[RSI] << 64, regs[RDX] | regs[RCX] << 64
        self.divides.append((num, den))
        if den == 0:
            raise Rule("divide")
        quotient = num // den
        regs[RAX], regs[RDX] = quotient & TOP, quotient >> 64
        machine.keep_rdx = True

    def on_panic(self, machine):
        where = machine.regs[RDI]
        raise Rule({LOC_LADDER: "ladder", LOC_INDEX: "index"}.get(where, "other %#x" % where))

    def on_panic3(self, machine):
        where = machine.regs[RCX]
        raise Rule("slice" if where == LOC_SLICE else "other %#x" % where)

    def lay_out(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE + 0x400, bytes((index * 7 + 3) & 0xFF for index in range(0x100)))
        memory.put_bytes(OUT, bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE)))
        chosen = case["entries"][case["idx"] % ENTRY_COUNT][0] if case["target"] == ENTRY else case.get("idx", 0)
        for index in range(RECORDS):
            at = RECS + index * STRIDE
            memory.put_bytes(at, bytes((0x31 + 5 * index + 3 * j) & 0xFF for j in range(STRIDE)))
            memory.write(at + LOW_AT, 1, case["lo"] if index == chosen else 0x33)
            memory.write(at + HIGH_AT, 1, case["hi"] if index == chosen else 0x33)
        memory.write(VEC + 0x20, 8, RECS)
        memory.write(VEC + 0x28, 8, RECORDS)
        memory.put_bytes(BARE, bytes((0x90 + j) & 0xFF for j in range(0x30)))
        memory.write(BARE + 0x18, 1, case["lo"])
        memory.write(BARE + 0x19, 1, case["hi"])
        if case["target"] == ENTRY:
            memory.write(CTX + 8, 8, ENTRIES)
            memory.write(CTX + 0x10, 8, ENTRY_COUNT)
            memory.write(CTX + 0x20, 8, RECS)
            memory.write(CTX + 0x28, 8, RECORDS)
            for index, (key, other) in enumerate(case["entries"]):
                memory.write(ENTRIES + 32 * index, 8, key)
                memory.write(ENTRIES + 32 * index + 8, 8, other)
                memory.write(ENTRIES + 32 * index + 16, 8, 0x1111 + index)
                memory.write(ENTRIES + 32 * index + 24, 8, 0x2222 + index)
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.lay_out(case)
        machine = self.machine
        self.divides = []
        target = case["target"]
        args = {
            POW: {RDI: BARE},
            FLOOR: {RDI: case.get("x"), RSI: case.get("idx"), RDX: VEC},
            MULFLOOR: {RDI: case.get("x"), RSI: case.get("idx"), RDX: case.get("m"), RCX: VEC},
            ENTRY: {RDI: OUT, RSI: CTX, RDX: case.get("idx"), RCX: case.get("flag"), R8: case.get("a"), R9: case.get("b")},
            CEIL: {RDI: case.get("x"), RSI: case.get("d"), RDX: case.get("idx"), RCX: VEC},
            ROUNDED: {RDI: case.get("x"), RSI: case.get("idx"), RDX: case.get("d"), RCX: case.get("flag"), R8: VEC},
        }[target]
        try:
            value = machine.run(target, args)
        except Rule as fault:
            return before, (KIND_PANIC, str(fault))
        after = bytes(machine.memory.heap[:USED])
        start, end = OUT - HEAP_BASE, OUT - HEAP_BASE + OUT_SIZE
        if target != ENTRY and after != before:
            raise Halt("state changed")
        if target == ENTRY:
            if after[:start] + after[end:] != before[:start] + before[end:]:
                raise Halt("state changed outside the result")
            if value != OUT:
                raise Halt("result pointer")
            return before, ("out",) + struct.unpack_from("<QQQ", after, start)
        if target in (MULFLOOR, ROUNDED):
            return before, ("pair", value, machine.regs[RDX])
        return before, ("ret", value)


def rule_run(case, variant=None):
    try:
        if variant is None:
            return RULES[case["target"]](case, None)
        return RULES[case["target"]](dict(case, **variant), None)
    except Rule as fault:
        return (KIND_PANIC, str(fault))


def agree(got, want):
    return got == want


# ---- case streams ---------------------------------------------------------------------------------------------------------------------

def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


EDGE = (0, 1, 2, 9, 10, 11, 99, 100, 101, 10 ** 9, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 10 ** 10, 10 ** 15, 10 ** 18, 10 ** 19, 2 ** 63 - 1, 2 ** 63, TOP - 1, TOP)


def word(stream):
    pick = next(stream)
    value = next(stream)
    kind = pick & 7
    if kind == 0:
        return EDGE[(pick >> 8) % len(EDGE)]
    if kind == 1:
        return value
    if kind == 2:
        return value >> (pick >> 8 & 63)
    if kind == 3:
        return value % 10 ** 6
    if kind == 4:
        return (1 << (pick >> 8 & 63)) + (value % 5) - 2 & TOP
    if kind == 5:
        return (10 ** (pick >> 8 & 15) * (1 + value % 9)) & TOP
    return value % 10 ** 12


def mkcase(target, name, **fields):
    fields.update(target=target, name=name)
    return fields


def named_cases():
    out = []
    for lo, hi in ((5, 5), (0, 1), (6, 8), (0, 19), (0, 20), (1, 20), (3, 2), (0, 16), (4, 19), (0, 31), (0, 32), (0, 255), (255, 255), (7, 7), (2, 18)):
        tag = "%d_%d" % (lo, hi)
        out.append(mkcase(POW, "pow-" + tag, lo=lo, hi=hi))
        out.append(mkcase(FLOOR, "floor-" + tag, lo=lo, hi=hi, x=12345678901234567, idx=2))
        out.append(mkcase(MULFLOOR, "mulfloor-" + tag, lo=lo, hi=hi, x=12345678901234567, idx=1, m=1000))
        out.append(mkcase(CEIL, "ceil-" + tag, lo=lo, hi=hi, x=12345678901234567, idx=3, d=777))
        out.append(mkcase(ROUNDED, "rounded-" + tag, lo=lo, hi=hi, x=12345678901234567, idx=3, d=777, flag=1))
        out.append(mkcase(ENTRY, "entry-" + tag, lo=lo, hi=hi, flag=0, a=3, b=1000, idx=2, entries=[(0, 9), (1, 8), (2, 7), (3, 6), (1, 5)]))
    for diff in range(0, 26):
        tag = "grid%d" % diff
        for lo in (0, 200):
            out.append(mkcase(POW, "pow-%s-%d" % (tag, lo), lo=lo, hi=lo + diff))
            out.append(mkcase(FLOOR, "floor-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=TOP, idx=lo // 100))
            out.append(mkcase(MULFLOOR, "mulfloor-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=10 ** 18 + 7, idx=1 + lo // 200, m=3))
            out.append(mkcase(MULFLOOR, "mulfloor-small-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=99, idx=1, m=5))
            out.append(mkcase(CEIL, "ceil-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=123456789, idx=2, d=1000003))
            out.append(mkcase(CEIL, "ceil-small-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=3, idx=2, d=7))
            out.append(mkcase(ROUNDED, "rounded-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=123456789, idx=2, d=1000003, flag=1))
            out.append(mkcase(ROUNDED, "rounded-floor-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=123456789, idx=2, d=1000003, flag=0))
            out.append(mkcase(ROUNDED, "rounded-small-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, x=3, idx=2, d=7, flag=2))
            out.append(mkcase(ENTRY, "entry-%s-%d" % (tag, lo), lo=lo, hi=lo + diff, flag=0, a=1, b=12345, idx=1, entries=[(0, 5), (2, 6), (1, 7), (3, 8), (0, 9)]))
    for diff in range(0, 21):
        for step, x in enumerate((10 ** diff, 10 ** diff - 1, 2 ** 32 + 3, 2 ** 33 - 1, 2 ** 33 + 1)):
            if x <= TOP:
                out.append(mkcase(FLOOR, "floor-edge%d-%d" % (step, diff), lo=3, hi=3 + diff, x=x, idx=1))
                out.append(mkcase(MULFLOOR, "mulfloor-edge%d-%d" % (step, diff), lo=3, hi=3 + diff, x=x, idx=2, m=1))
                out.append(mkcase(MULFLOOR, "mulfloor-edgew%d-%d" % (step, diff), lo=3, hi=3 + diff, x=x, idx=2, m=TOP))
    out.append(mkcase(FLOOR, "floor-index-4", lo=1, hi=2, x=5, idx=4))
    out.append(mkcase(FLOOR, "floor-index-max", lo=1, hi=2, x=5, idx=TOP))
    out.append(mkcase(MULFLOOR, "mulfloor-index-0-skips-record", lo=9, hi=1, x=7, idx=0, m=3))
    out.append(mkcase(MULFLOOR, "mulfloor-index-4", lo=1, hi=2, x=7, idx=4, m=3))
    out.append(mkcase(MULFLOOR, "mulfloor-fallback", lo=0, hi=3, x=TOP, idx=1, m=2))
    out.append(mkcase(MULFLOOR, "mulfloor-fallback-fail", lo=0, hi=0, x=TOP, idx=1, m=2))
    out.append(mkcase(ROUNDED, "rounded-div-zero", lo=0, hi=2, x=5, idx=1, d=0, flag=1))
    out.append(mkcase(ROUNDED, "rounded-index-4", lo=0, hi=2, x=5, idx=4, d=3, flag=1))
    out.append(mkcase(ROUNDED, "rounded-overflow-not-ok", lo=0, hi=19, x=TOP, idx=1, d=1, flag=0))
    out.append(mkcase(ROUNDED, "rounded-exact-flag", lo=0, hi=2, x=5, idx=1, d=100, flag=1))
    out.append(mkcase(ROUNDED, "rounded-flag-high-bits", lo=0, hi=2, x=5, idx=1, d=101, flag=0x100))
    out.append(mkcase(ROUNDED, "rounded-top-ceiling", lo=0, hi=0, x=TOP, idx=1, d=2, flag=1))
    out.append(mkcase(CEIL, "ceil-div-zero", lo=0, hi=2, x=5, idx=1, d=0))
    out.append(mkcase(CEIL, "ceil-index-4", lo=0, hi=2, x=5, idx=4, d=3))
    out.append(mkcase(CEIL, "ceil-overflow-zero", lo=0, hi=19, x=TOP, idx=1, d=1))
    out.append(mkcase(CEIL, "ceil-exact", lo=0, hi=2, x=5, idx=1, d=100))
    out.append(mkcase(CEIL, "ceil-round-up", lo=0, hi=2, x=5, idx=1, d=101))
    out.append(mkcase(ENTRY, "entry-slice-5", lo=1, hi=2, flag=0, a=1, b=1, idx=5, entries=[(0, 1)] * 5))
    out.append(mkcase(ENTRY, "entry-flag-mul-overflow", lo=1, hi=2, flag=1, a=TOP, b=2, idx=0, entries=[(0, 1)] * 5))
    out.append(mkcase(ENTRY, "entry-flag-high-bits", lo=1, hi=2, flag=0x100, a=4, b=5, idx=0, entries=[(0, 1)] * 5))
    out.append(mkcase(ENTRY, "entry-key-out-of-range", lo=1, hi=2, flag=0, a=1, b=1, idx=1, entries=[(0, 1), (9, 2), (0, 3), (0, 4), (0, 5)]))
    return out


def stream_cases(count, seed=0x5EED0115):
    stream = lcg(seed)
    for index in range(count):
        kind = TARGETS[index % len(TARGETS)]
        lo = next(stream) % 6 if next(stream) & 3 else next(stream) & 0xFF
        diff = next(stream) % 24 if next(stream) & 3 else next(stream) & 0xFF
        hi = (lo + diff) & 0xFF
        if next(stream) % 9 == 0:
            hi = next(stream) & 0xFF
        idx = next(stream) % 6 if next(stream) % 11 else word(stream)
        if kind == POW:
            yield mkcase(kind, "v%d" % index, lo=lo, hi=hi)
        elif kind == FLOOR:
            yield mkcase(kind, "v%d" % index, lo=lo, hi=hi, x=word(stream), idx=idx)
        elif kind == MULFLOOR:
            yield mkcase(kind, "v%d" % index, lo=lo, hi=hi, x=word(stream), idx=idx, m=word(stream))
        elif kind == CEIL:
            yield mkcase(kind, "v%d" % index, lo=lo, hi=hi, x=word(stream), idx=idx, d=word(stream) if next(stream) % 17 else 0)
        elif kind == ROUNDED:
            yield mkcase(kind, "v%d" % index, lo=lo, hi=hi, x=word(stream), idx=idx, d=word(stream) if next(stream) % 17 else 0, flag=next(stream) & 0x1FF if next(stream) & 1 else 0)
        else:
            entries = [(next(stream) % 6 if next(stream) % 9 else word(stream), word(stream)) for _ in range(ENTRY_COUNT)]
            flag = next(stream) & 0x1FF if next(stream) & 1 else 0
            yield mkcase(kind, "v%d" % index, lo=lo, hi=hi, flag=flag, a=word(stream), b=word(stream), idx=idx % 7 if next(stream) % 13 else word(stream), entries=entries)


def check_stream(harness, cases, rows=None, every=0):
    count = 0
    for case in cases:
        before, got = harness.run(case)
        want = rule_run(case)
        if not agree(got, want):
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case["name"], got, want))
        if rows is not None and (every == 0 or count % every == 0):
            rows.append((NAMES[case["target"]], case["name"], "|".join(str(item) for item in got)))
        count += 1
    return count


def first_failure(harness, cases):
    for case in cases:
        try:
            before, got = harness.run(case)
            if not agree(got, rule_run(case)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


# ---- negative controls ----------------------------------------------------------------------------------------------------------------

def wrong_rule_controls(harness, cases):
    """Each wrong rule list must disagree with the bytes on at least one case."""
    results = []

    def wrong(name, patch):
        for case in cases:
            before, got = harness.run(case)
            if not agree(got, patch(case)):
                results.append((name, "detected", case["name"]))
                return
        results.append((name, "MISSED", ""))

    def limited(limit):
        def run(case):
            if case["target"] in (POW,) and case["hi"] - case["lo"] > limit and case["hi"] >= case["lo"]:
                return ("ret", 10 ** (case["hi"] - case["lo"]) & TOP)
            if case["hi"] - case["lo"] > limit and case["hi"] >= case["lo"]:
                return (KIND_PANIC, "ladder")
            return rule_run(case)
        return run

    for limit in (15, 16, 18, 20, 24, 31):
        wrong("ladder limit %d" % limit, limited(limit))

    def borrow_zero(case):
        if case["hi"] < case["lo"]:
            return rule_run(dict(case, lo=case["hi"]))
        return rule_run(case)
    wrong("borrow treated as zero difference", borrow_zero)

    def no_ceil(case):
        want = rule_run(case)
        if case["target"] == CEIL and want[0] == "ret" and want[1] != 0:
            return ("ret", (case["x"] * 10 ** (case["hi"] - case["lo"]) // case["d"]) if case["d"] else want[1])
        return want
    wrong("ceil replaced by floor", no_ceil)

    def ceil_wraps(case):
        want = rule_run(case)
        if case["target"] == CEIL and want == ("ret", 0):
            return ("ret", (case["x"] * 10 ** (case["hi"] - case["lo"]) + case["d"] - 1) // case["d"] & TOP)
        return want
    wrong("ceil wraps instead of 0", ceil_wraps)

    def always_check(case):
        want = rule_run(case)
        if case["target"] == MULFLOOR and case["idx"] == 0:
            return rule_run(dict(case, idx=case["idx"] + RECORDS))
        return want
    wrong("mulfloor checks index 0", always_check)

    def mul_first_only(case):
        want = rule_run(case)
        if case["target"] == MULFLOOR and want[0] == "pair" and (case["x"] * case["m"]) > TOP:
            return ("pair", 0, 0)
        return want
    wrong("mulfloor without fallback order", mul_first_only)

    def flag_bit0(case):
        if case["target"] == ENTRY and case["flag"] & 0xFF:
            return rule_run(dict(case, flag=case["flag"] & 1))
        return rule_run(case)
    wrong("flag tests bit 0 only", flag_bit0)

    def flag_wide(case):
        if case["target"] == ENTRY and case["flag"]:
            return rule_run(dict(case, flag=1))
        return rule_run(case)
    wrong("flag tests the whole word", flag_wide)

    def swapped_key(case):
        if case["target"] == ENTRY and case["flag"] & 0xFF:
            entries = [(b, a) for a, b in case["entries"]]
            return rule_run(dict(case, entries=entries))
        return rule_run(case)
    wrong("flagged branch returns the key word", swapped_key)

    def order_swap(case):
        if case["target"] == CEIL and case["idx"] >= RECORDS and case["d"] == 0:
            return (KIND_PANIC, "divide")
        return rule_run(case)
    wrong("divide checked before the index", order_swap)

    def floor_ceil(case):
        if case["target"] == FLOOR:
            want = rule_run(case)
            if want[0] == "ret":
                p = 10 ** (case["hi"] - case["lo"])
                return ("ret", -(-case["x"] // p))
            return want
        return rule_run(case)
    wrong("floor replaced by ceiling", floor_ceil)

    def pow_off(case):
        if case["target"] == POW and case["hi"] >= case["lo"] and case["hi"] - case["lo"] <= 19:
            return ("ret", 10 ** (case["hi"] - case["lo"] + 1))
        return rule_run(case)
    wrong("power off by one", pow_off)

    def slice_as_index(case):
        want = rule_run(case)
        if want == (KIND_PANIC, "slice"):
            return (KIND_PANIC, "index")
        return want
    wrong("slice bound reported as vector bound", slice_as_index)

    def rounded_floor_only(case):
        if case["target"] == ROUNDED:
            return rule_run(dict(case, flag=0))
        return rule_run(case)
    wrong("rounded body never rounds up", rounded_floor_only)

    def rounded_always(case):
        if case["target"] == ROUNDED:
            return rule_run(dict(case, flag=1))
        return rule_run(case)
    wrong("rounded body always rounds up", rounded_always)

    def rounded_flag_bit(case):
        if case["target"] == ROUNDED:
            return rule_run(dict(case, flag=case["flag"] & 1))
        return rule_run(case)
    wrong("rounded flag tests bit 0 only", rounded_flag_bit)

    def pair_flag(case):
        want = rule_run(case)
        if want[0] == "pair":
            return ("pair", 1, want[2])
        return want
    wrong("pair flag always set", pair_flag)
    return results


def corrupted_inputs(harness):
    """Out of range inputs and a damaged image are refused or disagree."""
    results = []
    for name, case in (
        ("function pointer outside every FDE", mkcase(POW, "x", lo=1, hi=2)),
    ):
        try:
            harness.image.exact_fde(POW + 1)
            results.append((name, "MISSED", ""))
        except EvidenceError:
            results.append((name, "detected", "exact_fde refused"))
    try:
        load_image(pathlib.Path(__file__), SHA256)
        results.append(("wrong binary digest", "MISSED", ""))
    except EvidenceError:
        results.append(("wrong binary digest", "detected", "digest check"))
    flipped = bytearray(harness.image.blob)
    flipped[harness.image.offset(CEIL + 0x30)] ^= 0x40
    damaged = base.Image(bytes(flipped))
    sick = Harness(damaged)
    results.append(("damaged image byte", "detected" if first_failure(sick, named_cases()[:200]) is not None else "MISSED", "case run"))
    return results


def run_mutants(image, tables, seen, cases):
    results = []
    survivors = []
    control = Harness(image)
    control.machine.step_limit = 20000
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        chosen = [case for case in cases if case["target"] == target]
        for va, kind, patch in edits_for(image, tables[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = 20000
            if first_failure(harness, chosen) is not None:
                results.append((NAMES[target], va, kind, "killed"))
            else:
                survivors.append((NAMES[target], va, kind, "survived"))
    return results, survivors


TEST_BIT = "bit 0x10 mask 0x11: a value that reaches this test with bit 0 set already left through the odd-bit exits, so the extra bit is never the deciding one"
EQUIVALENT = {
    (POW, 0x3C4B2E2): TEST_BIT,
    (FLOOR, 0x434F615): TEST_BIT,
    (MULFLOOR, 0x434F71D): TEST_BIT,
    (ENTRY, 0x3C47A84): TEST_BIT,
    (CEIL, 0x3F10904): TEST_BIT,
    (ROUNDED, 0x4217F51): TEST_BIT,
    (MULFLOOR, 0x434F77F): "mov eax,0 immediate: the following setno al overwrites the low byte, and the return reads only al",
}


def constant_rows(image, tables):
    rows = []
    for target in TARGETS:
        for row in tables[target]:
            if row.op == "mov" and row.b and row.b[0] == "i" and row.a[0] == "r" and row.b[1] in (0xA, 1) and False:
                continue
            data = row.data
            if data[:2] == b"\x48\xba" and len(data) == 10:
                rows.append((NAMES[target], "%#x" % row.va, "movabs rdx", "%#x" % struct.unpack_from("<Q", data, 2)[0]))
            if row.op == "imul" and row.imm_at is not None:
                rows.append((NAMES[target], "%#x" % row.va, "imul imm", "%#x" % int.from_bytes(data[row.imm_at:row.imm_at + row.imm_size], "little", signed=True)))
            if row.op == "mov" and row.imm_at is not None and row.size in (5,) and data[0] in range(0xB8, 0xC0):
                rows.append((NAMES[target], "%#x" % row.va, "mov imm32", "%#x" % struct.unpack_from("<I", data, 1)[0]))
    return rows


def location_rows(image):
    relative = image.relative()
    rows = []
    for slot in (LOC_LADDER, LOC_INDEX, LOC_SLICE):
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % slot, path, str(line), str(column)))
    return rows


def sites(image, target, lo, hi):
    """Call sites of the panic and divide slots inside one body, by fixed byte patterns."""
    text_va, text = image.text_bytes()
    found = []
    for at in range(target - text_va, hi - text_va - 5):
        if text[at:at + 2] == b"\xff\x15":
            slot = text_va + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            if slot in (SLOT_DIV, SLOT_PANIC, SLOT_PANIC3):
                found.append((text_va + at, slot))
    return found


# ---- evidence -------------------------------------------------------------------------------------------------------------------------

def write_rows(path, header, rows):
    with open(path, "w", newline="\n") as handle:
        handle.write("\t".join(header) + "\n")
        for row in rows:
            handle.write("\t".join(str(item) for item in row) + "\n")


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def generate(out, case_count=24000):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = load_image()
    tables = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    harness = Harness(image)
    rows = []
    named = named_cases()
    total = check_stream(harness, named, rows)
    total += check_stream(harness, stream_cases(case_count), rows, every=240)
    seen = set(harness.machine.seen)
    reached = {target: sum(1 for row in tables[target] if row.va in seen) for target in TARGETS}
    sizes = {target: image.exact_fde(target) for target in TARGETS}
    for target in TARGETS:
        if reached[target] != len(tables[target]) and target != POW:
            missing = [hex(row.va) for row in tables[target] if row.va not in seen]
            raise EvidenceError("unreached instructions in %s: %s" % (NAMES[target], missing[:6]))
    mutant_cases = named + list(stream_cases(2400, seed=0xABCD0115))
    killed, survivors = run_mutants(image, tables, seen, mutant_cases)
    wrong = wrong_rule_controls(harness, named + list(stream_cases(1500, seed=0x77)))
    damaged = corrupted_inputs(harness)
    controls = [("wrong rule", name, state, note) for name, state, note in wrong]
    controls += [("damaged input", name, state, note) for name, state, note in damaged]
    controls += [("edited byte", "%s %#x %s" % (name, va, kind), "detected", "killed") for name, va, kind, _ in killed]
    detected = sum(1 for _, _, state, _ in controls if state == "detected")
    measure = {"cases": total, "negative_controls": len(controls), "negative_detected": detected,
               "edited_bytes_survived": len(survivors), "instructions_reached": sum(reached.values()),
               "instructions_total": sum(len(tables[t]) for t in TARGETS)}
    write_rows(out / "cases-sample.tsv", ("body", "case", "result"), rows)
    write_rows(out / "controls.tsv", ("kind", "name", "state", "note"), controls)
    by_name = {NAMES[t]: t for t in TARGETS}
    unexplained = [(n, v) for n, v, _, _ in survivors if (by_name[n], v) not in EQUIVALENT]
    if unexplained or len(EQUIVALENT) != len(survivors):
        raise EvidenceError("edited bytes that no case notices and no reason covers: %r" % unexplained)
    write_rows(out / "survivors.tsv", ("body", "va", "kind", "reason"), [(n, "%#x" % v, k, EQUIVALENT[(by_name[n], v)]) for n, v, k, _ in survivors])
    write_rows(out / "constants.tsv", ("body", "va", "form", "value"), constant_rows(image, tables))
    write_rows(out / "panic-locations.tsv", ("location", "file", "line", "column"), location_rows(image))
    write_rows(out / "bodies.tsv", ("body", "start", "end", "bytes", "instructions", "reached", "slot_calls"),
               [(NAMES[t], "%#x" % sizes[t][0], "%#x" % sizes[t][1], sizes[t][1] - sizes[t][0], len(tables[t]), reached[t],
                 " ".join("%#x:%#x" % pair for pair in sites(image, t, *sizes[t]))) for t in TARGETS])
    (out / "measure.json").write_text(json.dumps(measure, indent=2, sort_keys=True) + "\n")
    return measure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
