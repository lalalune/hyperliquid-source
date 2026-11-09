#!/usr/bin/env python3
"""Reconstruct the node #115 chrono `format::scan` helpers: eight bodies run from the ELF bytes against a written rule list.

The bodies are number 0x161f900, nanosecond_fixed 0x1625550, short_month0 0x1624fb0, short_weekday 0x1625100, short_or_long_month0 0x1625680,
comment_2822 0x1624e80, trim_start 0x16288c0 and the colon-or-space trim 0x1628a40. Each real body runs in the small x86-64 evaluator of
tools/bole_rate115.py with the panic entry points as recording stubs. A rule list written from the documented chrono behaviour (a different
code path from the bytes) predicts the exact 32 result bytes, the two result registers or the panic of every generated input, and every
reached conditional, immediate and displacement of the eight bodies is edited to prove the cases notice. No objdump or readelf output is
parsed and the binary is never executed. Standard library only.

    python3 tools/chrono_scan_family_115.py --out <dir>
"""

import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_rate115 as cpu  # noqa: E402

BINARY = cpu.BINARY
SHA256 = cpu.SHA256
EvidenceError = cpu.EvidenceError
Halt = cpu.Halt
Panicked = cpu.Panicked

NUMBER, NANO, MONTH, WEEKDAY, LONG_MONTH, COMMENT, TRIM, COLON = (
    0x161F900, 0x1625550, 0x1624FB0, 0x1625100, 0x1625680, 0x1624E80, 0x16288C0, 0x1628A40)
TARGETS = (NUMBER, NANO, MONTH, WEEKDAY, LONG_MONTH, COMMENT, TRIM, COLON)
NAMES = {NUMBER: "number", NANO: "nanosecond_fixed", MONTH: "short_month0", WEEKDAY: "short_weekday",
         LONG_MONTH: "short_or_long_month0", COMMENT: "comment_2822", TRIM: "trim_start", COLON: "trim_colon_space"}

# slot -> panic name for the five entry points the bodies call through the GOT
PANIC_SLOTS = {0x64DF670: "slice", 0x64DF730: "assert", 0x64DF620: "index", 0x64DF520: "overflow", 0x64DF6A0: "other"}
SLOT_LONG_CALL = 0x64E1B10
SLOT_WS_TABLE = 0x64DFC30
POW_TABLE = 0x46B7A0
LONG_TABLE = 0x64050B0
MARK_BASE = 0x7700000000
STR = cpu.HEAP_BASE + 0x1000
OUT = cpu.HEAP_BASE + 0x200
OUT_SIZE = 0x20
USED = 0x2000
FILL = bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE))
OUT_OF_RANGE, INVALID, TOO_SHORT = 0, 3, 4
I64_MAX = (1 << 63) - 1

MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
LONG_MONTHS = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# Unicode White_Space, the set char::is_whitespace answers for
WHITESPACE = frozenset(list(range(9, 14)) + [0x20, 0x85, 0xA0, 0x1680] + list(range(0x2000, 0x200B)) + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000])


class Case:
    __slots__ = ("kind", "data", "a", "b", "crit")

    def __init__(self, kind, data, a=0, b=0, crit=False):
        self.kind, self.data, self.a, self.b, self.crit = kind, bytes(data), a, b, crit

    def label(self):
        return "%s|%s|%d|%d" % (NAMES[self.kind], self.data.hex(), self.a, self.b)


# ---------------------------------------------------------------- the written rule list

class Spec:
    """Chrono scan rules. `mutants` names deliberate mistakes; the empty set is the claim under test."""

    def __init__(self, mutants=frozenset()):
        self.m = mutants

    @staticmethod
    def boundary(data, index):
        """str::is_char_boundary for a byte string; slicing `[index..]` panics when it is false."""
        return index >= len(data) or not 0x80 <= data[index] <= 0xBF

    @staticmethod
    def pack(*fields):
        out = bytearray(FILL)
        for offset, size, value in fields:
            out[offset:offset + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        return ("out", bytes(out))

    def err(self, tag):
        return self.pack((0, 8, 0), (8, 1, tag))

    def ok(self, rest_at, length, value=None, width=8):
        fields = [(0, 8, STR + rest_at), (8, 8, length)]
        if value is not None:
            fields.append((0x10, width, value))
        return self.pack(*fields)

    def number(self, case):
        data, low, high = case.data, case.a, case.b
        size = len(data)
        if low > high:
            return ("panic", "assert", 28, 0)
        if size < low:
            return self.err(TOO_SHORT)
        value, index = 0, 0
        while index != size:
            byte = data[index]
            if not 0x30 <= byte <= 0x39:
                if index < low:
                    return self.err(INVALID)
                if not self.boundary(data, index):
                    return ("panic", "slice", index, size)
                return self.ok(index, size - index, value)
            value = value * 10
            if value > I64_MAX:
                return self.err(OUT_OF_RANGE)
            value += byte - 0x30
            if value > I64_MAX:
                return self.err(OUT_OF_RANGE)
            index += 1
            if index == high:
                break
        # the do-while quirk: after the loop the cut is min(len, max), so max == 0 leaves the input untouched
        cut = min(size, high)
        if cut != 0 and high < size and not self.boundary(data, cut):
            return ("panic", "slice", cut, size)
        return self.ok(cut, size - cut, value)

    def nano(self, case):
        data, digits = case.data, case.a
        size = len(data)
        if size < digits:
            return self.err(TOO_SHORT)
        value = 0
        for index in range(digits):
            byte = data[index]
            if not 0x30 <= byte <= 0x39:
                return self.err(INVALID)
            value = value * 10
            if value > I64_MAX:
                return self.err(OUT_OF_RANGE)
            value += byte - 0x30
            if value > I64_MAX:
                return self.err(OUT_OF_RANGE)
        if digits < size and digits != 0 and not self.boundary(data, digits):
            return ("panic", "slice", digits, size)
        if digits > 9:
            return ("panic", "index", digits, 10)
        value *= 10 ** (9 - digits) if digits else 1
        if value > I64_MAX:
            return self.err(OUT_OF_RANGE)
        return self.ok(digits, size - digits, value)

    def lower3(self, data):
        return bytes(byte | 0x20 for byte in data[:3])

    def month(self, case):
        data = case.data
        if len(data) < 3:
            return self.err(TOO_SHORT)
        word = self.lower3(data).decode("latin-1")
        if word not in MONTHS:
            return self.err(INVALID)
        if len(data) != 3 and not self.boundary(data, 3):
            return ("panic", "slice", 3, len(data))
        return self.ok(3, len(data) - 3, MONTHS.index(word), 1)

    def weekday(self, case):
        data = case.data
        if len(data) < 3:
            return self.pack((0, 1, TOO_SHORT), (0x10, 1, 7))
        word = self.lower3(data).decode("latin-1")
        if word not in WEEKDAYS:
            return self.pack((0, 1, INVALID), (0x10, 1, 7))
        if len(data) != 3 and not self.boundary(data, 3):
            return ("panic", "slice", 3, len(data))
        return self.ok(3, len(data) - 3, WEEKDAYS.index(word), 1)

    def long_month(self, case):
        data = case.data
        short = self.month(case)
        if short[0] == "panic" or short[1][0:8] == bytes(8):
            return short
        index = short[1][0x10]
        rest = data[3:]
        suffix = LONG_MONTHS[index][3:].encode()
        if len(rest) >= len(suffix) and bytes((c + 32) if 65 <= c <= 90 else c for c in rest[:len(suffix)]) == suffix:
            if index != 4 and len(rest) > len(suffix) and not self.boundary(rest, len(suffix)):
                return ("panic", "slice", len(suffix), len(rest))
            return self.ok(3 + len(suffix), len(rest) - len(suffix), index, 1)
        return self.ok(3, len(rest), index, 1)

    @staticmethod
    def trim_count(text, extra=()):
        """Bytes dropped from the front: whole characters that are Unicode white space (or one of `extra`)."""
        cut = 0
        for char in text.decode("utf-8", "surrogateescape"):
            if ord(char) in WHITESPACE or ord(char) in extra:
                cut += len(char.encode("utf-8"))
            else:
                break
        return cut

    def trim(self, case):
        cut = self.trim_count(case.data)
        return ("regs", STR + cut, len(case.data) - cut)

    def colon(self, case):
        cut = self.trim_count(case.data, (0x3A,))
        return ("regs", STR + cut, len(case.data) - cut)

    def comment(self, case):
        data = case.data
        cut = self.trim_count(data)
        text = data[cut:]
        if not text:
            return self.err(TOO_SHORT)
        if text[0] != 0x28:
            return self.err(INVALID)
        depth, index = 1, 1
        while index < len(text):
            byte = text[index]
            index += 1
            if byte == 0x5C:
                index += 1
            elif byte == 0x28:
                depth += 1
            elif byte == 0x29:
                depth -= 1
                if depth == 0:
                    if not self.boundary(text, index):
                        return ("panic", "slice", index, len(text))
                    return self.ok(cut + index, len(text) - index)
        return self.err(TOO_SHORT)

    def run(self, case):
        return {NUMBER: self.number, NANO: self.nano, MONTH: self.month, WEEKDAY: self.weekday, LONG_MONTH: self.long_month,
                COMMENT: self.comment, TRIM: self.trim, COLON: self.colon}[case.kind](case)


# ---------------------------------------------------------------- deliberately wrong rule lists

class Wrong(Spec):
    """One mistake each; the case set must contradict every one of them."""

    def number(self, case):
        m = self.m
        if "number-skip-assert" in m and case.a > case.b:
            return Spec.number(self, Case(NUMBER, case.data, case.b, case.b))
        if "number-signed-ceiling-u64" in m:
            old = I64_MAX
            try:
                globals()["I64_MAX"] = (1 << 64) - 1
                return Spec.number(self, case)
            finally:
                globals()["I64_MAX"] = old
        if "number-min-ignored" in m and not case.a > case.b:
            return Spec.number(self, Case(NUMBER, case.data, 0, case.b))
        if "number-bounded-max-zero" in m and case.b == 0 and case.a == 0:
            return Spec.number(self, Case(NUMBER, case.data, 0, 1 << 70))
        return Spec.number(self, case)

    def nano(self, case):
        m = self.m
        if "nano-scale-wrong" in m:
            got = Spec.nano(self, case)
            if got[0] == "out" and got[1][0:8] != bytes(8) and case.a:
                value = struct.unpack_from("<Q", got[1], 0x10)[0] * 10 // 10 + 1
                return self.pack((0, 8, STR + case.a), (8, 8, len(case.data) - case.a), (0x10, 8, value))
            return got
        if "nano-digit-error-too-short" in m:
            got = Spec.nano(self, case)
            if got[0] == "out" and got[1][8] == INVALID and got[1][0:8] == bytes(8):
                return self.err(TOO_SHORT)
            return got
        if "nano-index-ignored" in m and case.a > 9:
            return self.err(INVALID)
        return Spec.nano(self, case)

    def month(self, case):
        m = self.m
        if "month-case-sensitive" in m and case.data[:3] != case.data[:3].lower():
            return self.err(INVALID if len(case.data) >= 3 else TOO_SHORT)
        if "month-sep-first" in m:
            got = Spec.month(self, case)
            if got[0] == "out" and got[1][0x10] == 8 and got[1][0:8] != bytes(8):
                return self.pack((0, 8, STR + 3), (8, 8, len(case.data) - 3), (0x10, 1, 9))
            return got
        if "month-short-is-invalid" in m and len(case.data) < 3:
            return self.err(INVALID)
        if "month-no-boundary-panic" in m:
            if len(case.data) > 3 and case.data[3] & 0xC0 == 0x80 and Spec.month(self, case)[0] == "panic":
                return self.ok(3, len(case.data) - 3, MONTHS.index(self.lower3(case.data).decode("latin-1")), 1)
        return Spec.month(self, case)

    def weekday(self, case):
        m = self.m
        if "weekday-sunday-zero" in m:
            got = Spec.weekday(self, case)
            if got[0] == "out" and got[1][0x10] == 6:
                return self.ok(3, len(case.data) - 3, 0, 1)
            return got
        if "weekday-err-value-zero" in m:
            got = Spec.weekday(self, case)
            if got[0] == "out" and got[1][0x10] == 7:
                return self.pack((0, 1, got[1][0]), (0x10, 1, 0))
            return got
        if "weekday-thursday-swapped" in m:
            got = Spec.weekday(self, case)
            if got[0] == "out" and got[1][0x10] in (1, 3):
                return self.ok(3, len(case.data) - 3, 4 - got[1][0x10], 1)
            return got
        return Spec.weekday(self, case)

    def long_month(self, case):
        m = self.m
        got = Spec.long_month(self, case)
        if got[0] != "out" or got[1][0:8] == bytes(8):
            return got
        if "long-case-sensitive" in m and case.data[3:] != case.data[3:].lower():
            return Spec.month(self, case)
        if "long-may-suffix" in m and got[1][0x10] == 4 and len(case.data) >= 4:
            return self.ok(4, len(case.data) - 4, 4, 1)
        if "long-prefix-only" in m and got[1][0x10] != 4:
            return Spec.month(self, case)
        return got

    def trim(self, case):
        if "trim-ascii-only" in self.m:
            cut = 0
            for char in case.data.decode("utf-8"):
                if ord(char) in WHITESPACE and ord(char) < 0x80:
                    cut += 1
                else:
                    break
            return ("regs", STR + cut, len(case.data) - cut)
        if "trim-includes-zero-width" in self.m:
            cut = self.trim_count(case.data, (0x200B,))
            return ("regs", STR + cut, len(case.data) - cut)
        if "trim-misses-nel" in self.m:
            cut = 0
            for char in case.data.decode("utf-8"):
                if ord(char) in WHITESPACE and ord(char) != 0x85:
                    cut += len(char.encode("utf-8"))
                else:
                    break
            return ("regs", STR + cut, len(case.data) - cut)
        return Spec.trim(self, case)

    def colon(self, case):
        if "colon-not-skipped" in self.m:
            return Spec.trim(self, case)
        if "colon-only-first" in self.m:
            text = case.data
            cut = self.trim_count(text)
            if cut < len(text) and text[cut] == 0x3A:
                cut += 1
            return ("regs", STR + cut, len(text) - cut)
        return Spec.colon(self, case)

    def comment(self, case):
        m = self.m
        data = case.data
        if "comment-no-escape" in m:
            return self.comment_with(data, escapes=False)
        if "comment-no-nesting" in m:
            return self.comment_with(data, nesting=False)
        if "comment-start-not-trimmed" in m:
            if data and data[0] != 0x28:
                return self.err(INVALID)
        if "comment-open-is-invalid" in m:
            got = Spec.comment(self, case)
            if got[0] == "out" and got[1][0:8] == bytes(8) and got[1][8] == TOO_SHORT and data.lstrip().startswith(b"("):
                return self.err(INVALID)
            return got
        return Spec.comment(self, case)

    def comment_with(self, data, escapes=True, nesting=True):
        cut = self.trim_count(data)
        text = data[cut:]
        if not text:
            return self.err(TOO_SHORT)
        if text[0] != 0x28:
            return self.err(INVALID)
        depth, index = 1, 1
        while index < len(text):
            byte = text[index]
            index += 1
            if byte == 0x5C and escapes:
                index += 1
            elif byte == 0x28 and nesting:
                depth += 1
            elif byte == 0x29:
                depth -= 1
                if depth == 0:
                    return self.ok(cut + index, len(text) - index)
        return self.err(TOO_SHORT)


SPEC_MUTANTS = (
    "number-skip-assert", "number-signed-ceiling-u64", "number-min-ignored", "number-bounded-max-zero",
    "nano-scale-wrong", "nano-digit-error-too-short", "nano-index-ignored",
    "month-case-sensitive", "month-sep-first", "month-short-is-invalid", "month-no-boundary-panic",
    "weekday-sunday-zero", "weekday-err-value-zero", "weekday-thursday-swapped",
    "long-case-sensitive", "long-may-suffix", "long-prefix-only",
    "trim-ascii-only", "trim-includes-zero-width", "trim-misses-nel",
    "colon-not-skipped", "colon-only-first",
    "comment-no-escape", "comment-no-nesting", "comment-open-is-invalid",
)


# ---------------------------------------------------------------- the evaluator harness

class Machine(cpu.Machine):
    """The shared evaluator leaves OF alone on imul; the bodies branch on it (jo after each multiply), so it is added here."""

    def step(self, row):
        if row.op in ("imul2", "imul3"):
            width = row.width
            sign = cpu.SIGN[width]

            def signed(value):
                return value - (1 << (8 * width)) if value & sign else value
            left = signed(self.get(row.a if row.op == "imul2" else row.b, width))
            right = signed(self.get(row.b, width)) if row.op == "imul2" else row.target
            product = left * right
            result = product & cpu.MASK[width]
            self.put(row.a, width, result)
            self.cf = self.of = product != signed(result)
            return row.next
        return super().step(row)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        for slot, name in PANIC_SLOTS.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = self.panic_hook(name)
        relative = image.relative()
        statics[SLOT_LONG_CALL] = relative[SLOT_LONG_CALL]
        statics[SLOT_WS_TABLE] = relative[SLOT_WS_TABLE]
        for index in range(12):
            slot = LONG_TABLE + 16 * index
            if slot in relative:
                statics[slot] = relative[slot]
        machine.real = frozenset((MONTH, TRIM))
        machine.step_limit = 20000

    @staticmethod
    def panic_hook(name):
        def hook(machine):
            regs = machine.regs
            if name == "slice":
                raise Panicked((name, regs[cpu.RDX], regs[cpu.RCX]))
            if name == "index":
                raise Panicked((name, regs[cpu.RDI], regs[cpu.RSI]))
            if name == "assert":
                raise Panicked((name, regs[cpu.RSI], 0))
            raise Panicked((name, 0, 0))
        return hook

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(cpu.HEAP_BASE, bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000)))
        memory.put_bytes(OUT, FILL)
        memory.put_bytes(STR, case.data)
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        size = len(case.data)
        args = {
            NUMBER: {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size, cpu.RCX: case.a, cpu.R8: case.b},
            NANO: {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size, cpu.RCX: case.a},
            MONTH: {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size},
            WEEKDAY: {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size},
            LONG_MONTH: {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size},
            COMMENT: {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size},
            TRIM: {cpu.RDI: STR, cpu.RSI: size},
            COLON: {cpu.RDI: STR, cpu.RSI: size},
        }[case.kind]
        try:
            value = machine.run(case.kind, args)
        except Panicked as stop:
            name, begin, end = stop.args[0]
            return ("panic", name, begin, end)
        after = bytes(memory.heap[:USED])
        start, end = OUT - cpu.HEAP_BASE, OUT - cpu.HEAP_BASE + OUT_SIZE
        if after[:start] + after[end:] != before[:start] + before[end:]:
            raise Halt("state changed outside the result")
        if case.kind in (TRIM, COLON):
            if after[start:end] != before[start:end]:
                raise Halt("a trim body wrote into the result area")
            return ("regs", value, machine.regs[cpu.RDX])
        return ("out", after[start:end])


# ---------------------------------------------------------------- generated inputs

def lcg(seed):
    state = seed & 0xFFFFFFFFFFFFFFFF
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        yield state >> 33


def pick(stream, options):
    return options[next(stream) % len(options)]


def digits_case(stream, kind):
    """Digit-heavy inputs: run of digits of length 0..24, optional terminator, optional multi-byte tail or a raw continuation byte."""
    count = next(stream) % 25
    body = bytes(0x30 + next(stream) % 10 if next(stream) % 4 else 0x39 for _ in range(count))
    tail = pick(stream, (b"", b"", b"a", b" ", b":", "é".encode(), " ".encode(), b"\x80", b"\xa5\x41", "€".encode(), b"-", b".", b"/", b"\xbf", b"\xc0", b"\x7f", b"@"))
    head = pick(stream, (b"", b"", b"", b"+", b" ", b"\xbf"))
    data = head + body + tail
    if kind == NUMBER:
        low = next(stream) % 8
        high = low + pick(stream, (0, 0, 1, 1, 2, 3, 5, 9, 12, 14, 20, 40))
        if next(stream) % 29 == 0:
            high = pick(stream, (0, 0, 1, 2, 3))
            low = high if next(stream) % 3 else high + 1
        return Case(NUMBER, data, low, high)
    return Case(NANO, data, pick(stream, (0, 1, 2, 3, 6, 9, 9, 9, 10, 12, 18, 19, 20, 22, next(stream) % 24)))


def mangle(stream, word):
    """Case flips, a perturbed letter, truncation and a tail around one name."""
    data = bytearray(word.encode())
    mode = next(stream) % 6
    for index in range(len(data)):
        if next(stream) % 3 == 0:
            data[index] ^= 0x20
    if mode == 0 and data:
        data[next(stream) % len(data)] = pick(stream, (0x41, 0x7A, 0x20, 0x00, 0x80, 0xC3, 0x60, 0x40, 0x5B, 0x7B))
    if mode == 1:
        del data[next(stream) % (len(data) + 1):]
    tail = pick(stream, (b"", b"", b"", b"x", b" ", b"uary", "é".encode(), b"\x80", b"\xbf\xbf", b"\xe2\x82\xac", b"ember", b"."))
    return bytes(data) + tail


def month_case(stream, kind):
    if kind == WEEKDAY:
        return Case(WEEKDAY, mangle(stream, pick(stream, WEEKDAYS + ("monday", "sunday", "thursday", "wednesday"))))
    if kind == MONTH:
        return Case(MONTH, mangle(stream, pick(stream, MONTHS + LONG_MONTHS)))
    word = pick(stream, LONG_MONTHS + MONTHS + ("janu", "septem", "decembe", "augus", "marc", "aprilx"))
    return Case(LONG_MONTH, mangle(stream, word))


def trim_cases(kind):
    """Every code point below U+3100 behind a marker, then a stride over the planes: the whole table, not a sample."""
    stream = lcg(0xC0FFEE ^ kind)
    sweep = [c for c in range(0, 0x3100) if not 0xD800 <= c < 0xE000]
    sweep += [c for c in range(0x3100, 0x110000, 0x533) if not 0xD800 <= c < 0xE000] + [0x10FFFF, 0xFEFF, 0x180E, 0x200B, 0xE0020]
    for code in sweep:
        char = chr(code).encode("utf-8")
        yield Case(kind, char + b"x")
        if code % 5 == 0:
            yield Case(kind, char + char + b" " + char)
    for plane in range(1, 17):
        for white in sorted(WHITESPACE):
            code = plane << 16 | white
            if code < 0x110000:
                yield Case(kind, chr(code).encode("utf-8") + b"x")
    pool = [b" ", b"\t", b"\n", b"\r\n", " ".encode(), "　".encode(), " ".encode(), "\u0085".encode(), b":", b"::", b"a", b"(", "é".encode(), "​".encode(), b"\x0b", b"\x0c"]
    for _ in range(2400):
        count = next(stream) % 8
        yield Case(kind, b"".join(pick(stream, pool) for _ in range(count)))


def comment_cases(count):
    stream = lcg(0x2822)
    pool = (b"(", b"(", b")", b")", b"\\", b"a", b" ", b"\t", "é".encode(), b"\\(", b"\\)", b"\\\\", " ".encode(), " ".encode(), b"((", b"))", b":", b")\x80", b")\xbf", b")\xc0", "\U00010000".encode())
    for _ in range(count):
        head = pick(stream, (b"", b"", b" ", b"\t \n", " ".encode(), "　(".encode(), b"(", b"(", b"(", b"x(", b":("))
        parts = [pick(stream, pool) for _ in range(next(stream) % 14)]
        yield Case(COMMENT, head + b"".join(parts))


CRITICAL = frozenset((0x00, 0x20, 0x2F, 0x30, 0x39, 0x3A, 0x40, 0x41, 0x5A, 0x5B, 0x60, 0x61, 0x7A, 0x7B, 0x7F, 0x80, 0xBF, 0xC0, 0xFF))


def name_family(kind, words, offset):
    """Every byte value at every position of every name (`offset` skips the 3 letter prefix of the long month suffix)."""
    for word in words:
        text = word.encode()
        for position in range(offset, len(text)):
            for value in range(256):
                data = bytearray(text)
                data[position] = value
                critical = value in CRITICAL or value in (text[position], text[position] ^ 0x20)
                yield Case(kind, bytes(data) + (b"" if position % 2 else b"x"), crit=critical)


def family_cases():
    yield from name_family(MONTH, MONTHS, 0)
    yield from name_family(WEEKDAY, WEEKDAYS, 0)
    yield from name_family(LONG_MONTH, tuple(word[:3] + word[3:] for word in LONG_MONTHS), 3)


def all_cases(scale=1):
    stream = lcg(0x115)
    for _ in range(6000 * scale):
        yield digits_case(stream, NUMBER)
    for _ in range(4000 * scale):
        yield digits_case(stream, NANO)
    for _ in range(4000 * scale):
        yield month_case(stream, MONTH)
    for _ in range(3000 * scale):
        yield month_case(stream, WEEKDAY)
    for _ in range(4000 * scale):
        yield month_case(stream, LONG_MONTH)
    yield from family_cases()
    yield from comment_cases(6000 * scale)
    yield from trim_cases(TRIM)
    yield from trim_cases(COLON)


def named_cases():
    """Hand-written edge inputs that the generated streams are not guaranteed to hit in every build."""
    rows = [
        (NUMBER, b"", 0, 0), (NUMBER, b"", 1, 2), (NUMBER, b"12", 3, 4), (NUMBER, b"12x", 2, 2), (NUMBER, b"123", 2, 2), (NUMBER, b"123", 0, 0),
        (NUMBER, b"9223372036854775807", 1, 19), (NUMBER, b"9223372036854775808", 1, 19), (NUMBER, b"99999999999999999999", 1, 20),
        (NUMBER, b"7\x80", 1, 3), (NUMBER, b"12\x80", 0, 2), (NUMBER, b"12\xbf", 0, 2), (NUMBER, b"12\xc0", 0, 2), (NUMBER, b"1/", 1, 3), (NUMBER, b"1:", 1, 3),
        (NUMBER, b"12\x80", 0, 5), (NUMBER, b"\xbf1", 0, 3), (NUMBER, b"\xc01", 0, 3), (NUMBER, b"123\xbf", 1, 2), (NANO, b"12\xbf", 2), (NANO, b"12\xc0", 2), (NANO, b"1/", 2),
        (COMMENT, b"(a)\xc0"), (COMMENT, b"(a)\xbf"), (COMMENT, b"(a)\x80"), (COMMENT, b"(a)\xc3\xa9"), (NUMBER, "12é".encode(), 1, 3), (NUMBER, b"12", 5, 4), (NUMBER, b"00007", 1, 3),
        (NANO, b"123456789", 9), (NANO, b"12", 3), (NANO, b"1x", 2), (NANO, b"", 0), (NANO, b"5", 0), (NANO, b"1234567890", 10),
        (NANO, b"9999999999999999999", 19), (NANO, b"12\x80", 2), (NANO, "12é".encode(), 2), (NANO, b"123x", 3), (NANO, b"001", 3),
        (MONTH, b"Jan"), (MONTH, b"JAN"), (MONTH, b"ja"), (MONTH, b"Mayx"), (MONTH, b"Mar\x80"), (MONTH, b"Dec\xc3\xa9"), (MONTH, b"xyz"),
        (WEEKDAY, b"Sun"), (WEEKDAY, b"sunday"), (WEEKDAY, b"su"), (WEEKDAY, b"Thx"), (WEEKDAY, b"Fri\xbf"), (WEEKDAY, b"Wed"),
        (LONG_MONTH, b"September"), (LONG_MONTH, b"Sept"), (LONG_MONTH, b"may"), (LONG_MONTH, b"MAYBE"), (LONG_MONTH, b"Decemberx"), (LONG_MONTH, b"Mar\xbf"),
        (LONG_MONTH, b"Marc\xc3\xa9"), (LONG_MONTH, "Marché".encode()), (LONG_MONTH, b"Aug"), (LONG_MONTH, b"august"), (LONG_MONTH, b"nOVeMbEr"),
        (COMMENT, b"(a)b"), (COMMENT, b"(a(b)c)d"), (COMMENT, b"(a\\)b)c"), (COMMENT, b"  (x"), (COMMENT, b"   "), (COMMENT, b"x"), (COMMENT, b"()"),
        (TRIM, b"  a"), (TRIM, b""), (TRIM, b"   "), (TRIM, "　 a".encode()), (COLON, b":: a"), (COLON, b""), (COLON, b":"),
    ]
    out = []
    for row in rows:
        out.append(Case(row[0], row[1], *(row[2:] if len(row) > 2 else ())))
    return out


# ---------------------------------------------------------------- checking

def digest(outcome):
    blob = repr(outcome).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


def is_error(kind, blob):
    """The error marker: a zero pointer, or for short_weekday the niche value 7 in its result byte."""
    return blob[0x10] == 7 if kind == WEEKDAY else blob[0:8] == bytes(8)


def classify(outcome, kind=None):
    if outcome[0] == "panic":
        return "panic-" + outcome[1]
    if outcome[0] == "regs":
        return "trim-%d" % min(outcome[1] - STR, 6)
    blob = outcome[1]
    if kind == WEEKDAY and blob[0x10] == 7:
        return "err-%d" % blob[0]
    if kind != WEEKDAY and blob[0:8] == bytes(8):
        return "err-%d" % blob[8]
    return "ok"


def check_stream(harness, cases, spec, tally, samples, sample_every, chosen=None):
    """Run each case, compare at once, keep only counts, every `sample_every`-th row and a class-picked subset for the edit controls."""
    count = 0
    taken = {}
    for case in cases:
        got = harness.run(case)
        want = spec.run(case)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.label(), got, want))
        key = (case.kind, classify(got, case.kind))
        tally[key] = tally.get(key, 0) + 1
        if samples is not None and count % sample_every == 0:
            samples.append((case.label(), classify(got, case.kind), digest(got)))
        if chosen is not None:
            key = (case.kind, classify(got, case.kind), min(len(case.data), 4))
            taken[key] = taken.get(key, 0) + 1
            leading = case.kind in (TRIM, COLON) and Spec.trim_count(case.data, (0x3A,) if case.kind == COLON else ()) > 0
            if taken[key] <= 3 or case.crit or leading or (case.kind in (TRIM, COLON) and count % 17 == 0):
                chosen[case.kind].append(case)
        count += 1
    return count


def first_failure(harness, cases, spec):
    for case in cases:
        try:
            if harness.run(case) != spec.run(case):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error, UnicodeError):
            return case
    return None


def edit_rows(image):
    rows = {}
    for target in TARGETS:
        start, end = image.exact_fde(target)
        rows[target] = cpu.decode_range(image, start, end)
    return rows


# ---------------------------------------------------------------- evidence tables

def constant_rows(image):
    """Tables the bodies read, taken from file bytes; the rule list holds its own copy of each."""
    rows = []
    offset = image.offset(POW_TABLE)
    for index in range(10):
        value = struct.unpack_from("<Q", image.blob, offset + 8 * index)[0]
        expected = 10 ** (9 - index) if index else 0
        rows.append(("pow-table", "%#x" % (POW_TABLE + 8 * index), str(index), str(value), "match" if value == expected else "DIFFERENT"))
    relative = image.relative()
    table = image.offset(LONG_TABLE)
    for index in range(12):
        slot = LONG_TABLE + 16 * index
        pointer, size = struct.unpack_from("<QQ", image.blob, table + 16 * index)
        target = relative.get(slot, pointer)
        suffix = bytes(image.blob[image.offset(target):image.offset(target) + size]) if size else b""
        expected = LONG_MONTHS[index][3:]
        rows.append(("long-month-suffix", "%#x" % slot, str(index), "%s/%d" % (suffix.decode(), size), "match" if suffix.decode() == expected else "DIFFERENT"))
    base = relative[SLOT_WS_TABLE]
    start = image.offset(base)
    for code in (0x09, 0x0D, 0x20, 0x85, 0xA0, 0xFF, 0x00, 0x01, 0x28, 0x3A):
        flag = image.blob[start + code]
        rows.append(("white-space-map", "%#x" % (base + code), "%#x" % code, str(flag), "bit1 (U+20xx block)" if flag & 2 else "bit0 (Latin-1 block)" if flag & 1 else "clear"))
    rows.append(("slot", "%#x" % SLOT_LONG_CALL, "short_month0 call slot", "%#x" % relative[SLOT_LONG_CALL], "match" if relative[SLOT_LONG_CALL] == MONTH else "DIFFERENT"))
    for slot, name in sorted(PANIC_SLOTS.items()):
        rows.append(("panic-slot", "%#x" % slot, name, "%#x" % relative[slot], "relative"))
    return rows


def white_space_runs(image):
    """The non-zero entries of the 256 byte map: bit 1 is read for the U+20xx block, bit 0 for the Latin-1 block."""
    base = image.relative()[SLOT_WS_TABLE]
    start = image.offset(base)
    return [(code, image.blob[start + code]) for code in range(0x100) if image.blob[start + code]]


def render_functions(image, rows):
    lines = ["function\tstart\tend\tsize\tinstructions\tconditionals\tcalls"]
    for target in TARGETS:
        start, end = image.exact_fde(target)
        body = rows[target]
        lines.append("\t".join((NAMES[target], "%#x" % start, "%#x" % end, str(end - start), str(len(body)),
                                 str(sum(1 for row in body if row.op == "jcc")), str(sum(1 for row in body if row.op in ("call", "calli", "jmpi"))))))
    return lines


def render_reach(image, rows, seen):
    lines = ["function\tinsns\treached\tunreached\tfirst_unreached"]
    for target in TARGETS:
        body = rows[target]
        missing = [row.va for row in body if row.va not in seen]
        lines.append("\t".join((NAMES[target], str(len(body)), str(len(body) - len(missing)), str(len(missing)),
                                 ",".join("%#x" % va for va in missing[:12]) or "-")))
    return lines


# ---------------------------------------------------------------- mutants

def run_byte_mutants(image, rows, seen, chosen):
    results = []
    spec = Spec()
    for target in TARGETS:
        subset = chosen[target]
        for va, kind, patch in cpu.edits_for(image, rows[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = 4000
            if first_failure(harness, subset, spec) is not None:
                results.append((NAMES[target], va, kind, "killed", "class-picked subset"))
            else:
                results.append((NAMES[target], va, kind, "survived", "equivalent edit"))
    return results


def spec_mutant_rows(image, cases):
    rows = []
    harness = Harness(image)
    for name in SPEC_MUTANTS:
        wrong = Wrong(frozenset((name,)))
        found = None
        for case in cases:
            if harness.run(case) != wrong.run(case):
                found = case
                break
        rows.append((name, "detected" if found is not None else "MISSED", found.label() if found is not None else "-"))
    return rows


def structural_rows(image):
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    rows.append(("one flipped file byte changes the SHA-256", "detected" if hashlib.sha256(bytes(blob)).hexdigest() != SHA256 else "MISSED"))
    for label, va in (("address inside a function", MONTH + 1), ("address before a body", NUMBER - 1), ("address in .rodata", 0x459230), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    relative = image.relative()
    for label, slot, target in (("long-month call slot against the weekday body", SLOT_LONG_CALL, WEEKDAY), ("white space slot against a code address", SLOT_WS_TABLE, TRIM)):
        rows.append((label + " is not a slot to that target", "detected" if relative.get(slot) != target else "MISSED"))
    # a rule list used for the wrong body
    harness = Harness(image)
    probe = Case(MONTH, b"Mar")
    got = harness.run(probe)
    rows.append(("month result compared with the weekday rule", "detected" if got != Spec().weekday(probe) else "MISSED"))
    # a body run against the rule of a neighbour
    nano = Case(NANO, b"123", 3)
    rows.append(("nanosecond_fixed result compared with the number rule", "detected" if harness.run(nano) != Spec().number(Case(NUMBER, b"123", 3, 3)) else "MISSED"))
    # a string longer than the evaluator heap cannot be placed
    try:
        Harness(image).run(Case(NUMBER, b"1" * 140000, 0, 5000))
        rows.append(("a string that does not fit the evaluator memory is refused", "MISSED"))
    except Halt:
        rows.append(("a string that does not fit the evaluator memory is refused", "detected"))
    return rows


# ---------------------------------------------------------------- driver

def analyse(image, mutate=True):
    harness = Harness(image)
    spec = Spec()
    tally, samples = {}, []
    chosen = {kind: [] for kind in TARGETS}
    total = check_stream(harness, named_cases(), spec, tally, samples, 1, chosen)
    for case in named_cases():
        chosen[case.kind].append(case)
    named_total = total
    total += check_stream(harness, all_cases(), spec, tally, samples, 450, chosen)
    seen = set(harness.machine.seen)
    rows = edit_rows(image)
    result = {"total": total, "named": named_total, "tally": tally, "samples": samples, "seen": seen, "rows": rows,
              "constants": constant_rows(image), "ws": white_space_runs(image)}
    if mutate:
        result["byte"] = run_byte_mutants(image, rows, seen, chosen)
        result["spec"] = spec_mutant_rows(image, [case for kind in TARGETS for case in chosen[kind]])
        result["struct"] = structural_rows(image)
    return result


def tsv(header, rows):
    return ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]


def write_lines(path, lines):
    path.write_text("\n".join(lines) + "\n")


def render(result, image):
    files = {}
    files["functions.tsv"] = render_functions(image, result["rows"])
    files["reach.tsv"] = render_reach(image, result["rows"], result["seen"])
    files["constants.tsv"] = tsv(("table", "address", "index", "value", "check"), result["constants"])
    files["white-space.tsv"] = tsv(("low_byte", "map_value", "used_for"), [("%#x" % code, value, "U+20xx block" if value & 2 else "Latin-1 block") for code, value in result["ws"]])
    outcomes = sorted(result["tally"].items())
    files["outcomes.tsv"] = tsv(("function", "outcome", "cases"), [(NAMES[kind], name, count) for (kind, name), count in outcomes])
    files["sample-cases.tsv"] = tsv(("case", "outcome", "result-digest"), result["samples"])
    byte = result.get("byte", [])
    files["byte-mutants.tsv"] = tsv(("function", "address", "edit", "verdict", "caught_by"), [(n, "%#x" % va, k, v, w) for n, va, k, v, w in byte])
    files["rule-mutants.tsv"] = tsv(("wrong rule", "verdict", "first contradicting case"), result.get("spec", []))
    files["structural.tsv"] = tsv(("control", "verdict"), result.get("struct", []))
    killed = sum(1 for row in byte if row[3] == "killed")
    survived = [row for row in byte if row[3] == "survived"]
    spec_rows = result.get("spec", [])
    struct_rows = result.get("struct", [])
    negatives = len(byte) + len(spec_rows) + len(struct_rows)
    detected = killed + sum(1 for row in spec_rows if row[1] == "detected") + sum(1 for row in struct_rows if row[1] == "detected")
    # edits that change no observable result are reported, not counted as controls
    equivalent = len(survived)
    summary = {
        "cases": result["total"],
        "negative_controls": negatives - equivalent,
        "negative_detected": detected,
        "byte_edits": len(byte),
        "byte_edits_killed": killed,
        "byte_edits_equivalent": equivalent,
        "rule_mutants": len(spec_rows),
        "structural_controls": len(struct_rows),
        "named_cases": result["named"],
        "binary_sha256": SHA256,
    }
    files["measure.json"] = json.dumps(summary, indent=1, sort_keys=True).split("\n")
    return files, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = cpu.load_image(BINARY, SHA256)
    result = analyse(image)
    files, summary = render(result, image)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, lines in sorted(files.items()):
        write_lines(out / name, lines)
    if summary["negative_detected"] != summary["negative_controls"]:
        print("a negative control was missed: %r" % summary, file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
