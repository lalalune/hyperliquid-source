#!/usr/bin/env python3
"""Reconstruct the node #115 chrono `scan::timezone_offset` body, its RFC 2822 sibling and the date-time tail parser that calls it.

The real bytes of timezone_offset 0x1625210 (820 bytes), the zone-name and hhmm scanner 0x1625790 (1,358 bytes, a jump table over the
first letter), the date-time wrapper 0x1621730 (458 bytes) and the two scanners they call,
trim_start 0x16288c0 and the colon-or-space trim 0x1628a40, run in the small x86-64 evaluator of tools/bole_rate115.py. The large
parse_internal body 0x1620be0 that the wrapper calls twice is a recording stub: its arguments (parsed state, string window, item list
bounds) are compared with the rule list and its result is chosen by each case. A rule list written from the documented chrono
behaviour (a different code path from the bytes) predicts the exact 32 result bytes, the parsed-state update, the stub call log or the
panic of every generated input; every reached conditional, immediate and displacement of the two bodies is edited to prove the cases
notice. Call sites, item tables and flag constants are read from file bytes. No objdump or readelf output is parsed and the binary is
never executed. Standard library only.

    python3 tools/chrono_tz_offset_115.py --out <dir>
"""

import argparse
import hashlib
import json
import pathlib
import re
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

TZ, WRAP, PARSE, TRIM, COLON, ZONE = 0x1625210, 0x1621730, 0x1620BE0, 0x16288C0, 0x1628A40, 0x1625790
TARGETS = (TZ, WRAP, ZONE)
NAMES = {TZ: "timezone_offset", WRAP: "datetime_tail", ZONE: "timezone_offset_2822"}
ALL_BODIES = (TZ, WRAP, ZONE, TRIM, COLON)
ZONE_NAMES = {"cst": -6, "cdt": -5, "est": -5, "edt": -4, "mst": -7, "mdt": -6, "pst": -8, "pdt": -7, "gmt": 0}

PANIC_SLOTS = {0x64DF670: "slice", 0x64DF730: "assert", 0x64DF620: "index", 0x64DF520: "overflow", 0x64DF6A0: "other"}
SLOT_WS_TABLE = 0x64DFC30
DATE_ITEMS = (0x6404588, 0x6404630)
TIME_ITEMS = (0x6404648, 0x6404720)
MARK_BASE = 0x7700000000
OUT = cpu.HEAP_BASE + 0x200
OUT_SIZE = 0x20
PARSED = cpu.HEAP_BASE + 0x300
PARSED_FLAG, PARSED_VALUE = 0x98, 0x9C
STR = cpu.HEAP_BASE + 0x1000
USED = 0x2000
FILL = bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE))
OUT_OF_RANGE, IMPOSSIBLE, INVALID, TOO_SHORT = 0, 1, 3, 4

WHITESPACE = frozenset(list(range(9, 14)) + [0x20, 0x85, 0xA0, 0x1680] + list(range(0x2000, 0x200B)) + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000])
MINUS_SIGN = 0x2212


class Case:
    """One input. TZ uses data and the three flags; WRAP uses data, the stub results and the parsed-state words."""

    __slots__ = ("kind", "data", "zulu", "missing", "minus", "date", "time", "pset", "pval", "crit")

    def __init__(self, kind, data, zulu=0, missing=0, minus=0, date=("ok", 0), time=("ok", 0), pset=0, pval=0, crit=False):
        self.kind, self.data = kind, bytes(data)
        self.zulu, self.missing, self.minus = zulu, missing, minus
        self.date, self.time, self.pset, self.pval, self.crit = date, time, pset, pval, crit

    def label(self):
        if self.kind == TZ:
            return "tz|%s|%d%d%d" % (self.data.hex(), self.zulu, self.missing, self.minus)
        return "tail|%s|%s%d|%s%d|%d:%d" % (self.data.hex(), self.date[0], self.date[1], self.time[0], self.time[1], self.pset, self.pval)


# ---------------------------------------------------------------- the written rule list

class Spec:
    """Chrono scan rules. `mutants` names deliberate mistakes; the empty set is the claim under test."""

    def __init__(self, mutants=frozenset()):
        self.m = mutants
        self.pos = None

    def stop(self, index, start, end):
        """A char-boundary panic: remember which input byte was the stray continuation byte."""
        self.pos = index
        return ("panic", "slice", start, end)

    @staticmethod
    def is_cont(byte):
        return 0x80 <= byte <= 0xBF

    @staticmethod
    def pack(*fields):
        out = bytearray(FILL)
        for offset, size, value in fields:
            out[offset:offset + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        return bytes(out)

    def err(self, tag):
        return self.pack((0, 8, 0), (8, 1, tag))

    def ok(self, rest_at, length, value=None):
        fields = [(0, 8, STR + rest_at), (8, 8, length)]
        if value is not None:
            fields.append((0x10, 4, value))
        return self.pack(*fields)

    @staticmethod
    def trim_count(text, extra=()):
        cut = 0
        for char in text.decode("utf-8", "surrogateescape"):
            if ord(char) in WHITESPACE or ord(char) in extra:
                cut += len(char.encode("utf-8"))
            else:
                break
        return cut

    @staticmethod
    def lead(data):
        """First scalar value and its width; the inputs begin with a whole character."""
        char = data[:4].decode("utf-8", "ignore")[:1]
        if not char:
            return -1, 1
        return ord(char), len(char.encode("utf-8"))

    def tz(self, case):
        """timezone_offset(s, colon_or_space, allow_zulu, allow_missing_minutes, allow_minus_sign) as (out bytes) or a panic."""
        data, size = case.data, len(case.data)
        m = self.m
        zulu_ok = case.zulu and "tz-zulu-ignored" not in m
        if size and zulu_ok and (data[0] | 0x20) == 0x7A:
            if size >= 2 and self.is_cont(data[1]):
                return self.stop(1, 1, size)
            return self.ok(1, size - 1, 0)
        if size == 0:
            return self.err(TOO_SHORT)
        code, width = self.lead(data)
        if code == 0x2B:
            negative = False
        elif code == 0x2D:
            negative = True
        elif code == MINUS_SIGN and (case.minus or "tz-minus-flag-ignored" in m):
            negative = True
        else:
            return self.err(INVALID)
        if size == width:
            return self.err(TOO_SHORT)
        if self.is_cont(data[width]):
            return self.stop(width, width, size)
        avail = size - width
        if avail < 2:
            return self.err(TOO_SHORT)
        high, low = data[width], data[width + 1]
        if not (0x30 <= high <= 0x39 and 0x30 <= low <= 0x39):
            return self.err(INVALID)
        if avail != 2 and self.is_cont(data[width + 2]):
            return self.stop(width + 2, 2, avail)
        hours = (high - 0x30) * 10 + (low - 0x30)
        rest = data[width + 2:]
        cut = self.trim_count(rest, (0x3A,) if "tz-colon-not-skipped" not in m else ())
        base = width + 2 + cut
        rest = rest[cut:]
        left = len(rest)
        seconds = 0
        if left >= 2:
            first, second = rest[0], rest[1]
            if 0x30 <= first <= 0x35:
                if not 0x30 <= second <= 0x39:
                    return self.err(INVALID)
                if left != 2 and self.is_cont(rest[2]):
                    return self.stop(base + 2, 2, left)
                seconds = ((first - 0x30) * 10 + second - 0x30) * 60
                base += 2
                left -= 2
            elif 0x36 <= first <= 0x39 and 0x30 <= second <= 0x39 and "tz-sixty-accepted" not in m:
                return self.err(OUT_OF_RANGE)
            elif 0x36 <= first <= 0x39 and 0x30 <= second <= 0x39:
                seconds = ((first - 0x30) * 10 + second - 0x30) * 60
                base += 2
                left -= 2
            else:
                return self.err(INVALID)
        elif not (case.missing or "tz-missing-flag-ignored" in m):
            return self.err(TOO_SHORT)
        elif left == 1 and "tz-one-digit-minutes-ok" not in m:
            return self.err(TOO_SHORT)
        elif left == 1:
            seconds = 0
        total = hours * 3600 + seconds
        if "tz-sign-lost" in m:
            negative = False
        return self.ok(base, left, -total if negative else total)

    @staticmethod
    def window(data, begin):
        return len(data) - begin

    def stub(self, res, length):
        """Result of the stubbed parse_internal for a window of `length` bytes."""
        return res if res[0] == "err" else ("ok", min(res[1], length))

    def tail(self, case):
        """The date-time tail: date items, separator, time items, optional UTC or numeric offset, then the offset merge."""
        m = self.m
        data, size = case.data, len(case.data)
        log = [("date", PARSED, 0, size, DATE_ITEMS)]
        first = self.stub(case.date, size)
        if first[0] == "err":
            return self.finish(self.err(first[1]), case, log)
        begin = first[1]
        left = size - begin
        if left == 0:
            return self.finish(self.err(TOO_SHORT), case, log)
        lead = data[begin]
        separators = (0x20, 0x54, 0x74) if "tail-lower-t-rejected" not in m else (0x20, 0x54)
        if "tail-only-t" in m:
            separators = (0x54,)
        if lead not in separators:
            return self.finish(self.err(INVALID), case, log)
        if left >= 2 and self.is_cont(data[begin + 1]):
            return self.stop(begin + 1, 1, left)
        begin += 1
        log.append(("time", PARSED, begin, size - begin, TIME_ITEMS))
        second = self.stub(case.time, size - begin)
        if second[0] == "err":
            return self.finish(self.err(second[1]), case, log)
        begin += second[1]
        rest = data[begin:]
        cut = self.trim_count(rest)
        if "tail-no-trim" in m:
            cut = 0
        begin += cut
        rest = data[begin:]
        left = len(rest)
        if left > 2 and bytes((c + 32) if 65 <= c <= 90 else c for c in rest[:3]) == b"utc":
            if left != 3 and self.is_cont(rest[3]):
                return self.stop(begin + 3, 3, left)
            offset, begin, left = 0, begin + 3, left - 3
        else:
            sub = Case(TZ, rest, 1, 0, 1)
            if "tail-flags-changed" in m:
                sub = Case(TZ, rest, 0, 1, 1)
            got = self.tz(sub)
            if isinstance(got, tuple):
                self.pos += begin
                return got
            if got[0:8] == bytes(8):
                return self.finish(got, case, log)
            offset = struct.unpack_from("<i", got, 0x10)[0]
            begin += struct.unpack_from("<Q", got, 0)[0] - STR
            left = struct.unpack_from("<Q", got, 8)[0]
        out = self.pack((0, 8, STR + begin), (8, 8, left))
        if case.pset == 1 and "tail-merge-ignored" not in m:
            if case.pval != offset:
                return self.finish(self.err(IMPOSSIBLE), case, log)
            return self.finish(out, case, log)
        return self.finish(out, case, log, (1, offset))

    def finish(self, out, case, log, state=None):
        if state is None:
            state = (case.pset, case.pval)
        return ("out", out, struct.pack("<Ii", state[0] & 0xFFFFFFFF, state[1]), tuple(log))

    def zone(self, case):
        """timezone_offset_2822: an ASCII letter run is a zone word (UT, GMT, US names, one military letter), otherwise [+-]hhmm."""
        data, size = case.data, len(case.data)
        m = self.m
        if size == 0:
            return self.err(TOO_SHORT)
        run = 0
        while run < size and (data[run] & 0xDF) in range(0x41, 0x5B):
            run += 1
        if run:
            if run < size and self.is_cont(data[run]):
                return self.stop(run, run, size)
            word = data[:run].decode("ascii").lower()
            if run == 1:
                upper = word.upper()
                if word == "z" or "A" <= upper <= "I" or ("K" <= upper <= "Y" and "z-military-k-rejected" not in m):
                    return self.ok(1, size - 1, 0)
                return self.err(INVALID)
            if run == 2:
                return self.ok(2, size - 2, 0) if word == "ut" else self.err(INVALID)
            if run == 3 and word in ZONE_NAMES:
                hours = ZONE_NAMES[word]
                if "z-est-edt-swapped" in m and word in ("est", "edt"):
                    hours = -5 if word == "edt" else -4
                if "z-gmt-skipped" in m and word == "gmt":
                    return self.err(INVALID)
                return self.ok(3, size - 3, hours * 3600)
            return self.err(INVALID)
        code, _ = self.lead(data)
        if code == 0x2B:
            negative = False
        elif code == 0x2D or (code == MINUS_SIGN and "z-unicode-minus-ok" in m):
            negative = True
        else:
            return self.err(INVALID)
        if size == 1:
            return self.err(TOO_SHORT)
        if self.is_cont(data[1]):
            return self.stop(1, 1, size)
        if size < 3:
            return self.err(TOO_SHORT)
        if not (0x30 <= data[1] <= 0x39 and 0x30 <= data[2] <= 0x39):
            return self.err(INVALID)
        if size - 1 < 3:
            return self.err(TOO_SHORT)
        if self.is_cont(data[3]):
            return self.stop(3, 2, size - 1)
        if size - 3 < 2:
            return self.err(TOO_SHORT)
        first, second = data[3], data[4]
        if 0x30 <= first <= 0x35:
            if not 0x30 <= second <= 0x39:
                return self.err(INVALID)
            if size - 3 != 2 and self.is_cont(data[5]):
                return self.stop(5, 2, size - 3)
            total = ((data[1] - 0x30) * 10 + data[2] - 0x30) * 3600 + ((first - 0x30) * 10 + second - 0x30) * 60
            if "z-sign-lost" in m:
                negative = False
            return self.ok(5, size - 5, -total if negative else total)
        if 0x36 <= first <= 0x39 and 0x30 <= second <= 0x39:
            return self.err(OUT_OF_RANGE)
        return self.err(INVALID)

    def run(self, case):
        if case.kind in (TZ, ZONE):
            got = self.tz(case) if case.kind == TZ else self.zone(case)
            return got if isinstance(got, tuple) else ("out", got)
        return self.tail(case)


# ---------------------------------------------------------------- deliberately wrong rule lists

SPEC_MUTANTS = (
    "tz-zulu-ignored", "tz-minus-flag-ignored", "tz-colon-not-skipped", "tz-sixty-accepted", "tz-missing-flag-ignored",
    "tz-one-digit-minutes-ok", "tz-sign-lost", "tail-lower-t-rejected", "tail-only-t", "tail-no-trim", "tail-flags-changed",
    "tail-merge-ignored",
)


class Wrong(Spec):
    """One mistake each (more than the table above: the shape-level mistakes live here); the case set must contradict every one."""

    def tz(self, case):
        m = self.m
        got = Spec.tz(self, case)
        if isinstance(got, tuple):
            return got
        if "tz-hours-times-3000" in m and got[0:8] != bytes(8) and got[0x10] | got[0x11] | got[0x12] | got[0x13]:
            value = struct.unpack_from("<i", got, 0x10)[0]
            return self.pack((0, 8, struct.unpack_from("<Q", got, 0)[0]), (8, 8, struct.unpack_from("<Q", got, 8)[0]), (0x10, 4, value * 5 // 6))
        if "tz-invalid-as-short" in m and got[0:8] == bytes(8) and got[8] == INVALID:
            return self.err(TOO_SHORT)
        if "tz-range-as-invalid" in m and got[0:8] == bytes(8) and got[8] == OUT_OF_RANGE:
            return self.err(INVALID)
        if "tz-unicode-digits" in m and got[0:8] == bytes(8) and got[8] == INVALID and len(case.data) >= 3:
            text = case.data.decode("utf-8", "ignore")
            if len(text) >= 3 and text[0] in "+-" and text[1].isdigit() and text[2].isdigit():
                return self.err(TOO_SHORT)
        if "tz-zulu-uppercase-only" in m and case.zulu and case.data[:1] == b"z":
            return Spec.tz(self, Case(TZ, case.data, 0, case.missing, case.minus))
        if "tz-plus-sets-negative" in m and case.data[:1] == b"+" and got[0:8] != bytes(8) and got[0x10] | got[0x11] | got[0x12] | got[0x13]:
            value = struct.unpack_from("<i", got, 0x10)[0]
            return self.pack((0, 8, struct.unpack_from("<Q", got, 0)[0]), (8, 8, struct.unpack_from("<Q", got, 8)[0]), (0x10, 4, -value))
        return got

    def zone(self, case):
        m = self.m
        got = Spec.zone(self, case)
        if isinstance(got, tuple):
            return got
        value = struct.unpack_from("<i", got, 0x10)[0] if got[0:8] != bytes(8) else None
        if "z-offsets-in-minutes" in m and value:
            return self.pack((0, 8, struct.unpack_from("<Q", got, 0)[0]), (8, 8, struct.unpack_from("<Q", got, 8)[0]), (0x10, 4, value // 60))
        if "z-four-letters-ok" in m and got[0:8] == bytes(8) and got[8] == INVALID and case.data[:4].lower() in (b"gmtx", b"estx", b"utcx"):
            return self.ok(4, len(case.data) - 4, 0)
        if "z-numeric-needs-colon" in m and got[0:8] != bytes(8) and case.data[:1] in (b"+", b"-"):
            return self.err(INVALID)
        if "z-ut-is-invalid" in m and got[0:8] != bytes(8) and case.data[:2].lower() == b"ut" and not case.data[2:3].isalpha():
            return self.err(INVALID)
        return got

    def tail(self, case):
        m = self.m
        got = Spec.tail(self, case)
        if got[0] != "out":
            return got
        if "tail-impossible-as-invalid" in m and got[1][0:8] == bytes(8) and got[1][8] == IMPOSSIBLE:
            return self.finish(self.err(INVALID), case, list(got[3]))
        if "tail-state-always-set" in m and case.pset == 1:
            return self.finish(got[1], case, list(got[3]), (1, 0x55))
        if "tail-time-window-full" in m and len(got[3]) == 2:
            log = list(got[3])
            log[1] = ("time", PARSED, 0, len(case.data), TIME_ITEMS)
            return self.finish(got[1], case, log, struct.unpack("<Ii", got[2]))
        if "tail-date-items-swapped" in m:
            log = list(got[3])
            log[0] = ("date", PARSED, 0, len(case.data), TIME_ITEMS)
            return self.finish(got[1], case, log, struct.unpack("<Ii", got[2]))
        return got


ZONE_MUTANTS = ("z-military-k-rejected", "z-est-edt-swapped", "z-gmt-skipped", "z-unicode-minus-ok", "z-sign-lost", "z-offsets-in-minutes", "z-four-letters-ok",
                "z-numeric-needs-colon", "z-ut-is-invalid")

WRONG_MUTANTS = (
    "tz-hours-times-3000", "tz-invalid-as-short", "tz-range-as-invalid", "tz-unicode-digits", "tz-zulu-uppercase-only",
    "tz-plus-sets-negative", "tail-impossible-as-invalid", "tail-state-always-set", "tail-time-window-full", "tail-date-items-swapped",
)


# ---------------------------------------------------------------- the evaluator harness

class Machine(cpu.Machine):
    """The shared evaluator leaves OF alone on imul; the bodies branch on it, so it is added here."""

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
        statics[SLOT_WS_TABLE] = image.relative()[SLOT_WS_TABLE]
        machine.real = frozenset((TZ, TRIM, COLON))
        machine.calls[PARSE] = self.on_parse
        machine.step_limit = 20000
        self.script = None
        self.log = []

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

    def on_parse(self, machine):
        """The stubbed parse_internal(out, parsed, s_ptr, s_len, items_begin, items_end)."""
        regs = machine.regs
        out, parsed, ptr, length, begin, end = regs[cpu.RDI], regs[cpu.RSI], regs[cpu.RDX], regs[cpu.RCX], regs[cpu.R8], regs[cpu.R9]
        which = "date" if len(self.log) == 0 else "time"
        self.log.append((which, parsed, ptr - STR, length, (begin, end)))
        res = self.script[len(self.log) - 1]
        res = res if res[0] == "err" else ("ok", min(res[1], length))
        memory = machine.memory
        if res[0] == "err":
            memory.write(out, 8, 0)
            memory.write(out + 8, 1, res[1])
        else:
            memory.write(out, 8, ptr + res[1])
            memory.write(out + 8, 8, length - res[1])

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(cpu.HEAP_BASE, bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000)))
        memory.put_bytes(OUT, FILL)
        memory.put_bytes(STR, case.data)
        if case.kind == WRAP:
            memory.put_bytes(PARSED + PARSED_FLAG, struct.pack("<Ii", case.pset & 0xFFFFFFFF, case.pval))
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        size = len(case.data)
        self.log = []
        self.script = (case.date, case.time)
        if case.kind == ZONE:
            args = {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size}
        elif case.kind == TZ:
            args = {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size, cpu.RCX: case.zulu, cpu.R8: case.missing, cpu.R9: case.minus}
        else:
            args = {cpu.RDI: OUT, cpu.RSI: PARSED, cpu.RDX: STR, cpu.RCX: size}
        try:
            machine.run(case.kind, args)
        except Panicked as stop:
            name, begin, end = stop.args[0]
            return ("panic", name, begin, end)
        after = bytes(memory.heap[:USED])
        start, end = OUT - cpu.HEAP_BASE, OUT - cpu.HEAP_BASE + OUT_SIZE
        state_at = PARSED - cpu.HEAP_BASE + PARSED_FLAG
        skip = ((start, end), (state_at, state_at + 8)) if case.kind == WRAP else ((start, end),)
        mask_before, mask_after = bytearray(before), bytearray(after)
        for low, high in skip:
            mask_before[low:high] = bytes(high - low)
            mask_after[low:high] = bytes(high - low)
        if mask_before != mask_after:
            raise Halt("state changed outside the result")
        if case.kind in (TZ, ZONE):
            return ("out", after[start:end])
        return ("out", after[start:end], after[state_at:state_at + 8], tuple(self.log))


# ---------------------------------------------------------------- generated inputs

def lcg(seed):
    state = seed & 0xFFFFFFFFFFFFFFFF
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        yield state >> 33


def pick(stream, options):
    return options[next(stream) % len(options)]


LEADS = ("+", "+", "+", "-", "-", "-", "−", "−", "Z", "z", "", "x", "1", " ", "é", "€", "\U0001f600", "＋", "–", ":", "(")
HOURS = ("00", "05", "09", "10", "12", "14", "23", "24", "59", "99", "0a", "a0", "1", "", "ab", "٣٣", "7:", "05")
SEPS = ("", "", ":", ":", " ", "::", " : ", "\t", "　", " :", ": ", "x", "\n:", " ")
MINUTES = ("00", "30", "45", "59", "60", "61", "99", "6", "7a", "0", "a", "5x", "", "٣" + "0", "15", "05")
TAILS = ("", "", "", " ", "x", "é", ":00", "abc", " ", "00", ")", "€")


def stray(stream, flags_rate=11):
    """A lone continuation byte, planted only where the body reads a char-boundary byte first."""
    return b"\x80" if next(stream) % flags_rate == 0 else b""


def tz_random(stream):
    lead = pick(stream, LEADS).encode()
    hours = pick(stream, HOURS).encode()
    sep = pick(stream, SEPS).encode()
    minutes = pick(stream, MINUTES).encode()
    tail = pick(stream, TAILS).encode()
    mode = next(stream) % 9
    parts = [lead, hours, sep, minutes, tail]
    if mode == 0:
        parts = [lead, stray(stream, 1)]
    elif mode == 1:
        parts = [lead, hours[:2], stray(stream, 1)]
    elif mode == 2:
        parts = [lead, hours[:2], sep, minutes[:2], stray(stream, 1)] if len(hours) >= 2 else parts
    data = b"".join(parts)
    flags = next(stream) % 8
    return Case(TZ, data, flags & 1, flags >> 1 & 1, flags >> 2 & 1)


def tz_grid():
    """Every sign, every two-digit hour and minute value, in every flag combination of the three call shapes."""
    for lead in (b"+", b"-", "−".encode()):
        for hours in range(100):
            for minutes in range(0, 100, 1 if hours % 7 == 0 else 7):
                text = lead + b"%02d" % hours + b":" + b"%02d" % minutes
                yield Case(TZ, text, 1, 0, 1)
                if hours % 11 == 0:
                    for flags in range(8):
                        yield Case(TZ, text + b"x", flags & 1, flags >> 1 & 1, flags >> 2 & 1)
    for lead in ("+", "-", "−"):
        for hours in range(0, 100, 3):
            yield Case(TZ, (lead + "%02d" % hours).encode(), 1, 1, 1)
            yield Case(TZ, (lead + "%02d" % hours).encode(), 0, 0, 0)
            yield Case(TZ, (lead + "%02d" % hours + " ").encode(), 0, 1, 1)
            yield Case(TZ, (lead + "%02d" % hours + "0").encode(), 0, 1, 1)


def tz_leads():
    """The first character: every scalar below U+3100 and a stride over the planes."""
    sweep = [c for c in range(0, 0x3100) if not 0xD800 <= c < 0xE000]
    sweep += [c for c in range(0x3100, 0x110000, 0x2B7) if not 0xD800 <= c < 0xE000] + [0x10FFFF, 0xFF0B, 0xFE63, 0x207A, 0x208A, 0x2212]
    for code in sweep:
        char = chr(code).encode("utf-8")
        yield Case(TZ, char + b"05:30", 1, 0, 1)
        if code < 0x80 or code in (0x2212, 0xFF0B):
            yield Case(TZ, char + b"0530", 0, 1, 0)
            yield Case(TZ, char + b"9", 1, 1, 1)


def tz_positions():
    """Every byte value at every position of a full offset string, the whole byte-level boundary of the body."""
    for base, flags in ((b"+05:30", (1, 0, 1)), ("−09:45x".encode(), (0, 1, 1)), (b"-1200", (0, 0, 0)), (b"Zx", (1, 0, 0))):
        for position in range(len(base)):
            for value in range(256):
                data = bytearray(base)
                data[position] = value
                critical = value in (0, 0x2B, 0x2D, 0x30, 0x39, 0x3A, 0x35, 0x36, 0x7A, 0x5A, 0x80, 0xBF, 0xC0, 0x20)
                yield Case(TZ, bytes(data), *flags, crit=critical)


DATES = (b"2020-01-02", b"1999-12-31", b"0001-01-01", b"", b"x", b"2020")
TIMES = (b"03:04:05", b"23:59:59.123456789", b"00:00:00", b"", b"1:2")
SEPARATORS = ("T", "T", "t", " ", " ", "x", "", "é", "\t")
OFFSETS = ("", "Z", "z", "UTC", "utc", "Utc", "uTC", "+05:30", "-08:00", "+0530", "-0800", "+05", " UTC", "  +01:00", "−" + "03:30", "UTCx", "ut", "u", "UT", "+9999", "　utc", "é", "+0", "+05:6")


def tail_case(stream):
    date, time = pick(stream, DATES), pick(stream, TIMES)
    sep = pick(stream, SEPARATORS).encode()
    offset = pick(stream, OFFSETS).encode()
    stray_after_sep = stray(stream, 9)
    data = date + sep + stray_after_sep + time + (b" " if next(stream) % 4 == 0 else b"") + offset
    if next(stream) % 17 == 0:
        data += b"\x80"
    first = ("ok", len(date)) if next(stream) % 9 else pick(stream, (("err", 0), ("err", 3), ("err", 4), ("ok", 0), ("ok", len(data) + 5), ("ok", 1)))
    second = ("ok", len(time)) if next(stream) % 9 else pick(stream, (("err", 0), ("err", 1), ("err", 3), ("err", 4), ("ok", 0), ("ok", 99)))
    pset = pick(stream, (0, 0, 1, 1, 2, 0xFFFFFFFF))
    pval = pick(stream, (0, 19800, -28800, 0, 12345, -19800, 3600))
    if next(stream) % 3 == 0:
        pval = {"+05:30": 19800, "-08:00": -28800, "+0530": 19800, "-0800": -28800}.get(offset.decode("utf-8", "ignore").strip(), pval)
    return Case(WRAP, data, date=first, time=second, pset=pset, pval=pval)


def tail_grid():
    """Each stub result against each separator, each tag value, and each parsed-state word."""
    for tag in range(0, 7):
        yield Case(WRAP, b"2020-01-02T03:04:05Z", date=("err", tag), time=("ok", 8))
        yield Case(WRAP, b"2020-01-02T03:04:05Z", date=("ok", 10), time=("err", tag))
    for sep in (b"T", b"t", b" ", b"x", b"", b"\xc3\xa9", b"T\x80", b"\x80"):
        for consumed in (0, 1, 10, 11, 19, 20, 40):
            yield Case(WRAP, b"2020-01-02" + sep + b"03:04:05Z", date=("ok", consumed), time=("ok", 8))
    for offset in OFFSETS:
        for pset, pval in ((0, 0), (1, 0), (1, 19800), (1, -28800), (2, 19800), (0xFFFFFFFF, 19800)):
            data = b"2020-01-02T03:04:05" + offset.encode()
            yield Case(WRAP, data, date=("ok", 10), time=("ok", 8), pset=pset, pval=pval)
            if offset.startswith((" ", "+", "-")):
                yield Case(WRAP, data + b"\x80", date=("ok", 10), time=("ok", 8), pset=pset, pval=pval)
    for tail in (b"utc\x80", b"UTC\xbf", b"utc\xc3\xa9", b"ut\x80", b"utc", b"Z\x80", b"+\x80", b"+05\x80", b"+05:30\x80", b"+05:3\x80"):
        yield Case(WRAP, b"2020-01-02T03:04:05" + tail, date=("ok", 10), time=("ok", 8), pset=1, pval=0)


def admissible(case):
    """Inputs a `&str` could hold, plus one stray continuation byte at the exact byte the body checks for a char boundary."""
    try:
        case.data.decode("utf-8")
        return True
    except UnicodeDecodeError as error:
        spec = Spec()
        got = spec.run(case)
        return got[0] == "panic" and spec.pos == error.start and len(case.data) > error.end - 1 and error.end - error.start == 1


def admitted(cases):
    for case in cases:
        if admissible(case):
            yield case


def zone_cases(stream):
    """Every 1, 2 and 3 letter word in both cases, then names behind tails, then the numeric form."""
    letters = "abcdefghijklmnopqrstuvwxyz"
    for a in letters:
        yield Case(ZONE, a.encode())
        yield Case(ZONE, a.upper().encode() + b"x1")
        for b in letters:
            yield Case(ZONE, (a + b).encode())
            if a in "um":
                yield Case(ZONE, (a + b).upper().encode() + b" ")
            for c in letters:
                yield Case(ZONE, (a + b + c).encode(), crit=(a + b + c) in ZONE_NAMES)
    for name in tuple(ZONE_NAMES) + ("ut", "z", "j", "k", "y", "a", "i"):
        for tail in (b"", b" ", b"+0100", b"x", "\u00e9".encode(), b"\x80", b"1", b"-0500", b"ut", b"est"):
            for mangled in (name, name.upper(), name.capitalize(), name[::-1]):
                yield Case(ZONE, mangled.encode() + tail)
                yield Case(ZONE, b" " + mangled.encode() + tail)
    for sign in (b"+", b"-", "\u2212".encode()):
        for hours in range(100):
            for minutes in range(0, 100, 1 if hours % 9 == 0 else 11):
                yield Case(ZONE, sign + b"%02d%02d" % (hours, minutes))
                if hours % 13 == 0:
                    yield Case(ZONE, sign + b"%02d%02dx" % (hours, minutes))
    for _ in range(3000):
        lead = pick(stream, ("+", "-", "+", "-", "", "x", "\u2212", "\u00e9"))
        digits = pick(stream, ("0530", "053", "05", "0", "", "05a0", "a530", "0560", "0599", "9999", "05\u06630", "0630", "1234"))
        tail = pick(stream, ("", "", " ", "x", "\u00e9", "0", ":00"))
        data = (lead + digits + tail).encode()
        if next(stream) % 12 == 0:
            cut = next(stream) % (len(data) + 1)
            data = data[:cut] + b"\x80" + data[cut:]
        yield Case(ZONE, data)


def all_cases(scale=1):
    yield from admitted(raw_cases(scale))


def raw_cases(scale=1):
    stream = lcg(0x115)
    for _ in range(9000 * scale):
        yield tz_random(stream)
    yield from tz_grid()
    yield from tz_leads()
    yield from tz_positions()
    for _ in range(9000 * scale):
        yield tail_case(stream)
    yield from tail_grid()
    yield from zone_cases(stream)


def named_cases():
    """Hand-written edge inputs that the generated streams are not guaranteed to hit in every build."""
    rows = [
        (b"", 1, 1, 1), (b"Z", 1, 0, 0), (b"z", 1, 0, 0), (b"Z", 0, 0, 0), (b"Zx", 1, 0, 0), (b"Z\x80", 1, 0, 0), (b"+", 0, 0, 0), (b"-", 0, 0, 0),
        (b"+0", 0, 0, 0), (b"+05", 0, 0, 0), (b"+05", 0, 1, 0), (b"+05:", 0, 1, 0), (b"+05:3", 0, 1, 0), (b"+05:30", 0, 0, 0), (b"-05:30", 0, 0, 0),
        (b"+05:60", 0, 0, 0), (b"+05:59", 0, 0, 0), (b"+99:59", 0, 0, 0), (b"+0a", 0, 0, 0), (b"+05 : 30", 0, 0, 0), (b"+05\x80", 0, 0, 0),
        (b"+\x80", 0, 0, 0), (b"-\x80", 0, 0, 0), (b"+05:30\x80", 0, 0, 0), (b"+05:3\x80", 0, 0, 0), ("−05".encode(), 0, 1, 1),
        ("−05".encode(), 0, 1, 0), ("−".encode(), 0, 0, 1), ("−05:30".encode(), 0, 0, 1), ("−\x80".encode("latin-1", "ignore"), 0, 0, 1),
        ("−".encode() + b"\x80", 0, 0, 1), ("−".encode() + b"0530", 0, 0, 1), ("−".encode() + b"0530", 0, 0, 0), (b"+05\xe2\x80\x83:30", 0, 0, 0),
        (b"+05:30 ", 0, 0, 0), (b"+0530", 0, 0, 0), (b"+05\n30", 0, 0, 0),
    ]
    out = [Case(TZ, *row) for row in rows]
    for text in (b"", b"z", b"Z", b"j", b"J", b"k", b"y", b"zz", b"ut", b"UT", b"gmt", b"GMT", b"Est", b"PDT", b"pdt1", b"abcd", b"gmtx", b"+0530", b"-0800", b"+05", b"+053",
                 b"+0560", b"+0599", b"+05a0", b"+", b"-", b"+\x80", b"+05\x80", b"+0530\x80", b"+0530x", b"gmt\x80", b"est\xbf",
                 b" gmt", b"x", "\u2212".encode() + b"0530", b"+9959"):
        out.append(Case(ZONE, text))
    out = [case for case in out if admissible(case)]
    for date, time, data, pset, pval in (
        (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05Z", 0, 0), (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05 UTC", 0, 0),
        (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05utc", 1, 0), (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05utc", 1, 5),
        (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05+05:30", 1, 19800), (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05+05:30", 1, 0),
        (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05", 0, 0), (("ok", 10), ("ok", 8), b"2020-01-02", 0, 0),
        (("ok", 10), ("ok", 8), b"2020-01-02t03:04:05-0800", 7, 0), (("ok", 10), ("ok", 8), b"2020-01-02T03:04:05\xe2\x80\x83utc", 0, 0),
    ):
        out.append(Case(WRAP, data, date=date, time=time, pset=pset, pval=pval))
    return [case for case in out if admissible(case)]


# ---------------------------------------------------------------- checking

def digest(outcome):
    return hashlib.sha256(repr(outcome).encode()).hexdigest()[:12]


def classify(case, outcome):
    if outcome[0] == "panic":
        return "panic-" + outcome[1]
    blob = outcome[1]
    if blob[0:8] == bytes(8):
        return "err-%d" % blob[8]
    if case.kind in (TZ, ZONE):
        value = struct.unpack_from("<i", blob, 0x10)[0]
        return "ok-negative" if value < 0 else "ok-zero" if value == 0 else "ok-positive"
    return "ok-merged" if outcome[2][0:4] == struct.pack("<I", 1) else "ok-set"


def check_stream(harness, cases, spec, tally, samples, sample_every, chosen=None):
    """Run each case, compare at once, keep only counts, every `sample_every`-th row and a class-picked subset for the edit controls."""
    count = 0
    taken = {}
    for case in cases:
        got = harness.run(case)
        want = spec.run(case)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.label(), got, want))
        name = classify(case, got)
        key = (case.kind, name)
        tally[key] = tally.get(key, 0) + 1
        if samples is not None and count % sample_every == 0:
            samples.append((case.label(), name, digest(got)))
        if chosen is not None:
            picked = (case.kind, name, case.zulu, case.missing, case.minus, min(len(case.data), 3))
            taken[picked] = taken.get(picked, 0) + 1
            if taken[picked] <= 2 or case.crit:
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
    for target in ALL_BODIES:
        start, end = image.exact_fde(target)
        rows[target] = cpu.decode_range(image, start, end)
    return rows


# ---------------------------------------------------------------- evidence tables

def read_items(image, begin, end):
    """Decode a chrono Item slice: 24-byte entries, tag byte, kind byte, padding byte; literals point at 1 byte."""
    relative = image.relative()
    tags = {0: "Literal", 1: "OwnedLiteral", 2: "Space", 3: "OwnedSpace", 4: "Numeric", 5: "Fixed", 6: "Error"}
    rows = []
    for index, va in enumerate(range(begin, end, 24)):
        raw = bytes(image.blob[image.offset(va):image.offset(va) + 24])
        tag = raw[0]
        detail = "-"
        if tag in (0, 2):
            pointer = relative.get(va + 8, struct.unpack_from("<Q", raw, 8)[0])
            size = struct.unpack_from("<Q", raw, 16)[0]
            text = bytes(image.blob[image.offset(pointer):image.offset(pointer) + size]) if size else b""
            detail = "%r/%d" % (text.decode("latin-1"), size)
        elif tag in (4, 5):
            detail = "kind=%d pad=%d" % (raw[1], raw[2])
        rows.append((index, "%#x" % va, tags.get(tag, "?%d" % tag), detail, raw.hex()))
    return rows


def item_rows(image):
    rows = []
    for name, (begin, end) in (("DATE", DATE_ITEMS), ("TIME", TIME_ITEMS)):
        for row in read_items(image, begin, end):
            rows.append((name,) + row)
    return rows


def text_calls(image):
    """(call site, callee) for every direct near call or jump in .text, found by the E8/E9 byte pattern."""
    section = image.named[".text"]
    base, address, size = section["offset"], section["address"], section["size"]
    blob = bytes(image.blob[base:base + size])
    wanted = set(ALL_BODIES) | {PARSE}
    found = []
    for hit in re.finditer(rb"[\xe8\xe9]", blob):
        at = hit.start()
        if at + 5 > size:
            continue
        target = (address + at + 5 + struct.unpack_from("<i", blob, at + 1)[0]) & 0xFFFFFFFFFFFFFFFF
        if target in wanted:
            found.append((address + at, target, blob[at] == 0xE8))
    return found


def owner_of(image, va):
    index = max(0, len([s for s in image.starts if s <= va]) - 1)
    return image.starts[index]


def caller_rows(image):
    rows = []
    for site, target, is_call in sorted(text_calls(image)):
        if not is_call:
            continue
        rows.append((NAMES.get(target) or {PARSE: "parse_internal", TRIM: "trim_start", COLON: "trim_colon_space"}[target], "%#x" % target, "%#x" % site, "%#x" % owner_of(image, site)))
    rows.sort(key=lambda row: (row[1], row[2]))
    return rows


def flag_rows(image, rows):
    """For every call of timezone_offset: the constants loaded into rcx, r8 and r9 (zulu, missing minutes, minus sign)."""
    out = []
    for site, target, is_call in sorted(text_calls(image)):
        if target != TZ or not is_call:
            continue
        owner = owner_of(image, site)
        body = rows.get(owner) or cpu.decode_range(image, owner, image.exact_fde(owner)[1])
        position = next(i for i, row in enumerate(body) if row.va == site)
        values = {}
        for row in reversed(body[max(0, position - 14):position]):
            if row.op in ("jcc", "jmp", "call"):
                break
            if row.op == "mov" and row.a[0] == "r" and row.b[0] == "i" and row.a[1] in (cpu.RCX, cpu.R8, cpu.R9):
                values.setdefault(row.a[1], row.b[1] & 0xFF)
            elif row.op == "xor" and row.a == row.b and row.a[0] == "r" and row.a[1] in (cpu.RCX, cpu.R8, cpu.R9):
                values.setdefault(row.a[1], 0)
        out.append(("%#x" % owner, "%#x" % site, *("%s" % values.get(reg, "unset") for reg in (cpu.RCX, cpu.R8, cpu.R9))))
    return out


def render_functions(image, rows):
    lines = ["function\tstart\tend\tsize\tinstructions\tconditionals\tcalls"]
    names = dict(NAMES)
    names[TRIM], names[COLON] = "trim_start", "trim_colon_space"
    for target in ALL_BODIES:
        start, end = image.exact_fde(target)
        body = rows[target]
        lines.append("\t".join((names[target], "%#x" % start, "%#x" % end, str(end - start), str(len(body)),
                                 str(sum(1 for row in body if row.op == "jcc")), str(sum(1 for row in body if row.op in ("call", "calli", "jmpi"))))))
    return lines


def render_reach(rows, seen):
    lines = ["function\tinsns\treached\tunreached\tfirst_unreached"]
    for target in ALL_BODIES:
        body = rows[target]
        missing = [row.va for row in body if row.va not in seen]
        lines.append("\t".join(({TZ: "timezone_offset", WRAP: "datetime_tail", ZONE: "timezone_offset_2822", TRIM: "trim_start", COLON: "trim_colon_space"}[target], str(len(body)), str(len(body) - len(missing)), str(len(missing)),
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
    for name in SPEC_MUTANTS + WRONG_MUTANTS + ZONE_MUTANTS:
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
    for label, va in (("address inside a function", TZ + 1), ("address before a body", WRAP - 1), ("address in .rodata", 0x459230), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    relative = image.relative()
    rows.append(("white space slot against a code address is not a slot to that target", "detected" if relative.get(SLOT_WS_TABLE) != TRIM else "MISSED"))
    harness = Harness(image)
    probe = Case(TZ, b"+05:30", 0, 0, 0)
    rows.append(("timezone_offset result compared with the datetime_tail rule", "detected" if harness.run(probe) != Spec().tail(Case(WRAP, b"+05:30", date=("ok", 0), time=("ok", 0))) else "MISSED"))
    sites = {site for site, target, call in text_calls(image) if target == TZ and call}
    rows.append(("the wrapper call of timezone_offset is one of the located call sites", "detected" if 0x1621865 in sites else "MISSED"))
    rows.append(("an address that does not call timezone_offset is not a call site", "detected" if 0x1621866 not in sites else "MISSED"))
    try:
        Harness(image).run(Case(TZ, b"1" * 140000, 1, 1, 1))
        rows.append(("a string that does not fit the evaluator memory is refused", "MISSED"))
    except Halt:
        rows.append(("a string that does not fit the evaluator memory is refused", "detected"))
    rows.append(("date window of the stub differs when the item list is swapped", "detected" if harness.run(Case(WRAP, b"2020-01-02T03:04:05Z", date=("ok", 10), time=("ok", 8)))[3] != Spec().tail(Case(WRAP, b"2020-01-02T03:04:05Z", date=("ok", 10), time=("ok", 8)))[3][::-1] else "MISSED"))
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
    total += check_stream(harness, all_cases(), spec, tally, samples, 600, chosen)
    seen = set(harness.machine.seen)
    rows = edit_rows(image)
    result = {"total": total, "named": named_total, "tally": tally, "samples": samples, "seen": seen, "rows": rows,
              "items": item_rows(image), "callers": caller_rows(image), "flags": flag_rows(image, rows)}
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
    files["reach.tsv"] = render_reach(result["rows"], result["seen"])
    files["items.tsv"] = tsv(("list", "index", "address", "item", "detail", "raw_24_bytes"), result["items"])
    files["callers.tsv"] = tsv(("callee", "callee_address", "call_site", "owner_function"), result["callers"])
    files["call-flags.tsv"] = tsv(("owner_function", "call_site", "allow_zulu_rcx", "allow_missing_minutes_r8", "allow_minus_sign_r9"), result["flags"])
    outcomes = sorted(result["tally"].items())
    files["outcomes.tsv"] = tsv(("function", "outcome", "cases"), [(NAMES[kind], name, count) for (kind, name), count in outcomes])
    files["sample-cases.tsv"] = tsv(("case", "outcome", "result-digest"), result["samples"])
    byte = result.get("byte", [])
    files["byte-mutants.tsv"] = tsv(("function", "address", "edit", "verdict", "caught_by"), [(n, "%#x" % va, k, v, w) for n, va, k, v, w in byte])
    files["rule-mutants.tsv"] = tsv(("wrong rule", "verdict", "first contradicting case"), result.get("spec", []))
    files["structural.tsv"] = tsv(("control", "verdict"), result.get("struct", []))
    killed = sum(1 for row in byte if row[3] == "killed")
    equivalent = sum(1 for row in byte if row[3] == "survived")
    spec_rows = result.get("spec", [])
    struct_rows = result.get("struct", [])
    negatives = len(byte) + len(spec_rows) + len(struct_rows)
    detected = killed + sum(1 for row in spec_rows if row[1] == "detected") + sum(1 for row in struct_rows if row[1] == "detected")
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
