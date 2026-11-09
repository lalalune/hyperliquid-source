#!/usr/bin/env python3
"""Reconstruct the node #115 chrono RFC 2822 date parser and the seven scanners it is built from.

The real bytes of parse_rfc2822 0x161fa20 (1,425 bytes) and of every body it calls run in the small x86-64 evaluator of
tools/bole_rate115.py: the digit scanner 0x161f900, set_hour 0x1621cc0, the single-character scanner 0x1625ce0, the parenthesised
comment scanner 0x1624e80, the weekday and month name scanners 0x1625100 and 0x1624fb0 (reached through two GOT slots), the numeric
and named zone scanner 0x1625790 and trim_start 0x16288c0. Nothing is stubbed except the panic slots. A rule list written from the
documented chrono behaviour (a different code path from the bytes) predicts, for every generated input, the exact result bytes, the
update of the parsed-fields record (an optional weekday byte and seven present-flag plus value word pairs), the value returned by
set_hour, or the panic and the input byte that caused it. Every reached conditional, immediate and displacement of the seven main
bodies is edited to prove the cases notice. Call sites, slot users and the field offsets are read from file bytes. No objdump or
readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/chrono_rfc2822_parse_115.py --out <dir>
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

P2822, NUM, HOUR, CHAR, COMMENT, WEEK, MONTH, ZONE, TRIM = 0x161FA20, 0x161F900, 0x1621CC0, 0x1625CE0, 0x1624E80, 0x1625100, 0x1624FB0, 0x1625790, 0x16288C0
TARGETS = (P2822, NUM, HOUR, CHAR, COMMENT, WEEK, MONTH)
ALL_BODIES = TARGETS + (ZONE, TRIM)
NAMES = {P2822: "parse_rfc2822", NUM: "scan_number", HOUR: "set_hour", CHAR: "scan_char", COMMENT: "scan_comment_2822", WEEK: "scan_weekday",
         MONTH: "scan_month", ZONE: "timezone_offset_2822", TRIM: "trim_start"}
SLOT_WEEK, SLOT_MONTH = 0x64E1B08, 0x64E1B10
PANIC_SLOTS = {0x64DF670: "slice", 0x64DF730: "assert", 0x64DF620: "index", 0x64DF520: "overflow", 0x64DF6A0: "other", 0x64DF848: "unwrap"}
SLOT_WS_TABLE = 0x64DFC30
MARK_BASE = 0x7700000000
OUT = cpu.HEAP_BASE + 0x200
OUT_SIZE = 0x20
PARSED = cpu.HEAP_BASE + 0x300
PARSED_SIZE = 0xA8
STR = cpu.HEAP_BASE + 0x1000
USED = 0x2000
FILL = bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE))
PATTERN = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000))
INITIAL = PATTERN[PARSED - cpu.HEAP_BASE:PARSED - cpu.HEAP_BASE + PARSED_SIZE]
OUT_OF_RANGE, IMPOSSIBLE, INVALID, TOO_SHORT = 0, 1, 3, 4
U64 = (1 << 64) - 1
# field offsets inside the parsed-fields record: a present flag word, then the value word; the weekday is a single byte
F_YEAR, F_MONTH, F_DAY, F_HOUR12, F_HOURMOD, F_MINUTE, F_SECOND, F_OFFSET, F_WEEKDAY = 0x10, 0x40, 0x68, 0x70, 0x78, 0x80, 0x88, 0x98, 0xA0
FIELDS = (F_YEAR, F_MONTH, F_DAY, F_HOUR12, F_HOURMOD, F_MINUTE, F_SECOND, F_OFFSET)
FIELD_NAMES = {F_YEAR: "year", F_MONTH: "month", F_DAY: "day", F_HOUR12: "hour_div_12", F_HOURMOD: "hour_mod_12", F_MINUTE: "minute",
               F_SECOND: "second", F_OFFSET: "offset", F_WEEKDAY: "weekday"}
WEEKDAYS = {b"mon": 0, b"tue": 1, b"wed": 2, b"thu": 3, b"fri": 4, b"sat": 5, b"sun": 6}
MONTHS = {b"jan": 0, b"feb": 1, b"mar": 2, b"apr": 3, b"may": 4, b"jun": 5, b"jul": 6, b"aug": 7, b"sep": 8, b"oct": 9, b"nov": 10, b"dec": 11}
ZONE_NAMES = {"cst": -6, "cdt": -5, "est": -5, "edt": -4, "mst": -7, "mdt": -6, "pst": -8, "pdt": -7, "gmt": 0}
WHITESPACE = frozenset(list(range(9, 14)) + [0x20, 0x85, 0xA0, 0x1680] + list(range(0x2000, 0x200B)) + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000])
MINUS_SIGN = 0x2212


class Case:
    """One input. `arg` is the extra argument tuple of the kind; `pre` lists (offset, bytes) writes into the parsed record."""

    __slots__ = ("kind", "data", "arg", "pre", "crit")

    def __init__(self, kind, data=b"", arg=(), pre=(), crit=False):
        pre = tuple(pre)
        if kind == P2822 and all(offset != F_WEEKDAY for offset, _ in pre):
            pre = ((F_WEEKDAY, b"\x07"),) + pre  # an empty record holds no weekday; the byte value 7 means none
        self.kind, self.data, self.arg, self.pre, self.crit = kind, bytes(data), tuple(arg), pre, crit

    def label(self):
        pre = ";".join("%x=%s" % (off, raw.hex()) for off, raw in self.pre) or "-"
        return "%x|%s|%s|%s" % (self.kind, self.data.hex(), ",".join(str(a) for a in self.arg) or "-", pre)


def initial_state(case):
    st = bytearray(INITIAL)
    for offset, raw in case.pre:
        st[offset:offset + len(raw)] = raw
    return st


def word(flag, value):
    return struct.pack("<II", flag & 0xFFFFFFFF, value & 0xFFFFFFFF)


class Stop(Exception):
    def __init__(self, panic, pos):
        super().__init__(panic)
        self.panic, self.pos = panic, pos


# ---------------------------------------------------------------- the written rule list

class Spec:
    """chrono's RFC 2822 rules. `mutants` names deliberate mistakes; the empty set is the claim under test."""

    def __init__(self, mutants=frozenset()):
        self.m = mutants
        self.pos = None

    def stop(self, pos, start, end):
        raise Stop(("panic", "slice", start, end), pos)

    @staticmethod
    def is_cont(byte):
        return 0x80 <= byte <= 0xBF

    @staticmethod
    def pack(*fields):
        out = bytearray(FILL)
        for offset, size, value in fields:
            out[offset:offset + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        return bytes(out)

    def err(self, kind):
        return self.pack((0, 8, 0), (8, 1, kind))

    @staticmethod
    def trim_count(text):
        cut = 0
        for char in text.decode("utf-8", "surrogateescape"):
            if ord(char) in WHITESPACE:
                cut += len(char.encode("utf-8"))
            else:
                break
        return cut

    def trim(self, d, p):
        return p + self.trim_count(d[p:])

    # -- the small scanners; each returns ("ok", new_position, value) or ("err", kind)

    def number(self, d, p, low, high):
        m = self.m
        size = len(d) - p
        if low > high:
            raise Stop(("panic", "assert", 28, 0), None)
        if size < low:
            return ("err", TOO_SHORT)
        used, value = 0, 0
        while used != size:
            byte = d[p + used]
            digit = byte - 0x30
            if not 0 <= digit <= 9:
                if used < low:
                    return ("err", INVALID)
                if self.is_cont(byte) and "num-no-boundary" not in m:
                    self.stop(p + used, used, size)
                return ("ok", p + used, value)
            value = value * 10
            if value >= 1 << 63 and "num-wraps" not in m:
                return ("err", OUT_OF_RANGE)
            value += digit
            if value >= 1 << 63 and "num-wraps" not in m:
                return ("err", OUT_OF_RANGE)
            used += 1
            if used == high:
                break
        stop_at = min(high, size)
        if not (high >= size or stop_at == 0) and self.is_cont(d[p + stop_at]) and "num-no-boundary" not in m:
            self.stop(p + stop_at, stop_at, size)
        if "num-max-is-exact" in m and high < size and used != high:
            return ("err", INVALID)
        return ("ok", p + stop_at, value)

    def char(self, d, p, ch):
        size = len(d) - p
        if size == 0:
            return ("err", TOO_SHORT)
        if d[p] != ch:
            return ("err", INVALID)
        if size > 1 and self.is_cont(d[p + 1]) and "char-no-boundary" not in self.m:
            self.stop(p + 1, 1, size)
        return ("ok", p + 1, None)

    def comment(self, d, p):
        m = self.m
        q = self.trim(d, p)
        size = len(d) - q
        if size == 0:
            return ("err", TOO_SHORT)
        state, depth, index = 0, 0, 1
        while True:
            byte = d[q + index - 1]
            if state == 0:
                state, depth = 1, 1
                if byte != 0x28:
                    return ("err", INVALID)
            elif state == 1:
                if byte == 0x28:
                    depth += 1
                    if "comment-flat" in m:
                        depth = 1
                elif byte == 0x29:
                    if depth == 1:
                        if index < size and self.is_cont(d[q + index]):
                            self.stop(q + index, index, size)
                        return ("ok", q + index, None)
                    depth -= 1
                elif byte == 0x5C and "comment-no-escape" not in m:
                    state = 2
                    if index == size:
                        return ("err", TOO_SHORT)
                    index += 1
                    continue
            else:
                state = 1
            if index == size:
                return ("err", TOO_SHORT)
            index += 1

    def named(self, d, p, table, short_kind_bytes):
        """Shared by the weekday and month scanners: three ASCII letters, case-insensitive, then a character boundary."""
        size = len(d) - p
        if size <= 2:
            return ("err", TOO_SHORT)
        key = bytes((b | 0x20) if 0x41 <= b <= 0x5A else b for b in d[p:p + 3])
        if key not in table:
            return ("err", INVALID)
        if size > 3 and self.is_cont(d[p + 3]):
            self.stop(p + 3, 3, size)
        return ("ok", p + 3, table[key])

    def weekday(self, d, p):
        table = WEEKDAYS
        if "week-sunday-first" in self.m:
            table = {k: (v + 1) % 7 for k, v in WEEKDAYS.items()}
        return self.named(d, p, table, None)

    def month(self, d, p):
        table = MONTHS
        if "month-one-based" in self.m:
            table = {k: v + 1 for k, v in MONTHS.items()}
        return self.named(d, p, table, None)

    def zone(self, d, p):
        """timezone_offset_2822: an ASCII letter run is a zone word (UT, GMT, US names, one military letter), otherwise [+-]hhmm."""
        data, size = d[p:], len(d) - p
        m = self.m

        def stop(index, start, end):
            self.stop(p + index, start, end)
        if size == 0:
            return ("err", TOO_SHORT)
        run = 0
        while run < size and (data[run] & 0xDF) in range(0x41, 0x5B):
            run += 1
        if run:
            if run < size and self.is_cont(data[run]):
                stop(run, run, size)
            text = data[:run].decode("ascii").lower()
            if run == 1:
                upper = text.upper()
                if text == "z" or "A" <= upper <= "I" or "K" <= upper <= "Y":
                    return ("ok", p + 1, 0)
                return ("err", INVALID)
            if run == 2:
                return ("ok", p + 2, 0) if text == "ut" else ("err", INVALID)
            if run == 3 and text in ZONE_NAMES:
                hours = ZONE_NAMES[text]
                if "zone-est-edt-swapped" in m and text in ("est", "edt"):
                    hours = -5 if text == "edt" else -4
                return ("ok", p + 3, hours * 3600)
            return ("err", INVALID)
        char = data[:4].decode("utf-8", "ignore")[:1]
        code = ord(char) if char else -1
        if code == 0x2B:
            negative = False
        elif code == 0x2D:
            negative = True
        else:
            return ("err", INVALID)
        if size == 1:
            return ("err", TOO_SHORT)
        if self.is_cont(data[1]):
            stop(1, 1, size)
        if size < 3:
            return ("err", TOO_SHORT)
        if not (0x30 <= data[1] <= 0x39 and 0x30 <= data[2] <= 0x39):
            return ("err", INVALID)
        if size - 1 < 3:
            return ("err", TOO_SHORT)
        if self.is_cont(data[3]):
            stop(3, 2, size - 1)
        if size - 3 < 2:
            return ("err", TOO_SHORT)
        first, second = data[3], data[4]
        if 0x30 <= first <= 0x35:
            if not 0x30 <= second <= 0x39:
                return ("err", INVALID)
            if size - 3 != 2 and self.is_cont(data[5]):
                stop(5, 2, size - 3)
            total = ((data[1] - 0x30) * 10 + data[2] - 0x30) * 3600 + ((first - 0x30) * 10 + second - 0x30) * 60
            return ("ok", p + 5, -total if negative else total)
        if 0x36 <= first <= 0x39 and 0x30 <= second <= 0x39:
            return ("err", OUT_OF_RANGE)
        return ("err", INVALID)

    # -- the parsed-fields record

    def put(self, st, offset, value):
        """Set-once: a present field must hold the same value, otherwise the parse is impossible. True means impossible."""
        flag, held = struct.unpack_from("<II", st, offset)
        if flag == 1 and "put-overwrites" not in self.m:
            return held != value & 0xFFFFFFFF
        st[offset:offset + 8] = word(1, value)
        return False

    def set_hour(self, st, value):
        m = self.m
        if value >= 24:
            return 0
        div, mod = (0, value) if value < 12 else (1, value - 12)
        if "hour-no-wrap" in m:
            mod = value
        if self.put(st, F_HOUR12, div):
            return 1
        return 8 if not self.put(st, F_HOURMOD, mod) else 1

    def after(self, d, p, text_len):
        """The whitespace that must follow a field: nothing trimmed is an error, too short when nothing is left at all."""
        q = self.trim(d, p)
        if q == p and "after-optional" not in self.m:
            return None, (TOO_SHORT if len(d) - p == 0 else INVALID)
        return q, None

    def parse(self, d, st):
        """parse_rfc2822: [weekday ","] day month year hour ":" minute [":" second] zone {comment}, as (kind, payload)."""
        m = self.m
        size = len(d)
        p = self.trim(d, 0)
        week = self.weekday(d, p)
        if week[0] == "ok":
            q = week[1]
            if size - q == 0 or d[q] != 0x2C:
                return ("err", INVALID)
            if size - q > 1 and self.is_cont(d[q + 1]):
                self.stop(q + 1, 1, size - q)
            current = st[F_WEEKDAY]
            if current == 7:
                st[F_WEEKDAY] = week[2]
            elif current != week[2] and "weekday-conflict-ignored" not in m:
                return ("err", IMPOSSIBLE)
            p = q + 1
        p = self.trim(d, p)
        # day: one or two digits
        left = size - p
        if left == 0:
            return ("err", TOO_SHORT)
        first = d[p] - 0x30
        if not 0 <= first <= 9:
            return ("err", INVALID)
        value, used = first, 1
        if left > 1:
            second = d[p + 1]
            if 0x30 <= second <= 0x39:
                value, used = value * 10 + second - 0x30, 2
                if left >= 3 and self.is_cont(d[p + 2]):
                    self.stop(p + 2, 2, left)
            elif self.is_cont(second):
                self.stop(p + 1, 1, left)
        low_day = 1 if "day-zero-ok" not in m else 0
        if not low_day <= value <= 31:
            return ("err", OUT_OF_RANGE)
        if self.put(st, F_DAY, value):
            return ("err", IMPOSSIBLE)
        q = self.trim(d, p + used)
        if q == p + used:
            return ("err", TOO_SHORT if left == used else INVALID)
        p = q
        month = self.month(d, p)
        if month[0] == "err":
            return month
        if self.put(st, F_MONTH, month[2] + 1):
            return ("err", IMPOSSIBLE)
        p = month[1]
        q, bad = self.after(d, p, 0)
        if bad is not None:
            return ("err", bad)
        p = q
        year = self.number(d, p, 2, U64)
        if year[0] == "err":
            return year
        digits = year[1] - p
        value = year[2]
        if digits == 2 and "year-no-window" not in m:
            value += 2000 if value < 50 else 1900
        elif digits == 3:
            value += 1900
        if value >= 1 << 31:
            return ("err", OUT_OF_RANGE)
        if self.put(st, F_YEAR, value):
            return ("err", IMPOSSIBLE)
        q, bad = self.after(d, year[1], 0)
        if bad is not None:
            return ("err", bad)
        hour = self.number(d, q, 2, 2)
        if hour[0] == "err":
            return hour
        code = self.set_hour(st, hour[2])
        if code != 8:
            return ("err", code)
        p = self.trim(d, hour[1])
        colon = self.char(d, p, 0x3A)
        if colon[0] == "err":
            return colon
        p = self.trim(d, colon[1])
        minute = self.number(d, p, 2, 2)
        if minute[0] == "err":
            return minute
        if minute[2] > 59:
            return ("err", OUT_OF_RANGE)
        if self.put(st, F_MINUTE, minute[2]):
            return ("err", IMPOSSIBLE)
        p = minute[1]
        again = self.char(d, self.trim(d, p), 0x3A)
        if again[0] == "ok":
            second = self.number(d, again[1], 2, 2)
            if second[0] == "err":
                return second
            if second[2] > (60 if "second-59" not in m else 59):
                return ("err", OUT_OF_RANGE)
            if self.put(st, F_SECOND, second[2]):
                return ("err", IMPOSSIBLE)
            p = second[1]
        q, bad = self.after(d, p, 0)
        if bad is not None:
            return ("err", bad)
        zone = self.zone(d, q)
        if zone[0] == "err":
            return zone
        if self.put(st, F_OFFSET, zone[2]):
            return ("err", IMPOSSIBLE)
        p = zone[1]
        while "comments-ignored" not in m:
            got = self.comment(d, p)
            if got[0] != "ok":
                break
            p = got[1]
        return ("ok", p)

    def run(self, case):
        kind, d = case.kind, case.data
        st = initial_state(case)
        try:
            if kind == P2822:
                got = self.parse(d, st)
                out = self.err(got[1]) if got[0] == "err" else self.pack((0, 8, STR + got[1]), (8, 8, len(d) - got[1]))
                return ("out", out, bytes(st))
            if kind == HOUR:
                return ("hour", self.set_hour(st, case.arg[0]), bytes(st))
            if kind == NUM:
                got = self.number(d, 0, case.arg[0], case.arg[1])
                if got[0] == "err":
                    return ("out", self.err(got[1]), bytes(st))
                return ("out", self.pack((0, 8, STR + got[1]), (8, 8, len(d) - got[1]), (0x10, 8, got[2])), bytes(st))
            if kind == CHAR:
                got = self.char(d, 0, case.arg[0])
            elif kind == COMMENT:
                got = self.comment(d, 0)
            else:
                got = (self.weekday if kind == WEEK else self.month)(d, 0)
                if got[0] == "err" and kind == WEEK:
                    return ("out", self.pack((0, 1, got[1]), (0x10, 1, 7)), bytes(st))
                if got[0] == "ok":
                    return ("out", self.pack((0, 8, STR + got[1]), (8, 8, len(d) - got[1]), (0x10, 1, got[2])), bytes(st))
            if got[0] == "err":
                return ("out", self.err(got[1]), bytes(st))
            return ("out", self.pack((0, 8, STR + got[1]), (8, 8, len(d) - got[1])), bytes(st))
        except Stop as stop:
            self.pos = stop.pos
            return stop.panic


SPEC_MUTANTS = (
    "num-wraps", "num-no-boundary", "num-max-is-exact", "char-no-boundary", "comment-flat", "comment-no-escape", "week-sunday-first",
    "month-one-based", "zone-est-edt-swapped", "put-overwrites", "hour-no-wrap", "after-optional", "weekday-conflict-ignored",
    "day-zero-ok", "year-no-window", "second-59", "comments-ignored",
)


class Wrong(Spec):
    """Shape-level mistakes layered on the rule list; the case set must contradict every one."""

    def run(self, case):
        got = Spec.run(self, case)
        m = self.m
        if got[0] == "panic":
            return got
        if "wrong-error-kind-three-as-four" in m and got[0] == "out" and got[1][0:8] == bytes(8) and got[1][8] == INVALID:
            return ("out", self.err(TOO_SHORT), got[2])
        if "wrong-hour-ok-code" in m and got[0] == "hour" and got[1] == 8:
            return ("hour", 0, got[2])
        if "wrong-hour-keeps-state" in m and got[0] == "hour":
            return ("hour", got[1], initial_state(case) and bytes(initial_state(case)))
        if "wrong-rest-off-by-one" in m and got[0] == "out" and got[1][0:8] != bytes(8):
            ptr, size = struct.unpack_from("<QQ", got[1], 0)
            return ("out", got[1][:8] + struct.pack("<Q", max(size - 1, 0)) + got[1][16:], got[2]) if size else got
        if "wrong-leaves-state-on-error" in m and got[0] == "out" and got[1][0:8] == bytes(8) and case.kind == P2822:
            return ("out", got[1], bytes(initial_state(case)))
        if "wrong-weekday-not-stored" in m and case.kind == P2822 and got[2][F_WEEKDAY] != initial_state(case)[F_WEEKDAY]:
            kept = bytearray(got[2])
            kept[F_WEEKDAY] = initial_state(case)[F_WEEKDAY]
            return ("out", got[1], bytes(kept))
        if "wrong-year-stored-raw" in m and case.kind == P2822 and struct.unpack_from("<I", got[2], F_YEAR)[0] == 1:
            kept = bytearray(got[2])
            value = struct.unpack_from("<I", kept, F_YEAR + 4)[0]
            kept[F_YEAR + 4:F_YEAR + 8] = struct.pack("<I", value % 100 if 1900 <= value < 2100 else value)
            return ("out", got[1], bytes(kept))
        return got


WRONG_MUTANTS = (
    "wrong-error-kind-three-as-four", "wrong-hour-ok-code", "wrong-hour-keeps-state", "wrong-rest-off-by-one", "wrong-leaves-state-on-error",
    "wrong-weekday-not-stored", "wrong-year-stored-raw",
)


# ---------------------------------------------------------------- the evaluator harness

class Machine(cpu.Machine):
    """The shared evaluator leaves OF alone on imul; the digit scanner branches on it, so it is added here."""

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
        for slot in (SLOT_WS_TABLE, SLOT_WEEK, SLOT_MONTH):
            statics[slot] = relative[slot]
        machine.real = frozenset(ALL_BODIES)
        machine.step_limit = 30000

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
        memory.put_bytes(cpu.HEAP_BASE, PATTERN)
        memory.put_bytes(OUT, FILL)
        memory.put_bytes(STR, case.data)
        for offset, raw in case.pre:
            memory.put_bytes(PARSED + offset, raw)
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        size = len(case.data)
        kind = case.kind
        if kind == P2822:
            args = {cpu.RDI: OUT, cpu.RSI: PARSED, cpu.RDX: STR, cpu.RCX: size}
        elif kind == NUM:
            args = {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size, cpu.RCX: case.arg[0], cpu.R8: case.arg[1]}
        elif kind == HOUR:
            args = {cpu.RDI: PARSED, cpu.RSI: case.arg[0]}
        elif kind == CHAR:
            args = {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size, cpu.RCX: case.arg[0]}
        else:
            args = {cpu.RDI: OUT, cpu.RSI: STR, cpu.RDX: size}
        try:
            returned = machine.run(kind, args)
        except Panicked as stop:
            name, begin, end = stop.args[0]
            return ("panic", name, begin, end)
        after = bytes(memory.heap[:USED])
        start, end = OUT - cpu.HEAP_BASE, OUT - cpu.HEAP_BASE + OUT_SIZE
        state_at = PARSED - cpu.HEAP_BASE
        mask_before, mask_after = bytearray(before), bytearray(after)
        for low, high in ((start, end), (state_at, state_at + PARSED_SIZE)):
            mask_before[low:high] = bytes(high - low)
            mask_after[low:high] = bytes(high - low)
        if mask_before != mask_after:
            raise Halt("state changed outside the result")
        parsed = after[state_at:state_at + PARSED_SIZE]
        if kind == HOUR:
            return ("hour", returned & 0xFF, parsed)
        return ("out", after[start:end], parsed)


# ---------------------------------------------------------------- generated inputs

def lcg(seed):
    state = seed & U64
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & U64
        yield state >> 33


def pick(stream, options):
    return options[next(stream) % len(options)]


def admissible(case):
    """Inputs a `&str` could hold, plus one stray continuation byte at the exact byte a body checks for a char boundary."""
    try:
        case.data.decode("utf-8")
        return True
    except UnicodeDecodeError as error:
        spec = Spec()
        got = spec.run(case)
        return got[0] == "panic" and spec.pos == error.start and error.end - error.start == 1


def admitted(cases):
    for case in cases:
        if admissible(case):
            yield case


def with_presets(stream, case):
    """Pre-set a few parsed fields to the value this very input would produce, or to a different one."""
    if case.kind != P2822 or next(stream) % 4:
        return case
    spec = Spec()
    dry = spec.run(case)
    if dry[0] == "panic":
        return case
    state = dry[2]
    pre = []
    for offset in FIELDS + (F_WEEKDAY,):
        mode = next(stream) % 10
        if mode < 7:
            continue
        if offset == F_WEEKDAY:
            held = state[offset]
            pre.append((offset, bytes((held if mode < 9 and held != 7 else next(stream) % 8,))))
            continue
        flag, value = struct.unpack_from("<II", state, offset)
        wanted = value if flag == 1 and mode < 9 else (next(stream) % 3000)
        pre.append((offset, word(1 if mode < 9 or next(stream) % 3 else 2, wanted)))
    return Case(case.kind, case.data, case.arg, pre)


WEEKDAY_TEXT = ("", "", "Mon, ", "tue,", "WED ,", "Thu,", "fri, ", "Sat,  ", "sun,", "Mon ", "Mo", "Monday, ", "xyz, ", "Fri,x", "Sun;", ",", "Sat", " Tue,")
DAY_TEXT = ("1", "01", "5", "12", "31", "32", "0", "00", "99", "5x", "123", "", "a", "٣", "9é", "7\t")
GAP = (" ", " ", " ", "  ", "", "\t", "　", "\n ", " ")
MONTH_TEXT = tuple(n.decode() for n in MONTHS) + ("JAN", "dEc", "Sep", "Sept", "Ja", "", "xyz", "Mayx", "mär", "aprl")
YEAR_TEXT = ("2020", "1999", "99", "49", "50", "00", "20", "2", "20x", "999", "100", "12345", "2147483647", "2147483648", "2147481748", "99999999999999999999",
             "9223372036854775807", "9223372036854775808", "٣٣", "0000", "1900")
TIME_TEXT = ("12:34:56", "00:00", "23:59:60", "24:00", "12:60", "12:34:61", "1:23", "12 : 34 : 56", "09: 08", "11:11 :11", "12:34:5", "12:34:", "12:", "12",
             "12:3x", "00:00:00", "13:00", "99:00", "12:34:56x", "3:07:09", "11:59:59")
ZONE_TEXT = ("+0100", "-0800", "GMT", "UT", "est", "Z", "+01", "", "x", "UTC", "+0560", "-0000", "pst", "J", "+2359", "+9999", "−" + "0500", "+05:30")
TAIL_TEXT = ("", "", "", " (comment)", " (a (b) c) (d)", " (unterminated", "(\\))", " x", " (a)x", " ((", " (\\", "()", " (é) (ü)", " (a\\)b)")


GOOD_WEEKDAY = ("", "Mon, ", "tue,", "WED, ", "Thu,  ", "fri,", "Sat, ", "sUn,")
GOOD_DAY = ("1", "01", "9", "12", "31", "28")
GOOD_YEAR = ("2020", "1999", "99", "49", "50", "100", "0000", "2038")
GOOD_TIME = ("12:34:56", "00:00", "23:59:60", "09: 08", "11:11 :11", "3:07:09"[1:], "12 : 34")
GOOD_ZONE = ("+0100", "-0800", "GMT", "UT", "est", "Z", "pst", "+2359", "J")


def main_case(stream):
    if next(stream) % 5 < 3:
        parts = [pick(stream, GOOD_WEEKDAY), pick(stream, GAP[:3]), pick(stream, GOOD_DAY), pick(stream, GAP[:3]), pick(stream, MONTH_TEXT[:12]), pick(stream, GAP[:3]),
                 pick(stream, GOOD_YEAR), pick(stream, GAP[:3]), pick(stream, GOOD_TIME), pick(stream, GAP[:3]), pick(stream, GOOD_ZONE), pick(stream, TAIL_TEXT)]
        parts[1] = parts[1] if parts[1] else " "
        data = "".join(parts).encode()
        if next(stream) % 9 == 0:
            cut = next(stream) % (len(data) + 1)
            data = data[:cut] + b"\x80" + data[cut:]
        return with_presets(stream, Case(P2822, data))
    parts = [pick(stream, WEEKDAY_TEXT), pick(stream, GAP), pick(stream, DAY_TEXT), pick(stream, GAP), pick(stream, MONTH_TEXT), pick(stream, GAP),
             pick(stream, YEAR_TEXT), pick(stream, GAP), pick(stream, TIME_TEXT), pick(stream, GAP), pick(stream, ZONE_TEXT), pick(stream, TAIL_TEXT)]
    if next(stream) % 5:
        for index in (1, 3, 5, 7, 9):
            if parts[index] == "":
                parts[index] = " "
    data = "".join(parts).encode()
    if next(stream) % 14 == 0:
        cut = next(stream) % (len(data) + 1)
        data = data[:cut] + b"\x80" + data[cut:]
    return with_presets(stream, Case(P2822, data))


BASES = (b"Tue, 02 Jan 2024 03:04:05 +0100 (CET)", b" 7 sep 99 23:59 GMT", b"Sun,31\tDec 0099 00:00:60 -0830 (a (b\\)) c)", b"1 Feb 2020 12:00 Z")


def position_cases(stream):
    """Every byte value at every position of well-formed dates, the whole byte-level boundary of the parser."""
    values = list(range(0x80)) + [0x80, 0xBF, 0xC0, 0xC3, 0xFF]
    for base in BASES:
        for position in range(len(base)):
            for value in values:
                data = bytearray(base)
                data[position] = value
                yield with_presets(stream, Case(P2822, bytes(data), crit=value in (0x20, 0x2C, 0x30, 0x39, 0x3A, 0x28, 0x29, 0x5C, 0x80, 0xBF)))


def truncation_cases(stream):
    for base in BASES:
        for cut in range(len(base) + 1):
            for tail in (b"", b"\x80", "é".encode()):
                yield with_presets(stream, Case(P2822, base[:cut] + tail))


def number_cases(stream):
    shapes = ((0, 0), (0, 1), (1, 1), (2, 2), (2, 3), (2, U64), (1, U64), (0, U64), (4, 4), (3, 2), (5, 2), (0, 3), (2, 1 << 63))
    texts = ("", "0", "7", "12", "123", "1234", "12x", "1é", "x1", "99999999999999999999", "9223372036854775807", "9223372036854775808", "922337203685477580x",
             "00", "000000000000000000000000012", "1 ", "12\t", "٣٣", "1234567890123456789", "4294967296")
    for mn, mx in shapes:
        for text in texts:
            for tail in ("", "7", "x", "é", "\x80"):
                data = (text + tail).encode("utf-8", "surrogateescape") if tail != "\x80" else text.encode() + b"\x80"
                yield Case(NUM, data, (mn, mx))
    for _ in range(2200):
        text = "".join(pick(stream, "0123456789" * 3 + "x é") for _ in range(next(stream) % 24))
        data = text.encode()
        if next(stream) % 6 == 0:
            cut = next(stream) % (len(data) + 1)
            data = data[:cut] + b"\x80" + data[cut:]
        yield Case(NUM, data, pick(stream, shapes))


def hour_cases(stream):
    values = list(range(0, 30)) + [47, 48, 255, 256, (1 << 32) - 1, 1 << 32, (1 << 32) + 5, U64]
    for value in values:
        yield Case(HOUR, arg=(value,))
        for flag12 in (0, 1, 2):
            for held12 in (0, 1, 7):
                for flagmod in (0, 1):
                    for heldmod in (0, 3, value % 12 if value < 24 else 0, 11):
                        pre = ((F_HOUR12, word(flag12, held12)), (F_HOURMOD, word(flagmod, heldmod)))
                        yield Case(HOUR, arg=(value,), pre=pre)


def char_cases(stream):
    for ch in (0x3A, 0x2C, 0x20, 0x7F, 0x80, 0xC3, 0xFF, 0x00):
        for text in ("", ":", ",", ":x", ":é", ":\x80", ":::", " :", "\xc3", "é", "\x00"):
            data = text.encode("utf-8", "surrogateescape") if "\x80" not in text else text.replace("\x80", "").encode() + b"\x80"
            yield Case(CHAR, data, (ch,))


COMMENT_ALPHABET = ("(", ")", "\\", "a", " ", "é", "(", ")", "x", "\t")


def comment_cases(stream):
    for text in ("", " ", "(", "()", "(a)", "(a)b", "(a)é", "( ( ) )", "(\\)", "(\\))", "(()", "((a))", "(a\\", "x", " (a)", "　(b)", "(é)", "(a\\\\)", "(\\", ")(", "((((a))))"):
        yield Case(COMMENT, text.encode())
        yield Case(COMMENT, text.encode() + b"\x80")
    for _ in range(3600):
        text = "".join(pick(stream, COMMENT_ALPHABET) for _ in range(next(stream) % 16))
        data = (pick(stream, ("", "", " ", "(")) + text).encode()
        if next(stream) % 6 == 0:
            cut = next(stream) % (len(data) + 1)
            data = data[:cut] + b"\x80" + data[cut:]
        yield Case(COMMENT, data)


def name_cases(kind, table):
    values = list(range(0x20, 0x7F)) + [0x80, 0xBF, 0xC3]
    for name in table:
        word_text = name.decode()
        for variant in (word_text, word_text.upper(), word_text.capitalize()):
            for tail in (b"", b"x", b"\x80", "é".encode(), b" "):
                yield Case(kind, variant.encode() + tail, crit=True)
        for position in range(3):
            for value in values:
                data = bytearray(name)
                data[position] = value
                yield Case(kind, bytes(data) + b" ")
                if value in (0x80, 0xBF):
                    yield Case(kind, bytes(data) + "é".encode())
    for first in range(0x61, 0x7B):
        for second in (0x61, 0x6F, 0x75, 0x65, 0x72):
            yield Case(kind, bytes((first, second, 0x6E)))
            yield Case(kind, bytes((first, second)))


def raw_cases(scale=1):
    stream = lcg(0x115)
    for _ in range(14000 * scale):
        yield main_case(stream)
    yield from position_cases(stream)
    yield from truncation_cases(stream)
    yield from number_cases(stream)
    yield from hour_cases(stream)
    yield from char_cases(stream)
    yield from comment_cases(stream)
    yield from name_cases(WEEK, WEEKDAYS)
    yield from name_cases(MONTH, MONTHS)


def all_cases(scale=1):
    yield from admitted(raw_cases(scale))


def named_cases():
    """Hand-written edge inputs that the generated streams are not guaranteed to hit in every build."""
    rows = [
        b"Tue, 02 Jan 2024 03:04:05 +0100", b"2 Jan 24 03:04 GMT", b"Mon, 31 Dec 99 23:59:60 UT", b"1 Jan 100 00:00 Z", b"1 Jan 2020 12:00 +0100 (c) (d) tail",
        b"Mon,", b"Mon", b"Mo", b"", b" ", b"32 Jan 2020 12:00 Z", b"0 Jan 2020 12:00 Z", b"1 Jan 2147483648 12:00 Z", b"1 Jan 2147483647 12:00 Z",
        b"1 Jan 2020 24:00 Z", b"1 Jan 2020 12:60 Z", b"1 Jan 2020 12:00:61 Z", b"1 Jan 2020 12:00:60 Z", b"1\x80", b"12\x80", b"Mon\x80, 1", b"Mon,\x80",
        b"1 Jan 2020 12:00Z", b"1 Jan2020 12:00 Z", b"1Jan 2020 12:00 Z", b"1 Jan 2020 12:00 Z\x80", b"1 Jan 2020 12:00 Z (\x80)",
    ]
    for zone in (b"EST", b"edt", b"CST", b"cdt", b"MST", b"mdt", b"PST", b"pdt", b"GMT", b"UT", b"ut", b"J", b"K", b"y", b"Z", b"utc", b"+2359", b"-0000"):
        rows.append(b"1 Jan 2020 12:00 " + zone)
    out = [Case(P2822, data) for data in rows]
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_WEEKDAY, bytes((1,))),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_WEEKDAY, bytes((2,))),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_DAY, word(1, 2)), (F_MONTH, word(1, 1)))))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_OFFSET, word(1, 3600)),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_OFFSET, word(1, 3601)),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_HOUR12, word(1, 1)),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_SECOND, word(1, 5)),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_SECOND, word(1, 6)),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_YEAR, word(1, 2023)),)))
    out.append(Case(P2822, b"Tue, 02 Jan 2024 03:04:05 +0100", pre=((F_MINUTE, word(1, 5)),)))
    return [case for case in out if admissible(case)]


# ---------------------------------------------------------------- checking

def digest(outcome):
    return hashlib.sha256(repr(outcome).encode()).hexdigest()[:12]


def classify(case, outcome):
    if outcome[0] == "panic":
        return "panic-" + outcome[1], 0
    if outcome[0] == "hour":
        return "ret-%d" % outcome[1], 0
    blob = outcome[1]
    stage = sum(1 for offset in FIELDS if struct.unpack_from("<I", outcome[2], offset)[0] == 1) if case.kind == P2822 else 0
    if case.kind == WEEK:
        return ("err-%d" % blob[0] if blob[0] < 8 and blob[0x10] == 7 else "ok"), stage
    if blob[0:8] == bytes(8):
        return "err-%d" % blob[8], stage
    return "ok", stage


def check_stream(harness, cases, spec, tally, samples, sample_every, chosen=None):
    """Run each case, compare at once, keep only counts, every `sample_every`-th row and a class-picked subset for the edit controls."""
    count = 0
    taken = {}
    for case in cases:
        got = harness.run(case)
        want = spec.run(case)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.label(), got, want))
        name, stage = classify(case, got)
        key = (case.kind, name)
        tally[key] = tally.get(key, 0) + 1
        if samples is not None and count % sample_every == 0:
            samples.append((case.label(), name, digest(got)))
        if chosen is not None:
            picked = (case.kind, name, stage, len(case.pre) > 0, min(len(case.data), 4))
            taken[picked] = taken.get(picked, 0) + 1
            if taken[picked] <= 1 or case.crit:
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

def text_calls(image):
    """(call site, callee, kind) for every direct near call or jump in .text and every call through a slot, found by byte patterns."""
    section = image.named[".text"]
    base, address, size = section["offset"], section["address"], section["size"]
    blob = bytes(image.blob[base:base + size])
    relative = image.relative()
    slots = {slot: target for slot, target in relative.items() if target in ALL_BODIES}
    wanted = set(ALL_BODIES)
    found = []
    for hit in re.finditer(rb"[\xe8\xe9]", blob):
        at = hit.start()
        if at + 5 > size:
            continue
        target = (address + at + 5 + struct.unpack_from("<i", blob, at + 1)[0]) & U64
        if target in wanted:
            found.append((address + at, target, "call" if blob[at] == 0xE8 else "jmp"))
    for hit in re.finditer(rb"\xff[\x15\x25]", blob):
        at = hit.start()
        if at + 6 > size:
            continue
        slot = (address + at + 6 + struct.unpack_from("<i", blob, at + 2)[0]) & U64
        if slot in slots:
            found.append((address + at, slots[slot], "slot-call" if blob[at + 1] == 0x15 else "slot-jmp"))
    return found


def owner_of(image, va):
    index = max(0, len([s for s in image.starts if s <= va]) - 1)
    return image.starts[index]


def caller_rows(image):
    rows = []
    for site, target, kind in sorted(text_calls(image)):
        rows.append((NAMES[target], "%#x" % target, kind, "%#x" % site, "%#x" % owner_of(image, site)))
    rows.sort(key=lambda row: (row[1], row[3]))
    return rows


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, target in sorted(relative.items()):
        if target in ALL_BODIES:
            rows.append(("%#x" % slot, "%#x" % target, NAMES[target]))
    return rows


def layout_rows(image, rows, seen):
    """Offsets of the parsed-fields record the parser touches, read from the [r14+disp] operands of the target body."""
    found = {}
    start, end = image.exact_fde(P2822)
    blob = bytes(image.blob[image.offset(start):image.offset(end)])
    for hit in re.finditer(rb"(?s)\x83\xb8|\x41\x83\xbe|\x41\xc7\x86|\x41\x80\xbe|\x45\x0f\xb6|\x41\x88\x86", blob):
        pass
    rows_out = []
    for row in rows[P2822]:
        text = repr(row.a) + repr(row.b)
        if row.op in ("cmp", "mov") and any(isinstance(part, tuple) and part and part[0] == "m" and part[1] == cpu.R14 for part in (row.a, row.b)):
            for part in (row.a, row.b):
                if isinstance(part, tuple) and part and part[0] == "m" and part[1] == cpu.R14:
                    found.setdefault(part[4], []).append(row.va)
    for offset in sorted(found):
        rows_out.append(("%#x" % offset, FIELD_NAMES.get(offset, FIELD_NAMES.get(offset - 4, "-")) + ("" if offset in FIELD_NAMES else ".value"), len(found[offset]),
                         ",".join("%#x" % va for va in found[offset][:8])))
    return rows_out


def render_functions(image, rows):
    lines = ["function\tstart\tend\tsize\tinstructions\tconditionals\tcalls"]
    for target in ALL_BODIES:
        start, end = image.exact_fde(target)
        body = rows[target]
        lines.append("\t".join((NAMES[target], "%#x" % start, "%#x" % end, str(end - start), str(len(body)),
                                 str(sum(1 for row in body if row.op == "jcc")), str(sum(1 for row in body if row.op in ("call", "calli", "jmpi"))))))
    return lines


def render_reach(rows, seen):
    lines = ["function\tinsns\treached\tunreached\tfirst_unreached"]
    for target in ALL_BODIES:
        body = rows[target]
        missing = [row.va for row in body if row.va not in seen]
        lines.append("\t".join((NAMES[target], str(len(body)), str(len(body) - len(missing)), str(len(missing)), ",".join("%#x" % va for va in missing[:12]) or "-")))
    return lines


# ---------------------------------------------------------------- mutants

def run_byte_mutants(image, rows, seen, chosen):
    results = []
    spec = Spec()
    for target in TARGETS:
        subset = chosen[target]
        for va, kind, patch in cpu.edits_for(image, rows[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = 6000
            if first_failure(harness, subset, spec) is not None:
                results.append((NAMES[target], va, kind, "killed", "class-picked subset"))
            else:
                results.append((NAMES[target], va, kind, "survived", "equivalent edit"))
    return results


def spec_mutant_rows(image, cases):
    rows = []
    harness = Harness(image)
    outcomes = [(case, harness.run(case)) for case in cases]
    for name in SPEC_MUTANTS + WRONG_MUTANTS:
        wrong = Wrong(frozenset((name,)))
        found = None
        for case, got in outcomes:
            if got != wrong.run(case):
                found = case
                break
        rows.append((name, "detected" if found is not None else "MISSED", found.label() if found is not None else "-"))
    return rows


def structural_rows(image):
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    rows.append(("one flipped file byte changes the SHA-256", "detected" if hashlib.sha256(bytes(blob)).hexdigest() != SHA256 else "MISSED"))
    for label, va in (("address inside a function", P2822 + 1), ("address before a body", NUM - 1), ("address in .rodata", 0x459230), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    relative = image.relative()
    rows.append(("the weekday slot holds the weekday scanner and not the month scanner", "detected" if relative.get(SLOT_WEEK) == WEEK and relative.get(SLOT_MONTH) == MONTH else "MISSED"))
    rows.append(("white space slot against a code address is not a slot to that target", "detected" if relative.get(SLOT_WS_TABLE) != TRIM else "MISSED"))
    harness = Harness(image)
    sites = {site for site, target, kind in text_calls(image) if target == TRIM and kind == "call"}
    rows.append(("the parser's first call of trim_start is one of the located call sites", "detected" if 0x161FA39 in sites else "MISSED"))
    rows.append(("an address that does not call trim_start is not a call site", "detected" if 0x161FA3A not in sites else "MISSED"))
    try:
        harness.run(Case(P2822, b"1" * 140000))
        rows.append(("a string that does not fit the evaluator memory is refused", "MISSED"))
    except Halt:
        rows.append(("a string that does not fit the evaluator memory is refused", "detected"))
    probe = Case(NUM, b"12", (2, 2))
    rows.append(("scan_number result differs from the month scanner rule", "detected" if harness.run(probe) != Spec().run(Case(MONTH, b"12")) else "MISSED"))
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
    total += check_stream(harness, all_cases(), spec, tally, samples, 800, chosen)
    seen = set(harness.machine.seen)
    rows = edit_rows(image)
    result = {"total": total, "named": named_total, "tally": tally, "samples": samples, "seen": seen, "rows": rows,
              "callers": caller_rows(image), "slots": slot_rows(image), "layout": layout_rows(image, rows, seen)}
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
    files["callers.tsv"] = tsv(("callee", "callee_address", "kind", "call_site", "owner_function"), result["callers"])
    files["slots.tsv"] = tsv(("slot", "relocated_target", "function"), result["slots"])
    files["record-layout.tsv"] = tsv(("record_offset", "field", "touching_instructions", "first_sites"), result["layout"])
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
