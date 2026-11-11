#!/usr/bin/env python3
"""Reconstruct the node #115 chrono format-item interpreter (parse_internal) and the setters and scanners it drives.

parse_internal 0x1620be0 (2,888 bytes) walks a slice of 24 byte format items over an input string and fills the parsed-fields record:
literals (borrowed and owned), white space, twenty numeric kinds with their per-kind digit width, sign rule and set-once setter, the
name, am/pm, fraction and time zone name items, and the error item. The real bytes of the interpreter, of trim_start 0x16288c0, of the
name skipper 0x1628740, of the weekday, month and long-month scanners, of both fraction scanners and of all nineteen setters run in the
small x86-64 evaluator of tools/bole_rate115.py; only the panic slots and the memory compare slot are stubbed. A rule list written from the
documented chrono behaviour predicts, for every generated item list and input, the result bytes and the final parsed-fields record. The
dispatch tables, setter record offsets, GOT slots and call sites are read from file bytes. Every reached conditional, immediate and
displacement of the thirteen main bodies is edited to prove the cases notice. The time zone offset items, RFC 2822 and RFC 3339 items are
dispatched through other bodies and are outside this domain. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/chrono_parse_internal_115.py --out <dir>
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

INTERNAL, TRIM, SKIP, WEEK, MONTH, LMONTH, NANO, NANOFIX, WFROMSUN, WFROMMON = (
    0x1620BE0, 0x16288C0, 0x1628740, 0x1625100, 0x1624FB0, 0x1625680, 0x1624BC0, 0x1625550, 0x1621940, 0x1621900)
SETTERS = {0x1621D20: "set_year", 0x1621B60: "set_year_div_100", 0x1621B90: "set_year_mod_100", 0x1621A80: "set_isoyear", 0x1621C20: "set_isoyear_div_100",
           0x1621C50: "set_isoyear_mod_100", 0x1621D50: "set_month", 0x1621C80: "set_day", 0x1621BF0: "set_week_from_sun", 0x1621BC0: "set_week_from_mon",
           0x1621A40: "set_isoweek", 0x1621AB0: "set_ordinal", 0x1621CC0: "set_hour", 0x1621980: "set_hour12", 0x16219C0: "set_minute", 0x1621A00: "set_second",
           0x1621B20: "set_nanosecond", 0x1621AF0: "set_timestamp"}
TARGETS = (INTERNAL, TRIM, SKIP, WEEK, MONTH, LMONTH, NANO, NANOFIX, WFROMSUN, WFROMMON) + tuple(sorted(SETTERS))
ALL_BODIES = TARGETS
NAMES = {INTERNAL: "parse_internal", TRIM: "trim_start", SKIP: "timezone_name_skip", WEEK: "scan_weekday", MONTH: "scan_month", LMONTH: "scan_long_month",
         NANO: "scan_nanosecond", NANOFIX: "scan_nanosecond_fixed", WFROMSUN: "set_weekday_from_sunday", WFROMMON: "set_weekday_from_monday"}
NAMES.update(SETTERS)
SLOT_WEEK, SLOT_MONTH, SLOT_NANO, SLOT_YEAR_SET, SLOT_WDAY_SET, SLOT_LMONTH, SLOT_NANOFIX = 0x64E1B08, 0x64E1B10, 0x64E1B18, 0x64E1B20, 0x64E1B28, 0x64E1B38, 0x64E1B40
SLOT_RFC2822, SLOT_RFC3339 = 0x64E1B00, 0x64E1B30
SLOT_WS_TABLE, SLOT_MEMCMP = 0x64DFC30, 0x64DF9F8
PANIC_SLOTS = {0x64DF670: "slice", 0x64DF730: "assert", 0x64DF620: "index", 0x64DF520: "overflow", 0x64DF6A0: "other", 0x64DF848: "unwrap"}
MARK_BASE = 0x7700000000
TAG_TABLE, FIXED_TABLE, INTERNAL_TABLE, NUMERIC_TABLE = 0x46B188, 0x46B1A4, 0x46B1F4, 0x46B204
LONG_WEEKDAY_TABLE, LONG_MONTH_TABLE = 0x64051A0, 0x64050B0
OUT = cpu.HEAP_BASE + 0x200
OUT_SIZE = 0x20
PARSED = cpu.HEAP_BASE + 0x300
PARSED_SIZE = 0xA8
ITEMS = cpu.HEAP_BASE + 0x500
LITS = cpu.HEAP_BASE + 0xB00
STR = cpu.HEAP_BASE + 0x1000
USED = 0x2000
FILL = bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE))
PATTERN = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000))

def valid_record():
    """A record every Option flag of which holds a legal encoding (absent); the value words keep garbage so a read of an absent value shows."""
    record = bytearray(PATTERN[PARSED - cpu.HEAP_BASE:PARSED - cpu.HEAP_BASE + PARSED_SIZE])
    for offset in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98):
        record[offset:offset + 4] = bytes(4)
    record[0:8] = bytes(8)
    record[0xA0] = 7
    return record


INITIAL = bytes(valid_record())
OUT_OF_RANGE, IMPOSSIBLE, INVALID, TOO_SHORT, BAD_FORMAT = 0, 1, 3, 4, 6
OK_CODE = 8
U64 = (1 << 64) - 1
I64 = (1 << 63) - 1
WHITESPACE = frozenset(list(range(9, 14)) + [0x20, 0x85, 0xA0, 0x1680] + list(range(0x2000, 0x200B)) + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000])
WEEKDAYS = {b"mon": 0, b"tue": 1, b"wed": 2, b"thu": 3, b"fri": 4, b"sat": 5, b"sun": 6}
MONTHS = {b"jan": 0, b"feb": 1, b"mar": 2, b"apr": 3, b"may": 4, b"jun": 5, b"jul": 6, b"aug": 7, b"sep": 8, b"oct": 9, b"nov": 10, b"dec": 11}
LONG_MONTH_SUFFIX = (b"uary", b"ruary", b"ch", b"il", b"", b"e", b"y", b"ust", b"tember", b"ober", b"ember", b"ember")
LONG_WEEKDAY_SUFFIX = (b"day", b"sday", b"nesday", b"rsday", b"day", b"urday", b"day")

# item tags and the sub-kinds the interpreter dispatches on (byte 0 and byte 1 of a 24 byte item)
LITERAL, OWNED_LITERAL, SPACE, OWNED_SPACE, NUMERIC, FIXED, ERROR = range(7)
# numeric kind -> (name, record offset or None, digit width, signed)
NUMERIC_KINDS = (
    ("Year", 0x10, 4, True), ("YearDiv100", 0x18, 2, False), ("YearMod100", 0x20, 2, False), ("IsoYear", 0x28, 4, True),
    ("IsoYearDiv100", 0x30, 2, False), ("IsoYearMod100", 0x38, 2, False), ("Month", 0x40, 2, False), ("Day", 0x68, 2, False),
    ("WeekFromSun", 0x48, 2, False), ("WeekFromMon", 0x50, 2, False), ("IsoWeek", 0x58, 2, False), ("NumDaysFromSun", 0xA0, 1, False),
    ("WeekdayFromMon", 0xA0, 1, False), ("Ordinal", 0x60, 3, False), ("Hour", 0x70, 2, False), ("Hour12", 0x78, 2, False),
    ("Minute", 0x80, 2, False), ("Second", 0x88, 2, False), ("Nanosecond", 0x90, 9, False), ("Timestamp", 0x00, U64, False),
)
# fixed kind byte -> name; bytes 0..3 are the internal items, 4.. are the public ones
FIXED_KINDS = {0: "TimezoneOffsetPermissive", 1: "Nanosecond3NoDot", 2: "Nanosecond6NoDot", 3: "Nanosecond9NoDot", 4: "ShortMonthName", 5: "LongMonthName",
               6: "ShortWeekdayName", 7: "LongWeekdayName", 8: "LowerAmPm", 9: "UpperAmPm", 10: "Nanosecond", 11: "Nanosecond3", 12: "Nanosecond6",
               13: "Nanosecond9", 14: "TimezoneName"}
IN_DOMAIN_FIXED = (1, 2, 3) + tuple(range(4, 15))
F_YEAR, F_MONTH, F_HOUR12, F_HOURMOD, F_NANO, F_WEEKDAY = 0x10, 0x40, 0x70, 0x78, 0x90, 0xA0
FIELD_NAMES = {0x00: "timestamp", 0x10: "year", 0x18: "year_div_100", 0x20: "year_mod_100", 0x28: "isoyear", 0x30: "isoyear_div_100", 0x38: "isoyear_mod_100",
               0x40: "month", 0x48: "week_from_sun", 0x50: "week_from_mon", 0x58: "isoweek", 0x60: "ordinal", 0x68: "day", 0x70: "hour_div_12", 0x78: "hour_mod_12",
               0x80: "minute", 0x88: "second", 0x90: "nanosecond", 0x98: "offset", 0xA0: "weekday"}
WORD_FIELDS = tuple(sorted(offset for offset in FIELD_NAMES if offset not in (0x00, 0xA0, 0x98)))
RANGES = {0x10: (-(1 << 31), (1 << 31) - 1), 0x28: (-(1 << 31), (1 << 31) - 1), 0x18: (0, 0x7FFFFFFF), 0x30: (0, 0x7FFFFFFF), 0x20: (0, 99), 0x38: (0, 99),
          0x40: (1, 12), 0x48: (0, 53), 0x50: (0, 53), 0x58: (1, 53), 0x60: (1, 366), 0x68: (1, 31), 0x80: (0, 59), 0x88: (0, 60), 0x90: (0, 999999999)}


class Item:
    """One 24 byte format item. `text` is the literal for the literal and space tags, `junk` fills the bytes the interpreter does not read."""

    __slots__ = ("tag", "sub", "text", "junk")

    def __init__(self, tag, sub=0, text=b"", junk=0):
        self.tag, self.sub, self.text, self.junk = tag, sub, bytes(text), junk

    def label(self):
        return "%d.%d.%s.%d" % (self.tag, self.sub, self.text.hex() or "-", self.junk)


class Case:
    """An item list, an input and `pre` writes (offset, bytes) into the parsed record."""

    __slots__ = ("items", "data", "pre", "crit")

    def __init__(self, items, data=b"", pre=(), crit=False):
        self.items, self.data, self.pre, self.crit = tuple(items), bytes(data), tuple(pre), crit

    def label(self):
        pre = ";".join("%x=%s" % (off, raw.hex()) for off, raw in self.pre) or "-"
        return "%s|%s|%s" % (",".join(item.label() for item in self.items) or "-", self.data.hex() or "-", pre)


def initial_state(case):
    st = bytearray(INITIAL)
    for offset, raw in case.pre:
        st[offset:offset + len(raw)] = raw
    return st


def word(flag, value):
    return struct.pack("<II", flag & 0xFFFFFFFF, value & 0xFFFFFFFF)


# ---------------------------------------------------------------- the written rule list

class Spec:
    """chrono's `parse_internal` over its item list. `mutants` names deliberate mistakes; the empty set is the claim under test."""

    def __init__(self, mutants=frozenset()):
        self.m = mutants

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
        if "space-ascii-only" in self.m:
            while p < len(d) and d[p] in (9, 10, 11, 12, 13, 32):
                p += 1
            return p
        return p + self.trim_count(d[p:])

    def number(self, d, p, low, high):
        """scan::number: at least `low` and at most `high` ASCII digits, an i64 accumulator."""
        m = self.m
        size = len(d) - p
        if size < low:
            return ("err", TOO_SHORT)
        used, value = 0, 0
        while used != size:
            byte = d[p + used]
            digit = byte - 0x30
            if not 0 <= digit <= 9:
                if used < low:
                    return ("err", INVALID)
                return ("ok", p + used, value)
            value = value * 10 + digit
            if value > I64 and "num-wraps" not in m:
                return ("err", OUT_OF_RANGE)
            used += 1
            if used == high:
                break
        return ("ok", p + min(high, size), value)

    def named(self, d, p, table):
        if len(d) - p <= 2:
            return ("err", TOO_SHORT)
        key = bytes((b | 0x20) if 0x41 <= b <= 0x5A else b for b in d[p:p + 3])
        if key not in table:
            return ("err", INVALID)
        return ("ok", p + 3, table[key])

    def weekday(self, d, p):
        table = WEEKDAYS
        if "week-sunday-first" in self.m:
            table = {k: (v + 1) % 7 for k, v in WEEKDAYS.items()}
        return self.named(d, p, table)

    def month(self, d, p):
        table = MONTHS
        if "month-one-based" in self.m:
            table = {k: v + 1 for k, v in MONTHS.items()}
        return self.named(d, p, table)

    @staticmethod
    def suffix(d, p, tail):
        if len(d) - p >= len(tail) and bytes((b | 0x20) if 0x41 <= b <= 0x5A else b for b in d[p:p + len(tail)]) == tail:
            return p + len(tail)
        return None

    def long_month(self, d, p):
        got = self.month(d, p)
        if got[0] == "err":
            return got
        if "long-month-suffix-ignored" in self.m:
            return got
        end = self.suffix(d, got[1], LONG_MONTH_SUFFIX[got[2]])
        return ("ok", got[1] if end is None else end, got[2])

    def long_weekday(self, d, p):
        got = self.weekday(d, p)
        if got[0] == "err":
            return got
        tail = LONG_WEEKDAY_SUFFIX[got[2]]
        if "long-weekday-suffix-ignored" in self.m:
            return got
        end = self.suffix(d, got[1], tail)
        return ("ok", got[1] if end is None else end, got[2])

    def nanosecond(self, d, p):
        """scan::nanosecond: one to nine digits scaled to nanoseconds, then any further digits are skipped."""
        got = self.number(d, p, 1, 9)
        if got[0] == "err":
            return got
        used = got[1] - p
        scale = (0, 10 ** 8, 10 ** 7, 10 ** 6, 10 ** 5, 10 ** 4, 10 ** 3, 100, 10, 1)[used]
        if "nano-unscaled" in self.m:
            scale = 1
        q = got[1]
        while "nano-keeps-digits" not in self.m and q < len(d) and 0x30 <= d[q] <= 0x39:
            q += 1
        return ("ok", q, got[2] * scale)

    def nanosecond_fixed(self, d, p, digits):
        got = self.number(d, p, digits, digits)
        if got[0] == "err":
            return got
        return ("ok", got[1], got[2] * 10 ** (9 - digits))

    # -- the parsed-fields record

    def put(self, st, offset, value):
        """Set-once: a present field must hold the same value, otherwise the parse is impossible. True means impossible."""
        flag, held = struct.unpack_from("<II", st, offset)
        if flag == 1 and "put-overwrites" not in self.m:
            return held != value & 0xFFFFFFFF
        st[offset:offset + 8] = word(1, value)
        return False

    def set_hour(self, st, value):
        if value >= 24 or value < 0:
            return OUT_OF_RANGE
        div, mod = (0, value) if value < 12 else (1, value - 12)
        if "hour-no-wrap" in self.m:
            mod = value
        if self.put(st, F_HOUR12, div):
            return IMPOSSIBLE
        return OK_CODE if not self.put(st, F_HOURMOD, mod) else IMPOSSIBLE

    def set_weekday(self, st, number):
        if st[F_WEEKDAY] == 7:
            st[F_WEEKDAY] = number
            return OK_CODE
        return OK_CODE if st[F_WEEKDAY] == number else IMPOSSIBLE

    def setter(self, st, kind, value):
        """The per-kind setter; returns the code the interpreter tests against 8."""
        name, offset, _, _ = NUMERIC_KINDS[kind]
        if name == "Hour":
            return self.set_hour(st, value)
        if name == "Timestamp":
            flag = struct.unpack_from("<I", st, 0)[0]
            if flag == 1 and "put-overwrites" not in self.m:
                return OK_CODE if struct.unpack_from("<Q", st, 8)[0] == value & U64 else IMPOSSIBLE
            st[0:16] = struct.pack("<QQ", 1, value & U64)
            return OK_CODE
        if name == "NumDaysFromSun":
            if not 0 <= value <= 6:
                return OUT_OF_RANGE
            return self.set_weekday(st, (value + 6) % 7 if "sunday-zero-is-monday" not in self.m else value)
        if name == "WeekdayFromMon":
            if not 1 <= value <= 7:
                return OUT_OF_RANGE
            return self.set_weekday(st, value - 1)
        if name == "Hour12":
            if not 1 <= value <= 12:
                return OUT_OF_RANGE
            return OK_CODE if not self.put(st, F_HOURMOD, value % 12 if "hour12-twelve-stays" not in self.m else value) else IMPOSSIBLE
        low, high = RANGES[offset]
        if name == "Second" and "second-59" in self.m:
            high = 59
        if name == "Day" and "day-zero-ok" in self.m:
            low = 0
        if not low <= value <= high:
            return OUT_OF_RANGE
        return OK_CODE if not self.put(st, offset, value) else IMPOSSIBLE

    # -- the interpreter

    def numeric(self, d, p, kind, st):
        name, _, width, signed = NUMERIC_KINDS[kind]
        p = self.trim(d, p)
        if signed and p < len(d) and d[p] in (0x2B, 0x2D) and "sign-ignored" not in self.m:
            got = self.number(d, p + 1, 1, U64)
            if got[0] == "err":
                return got
            value = -got[2] if d[p] == 0x2D else got[2]
            q = got[1]
        else:
            got = self.number(d, p, 1, width if "width-unlimited" not in self.m else U64)
            if got[0] == "err":
                return got
            value, q = got[2], got[1]
        code = self.setter(st, kind, value)
        return ("ok", q) if code == OK_CODE else ("err", code)

    def fixed(self, d, p, sub, st):
        m = self.m
        if sub == 4 or sub == 5:
            got = self.month(d, p) if sub == 4 else self.long_month(d, p)
            if got[0] == "err":
                return got
            return ("err", IMPOSSIBLE) if self.put(st, F_MONTH, got[2] + 1) else ("ok", got[1])
        if sub == 6 or sub == 7:
            got = self.weekday(d, p) if sub == 6 else self.long_weekday(d, p)
            if got[0] == "err":
                return got
            return ("err", IMPOSSIBLE) if self.set_weekday(st, got[2]) != OK_CODE else ("ok", got[1])
        if sub == 8 or sub == 9:
            if len(d) - p < 2:
                return ("err", TOO_SHORT)
            first, second = d[p] | 0x20, d[p + 1] | 0x20
            if (first, second) == (0x61, 0x6D):
                pm = 0
            elif (first, second) == (0x70, 0x6D):
                pm = 1 if "ampm-inverted" not in m else 0
            else:
                return ("err", INVALID)
            if "ampm-case-sensitive" in m and (d[p] != first or d[p + 1] != second) and sub == 8:
                return ("err", INVALID)
            return ("err", IMPOSSIBLE) if self.put(st, F_HOUR12, pm) else ("ok", p + 2)
        if sub == 10 or sub == 11 or sub == 12 or sub == 13:
            if p >= len(d):
                return ("ok", p)
            if d[p] != 0x2E:
                return ("ok", p)
            got = self.nanosecond(d, p + 1)
            if got[0] == "err":
                return got
            if got[2] > 999999999:
                return ("err", OUT_OF_RANGE)
            return ("err", IMPOSSIBLE) if self.put(st, F_NANO, got[2]) else ("ok", got[1])
        if sub in (1, 2, 3):
            digits = {1: 3, 2: 6, 3: 9}[sub]
            if len(d) - p < digits:
                return ("err", TOO_SHORT)
            got = self.nanosecond_fixed(d, p, digits)
            if got[0] == "err":
                return got
            if got[2] > 999999999:
                return ("err", OUT_OF_RANGE)
            return ("err", IMPOSSIBLE) if self.put(st, F_NANO, got[2]) else ("ok", got[1])
        if sub == 14:
            q = p
            text = d[p:].decode("utf-8", "surrogateescape")
            used = 0
            for char in text:
                if ord(char) in WHITESPACE and "skip-stops-late" not in m:
                    break
                used += len(char.encode("utf-8"))
            return ("ok", q + used)
        raise EvidenceError("fixed kind %d is outside the modelled domain" % sub)

    def parse(self, case, st):
        m = self.m
        d, p = case.data, 0
        for item in case.items:
            tag = item.tag
            if tag in (LITERAL, OWNED_LITERAL):
                lit = item.text
                if len(d) - p < len(lit):
                    return ("err", TOO_SHORT)
                if d[p:p + len(lit)] != lit and "literal-prefix-unchecked" not in m:
                    return ("err", INVALID)
                p += len(lit)
            elif tag in (SPACE, OWNED_SPACE):
                p = self.trim(d, p)
            elif tag == NUMERIC:
                got = self.numeric(d, p, item.sub, st)
                if got[0] == "err":
                    return got
                p = got[1]
            elif tag == FIXED:
                got = self.fixed(d, p, item.sub, st)
                if got[0] == "err":
                    return got
                p = got[1]
            elif tag == ERROR:
                return ("err", BAD_FORMAT if "error-item-skipped" not in m else INVALID)
            else:
                raise EvidenceError("tag %d" % tag)
        return ("ok", p)

    def run(self, case):
        st = initial_state(case)
        got = self.parse(case, st)
        if got[0] == "err":
            if "wrong-leaves-state-on-error" in self.m:
                return ("out", self.err(got[1]), bytes(initial_state(case)))
            return ("out", self.err(got[1]), bytes(st))
        return ("out", self.pack((0, 8, STR + got[1]), (8, 8, len(case.data) - got[1])), bytes(st))


SPEC_MUTANTS = (
    "space-ascii-only", "num-wraps", "week-sunday-first", "month-one-based", "long-month-suffix-ignored", "long-weekday-suffix-ignored", "nano-unscaled",
    "nano-keeps-digits", "put-overwrites", "hour-no-wrap", "day-zero-ok", "second-59", "sunday-zero-is-monday", "hour12-twelve-stays", "sign-ignored",
    "width-unlimited", "ampm-inverted", "ampm-case-sensitive", "skip-stops-late", "literal-prefix-unchecked", "error-item-skipped", "wrong-leaves-state-on-error",
)


# ---------------------------------------------------------------- the evaluator harness

_DECODE = cpu.decode


def decode_with_bit_test(read, va):
    """The shared decoder lacks the register form of bit test (REX.WB 0F A3 /r) that the name skipper uses."""
    if bytes(read(va, 4)) == b"\x49\x0f\xa3\xd8":
        return cpu.Insn(va, 4, "btr", ("r", cpu.R8), ("r", cpu.RBX), 8)
    return _DECODE(read, va)


cpu.decode = decode_with_bit_test


class Machine(cpu.Machine):
    """The shared evaluator leaves OF alone on imul; the digit loops branch on it, so it is added here. It also gets the register bit test."""

    def step(self, row):
        if row.op == "btr":
            self.cf = bool(self.get(row.a, 8) >> (self.get(row.b, 8) & 63) & 1)
            return row.next
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
        statics[SLOT_MEMCMP] = MARK_BASE + SLOT_MEMCMP
        machine.slots[MARK_BASE + SLOT_MEMCMP] = self.compare_hook
        relative = image.relative()
        for slot in (SLOT_WS_TABLE, SLOT_WEEK, SLOT_MONTH, SLOT_NANO, SLOT_YEAR_SET, SLOT_WDAY_SET, SLOT_LMONTH, SLOT_NANOFIX):
            statics[slot] = relative[slot]
        for table, count in ((LONG_WEEKDAY_TABLE, 7), (LONG_MONTH_TABLE, 12)):  # (pointer, length) pairs whose pointers are relocated
            for index in range(count):
                statics[table + 16 * index] = relative.get(table + 16 * index, struct.unpack_from("<Q", image.blob, image.offset(table + 16 * index))[0])
        machine.real = frozenset(ALL_BODIES) | {INTERNAL}
        machine.step_limit = 60000

    @staticmethod
    def compare_hook(machine):
        regs = machine.regs
        count = regs[cpu.RDX]
        left = machine.memory.bytes_at(regs[cpu.RDI], count)
        right = machine.memory.bytes_at(regs[cpu.RSI], count)
        regs[cpu.RAX] = 0 if left == right else 1

    @staticmethod
    def panic_hook(name):
        def hook(machine):
            regs = machine.regs
            if name == "slice":
                raise Panicked((name, regs[cpu.RDX], regs[cpu.RCX]))
            raise Panicked((name, 0, 0))
        return hook

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(cpu.HEAP_BASE, PATTERN)
        memory.put_bytes(OUT, FILL)
        memory.put_bytes(PARSED, INITIAL)
        memory.put_bytes(STR, case.data)
        place = LITS
        for index, item in enumerate(case.items):
            raw = bytearray(24)
            raw[0], raw[1] = item.tag, item.sub
            raw[2:8] = bytes(((item.junk * 17 + k * 5) & 0xFF) for k in range(6))
            if item.tag in (LITERAL, OWNED_LITERAL, SPACE, OWNED_SPACE):
                memory.put_bytes(place, item.text)
                struct.pack_into("<QQ", raw, 8, place, len(item.text))
                place += len(item.text) + 1
            memory.put_bytes(ITEMS + 24 * index, bytes(raw))
        for offset, raw in case.pre:
            memory.put_bytes(PARSED + offset, raw)
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        args = {cpu.RDI: OUT, cpu.RSI: PARSED, cpu.RDX: STR, cpu.RCX: len(case.data), cpu.R8: ITEMS, cpu.R9: ITEMS + 24 * len(case.items)}
        try:
            machine.run(INTERNAL, args)
        except Panicked as stop:
            name, begin, end = stop.args[0]
            return ("panic", name, begin, end)
        after = bytes(memory.heap[:USED])
        start, end = OUT - cpu.HEAP_BASE, OUT - cpu.HEAP_BASE + OUT_SIZE
        state_at = PARSED - cpu.HEAP_BASE
        mask_before, mask_after = bytearray(before), bytearray(after)
        # the item and literal areas are inputs and stay as written
        for low, high in ((start, end), (state_at, state_at + PARSED_SIZE)):
            mask_before[low:high] = bytes(high - low)
            mask_after[low:high] = bytes(high - low)
        if mask_before != mask_after:
            raise Halt("state changed outside the result")
        return ("out", after[start:end], after[state_at:state_at + PARSED_SIZE])


# ---------------------------------------------------------------- generated inputs

def lcg(seed):
    state = seed & U64
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & U64
        yield state >> 33


def pick(stream, options):
    return options[next(stream) % len(options)]


def admissible(case):
    """Inputs a `&str` can hold: valid UTF-8 text and literals."""
    try:
        case.data.decode("utf-8")
        for item in case.items:
            item.text.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


NUM_TEXT = {
    "Year": ("2024", "99", "0", "12345", "-1", "+12", "-2147483648", "-2147483649", "2147483647", "+2147483648", "  2020x", "  7", "-", "+", "+a", "abc", "", "٣", "-0",
             "9223372036854775807", "+9223372036854775808", "-9223372036854775808", "+99999999999999999999"),
    "Div": ("0", "19", "20", "99", "100", "007", "999", "1", "x", "", " 21", "2147483647"),
    "Mod": ("0", "24", "99", "100", "07", "1", "x", "", " 5", "123"),
    "Month": ("1", "01", "12", "13", "0", "00", "99", "7x", " 3", "", "a", "123"),
    "Day": ("1", "31", "32", "0", "28", "07", "99", "x", "", "  15"),
    "Week": ("0", "1", "52", "53", "54", "99", "00", "x", ""),
    "IsoWeek": ("0", "1", "53", "54", "07", "x", ""),
    "Dow": ("0", "1", "6", "7", "8", "9", "x", "", " 3"),
    "Ordinal": ("1", "366", "367", "0", "000", "100", "1000", "999", "x", ""),
    "Hour": ("0", "1", "11", "12", "23", "24", "25", "00", "99", "x", "", " 9"),
    "Hour12": ("0", "1", "11", "12", "13", "00", "99", "x", ""),
    "Minute": ("0", "59", "60", "07", "99", "x", ""),
    "Second": ("0", "59", "60", "61", "07", "99", "x", ""),
    "Nanosecond": ("0", "1", "123456789", "999999999", "1234567890", "000000000", "12345678901234567890", "x", ""),
    "Timestamp": ("0", "1700000000", "-1", "+1", "-9223372036854775808", "9223372036854775807", "9223372036854775808", "99999999999999999999", " 5", "x", "", "-", "+0"),
}
KIND_TEXT = ("Year", "Div", "Mod", "Year", "Div", "Mod", "Month", "Day", "Week", "Week", "IsoWeek", "Dow", "Dow", "Ordinal", "Hour", "Hour12", "Minute", "Second",
             "Nanosecond", "Timestamp")
NAME_TEXT = {
    4: ("Jan", "feb", "MAR", "dec", "Sept", "xyz", "Ja", "", "Janu", "jan2"),
    5: ("January", "febRUARY", "March", "may", "September", "Sept", "decem", "decemberx", "jun", "july", "Janu", "augustus", "xyz", ""),
    6: ("Mon", "tue", "WED", "sun", "Moo", "xyz", "Mo", "", "frI"),
    7: ("Monday", "tuesday", "WEDNESDAY", "wed", "Thursday", "friday", "sat", "Saturday", "sunday", "sund", "xyz", "Mondayx", ""),
    8: ("am", "AM", "pm", "Pm", "a", "", "xm", "ax", "pmx", "p"),
    9: ("am", "AM", "pm", "Pm", "a", "", "xm", "ax", "pmx", "p"),
    10: (".5", ".123456789", ".1234567890123", ".", "5", "", ".x", ".000", ".999999999", ".0"),
    11: (".5", ".123", ".1234", ".", "", "x"),
    12: (".5", ".123456", "x"),
    13: (".5", ".123456789", "x"),
    1: ("123", "12", "1234", "abc", "", "12a", "999"),
    2: ("123456", "12345", "1234567", "abcdef", "", "000000"),
    3: ("123456789", "12345678", "1234567890", "abcdefghi", "", "000000001"),
    14: ("EST", "UTC+9", "x y", " abc", "", "é", "a　b", "CET)"),
}
LITERAL_TEXT = ("", ":", "-", "T", "ab", "é", " ", ", ", "+", "/", "ß")
GAP_TEXT = (" ", "", "  ", "\t", "　", "\n", "x")
TAIL_TEXT = ("", "", "", " x", "é", "5", " 12", "-")


def text_for(stream, item):
    tag = item.tag
    if tag in (LITERAL, OWNED_LITERAL):
        lit = item.text.decode()
        return lit if next(stream) % 6 else pick(stream, LITERAL_TEXT)
    if tag in (SPACE, OWNED_SPACE):
        return pick(stream, GAP_TEXT)
    if tag == NUMERIC:
        return pick(stream, NUM_TEXT[KIND_TEXT[item.sub]])
    if tag == FIXED:
        return pick(stream, NAME_TEXT[item.sub])
    return pick(stream, ("", "x"))


def random_item(stream):
    roll = next(stream) % 20
    junk = next(stream) % 7
    if roll < 3:
        return Item(pick(stream, (LITERAL, OWNED_LITERAL)), 0, pick(stream, LITERAL_TEXT).encode(), junk)
    if roll < 5:
        return Item(pick(stream, (SPACE, OWNED_SPACE)), 0, pick(stream, ("", " ", "x")).encode(), junk)
    if roll < 13:
        return Item(NUMERIC, next(stream) % len(NUMERIC_KINDS), b"", junk)
    if roll < 19:
        return Item(FIXED, pick(stream, IN_DOMAIN_FIXED), b"", junk)
    return Item(ERROR, 0, b"", junk)


def with_presets(stream, case):
    """Pre-set a few record fields to the value this very input would produce, or to a different one."""
    if next(stream) % 3:
        return case
    dry = Spec().run(case)
    state = dry[2]
    pre = []
    for offset in WORD_FIELDS + (F_WEEKDAY,):
        mode = next(stream) % 14
        if mode < 11:
            continue
        if offset == F_WEEKDAY:
            held = state[offset]
            pre.append((offset, bytes((held if mode < 13 and held != 7 else next(stream) % 8,))))
            continue
        flag, value = struct.unpack_from("<II", state, offset)
        wanted = value if flag == 1 and mode < 13 else (next(stream) % 70)
        pre.append((offset, word(1, wanted)))
    if next(stream) % 11 == 0:
        pre.append((0, struct.pack("<QQ", 1, next(stream) % 5)))
    return Case(case.items, case.data, pre)


def main_case(stream):
    count = 1 + next(stream) % 4
    items = [random_item(stream) for _ in range(count)]
    if next(stream) % 5:
        items = [item for item in items if item.tag != ERROR] or items
    data = "".join(text_for(stream, item) for item in items) + pick(stream, TAIL_TEXT)
    case = Case(items, data.encode())
    return with_presets(stream, case)


def single_item_cases(stream):
    """Every numeric and fixed kind against its whole text list, bare and under each pad byte and a preset conflict."""
    for kind in range(len(NUMERIC_KINDS)):
        for text in NUM_TEXT[KIND_TEXT[kind]]:
            for junk in (0, 1, 2):
                item = Item(NUMERIC, kind, b"", junk)
                yield Case((item,), text.encode(), crit=True)
            offset = NUMERIC_KINDS[kind][1]
            if kind == 19:
                yield Case((Item(NUMERIC, kind),), text.encode(), ((0, struct.pack("<QQ", 1, 5)),))
            elif offset == F_WEEKDAY:
                for held in (0, 3, 6):
                    yield Case((Item(NUMERIC, kind),), text.encode(), ((F_WEEKDAY, bytes((held,))),))
            elif kind == 14:
                yield Case((Item(NUMERIC, kind),), text.encode(), ((F_HOUR12, word(1, 1)),))
                yield Case((Item(NUMERIC, kind),), text.encode(), ((F_HOURMOD, word(1, 5)),))
            else:
                for held in (0, 1, 2, 7, 12, 31):
                    yield Case((Item(NUMERIC, kind),), text.encode(), ((offset, word(1, held)),))
                yield Case((Item(NUMERIC, kind),), text.encode(), ((offset, word(1, 3)),))
    for sub in IN_DOMAIN_FIXED:
        for text in NAME_TEXT[sub]:
            for tail in ("", "x", "é", " ", "5"):
                yield Case((Item(FIXED, sub),), (text + tail).encode(), crit=True)
            for field, raw in ((F_MONTH, word(1, 1)), (F_MONTH, word(1, 2)), (F_HOUR12, word(1, 0)), (F_HOUR12, word(1, 1)), (F_NANO, word(1, 5)), (F_NANO, word(1, 500000000)),
                               (F_WEEKDAY, bytes((0,))), (F_WEEKDAY, bytes((6,)))):
                yield Case((Item(FIXED, sub),), text.encode(), ((field, raw),))
    for text in ("", " ", "  x", "　x", "  y", "​x", "x ", " ᚁ", "\u0085z", "  q", " 1", " 　", "  a", "é"):
        for tag in (SPACE, OWNED_SPACE):
            yield Case((Item(tag, 0, b" "),), text.encode(), crit=True)
    for lit in LITERAL_TEXT:
        for text in ("", lit, lit + "x", lit[:1], "x" + lit, "é" if lit == "é" else "q", lit.upper()):
            for tag in (LITERAL, OWNED_LITERAL):
                yield Case((Item(tag, 0, lit.encode()),), text.encode(), crit=True)
    for text in ("", "x", "12"):
        yield Case((Item(ERROR),), text.encode(), crit=True)
        yield Case((Item(NUMERIC, 6), Item(ERROR)), text.encode())
        yield Case((), text.encode(), crit=True)


def raw_cases(scale=1):
    stream = lcg(0x115)
    yield from single_item_cases(stream)
    for _ in range(11000 * scale):
        yield main_case(stream)


def all_cases(scale=1):
    for case in raw_cases(scale):
        if admissible(case):
            yield case


def named_cases():
    """Hand-written item lists shaped like the format strings chrono feeds the interpreter."""
    year, month, day, hour, minute, second = (Item(NUMERIC, k) for k in (0, 6, 7, 14, 16, 17))
    dash, colon, space, tee = (Item(LITERAL, 0, c) for c in (b"-", b":", b" ", b"T"))
    rows = [
        ((year, dash, month, dash, day, tee, hour, colon, minute, colon, second), b"2024-01-02T03:04:05"),
        ((year, dash, month, dash, day, tee, hour, colon, minute, colon, second), b"2024-13-02T03:04:05"),
        ((year, dash, month, dash, day), b"2024-1-2"), ((year, dash, month, dash, day), b"-0001-12-31"), ((year, dash, month, dash, day), b"2024/01/02"),
        ((Item(FIXED, 6), Item(LITERAL, 0, b", "), day, Item(SPACE, 0, b" "), Item(FIXED, 4), Item(SPACE), year), b"Tue, 2 Jan 2024"),
        ((Item(FIXED, 7), Item(SPACE), Item(FIXED, 5), Item(SPACE), day), b"Tuesday January 2"),
        ((hour, colon, minute, Item(FIXED, 10), Item(SPACE), Item(FIXED, 8)), b"11:59.250 PM"),
        ((Item(NUMERIC, 15), Item(FIXED, 9)), b"12pm"), ((Item(NUMERIC, 15), Item(FIXED, 9)), b"12am"), ((Item(NUMERIC, 14), Item(FIXED, 9)), b"13pm"),
        ((Item(NUMERIC, 19),), b"-1700000000"), ((Item(NUMERIC, 19),), b"1700000000"),
        ((Item(FIXED, 1), Item(FIXED, 2)), b"123456789012"), ((Item(FIXED, 3),), b"12345678"),
        ((Item(FIXED, 14), Item(SPACE), Item(LITERAL, 0, b"x")), b"UTC+09:00 x"),
    ]
    out = [Case(items, data) for items, data in rows]
    out.append(Case((year, dash, month), b"2024-02", ((F_YEAR, word(1, 2024)), (F_MONTH, word(1, 2)))))
    out.append(Case((year, dash, month), b"2024-02", ((F_YEAR, word(1, 2023)),)))
    return [case for case in out if admissible(case)]


# ---------------------------------------------------------------- checking

def digest(outcome):
    return hashlib.sha256(repr(outcome).encode()).hexdigest()[:12]


def classify(case, outcome):
    if outcome[0] == "panic":
        return "panic-" + outcome[1], 0
    blob = outcome[1]
    stage = sum(1 for offset in WORD_FIELDS if struct.unpack_from("<I", outcome[2], offset)[0] == 1)
    if blob[0:8] == bytes(8):
        return "err-%d" % blob[8], stage
    return "ok", stage


def check_stream(harness, cases, spec, tally, samples, sample_every, chosen=None, shapes=None):
    """Run each case, compare at once, keep only counts, every `sample_every`-th row and a class-picked subset for the edit controls."""
    count = 0
    taken = {}
    for case in cases:
        got = harness.run(case)
        want = spec.run(case)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.label(), got, want))
        name, stage = classify(case, got)
        first = (case.items[0].tag, case.items[0].sub) if case.items else (9, 0)
        key = (first, name)
        tally[key] = tally.get(key, 0) + 1
        if samples is not None and count % sample_every == 0:
            samples.append((case.label(), name, digest(got)))
        if chosen is not None:
            picked = (first, name, stage, len(case.pre) > 0, min(len(case.data), 2))
            taken[picked] = taken.get(picked, 0) + 1
            if taken[picked] <= 1:
                chosen.append(case)
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


# ---------------------------------------------------------------- evidence tables read from file bytes

def table_targets(image, table, count):
    base = image.offset(table)
    return [(table + struct.unpack_from("<i", image.blob, base + 4 * index)[0]) & U64 for index in range(count)]


def dispatch_rows(image):
    """The four jump tables the interpreter indexes: item tag, numeric kind, fixed kind and internal fixed kind, as relative 32 bit entries."""
    rows = []
    for label, table, count in (("tag", TAG_TABLE, 7), ("numeric-kind", NUMERIC_TABLE, 20), ("fixed-kind", FIXED_TABLE, 19), ("internal-fixed-kind", INTERNAL_TABLE, 4)):
        for index, target in enumerate(table_targets(image, table, count)):
            rows.append((label, index, "%#x" % table, "%#x" % target))
    return rows


def setter_rows(image):
    """For each setter the record offset of its present flag, found as the first `cmp dword [rdi+disp], 1` (or the byte compare against zero in set_hour12)."""
    rows = []
    for target in sorted(SETTERS):
        start, end = image.exact_fde(target)
        blob = bytes(image.blob[image.offset(start):image.offset(end)])
        flag = None
        if blob[:3] == b"\x83\x3f\x01":
            flag = 0
        else:
            hit = re.search(rb"\x83\xbf(....)\x01", blob, re.S)
            if hit:
                flag = struct.unpack("<I", hit.group(1))[0]
            else:
                hit = re.search(rb"\x83\x7f(.)\x01", blob, re.S)
                if hit:
                    flag = hit.group(1)[0]
                else:
                    hit = re.search(rb"\x80\x7f(.)\x00", blob, re.S)  # set_hour12 tests the flag byte against zero
                    if hit:
                        flag = hit.group(1)[0]
        rows.append((SETTERS[target], "%#x" % target, end - start, "-" if flag is None else "%#x" % flag, FIELD_NAMES.get(flag, "-") if flag is not None else "-"))
    return rows


def text_calls(image):
    """(call site, callee, kind) for every direct near call or jump in .text and every call through a slot to one of the bodies, by byte patterns."""
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
        if owner_of(image, site) == INTERNAL and target != INTERNAL or target == INTERNAL:
            rows.append((NAMES[target], "%#x" % target, kind, "%#x" % site, "%#x" % owner_of(image, site)))
    rows.sort(key=lambda row: (row[1], row[3]))
    return rows


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, target in sorted(relative.items()):
        if target in ALL_BODIES:
            rows.append(("%#x" % slot, "%#x" % target, NAMES[target]))
    for slot, label in ((SLOT_RFC2822, "parse_rfc2822 (outside the domain)"), (SLOT_RFC3339, "parse_rfc3339 (outside the domain)")):
        rows.append(("%#x" % slot, "%#x" % relative[slot], label))
    return rows


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
    for target in ALL_BODIES:
        for va, kind, patch in cpu.edits_for(image, rows[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = 9000
            if first_failure(harness, chosen, spec) is not None:
                results.append((NAMES[target], va, kind, "killed", "class-picked subset"))
            else:
                results.append((NAMES[target], va, kind, "survived", "result unchanged on the subset"))
    return results


def spec_mutant_rows(image, cases):
    rows = []
    harness = Harness(image)
    outcomes = [(case, harness.run(case)) for case in cases]
    for name in SPEC_MUTANTS:
        wrong = Spec(frozenset((name,)))
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
    for label, va in (("address inside a function", INTERNAL + 1), ("address before a body", TRIM - 1), ("address in .rodata", 0x459230), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    relative = image.relative()
    rows.append(("the weekday slot holds the weekday scanner and not the month scanner", "detected" if relative.get(SLOT_WEEK) == WEEK and relative.get(SLOT_MONTH) == MONTH else "MISSED"))
    rows.append(("the long month slot holds the long month scanner", "detected" if relative.get(SLOT_LMONTH) == LMONTH and relative.get(SLOT_NANOFIX) == NANOFIX else "MISSED"))
    rows.append(("white space slot against a code address is not a slot to that target", "detected" if relative.get(SLOT_WS_TABLE) != TRIM else "MISSED"))
    sites = {site for site, target, kind in text_calls(image) if target == TRIM and kind == "call"}
    rows.append(("the interpreter's space item calls trim_start from a located call site", "detected" if 0x1620C4D in sites else "MISSED"))
    rows.append(("an address that does not call trim_start is not a call site", "detected" if 0x1620C4E not in sites else "MISSED"))
    targets = table_targets(image, TAG_TABLE, 7)
    rows.append(("the space and owned space tags share one handler", "detected" if targets[2] == targets[3] != targets[0] else "MISSED"))
    harness = Harness(image)
    try:
        harness.run(Case((Item(LITERAL, 0, b"a"),), b"x" * 140000))
        rows.append(("a string that does not fit the evaluator memory is refused", "MISSED"))
    except Halt:
        rows.append(("a string that does not fit the evaluator memory is refused", "detected"))
    try:
        Spec().run(Case((Item(FIXED, 0),), b"+01:00"))
        rows.append(("a time zone offset item is refused as outside the modelled domain", "MISSED"))
    except EvidenceError:
        rows.append(("a time zone offset item is refused as outside the modelled domain", "detected"))
    probe = Case((Item(NUMERIC, 6),), b"12")
    rows.append(("month item result differs from the minute item rule", "detected" if harness.run(probe) != Spec().run(Case((Item(NUMERIC, 16),), b"12")) else "MISSED"))
    return rows


# ---------------------------------------------------------------- driver

def analyse(image, mutate=True):
    harness = Harness(image)
    spec = Spec()
    tally, samples = {}, []
    chosen = []
    named = named_cases()
    total = check_stream(harness, named, spec, tally, samples, 1, chosen)
    chosen.extend(named)
    named_total = total
    total += check_stream(harness, all_cases(), spec, tally, samples, 900, chosen)
    seen = set(harness.machine.seen)
    rows = edit_rows(image)
    result = {"total": total, "named": named_total, "tally": tally, "samples": samples, "seen": seen, "rows": rows, "chosen": len(chosen),
              "callers": caller_rows(image), "slots": slot_rows(image), "dispatch": dispatch_rows(image), "setters": setter_rows(image)}
    if mutate:
        result["byte"] = run_byte_mutants(image, rows, seen, chosen)
        result["spec"] = spec_mutant_rows(image, chosen)
        result["struct"] = structural_rows(image)
    return result


def tsv(header, rows):
    return ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]


def write_lines(path, lines):
    path.write_text("\n".join(lines) + "\n")


def first_name(first):
    tag, sub = first
    if tag == NUMERIC:
        return "Numeric." + NUMERIC_KINDS[sub][0]
    if tag == FIXED:
        return "Fixed." + FIXED_KINDS[sub]
    return {LITERAL: "Literal", OWNED_LITERAL: "OwnedLiteral", SPACE: "Space", OWNED_SPACE: "OwnedSpace", ERROR: "Error", 9: "(no items)"}[tag]


def render(result, image):
    files = {}
    files["functions.tsv"] = render_functions(image, result["rows"])
    files["reach.tsv"] = render_reach(result["rows"], result["seen"])
    files["callers.tsv"] = tsv(("callee", "callee_address", "kind", "call_site", "owner_function"), result["callers"])
    files["slots.tsv"] = tsv(("slot", "relocated_target", "function"), result["slots"])
    files["dispatch-tables.tsv"] = tsv(("table", "index", "table_address", "handler"), result["dispatch"])
    files["setters.tsv"] = tsv(("setter", "address", "size", "present_flag_offset", "field"), result["setters"])
    outcomes = sorted(result["tally"].items(), key=lambda item: (item[0][0], item[0][1]))
    files["outcomes.tsv"] = tsv(("first_item", "outcome", "cases"), [(first_name(first), name, count) for (first, name), count in outcomes])
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
        "edit_subset_cases": result["chosen"],
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
