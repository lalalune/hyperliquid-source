#!/usr/bin/env python3
"""Pin the node #94 ADL shortfall budget (dex field +0x248) from ELF bytes.

The field is named by the binary itself: its serde key and two log messages say
`adl_shortfall_remaining`. This tool finds every immediate of the daily bump and
of the validator cap, then runs the real instruction bytes in a small evaluator.

Each run covers one interval of a u64 input. A value derived from the input is
kept as x+c, and every compare on it cuts the interval exactly where its result
can change. A run that ends without a cut has one path and one output form for
all its inputs, so the union of the intervals is a proof over the whole u64
domain, not a sample. The evaluator stops on any opcode, call or read it does
not know. No disassembler is called and the target is never executed.

Usage: python3 tools/adl_shortfall_budget.py --out <folder>
"""
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import re
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"

BUMP = 50_000_000_000
CAP_MAINNET = 1_000_000_000_000
CAP_OTHER = 5_000_000_000_000
WIRE_LIMIT = 0x0ccccccccccccccc
MAINNET = 3
FIELD_REMAINING = 0x248
FIELD_FEE = 0x250
FIELD_PERFORM = 0x2ec
DEFAULT_FEE = 500_000
TAG_WIRE_LIMIT = 0x13f
TAG_ABOVE_CAP = 0x3d

BUMP_FUNCTIONS = (0x2702330, 0x4ceea90, 0x4ceeb80)
DISPATCHERS = (0x2355f40, 0x4caa870, 0x4cb3200)
CASE_PERFORM, CASE_REMAINING, CASE_FEE = 0x0a, 0x0c, 0x10
TAG_BIAS = 0x12
SLOT_RECORDER = 0x5773190
SLOT_DEX = 0x5773d80
SLOT_UNWRAP_PANIC = 0x576e048
SLOT_OVERFLOW_PANIC = 0x576eb38
FN_DROP_ERROR = 0x3379490
SITE_INIT = 0x370ac37
SITE_POINTER = 0x36f7ccd
SITE_GATE = 0x36f86d9
GATE_LOW = 0x36f87c9
GATE_FALL = 0x36f86ea
SITE_DEBIT = 0x3703874
DEBIT_FALL = 0x37038a6
DEBIT_PANIC = 0x3703c1d
SITE_LOG_ARGS = 0x36f926f
SITE_LOG_TRIGGERED = 0x36f92eb
SITE_LOG_REFUSED = 0x36f936a
LOCATION_TOTAL = 0x5714d30
SLOT_DEBIT_INPUT = 0x57746f0
FN_DISPLAY = 0x37ffd40
FN_DEBIT = 0x36fff10
SITE_DEBIT_DEX = 0x36fff62
SITE_FLAG_DEX = 0x36f7d3b
SITE_FLAG = 0x36fa3bf
NAME = b"adl_shortfall_remaining"
CHAIN_NAMES = b"LocalSandboxTestnetMainnet"

# Exact bytes, each with the reading it carries.
INIT_BYTES = bytes.fromhex("41c686ec02000001" "49c78648020000" "00000000" "49c78650020000" "20a10700")
POINTER_BYTES = bytes.fromhex("488d9648020000" "4889942400050000")
GATE_BYTES = bytes.fromhex("488b8c2400050000" "483b01" "0f82")
DEBIT_BYTES = bytes.fromhex("488b842438030000" "4885c0" "7925" "48f7d8" "0f8093030000"
                            "488b742428" "488b8e48020000" "31d2" "4829c1" "480f43d1" "48899648020000")
LOG_ARGS_BYTES = bytes.fromhex("488d842480020000" "4889842418010000"
                               "488b842400050000" "4889842440030000")
LAYOUTS = ((0x5b8, 0x8f2), (0x1038, 0x1372))
SATURATE = bytes.fromhex("48c7c0ffffffff")
SATURATE_OFFSET = 0x9d
CALLER_COPY = bytes.fromhex("418b4608" "89442428" "498b06" "4889442420" "488d742420" "4c89e7" "e8")
CALLER_AFTER = bytes.fromhex("418b06" "413b442460" "0f8d")
DISPLAY_HEAD = bytes.fromhex("4883ec48" "0fb707" "488d0d")
DISPLAY_JUMP = bytes.fromhex("48630481" "4801c8" "ffe0")
DISPLAY_TEXT_HEAD = bytes.fromhex("488b3e" "488b4608" "488b4018" "488d35")
DEBIT_DEX_ENTRY = bytes.fromhex("4889f3")
DEBIT_DEX_SPILL = bytes.fromhex("48895c2428")
FLAG_DEX_SPILL = bytes.fromhex("4889742470")
FLAG_BYTES = bytes.fromhex("488b442470" "80b8ec02000001")
TEXT_ABOVE_CAP = "Adl shortfall too large"
TEXT_WIRE_LIMIT = "Invalid input number"
SPILL_0X28 = re.compile(rb"[\x48\x4c]\x89[\x44\x4c\x54\x5c\x64\x6c\x74\x7c]\x24\x28")
PROLOGUE = re.compile(rb"\x48\x8d\x45\xee\x48\x83\xfd\x12\xb9\x4e\x00\x00\x00\x48\x0f\x43\xc8"
                      rb"\x48\x89\x3c\x24\x48\x8d\x05(....)\x48\x63\x0c\x88\x48\x01\xc1\xff\xe1", re.S)
LEA = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")

U64 = (1 << 64) - 1
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R12, R13, R14, R15 = 12, 13, 14, 15
CALLER_SAVED = (RAX, RCX, RDX, RSI, RDI, 8, 9, 10, 11)
STACK = 0x6f00_0000
STATE = 0x7000_0000
DEX = 0x7100_0000
ARG = 0x7200_0000
ACTION = 0x7300_0000
OUT = 0x7400_0000
RETURN_MARK = 0x6000_0000
MAX_STEPS = 2000
MAX_PIECES = 5000
EDGES_I64 = (0, 1, 2, 49_999_999_999, 50_000_000_000, (1 << 63) - 1, -1, -2, -50_000_000_000, -(1 << 63) + 1,
             -(1 << 63))
EDGES_U64 = (0, 1, 2, 49_999_999_999, 50_000_000_000, 50_000_000_001, (1 << 63) - 1, 1 << 63, (1 << 63) + 1,
             U64 - 1, U64)
DATE_FIELD = 7
DATE_EDGES = (0, 1, -1, 2, 0x7fffffff, -0x80000000, 0x0fd0_0000)


class ToolError(Exception):
    pass


def fail(message):
    raise ToolError(message)


class Split(Exception):
    """The current interval must be cut before `at`."""

    def __init__(self, at):
        super().__init__(at)
        self.at = at


class Done(Exception):
    def __init__(self, how):
        super().__init__(how)
        self.how = how


class Image:
    """Bytes, loaded sections and FDE extents, from the shared repository parsers."""

    def __init__(self, data, fdes=None):
        self.data = data
        self.sections = [s for s in elf_index.sections(data) if s["type"] != 8 and s["address"]]
        self.text = next(s for s in self.sections if s["name"] == ".text")
        if fdes is None:
            _, records = fde_extents.eh_frame_records(data, elf_index.sections(data))
            fdes = sorted((r["start"], r["end"]) for r in records)
        self.fdes = fdes
        self.starts = [row[0] for row in fdes]
        self.relocs = {}

    def patched(self, edits):
        """A copy with bytes replaced, for negative controls."""
        blob = bytearray(self.data)
        for va, raw in edits:
            off = self.file_offset(va)
            blob[off:off + len(raw)] = raw
        other = Image(bytes(blob), self.fdes)
        other.relocs = self.relocs
        return other

    def file_offset(self, va):
        for s in self.sections:
            if s["address"] <= va < s["address"] + s["size"]:
                return va - s["address"] + s["offset"]
        fail(f"address {va:#x} is outside every section with file bytes")

    def read(self, va, size):
        off = self.file_offset(va)
        return self.data[off:off + size]

    def word(self, va, fmt):
        return struct.unpack_from(fmt, self.data, self.file_offset(va))[0]

    def fde_of(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or not self.fdes[i][0] <= va < self.fdes[i][1]:
            fail(f"{va:#x} is outside every FDE")
        return self.fdes[i]

    def load_relocs(self):
        """RELATIVE relocations by slot address; slots hold their value only here."""
        if self.relocs:
            return self.relocs
        rela = next(s for s in self.sections if s["name"] == ".rela.dyn")
        for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
            where, info, addend = struct.unpack_from("<QQq", self.data, off)
            if info & 0xffffffff == 8:
                self.relocs[where] = addend
        return self.relocs


class V:
    """x+c on the current interval (a == 1), or the constant c (a == 0)."""

    __slots__ = ("a", "c", "v")

    def __init__(self, a, c, v):
        self.a, self.c, self.v = a, c, v


def const(value):
    return V(0, value & U64, value & U64)


COND = {0: lambda f: f[3], 1: lambda f: not f[3], 2: lambda f: f[0], 3: lambda f: not f[0],
        4: lambda f: f[1], 5: lambda f: not f[1], 6: lambda f: f[0] or f[1], 7: lambda f: not (f[0] or f[1]),
        8: lambda f: f[2], 9: lambda f: not f[2], 12: lambda f: f[2] != f[3], 13: lambda f: f[2] == f[3],
        14: lambda f: f[1] or f[2] != f[3], 15: lambda f: not f[1] and f[2] == f[3]}


class Machine:
    """Strict evaluator for one input interval. Unknown values are None."""

    def __init__(self, image, lo=0, hi=0):
        self.image, self.lo, self.hi = image, lo, hi
        self.regs = [None] * 16
        self.regs[RSP] = const(STACK)
        self.mem = {}
        self.flags = None
        self.pc = 0
        self.recorded = []
        self.stop_at = set()
        self.steps = 0

    def input(self):
        return V(1, 0, self.lo)

    def form(self, c):
        c &= U64
        base = (self.lo + c) & U64
        if base + (self.hi - self.lo) > U64:
            raise Split(self.lo + (U64 + 1 - base))
        return V(1, c, base)

    def cross(self, value, points):
        """Cut the interval where the value reaches any of the points."""
        if value is None or not value.a:
            return
        cuts = []
        for point in points:
            if point > value.v:
                at = self.lo + point - value.v
                if at <= self.hi:
                    cuts.append(at)
        if cuts:
            raise Split(min(cuts))

    def narrow(self, value, bits):
        if value is None or bits == 64:
            return value
        mask = (1 << bits) - 1
        if not value.a:
            return const(value.v & mask)
        if value.c or value.v + self.hi - self.lo > mask:
            fail(f"input value does not fit {bits} bits at {self.pc:#x}")
        return value

    def load(self, at, size):
        slot = self.mem.get(at)
        if slot is None or slot[0] != size:
            fail(f"read of {size} bytes at {at:#x} that nothing wrote, from {self.pc:#x}")
        return slot[1]

    def store(self, at, size, value):
        self.mem[at] = (size, value)

    def modrm(self, p, rex):
        data = self.image.data
        modrm = data[p]
        p += 1
        mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) | ((rex & 4) << 1), modrm & 7
        rexb = (rex & 1) << 3
        if mod == 3:
            return ("r", rm | rexb), reg, p
        base, disp = None, 0
        if rm == 4:
            sib = data[p]
            p += 1
            if sib != 0x24:
                fail(f"unhandled SIB at {self.pc:#x}")
            base = RSP
        elif mod == 0 and rm == 5:
            disp = struct.unpack_from("<i", data, p)[0]
            return ("rip", disp), reg, p + 4
        else:
            base = rm | rexb
        if mod == 1:
            disp = struct.unpack_from("<b", data, p)[0]
            p += 1
        elif mod == 2:
            disp = struct.unpack_from("<i", data, p)[0]
            p += 4
        return ("m", base, disp), reg, p

    def address(self, operand):
        if operand[0] == "m":
            base = self.regs[operand[1]]
            if base is None or base.a:
                fail(f"address through an unknown register at {self.pc:#x}")
            return (base.v + operand[2]) & U64
        fail(f"unexpected operand at {self.pc:#x}")

    def get(self, operand, bits):
        if operand[0] == "r":
            return self.narrow(self.regs[operand[1]], bits)
        return self.load(self.address(operand), bits // 8)

    def put(self, operand, bits, value):
        if operand[0] == "r":
            if bits < 32:
                fail(f"partial register write at {self.pc:#x}")
            self.regs[operand[1]] = self.narrow(value, bits)
        else:
            self.store(self.address(operand), bits // 8, value)

    def set_flags(self, left, right, result, bits, subtract):
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        res = result & mask
        carry = left < right if subtract else left + right > mask
        if subtract:
            over = bool((left ^ right) & (left ^ res) & sign)
        else:
            over = bool(~(left ^ right) & (left ^ res) & sign)
        self.flags = (carry, res == 0, bool(res & sign), over)

    def compare(self, left, right, bits):
        if left is None or right is None:
            fail(f"compare on an unknown value at {self.pc:#x}")
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        if left.a and right.a:
            fail(f"compare of two input forms at {self.pc:#x}")
        if left.a:
            self.cross(left, [right.v, right.v + 1, sign, (right.v + sign) & mask])
        elif right.a:
            self.cross(right, [left.v, left.v + 1, sign, (left.v + sign) & mask, ((left.v + sign) & mask) + 1])
        self.set_flags(left.v, right.v, left.v - right.v, bits, True)

    def add(self, left, right, bits):
        if bits != 64 or left is None or right is None or (left.a and right.a):
            fail(f"unhandled add at {self.pc:#x}")
        if left.a or right.a:
            one, other = (left, right) if left.a else (right, left)
            self.cross(one, [(U64 + 1 - other.v) & U64, (1 << 63) - other.v & U64])
            total = self.form(other.v + one.c)
        else:
            total = const(left.v + right.v)
        self.set_flags(left.v, right.v, left.v + right.v, bits, False)
        return total

    def sub(self, left, right, bits):
        self.compare(left, right, bits)
        if left.a:
            return self.form(left.c - right.v)
        if right.a:
            fail(f"constant minus input at {self.pc:#x}")
        return const((left.v - right.v) & ((1 << bits) - 1))

    def logic(self, value, bits):
        """Flags of xor, or test with itself."""
        if value is None:
            fail(f"logic flags on an unknown value at {self.pc:#x}")
        sign = 1 << (bits - 1)
        self.cross(value, [1, sign])
        self.flags = (False, value.v == 0, bool(value.v & sign), False)

    def call(self, target, ret):
        stub = self.stubs.get(target)
        if stub is not None:
            stub(self)
            self.pc = ret
            return
        if target not in self.follow:
            fail(f"call to unmodelled {target:#x} at {self.pc:#x}")
        self.push(const(ret))
        self.pc = target

    def push(self, value):
        self.regs[RSP] = const(self.regs[RSP].v - 8)
        self.store(self.regs[RSP].v, 8, value)

    def pop(self):
        value = self.load(self.regs[RSP].v, 8)
        self.regs[RSP] = const(self.regs[RSP].v + 8)
        return value

    def poison(self):
        for reg in CALLER_SAVED:
            self.regs[reg] = None
        self.flags = None

    def run(self):
        while True:
            if self.pc in self.stop_at:
                raise Done(f"stop {self.pc:#x}")
            self.steps += 1
            if self.steps > MAX_STEPS:
                fail(f"too many steps at {self.pc:#x}")
            self.step()

    def step(self):
        va = self.pc
        data = self.image.data
        delta = self.image.text["offset"] - self.image.text["address"]
        p = va + delta
        if not self.image.text["address"] <= va < self.image.text["address"] + self.image.text["size"]:
            fail(f"fetch outside .text at {va:#x}")
        wide16 = data[p] == 0x66
        p += wide16
        rex = 0
        if 0x40 <= data[p] <= 0x4f:
            rex = data[p]
            p += 1
        op = data[p]
        p += 1
        bits = 64 if rex & 8 else 16 if wide16 else 32

        def after(q):
            return q - delta

        if 0x50 <= op <= 0x57:
            self.push(self.regs[(op & 7) | ((rex & 1) << 3)])
            self.pc = after(p)
        elif 0x58 <= op <= 0x5f:
            self.regs[(op & 7) | ((rex & 1) << 3)] = self.pop()
            self.pc = after(p)
        elif op in (0x81, 0x83, 0x80):
            operand, reg, p = self.modrm(p, rex)
            if op == 0x81:
                imm = struct.unpack_from("<i", data, p)[0]
                p += 4
            else:
                imm = struct.unpack_from("<b", data, p)[0]
                p += 1
            width = 8 if op == 0x80 else bits
            if operand == ("r", 5) and width == 8 and not rex:
                fail(f"legacy high byte register at {va:#x}")
            mask = (1 << width) - 1
            left, right = self.get(operand, width), const(imm & mask)
            kind = reg & 7
            if kind == 7:
                self.compare(left, right, width)
            elif kind == 0 and width == 64:
                self.put(operand, width, self.add(left, right, width))
            elif kind == 5 and width == 64:
                self.put(operand, width, self.sub(left, right, width))
            else:
                fail(f"unhandled group 1 at {va:#x}")
            self.pc = after(p)
        elif op == 0x8b:
            operand, reg, p = self.modrm(p, rex)
            self.put(("r", reg), bits, self.get(operand, bits))
            self.pc = after(p)
        elif op == 0x89:
            operand, reg, p = self.modrm(p, rex)
            self.put(operand, bits, self.narrow(self.regs[reg], bits))
            self.pc = after(p)
        elif op == 0x88:
            operand, reg, p = self.modrm(p, rex)
            if operand[0] == "r" or (reg in (4, 5, 6, 7) and not rex):
                fail(f"unhandled byte move at {va:#x}")
            self.put(operand, 8, self.narrow(self.regs[reg], 8))
            self.pc = after(p)
        elif op == 0x8d:
            operand, reg, p = self.modrm(p, rex)
            if operand[0] == "rip":
                value = const(after(p) + operand[1])
            else:
                value = const(self.address(operand))
            self.put(("r", reg), bits, value)
            self.pc = after(p)
        elif op == 0xc7:
            operand, reg, p = self.modrm(p, rex)
            if reg & 7:
                fail(f"unhandled group 11 at {va:#x}")
            if wide16:
                imm = struct.unpack_from("<H", data, p)[0]
                p += 2
            else:
                imm = struct.unpack_from("<i", data, p)[0]
                p += 4
            self.put(operand, bits, const(imm & ((1 << bits) - 1)))
            self.pc = after(p)
        elif 0xb8 <= op <= 0xbf:
            reg = (op & 7) | ((rex & 1) << 3)
            if rex & 8:
                imm = struct.unpack_from("<Q", data, p)[0]
                p += 8
            else:
                imm = struct.unpack_from("<I", data, p)[0]
                p += 4
            self.regs[reg] = const(imm)
            self.pc = after(p)
        elif op in (0x03, 0x01, 0x2b, 0x29, 0x3b, 0x39):
            operand, reg, p = self.modrm(p, rex)
            if op in (0x03, 0x2b, 0x3b):
                left, right = self.get(("r", reg), bits), self.get(operand, bits)
                dest = ("r", reg)
            else:
                left, right = self.get(operand, bits), self.get(("r", reg), bits)
                dest = operand
            if op in (0x3b, 0x39):
                self.compare(left, right, bits)
            elif op in (0x03, 0x01):
                self.put(dest, bits, self.add(left, right, bits))
            else:
                self.put(dest, bits, self.sub(left, right, bits))
            self.pc = after(p)
        elif op in (0x31, 0x33):
            operand, reg, p = self.modrm(p, rex)
            if operand != ("r", reg):
                fail(f"xor of two registers at {va:#x}")
            self.put(operand, bits, const(0))
            self.flags = (False, True, False, False)
            self.pc = after(p)
        elif op == 0x85:
            operand, reg, p = self.modrm(p, rex)
            if operand != ("r", reg):
                fail(f"test of two registers at {va:#x}")
            self.logic(self.get(operand, bits), bits)
            self.pc = after(p)
        elif op == 0xf7:
            operand, reg, p = self.modrm(p, rex)
            value = self.get(operand, bits)
            if reg & 7 != 3 or value is None or value.a:
                fail(f"unhandled group 3 at {va:#x}")
            self.set_flags(0, value.v, -value.v, bits, True)
            self.put(operand, bits, const(-value.v))
            self.pc = after(p)
        elif op == 0x69:
            operand, reg, p = self.modrm(p, rex)
            imm = struct.unpack_from("<i", data, p)[0]
            p += 4
            value = self.get(operand, bits)
            if value is None or value.a:
                fail(f"unhandled imul at {va:#x}")
            self.flags = None
            self.put(("r", reg), bits, const(value.v * imm))
            self.pc = after(p)
        elif 0x70 <= op <= 0x7f:
            rel = struct.unpack_from("<b", data, p)[0]
            self.branch(op & 15, after(p + 1), rel)
        elif op == 0xe9:
            self.leave(after(p + 4) + struct.unpack_from("<i", data, p)[0])
        elif op == 0xeb:
            self.leave(after(p + 1) + struct.unpack_from("<b", data, p)[0])
        elif op == 0xe8:
            ret = after(p + 4)
            self.call(ret + struct.unpack_from("<i", data, p)[0], ret)
        elif op == 0xff:
            operand, reg, p = self.modrm(p, rex)
            if reg & 7 != 2 or operand[0] != "rip":
                fail(f"unhandled indirect call at {va:#x}")
            ret = after(p)
            self.indirect(ret + operand[1], ret)
        elif op == 0xc3:
            target = self.pop()
            if target is None or target.a:
                fail(f"return to an unknown address at {va:#x}")
            if target.v == RETURN_MARK:
                raise Done("ret")
            self.pc = target.v
        elif op == 0x90:
            self.pc = after(p)
        elif op == 0x0f:
            two = data[p]
            p += 1
            if 0x80 <= two <= 0x8f:
                rel = struct.unpack_from("<i", data, p)[0]
                self.branch(two & 15, after(p + 4), rel)
            elif 0x40 <= two <= 0x4f:
                operand, reg, p = self.modrm(p, rex)
                if self.flags is None or two & 15 not in COND:
                    fail(f"unhandled cmov at {va:#x}")
                source = self.get(operand, bits)
                if bits != 64:
                    fail(f"unhandled cmov width at {va:#x}")
                if COND[two & 15](self.flags):
                    self.regs[reg] = source
                self.pc = after(p)
            elif two == 0xb6:
                operand, reg, p = self.modrm(p, rex)
                if operand[0] != "m":
                    fail(f"unhandled movzx at {va:#x}")
                self.put(("r", reg), bits, self.get(operand, 8))
                self.pc = after(p)
            else:
                fail(f"unknown opcode 0f {two:02x} at {va:#x}")
        else:
            fail(f"unknown opcode {op:02x} at {va:#x}")

    def leave(self, target):
        """A case block ends at its first jump; a function follows its own."""
        if self.jump_ends:
            raise Done(f"jmp {target:#x}")
        self.pc = target

    def branch(self, cc, fall, rel):
        if self.flags is None or cc not in COND:
            fail(f"unhandled branch at {self.pc:#x}")
        self.pc = fall + rel if COND[cc](self.flags) else fall

    def indirect(self, slot, ret):
        stub = self.slots.get(slot)
        if stub is not None:
            stub(self)
            self.pc = ret
            return
        relocs = self.image.load_relocs()
        if slot not in relocs:
            fail(f"slot {slot:#x} has no relocation")
        self.call(relocs[slot], ret)

    stubs = {}
    slots = {}
    follow = ()
    jump_ends = False


def record(machine):
    if machine.regs[RDI] is None or machine.regs[RDI].v or machine.regs[RSI] is None:
        fail(f"recorder arguments at {machine.pc:#x}")
    machine.recorded.append(machine.regs[RSI].v)
    machine.poison()


def drop(machine):
    machine.poison()


def panic(machine):
    raise Done("panic")


def show(value):
    """Output form as text, with x the input."""
    if value is None:
        return "unknown"
    if not value.a:
        return str(value.v)
    if value.c == 0:
        return "x"
    if value.c < 1 << 63:
        return f"x+{value.c}"
    return f"x-{(1 << 64) - value.c}"


def refine(run, lo, hi):
    """All pieces of [lo, hi]; adjacent pieces with one outcome are merged."""
    pieces, stack, runs = [], [(lo, hi)], 0
    while stack:
        a, b = stack.pop()
        runs += 1
        if runs > MAX_PIECES:
            fail("too many pieces")
        try:
            outcome = run(a, b)
        except Split as cut:
            if not a < cut.at <= b:
                fail(f"cut {cut.at:#x} outside [{a:#x}, {b:#x}]")
            stack.append((cut.at, b))
            stack.append((a, cut.at - 1))
            continue
        if pieces and pieces[-1][2] == outcome and pieces[-1][1] + 1 == a:
            pieces[-1] = (pieces[-1][0], b, outcome)
        else:
            pieces.append((a, b, outcome))
    return pieces


def apply(form, x):
    """Value of a shown form at x."""
    if form == "x":
        return x
    if form.startswith("x+"):
        return (x + int(form[2:])) & U64
    if form.startswith("x-"):
        return (x - int(form[2:])) & U64
    return int(form)


def bump_layout(image, fn):
    """The three state offsets are read from the bytes of each copy."""
    code = image.read(fn, 0x30)
    if code[0x0d:0x10] != b"\x48\x83\xbf" or code[0x1b:0x1e] != b"\x0f\xb6\xaf" or code[0x22:0x25] != b"\x48\x8b\x9f":
        fail(f"{fn:#x} does not start like a bump")
    length = struct.unpack_from("<i", code, 0x10)[0]
    mode = struct.unpack_from("<i", code, 0x1e)[0]
    pointer = struct.unpack_from("<i", code, 0x25)[0]
    if length != pointer + 8:
        fail(f"{fn:#x}: length and pointer are not one vector")
    if (pointer - 8, mode) not in LAYOUTS:
        fail(f"{fn:#x}: unknown state layout")
    return {"vec": pointer - 8, "mode": mode}


def bump_machine(image, fn, layout, mode, lo, hi, x, date_a, date_b, count=1):
    machine = Machine(image, lo, hi)
    machine.stubs = {FN_DROP_ERROR: drop}
    machine.slots = {SLOT_RECORDER: record, SLOT_UNWRAP_PANIC: panic}
    machine.regs[RDI] = const(STATE)
    machine.regs[RSI] = const(ARG)
    machine.store(ARG, 4, date_a if isinstance(date_a, V) else const(date_a & 0xffffffff))
    machine.store(STATE + 0x60, 4, const(date_b & 0xffffffff))
    machine.store(STATE + layout["vec"] + 8, 8, const(DEX))
    machine.store(STATE + layout["vec"] + 0x10, 8, const(count))
    machine.store(STATE + layout["mode"], 1, const(mode))
    machine.store(DEX + FIELD_REMAINING, 8, x if isinstance(x, V) else const(x))
    machine.push(const(RETURN_MARK))
    machine.pc = fn
    return machine


def finish(machine):
    """Run to the end and describe the result."""
    try:
        machine.run()
    except Done as end:
        how = end.how
    else:
        fail("evaluator stopped without an exit")
    field = machine.mem.get(DEX + FIELD_REMAINING)
    return how, show(field[1]) if field else "unset", tuple(machine.recorded)


def bump_pieces(image, fn, mode):
    layout = bump_layout(image, fn)

    def run(lo, hi):
        machine = Machine(image, lo, hi)
        machine = bump_machine(image, fn, layout, mode, lo, hi, machine.input(), 0, 1)
        return finish(machine)

    return refine(run, 0, U64)


def date_pieces(image, fn, date_b):
    """Bump or skip over all 2^32 date words, for one state word."""
    layout = bump_layout(image, fn)

    def run(lo, hi):
        machine = Machine(image, lo, hi)
        machine = bump_machine(image, fn, layout, 0, lo, hi, DATE_FIELD, machine.input(), date_b)
        return finish(machine)

    return refine(run, 0, 0xffffffff)


def expected_bump(mode):
    cap = CAP_MAINNET if mode == MAINNET else CAP_OTHER
    limit = U64 + 1 - BUMP
    return [(0, cap - BUMP, ("ret", f"x+{BUMP}", ())),
            (cap - BUMP + 1, limit - 1, ("ret", str(cap), ())),
            (limit, U64, ("ret", str(cap), "recorded"))]


def check_bump(rows, mode, fn):
    want = expected_bump(mode)
    if len(rows) != 3:
        fail(f"{fn:#x} mode {mode}: {len(rows)} pieces")
    for row, model in zip(rows, want):
        if row[:2] != model[:2] or row[2][:2] != model[2][:2] or bool(row[2][2]) != bool(model[2][2]):
            fail(f"{fn:#x} mode {mode}: piece {row} differs from the model")
        if len(row[2][2]) > 1:
            fail(f"{fn:#x}: more than one recorder call")


def check_date(rows, fn, date_b):
    """Signed: the bump runs exactly when date_a < date_b."""
    b = date_b & 0xffffffff
    runs = [(row[0], row[1], row[2][1] == str(DATE_FIELD + BUMP)) for row in rows]
    for lo, hi, bumped in runs:
        for a in (lo, hi):
            signed = a - (1 << 32) if a >> 31 else a
            if bumped != (signed < date_b):
                fail(f"{fn:#x}: date word {a:#x} against {b:#x}")


def dispatch_block(image, dispatcher, case):
    """Jump table entry of one normalized tag, from the dispatcher's own prologue."""
    fde = image.fde_of(dispatcher)
    if fde[0] != dispatcher:
        fail(f"{dispatcher:#x} is not an FDE start")
    code = image.read(dispatcher, 0x60)
    match = PROLOGUE.search(code)
    if match is None:
        fail(f"{dispatcher:#x} has no tag dispatch")
    lea_end = dispatcher + match.start(1) + 4
    table = lea_end + struct.unpack("<i", match.group(1))[0]
    block = table + image.word(table + 4 * case, "<i")
    if not fde[0] <= block < fde[1]:
        fail(f"case {case:#x} of {dispatcher:#x} leaves the FDE")
    return table, block


def setter_machine(image, block, lo, hi, payload, size, mode_offset, mode, vec_offset=0x5b8, count=1):
    machine = Machine(image, lo, hi)
    machine.stubs = {FN_DROP_ERROR: drop}
    machine.slots = {SLOT_RECORDER: record, SLOT_UNWRAP_PANIC: panic}
    machine.follow = (image.load_relocs().get(SLOT_DEX),)
    machine.jump_ends = True
    machine.regs[R15] = const(ACTION)
    machine.regs[R13] = const(STATE)
    machine.regs[RDX] = const(STATE)
    machine.store(STACK, 8, const(OUT))
    machine.store(ACTION + 8, size, payload)
    machine.store(STATE + mode_offset, 1, const(mode))
    machine.store(STATE + vec_offset + 8, 8, const(DEX))
    machine.store(STATE + vec_offset + 0x10, 8, const(count))
    machine.pc = block
    return machine


def setter_result(machine, field=FIELD_REMAINING):
    try:
        machine.run()
    except Done as end:
        how = end.how
    else:
        fail("evaluator stopped without an exit")
    slot = machine.mem.get(DEX + field)
    tag = machine.mem.get(OUT)
    value = machine.mem.get(OUT + 8)
    return (how, show(slot[1]) if slot else "unset", hex(tag[1].v) if tag else "none",
            show(value[1]) if value else "none")


def setter_layout(image, dispatcher):
    """State offsets of one dispatcher, read from its case 0xc bytes."""
    _, block = dispatch_block(image, dispatcher, CASE_REMAINING)
    code = image.read(block, 0x16)
    match = re.match(rb"\x49\x8b\x5f\x08(?:\x41\x0f\xb6\xad|\x0f\xb6\xaa)(....)(?:\x49\x81\xc5|\x48\x81\xc2)(....)",
                     code, re.S)
    if match is None:
        fail(f"case block {block:#x} has an unknown shape")
    mode, vec = struct.unpack("<i", match.group(1))[0], struct.unpack("<i", match.group(2))[0]
    if (vec, mode) not in LAYOUTS:
        fail(f"case block {block:#x}: unknown state layout")
    return {"mode": mode, "vec": vec, "block": block}


def setter_pieces(image, dispatcher, mode):
    layout = setter_layout(image, dispatcher)

    def run(lo, hi):
        machine = Machine(image, lo, hi)
        payload = machine.input()
        machine = setter_machine(image, layout["block"], lo, hi, payload, 8, layout["mode"], mode, layout["vec"])
        return setter_result(machine)

    return refine(run, 0, U64)


def expected_setter(mode):
    cap = CAP_MAINNET if mode == MAINNET else CAP_OTHER
    return [(0, cap, ("x", "none", "none")),
            (cap + 1, WIRE_LIMIT - 1, ("unset", hex(TAG_ABOVE_CAP), "none")),
            (WIRE_LIMIT, U64, ("unset", hex(TAG_WIRE_LIMIT), "x"))]


def without_exit(rows):
    return [(lo, hi, outcome[1:]) for lo, hi, outcome in rows]


def fee_pieces(image, dispatcher):
    """Neighbour case 0x10: same dex, field +0x250, wire limit and no cap."""
    _, block = dispatch_block(image, dispatcher, CASE_FEE)
    layout = setter_layout(image, dispatcher)

    def run(lo, hi):
        machine = Machine(image, lo, hi)
        payload = machine.input()
        machine = setter_machine(image, block, lo, hi, payload, 8, layout["mode"], 0, layout["vec"])
        return setter_result(machine, FIELD_FEE)

    return refine(run, 0, U64)


def perform_row(image, dispatcher, flag):
    """Neighbour case 0xa: a byte stored to dex +0x2ec."""
    _, block = dispatch_block(image, dispatcher, CASE_PERFORM)
    layout = setter_layout(image, dispatcher)
    machine = setter_machine(image, block, 0, 0, const(flag), 1, layout["mode"], 0, layout["vec"])
    return setter_result(machine, FIELD_PERFORM)


def debit_run(image, x, budget):
    """Real bytes of the debit, from the read of x to the store."""
    machine = Machine(image)
    machine.slots = {SLOT_OVERFLOW_PANIC: panic}
    machine.store(STACK + 0x338, 8, const(x))
    machine.store(STACK + 0x28, 8, const(DEX))
    machine.store(DEX + FIELD_REMAINING, 8, const(budget))
    machine.stop_at = {DEBIT_FALL, DEBIT_PANIC}
    machine.pc = SITE_DEBIT
    try:
        machine.run()
    except Done as end:
        how = "panic" if end.how == f"stop {DEBIT_PANIC:#x}" else "next"
    return how, machine.mem[DEX + FIELD_REMAINING][1].v


def debit_model(x, budget):
    if x >= 0:
        return "next", budget
    if x == -(1 << 63):
        return "panic", budget
    return "next", max(budget + x, 0)


def gate_run(image, total, budget):
    machine = Machine(image)
    machine.regs[RAX] = const(total)
    machine.store(STACK + 0x500, 8, const(DEX + FIELD_REMAINING))
    machine.store(DEX + FIELD_REMAINING, 8, const(budget))
    machine.stop_at = {GATE_LOW, GATE_FALL}
    machine.pc = SITE_GATE
    try:
        machine.run()
    except Done as end:
        return "skip" if end.how == f"stop {GATE_LOW:#x}" else "collect"
    fail("gate did not stop")


def display_text(image, tag):
    """Text of one error tag, from the jump table of its Display function."""
    head = image.read(FN_DISPLAY, 23)
    if head[:10] != DISPLAY_HEAD or head[14:] != DISPLAY_JUMP:
        fail("error Display has an unknown shape")
    table = FN_DISPLAY + 14 + struct.unpack_from("<i", head, 10)[0]
    block = table + image.word(table + 4 * tag, "<i")
    code = image.read(block, 23)
    if code[:14] != DISPLAY_TEXT_HEAD or code[18] != 0xba:
        fail(f"error tag {tag:#x} is not a plain string arm")
    target = block + 18 + struct.unpack_from("<i", code, 14)[0]
    size = struct.unpack_from("<I", code, 19)[0]
    return block, target, image.read(target, size).decode()


def direct_callers(image, targets):
    """Every E8 of .text whose target is in `targets`, by target."""
    text = image.data[image.text["offset"]:image.text["offset"] + image.text["size"]]
    base = image.text["address"]
    rows = {target: [] for target in targets}
    for match in re.finditer(rb"\xe8", text):
        at = match.start()
        if at + 5 > len(text):
            break
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in rows:
            rows[target].append(base + at)
    return rows


def relative_lea_sites(image, wanted):
    """Every RIP-relative 64-bit LEA of .text whose target is in `wanted`."""
    text = image.data[image.text["offset"]:image.text["offset"] + image.text["size"]]
    base = image.text["address"]
    rows = []
    for match in LEA.finditer(text):
        at = match.start()
        if at + 7 > len(text):
            break
        target = base + at + 7 + struct.unpack_from("<i", text, at + 3)[0]
        if target in wanted:
            rows.append((base + at, target))
    return rows


def all_offsets(image, needle):
    """Addresses of a byte string in every loaded section with file bytes."""
    rows = []
    for s in image.sections:
        body = image.data[s["offset"]:s["offset"] + s["size"]]
        rows += [(s["name"], s["address"] + m.start()) for m in re.finditer(re.escape(needle), body)]
    return rows


def field_rows(image):
    """Serde key sites of the field, classified by the instruction before them."""
    copies = [va for name, va in all_offsets(image, NAME) if name != ".text"]
    rows = []
    for site, target in relative_lea_sites(image, set(copies)):
        before = image.read(site - 7, 7)
        if before == bytes.fromhex("4d8b8748020000"):
            kind = "value_read_0x248"
        elif before == bytes.fromhex("488d8b48020000"):
            kind = "size_pass_0x248"
        else:
            kind = "other"
        rows.append((site, image.fde_of(site)[0], target, kind))
    return copies, rows


def location(image, record_va):
    """Rust Location record: file pointer, length, line, column. Path is cut to l1/src."""
    pointer = image.load_relocs().get(record_va)
    if pointer is None:
        fail(f"no relocation for Location {record_va:#x}")
    length = image.word(record_va + 8, "<Q")
    line = image.word(record_va + 16, "<I")
    column = image.word(record_va + 20, "<I")
    path = image.read(pointer, length).decode()
    cut = path.find("l1/src/")
    if cut < 0:
        fail(f"unexpected Location path at {record_va:#x}")
    return f"{path[cut:]}:{line}:{column}"


def field_store_count(image):
    """64-bit register stores with displacement 0x248 anywhere in .text, of any type."""
    text = image.data[image.text["offset"]:image.text["offset"] + image.text["size"]]
    pattern = rb"[\x48\x49\x4c\x4d]\x89[\x80-\xbf]\x48\x02\x00\x00"
    return sum(1 for m in re.finditer(pattern, text) if text[m.start() + 2] & 7 != 4)


def format_pieces(image, va):
    """Literal pieces of a Rust format string, stored as length byte then text."""
    pieces, p = [], va
    while True:
        size = image.read(p, 1)[0]
        if size == 0:
            return pieces
        if size == 0xc0:
            p += 1
            continue
        pieces.append(image.read(p + 1, size).decode())
        p += 1 + size


def safe_text(pieces):
    """Log text for evidence files, with the at sign written as [at]."""
    return [piece.replace(chr(64), "[at]") for piece in pieces]


def hex_row(value):
    return f"{value:#x}"


def constant_census(image):
    rows = []
    for name, value in (("bump", BUMP), ("cap_other", CAP_OTHER), ("cap_mainnet", CAP_MAINNET)):
        for section, va in all_offsets(image, struct.pack("<Q", value)):
            fn = image.fde_of(va)[0] if section == ".text" else None
            rows.append((name, value, section, va, fn))
    return rows


def static_checks(image):
    """Byte facts that need no evaluator run."""
    callers = direct_callers(image, BUMP_FUNCTIONS)
    caller_rows = []
    for fn in BUMP_FUNCTIONS:
        if image.read(fn + SATURATE_OFFSET, len(SATURATE)) != SATURATE:
            fail(f"{fn:#x} does not saturate to u64::MAX")
        if len(callers[fn]) != 1:
            fail(f"{fn:#x} has {len(callers[fn])} direct callers")
        site = callers[fn][0]
        if image.read(site - len(CALLER_COPY) + 1, len(CALLER_COPY)) != CALLER_COPY:
            fail(f"caller {site:#x} does not copy the 12-byte argument")
        if image.read(site + 5, len(CALLER_AFTER)) != CALLER_AFTER:
            fail(f"caller {site:#x} has no repeated date guard")
        caller_rows.append((fn, site, image.fde_of(site)[0]))
    if image.read(SITE_INIT - 8, len(INIT_BYTES)) != INIT_BYTES:
        fail("initializer bytes differ")
    if image.read(SITE_POINTER, len(POINTER_BYTES)) != POINTER_BYTES:
        fail("gate pointer bytes differ")
    if image.read(SITE_GATE, len(GATE_BYTES)) != GATE_BYTES:
        fail("gate bytes differ")
    if image.read(SITE_DEBIT, len(DEBIT_BYTES)) != DEBIT_BYTES:
        fail("debit bytes differ")
    if image.read(SITE_LOG_ARGS, len(LOG_ARGS_BYTES)) != LOG_ARGS_BYTES:
        fail("log argument bytes differ")
    if image.read(FN_DEBIT + 44, 3) != DEBIT_DEX_ENTRY or image.read(SITE_DEBIT_DEX, 5) != DEBIT_DEX_SPILL:
        fail("debit dex pointer bytes differ")
    fde = image.fde_of(FN_DEBIT)
    if fde[0] != FN_DEBIT or not fde[0] <= SITE_DEBIT < fde[1]:
        fail("debit site is outside its FDE")
    spills = [m.start() for m in SPILL_0X28.finditer(image.read(fde[0], fde[1] - fde[0]))]
    if spills != [SITE_DEBIT_DEX - fde[0]]:
        fail(f"slot 0x28 has other register writes: {spills}")
    if image.read(SITE_FLAG_DEX, 5) != FLAG_DEX_SPILL or image.read(SITE_FLAG, len(FLAG_BYTES)) != FLAG_BYTES:
        fail("flag gate bytes differ")
    texts = {tag: display_text(image, tag) for tag in (TAG_ABOVE_CAP, TAG_WIRE_LIMIT)}
    if texts[TAG_ABOVE_CAP][2] != TEXT_ABOVE_CAP or texts[TAG_WIRE_LIMIT][2] != TEXT_WIRE_LIMIT:
        fail(f"error texts differ: {texts}")
    return caller_rows, texts


def analyse(image):
    """Every claim of the packet. Raises ToolError when any one fails."""
    out = {}
    caller_rows, texts = static_checks(image)
    census = constant_census(image)
    bump_fns = sorted({r[4] for r in census if r[0] == "bump" and r[2] == ".text"})
    if tuple(bump_fns) != BUMP_FUNCTIONS or sum(r[0] == "bump" for r in census) != 3:
        fail(f"bump immediate sites differ: {bump_fns}")
    text_caps = sorted({r[4] for r in census if r[0] == "cap_other" and r[2] == ".text"})
    if tuple(sorted(BUMP_FUNCTIONS + DISPATCHERS)) != tuple(text_caps):
        fail(f"cap immediate sites differ: {text_caps}")
    for fn in BUMP_FUNCTIONS:
        if image.fde_of(fn)[0] != fn:
            fail(f"{fn:#x} is not an FDE start")
    bump_rows, date_rows, setter_rows, fee_rows, perform_rows = [], [], [], [], []
    recorded = set()
    for fn in BUMP_FUNCTIONS:
        by_class = {}
        for mode in range(256):
            rows = bump_pieces(image, fn, mode)
            check_bump(rows, mode, fn)
            by_class.setdefault("byte_3" if mode == MAINNET else "other", set()).add(tuple(rows))
        if any(len(group) != 1 for group in by_class.values()) or len(by_class) != 2:
            fail(f"{fn:#x}: chain bytes other than {MAINNET} differ")
        for name, group in sorted(by_class.items()):
            for lo, hi, outcome in next(iter(group)):
                bump_rows.append((fn, bump_layout(image, fn)["mode"], name, lo, hi, *outcome))
                recorded.update(outcome[2])
        for date_b in DATE_EDGES:
            rows = date_pieces(image, fn, date_b)
            check_date(rows, fn, date_b)
            for lo, hi, outcome in rows:
                date_rows.append((fn, date_b & 0xffffffff, lo, hi, "bumped" if outcome[1] == str(DATE_FIELD + BUMP) else "unchanged"))
        layout = bump_layout(image, fn)
        machine = bump_machine(image, fn, layout, 0, 0, 0, DATE_FIELD, 0, 1, count=0)
        if finish(machine)[0] != "panic":
            fail(f"{fn:#x}: an empty vector did not reach the unwrap panic")
    tables = []
    for dispatcher in DISPATCHERS:
        table, block = dispatch_block(image, dispatcher, CASE_REMAINING)
        layout = setter_layout(image, dispatcher)
        tables.append((dispatcher, table, block, layout["mode"], layout["vec"]))
        groups = {}
        for mode in range(256):
            rows = setter_pieces(image, dispatcher, mode)
            if without_exit(rows) != expected_setter(mode):
                fail(f"setter {dispatcher:#x} mode {mode}: {rows}")
            groups.setdefault("byte_3" if mode == MAINNET else "other", set()).add(tuple(rows))
        for name, group in sorted(groups.items()):
            if len(group) != 1:
                fail(f"setter {dispatcher:#x}: chain bytes other than {MAINNET} differ")
            for lo, hi, outcome in next(iter(group)):
                setter_rows.append((dispatcher, block, name, lo, hi, *outcome))
        machine = setter_machine(image, block, 0, 0, const(0), 8, layout["mode"], 0, layout["vec"], count=0)
        if setter_result(machine)[0] != "panic":
            fail(f"setter {dispatcher:#x}: an empty vector did not reach the unwrap panic")
        fee = fee_pieces(image, dispatcher)
        if without_exit(fee) != [(0, WIRE_LIMIT - 1, ("x", "none", "none")),
                                 (WIRE_LIMIT, U64, ("unset", hex(TAG_WIRE_LIMIT), "x"))]:
            fail(f"fee case of {dispatcher:#x}: {fee}")
        fee_rows.append((dispatcher, dispatch_block(image, dispatcher, CASE_FEE)[1], len(fee)))
        for flag in (0, 1, 255):
            result = perform_row(image, dispatcher, flag)
            if result[1] != str(flag):
                fail(f"case 0xa of {dispatcher:#x}: {result}")
            stored = next(iter(group))[0][2][0]
            refused = next(iter(group))[1][2][0]
            if result[0] != stored or fee[0][2][0] != stored or fee[1][2][0] != refused:
                fail(f"case exits of {dispatcher:#x} differ")
        perform_rows.append((dispatcher, dispatch_block(image, dispatcher, CASE_PERFORM)[1]))
    debit_rows = []
    for x in EDGES_I64:
        for budget in EDGES_U64:
            got = debit_run(image, x & U64, budget)
            if got != debit_model(x, budget):
                fail(f"debit x={x} budget={budget}: {got}")
            debit_rows.append((x, budget, *got))
    gate_rows = []
    for total in EDGES_U64:
        for budget in EDGES_U64:
            got = gate_run(image, total, budget)
            if (got == "skip") != (total < budget):
                fail(f"gate total={total} budget={budget}: {got}")
            gate_rows.append((total, budget, got))
    copies, sites = field_rows(image)
    kinds = collections.Counter(row[3] for row in sites)
    if kinds["value_read_0x248"] != 6 or kinds["size_pass_0x248"] != 3:
        fail(f"field sites differ: {kinds}")
    triggered = image.fde_of(SITE_LOG_TRIGGERED)[0]
    if image.fde_of(SITE_GATE)[0] != triggered or image.fde_of(SITE_LOG_REFUSED)[0] != triggered:
        fail("gate and log sites are not in one FDE")
    leas = {}
    for site, target in relative_lea_sites(image, {0x1e5653, 0x1eacfe}):
        leas.setdefault(target, []).append(site)
    if leas.get(0x1e5653) != [SITE_LOG_TRIGGERED] or leas.get(0x1eacfe) != [SITE_LOG_REFUSED]:
        fail(f"log string sites differ: {leas}")
    chain = all_offsets(image, CHAIN_NAMES)
    if not chain:
        fail("chain variant names are absent")
    if len(recorded) != 1:
        fail(f"recorder Locations differ: {recorded}")
    out.update(census=census, bump_rows=bump_rows, date_rows=date_rows, setter_rows=setter_rows, fee_rows=fee_rows,
               perform_rows=perform_rows, tables=tables, debit_rows=debit_rows, gate_rows=gate_rows, sites=sites,
               copies=copies, kinds=kinds, caller_rows=caller_rows, texts=texts,
               total_location=location(image, LOCATION_TOTAL), field_stores=field_store_count(image),
               debit_helper=image.load_relocs()[SLOT_DEBIT_INPUT], chain=chain, recorder=location(image, recorded.pop()),
               triggered=format_pieces(image, 0x1e5653), refused=format_pieces(image, 0x1eacfe),
               debit_fde=image.fde_of(SITE_DEBIT), gate_fde=image.fde_of(SITE_GATE), init_fde=image.fde_of(SITE_INIT))
    return out


def tsv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\t".join(header) + "\n")
        for row in rows:
            handle.write("\t".join(str(cell) for cell in row) + "\n")


def write_evidence(result, out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    tsv(out / "bump-pieces.tsv", ("function", "chain_byte_offset", "chain_class", "x_lo", "x_hi", "exit", "new_value",
                                  "recorder_calls"),
        [(hex_row(r[0]), hex_row(r[1]), r[2], r[3], r[4], r[5], r[6], len(r[7])) for r in result["bump_rows"]])
    tsv(out / "date-guard.tsv", ("function", "state_word", "arg_word_lo", "arg_word_hi", "field"),
        [(hex_row(r[0]), hex_row(r[1]), hex_row(r[2]), hex_row(r[3]), r[4]) for r in result["date_rows"]])
    tsv(out / "setter-pieces.tsv", ("dispatcher", "case_block", "chain_class", "x_lo", "x_hi", "exit", "new_value",
                                    "error_tag", "error_payload"),
        [(hex_row(r[0]), hex_row(r[1]), *r[2:]) for r in result["setter_rows"]])
    tsv(out / "debit-grid.tsv", ("x_i64", "budget", "exit", "new_budget"), result["debit_rows"])
    tsv(out / "gate-grid.tsv", ("total_shortfall", "budget", "result"), result["gate_rows"])
    tsv(out / "field-sites.tsv", ("lea", "fde_start", "string", "kind"),
        [(hex_row(r[0]), hex_row(r[1]), hex_row(r[2]), r[3]) for r in result["sites"]])
    tsv(out / "constant-sites.tsv", ("name", "value", "section", "va", "fde_start"),
        [(r[0], r[1], r[2], hex_row(r[3]), "" if r[4] is None else hex_row(r[4])) for r in result["census"]])
    summary = {
        "target_sha256": SHA256,
        "coordinate_system": "ELF virtual addresses of node #94",
        "field": {"register_stores_with_displacement_0x248": result["field_stores"],
                  "offset_in_dex": hex_row(FIELD_REMAINING), "serde_key": NAME.decode(),
                  "key_copies": [hex_row(va) for va in result["copies"]], "key_site_kinds": dict(sorted(result["kinds"].items())),
                  "initial_value": 0, "initializer_site": hex_row(SITE_INIT), "initializer_fde": hex_row(result["init_fde"][0]),
                  "neighbour_initial_values": {"bridge2_withdraw_fee": DEFAULT_FEE, "perform_auto_deleveraging": 1}},
        "bump": {"functions": [hex_row(fn) for fn in BUMP_FUNCTIONS], "amount": BUMP,
                 "cap_chain_byte_3": CAP_MAINNET, "cap_other_chain_bytes": CAP_OTHER,
                 "overflow_threshold": U64 + 1 - BUMP, "overflow_location": result["recorder"],
                 "chain_bytes_tested": 256, "date_state_words_tested": len(DATE_EDGES),
                 "bumps_from_zero_to_cap": {"chain_byte_3": CAP_MAINNET // BUMP, "other": CAP_OTHER // BUMP},
                 "direct_callers": [{"function": hex_row(r[0]), "call": hex_row(r[1]), "caller_fde": hex_row(r[2])}
                                    for r in result["caller_rows"]]},
        "setter": {"raw_tag": hex_row(CASE_REMAINING + TAG_BIAS), "normalized_case": hex_row(CASE_REMAINING),
                   "dispatchers": [{"function": hex_row(t[0]), "jump_table": hex_row(t[1]), "case_block": hex_row(t[2]),
                                    "chain_byte_offset": hex_row(t[3]), "dex_vector_offset": hex_row(t[4])}
                                   for t in result["tables"]],
                   "wire_limit": WIRE_LIMIT, "tag_at_or_above_wire_limit": hex_row(TAG_WIRE_LIMIT),
                   "tag_above_cap": hex_row(TAG_ABOVE_CAP), "chain_bytes_tested": 256,
                   "error_text": {hex_row(tag): {"display_arm": hex_row(row[0]), "string": hex_row(row[1]), "text": row[2]}
                                  for tag, row in sorted(result["texts"].items())},
                   "neighbour_cases": {"0x0a_stores_dex_0x2ec": [hex_row(r[1]) for r in result["perform_rows"]],
                                       "0x10_stores_dex_0x250": [hex_row(r[1]) for r in result["fee_rows"]]}},
        "gate": {"total_add_location": result["total_location"], "site": hex_row(SITE_GATE), "fde": hex_row(result["gate_fde"][0]), "skip_target": hex_row(GATE_LOW),
                 "fall_through": hex_row(GATE_FALL), "vectors": len(result["gate_rows"]),
                 "log_triggered_site": hex_row(SITE_LOG_TRIGGERED), "log_triggered_pieces": safe_text(result["triggered"]),
                 "log_refused_site": hex_row(SITE_LOG_REFUSED), "log_refused_pieces": safe_text(result["refused"])},
        "debit": {"input_slot": hex_row(SLOT_DEBIT_INPUT), "input_function": hex_row(result["debit_helper"]),
                  "site": hex_row(SITE_DEBIT), "fde": hex_row(result["debit_fde"][0]),
                  "panic_target": hex_row(DEBIT_PANIC), "vectors": len(result["debit_rows"])},
        "chain_variant_names": [[name, hex_row(va)] for name, va in result["chain"]],
        "counts": {"bump_pieces": len(result["bump_rows"]), "date_pieces": len(result["date_rows"]),
                   "setter_pieces": len(result["setter_rows"]), "field_key_sites": len(result["sites"]),
                   "constant_sites": len(result["census"])},
    }
    with open(out / "summary.json", "w", encoding="utf-8", newline="\n") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")


def load_target():
    data = TARGET.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        fail(f"target hash {digest} is not {SHA256}")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        image = Image(load_target())
        write_evidence(analyse(image), args.out)
    except ToolError as problem:
        sys.exit(f"adl_shortfall_budget: {problem}")


if __name__ == "__main__":
    main()
