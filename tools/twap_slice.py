#!/usr/bin/env python3
"""Pin the node #94 TWAP step from ELF bytes: drain, slice size and limit price, reschedule, heap order.

A heap of (order id, due time, user) records drives TWAP orders. Four drains (`0x42f1500` family) pop
every due record, four slice functions (`0x4339480` family, two perp and two spot) turn one record
into an order, and four advance functions (`0x42eef80` family) move the record 30 s on or finish it.
The real bytes of all twelve, the heap push `0x44c1900`, the heap pop `0x44c0fe0` and the rounding
helpers run in a Python evaluator with only the edges stubbed, and a separately written specification
predicts every event and every record byte. Every condition, immediate and field offset is then
flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never
executed. Standard library only.
"""

import argparse
import bisect
import fractions
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

# One row per copy: drain, its collector, slice, advance, family, perp field offsets.
PERP, SPOT = "perp", "spot"
COPIES = (
    dict(drain=0x42F1500, collect=0x47F7FD0, slice=0x4339480, advance=0x42EEF80, family=PERP, markets=0x1040, count=0x1048),
    dict(drain=0x42F18C0, collect=0x47F7520, slice=0x4338210, advance=0x42F0AF0, family=PERP, markets=0x5C0, count=0x5C8),
    dict(drain=0x42F2040, collect=0x47F6C30, slice=0x4336B90, advance=0x42F0240, family=SPOT),
    dict(drain=0x42F1C80, collect=0x47F5C90, slice=0x43377C0, advance=0x42EF990, family=SPOT),
)
OTHER_ADVANCE_CALLERS = (0x42ED300, 0x42EE6E0, 0x42ECA60, 0x42EDCF0)
HEAP_PUSH = 0x44C1900
HEAP_POP = 0x44C0FE0
PERP_TOP = 0x3C18B70
PERP_TICK = 0x42C7600
SPOT_TICK = 0x4CA6B90
DROP_ERROR = 0x3379490
ROUND = 0x565F410
CEIL = 0x565F670
FLOOR = 0x565F6F0
FMA = 0x565F8C0
FMA_POINTER = 0x57882E8
SLOT_ROUND = 0x576F6D8
SLOT_FMA = 0x576F6E0
SLOT_FLOOR = 0x5774E18
SLOT_CEIL = 0x57747C8
SLOT_SPOT_MID = 0x5774E10
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_TIME_SUB = 0x576E8C0
SLOT_DATE_SECS = 0x576EFB8
SLOT_RECORDER = 0x5773190
SLOT_ASSERT = 0x576E108
SLOT_EXPECT = 0x576E468
SLOT_FREE = 0x576E010
SLOT_PANIC_INDEX = 0x576DFC8
SLOT_UNWRAP = 0x576E048
SLOT_ONCE = 0x576E8B8
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_GROW_ROWS = 0x57747D0
SLOT_GROW_HEAP = 0x57747D8
SLOT_GROW_PERP = 0x5773D58
SLOT_GROW_SPOT = 0x5773D50
ONCE_STATE = 0x577AB98
ONCE_VALUE = 0x577AB80
ONCE_VTABLE = 0x5669F68
ONCE_LOCATION = 0x5669F50
LOCATION_MARKET = 0x56E9AE0
LOCATION_BOOKS = 0x56DFDA8
LOCATION_SZ = 0x571C990
LOCATION_DURATION_A = 0x566ADF8
LOCATION_DURATION_B = 0x566AB58
LOCATION_CHRONO = 0x566AF18
TIME_FILE = 0x5B9765
TIME_FILE_SIZE = 0x2B
TIME_LINE_WORD = 0x5400000001
ASSERT_A = 0x219F59
ASSERT_A_SIZE = 0x1E
ASSERT_B = 0x219D71
ASSERT_B_SIZE = 0x1C
EXPECT_TEXT = 0x21A01F
EXPECT_SIZE = 0x26
UNWRAP_TEXT = 0x58C079
UNWRAP_SIZE = 0x2B
ERROR_WORD = 0x141
FAILED_WORD = 0xCE
DIVISOR = 10000
MARKET_STRIDE = 0x2F0
BOOK_STRIDE = 0xD8
BOOK_TOP_FIELD = 0x80
SPOT_MID_FIELD = 0x80
SPOT_TICK_FIELD = 0x90
SPOT_CONVERT_FIELD = 0x90
STEP_SECONDS = 30
BUCKET_SECONDS = 60.0
FLOAT_CONSTANTS = {"buckets_divisor_60": 0x20ABF8, "buy_factor": 0x20A770, "sell_factor": 0x20AC58, "jitter_divisor": 0x20A960,
                   "jitter_offset": 0x20A470, "step_30": 0x20A1A0}
THRESHOLDS = {PERP: dict(whole=30000000, floor=12000000), SPOT: dict(whole=3000000000, floor=1200000000)}
JITTER_MODULUS = 40
CATCH_UP = 3
SIG_FIGS = 5
ENTRY_SIZE = 0x28
ROW_SIZE = 0x20
SLICE_SIZE = 0x70
RECORD_SIZE = {PERP: 0x278, SPOT: 0x268}
FINISH_WORD = 0x8000000000000002
RECORD_TAG = 4

CONVERT = {PERP: 0x46CA710, SPOT: 0x46CA2B0}
ORDER_REMOVE = {PERP: 0x49432C0, SPOT: 0x4944230}
USER_REMOVE = {PERP: 0x4944610, SPOT: 0x49463E0}
USER_DROP = {PERP: 0x494B020, SPOT: 0x49B7AD0}
USER_ENTRY = {PERP: 0x495B000, SPOT: 0x495A910}
DROP_FAILED = 0x4344430

# B-tree node shapes: keys, key stride, parent, parent index, length, edges, values, value stride.
USER_NODE = dict(keys=0x110, stride=20, parent=0, index=0x1EC, length=0x1EE, edges=0x1F0, size=0x1F0 + 12 * 8,
                 values=8, value_stride=0x18)
ORDER_NODE = dict(keys=0x428, stride=8, parent=0x420, index=0x480, length=0x482, edges=0x488, size=0x488 + 12 * 8,
                  values=0, value_stride=0x60)

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 300000
MUTANT_STEP_LIMIT = 8000
FAKE_MEMCMP = 0x7E000000



class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Image:
    """Section, relocation and FDE views of one ELF byte string, through the shared parsers."""

    def __init__(self, blob):
        self.blob = blob
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        for row in fdes:
            ends[row["start"]] = max(ends.get(row["start"], 0), row["end"])
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va):
        for section in self.mapped:
            if section["address"] <= va < section["address"] + section["size"]:
                return va - section["address"] + section["offset"]
        raise EvidenceError("address outside file-backed sections: %#x" % va)

    def fde(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or va >= self.fde_ends[self.starts[index]]:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return self.starts[index], self.fde_ends[self.starts[index]]

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        return start, end

    def text_bytes(self):
        text = self.named[".text"]
        return text["address"], bytes(self.blob[text["offset"]:text["offset"] + text["size"]])

    def relocations(self):
        """Yield (slot, type, addend, symbol index) for .rela.dyn."""
        rela = self.named[".rela.dyn"]
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/base/", "/chrono-"):
            if marker in path:
                path = path[path.rindex(marker) + 1:]
                break
        return path, line, column


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte != 0x2E:
            break
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    wide = bool(rex & 8)
    width = 8 if wide else (2 if opsize else 4)
    byte = window[pos]
    pos += 1
    imm = None
    rip_at = None

    def modrm(vector=False):
        nonlocal pos, rip_at
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("x" if vector else "r", rm | ((rex & 1) << 3))
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            if index == 4:
                index = None
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", window, pos)[0]
                pos += 4
                return reg, ("m", base, index, scale, disp, False)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2 or rip:
            if rip:
                rip_at = pos
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base, index, scale, disp, rip)

    def immediate(size):
        nonlocal pos, imm
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
        imm = (pos, size)
        pos += size
        return value

    def finish(op, a=None, b=None, w=None, cc=None, target=None):
        size = pos
        if (width if w is None else w) == 1 and not rex:
            for operand in (a, b):
                if operand and operand[0] == "r" and 4 <= operand[1] <= 7:
                    raise EvidenceError("high byte register at %#x" % va)

        def fix(operand):
            if operand and operand[0] == "m" and operand[5]:
                return ("m", None, None, 1, va + size + operand[4], False)
            return operand
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm, rip_at)

    if 0x50 <= byte <= 0x57:
        return finish("push", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if 0x58 <= byte <= 0x5F:
        return finish("pop", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if byte < 0x40 and byte & 7 < 4:
        name = GROUP1[byte >> 3]
        w = 1 if not byte & 1 else width
        reg, rm = modrm()
        if byte & 2:
            return finish(name, ("r", reg), rm, w)
        return finish(name, rm, ("r", reg), w)
    if byte < 0x40 and byte & 7 in (4, 5):
        w = 1 if byte & 7 == 4 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish(GROUP1[byte >> 3], ("r", RAX), ("i", value), w)
    if byte == 0x63 and wide:
        reg, rm = modrm()
        return finish("movsxd", ("r", reg), rm, 8)
    if 0x70 <= byte <= 0x7F:
        rel = immediate(1)
        return finish("jcc", cc=byte & 15, target=va + pos + rel)
    if byte in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if byte == 0x80 else width
        value = immediate(4 if byte == 0x81 and w != 2 else 2 if byte == 0x81 else 1)
        return finish(GROUP1[reg & 7], rm, ("i", value), w)
    if byte in (0x84, 0x85):
        reg, rm = modrm()
        return finish("test", rm, ("r", reg), 1 if byte == 0x84 else width)
    if byte in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if not byte & 1 else width
        if byte & 2:
            return finish("mov", ("r", reg), rm, w)
        return finish("mov", rm, ("r", reg), w)
    if byte == 0x8D:
        reg, rm = modrm()
        return finish("lea", ("r", reg), rm, width)
    if byte == 0x90:
        return finish("nop")
    if byte == 0x98 and wide:
        return finish("cdqe")
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 2 if opsize else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0x6B:
        reg, rm = modrm()
        value = immediate(1)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0xD3:
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), width)
    if byte in (0xD1, 0xD0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("i", 1), 1 if byte == 0xD0 else width)
    if byte in (0xC1, 0xC0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        value = immediate(1) & 0xFF
        return finish(SHIFTS[reg & 7], rm, ("i", value), 1 if byte == 0xC0 else width)
    if byte == 0xC3:
        return finish("ret")
    if byte in (0xC6, 0xC7):
        reg, rm = modrm()
        w = 1 if byte == 0xC6 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish("mov", rm, ("i", value & MASK[w]), w)
    if byte == 0xE8:
        rel = immediate(4)
        return finish("call", target=va + pos + rel)
    if byte == 0xE9:
        rel = immediate(4)
        return finish("jmp", target=va + pos + rel)
    if byte == 0xEB:
        rel = immediate(1)
        return finish("jmp", target=va + pos + rel)
    if byte in (0xF6, 0xF7):
        reg, rm = modrm()
        w = 1 if byte == 0xF6 else width
        kind = reg & 7
        if kind == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
        if kind in (2, 3, 4, 5, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x7E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", rm, ("x", reg), 8)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two in (0xB6, 0xB7):
            reg, rm = modrm()
            return finish("movzx", ("r", reg), rm, width, cc=1 if two == 0xB6 else 2)
    raise EvidenceError("undecodable opcode %#x at %#x" % (byte, va))


def decode_range(image, start, end):
    """Decode [start, end) linearly; the last instruction must end exactly at end."""
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va < end:
        row = decode(read, va)
        rows.append(row)
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran FDE end at %#x" % end)
    return rows


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.fresh = (bytes([STACK_MARK]) * STACK_SIZE, bytes([STACK_MARK]) * HEAP_SIZE)
        self.statics = {}

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        return None, 0

    def read(self, addr, count):
        return int.from_bytes(self.bytes_at(addr, count), "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = (value & MASK.get(count, (1 << (8 * count)) - 1)).to_bytes(count, "little")

    def put_bytes(self, addr, data):
        buffer, at = self.locate(addr, len(data))
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + len(data)] = data

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            offset = self.image.offset(addr)
        except EvidenceError:
            raise Halt("read outside every mapping: %#x" % addr)
        return bytes(self.image.blob[offset:offset + count])

    def copy(self, dst, src, count):
        self.put_bytes(dst, self.bytes_at(src, count))

class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False
        self.keep_float = False
        self.step_limit = STEP_LIMIT

    def read_code(self, va, count):
        offset = self.image.offset(va)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data

    def address(self, operand):
        _, base, index, scale, disp, _ = operand
        value = disp
        if base is not None:
            value += self.regs[base]
        if index is not None:
            value += self.regs[index] * scale
        return value & MASK[8]

    def get(self, operand, width):
        kind = operand[0]
        if kind == "r":
            return self.regs[operand[1]] & MASK[width]
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "r":
            reg = operand[1]
            if width >= 4:
                self.regs[reg] = value
            else:
                self.regs[reg] = (self.regs[reg] & ~MASK[width]) | value
        else:
            self.memory.write(self.address(operand), width, value)

    def condition(self, code):
        result = {
            0: self.of, 1: self.cf, 2: self.zf, 3: self.cf or self.zf, 4: self.sf,
            5: self.pf, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        return bool(result) != bool(code & 1)

    def set_logic(self, result, width):
        self.cf = self.of = False
        self.zf = result & MASK[width] == 0
        self.sf = bool(result & SIGN[width])

    def add_sub(self, left, right, carry, width, subtract):
        mask = MASK[width]
        if subtract:
            result = (left - right - carry) & mask
            self.cf = left < right + carry
            self.of = bool((left ^ right) & (left ^ result) & SIGN[width])
        else:
            total = left + right + carry
            result = total & mask
            self.cf = total > mask
            self.of = bool(~(left ^ right) & (left ^ result) & SIGN[width])
        self.zf = result == 0
        self.sf = bool(result & SIGN[width])
        return result

    def push(self, value):
        self.regs[RSP] -= 8
        self.memory.write(self.regs[RSP], 8, value)

    def pop(self):
        value = self.memory.read(self.regs[RSP], 8)
        self.regs[RSP] += 8
        return value

    def stub(self, hook):
        self.keep_rdx = self.keep_float = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        kept = self.xmm[0]
        self.xmm = [POISON | POISON << 64] * 16
        if self.keep_float:
            self.xmm[0] = kept

    def run(self, entry, args):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def step(self, row):
        op = row.op
        width = row.width
        if op == "mov":
            self.put(row.a, width, self.get(row.b, width))
        elif op == "jcc":
            return row.target if self.condition(row.cc) else row.next
        elif op == "lea":
            self.put(row.a, width, self.address(row.b))
        elif op == "push":
            self.push(self.regs[row.a[1]])
        elif op == "pop":
            self.regs[row.a[1]] = self.pop()
        elif op in ("add", "adc", "sub", "sbb", "cmp"):
            carry = int(self.cf) if op in ("adc", "sbb") else 0
            result = self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in ("add", "adc"))
            if op != "cmp":
                self.put(row.a, width, result)
        elif op in ("and", "or", "xor", "test"):
            left, right = self.get(row.a, width), self.get(row.b, width)
            result = left & right if op in ("and", "test") else left | right if op == "or" else left ^ right
            self.set_logic(result, width)
            if op != "test":
                self.put(row.a, width, result)
        elif op == "call":
            self.push(row.next)
            if row.target in self.real:
                return row.target
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            right = self.get(row.a, 8)
            right = right - (1 << 64) if right & SIGN[8] else right
            product = (left * right) & ((1 << 128) - 1)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
        elif op == "jmp":
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.stub(hook)
        elif op == "ret":
            return self.pop()
        elif op == "movzx":
            self.put(row.a, width, self.get(row.b, row.cc))
        elif op == "set":
            self.put(row.a, 1, int(self.condition(row.cc)))
        elif op == "cmov":
            value = self.get(row.b, width)
            self.put(row.a, width, value if self.condition(row.cc) else self.get(row.a, width))
        elif op in ("inc", "dec"):
            carry = self.cf
            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == "dec")
            self.cf = carry
            self.put(row.a, width, value)
        elif op == "neg":
            value = self.add_sub(0, self.get(row.a, width), 0, width, True)
            self.put(row.a, width, value)
        elif op == "not":
            self.put(row.a, width, ~self.get(row.a, width))
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
                result = value << count
            elif op == "shr":
                result = value >> count
            else:
                result = (value - (1 << (8 * width)) if value & SIGN[width] else value) >> count
            if count:
                self.set_logic(result, width)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.vector(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "movsxd":
            value = self.get(row.b, 4)
            self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)
        else:
            self.step_vector(row, op)
        return row.next

    def low(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]] & MASK[8]
        return self.memory.read(self.address(operand), 8)

    def set_low(self, register, bits):
        self.xmm[register] = (self.xmm[register] & ~MASK[8]) | bits

    def step_vector(self, row, op):
        if op == "movsd":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.set_low(row.a[1], self.low(row.b))
                else:
                    self.xmm[row.a[1]] = self.low(row.b)
            else:
                self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "movq":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.low(row.b) if row.b[0] != "r" else self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "divsd":
                result = left / right if right else math.copysign(math.inf, left) * math.copysign(1.0, right) if left == left and left else math.nan
            elif op == "minsd":
                result = left if left < right else right
            else:
                result = left if left > right else right
            self.set_low(row.a[1], to_bits(result))
        elif op == "ucomisd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            unordered = left != left or right != right
            self.of = self.sf = False
            self.pf = unordered
            self.zf = unordered or left == right
            self.cf = unordered or left < right
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


# ---- specification ----

def lcg(variant):
    """A small fixed generator so the sampled cases are the same on every run."""
    state = (variant * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 16


def user_id(number):
    return bytes((number * 37 + index * 11 + 5) & 0xFF for index in range(20))


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


def pack_date(year, ordinal, flags=0):
    return ((year << 13) | (ordinal << 4) | flags) & MASK[4]


def time_key(moment):
    return signed32(moment[0]), moment[1] & MASK[4], moment[2] & MASK[4]


def time_bytes(moment):
    return struct.pack("<III", *(value & MASK[4] for value in moment))


def days_from_ce(date):
    """Days from the Unix epoch for chrono's packed date: year above bit 13, ordinal in bits 4..12."""
    packed = signed32(date)
    year = packed >> 13
    ordinal = (packed >> 4) & 0x1FF
    shift = 0
    last = year - 1
    if last < 0:
        cycles = (-last) // 400 + 1
        last += cycles * 400
        shift = -cycles * 146097
    return ordinal + shift + last * 365 + last // 4 - last // 100 + last // 400 - 719163


def unix_millis(moment):
    return days_from_ce(moment[0]) * 86400 * 1000 + moment[1] * 1000 + moment[2] // 1000000


def saturate(value):
    """f64 to u64: NaN and infinities give 0, negatives 0, values above the top u64::MAX."""
    if value != value or value in (math.inf, -math.inf) or value <= 0.0:
        return 0
    return MASK[8] if value >= 18446744073709551616.0 else int(value)


def duration_steps(duration):
    """2 * (duration / 60) + 1, saturating; only a negative or NaN duration trips the assertion."""
    if duration != duration or duration < 0.0:
        return None
    buckets = saturate(duration / BUCKET_SECONDS)
    return MASK[8] if buckets >= 1 << 63 else 2 * buckets + 1


def round_half_away(value):
    whole = float(math.floor(abs(value))) if abs(value) < 4503599627370496.0 else abs(value)
    if abs(value) - whole >= 0.5:
        whole += 1.0
    return math.copysign(whole, value)


def fused(left, right, extra):
    exact = fractions.Fraction(left) * fractions.Fraction(right) + fractions.Fraction(extra)
    return float(exact) if exact else 0.0


def five_figures(size):
    unit = 1
    while size >= unit * 10 ** SIG_FIGS:
        unit *= 10
    return size // unit * unit


class Order:
    """One 0x60-byte TWAP value. Fields not named stay a ramp, so a wrong field read shows."""

    def __init__(self, asset=20003, total=1000000, duration=3600.0, side=0, reduce_only=0, randomize=0, executed=0, counter=7,
                 due=None, owner=None, raw_duration=None):
        self.asset, self.total, self.duration, self.side = asset, total, duration, side
        self.reduce_only, self.randomize, self.executed, self.counter = reduce_only, randomize, executed, counter
        self.due = due or (pack_date(2025, 100), 3600, 500)
        self.owner = owner
        self.raw_duration = raw_duration

    def body(self, user):
        out = bytearray((index * 13 + 0x31) & 0xFF for index in range(0x60))
        bits = self.raw_duration if self.raw_duration is not None else to_bits(self.duration)
        struct.pack_into("<QQQ", out, 0, self.asset, self.total, bits)
        out[0x20], out[0x21], out[0x22] = self.side, self.reduce_only, self.randomize
        struct.pack_into("<Q", out, 0x28, self.executed)
        struct.pack_into("<Q", out, 0x38, self.counter)
        out[0x40:0x4C] = time_bytes(self.due)
        out[0x4C:0x60] = self.owner or user_id(user)
        return bytes(out)


class SliceCase:
    def __init__(self, label, order=None, oid=5, user=1, others=(), orders=(), now=None, flag=0, once=0, top=(1000000, 1000200), mid=1000100,
                 tick=100, markets=3, books=5, width=11, users_missing=False, order_missing=False, **fields):
        self.label, self.order = label, order or Order(**fields)
        self.oid, self.user, self.others, self.orders = oid, user, tuple(others), tuple(orders)
        self.now = now or (pack_date(2025, 100), 3600, 123456789)
        self.flag, self.once, self.top, self.mid, self.tick = flag, once, top, mid, tick
        self.markets, self.books, self.width = markets, books, width
        self.users_missing, self.order_missing = users_missing, order_missing


def advance_call(copy, case):
    return ("advance", TRACKER, case.order.owner or user_id(case.user), case.oid, OUTER, VECTOR)


def spec_slice(copy, case):
    """Expected events and result of one slice call."""
    row = COPIES[copy]
    order = case.order
    if case.users_missing or case.order_missing:
        return {"events": [], "tag": 2}
    steps = duration_steps(order.duration if order.raw_duration is None else to_float(order.raw_duration))
    if steps is None:
        return {"events": [], "stop": ("assert", ASSERT_A, ASSERT_A_SIZE, LOCATION_DURATION_A)}
    events = []
    once = ("once", ONCE_STATE, 1, ONCE_VTABLE, ONCE_LOCATION, ONCE_VALUE)
    if case.flag:
        return {"events": ([once] if case.once else []) + [advance_call(copy, case)], "tag": 2}
    asset = order.asset
    dex, local = asset // DIVISOR, asset % DIVISOR
    if row["family"] == PERP:
        if dex >= case.markets:
            return {"events": [], "stop": ("unwrap", LOCATION_MARKET, ERROR_WORD, UNWRAP_SIZE)}
        events.append(("drop", ERROR_WORD))
        if local >= case.books:
            return {"events": events, "stop": ("index", local, case.books, LOCATION_BOOKS)}
        events.append(("top", BOOKS + local * BOOK_STRIDE + BOOK_TOP_FIELD))
        first, second = case.top
        mid = (first & second) + ((first ^ second) >> 1)
        if not first or not second:
            return {"events": events + [advance_call(copy, case)], "tag": 2}
    else:
        events.append(("mid", OUTER + SPOT_MID_FIELD, asset, COLLECTION))
        mid = case.mid
        if not mid:
            return {"events": events + [advance_call(copy, case)], "tag": 2}
    factor = 0.97 if order.side else 1.03
    priced = max(round_half_away(factor * float(mid)), 0.0)
    limit = max(saturate(priced), 1)
    if row["family"] == PERP:
        events.append(("tick", MARKETS + dex * MARKET_STRIDE, asset, limit))
    else:
        events.append(("tick", OUTER + SPOT_TICK_FIELD, asset, limit))
    units = limit // case.tick
    if order.side:
        units = min(units + 1, MASK[8])
    price = units * case.tick
    price = max(MASK[8] if price > MASK[8] else price, 1)
    total, executed, counter = order.total, order.executed, order.counter
    ratio = float(total) / float(steps)
    if counter == steps:
        target = total
    else:
        if order.randomize:
            jitter = max(unix_millis(case.now), 0) % JITTER_MODULUS / 100.0 + -0.2
            value = fused(ratio, float(counter), jitter * ratio)
        else:
            value = float(counter) * ratio
        target = saturate(math.floor(value) if value == value and abs(value) != math.inf else value)
    if target < executed:
        return {"events": events + [advance_call(copy, case)], "tag": 2}
    want = target - executed
    remaining = total - executed
    if remaining < 0:
        events.append(("recorder", LOCATION_SZ))
        remaining = 0
    size = remaining
    limits = THRESHOLDS[row["family"]]
    if price * remaining > limits["whole"]:
        floor = limits["floor"] // price if price <= limits["floor"] else 0
        want = max(want, floor)
        cap = saturate(ratio)
        cap = MASK[8] if cap * CATCH_UP >= MASK[8] else cap * CATCH_UP + 1
        size = min(cap, want)
        left = total - executed
        if left < 0:
            events.append(("recorder", LOCATION_SZ))
            left = 0
        size = min(size, left)
        if counter < steps:
            size = five_figures(size)
    if not size:
        return {"events": events + [advance_call(copy, case)], "tag": 2}
    fields = {0: struct.pack("<Q", 1), 8: struct.pack("<Q", size), 0x10: b"\x03", 0x19: b"\x02", 0x20: struct.pack("<Q", price),
              0x28: struct.pack("<Q", asset), 0x30: bytes((order.side, order.reduce_only, 0)), 0x48: struct.pack("<Q", asset),
              0x50: struct.pack("<Q", case.oid), 0x58: order.owner or user_id(case.user)}
    return {"events": events, "tag": 1, "fields": fields}


class AdvanceCase:
    def __init__(self, label, order=None, oid=5, user=1, others=(), orders=(), now=None, markets=3, width=11, users_missing=False,
                 order_missing=False, gone=False, carry=0, date_none=False, seconds=None, after=None, capacity=2, drop_steps=1,
                 user_value=True, user_root=True, filled=0, **fields):
        self.label, self.order = label, order or Order(**fields)
        self.oid, self.user, self.others, self.orders = oid, user, tuple(others), tuple(orders)
        self.now = now or (pack_date(2025, 100), 3600, 123456789)
        self.markets, self.width = markets, width
        self.users_missing, self.order_missing, self.gone = users_missing, order_missing, gone
        self.carry, self.date_none = carry, date_none
        self.seconds, self.after, self.capacity, self.drop_steps = seconds, after, capacity, drop_steps
        self.user_value, self.user_root, self.filled = user_value, user_root, filled


def stepped_time(case):
    """The stub answers of time add: seconds and nanos, plus the whole seconds carried over midnight."""
    due = case.order.due
    return ((due[1] + STEP_SECONDS) % 86400, due[2], case.carry if case.carry else 86400 * ((due[1] + STEP_SECONDS) // 86400))


def added_date(case, days):
    return (case.order.due[0] + (days << 4)) & MASK[4]


def advance_user(case):
    return user_id(case.user)


def spec_advance(copy, case):
    row = COPIES[copy]
    family = row["family"]
    order = case.order
    if case.users_missing:
        return {"events": [("entry", USER_ENTRY[family], advance_user(case), TRACKER + 0x18, 0, 0, 0)]}
    if case.order_missing:
        return {"events": []}
    events = []
    due = order.due
    seconds, nanos, carry = stepped_time(case)
    events.append(("time add", due[1], due[2], STEP_SECONDS, 0))
    wrapped = carry - (1 << 64) if carry >= 1 << 63 else carry
    if not -(1 << 31) * 86400 - 86399 <= wrapped <= (1 << 31) * 86400 - 1:
        return {"events": events, "stop": ("expect", EXPECT_TEXT, EXPECT_SIZE, LOCATION_CHRONO)}
    days = (abs(wrapped) // 86400) * (1 if wrapped >= 0 else -1)
    events.append(("date add", due[0] & MASK[4], days & MASK[4]))
    if case.date_none:
        return {"events": events, "stop": ("expect", EXPECT_TEXT, EXPECT_SIZE, LOCATION_CHRONO)}
    date = added_date(case, days)
    moment = (date, seconds, nanos)
    if time_key(moment) < time_key(case.now):
        events.append(("time sub", time_bytes(case.now), time_bytes(moment), TIME_LINE_WORD, TIME_FILE, TIME_FILE_SIZE))
        behind = case.seconds if case.seconds is not None else float((time_key(case.now)[1] - moment[1]) + 86400 * (signed32(case.now[0]) - signed32(date) >> 4))
        if behind != behind or behind < 0.0:
            return {"events": events, "stop": ("assert", ASSERT_A, ASSERT_A_SIZE, LOCATION_DURATION_A)}
        whole = math.ceil(behind / STEP_SECONDS) if behind / STEP_SECONDS != math.inf else math.inf
        rounded = float(whole)
        events.append(("date secs", time_bytes(moment), to_bits(rounded * STEP_SECONDS)))
        moment = case.after or (moment[0], (moment[1] + 1) & MASK[4], (moment[2] + 1) & MASK[4])
    counter = min(order.counter + 1, MASK[8])
    state = {"due": time_bytes(moment), "counter": counter}
    finished = order.executed >= order.total
    if not finished:
        steps = duration_steps(order.duration if order.raw_duration is None else to_float(order.raw_duration))
        if steps is None:
            return {"events": events, "stop": ("assert", ASSERT_A, ASSERT_A_SIZE, LOCATION_DURATION_A), "state": state}
        finished = counter > steps
    if not finished:
        entry = struct.pack("<Q", case.oid) + time_bytes(moment) + advance_user(case)
        events.append(("push", TRACKER, entry))
        return {"events": events, "state": state}
    events.append(("remove order", ORDER_REMOVE[family], case.oid))
    if case.gone:
        events.append(("drop failed", FAILED_WORD))
        return {"events": events, "state": state}
    if len(case.orders) == 0:
        events.append(("remove user", USER_REMOVE[family], advance_user(case)))
        if case.user_value:
            words = (1, 0, USER_TREE, USER_HEIGHT, 1, 0, USER_TREE, USER_HEIGHT, USER_COUNT) if case.user_root else (0, 0, 0)
            if family == PERP:
                for index in range(case.drop_steps):
                    events.append(("user drop", index) + words)
            else:
                events.append(("user drop", 0, USER_TREE if case.user_root else 0))
    if family == PERP:
        dex = order.asset // DIVISOR
        if dex >= case.markets:
            return {"events": events, "stop": ("unwrap", LOCATION_MARKET, ERROR_WORD, UNWRAP_SIZE), "state": state}
        events.append(("drop", ERROR_WORD))
        events.append(("convert", CONVERT[family], MARKETS + dex * MARKET_STRIDE, removed_value(case.oid)))
    else:
        events.append(("convert", CONVERT[family], OUTER + SPOT_CONVERT_FIELD, removed_value(case.oid)))
    if case.capacity == case.filled:
        events.append(("grow", family))
    size = RECORD_SIZE[family]
    events.append(("copy", size))
    state["count"] = case.filled + 1
    state["record"] = {0: struct.pack("<Q", RECORD_TAG), 8: converted(case.oid), 0x60: struct.pack("<Q", FINISH_WORD), 0x78: struct.pack("<Q", case.oid),
                       0x80: time_bytes(case.now), 0x8C: advance_user(case)}
    return {"events": events, "state": state}


def removed_value(oid):
    body = bytearray((oid + index * 7 + 1) & 0xFF for index in range(0x60))
    body[0x22] = 1
    return bytes(body)


def converted(oid):
    return bytes((oid + index * 3) & 0xFF for index in range(0x58))


class Entry:
    def __init__(self, oid, user, due):
        self.oid, self.user, self.due = oid, user, due

    def bytes(self):
        return struct.pack("<Q", self.oid) + time_bytes(self.due) + user_id(self.user)

    def key(self):
        return time_key(self.due) + (user_id(self.user), self.oid)


class DrainCase:
    def __init__(self, label, entries=(), users=None, now=None, flag=0, width=11):
        self.label, self.entries = label, tuple(entries)
        self.users = users or {}
        self.now = now or (pack_date(2025, 100), 3600, 500)
        self.flag, self.width = flag, width


def spec_drain(copy, case):
    pending = sorted(case.entries, key=Entry.key)
    rows = []
    left = list(pending)
    for entry in pending:
        known = entry.oid in case.users.get(entry.user, ())
        if not known:
            left.pop(0)
            continue
        if time_key(entry.due) > time_key(case.now):
            break
        left.pop(0)
        rows.append((user_id(entry.user), entry.oid))
    return {"rows": rows, "left": len(left), "events": [("collect", COPIES[copy]["collect"], 1 if rows else 8)]}


# ---- cases ----

NOW = (pack_date(2025, 100), 3600, 123456789)
TOPS = ((0, 1000), (1000, 0), (0, 0), (1, 1), (1, 2), (MASK[8], MASK[8]), (MASK[8], MASK[8] - 1), (1000000, 1000200))
SIZE_EDGES = tuple(sorted({value for power in range(5, 20) for value in (10 ** power - 1, 10 ** power, 10 ** power + 1, 123456789 * 10 ** max(power - 8, 0) + 7)}))


def slice_cases(family):
    rows = []

    def add(label, **options):
        rows.append(SliceCase(label, **options))

    limits = THRESHOLDS[family]
    whole = limits["whole"]
    add("plain mid book")
    add("sell side", side=1)
    add("reduce only byte", reduce_only=1)
    add("user missing", users_missing=True)
    add("order missing", order_missing=True)
    add("user below the only key", users_missing=True, user=3, others=(1,))
    add("other users around", user=4, others=(1, 2, 3, 5, 6, 7), width=2)
    add("other orders around", oid=9, orders=(1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13), width=2)
    add("last user of a deep tree", user=6, others=(1, 2, 3, 4, 5, 7, 8, 9), width=2)
    add("last order of a deep tree", oid=14, orders=(1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13), width=2)
    add("user missing, last edge", users_missing=True, user=6, others=(1, 2, 3, 4, 5, 7, 8, 9), width=2)
    add("order missing, last edge", order_missing=True, oid=14, orders=(1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13), width=2)
    add("user missing, early edge", users_missing=True, user=7, others=(1, 2, 3, 4, 5, 6, 8, 9), width=2)
    add("order missing, early edge", order_missing=True, oid=1, orders=(2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13), width=2)
    add("stored user differs from the key", owner=bytes(range(0x70, 0x84)))
    add("near the saturated step count", total=(1 << 53) + 1, executed=1 << 53, counter=MASK[8] - 1, duration=1e300, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("flag set", flag=1)
    add("flag set, once pending", flag=1, once=1)
    add("flag set, stored user differs", flag=1, owner=bytes(range(0x50, 0x64)))
    add("negative duration", duration=-1.0)
    add("negative duration with flag", duration=-1.0, flag=1)
    add("NaN duration", raw_duration=0x7FF8000000000000)
    add("infinite duration", duration=math.inf)
    add("zero duration", duration=0.0)
    add("duration below one bucket", duration=59.0)
    add("duration one bucket", duration=60.0)
    add("huge duration", duration=1e300)
    add("duration at 2^63 buckets", duration=9223372036854775808.0 * 60.0)
    add("duration just under 2^63 buckets", duration=9223372036854774784.0 * 60.0)
    add("duration at 2^64 buckets", duration=18446744073709551616.0 * 60.0)
    add("duration just under 2^64 buckets", duration=18446744073709549568.0 * 60.0, side=1)
    if family == PERP:
        add("market equals count", asset=30000)
        add("market past count", asset=MASK[8])
        add("last market last book", asset=29999, books=10000)
        add("book equals length", asset=20005)
        add("book past length", asset=20009)
        add("first asset", asset=0, markets=1, books=1)
        for top in TOPS:
            add("top %r" % (top,), top=top)
            add("top %r sell" % (top,), top=top, side=1)
    else:
        add("zero mid", mid=0)
        add("mid one", mid=1)
        add("mid top", mid=MASK[8])
        add("mid top sell", mid=MASK[8], side=1)
        add("big asset", asset=MASK[8])
        add("asset zero", asset=0)
    for tick in (1, 7, 10, 100, 1000, 1 << 33):
        add("tick %d" % tick, tick=tick, side=0)
        add("tick %d sell" % tick, tick=tick, side=1)
    add("price above the tick count", tick=1 << 40)
    add("price above the tick count, sell", tick=1 << 40, side=1)
    add("sell tick at the top", tick=1, side=1, mid=MASK[8], top=(MASK[8], MASK[8]))
    add("sell product overflow", tick=1 << 62, side=1, mid=MASK[8], top=(MASK[8], MASK[8]))
    # N = 3, counter 2, total u64::MAX: the even size is about 6e18, so the wanted size can be set exactly through the executed size.
    aimed = saturate(math.floor(2.0 * (float(MASK[8]) / 3.0)))
    for size in SIZE_EDGES:
        if size <= aimed:
            add("exact size %d" % size, total=MASK[8], duration=60.0, counter=2, executed=aimed - size, mid=1 << 40, top=(1 << 40, 1 << 40))
    unit_price = {PERP: 1000000, SPOT: 1000000}[family]
    for edge in (whole - 1, whole, whole + 1):
        add("remainder notional %d" % edge, total=edge // unit_price + 1, executed=1, mid=unit_price, top=(unit_price, unit_price), tick=1, duration=3600.0, side=0)
    base = {PERP: 1000000, SPOT: 100000000}[family]
    for price in (base - 1, base, base + 1):
        for total in (whole // base - 1, whole // base, whole // base + 1, whole // base + 2):
            add("edge notional, price %d total %d" % (price, total), total=total, mid=int(price / 1.03) + 1, top=(int(price / 1.03) + 1, int(price / 1.03) + 1), tick=1, counter=1)
    # A notional exactly at the threshold: a limit price that divides it.
    for extra in (-1, 0, 1):
        add("exact threshold %d" % extra, total=(whole + extra), executed=0, mid=1, top=(1, 1), tick=1, side=0, counter=0, duration=600.0)
        add("exact threshold doubled %d" % extra, total=(whole + extra) // 2, executed=0, mid=2, top=(2, 2), tick=2, side=0, counter=0, duration=600.0)
    add("floor applies", total=10 ** 9, duration=86400.0, counter=1, mid=1000, top=(1000, 1000), tick=1)
    add("floor equals the price", total=10 ** 12, mid=limits["floor"], top=(limits["floor"], limits["floor"]), side=1, tick=1, counter=1)
    add("price just over the floor", total=10 ** 12, mid=limits["floor"] * 2, top=(limits["floor"] * 2, limits["floor"] * 2), tick=1, counter=1)
    add("price at the floor exactly", total=10 ** 12, mid=int(limits["floor"] / 0.97) + 1, top=(int(limits["floor"] / 0.97) + 1,) * 2, side=1, tick=limits["floor"], counter=1)
    add("price over the floor by one", total=10 ** 12, mid=limits["floor"] + 1, top=(limits["floor"] + 1,) * 2, tick=limits["floor"] + 1, counter=1, side=1)
    # The floor size at a price dividing the dividend plus one: a wrong dividend moves the answer by one.
    divisor = {PERP: 923077, SPOT: 1323043}[family]
    add("floor at a divisor of the next integer", total=10 ** 15, counter=0, mid=divisor, top=(divisor, divisor), tick=divisor, side=0, duration=600.0)
    add("catch-up cap", total=10 ** 12, counter=300, duration=3600.0, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("catch-up cap, a little behind", total=10 ** 12, counter=20, executed=10 ** 9, duration=3600.0, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("ratio saturates", total=MASK[8], duration=0.0, counter=0, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("ratio times three overflows", total=MASK[8], duration=60.0, counter=0, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("ratio times three plus one saturates", total=(MASK[8] // 3) * 3, duration=0.0, counter=2, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("target above total", total=10 ** 12, counter=10 ** 6, duration=60.0, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("counter at the end", total=10 ** 12, executed=10 ** 11, counter=121, duration=3600.0, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("counter at the end, rounded size not used", total=1234567891, executed=1, counter=121, duration=3600.0, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("counter past the end", total=1234567891, executed=1, counter=122, duration=3600.0, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("counter one below the end", total=1234567891, executed=1, counter=120, duration=3600.0, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("counter top", total=1234567891, executed=1, counter=MASK[8], duration=3600.0, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("counter top against top steps", total=1234567891, executed=1, counter=MASK[8], duration=1e300, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("executed equals target", total=121 * 1000, executed=7000, counter=7, duration=3600.0)
    add("executed one over target", total=121 * 1000, executed=7001, counter=7, duration=3600.0)
    add("executed one under target", total=121 * 1000, executed=6999, counter=7, duration=3600.0)
    add("executed equals total", total=1000, executed=1000, counter=1000000, duration=60.0)
    add("executed over total, target over both", total=1000, executed=1001, counter=2000000, duration=60.0, mid=1 << 30, top=(1 << 30, 1 << 30))
    add("executed over total, small price", total=1000, executed=1001, counter=2000000, duration=60.0, mid=1, top=(1, 1), tick=1)
    add("rounding to zero", total=10 ** 19, executed=10 ** 19 - 3, counter=0, duration=86400.0, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("rounded size gives zero", total=10 ** 6 + 1, executed=0, counter=0, duration=600.0, mid=1 << 40, top=(1 << 40, 1 << 40))
    add("zero remainder after a large price", total=0, executed=0, counter=0)
    add("fractional target floors", total=10, duration=60.0, counter=1, executed=1, mid=1 << 30, top=(1 << 30, 1 << 30))
    for ms in (0, 1, 39, 40, 41, 999):
        moment = (pack_date(2025, 100), 3600, ms * 1000000 + 123)
        add("jitter at %d ms" % ms, randomize=1, now=moment, total=121 * 10 ** 10, executed=10 * 10 ** 10, counter=11, mid=1 << 30, top=(1 << 30, 1 << 30))
        add("jitter %d ms, first step" % ms, randomize=1, now=moment, total=10 ** 12, counter=0, mid=1 << 30, top=(1 << 30, 1 << 30))
        add("jitter %d ms, small ratio" % ms, randomize=1, now=moment, total=20, counter=0, duration=60.0, mid=1 << 30, top=(1 << 30, 1 << 30))
    for label, date in (("leap day", pack_date(2024, 60)), ("year 1", pack_date(1, 1)), ("year 0", pack_date(0, 1)), ("year -1", pack_date(-1, 365)),
                        ("year -400", pack_date(-400, 1)), ("year -401", pack_date(-401, 1)), ("before the epoch", pack_date(1960, 1)),
                        ("epoch", pack_date(1970, 1)), ("far year", pack_date(99999, 200))):
        add("jitter date %s" % label, randomize=1, now=(date, 71, 37000000), total=121 * 10 ** 10, executed=10 * 10 ** 10, counter=11, mid=1 << 30, top=(1 << 30, 1 << 30))
        add("jitter date %s, other nanos" % label, randomize=1, now=(date, 72, 11000000), total=121 * 10 ** 10, executed=10 * 10 ** 10, counter=11, mid=1 << 30, top=(1 << 30, 1 << 30))
    random = lcg(11 if family == PERP else 13)
    for index in range(70):
        total = 10 ** (next(random) % 14 + 2) + next(random) % 1000
        duration = float((next(random) % 2880 + 5) * 60)
        price = 1 + next(random) % (1 << (next(random) % 36 + 4))
        steps = duration_steps(duration)
        counter = next(random) % (steps + 3)
        add("random %d" % index, total=total, duration=duration, executed=next(random) % (total + 1) // (1 + next(random) % 4), counter=counter, side=next(random) % 2,
            reduce_only=next(random) % 2, randomize=next(random) % 2, mid=price, top=(price, price + next(random) % 100), tick=1 + next(random) % 50,
            now=(pack_date(2025, 1 + next(random) % 300), next(random) % 86400, next(random) % 1000000000))
    return rows


def advance_cases():
    rows = []

    def add(label, **options):
        rows.append(AdvanceCase(label, **options))

    early = (pack_date(2025, 100), 3000, 1)
    add("requeue before the end", counter=7)
    add("user missing", users_missing=True)
    add("user missing with others", users_missing=True, user=3, others=(1, 5))
    add("order missing", order_missing=True)
    add("order missing with others", order_missing=True, oid=9, orders=(1, 5, 12))
    add("other users around", user=4, others=(1, 2, 3, 5, 6, 7), width=2)
    add("other orders around", oid=9, orders=(1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13), width=2)
    add("last user of a deep tree", user=6, others=(1, 2, 3, 4, 5, 7, 8, 9), width=2)
    add("last order of a deep tree", oid=14, orders=(1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13), width=2)
    add("finish, last user of a deep tree", executed=1000000, user=6, others=(1, 2, 3, 4, 5, 7, 8, 9), width=2)
    add("finish, middle user of a deep tree", executed=1000000, user=4, others=(1, 2, 3, 5, 6, 7, 8, 9), width=2)
    add("finish, first user of a deep tree", executed=1000000, user=7, others=(1, 2, 3, 4, 5, 6, 8, 9), width=2)
    add("finish, deep order tree", executed=1000000, oid=9, orders=(1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13), width=2)
    add("finish, one record already out", executed=1000000, filled=1, capacity=4)
    add("finish, vector full with one record", executed=1000000, filled=1, capacity=1)
    add("executed reaches total", executed=1000000)
    add("executed passes total", executed=1000001)
    add("executed one short", executed=999999, counter=121)
    add("counter becomes the last step", counter=120, duration=3600.0)
    add("counter becomes one past the steps", counter=121, duration=3600.0)
    add("counter saturates", counter=MASK[8])
    add("counter saturates against top steps", counter=MASK[8], duration=1e300)
    add("counter under top steps", counter=MASK[8] - 2, duration=1e300)
    add("counter at 2^63 steps", counter=1 << 63, duration=9223372036854775808.0 * 60.0)
    add("duration infinite", counter=0, duration=math.inf)
    add("duration infinite, past one step", counter=1, duration=math.inf)
    add("duration negative, finishing by size", executed=1000000, duration=-1.0)
    add("duration negative", duration=-1.0)
    add("duration NaN", raw_duration=0x7FF8000000000000)
    add("zero total", total=0)
    add("finish leaves the user", executed=1000000, orders=(1, 2, 3))
    add("finish empties the user", executed=1000000)
    add("finish, removal fails", executed=1000000, gone=True)
    add("finish, removal fails, user kept", executed=1000000, gone=True, orders=(7,))
    add("finish, market missing", executed=1000000, asset=30000)
    add("finish, market past count", executed=1000000, asset=MASK[8])
    add("finish, last market", executed=1000000, asset=29999)
    add("finish, vector full", executed=1000000, capacity=0)
    add("finish, user drop three steps", executed=1000000, drop_steps=3)
    add("finish, user map empty", executed=1000000, user_root=False)
    add("finish, user value absent", executed=1000000, user_value=False)
    add("finish after the catch-up", executed=1000000, due=early)
    add("midnight carry", due=(pack_date(2025, 100), 86399, 9), now=(pack_date(2025, 100), 0, 0))
    add("midnight carry, equal next", due=(pack_date(2025, 100), 86370, 9), now=(pack_date(2025, 101), 0, 9))
    add("carry top of the range", carry=(1 << 31) * 86400 - 1)
    add("carry just over the range", carry=(1 << 31) * 86400)
    add("carry bottom of the range", carry=(-(1 << 31) * 86400 - 86399) & MASK[8])
    add("carry just under the range", carry=(-(1 << 31) * 86400 - 86400) & MASK[8])
    add("carry negative day", carry=(-86400) & MASK[8])
    add("carry negative partial day", carry=(-86399) & MASK[8])
    add("date add fails", date_none=True)
    add("next equals now", due=(pack_date(2025, 100), 3570, 123456789), now=(pack_date(2025, 100), 3600, 123456789))
    add("next one nano behind", due=(pack_date(2025, 100), 3570, 123456788), seconds=1e-9, now=(pack_date(2025, 100), 3600, 123456789))
    add("next one nano ahead", due=(pack_date(2025, 100), 3570, 123456790), now=(pack_date(2025, 100), 3600, 123456789))
    add("next one second behind", due=(pack_date(2025, 100), 3569, 123456789))
    add("next one second ahead", due=(pack_date(2025, 100), 3571, 123456789))
    add("next one day behind", due=(pack_date(2025, 99), 3570, 123456789), seconds=86400.0)
    add("next one day ahead", due=(pack_date(2025, 101), 3570, 123456789))
    add("high seconds bit", due=(pack_date(2025, 100), 3570, 0), now=(pack_date(2025, 100), 0x80000000, 0), seconds=100.0, carry=0)
    add("high nanos bit", due=(pack_date(2025, 100), 3570, 0x80000000), now=(pack_date(2025, 100), 3600, 1))
    add("high nanos in now", due=(pack_date(2025, 100), 3570, 1), now=(pack_date(2025, 100), 3600, 0x80000000), seconds=1.0)
    add("date below zero", due=(pack_date(-5, 100), 3570, 1), seconds=5.0)
    add("date below zero in now", due=(pack_date(2025, 100), 3570, 1), now=(pack_date(-5, 100), 3600, 1))
    add("seconds behind a multiple", due=early, seconds=60.0)
    add("seconds behind just past a multiple", due=early, seconds=60.5)
    add("seconds behind just under a multiple", due=early, seconds=59.5)
    add("seconds behind tiny", due=early, seconds=1e-300)
    add("seconds behind zero", due=early, seconds=0.0)
    add("seconds behind negative", due=early, seconds=-1.0)
    add("seconds behind NaN", due=early, seconds=math.nan)
    add("seconds behind huge", due=early, seconds=1e300)
    add("seconds behind infinite", due=early, seconds=math.inf)
    random = lcg(17)
    for index in range(50):
        total = 1 + next(random) % 1000000
        add("random %d" % index, total=total, executed=next(random) % (total * 2), counter=next(random) % 200, duration=float(next(random) % 7200),
            due=(pack_date(2025, 100), next(random) % 7200, next(random) % 1000), now=(pack_date(2025, 100), next(random) % 7200, next(random) % 1000),
            seconds=float(next(random) % 900) + 0.25, orders=tuple(range(20, 20 + next(random) % 3)), width=2 + next(random) % 4)
    return rows


def drain_cases():
    rows = []

    def add(label, **options):
        rows.append(DrainCase(label, **options))

    base = pack_date(2025, 100)
    now = (base, 3600, 500)
    add("empty heap")
    add("empty heap, live maps", users={1: (1,)})
    add("heap rows, empty maps", entries=[Entry(1, 1, now), Entry(2, 2, (base, 9000, 0))])
    add("user missing on an early edge", entries=[Entry(1, 7, now)], users={user: (1,) for user in (1, 2, 3, 4, 5, 6, 8, 9)}, width=2)
    add("user missing on the last edge", entries=[Entry(1, 6, now)], users={user: (1,) for user in (1, 2, 3, 4, 5, 7, 8, 9)}, width=2)
    add("order missing on an early edge", entries=[Entry(1, 1, now)], users={1: tuple(range(2, 14))}, width=2)
    add("order missing on the last edge", entries=[Entry(20, 1, now)], users={1: tuple(range(2, 14))}, width=2)
    add("one due", entries=[Entry(1, 1, now)], users={1: (1,)})
    add("one due, flag byte", entries=[Entry(1, 1, now)], users={1: (1,)}, flag=1)
    add("one a nano later", entries=[Entry(1, 1, (base, 3600, 501))], users={1: (1,)})
    add("one a nano earlier", entries=[Entry(1, 1, (base, 3600, 499))], users={1: (1,)})
    add("one a second later", entries=[Entry(1, 1, (base, 3601, 0))], users={1: (1,)})
    add("one a second earlier", entries=[Entry(1, 1, (base, 3599, 999))], users={1: (1,)})
    add("one a day later", entries=[Entry(1, 1, (base + 16, 0, 0))], users={1: (1,)})
    add("one a day earlier", entries=[Entry(1, 1, (base - 16, 86399, 999))], users={1: (1,)})
    add("date with the sign bit", entries=[Entry(1, 1, (pack_date(-5, 1), 90000, 900))], users={1: (1,)})
    add("now below zero", now=(pack_date(-5, 1), 5, 5), entries=[Entry(1, 1, now)], users={1: (1,)})
    add("high seconds bit", entries=[Entry(1, 1, (base, 0x80000000, 0))], users={1: (1,)})
    add("high nanos bit", entries=[Entry(1, 1, (base, 3600, 0x80000000))], users={1: (1,)})
    add("user missing, due", entries=[Entry(1, 2, now)], users={1: (1,)})
    add("order missing, due", entries=[Entry(9, 1, now)], users={1: (1,)})
    add("user missing, not due", entries=[Entry(1, 2, (base, 9000, 0))], users={1: (1,)})
    add("order missing, not due", entries=[Entry(9, 1, (base, 9000, 0))], users={1: (1,)})
    add("stale head before a due row", entries=[Entry(9, 1, (base, 1, 0)), Entry(1, 1, (base, 2, 0))], users={1: (1,)})
    add("stale head before a later row", entries=[Entry(9, 1, (base, 1, 0)), Entry(1, 1, (base, 9000, 0))], users={1: (1,)})
    add("later stale rows stay", entries=[Entry(1, 1, (base, 9000, 0)), Entry(9, 1, (base, 9001, 0))], users={1: (1,)})
    add("order by user at one time", entries=[Entry(1, 3, now), Entry(1, 2, now), Entry(1, 1, now)], users={1: (1,), 2: (1,), 3: (1,)})
    add("order by id at one time", entries=[Entry(3, 1, now), Entry(2, 1, now), Entry(1, 1, now)], users={1: (1, 2, 3)})
    add("deep trees", entries=[Entry(order, user, now) for user in (1, 3, 5) for order in (2, 7, 11)],
        users={user: tuple(range(1, 14)) for user in range(1, 8)}, width=2)
    random = lcg(23)
    for index in range(40):
        users = {user: tuple(sorted({1 + next(random) % 12 for _ in range(1 + next(random) % 6)})) for user in range(1, 2 + next(random) % 5)}
        seen, entries = set(), []
        for _ in range(next(random) % 12):
            user, order = 1 + next(random) % 6, 1 + next(random) % 13
            if (user, order) in seen:
                continue
            seen.add((user, order))
            entries.append(Entry(order, user, (base + (next(random) % 3 - 1) * 16, 3598 + next(random) % 5, 498 + next(random) % 5)))
        add("random %d" % index, entries=entries, users=users, width=2 + next(random) % 4)
    return rows


def heap_cases():
    random = lcg(29)
    rows = []
    for size in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17):
        rows.append([Entry(index + 1, 1 + index % 3, (pack_date(2025, 100), 3600 - index, 0)) for index in range(size)])
        rows.append([Entry(index + 1, 1, (pack_date(2025, 100), 3600, 0)) for index in range(size)])
    for _ in range(40):
        rows.append([Entry(next(random) % 9, next(random) % 4, ((pack_date(2025, 100) + (next(random) % 3 - 1) * 16) & MASK[4], next(random) % 3, next(random) % 3))
                     for _ in range(next(random) % 24)])
    for _ in range(30):
        rows.append([Entry(index, 1, (pack_date(2025, 100), next(random) % 1000, 0)) for index in range(20 + next(random) % 40)])
    return rows


# ---- harness ----

OUTER = HEAP_BASE + 0x1000
TRACKER = HEAP_BASE + 0x3000
CAPTURE = HEAP_BASE + 0x3100
NOW_AT = HEAP_BASE + 0x3200
FLAG_AT = HEAP_BASE + 0x3210
COLLECTION = HEAP_BASE + 0x3220
ROW_AT = HEAP_BASE + 0x3240
RESULT = HEAP_BASE + 0x3300
HOLDER = HEAP_BASE + 0x3400
VECTOR = HEAP_BASE + 0x3500
SLOT_ENTRY = HEAP_BASE + 0x3600
USER_AT = HEAP_BASE + 0x3640
ENTRY_AT = HEAP_BASE + 0x3680
POP_AT = HEAP_BASE + 0x36C0
HEAP_ARRAY = HEAP_BASE + 0x4000
OUT_ROWS = HEAP_BASE + 0x8000
RECORDS = HEAP_BASE + 0xA000
NODES = HEAP_BASE + 0x40000
MARKETS = 0x640000000
BOOKS = 0x650000000
LEAF_EDGE = 0x4242424242424200
USER_TREE = HEAP_BASE + 0x3800
USER_HEIGHT = 5
USER_COUNT = 9
STACK_PROBE = 0x5151515151515150


def tree_height(count, width):
    height = 0
    while (width + 1) ** (height + 1) - 1 < count:
        height += 1
    return height


def chunks(keys, width, height):
    if height == 0:
        return keys, None
    below = (width + 1) ** height - 1
    count = 2
    while count * below + count - 1 < len(keys):
        count += 1
    share = (len(keys) - (count - 1)) / count
    separators, children, start = [], [], 0
    for index in range(1, count):
        at = int(share * index) + index - 1
        children.append(keys[start:at])
        separators.append(keys[at])
        start = at + 1
    children.append(keys[start:])
    return separators, children


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        self.relative = relative
        for slot in (SLOT_ROUND, SLOT_FMA, SLOT_FLOOR, SLOT_CEIL, SLOT_SPOT_MID, SLOT_TIME_ADD, SLOT_DATE_ADD, SLOT_TIME_SUB, SLOT_DATE_SECS,
                     SLOT_RECORDER, SLOT_ASSERT, SLOT_EXPECT, SLOT_FREE, SLOT_PANIC_INDEX, SLOT_UNWRAP, SLOT_ONCE, SLOT_GROW_ROWS, SLOT_GROW_HEAP,
                     SLOT_GROW_PERP, SLOT_GROW_SPOT):
            machine.memory.statics[slot] = relative[slot]
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCMP + 0x10
        machine.memory.statics[ONCE_STATE] = 0
        machine.slots = {relative[SLOT_FMA]: self.on_fma, relative[SLOT_SPOT_MID]: self.on_mid, relative[SLOT_TIME_ADD]: self.on_time_add,
                         relative[SLOT_DATE_ADD]: self.on_date_add, relative[SLOT_TIME_SUB]: self.on_time_sub, relative[SLOT_DATE_SECS]: self.on_date_secs,
                         relative[SLOT_RECORDER]: self.on_recorder, relative[SLOT_ASSERT]: self.on_assert, relative[SLOT_EXPECT]: self.on_expect,
                         relative[SLOT_FREE]: self.on_free, relative[SLOT_PANIC_INDEX]: self.on_index, relative[SLOT_UNWRAP]: self.on_unwrap,
                         relative[SLOT_ONCE]: self.on_once, relative[SLOT_GROW_ROWS]: self.on_grow_rows, relative[SLOT_GROW_HEAP]: self.on_grow_heap,
                         relative[SLOT_GROW_PERP]: self.on_grow_perp, relative[SLOT_GROW_SPOT]: self.on_grow_spot,
                         FAKE_MEMCMP: self.on_memcmp, FAKE_MEMCMP + 0x10: self.on_memcpy}
        machine.calls = {DROP_ERROR: self.on_drop, PERP_TOP: self.on_top, PERP_TICK: self.on_tick, SPOT_TICK: self.on_tick, DROP_FAILED: self.on_drop_failed}
        for family in (PERP, SPOT):
            machine.calls[CONVERT[family]] = self.on_convert
            machine.calls[ORDER_REMOVE[family]] = self.on_remove_order
            machine.calls[USER_REMOVE[family]] = self.on_remove_user
            machine.calls[USER_DROP[family]] = self.on_user_drop
            machine.calls[USER_ENTRY[family]] = self.on_entry
        for row in COPIES:
            machine.calls[row["advance"]] = self.on_advance
            machine.calls[row["collect"]] = self.on_collect
        machine.calls[HEAP_PUSH] = self.on_push
        self.used = HEAP_SIZE
        self.brk = NODES

    def reset(self):
        self.machine.memory.reset(self.used)
        self.machine.memory.statics[ONCE_STATE] = 0
        self.used = NODES - HEAP_BASE
        self.events = []
        self.brk = NODES
        self.machine.real = frozenset((ROUND, CEIL, FLOOR))

    def carve(self, size):
        at = self.brk
        self.brk += (size + 15) & ~15
        self.used = max(self.used, self.brk - HEAP_BASE)
        return at

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def build_tree(self, at, keys, shape, width, write_key, write_value=None):
        keys = list(keys)
        if not keys:
            self.word(at, 0)
            self.word(at + 8, 0)
            self.word(at + 0x10, 0)
            return

        def make(items, parent, slot, level):
            node = self.carve(shape["size"])
            self.machine.memory.put_bytes(node, bytes(shape["size"]))
            self.machine.memory.put_bytes(node + shape["edges"], struct.pack("<Q", LEAF_EDGE) * 12)
            self.word(node + shape["parent"], parent)
            self.word(node + shape["index"], slot, 2)
            separators, children = chunks(items, width, level)
            self.word(node + shape["length"], len(separators), 2)
            for index, key in enumerate(separators):
                write_key(node + shape["keys"] + index * shape["stride"], key)
                if write_value:
                    write_value(node + shape["values"] + index * shape["value_stride"], key)
            for index, child in enumerate(children or ()):
                self.word(node + shape["edges"] + index * 8, make(child, node, index, level - 1))
            return node

        height = tree_height(len(keys), width)
        root = make(keys, 0, 0, height)
        self.word(at, root)
        self.word(at + 8, height)
        self.word(at + 0x10, len(keys))

    def install_users(self, case, users):
        """users: {user: {oid: body}} laid out as the two-level B-tree at tracker +0x18."""

        def write_user(at, user):
            self.machine.memory.put_bytes(at, user_id(user))

        def write_orders(at, user):
            orders = users[user]

            def write_body(slot, oid):
                self.machine.memory.put_bytes(slot, orders[oid])
                if user == getattr(case, "user", None) and oid == getattr(case, "oid", None):
                    self.body_slot = slot

            if user == getattr(case, "user", None):
                self.map_slot = at

            self.build_tree(at, sorted(orders), ORDER_NODE, case.width, lambda key_at, oid: self.word(key_at, oid), write_body)

        # User keys compare as bytes, and user_id is not monotonic in its number.
        self.build_tree(TRACKER + 0x18, sorted(users, key=user_id), USER_NODE, case.width, write_user, write_orders)

    def case_users(self, case):
        users = {}
        if not case.users_missing:
            orders = {oid: bytes((oid + index) & 0xFF for index in range(0x60)) for oid in case.orders}
            if not case.order_missing:
                orders[case.oid] = case.order.body(case.user)
            users[case.user] = orders
        for other in case.others:
            users.setdefault(other, {3: bytes(0x60)})
        return users

    def run_slice(self, copy, case):
        self.reset()
        self.case = case
        self.copy = copy
        row = COPIES[copy]
        users = self.case_users(case)
        self.install_users(case, users)
        machine = self.machine
        machine.memory.statics[ONCE_STATE] = case.once
        memory = machine.memory
        memory.put_bytes(NOW_AT, time_bytes(case.now))
        self.word(FLAG_AT, case.flag, 1)
        self.word(COLLECTION + 8, BOOKS)
        self.word(COLLECTION + 0x10, case.books)
        if row["family"] == PERP:
            self.word(OUTER + row["markets"], MARKETS)
            self.word(OUTER + row["count"], case.markets)
        for index, value in enumerate((TRACKER, NOW_AT, FLAG_AT, COLLECTION, OUTER, VECTOR)):
            self.word(CAPTURE + index * 8, value)
        self.word(HOLDER, CAPTURE)
        memory.put_bytes(ROW_AT, user_id(case.user))
        self.word(ROW_AT + 0x18, case.oid)
        try:
            machine.run(row["slice"], {RDI: RESULT, RSI: HOLDER, RDX: ROW_AT})
        except Panicked as stop:
            return {"events": self.events, "stop": stop.args[0]}
        out = {"events": self.events, "tag": memory.read(RESULT, 8)}
        if out["tag"] == 1:
            out["bytes"] = memory.bytes_at(RESULT, SLICE_SIZE)
        return out

    def run_advance(self, copy, case):
        self.reset()
        self.case = case
        self.copy = copy
        row = COPIES[copy]
        self.family = row["family"]
        users = self.case_users(case)
        self.body_slot = None
        self.install_users(case, users)
        machine = self.machine
        memory = machine.memory
        memory.put_bytes(NOW_AT, time_bytes(case.now))
        if row["family"] == PERP:
            self.word(OUTER + row["markets"], MARKETS)
            self.word(OUTER + row["count"], case.markets)
        self.word(VECTOR, case.capacity)
        self.word(VECTOR + 8, RECORDS)
        self.word(VECTOR + 0x10, case.filled)
        memory.put_bytes(OUTER + 0x60, time_bytes(case.now))
        memory.put_bytes(USER_AT, user_id(case.user))
        out = {"events": self.events}
        try:
            machine.run(row["advance"], {RDI: TRACKER, RSI: USER_AT, RDX: case.oid, RCX: OUTER, R8: VECTOR})
        except Panicked as stop:
            out["stop"] = stop.args[0]
        out["state"] = self.advance_state(case)
        return out

    def advance_state(self, case):
        """Read back what the function left in the order slot and the output vector."""
        memory = self.machine.memory
        if self.body_slot is None:
            return None
        state = {"due": memory.bytes_at(self.body_slot + 0x40, 12), "counter": memory.read(self.body_slot + 0x38, 8)}
        count = memory.read(VECTOR + 0x10, 8)
        if count != case.filled:
            state["count"] = count
            state["record"] = {}
            base = RECORDS + case.filled * RECORD_SIZE[self.family]
            for offset, value in spec_advance(self.copy, case)["state"].get("record", {}).items():
                state["record"][offset] = memory.bytes_at(base + offset, len(value))
        return state

    def run_drain(self, copy, case):
        self.reset()
        self.case = case
        self.copy = copy
        machine = self.machine
        memory = machine.memory
        users = {user: {oid: bytes(0x60) for oid in oids} for user, oids in case.users.items()}
        self.body_slot = None
        self.install_users(case, users)
        self.word(TRACKER, 64)
        self.word(TRACKER + 8, HEAP_ARRAY)
        self.word(TRACKER + 0x10, 0)
        self.rows = None
        for entry in case.entries:
            memory.put_bytes(ENTRY_AT, entry.bytes())
            machine.real = frozenset((HEAP_PUSH, HEAP_POP, ROUND, CEIL, FLOOR))
            machine.run(HEAP_PUSH, {RDI: TRACKER, RSI: ENTRY_AT})
        memory.put_bytes(NOW_AT, time_bytes(case.now))
        self.word(ROW_AT, 0x1234, 8)
        self.events.clear()
        self.word(ROW_AT + 8, 0x7777)
        self.word(STACK_TOP - 0x100, STACK_PROBE)
        machine.real = frozenset((HEAP_PUSH, HEAP_POP, ROUND, CEIL, FLOOR))
        machine.run(COPIES[copy]["drain"], {RDI: RESULT, RSI: TRACKER, RDX: NOW_AT, RCX: case.flag | 0x7700, R8: ROW_AT, R9: ROW_AT + 8})
        return {"events": self.events, "rows": self.rows, "left": memory.read(TRACKER + 0x10, 8)}

    def run_heap(self, entries):
        self.reset()
        machine = self.machine
        memory = machine.memory
        machine.real = frozenset()
        self.word(TRACKER, 64)
        self.word(TRACKER + 8, HEAP_ARRAY)
        self.word(TRACKER + 0x10, 0)
        # One slot before the array holds a key above every real key, so a walk past the root moves it and shows.
        memory.put_bytes(HEAP_ARRAY - ENTRY_SIZE, bytes([0x7F]) * ENTRY_SIZE)
        for entry in entries:
            memory.put_bytes(ENTRY_AT, entry.bytes())
            machine.real = frozenset((HEAP_PUSH, HEAP_POP))
            machine.run(HEAP_PUSH, {RDI: TRACKER, RSI: ENTRY_AT})
        popped = []
        for _ in range(len(entries) + 1):
            self.word(POP_AT + 8, 1, 4)
            machine.run(HEAP_POP, {RDI: POP_AT, RSI: TRACKER})
            if memory.read(POP_AT + 8, 4) == 0:
                popped.append(None)
                break
            popped.append(memory.bytes_at(POP_AT, ENTRY_SIZE))
        return popped, memory.read(TRACKER + 0x10, 8)

    # -- stubs --

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_top(self, machine):
        self.events.append(("top", machine.regs[RSI]))
        machine.memory.write(machine.regs[RDI], 8, self.case.top[0])
        machine.memory.write(machine.regs[RDI] + 8, 8, self.case.top[1])

    def on_mid(self, machine):
        self.events.append(("mid", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = self.case.mid

    def on_tick(self, machine):
        self.events.append(("tick", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = self.case.tick

    def on_fma(self, machine):
        left, right, extra = to_float(machine.xmm[0] & MASK[8]), to_float(machine.xmm[1] & MASK[8]), to_float(machine.xmm[2] & MASK[8])
        machine.xmm[0] = to_bits(fused(left, right, extra))
        machine.keep_float = True

    def on_recorder(self, machine):
        self.events.append(("recorder", machine.regs[RSI]))
        machine.regs[RAX] = POISON

    def on_advance(self, machine):
        regs = machine.regs
        self.events.append(("advance", regs[RDI], machine.memory.bytes_at(regs[RSI], 20), regs[RDX], regs[RCX], regs[R8]))

    def on_once(self, machine):
        regs = machine.regs
        reference = machine.memory.read(machine.memory.read(regs[RDX], 8), 8)
        self.events.append(("once", regs[RDI], regs[RSI] & 0xFF, regs[RCX], regs[R8], reference))

    def on_assert(self, machine):
        raise Panicked(("assert", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_expect(self, machine):
        raise Panicked(("expect", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_index(self, machine):
        raise Panicked(("index", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_unwrap(self, machine):
        regs = machine.regs
        raise Panicked(("unwrap", regs[R8], machine.memory.read(regs[RDX], 2), regs[RSI]))

    def on_free(self, machine):
        self.events.append(("free", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_time_add(self, machine):
        regs = machine.regs
        memory = machine.memory
        seconds, nanos = memory.read(regs[RSI], 4), memory.read(regs[RSI] + 4, 4)
        self.events.append(("time add", seconds, nanos, regs[RDX], regs[RCX] & MASK[4]))
        answer = stepped_time(self.case)
        memory.write(regs[RDI], 4, answer[0])
        memory.write(regs[RDI] + 4, 4, answer[1])
        memory.write(regs[RDI] + 8, 8, answer[2])

    def on_date_add(self, machine):
        regs = machine.regs
        days = signed32(regs[RSI])
        self.events.append(("date add", regs[RDI] & MASK[4], regs[RSI] & MASK[4]))
        regs[RAX] = 0 if self.case.date_none else added_date(self.case, days)

    def on_time_sub(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("time sub", memory.bytes_at(regs[RDI], 12), memory.bytes_at(regs[RSI], 12), memory.read(regs[RSI] + 0x10, 8),
                            memory.read(regs[RSI] + 0x18, 8), memory.read(regs[RSI] + 0x20, 8)))
        case = self.case
        behind = case.seconds
        if behind is None:
            moment = memory.bytes_at(regs[RSI], 12)
            first, second = struct.unpack("<II", moment[:8])
            behind = float((time_key(case.now)[1] - second) + 86400 * (signed32(case.now[0]) - signed32(first) >> 4))
        machine.xmm[0] = to_bits(behind)
        machine.keep_float = True

    def on_date_secs(self, machine):
        regs = machine.regs
        memory = machine.memory
        moment = memory.bytes_at(regs[RSI], 12)
        self.events.append(("date secs", moment, machine.xmm[0] & MASK[8]))
        first, second, third = struct.unpack("<III", moment)
        after = self.case.after or (first, (second + 1) & MASK[4], (third + 1) & MASK[4])
        memory.put_bytes(regs[RDI], time_bytes(after))

    def on_entry(self, machine):
        regs = machine.regs
        memory = machine.memory
        words = (memory.read(regs[RSI], 8), memory.read(regs[RSI] + 0x10, 8), memory.read(regs[RDX], 8), memory.read(regs[RDX] + 0x10, 8))
        self.events.append(("entry", USER_ENTRY[self.family], memory.bytes_at(regs[RSI] + 0x20, 20)) + words)
        memory.write(regs[RDI], 8, SLOT_ENTRY)
        memory.write(regs[RDI] + 0x10, 8, 0)
        memory.write(SLOT_ENTRY + 8, 8, 0)

    def on_remove_order(self, machine):
        regs = machine.regs
        memory = machine.memory
        oid = memory.read(regs[RDX], 8)
        if regs[RSI] != self.map_slot:
            raise Halt("order removal from the wrong map")
        self.events.append(("remove order", ORDER_REMOVE[self.family], oid))
        memory.write(regs[RSI] + 0x10, 8, len(self.case.orders))
        body = bytearray(removed_value(oid))
        if self.case.gone:
            body[0x22] = 2
        memory.put_bytes(regs[RDI], bytes(body))

    def on_remove_user(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("remove user", USER_REMOVE[self.family], memory.bytes_at(regs[RDX], 20)))
        case = self.case
        memory.write(regs[RDI], 8, int(case.user_value))
        memory.write(regs[RDI] + 8, 8, USER_TREE if case.user_root else 0)
        memory.write(regs[RDI] + 0x10, 8, USER_HEIGHT)
        memory.write(regs[RDI] + 0x18, 8, USER_COUNT)
        self.drop_left = case.drop_steps
        self.drop_step = 0

    def on_user_drop(self, machine):
        regs = machine.regs
        memory = machine.memory
        if self.family == PERP:
            words = [memory.read(regs[RSI] + index * 8, 8) for index in range(9)]
            if not words[0]:
                words = [words[0], words[4], words[8]]
            self.events.append(("user drop", self.drop_step) + tuple(words))
            self.drop_left -= 1
            memory.write(regs[RDI], 8, 1 if self.drop_left > 0 else 0)
        else:
            self.events.append(("user drop", self.drop_step, memory.read(regs[RDI], 8)))
        self.drop_step += 1

    def on_convert(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("convert", CONVERT[self.family], regs[RDX], memory.bytes_at(regs[RSI], 0x60)))
        memory.put_bytes(regs[RDI], converted(self.case.oid))

    def on_drop_failed(self, machine):
        self.events.append(("drop failed", machine.memory.read(machine.regs[RDI], 2)))

    def on_push(self, machine):
        regs = machine.regs
        self.events.append(("push", regs[RDI], machine.memory.bytes_at(regs[RSI], ENTRY_SIZE)))

    def on_grow_perp(self, machine):
        self.grow(RECORD_SIZE[PERP])

    def on_grow_spot(self, machine):
        self.grow(RECORD_SIZE[SPOT])

    def grow(self, stride):
        self.events.append(("grow", self.family))
        machine = self.machine
        machine.memory.write(machine.regs[RDI], 8, 4)
        machine.memory.write(machine.regs[RDI] + 8, 8, RECORDS)

    def on_grow_heap(self, machine):
        raise Halt("heap grew")

    def on_grow_rows(self, machine):
        regs = machine.regs
        memory = machine.memory
        capacity = memory.read(regs[RDI], 8)
        fresh = max(capacity * 2, 4)
        old, count = memory.read(regs[RDI] + 8, 8), memory.read(regs[RDI] + 0x10, 8)
        target = OUT_ROWS + (0x400 if old == OUT_ROWS else 0)
        if count:
            memory.copy(target, old, count * ROW_SIZE)
        memory.write(regs[RDI], 8, fresh)
        memory.write(regs[RDI] + 8, 8, target)

    def on_collect(self, machine):
        regs = machine.regs
        memory = machine.memory
        begin, current, _, end = [memory.read(regs[RSI] + index * 8, 8) for index in range(4)]
        rows = []
        for at in range(current, end, ROW_SIZE):
            rows.append((memory.bytes_at(at, 20), memory.read(at + 0x18, 8)))
        self.rows = rows
        self.events.append(("collect", COPIES[self.copy]["collect"], 1 if rows else begin))
        captured = [memory.read(regs[RSI] + 0x20 + index * 8, 8) for index in range(6)]
        if captured[0] != TRACKER or captured[1] != NOW_AT or captured[3] != ROW_AT or captured[4] != ROW_AT + 8 or captured[5] != STACK_PROBE:
            raise Halt("collector captures changed")
        if memory.read(captured[2], 1) != self.case.flag:
            raise Halt("collector flag changed")

    def on_memcmp(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcpy(self, machine):
        regs = machine.regs
        self.events.append(("copy", regs[RDX]))
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]


def compare(actual, expected, label):
    """Empty when the two outcomes agree, else the first difference."""
    if actual.get("stop") != expected.get("stop"):
        return "%s: stop %r, want %r" % (label, actual.get("stop"), expected.get("stop"))
    if actual["events"] != expected["events"]:
        for index, (left, right) in enumerate(zip(actual["events"], expected["events"])):
            if left != right:
                return "%s: event %d %r, want %r" % (label, index, left, right)
        return "%s: %d events, want %d" % (label, len(actual["events"]), len(expected["events"]))
    return ""


def guarded(run, *args):
    try:
        return run(*args), ""
    except Exception as stop:
        return None, "%s %s" % (type(stop).__name__, stop)


def compare_slice(harness, copy, case):
    actual, trouble = guarded(harness.run_slice, copy, case)
    if trouble:
        return "%s: %s" % (case.label, trouble)
    expected = spec_slice(copy, case)
    found = compare(actual, expected, case.label)
    if found or "stop" in expected:
        return found
    if actual["tag"] != expected["tag"]:
        return "%s: tag %r, want %r" % (case.label, actual["tag"], expected["tag"])
    if expected["tag"] == 1:
        record = bytearray([STACK_MARK]) * SLICE_SIZE
        for offset, value in expected["fields"].items():
            record[offset:offset + len(value)] = value
        if bytes(record) != actual["bytes"]:
            return "%s: record %s, want %s" % (case.label, actual["bytes"].hex(), bytes(record).hex())
    return ""


def compare_advance(harness, copy, case):
    actual, trouble = guarded(harness.run_advance, copy, case)
    if trouble:
        return "%s: %s" % (case.label, trouble)
    expected = spec_advance(copy, case)
    found = compare(actual, expected, case.label)
    if found:
        return found
    if "state" in expected and actual["state"] != expected["state"]:
        return "%s: state %r, want %r" % (case.label, actual["state"], expected["state"])
    return ""


def compare_drain(harness, copy, case):
    actual, trouble = guarded(harness.run_drain, copy, case)
    if trouble:
        return "%s: %s" % (case.label, trouble)
    expected = spec_drain(copy, case)
    found = compare(actual, expected, case.label)
    if found:
        return found
    if actual["rows"] != expected["rows"]:
        return "%s: rows %r, want %r" % (case.label, actual["rows"], expected["rows"])
    if actual["left"] != expected["left"]:
        return "%s: %d left, want %d" % (case.label, actual["left"], expected["left"])
    return ""


def compare_heap(harness, copy, entries):
    label = "heap of %d, first key %r" % (len(entries), entries[0].key()[:3] if entries else ())
    result, trouble = guarded(harness.run_heap, entries)
    if trouble:
        return "%s: %s" % (label, trouble)
    popped, left = result
    want = [entry.bytes() for entry in sorted(entries, key=Entry.key)] + [None]
    if popped != want:
        return "%s: popped order differs" % label
    return "%s: %d left" % (label, left) if left else ""


# ---- structure of the bytes ----

def direct_sites(image, targets):
    """Every E8/E9 rel32 byte pattern in .text that lands on a target."""
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    for opcode in (b"\xe8", b"\xe9"):
        at = text.find(opcode)
        while 0 <= at <= len(text) - 5:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in found:
                found[target].append((base + at, opcode[0]))
            at = text.find(opcode, at + 1)
    return found


def operand_text(operand):
    if operand is None:
        return ""
    kind = operand[0]
    if kind == "r":
        return "r%d" % operand[1]
    if kind == "x":
        return "x%d" % operand[1]
    if kind == "i":
        return "%#x" % (operand[1] & MASK[8])
    _, base, index, scale, disp, _ = operand
    parts = []
    if base is not None:
        parts.append("r%d" % base)
    if index is not None:
        parts.append("r%d*%d" % (index, scale))
    parts.append("%#x" % (disp & MASK[8]))
    return "[" + "+".join(parts) + "]"


def row_shape(row, start, end):
    """A row with its branch target made relative when the target stays inside the function."""
    target = row.target
    if target is not None and start <= target < end:
        target = "+%#x" % (target - start)
    elif target is not None:
        target = "%#x" % (target & MASK[8])
    return (row.op, row.width, row.cc, operand_text(row.a), operand_text(row.b), target)


def copy_differences(image, first, second):
    """Rows of two same-sized functions that differ after normalising code distance."""
    begin, end = image.exact_fde(first)
    other, other_end = image.exact_fde(second)
    if end - begin != other_end - other:
        raise EvidenceError("copies differ in size: %#x %#x" % (first, second))
    rows = decode_range(image, begin, end)
    others = decode_range(image, other, other_end)
    if [row.va - begin for row in rows] != [row.va - other for row in others]:
        raise EvidenceError("copies differ in instruction boundaries: %#x %#x" % (first, second))
    found = []
    for row, peer in zip(rows, others):
        left, right = row_shape(row, begin, end), row_shape(peer, other, other_end)
        if left != right:
            found.append({"first": first, "second": second, "offset": row.va - begin, "left": " ".join(map(str, left)),
                          "right": " ".join(map(str, right))})
    return found


def code_reader(image):
    def read(va, count):
        at = image.offset(va)
        return bytes(image.blob[at:at + count])
    return read


# Exact bytes: va, hex, meaning. Each is read back from the file.
BYTE_PINS = (
    (0x4339C2B, "483d81c3c901", "perp: remainder notional compared with 30000001 (cmp rax, setae)"),
    (0x4339C3C, "4881fd001bb700", "perp: limit price compared with 12000000"),
    (0x4339C45, "b8001bb700", "perp: 12000000 is the dividend of the floor size"),
    (0x4337273, "ba005ed0b2", "spot: remainder notional limit 3000000000"),
    (0x4337286, "4881fd008c8647", "spot: limit price compared with 1200000000"),
    (0x433728F, "b8008c8647", "spot: 1200000000 is the dividend of the floor size"),
    (0x4339CD8, "ba03000000", "perp: the slice cap multiplies the even size by 3"),
    (0x4337322, "ba03000000", "spot: the slice cap multiplies the even size by 3"),
    (0x565FD20, "c4e2f1a9c2c3", "fma target: vfmadd213sd xmm0, xmm1, xmm2 then ret"),
    (0x565FD30, "c4e3f96bc210c3", "second fma target: four-operand FMA4 form then ret"),
    (0x565FD6B, "48890576851200", "the resolver stores the chosen target in the pointer at 0x57882e8"),
    (0x565F8C4, "488b051d8a1200", "the wrapper loads that pointer"),
)


def byte_pins(image):
    read = code_reader(image)
    rows = []
    for va, expected, meaning in BYTE_PINS:
        if read(va, len(expected) // 2).hex() != expected:
            raise EvidenceError("pin changed at %#x: %s" % (va, read(va, len(expected) // 2).hex()))
        rows.append({"va": "%#x" % va, "bytes": expected, "meaning": meaning})
    return rows


def float_constants(image):
    return {name: struct.unpack_from("<d", image.blob, image.offset(va))[0] for name, va in sorted(FLOAT_CONSTANTS.items())}


def check_pairing(image):
    """Each drain calls its collector, each collector its slice, each slice its advance."""
    pairs = []
    sites = direct_sites(image, [row[key] for row in COPIES for key in ("drain", "collect", "slice", "advance")])
    for row in COPIES:
        for source, target in (("drain", "collect"), ("collect", "slice"), ("slice", "advance")):
            begin, end = image.exact_fde(row[source])
            inside = [va for va, _ in sites[row[target]] if begin <= va < end]
            if not inside:
                raise EvidenceError("%#x does not reach %#x" % (row[source], row[target]))
            pairs.append({"from": "%#x" % row[source], "to": "%#x" % row[target], "sites": ["%#x" % va for va in sorted(inside)]})
    return pairs


# ---- mutation pass ----

MUTATED = (COPIES[0]["slice"], COPIES[2]["slice"], COPIES[0]["advance"], COPIES[2]["advance"], COPIES[0]["drain"], HEAP_PUSH, HEAP_POP)


def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, offset in instruction, kind) for every conditional, immediate and field offset."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at, kind="branch"):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ (8 if kind == "offset" else 1)}


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    choices = {COPIES[0]["slice"]: (0, slice_cases(PERP), compare_slice), COPIES[2]["slice"]: (2, slice_cases(SPOT), compare_slice),
               COPIES[0]["advance"]: (0, advance_cases(), compare_advance), COPIES[2]["advance"]: (2, advance_cases(), compare_advance),
               COPIES[0]["drain"]: (0, drain_cases(), compare_drain), HEAP_PUSH: (0, heap_cases(), compare_heap), HEAP_POP: (0, heap_cases(), compare_heap)}
    for start in MUTATED:
        copy, cases, check = choices[start]
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = check(harness, copy, case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

LOCATIONS = (LOCATION_MARKET, LOCATION_BOOKS, LOCATION_SZ, LOCATION_DURATION_A, LOCATION_DURATION_B, LOCATION_CHRONO)
FINITE = "low bit of the finite test: it only matters for the largest finite double, which this value cannot reach"
CLAMP = "both arms give the same number: the clamp keeps an in-range value, and the saturating cast after it handles an out-of-range one"
SIGN_MASK = "sign mask shifted by one less: the masked word comes from a double of at least 2^62, so its bit 0 is clear either way"
ONE_PRICE = "the price is at least 1 here: mid >= 1 gives 1.03 * mid or 0.97 * mid >= 0.97, which rounds to at least 1"
JITTER_DATE = "date arithmetic only: whole days and seconds are multiples of 40 ms, and a year at or below 0 is hidden by the clamp of negative millis to 0"
LOW_BITS = "this bit of the mask is already clear after the shift by 2"
FLOOR_EDGE = "a price of one more than the limit gives size 0 either way"
LADDER = "one more on a ladder rung: the only input it moves is the power of ten itself, which floors to the same number at both units"
SATURATE = "-2 then the saturating increment gives -1, the same as -1 saturating"
WALK = "second walk of a key that the first walk just found, so the height budget never runs out"
HOLE = "this store fills the hole left by the pop; the final store at 0x44c1397 rewrites the slot that matters"
ROOT_HOP = "stops one hop early only at the root's children; the moved key is never below the new root, because one of its ancestors was a child of the old root"
EQUIVALENT = {}
for reason, sites in (
        (FINITE, (0x433966F, 0x433967C, 0x4339B50, 0x4339B65, 0x4339C5E, 0x4339C73, 0x4336D71, 0x4336D7E, 0x43371A2, 0x43371B7, 0x43372A6, 0x433729C, 0x42EF3E2, 0x42EF3EF,
                  0x42F0683, 0x42F0690)),
        (CLAMP, (0x4339698, 0x43396A2, 0x4339B7C, 0x4339B8A, 0x4336D95, 0x4336D9F, 0x43371CE, 0x43371DC, 0x42EF406, 0x42EF410, 0x42F06A7, 0x42F06B1)),
        (SIGN_MASK, (0x43396C2, 0x4339914, 0x4339BB5, 0x4339CB1, 0x4336DBF, 0x4336F71, 0x4337207, 0x43372FB, 0x42EF430, 0x42F06D1)),
        (ONE_PRICE, (0x433993B, 0x4336F98)),
        (JITTER_DATE, (0x4339A31, 0x4339A38, 0x4339A3F, 0x4339A45, 0x4339A4D, 0x4339A78, 0x4339A82, 0x4339A9F,
                       0x4337082, 0x4337089, 0x4337090, 0x4337096, 0x433709E, 0x43370BA, 0x43370C4, 0x43370DE)),
        (LOW_BITS, (0x4339ADC, 0x4337122)),
        (FLOOR_EDGE, (0x4339C3C, 0x4337286)),
        (LADDER, (0x4339D33, 0x4339D45, 0x4339D57, 0x4339D69, 0x4339D7B, 0x4339E0F, 0x4339E1E, 0x4339E2D, 0x4339E3C,
                  0x4337389, 0x433739B, 0x43373AD, 0x43373BF, 0x43373D1, 0x4337465, 0x4337474, 0x4337483, 0x4337492)),
        (SATURATE, (0x4339E68, 0x4339E74, 0x43374BE, 0x43374CA, 0x42EF896, 0x42F0A44)),
        (WALK, (0x42EF4C2, 0x42EF55A, 0x42F075B, 0x42F07EA)),
        (HOLE, (0x44C1231,)),
        (ROOT_HOP, (0x44C1304,))):
    for site in sites:
        EQUIVALENT[site] = reason
UNREACHED_GROUPS = ((0x42F1897, 0x42F18BD, "unwind cleanup"),)
ORDER_MAP = (
    (0x00, 8, "asset, packed as dex * 10000 + local"),
    (0x08, 8, "total size"),
    (0x10, 8, "duration in seconds, f64"),
    (0x20, 1, "side: 0 takes the 1.03 price and floors to a tick, nonzero takes 0.97 and adds a tick"),
    (0x21, 1, "copied to the slice at +0x31"),
    (0x22, 1, "nonzero turns on the time jitter"),
    (0x28, 8, "executed size"),
    (0x38, 8, "step counter, saturating"),
    (0x40, 12, "next due time, date word then seconds then nanos"),
    (0x4C, 20, "user, which is what the slice and the reschedule use"),
)
SLICE_MAP = (
    (0x00, 8, "tag: 1 is an order, 2 is none"),
    (0x08, 8, "size"),
    (0x10, 1, "constant 3"),
    (0x19, 1, "constant 2"),
    (0x20, 8, "limit price"),
    (0x28, 8, "asset"),
    (0x30, 1, "order byte +0x20"),
    (0x31, 1, "order byte +0x21"),
    (0x32, 1, "constant 0"),
    (0x48, 8, "asset again"),
    (0x50, 8, "order id"),
    (0x58, 20, "user"),
)
HEAP_ENTRY_MAP = ((0x00, 8, "order id"), (0x08, 12, "due time"), (0x14, 20, "user"))
REFERENCE_CLAIMS = (
    {"reference": "l1/time.rs:10-12", "claim": "TWAP step is 30 s and the retry bucket 60 s",
     "bytes": "agrees: the constants at 0x20a1a0 and 0x20abf8 are 30.0 and 60.0"},
    {"reference": "l1/time.rs:149-153", "claim": "the limit is 2 * (duration / 60) + 1, saturating",
     "bytes": "agrees, and the same count is the slice denominator, not only a retry limit"},
    {"reference": "l1/time.rs:201-211", "claim": "advance_and_decide finishes at the target or past the limit, else defers",
     "bytes": "agrees for the decision; the finish removes the order and writes a record with second word 0x8000000000000002"},
    {"reference": "l1/time.rs:163-178", "claim": "fields filled_or_progress at +0x28, slice_counter at +0x38, next_fire_time at +0x40",
     "bytes": "agrees; +0x18 and +0x30 are not read by any function in this packet"},
    {"reference": "l1/time.rs, l1/exchange/handlers/35_twap_order.rs", "claim": "no slice size, limit price, jitter or heap drain is written down",
     "bytes": "this packet supplies them from the bytes"},
)


def count_outcomes(evaluated):
    table = {}
    for name in evaluated:
        table[name] = table.get(name, 0) + 1
    return dict(sorted(table.items()))


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    perp, spot, advances, drains, heaps = slice_cases(PERP), slice_cases(SPOT), advance_cases(), drain_cases(), heap_cases()
    mismatches = []
    outcomes = []
    for copy, row in enumerate(COPIES):
        for case in (perp if row["family"] == PERP else spot):
            trouble = compare_slice(harness, copy, case)
            if trouble:
                mismatches.append(trouble)
            spec = spec_slice(copy, case)
            name = "panic" if "stop" in spec else "order" if spec["tag"] == 1 else "reschedule" if spec["events"] and spec["events"][-1][0] == "advance" else "none"
            outcomes.append("slice %s %s" % (row["family"], name))
        for case in advances:
            trouble = compare_advance(harness, copy, case)
            if trouble:
                mismatches.append(trouble)
            spec = spec_advance(copy, case)
            events = [event[0] for event in spec["events"]]
            name = "panic" if "stop" in spec else "requeue" if "push" in events else "finish" if "copy" in events else "failed removal" if "drop failed" in events else "nothing"
            outcomes.append("advance %s" % name)
        for case in drains:
            trouble = compare_drain(harness, copy, case)
            if trouble:
                mismatches.append(trouble)
            spec = spec_drain(copy, case)
            outcomes.append("drain with rows" if spec["rows"] else "drain without rows")
    for entries in heaps:
        trouble = compare_heap(harness, 0, entries)
        if trouble:
            mismatches.append(trouble)
    seen = set(harness.machine.seen)
    steps = harness.machine.steps
    relative = harness.relative
    functions = []
    roles = (("drain", [row["drain"] for row in COPIES]), ("slice", [row["slice"] for row in COPIES]), ("advance", [row["advance"] for row in COPIES]),
             ("heap push", [HEAP_PUSH]), ("heap pop", [HEAP_POP]), ("round", [ROUND]), ("ceil", [CEIL]), ("floor", [FLOOR]))
    for role, starts in roles:
        for start in starts:
            begin, end = image.exact_fde(start)
            rows = decode_range(image, begin, end) if role in ("slice", "advance", "drain", "heap push", "heap pop") else []
            functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows),
                              "instructions_stepped": sum(1 for row in rows if row.va in seen)})
    called = [row[key] for row in COPIES for key in ("drain", "advance", "slice")] + [HEAP_PUSH, HEAP_POP]
    sites = direct_sites(image, called)
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    differences = []
    for key in ("slice", "advance"):
        differences += copy_differences(image, COPIES[0][key], COPIES[1][key])
        differences += copy_differences(image, COPIES[2][key], COPIES[3][key])
    drain_differences = []
    for index in range(1, 4):
        drain_differences += copy_differences(image, COPIES[0]["drain"], COPIES[index]["drain"])
    results = run_mutants(image, seen, verbose) if full else []
    tally = {key: sum(1 for row in results if row["result"] == key) for key in ("killed", "survived", "unreached")}
    text = code_reader(image)
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "copies": [{key: ("%#x" % value if isinstance(value, int) else value) for key, value in row.items()} for row in COPIES],
        "pairing": check_pairing(image),
        "other_advance_callers": ["%#x" % start for start in OTHER_ADVANCE_CALLERS],
        "constants": {"step_seconds": STEP_SECONDS, "jitter_modulus": JITTER_MODULUS, "catch_up_multiple": CATCH_UP, "significant_figures": SIG_FIGS,
                      "thresholds": THRESHOLDS, "finish_word": "%#x" % FINISH_WORD, "record_tag": RECORD_TAG,
                      "record_size": {key: "%#x" % value for key, value in RECORD_SIZE.items()}, "heap_entry": "%#x" % ENTRY_SIZE, "row": "%#x" % ROW_SIZE,
                      "slice_record": "%#x" % SLICE_SIZE, "market_stride": "%#x" % MARKET_STRIDE, "book_stride": "%#x" % BOOK_STRIDE,
                      "book_top_field": "%#x" % BOOK_TOP_FIELD, "divisor": DIVISOR},
        "float_constants": float_constants(image),
        "slots": {"%#x" % slot: "%#x" % relative[slot] for slot in (SLOT_ROUND, SLOT_FMA, SLOT_FLOOR, SLOT_CEIL, SLOT_SPOT_MID, SLOT_TIME_ADD, SLOT_DATE_ADD, SLOT_TIME_SUB, SLOT_DATE_SECS, SLOT_RECORDER)},
        "byte_pins": byte_pins(image),
        "locations": [{"slot": "%#x" % slot, "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                       "column": image.location(slot, relative)[2]} for slot in LOCATIONS],
        "strings": {"assert_a": text(ASSERT_A, ASSERT_A_SIZE).decode("ascii"), "assert_b": text(ASSERT_B, ASSERT_B_SIZE).decode("ascii"),
                    "expect": text(EXPECT_TEXT, EXPECT_SIZE).decode("ascii"), "unwrap": text(UNWRAP_TEXT, UNWRAP_SIZE).decode("ascii"),
                    "time_file_suffix": text(TIME_FILE, TIME_FILE_SIZE).decode("ascii").split("/l1/")[-1]},
        "order_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in ORDER_MAP],
        "slice_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in SLICE_MAP],
        "heap_entry_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in HEAP_ENTRY_MAP],
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"slice_perp": len(perp), "slice_spot": len(spot), "advance": len(advances), "drain": len(drains), "heap": len(heaps)},
        "outcomes": count_outcomes(outcomes),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "drain_copy_differences": len(drain_differences),
        "_sites": site_rows, "_differences": differences + drain_differences, "_results": results,
    }


def reason_for(row):
    if row["result"] == "survived":
        return EQUIVALENT.get(row["va"], "")
    if row["result"] == "unreached":
        for low, high, reason in UNREACHED_GROUPS:
            if low <= row["va"] < high:
                return reason
        return UNREACHED_SINGLE.get(row["va"], "")
    return ""


DEAD_PRODUCT = "floor(x / unit) * unit cannot overflow, so this overflow arm has no input"
DEAD_ASSERT = "ceil of a non-negative number is not negative, so the second assertion has no input"
DEAD_RECORDER = "a remainder below 0 is already 0 here, and a remainder of 0 skips this block"
UNREACHED_SINGLE = {0x4339F6F: DEAD_PRODUCT, 0x43375C5: DEAD_PRODUCT, 0x42EF88B: DEAD_ASSERT, 0x42F0A39: DEAD_ASSERT, 0x433735D: DEAD_RECORDER, 0x4337366: DEAD_RECORDER}


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    differences = evidence.pop("_differences")
    results = evidence.pop("_results")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\topcode\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row for row in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["first\tsecond\toffset\tfirst_row\tsecond_row"]
    lines += ["%#x\t%#x\t%#x\t%s\t%s" % (row["first"], row["second"], row["offset"], row["left"], row["right"]) for row in differences]
    files["copy_differences.tsv"] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], reason_for(row)) for row in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (folder / name).write_text(text, encoding="ascii", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder")
    options = parser.parse_args(argv)
    files = render(analyse(load_image()))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
