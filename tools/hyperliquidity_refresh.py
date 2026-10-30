#!/usr/bin/env python3
"""Pin the node #94 hyperliquidity order refresh `0x26cb280` and its level cursor, from ELF bytes.

`0x26cb280` runs inside the `hyperliquidity_ensure_orders` span. For each spot in the ladder tree it
reads a level cursor from the `0xff` user's base balance (`0x3263760`), walks the ladder down from
the cursor for one side and up for the other, skips levels that would cross the book, keeps a resting
order that already matches, and otherwise collects cancels and new order records, capped at 100 a
side. The real bytes of both functions run in a Python evaluator with only the edges stubbed, a
separately written specification predicts every edge call and every level byte, and every condition,
immediate and field offset is then flipped to show the run can tell. No objdump or readelf output is
parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
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

ENSURE = 0x26CB280
CURSOR = 0x3263760
SPAN = 0x22293C0
SPAN_SITE = 0x2229404
DRIVER = 0x26FED00
DRIVER_SITE = 0x26FEF91
CANCEL_ALL = 0x26E4240
CANCEL_ONE = 0x26DE280
PLACE = 0x26CC730
MAP_NEXT = 0x286ADA0
MAP_STEP = 0x1B263C0
MAP_END = 0x1EB3690

SLOT_CURSOR = 0x5774750
SLOT_GROW_ORDERS = 0x5774758
SLOT_GROW_CANCELS = 0x5774458
SLOT_LOOKUP = 0x5773170
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_MEMCPY = 0x576DFE0
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_NAMES = {SLOT_CURSOR: "level cursor of one ladder, run real", SLOT_GROW_ORDERS: "grow the order record vector, stubbed", SLOT_GROW_CANCELS: "grow the cancel id vector, stubbed",
              SLOT_LOOKUP: "user map lookup, stubbed", SLOT_FREE: "free, stubbed", SLOT_PANIC: "panic with Location", SLOT_BOUNDS: "index bounds panic"}

LOCATION_BOOKS = 0x56BB478
LOCATION_NAVIGATE = 0x56C23A0
LOCATION_UNWRAP = 0x56C23B8
LOCATION_FIRST = 0x56C5540
LOCATION_TAIL = 0x56C5528
LOCATION_WALK = 0x56C5570
LOCATION_PAIR = 0x56DF828
LOCATION_TOKEN = 0x56F21F0
LOCATION_DECIMALS = 0x56F2270
LOCATIONS = (LOCATION_BOOKS, LOCATION_NAVIGATE, LOCATION_UNWRAP, LOCATION_FIRST, LOCATION_TAIL, LOCATION_WALK, LOCATION_PAIR, LOCATION_TOKEN, LOCATION_DECIMALS)

COPY_LOCATIONS = {0x5733F20: LOCATION_TAIL, 0x5742338: LOCATION_BOOKS, 0x5733F50: LOCATION_FIRST, 0x571D2C0: LOCATION_NAVIGATE, 0x5733F98: LOCATION_WALK}

USER_TAIL = 0x206610
SPAN_NAME = 0x3EF968
SPAN_NAME_TEXT = b"hyperliquidity_ensure_orders"

SIDE_CAP = 100
LEVEL_SIZE = 0x18
VALUE_SIZE = 0x20
ORDER_SIZE = 0xD8
BOOK_STRIDE = 0xD8
SLOT_STRIDE = 0xF8
PAIR_STRIDE = 0x20
TOKEN_STRIDE = 0xE8
FILL_STRIDE = 0x228
NICHE = 1 << 63
FX = 0xF1357AEA2E62A9C5

FIELD_TIME = 0x60
FIELD_USER_MAP = 0x80
FIELD_PAIRS = 0x1F8
FIELD_TOKENS = 0x210
FIELD_SPOT_BOOKS = 0x3380
FIELD_LADDERS = 0x38D0

# B-tree node shapes: the ladder tree and the side tree of a book share one, the balance tree differs.
LADDER_NODE = dict(values=0, parent=0x160, keys=0x168, index=0x1C0, length=0x1C2, edges=0x1C8, size=0x228)
SIDE_NODE = LADDER_NODE
BALANCE_NODE = dict(keys=8, values=0x60, stride=0x18, length=0x16A, edges=0x170, size=0x1D0)

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
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 2000000
MUTANT_STEP_LIMIT = 200000
UNMAPPED = 0x7300000000

EX = HEAP_BASE + 0x1000
CONTEXT = EX + 0x3F00
BOOKS = EX + 0x4000
PAIRS = BOOKS + 16 * BOOK_STRIDE
TOKENS = PAIRS + 16 * PAIR_STRIDE
MAP_NODES = TOKENS + 8 * TOKEN_STRIDE
TAIL_NODES = MAP_NODES + 0x3000
GROW = TAIL_NODES + 0x400
BUMP = GROW + 0x40000
FF_USER = b"\xff" * 20
OUT = EX + 0x3E00

# The three copies of the refresh: same field offsets, each with its own callees and Locations.
COPIES = (
    dict(entry=ENSURE, cancel_all=CANCEL_ALL, cancel_one=CANCEL_ONE, place=PLACE, next=MAP_NEXT, step=MAP_STEP, end=MAP_END, locations={}),
    dict(entry=0x42D2790, cancel_all=0x43038B0, cancel_one=0x42F7290, place=0x42D5310, next=0x4948400, step=0x42BB520, end=None, locations=COPY_LOCATIONS),
    dict(entry=0x42D3D50, cancel_all=0x4303B30, cancel_one=0x42F7700, place=0x42D5650, next=0x4948400, step=0x42BB520, end=None, locations=COPY_LOCATIONS),
)

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
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


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
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
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
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xBC and rep:
            reg, rm = modrm()
            return finish("tzcnt", ("r", reg), rm, width)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
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
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
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
        self.jump_low = self.jump_high = 0

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
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            if not self.jump_low <= target < self.jump_high:
                raise Halt("indirect jump out of the function at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
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
        elif op in ("shl", "shr", "sar", "rol"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "shl":
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
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * at)) & 0xFF) | ((right >> (8 * at)) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = sum(((source >> (16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source >> 64) << 64 | words
        elif op == "pshufd":
            source = self.vector(row.b)
            self.xmm[row.a[1]] = sum(((source >> (32 * ((row.target >> (2 * at)) & 3))) & MASK[4]) << (32 * at) for at in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            bits = 8 * size
            self.xmm[row.a[1]] = sum((MASK[size] if (left >> at) & MASK[size] == (right >> at) & MASK[size] else 0) << at for at in range(0, 128, bits))
        elif op == "pmovmskb":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, sum(((source >> (8 * at + 7)) & 1) << at for at in range(16)))
        elif op == "tzcnt":
            value = self.get(row.b, row.width)
            result = 8 * row.width if value == 0 else (value & -value).bit_length() - 1
            self.cf = value == 0
            self.zf = result == 0
            self.put(row.a, row.width, result)
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



# ---- specification, written from the reading and never from a run ----

def days_from_epoch(year, ordinal):
    """Days from 1970-01-01 to an ordinal date, proleptic Gregorian, any sign of year."""
    shift = 0
    while year <= 0:
        year += 400
        shift -= 146097
    previous = year - 1
    return previous * 365 + previous // 4 - previous // 100 + previous // 400 + ordinal - 1 - 719162 + shift


def pack_date(year, ordinal, flags=0xA):
    return ((year << 13) | (ordinal << 4) | flags) & MASK[4]


def time_millis(moment):
    """The time word as whole non-negative milliseconds."""
    word, seconds, nanos = moment
    signed = word - (1 << 32) if word & SIGN[4] else word
    days = days_from_epoch(signed >> 13, (word >> 4) & 0x1FF)
    total = (days * 86400 + seconds) * 1000 + nanos // 1000000
    return total if total > 0 else 0


class Level:
    """One ladder level: a tag word, the resting order id when the tag is 1, and the price."""

    def __init__(self, tag, oid, price):
        self.tag, self.oid, self.price = tag, oid, price

    def pack(self):
        return struct.pack("<QQQ", self.tag, self.oid, self.price)


class Ladder:
    def __init__(self, key=0, prices=(), order_size=1000, levels=None, none=False, capacity=None):
        self.key, self.order_size, self.none = key, order_size, none
        self.levels = levels if levels is not None else [Level(0, 0x7777, price) for price in prices]
        self.capacity = len(self.levels) + 3 if capacity is None else capacity


class Slot:
    """One slab slot of a book: tag 2 is vacant."""

    def __init__(self, tag=1, side=0, size=1000, user=FF_USER):
        self.tag, self.side, self.size, self.user = tag, side, size, user


class Book:
    """A book: first keys of the side trees, the slab, and the id table.

    `rows` is a list of (order id, slab index); `crowd` fills that many probe groups in front of each
    key and `decoys` puts same-hash-byte strangers in front of it.
    """

    def __init__(self, bid=None, ask=None, slots=(), rows=(), crowd=0, decoys=0, items=None, hidden=0):
        self.bid, self.ask, self.slots, self.rows = bid, ask, list(slots), list(rows)
        self.crowd, self.decoys, self.hidden = crowd, decoys, hidden
        self.items = len(self.rows) if items is None else items


def side_magnitude(shape):
    """The magnitude of the first key, 0 for none; `None` means the walk panics."""
    if shape is None or shape == "empty":
        return 0
    if shape == "orphan":
        return None
    key = shape[1] if isinstance(shape, tuple) else shape
    return abs(key) & MASK[8]


DEFAULT_TOKENS = ((3, 8), (0, 6), (8, 8), (2, 18))
DEFAULT_PAIRS = ((0, 1), (2, 1), (1, 2), (0, 0), (2, 0), (3, 3), (1, 3), (0, 3))
NOW = (pack_date(2026, 303), 45296, 789000000)


class Case:
    def __init__(self, label, ladders, shape="flat", claimed=None, books=None, pairs=DEFAULT_PAIRS, tokens=DEFAULT_TOKENS, now=NOW, balances=(), balance_depth=0,
                 places=None, header=True, book_count=None, cursor=None):
        self.label, self.ladders, self.shape = label, ladders, shape
        self.claimed = len(ladders) if claimed is None else claimed
        self.books = books if books is not None else {}
        self.pairs, self.tokens, self.now = pairs, tokens, now
        self.balances, self.balance_depth = balances, balance_depth
        self.places = places or {}
        self.header = header
        self.book_count = 8 if book_count is None else book_count
        self.cursor = cursor


class SpecPanic(Exception):
    pass


def spec_power(difference):
    """10 ** difference, or None where the bytes panic."""
    if difference >= 32:
        return None
    value = 10 ** difference
    return value if value <= MASK[8] else None


def spec_balance(rows, token):
    for key, value in rows:
        if key == token:
            return value
    return 0


def spec_cursor(case, ladder, spot, events):
    """The cursor helper: (level index, partial flag, remainder), in the order the bytes check."""
    if spot >= len(case.pairs):
        raise SpecPanic(("bounds", spot, len(case.pairs), LOCATION_PAIR))
    token = case.pairs[spot][0]
    events.append(("lookup", EX + FIELD_USER_MAP, FF_USER.hex()))
    balance = spec_balance(case.balances, token)
    if token >= len(case.tokens):
        raise SpecPanic(("panic", LOCATION_TOKEN))
    low, high = case.tokens[token]
    if high < low:
        raise SpecPanic(("panic", LOCATION_DECIMALS))
    scale = spec_power(high - low)
    if scale is None:
        raise SpecPanic(("panic", LOCATION_DECIMALS))
    count = len(ladder.levels)
    if ladder.order_size == 0:
        return count, 0, None
    whole, remainder = divmod(balance // scale, ladder.order_size)
    index = max(count - whole, 0)
    if remainder == 0:
        return index, 0, 0
    return (index - 1 if count > whole else 0), 1, remainder


def table_slot(book, oid):
    """The slab slot the id table gives for an order id, or None."""
    if not book.items:
        return None
    for key, index in book.rows:
        if key == oid:
            return index if index < len(book.slots) - book.hidden else None
    return None


class State:
    def __init__(self):
        self.position = -1
        self.grow_at = GROW


def grow(state, capacity, element):
    new = 4 if capacity == 0 else capacity * 2
    at = state.grow_at
    state.grow_at += (new * element + 15) & ~15
    return new, at


def order_fields(size, price, millis, side, stale):
    return ((0x00, 1), (0x08, size), (0x10, 0), (0x20, 0), (0x30, 0), (0x38, 8), (0x40, 0), (0x48, 0), (0x70, 0), (0x80, price), (0x88, millis),
            (0xA8, 0), (0xB0, stale))


def spec_ladder(case, ladder, events, state):
    if ladder.none:
        return
    if ladder.key >= case.book_count:
        raise SpecPanic(("panic", LOCATION_BOOKS))
    book_at = BOOKS + ladder.key * BOOK_STRIDE
    book = case.books.get(ladder.key, DEFAULT_BOOK)
    levels = ladder.levels
    if levels and levels[0].price == levels[-1].price:
        events.append(("cancel all", book_at, FF_USER.hex(), 1, EX, CONTEXT, 2))
        return
    millis = time_millis(case.now)
    if case.cursor is not None:
        index, partial, remainder = case.cursor
        events.append(("cursor", ladder.key))
    else:
        index, partial, remainder = spec_cursor(case, ladder, ladder.key, events)
    count_levels = len(levels)
    cancels, orders = [], []
    cancel_cap, order_cap, cancel_at, order_at = 0, 0, 8, 8

    def take(level_index, size, price, side):
        nonlocal order_cap, order_at
        if len(orders) == order_cap:
            events.append(("grow orders", order_cap))
            order_cap, order_at = grow(state, order_cap, ORDER_SIZE)
        orders.append((level_index, size, price, side))

    def drop(oid):
        nonlocal cancel_cap, cancel_at
        if len(cancels) == cancel_cap:
            events.append(("grow cancels", cancel_cap))
            cancel_cap, cancel_at = grow(state, cancel_cap, 8)
        cancels.append(oid)

    for side in (0, 1):
        for shape in (book.bid, book.ask):
            if side_magnitude(shape) is None:
                raise SpecPanic(("panic", LOCATION_FIRST))
        opposite = side_magnitude(book.bid if side else book.ask)
        placed, offset = 0, 0
        while True:
            if side:
                at = min(index + offset, MASK[8])
            else:
                at = index - offset - 1
                if at < 0:
                    break
            if at >= count_levels:
                break
            level = levels[at]
            if opposite and (level.price <= opposite if side else level.price >= opposite):
                offset += 1
                continue
            size = ladder.order_size
            if side and offset == 0 and partial:
                size = remainder
            place = placed < SIDE_CAP
            if level.tag & MASK[4] == 1:
                slot_index = table_slot(book, level.oid)
                slot = book.slots[slot_index] if slot_index is not None else None
                if slot is not None and slot.tag & MASK[4] != 2 and slot.user == FF_USER:
                    if slot.side == side and placed < SIDE_CAP and slot.size == size:
                        place = False
                    else:
                        drop(level.oid)
            elif not place:
                break
            if place:
                take(at, size, level.price, side)
            placed += 1
            offset += 1
    for oid in cancels:
        events.append(("cancel one", book_at, FF_USER.hex(), oid, EX, CONTEXT, 2))
    if cancel_cap:
        events.append(("free", cancel_at, cancel_cap * 8, 0))
    for level_index, size, price, side in orders:
        events.append(("memcpy", 8, 8, 0))
        state.position += 1
        events.append(("place", book_at, EX, CONTEXT, order_fields(size, price, millis, side, index), side, FF_USER.hex()))
        kind = case.places.get(state.position, DEFAULT_PLACE)
        if kind.failed:
            continue
        levels[level_index].tag = 1
        levels[level_index].oid = PLACED_ID + state.position
        if kind.fills:
            events.append(("free", UNMAPPED + state.position, kind.fills * FILL_STRIDE, 0))
        spec_result_map(kind, state, events)
    if order_cap:
        events.append(("free", order_at, order_cap * ORDER_SIZE, 0))


class PlaceResult:
    """What the stubbed place returns: fills, map rows, and how the map walk ends."""

    def __init__(self, failed=False, fills=0, rows=None, lazy=None, untag=False, step_none=False, tail=None):
        self.failed, self.fills, self.rows, self.lazy = failed, fills, rows, lazy
        self.untag, self.step_none, self.tail = untag, step_none, tail


DEFAULT_PLACE = PlaceResult()
PLACED_ID = 0x900000
ROW_POINTER = UNMAPPED + 0x1000


def spec_result_map(kind, state, events):
    rows = kind.rows
    tag = 1 if rows is not None else 0
    events.append(("map walk", tag, len(rows) if rows else 0))
    if not rows:
        return
    for at, capacity in enumerate(rows):
        if capacity:
            events.append(("free", ROW_POINTER + at, capacity * 8, 0))
        if at == len(rows) - 1:
            break
        if kind.untag:
            raise SpecPanic(("panic", LOCATION_WALK))
        if at == 0:
            events.append(("map step", MAP_FRONT if kind.lazy is None else MAP_NODES + kind.lazy * 0x300, 0, 0))
        else:
            events.append(("map step", MAP_FRONT, FRONT_HEIGHT, FRONT_INDEX))
        if kind.step_none:
            raise SpecPanic(("panic", LOCATION_TAIL))
    events.append(("map end",))
    if kind.tail:
        height, count = kind.tail
        for at in range(count):
            events.append(("free", TAIL_NODES + at * 0x10, 0x1F0 if height + at == 0 else 0x250, 0))


MAP_FRONT = MAP_NODES + 0x2000
FRONT_HEIGHT = 5
FRONT_INDEX = 6
DEFAULT_BOOK = Book(-2500000, 2510000)


def spec_run(case):
    events = []
    state = State()
    stop = None
    if case.header and case.claimed:
        try:
            for at in range(case.claimed):
                if at >= len(case.ladders):
                    raise SpecPanic(("panic", LOCATION_NAVIGATE))
                spec_ladder(case, case.ladders[at], events, state)
        except SpecPanic as caught:
            stop = caught.args[0]
    return {"events": events, "levels": [[level.pack() for level in ladder.levels] for ladder in case.ladders], "stop": stop}


def uses_result_map(case):
    """The copies inline the end of the map drop, so only the first copy runs these cases."""
    return any(kind.rows for kind in case.places.values())


def copy_case(case):
    """Spec and run must not share level objects: the specification writes the placed ids."""
    twin = Case.__new__(Case)
    twin.__dict__.update(case.__dict__)
    twin.ladders = []
    for ladder in case.ladders:
        other = Ladder(ladder.key, (), ladder.order_size, [Level(l.tag, l.oid, l.price) for l in ladder.levels], ladder.none, ladder.capacity)
        twin.ladders.append(other)
    return twin


# ---- harness: real bytes, edges stubbed, every edge argument recorded ----

HEAP_ALLOC = BUMP + 0x100000


def rotate20(value):
    value &= MASK[8]
    return ((value << 20) | (value >> 44)) & MASK[8]


def id_hash(oid):
    return rotate20((oid * FX) & MASK[8])


class Harness:
    def __init__(self, image):
        self.image = image
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        machine = Machine(image)
        self.machine = machine
        machine.real = frozenset((CURSOR,))
        for slot in (SLOT_CURSOR, SLOT_GROW_ORDERS, SLOT_GROW_CANCELS, SLOT_LOOKUP, SLOT_FREE, SLOT_ALLOC, SLOT_ALLOC_FAILED, SLOT_PANIC, SLOT_BOUNDS):
            machine.memory.statics[slot] = self.relative[slot]
        # memcpy is a dynamic symbol slot, so it gets a harness address.
        machine.memory.statics[SLOT_MEMCPY] = UNMAPPED + 0x40
        machine.slots = {
            self.relative[SLOT_CURSOR]: self.on_cursor, self.relative[SLOT_GROW_ORDERS]: self.on_grow_orders, self.relative[SLOT_GROW_CANCELS]: self.on_grow_cancels,
            self.relative[SLOT_LOOKUP]: self.on_lookup, self.relative[SLOT_FREE]: self.on_free, self.relative[SLOT_ALLOC]: self.on_alloc,
            self.relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed, self.relative[SLOT_PANIC]: self.on_panic, self.relative[SLOT_BOUNDS]: self.on_bounds,
            UNMAPPED + 0x40: self.on_memcpy}
        self.select(COPIES[0])
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.grow_at = GROW
        self.events = []
        self.case = None
        self.position = -1
        self.lookup_at = 0

    def select(self, copy):
        """Point the stubs at one of the three copies of the refresh."""
        self.copy = copy
        self.machine.calls = {copy["cancel_all"]: self.on_cancel_all, copy["cancel_one"]: self.on_cancel_one, copy["place"]: self.on_place,
                              copy["next"]: self.on_map_next, copy["step"]: self.on_map_step}
        if copy["end"]:
            self.machine.calls[copy["end"]] = self.on_map_end

    # layout helpers

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_ALLOC:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value & MASK.get(width, (1 << (8 * width)) - 1))

    def fresh(self):
        self.machine.memory.reset(self.top)
        self.top = HEAP_ALLOC - HEAP_BASE
        self.bump = BUMP
        self.grow_at = GROW
        self.events = []
        self.position = -1

    def node(self, parent, slot, rows):
        at = self.alloc(LADDER_NODE["size"])
        self.put(at + LADDER_NODE["parent"], 8, parent)
        self.put(at + LADDER_NODE["index"], 2, slot)
        self.put(at + LADDER_NODE["length"], 2, len(rows))
        for index, ladder in enumerate(rows):
            self.put(at + LADDER_NODE["keys"] + index * 8, 8, ladder.key)
            value = at + index * VALUE_SIZE
            self.put(value, 8, NICHE if ladder.none else ladder.capacity)
            levels = self.alloc(len(ladder.levels) * LEVEL_SIZE + 8)
            self.put(value + 8, 8, levels)
            self.put(value + 0x10, 8, len(ladder.levels))
            self.put(value + 0x18, 8, ladder.order_size)
            for row, level in enumerate(ladder.levels):
                self.machine.memory.put_bytes(levels + row * LEVEL_SIZE, level.pack())
            self.placed.append((ladder, levels))
        for index in range(12):
            self.put(at + LADDER_NODE["edges"] + index * 8, 8, UNMAPPED)
        return at

    def link(self, parent, slot, child):
        self.put(parent + LADDER_NODE["edges"] + slot * 8, 8, child)
        self.put(child + LADDER_NODE["parent"], 8, parent)
        self.put(child + LADDER_NODE["index"], 2, slot)

    def spine(self, height, rows):
        """A chain of `height` keyless nodes above one leaf; returns the top."""
        node = self.node(0, 0, rows)
        for _ in range(height):
            top = self.node(0, 0, ())
            self.link(top, 0, node)
            node = top
        return node

    def build_tree(self, case):
        self.placed = []
        rows = case.ladders
        shape = case.shape
        if shape == "flat":
            root = self.node(0, 0, rows)
            height = 0
        elif shape == "two":
            root = self.node(0, 0, rows[1:2] + rows[3:4])
            self.link(root, 0, self.node(root, 0, rows[:1]))
            self.link(root, 1, self.node(root, 1, rows[2:3]))
            self.link(root, 2, self.node(root, 2, rows[4:]))
            height = 1
        else:
            height = shape
            root = self.node(0, 0, rows[1:2])
            self.link(root, 0, self.spine(height - 1, rows[:1]))
            self.link(root, 1, self.spine(height - 1, rows[2:]))
        base = EX + FIELD_LADDERS
        self.put(base + 0x10, 8, root if case.header else 0)
        self.put(base + 0x18, 8, height)
        self.put(base + 0x20, 8, case.claimed)

    def side_tree(self, base, shape):
        """One side tree: None, "empty", "orphan", a key, ("deep", key, depth) or ("up", key, depth)."""
        if shape is None:
            self.put(base, 8, 0)
            self.put(base + 8, 8, 0)
            self.put(base + 0x10, 8, 0)
            return
        kind, key, depth = shape if isinstance(shape, tuple) else ("deep", shape, 0)
        nodes = [self.alloc(SIDE_NODE["size"]) for _ in range(depth + 1)]
        for index, node in enumerate(nodes):
            for edge in range(12):
                self.put(node + SIDE_NODE["edges"] + edge * 8, 8, UNMAPPED)
            self.put(node + SIDE_NODE["length"], 2, 0)
            # An unused key slot holds a tempting value, so a wrong length reads as a hit.
            self.put(node + SIDE_NODE["keys"], 8, 0x123456)
            self.put(node + SIDE_NODE["parent"], 8, nodes[index - 1] if index else 0)
            self.put(node + SIDE_NODE["index"], 2, 0)
            if index:
                self.put(nodes[index - 1] + SIDE_NODE["edges"], 8, node)
        if shape == "empty":
            self.put(base, 8, nodes[0])
            self.put(base + 8, 8, 0)
            self.put(base + 0x10, 8, 0)
            return
        if shape == "orphan":
            self.put(base, 8, nodes[0])
            self.put(base + 8, 8, 0)
            self.put(base + 0x10, 8, 1)
            return
        holder = nodes[-1] if kind == "deep" else nodes[0]
        self.put(holder + SIDE_NODE["length"], 2, 1)
        self.put(holder + SIDE_NODE["keys"], 8, key)
        self.put(base, 8, nodes[0])
        self.put(base + 8, 8, depth)
        self.put(base + 0x10, 8, 1)

    def build_table(self, base, book):
        rows = book.rows
        capacity = 64 if len(rows) <= 16 else 1024
        mask = capacity - 1
        block = self.alloc(capacity * 0x10 + capacity + 16)
        ctrl = block + capacity * 0x10
        memory = self.machine.memory
        memory.put_bytes(ctrl, b"\xff" * (capacity + 16))
        used = set()

        def fill(index, byte, key, value):
            used.add(index)
            self.put(ctrl + index, 1, byte)
            if index < 16:
                self.put(ctrl + capacity + index, 1, byte)
            self.put(ctrl - (index + 1) * 0x10, 8, key)
            self.put(ctrl - (index + 1) * 0x10 + 8, 8, value)

        for oid, value in rows:
            full = id_hash(oid)
            top = full >> 57
            at = full & mask
            stride = 0
            for _ in range(book.crowd):
                for step in range(16):
                    fill((at + step) & mask, 0x11 if top != 0x11 else 0x12, oid + 1 + step, 0x3F3F)
                at = (at + stride + 16) & mask
                stride += 16
            for step in range(book.decoys):
                fill((at + step) & mask, top, oid ^ (0x1000 + step), 0x3E3E)
            at = (at + book.decoys) & mask
            while at in used:
                at = (at + 1) & mask
            fill(at, top, oid, value)
        self.put(base + 0x28, 8, ctrl)
        self.put(base + 0x30, 8, mask)
        self.put(base + 0x40, 8, book.items)

    def build_book(self, index, book):
        base = BOOKS + index * BOOK_STRIDE
        self.side_tree(base + 0x80, book.bid)
        self.side_tree(base + 0x98, book.ask)
        slab = self.alloc(max(len(book.slots), 1) * SLOT_STRIDE)
        self.put(base + 8, 8, slab)
        self.put(base + 0x10, 8, len(book.slots) - book.hidden)
        for row, slot in enumerate(book.slots):
            at = slab + row * SLOT_STRIDE
            self.put(at, 4, slot.tag)
            self.put(at + 0xC2, 1, slot.side)
            self.put(at + 0xC8, 8, slot.size)
            self.machine.memory.put_bytes(at + 0xE0, slot.user)
        self.build_table(base, book)

    def balance_tree(self, rows, depth):
        """A balance tree; depth 1 spreads the keys over one root and two leaves."""
        rows = sorted(rows)

        def node(items):
            at = self.alloc(BALANCE_NODE["size"])
            self.put(at + BALANCE_NODE["length"], 2, len(items))
            for index, (key, value) in enumerate(items):
                self.put(at + BALANCE_NODE["keys"] + index * 8, 8, key)
                self.put(at + BALANCE_NODE["values"] + index * BALANCE_NODE["stride"], 8, value)
            # Slots past the length hold a tempting key, so a wrong length reads as a hit.
            for index in range(len(items), 11):
                self.put(at + BALANCE_NODE["keys"] + index * 8, 8, 1)
                self.put(at + BALANCE_NODE["values"] + index * BALANCE_NODE["stride"], 8, 1 << 50)
            return at
        if not depth or len(rows) < 3:
            return node(rows), 0
        middle = len(rows) // 2
        root = node(rows[middle:middle + 1])
        self.put(root + BALANCE_NODE["edges"], 8, node(rows[:middle]))
        self.put(root + BALANCE_NODE["edges"] + 8, 8, node(rows[middle + 1:]))
        return root, 1

    def lookup_record(self, rows, depth):
        record = self.alloc(0x20)
        if rows:
            root, height = self.balance_tree(rows, depth)
            self.put(record + 0x10, 8, root)
            self.put(record + 0x18, 8, height)
        else:
            self.put(record + 0x10, 8, 0)
            self.put(record + 0x18, 8, 0)
        return record

    def build_meta(self, case):
        put = self.put
        for at, value in zip((0, 4, 8), case.now):
            put(EX + FIELD_TIME + at, 4, value)
        put(EX + FIELD_PAIRS, 8, PAIRS)
        put(EX + FIELD_PAIRS + 8, 8, len(case.pairs))
        put(EX + FIELD_TOKENS, 8, TOKENS)
        put(EX + FIELD_TOKENS + 8, 8, len(case.tokens))
        for index, (base, quote) in enumerate(case.pairs):
            put(PAIRS + index * PAIR_STRIDE, 8, base)
            put(PAIRS + index * PAIR_STRIDE + 8, 8, quote)
        for index, (first, second) in enumerate(case.tokens):
            put(TOKENS + index * TOKEN_STRIDE + 0x48, 1, first)
            put(TOKENS + index * TOKEN_STRIDE + 0x49, 1, second)
        self.lookup_at = self.lookup_record(case.balances, case.balance_depth)

    # stubs

    def on_cursor(self, m):
        self.events.append(("cursor", m.regs[RDX]))
        index, partial, remainder = self.case.cursor
        out = m.regs[RDI]
        self.put(out, 8, index)
        self.put(out + 8, 8, partial)
        self.put(out + 0x10, 8, remainder)

    def grow(self, m, name, element):
        vec = m.regs[RDI]
        capacity = m.memory.read(vec, 8)
        pointer = m.memory.read(vec + 8, 8)
        if not capacity and pointer != 8:
            raise Halt("empty vector pointer")
        self.events.append((name, capacity))
        new = 4 if capacity == 0 else capacity * 2
        at = self.grow_at
        self.grow_at += (new * element + 15) & ~15
        if self.grow_at > BUMP:
            raise Halt("grow region too small")
        if capacity:
            m.memory.copy(at, pointer, capacity * element)
        self.put(vec, 8, new)
        self.put(vec + 8, 8, at)

    def on_grow_orders(self, m):
        self.grow(m, "grow orders", ORDER_SIZE)

    def on_grow_cancels(self, m):
        self.grow(m, "grow cancels", 8)

    def on_lookup(self, m):
        self.events.append(("lookup", m.regs[RDI], m.memory.bytes_at(m.regs[RSI], 20).hex()))
        m.regs[RAX] = self.lookup_at

    def on_cancel_all(self, m):
        self.events.append(("cancel all", m.regs[RDI], m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX] & 0xFF, m.regs[RCX], m.regs[R8], m.regs[R9] & MASK[4]))

    def on_cancel_one(self, m):
        self.events.append(("cancel one", m.regs[RDI], m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX], m.regs[RCX], m.regs[R8], m.regs[R9] & MASK[4]))

    def on_memcpy(self, m):
        self.events.append(("memcpy", m.regs[RDI], m.regs[RSI], m.regs[RDX]))
        m.regs[RAX] = m.regs[RDI]

    def on_place(self, m):
        self.position += 1
        record = m.regs[RSI]
        read = m.memory.read
        fields = tuple((at, read(record + at, 8)) for at, _ in order_fields(0, 0, 0, 0, 0))
        # The two bytes +0x90, +0x91 and the byte +0xcc are 0 in every record; the side is the only other byte.
        if read(record + 0x90, 2) or read(record + 0xCC, 1):
            raise Halt("record flag bytes")
        self.events.append(("place", m.regs[RDX], m.regs[RCX], m.regs[R8], fields, read(record + 0xA2, 1), m.memory.bytes_at(record + 0xB8, 20).hex()))
        out = m.regs[RDI]
        kind = self.case.places.get(self.position, DEFAULT_PLACE)
        self.kind = kind
        if kind.failed:
            self.put(out, 8, NICHE)
            self.put(out + 8, 8, 0x41)
            return
        self.put(out, 8, kind.fills)
        self.put(out + 8, 8, UNMAPPED + self.position)
        self.put(out + 0x10, 8, 0)
        root = MAP_NODES if kind.lazy is not None else UNMAPPED + 0x800
        height = kind.lazy if kind.lazy is not None else 7
        self.put(out + 0x18, 8, root if kind.rows is not None else 0)
        self.put(out + 0x20, 8, height)
        self.put(out + 0x28, 8, len(kind.rows) if kind.rows else 0)
        self.put(out + 0x30, 8, PLACED_ID + self.position)
        if kind.lazy is not None:
            for at in range(kind.lazy):
                self.put(MAP_NODES + at * 0x300 + 0x1F0, 8, MAP_NODES + (at + 1) * 0x300)
        self.map_at = 0
        self.map_first = True
        self.map_root = root
        self.map_height = height
        m.regs[RAX] = out

    def on_map_next(self, m):
        walker = m.regs[RSI]
        kind = self.kind
        read = m.memory.read
        tag, other, size = read(walker, 8), read(walker + 0x20, 8), read(walker + 0x40, 8)
        if tag != other:
            raise Halt("map walker tags differ")
        if tag:
            shape = (read(walker + 8, 8), read(walker + 0x10, 8), read(walker + 0x18, 8), read(walker + 0x28, 8), read(walker + 0x30, 8), read(walker + 0x38, 8))
            if shape != (0, self.map_root, self.map_height, 0, self.map_root, self.map_height):
                raise Halt("map walker fields")
        self.events.append(("map walk", tag, size))
        out = m.regs[RDI]
        if not kind.rows:
            self.put(out, 8, 0)
            return
        self.put(walker + 0x40, 8, size - 1)
        if kind.lazy is None:
            self.put(walker + 8, 8, MAP_FRONT)
            self.put(walker + 0x10, 8, 0)
            self.put(walker + 0x18, 8, 0)
        if kind.untag:
            self.put(walker, 8, 0)
        self.emit_row(out)

    def emit_row(self, out):
        rows = self.kind.rows
        node = self.alloc(0x210)
        at = self.map_at * 0x18
        self.put(node + at + 8, 8, rows[self.map_at])
        self.put(node + at + 0x10, 8, ROW_POINTER + self.map_at)
        self.put(out, 8, node)
        self.put(out + 8, 8, 0)
        self.put(out + 0x10, 8, self.map_at)
        self.map_at += 1

    def on_map_step(self, m):
        walker = m.regs[RSI]
        read = m.memory.read
        self.events.append(("map step", read(walker, 8), read(walker + 8, 8), read(walker + 0x10, 8)))
        out = m.regs[RDI]
        if self.kind.step_none:
            self.put(out, 8, 0)
            return
        self.put(out, 8, MAP_FRONT)
        self.put(out + 8, 8, FRONT_HEIGHT)
        self.put(out + 0x10, 8, FRONT_INDEX)
        self.emit_row(out + 0x18)

    def on_map_end(self, m):
        self.events.append(("map end",))
        out = m.regs[RDI]
        tail = self.kind.tail
        if not tail:
            self.put(out, 8, 0)
            return
        height, count = tail
        for at in range(count):
            self.put(TAIL_NODES + at * 0x10, 8, TAIL_NODES + (at + 1) * 0x10 if at + 1 < count else 0)
        self.put(out, 8, TAIL_NODES)
        self.put(out + 8, 8, height)

    def on_free(self, m):
        self.events.append(("free", m.regs[RDI], m.regs[RSI], m.regs[RDX] & MASK[8]))

    def on_alloc(self, m):
        raise Halt("allocation in a path no record reaches")

    def on_alloc_failed(self, m):
        raise Panicked(("alloc failed", m.regs[RDI], m.regs[RSI]))

    def on_panic(self, m):
        raise Panicked(("panic", self.copy["locations"].get(m.regs[RDI], m.regs[RDI])))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    # runs

    def run(self, case):
        self.fresh()
        self.case = case
        self.machine.real = frozenset() if case.cursor is not None else frozenset((CURSOR,))
        self.build_tree(case)
        put = self.put
        put(EX + FIELD_SPOT_BOOKS + 8, 8, BOOKS)
        put(EX + FIELD_SPOT_BOOKS + 0x10, 8, case.book_count)
        self.build_meta(case)
        for index in range(min(case.book_count, 12)):
            self.build_book(index, case.books.get(index, DEFAULT_BOOK))
        self.top = self.bump - HEAP_BASE
        stop = None
        machine = self.machine
        try:
            machine.run(self.copy["entry"], {RDI: EX + FIELD_LADDERS, RSI: EX + FIELD_SPOT_BOOKS, RDX: EX, RCX: CONTEXT})
        except Panicked as caught:
            stop = caught.args[0]
        self.top = max(self.top, self.bump - HEAP_BASE)
        rows = {id(ladder): at for ladder, at in self.placed}
        levels = [[machine.memory.bytes_at(rows[id(ladder)] + row * LEVEL_SIZE, LEVEL_SIZE) for row in range(len(ladder.levels))] for ladder in case.ladders]
        return {"events": self.events, "levels": levels, "stop": stop}

    def run_cursor(self, case):
        """The helper alone, on the first ladder of a case with spot = its key."""
        self.fresh()
        self.case = case
        self.machine.real = frozenset((CURSOR,))
        self.build_meta(case)
        ladder = case.ladders[0]
        value = self.alloc(VALUE_SIZE)
        self.put(value + 0x10, 8, len(ladder.levels))
        self.put(value + 0x18, 8, ladder.order_size)
        self.top = self.bump - HEAP_BASE
        machine = self.machine
        try:
            returned = machine.run(CURSOR, {RDI: OUT, RSI: value, RDX: ladder.key, RCX: EX + FIELD_USER_MAP})
        except Panicked as caught:
            return {"stop": caught.args[0], "events": self.events, "out": None}
        read = machine.memory.read
        flag = read(OUT + 8, 8)
        return {"stop": None, "events": self.events, "out": (read(OUT, 8), flag, read(OUT + 0x10, 8) if flag else None), "returned": returned}


def compare_run(harness, case):
    twin = copy_case(case)
    expected = spec_run(twin)
    try:
        actual = harness.run(case)
    except (Halt, EvidenceError, IndexError, KeyError, ZeroDivisionError) as caught:
        return "%s: crash %s" % (case.label, caught)
    for key in ("stop", "events", "levels"):
        if actual[key] != expected[key]:
            return "%s: %s differs" % (case.label, key)
    return None


def spec_cursor_run(case):
    ladder = case.ladders[0]
    events = []
    try:
        index, partial, remainder = spec_cursor(case, ladder, ladder.key, events)
    except SpecPanic as caught:
        return {"stop": caught.args[0], "events": events, "out": None}
    return {"stop": None, "events": events, "out": (index, partial, remainder if partial else None)}


def compare_cursor(harness, case):
    expected = spec_cursor_run(case)
    try:
        actual = harness.run_cursor(case)
    except (Halt, EvidenceError, IndexError, KeyError, ZeroDivisionError) as caught:
        return "%s: crash %s" % (case.label, caught)
    for key in ("stop", "events", "out"):
        if actual[key] != expected[key]:
            return "%s: %s differs" % (case.label, key)
    if expected["out"] is not None and actual["returned"] != OUT:
        return "%s: returned value differs" % case.label
    return None


# ---- cases ----

# Spot 0's base token 0 has weiDecimals 8, szDecimals 3 in DEFAULT_TOKENS, so one size unit is 1e5 wei.
UNIT = 100000
PRICES = tuple(1000 + 40 * at for at in range(10))


def balance_for(whole, part=0, size=1000):
    return ((0, (whole * size + part) * UNIT),)


def ladder_case(label, whole=3, part=0, prices=PRICES, size=1000, book=None, levels=None, **options):
    ladder = Ladder(0, prices, size, levels)
    books = {0: book} if book is not None else None
    options.setdefault("balances", balance_for(whole, part, size))
    return Case(label, [ladder], books=books, **options)


def resting(*rows):
    """Levels from (tag, id, price) rows."""
    return [Level(tag, oid, price) for tag, oid, price in rows]


def run_cases():
    cases = []
    add = cases.append
    add(Case("no root", [Ladder(0, PRICES)], header=False))
    add(Case("zero claimed", [Ladder(0, PRICES)], claimed=0))
    for whole in (0, 1, 3, 9, 10, 11):
        add(ladder_case("whole levels %d" % whole, whole))
    for whole, part in ((0, 1), (3, 1), (3, 999), (9, 500), (10, 7), (11, 7), (25, 3)):
        add(ladder_case("partial %d + %d" % (whole, part), whole, part))
    add(ladder_case("wei below one size unit is dropped", 3, balances=((0, 3000 * UNIT + UNIT - 1),)))
    add(ladder_case("one wei short of a unit, whole below", 2, balances=((0, 3000 * UNIT - 1),)))
    add(ladder_case("no balance row", 0, balances=()))
    add(ladder_case("other token only", 0, balances=((1, 1 << 40),)))
    add(ladder_case("order size 0", 3, size=0, balances=((0, 1 << 40),)))
    add(ladder_case("empty ladder", 0, prices=()))
    add(ladder_case("one level: first equals last", 0, prices=(1000,)))
    add(ladder_case("first equals last, many levels", 3, levels=resting((1, 5, 700), (0, 0, 900), (0, 0, 700))))
    add(ladder_case("first and last differ by one", 1, prices=(1000, 1001)))
    add(ladder_case("first and last differ high bits", 1, levels=resting((0, 0, 1000), (0, 0, (1 << 40) + 1000))))
    # Crossing: the ask side walks up past bids, the bid side walks down past asks.
    for bid, ask, label in ((None, None, "empty book"), ("empty", "empty", "keyless roots"), (-1100, 1120, "inside"), (-1120, 1120, "bid on a level"), (-1121, 1200, "bid above a level"),
                            (-5000, 6000, "bid above all"), (-1, 1000, "ask at the first"), (-1, 999, "ask below all"), (-1, 1001, "ask just above first"), (1100, 1120, "positive bid key"),
                            (-1100, -1120, "negative ask key")):
        add(ladder_case("book: %s" % label, 5, book=Book(bid, ask)))
        add(ladder_case("book, partial: %s" % label, 5, 11, book=Book(bid, ask)))
    add(ladder_case("minimum key", 5, book=Book(-(1 << 63), 1200)))
    add(ladder_case("keyless roots, prices from 1", 5, prices=tuple(range(1, 11)), book=Book("empty", "empty")))
    add(ladder_case("no roots, prices from 1", 5, prices=tuple(range(1, 11)), book=Book(None, None)))
    add(ladder_case("keyless roots, prices from 1, all asks", 10, prices=tuple(range(1, 11)), book=Book("empty", "empty")))
    for depth in (1, 2, 3, 7, 8, 9, 15, 16, 17):
        add(ladder_case("deep bid %d" % depth, 5, book=Book(("deep", -1100, depth), 1400)))
        add(ladder_case("deep ask %d" % depth, 5, book=Book(-1000, ("deep", 1200, depth))))
    for depth in (1, 2, 3):
        add(ladder_case("bid key in parent %d" % depth, 5, book=Book(("up", -1100, depth), 1400)))
        add(ladder_case("ask key in parent %d" % depth, 5, book=Book(-1000, ("up", 1200, depth))))
    add(ladder_case("ask key two nodes up, bound matters", 5, book=Book(-1000, ("up", 1100, 2))))
    add(ladder_case("bid key two nodes up, bound matters", 5, book=Book(("up", -1300, 2), 2000)))
    add(ladder_case("orphan bid", 5, book=Book("orphan", 1400)))
    add(ladder_case("orphan ask", 5, book=Book(-1000, "orphan")))
    # Resting orders.
    size = 1000
    base = [(0, 0, price) for price in PRICES]

    def with_ids(*ids):
        rows = list(base)
        for at, oid in ids:
            rows[at] = (1, oid, PRICES[at])
        return resting(*rows)
    add(ladder_case("own order kept", 5, levels=with_ids((7, 301)), book=Book(-1000, 1400, [Slot(side=1)], [(301, 0)])))
    add(ladder_case("own bid kept", 5, levels=with_ids((3, 302)), book=Book(-1000, 1400, [Slot(side=0)], [(302, 0)])))
    add(ladder_case("wrong side", 5, levels=with_ids((7, 303)), book=Book(-1000, 1400, [Slot(side=0)], [(303, 0)])))
    add(ladder_case("wrong size", 5, levels=with_ids((7, 304)), book=Book(-1000, 1400, [Slot(side=1, size=999)], [(304, 0)])))
    add(ladder_case("wrong size, high bit", 5, levels=with_ids((7, 304)), book=Book(-1000, 1400, [Slot(side=1, size=1000 | 1 << 40)], [(304, 0)])))
    add(ladder_case("other user", 5, levels=with_ids((7, 305)), book=Book(-1000, 1400, [Slot(side=1, user=b"\xff" * 19 + b"\xfe")], [(305, 0)])))
    add(ladder_case("other user, first byte", 5, levels=with_ids((7, 305)), book=Book(-1000, 1400, [Slot(side=1, user=b"\xfe" + b"\xff" * 19)], [(305, 0)])))
    add(ladder_case("other user, byte 16", 5, levels=with_ids((7, 305)), book=Book(-1000, 1400, [Slot(side=1, user=b"\xff" * 16 + b"\x00" + b"\xff" * 3)], [(305, 0)])))
    add(ladder_case("vacant slot", 5, levels=with_ids((7, 306)), book=Book(-1000, 1400, [Slot(tag=2, side=1)], [(306, 0)])))
    add(ladder_case("slot index past slab", 5, levels=with_ids((7, 307)), book=Book(-1000, 1400, [Slot(side=1)], [(307, 1)])))
    add(ladder_case("slot past the slab length, in memory", 5, levels=with_ids((7, 317)), book=Book(-1000, 1400, [Slot(side=0), Slot(side=1)], [(317, 1)], hidden=1)))
    add(ladder_case("id with high bits", 5, levels=with_ids((7, 0x0123456789ABCDEF)), book=Book(-1000, 1400, [Slot(side=1)], [(0x0123456789ABCDEF, 0)])))
    add(ladder_case("id with bit 50", 5, levels=with_ids((7, 1 << 50)), book=Book(-1000, 1400, [Slot(side=1)], [(1 << 50, 0)])))
    add(ladder_case("id not in table", 5, levels=with_ids((7, 308)), book=Book(-1000, 1400, [Slot(side=1)], [(309, 0)])))
    add(ladder_case("empty table", 5, levels=with_ids((7, 310)), book=Book(-1000, 1400, [Slot(side=1)], [(310, 0)], items=0)))
    add(ladder_case("level tag 2", 5, levels=resting(*[(2, 311, price) for price in PRICES]), book=Book(-1000, 1400, [Slot(side=1)], [(311, 0)])))
    add(ladder_case("level tag high word", 5, levels=resting(*[(1 | 1 << 32, 312, price) for price in PRICES]), book=Book(-1000, 1400, [Slot(side=1)], [(312, 0)])))
    add(ladder_case("partial first ask kept", 5, 11, levels=with_ids((6, 313)), book=Book(-1000, 1400, [Slot(side=1, size=11)], [(313, 0)])))
    add(ladder_case("partial first ask stale size", 5, 11, levels=with_ids((6, 314)), book=Book(-1000, 1400, [Slot(side=1, size=1000)], [(314, 0)])))
    add(ladder_case("skip moves the first ask, full size kept", 5, 11, levels=with_ids((7, 315)), book=Book(-1160, 1400, [Slot(side=1, size=1000)], [(315, 0)])))
    add(ladder_case("own order on a crossing level is left alone", 5, levels=with_ids((5, 316)), book=Book(-1200, 1400, [Slot(side=1)], [(316, 0)])))
    add(ladder_case("mixed sides", 5, levels=with_ids((2, 320), (3, 321), (6, 322), (7, 323), (8, 324)),
                    book=Book(-1000, 1400, [Slot(side=0), Slot(side=1, size=5), Slot(side=1), Slot(side=0), Slot(side=1)], [(320, 0), (321, 1), (322, 2), (323, 3), (324, 4)])))
    add(ladder_case("spent order, bid level", 5, levels=with_ids((1, 325)), book=Book(-1000, 1400, [Slot(side=1)], [(325, 0)])))
    # Probing of the id table.
    for crowd, decoys in ((0, 1), (0, 2), (0, 5), (1, 0), (1, 2), (2, 0), (2, 3), (3, 1)):
        add(ladder_case("probe crowd %d decoys %d" % (crowd, decoys), 5, levels=with_ids((7, 331 + crowd * 16 + decoys)),
                        book=Book(-1000, 1400, [Slot(side=1)], [(331 + crowd * 16 + decoys, 0)], crowd=crowd, decoys=decoys)))
    add(ladder_case("probe misses behind a full group", 5, levels=with_ids((7, 340)), book=Book(-1000, 1400, [Slot(side=1)], [(340, 0)], crowd=1, items=1)))
    # The cap of 100 a side.
    many = tuple(1000 + at * 8 for at in range(260))
    add(ladder_case("99 bids", 0, prices=many[:99]))
    add(ladder_case("100 bids", 0, prices=many[:100]))
    add(ladder_case("101 bids", 0, prices=many[:101]))
    add(ladder_case("260 levels: 100 each side", 130, prices=many))
    add(ladder_case("100 asks exactly", 100, prices=many[:120]))
    add(ladder_case("101 asks wanted", 101, prices=many[:120]))

    def tagged(count, slots_for):
        rows = [(1, 2000 + at, many[at]) for at in range(count)]
        return resting(*rows), [(2000 + at, at) for at in range(count)], [slots_for(at) for at in range(count)]
    levels, rows, slots = tagged(130, lambda at: Slot(side=1 if at >= 130 - 110 else 0))
    add(ladder_case("110 own asks: past 100 cancelled", 110, prices=None, levels=levels, book=Book(None, None, slots, rows)))
    levels, rows, slots = tagged(130, lambda at: Slot(side=0))
    add(ladder_case("110 own bids: past 100 cancelled", 20, levels=levels, book=Book(None, None, slots, rows)))
    levels, rows, slots = tagged(130, lambda at: Slot(side=1, user=b"\x01" * 20))
    add(ladder_case("strangers past 100: no cancel, no place", 110, levels=levels, book=Book(None, None, slots, rows)))
    levels, rows, slots = tagged(130, lambda at: Slot(side=0, size=3))
    add(ladder_case("past 100 and wrong size", 20, levels=levels, book=Book(None, None, slots, rows)))
    levels = [Level(0, 0, price) for price in many[:130]]
    for at in range(0, 130):
        if at % 2 and at < 110:
            levels[at].tag = 1
            levels[at].oid = 3000 + at
    add(ladder_case("untagged level past 100 stops the side", 130, levels=levels))
    levels = [Level(0, 0, price) for price in many[:130]]
    add(ladder_case("first ask partial past 100", 110, 3, levels=levels))
    # Tree shapes.
    # Each spot needs its own orders, or a walk that repeats or skips a ladder looks the same.
    def spread(count):
        return [Ladder(key, PRICES[:3 + key], 100 + key) for key in range(count)]
    open_books = {key: Book(None, None) for key in range(8)}
    add(Case("five flat", spread(5), books=open_books))
    add(Case("five, two levels", spread(5), shape="two", books=open_books))
    for height in (2, 3, 7, 8, 9, 15, 16, 17, 24, 25):
        add(Case("three, height %d" % height, spread(3), shape=height, books=open_books))
        add(Case("four, height %d" % height, spread(4), shape=height, books=open_books))
    add(Case("claimed past the rows", [Ladder(0, PRICES), Ladder(1, PRICES)], claimed=3, balances=balance_for(3)))
    add(Case("claimed below the rows", [Ladder(0, PRICES), Ladder(1, PRICES)], claimed=1, balances=balance_for(3)))
    add(Case("no ladder row", [Ladder(0, PRICES, none=True), Ladder(1, PRICES)], balances=balance_for(3)))
    add(Case("no ladder row, bad key", [Ladder(99, PRICES, none=True), Ladder(1, PRICES)], balances=balance_for(3)))
    add(Case("book index at the end", [Ladder(4, PRICES)], book_count=5, balances=balance_for(3)))
    add(Case("book index past the end", [Ladder(5, PRICES)], book_count=5, balances=balance_for(3)))
    add(Case("pair past the end", [Ladder(9, PRICES)], book_count=12, balances=balance_for(3)))
    add(Case("two spots: level ids", [Ladder(0, PRICES), Ladder(2, PRICES)], balances=((0, 3000 * UNIT), (1, 1 << 30))))
    # Time word.
    for moment, label in (((pack_date(2026, 1), 0, 0), "start of a year"), ((pack_date(2024, 366), 86399, 999999999), "end of a leap year"), ((pack_date(1970, 1), 0, 0), "epoch"),
                          ((pack_date(1970, 1), 0, 999999), "epoch below 1 ms"), ((pack_date(1970, 1), 0, 1000000), "epoch plus 1 ms"), ((pack_date(1969, 365), 86399, 0), "before the epoch"),
                          ((pack_date(2101, 59), 3, 4), "century"), ((pack_date(2401, 59), 3, 4), "400 years"), ((pack_date(2000, 60), 1, 2), "leap day 2000"), ((pack_date(-400, 1), 0, 0), "negative year"),
                          ((pack_date(1, 1), 0, 0), "year 1"), ((pack_date(0, 1), 0, 0), "year 0")):
        add(ladder_case("time: %s" % label, 3, now=moment))
    # Place results.
    def place_case(label, kind):
        return ladder_case("place: %s" % label, 3, prices=PRICES[:4], places={0: kind})
    add(place_case("fails", PlaceResult(failed=True)))
    add(ladder_case("place: all fail", 3, prices=PRICES[:4], places={at: PlaceResult(failed=True) for at in range(4)}))
    add(place_case("fills", PlaceResult(fills=3)))
    add(place_case("empty map root", PlaceResult(rows=[])))
    add(place_case("one row", PlaceResult(rows=[4])))
    add(place_case("one row, no capacity", PlaceResult(rows=[0])))
    add(place_case("three rows", PlaceResult(fills=2, rows=[4, 0, 9])))
    add(place_case("four rows", PlaceResult(rows=[4, 3, 2, 1])))
    add(place_case("tail leaf only", PlaceResult(rows=[1], tail=(0, 1))))
    add(place_case("tail chain", PlaceResult(rows=[1], tail=(0, 3))))
    add(place_case("tail from height 2", PlaceResult(rows=[1, 2], tail=(2, 2))))
    for height in (0, 1, 2, 3, 7, 8, 9, 15, 16, 17):
        add(place_case("lazy descent %d" % height, PlaceResult(rows=[1, 2, 3], lazy=height)))
    add(place_case("walker tag cleared", PlaceResult(rows=[1, 2], untag=True)))
    add(place_case("step gives nothing", PlaceResult(rows=[1, 2], step_none=True)))
    # A stubbed cursor reaches indexes the real helper cannot give.
    add(ladder_case("cursor past the end", 0, cursor=(14, 0, 0)))
    add(ladder_case("cursor at the end", 0, cursor=(10, 0, 0)))
    add(ladder_case("cursor flag, side bit only", 0, cursor=(4, 1, 77), book=Book(-1000, 1400)))
    add(ladder_case("cursor one past, partial", 0, cursor=(11, 1, 77)))
    return cases


TOKEN_ROWS = tuple((low, low + difference) for low in (0, 3) for difference in range(0, 21))


def cursor_cases():
    rows = []

    def add(label, key=0, levels=10, size=1000, balances=(), tokens=DEFAULT_TOKENS, pairs=DEFAULT_PAIRS, depth=0):
        rows.append(Case(label, [Ladder(key, tuple(range(1000, 1000 + levels)), size)], tokens=tokens, pairs=pairs, balances=balances, balance_depth=depth))
    for difference in list(range(0, 33)) + [33, 34, 35, 36, 40, 48, 64, 65, 80, 96, 128, 200, 255]:
        tokens = ((0, difference),) if difference <= 255 else ()
        add("decimals %d" % difference, balances=((0, (1 << 63) + 12345),), tokens=tokens)
        add("decimals %d, small" % difference, balances=((0, 12345678),), tokens=tokens, size=7)
    add("szDecimals above weiDecimals", tokens=((5, 4),))
    add("szDecimals one above", tokens=((1, 0),))
    add("same decimals", tokens=((6, 6),), balances=((0, 3500),))
    add("token past the end", tokens=(), balances=((0, 1),))
    add("token past the end, key 3", tokens=((0, 0), (0, 0), (0, 0)), key=7, balances=((3, 1),))
    add("pair past the end", key=8)
    add("pair at the end", key=7, tokens=((0, 0),) * 4, balances=((0, 5000),))
    for balance, size, levels in ((0, 1000, 10), (999, 1000, 10), (1000, 1000, 10), (1001, 1000, 10), (2999, 1000, 10), (3000, 1000, 10), (9999, 1000, 10), (10000, 1000, 10), (10001, 1000, 10), (11000, 1000, 10),
                                  (10999, 1000, 10), (1 << 40, 1000, 10), ((1 << 33) + 5, 1 << 33, 3), (1 << 33, 1 << 33, 3), (MASK[8], 1, 3), (MASK[8], MASK[8], 3), (MASK[8] - 1, MASK[8], 3), (7, 3, 0), (6, 3, 0),
                                  (1 << 36, 1 << 35, 5), ((1 << 36) + 1, 1 << 35, 5), ((1 << 36) + 1, 1 << 35, 1 << 16), (5, 0, 4), (0, 0, 4), (0, 1, 4), (3, 7, 4), (MASK[4], MASK[4], 2), (1 << 32, MASK[4], 2), (1 << 32, 1 << 32, 2)):
        add("balance %d size %d levels %d" % (balance, size, levels), levels=levels, size=size, balances=((0, balance),), tokens=((2, 2),))
    for difference in (16, 17, 18, 19):
        # 7e19 does not fit a u64, so the last power uses a factor of 1.
        factor = 1 if difference == 19 else 7
        add("exact multiple of 1e%d" % difference, tokens=((0, difference),), balances=((0, 10 ** difference * factor),), size=factor)
        add("just under a multiple of 1e%d" % difference, tokens=((0, difference),), balances=((0, 10 ** difference * factor - 1),), size=factor)
    add("no balance, token past the end", tokens=(), balances=())
    add("small balance, size 2^32", size=1 << 32, tokens=((2, 2),), balances=((0, 7),))
    add("small balance, size 2^33", size=1 << 33, tokens=((2, 2),), balances=((0, 7),))
    add("scale 10, small quotient, size 2^32", size=(1 << 32) + 5, tokens=((0, 1),), balances=((0, 70),))
    add("big scale, big quotient", tokens=((0, 3),), balances=((0, MASK[8]),), size=3)
    add("scale above 32 bits, balance below", tokens=((0, 10),), balances=((0, 123456789),), size=3)
    add("scale above 32 bits", tokens=((0, 10),), balances=((0, 123456789 * 10 ** 10 + 5),), size=7)
    tree = ((0, 111000), (1, 222000), (2, 333000), (3, 444000), (4, 555000), (5, 666000), (6, 777000))
    for key, base in ((0, 0), (1, 2), (2, 1), (5, 3)):
        add("token %d, flat" % base, key=key, tokens=((1, 1),) * 8, balances=tree)
        add("token %d, split" % base, key=key, tokens=((1, 1),) * 8, balances=tree, depth=1)
    add("balance key past all", key=0, pairs=((9, 0),), tokens=((1, 1),) * 10, balances=tree)
    add("balance key past all, split", key=0, pairs=((9, 0),), tokens=((1, 1),) * 10, balances=tree, depth=1)
    add("balance key between", key=0, pairs=((3, 0),), tokens=((1, 1),) * 10, balances=((1, 5000), (5, 9000)))
    add("balance key below all, split", key=0, pairs=((0, 0),), tokens=((1, 1),) * 10, balances=((1, 5000), (2, 5000), (5, 9000)), depth=1)
    return rows


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


def slot_sites(image, slot):
    """Every `call [rip+rel32]` (FF 15) in .text that reads one slot."""
    base, text = image.text_bytes()
    found = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            found.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return found


def find_all(image, start, pattern):
    """Every place a byte pattern occurs inside a function."""
    begin, end = image.exact_fde(start)
    data = bytes(image.blob[image.offset(begin):image.offset(begin) + end - begin])
    found = []
    at = data.find(pattern)
    while at >= 0:
        found.append(begin + at)
        at = data.find(pattern, at + 1)
    return found


# Each row: function, meaning, byte pattern, expected number of sites.
PINS = (
    (ENSURE, "cmp qword [rsp+0x18], 0x63: the side count, 100 and up stops new orders", b"\x48\x83\x7c\x24\x18\x63", 3),
    (ENSURE, "cmp qword [rsp+0x18], 0x64: the same cap after a cancel", b"\x48\x83\x7c\x24\x18\x64", 1),
    (ENSURE, "cmp qword [rbp+0x40], 0: id table item count", b"\x48\x83\x7d\x40\x00", 1),
    (ENSURE, "imul rdi, rdx, 0xd8: book stride", b"\x48\x69\xfa\xd8\x00\x00\x00", 1),
    (ENSURE, "imul rcx, rcx, 0xf8: slab stride", b"\x48\x69\xc9\xf8\x00\x00\x00", 1),
    (ENSURE, "imul rcx, r15, 0xd8: order record stride", b"\x49\x69\xcf\xd8\x00\x00\x00", 1),
    (ENSURE, "imul rsi, rax, 0x228: fill stride", b"\x48\x69\xf0\x28\x02\x00\x00", 1),
    (ENSURE, "movabs rcx, FX multiplier of the id table", b"\x48\xb9" + struct.pack("<Q", FX), 1),
    (ENSURE, "rol rax, 20: the hash rotate", b"\x48\xc1\xc0\x14", 1),
    (ENSURE, "cmp dword [rcx], 1: level tag", b"\x83\x39\x01", 1),
    (ENSURE, "cmp dword [rax+rcx], 2: vacant slab slot", b"\x83\x3c\x08\x02", 1),
    (ENSURE, "mov r9d, 2: reason, cancel-all and cancel-one", b"\x41\xb9\x02\x00\x00\x00", 2),
    (ENSURE, "cmp ecx, 0xffff: all 16 compared bytes of the user equal", b"\x81\xf9\xff\xff\x00\x00", 1),
    (ENSURE, "cmp al, [rax+0xc2]-style side compare", b"\x38\x88\xc2\x00\x00\x00", 1),
    (ENSURE, "cmp [rax+0xc8], r12: slot size against the wanted size", b"\x4c\x39\xa0\xc8\x00\x00\x00", 1),
    (CURSOR, "shl rdx, 5: pair stride", b"\x48\xc1\xe2\x05", 1),
    (CURSOR, "imul rsi, r12, 0xe8: token stride", b"\x49\x69\xf4\xe8\x00\x00\x00", 1),
    (CURSOR, "mov esi, 10: first power", b"\xbe\x0a\x00\x00\x00", 1),
    (CURSOR, "imul rsi, rsi, 100", b"\x48\x6b\xf6\x64", 1),
    (CURSOR, "imul rsi, rsi, 10000", b"\x48\x69\xf6\x10\x27\x00\x00", 1),
    (CURSOR, "imul rsi, rsi, 100000000", b"\x48\x69\xf6\x00\xe1\xf5\x05", 1),
    (CURSOR, "movabs rdx, 1e16", b"\x48\xba" + struct.pack("<Q", 10 ** 16), 1),
)


def read_pins(image):
    rows = []
    for start, meaning, pattern, expected in PINS:
        found = find_all(image, start, pattern)
        if len(found) != expected:
            raise EvidenceError("pin %r has %d sites" % (meaning, len(found)))
        rows.append({"function": "%#x" % start, "sites": ["%#x" % va for va in found], "bytes": pattern.hex(), "meaning": meaning})
    return rows


def read_constants(image):
    tail = bytes(image.blob[image.offset(USER_TAIL):image.offset(USER_TAIL) + 16])
    if tail != b"\xff" * 4 + bytes(12):
        raise EvidenceError("user tail mask differs")
    name = bytes(image.blob[image.offset(SPAN_NAME):image.offset(SPAN_NAME) + len(SPAN_NAME_TEXT)])
    if name != SPAN_NAME_TEXT:
        raise EvidenceError("span name differs")
    return {"user_tail_mask": {"va": "%#x" % USER_TAIL, "bytes": tail.hex()}, "span_name": {"va": "%#x" % SPAN_NAME, "text": name.decode("ascii")}, "side_cap": SIDE_CAP}


def check_callers(image):
    """The two direct calls of the refresh, and the only `call [slot]` sites of the cursor."""
    sites = direct_sites(image, [ENSURE])[ENSURE]
    if sorted((va, image.fde(va)[0]) for va, _ in sites) != sorted(((SPAN_SITE, SPAN), (DRIVER_SITE, DRIVER))):
        raise EvidenceError("refresh sites differ: %s" % sites)
    cursor = slot_sites(image, SLOT_CURSOR)
    return {"refresh": [{"site": "%#x" % va, "function": "%#x" % image.fde(va)[0]} for va, _ in sorted(sites)],
            "cursor_slot": [{"site": "%#x" % va, "function": "%#x" % image.fde(va)[0]} for va in cursor]}


# ---- mutation pass ----

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
    for start, cases, check in ((CURSOR, cursor_cases(), compare_cursor), (ENSURE, run_cases(), compare_run)):
        rows = decode_range(image, *image.exact_fde(start))
        if start == ENSURE:
            # Cursor cases sit behind the big list; the small ones first keep a survivor cheap.
            cases.sort(key=lambda case: max([len(ladder.levels) for ladder in case.ladders] + [0]))
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = check(harness, case)
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

LEVEL_MAP = (
    (0x00, "u64", "tag, read as a dword: 1 means +0x08 holds a resting order id"),
    (0x08, "u64", "order id, written from the place result"),
    (0x10, "u64", "price, raw; never written here"),
)
LADDER_MAP = (
    (0x00, "u64", "level vector capacity; 1 << 63 is the niche for no ladder, which is skipped"),
    (0x08, "pointer", "level vector, stride 0x18"),
    (0x10, "u64", "level count"),
    (0x18, "u64", "order size in size units"),
)
RECORD_MAP = (
    (0x00, 8, "1"),
    (0x08, 8, "size: the ladder size, or the remainder on the first ask"),
    (0x10, 8, "0"),
    (0x20, 8, "0"),
    (0x30, 8, "0, with +0x38 = 8 and +0x40 = 0: an empty vector"),
    (0x48, 8, "0"),
    (0x70, 8, "0"),
    (0x80, 8, "level price, raw"),
    (0x88, 8, "block time in milliseconds, clamped at 0"),
    (0x90, 2, "0"),
    (0xA2, 1, "side: 0 for levels below the cursor, 1 for the cursor and above"),
    (0xA8, 8, "0"),
    (0xB0, 8, "cursor index, a stale word behind the tag at +0xa8"),
    (0xB8, 20, "user 0xff * 20"),
    (0xCC, 1, "0"),
)
BOOK_MAP = (
    (0x08, "slab pointer, stride 0xf8"),
    (0x10, "slab length"),
    (0x28, "id table control bytes"),
    (0x30, "id table bucket mask"),
    (0x40, "id table item count; 0 skips the probe"),
    (0x80, "side tree: root, height, length; bound for side 1"),
    (0x98, "side tree: root, height, length; bound for side 0"),
)
SLOT_MAP = (
    (0x00, "tag dword; 2 is vacant"),
    (0xC2, "side byte, compared with the walk's side"),
    (0xC8, "size, compared with the wanted size"),
    (0xE0, "user, 20 bytes"),
)
RESULT_MAP = (
    (0x00, "fill vector capacity; 1 << 63 means the place failed and the level is left alone"),
    (0x08, "fill vector pointer, stride 0x228"),
    (0x18, "result map root, 0 for none"),
    (0x20, "result map height"),
    (0x28, "result map length"),
    (0x30, "order id, stored in the level with tag 1"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/hyperliquidity.rs:53-57", "claim": "HyperliquidityLevel is 24 bytes: two unknown words and the price at +0x10",
     "bytes": "size and offset agree; the two words are a tag and a resting order id: 1 at +0x00 makes +0x08 an id that is looked up in the book, and each placed order writes both"},
    {"reference": "l1/exchange/impl_spot_deploy.rs:180", "claim": "HyperliquidityLevel holds a price, a size and a flag",
     "bytes": "no size or flag is read from a level: the size is the ladder's +0x18, or the remainder for the first ask"},
    {"reference": "l1/hyperliquidity.rs:39-44 and l1/exchange/impl_spot_deploy.rs:172-177", "claim": "HyperliquidityBook also holds base_balance and a USDC amount",
     "bytes": "the tree value here is 0x20 bytes, the node's value slots run to +0x160 at stride 0x20, and the only word past the vector is the order size at +0x18; the base balance comes from the 0xff user's balance tree instead"},
    {"reference": "l1/ (whole tree)", "claim": "by_spot is read only by contains_key and written by insert",
     "bytes": "the refresh `0x26cb280` is the reader; no function in the reference has its loop, the cursor, the crossing skip or the cap of 100"},
)
LANDING = "unwind landing pad or panic tail: no case unwinds"
NOT_TWO = "the iterator's end test: every record has +0x08 = 1, so it never reads 2"
EMPTY_VEC = "each record's vector is empty with capacity 0, so the copy needs no allocation and the source needs no free"
NO_TAG = "bytes +0x50 and +0x99 of every record are 0, so these copies never run"
BOUND_LEVEL = "the record's level index was bound-checked when the record was made, and the level count has not changed"
NOT_ONE = "the unwrap of the side tree flag: the walk starts only with a nonzero root, so this flag is 1"
DROP_REST = "drops records left after an early iterator end, and the iterator never ends early"


def reason_for(row):
    va = row["va"]
    if row["result"] == "killed":
        return ""
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "")


def outcome_name(spec):
    kinds = {event[0] for event in spec["events"]}
    if spec["stop"]:
        return "panic"
    if "cancel all" in kinds:
        return "flat ladder, all cancelled"
    if "place" in kinds and "cancel one" in kinds:
        return "cancels and new orders"
    if "place" in kinds:
        return "new orders only"
    if "cancel one" in kinds:
        return "cancels only"
    if "lookup" in kinds:
        return "nothing to change"
    return "no ladder read"


def worked_run(harness):
    """One small ladder through the real bytes: the cursor table, then the orders of one block."""
    table = []
    for wanted in range(0, 11500, 500):
        case = ladder_case("t", balances=((0, wanted * UNIT),))
        out = harness.run_cursor(case)["out"]
        table.append({"balance_units": wanted, "index": out[0], "partial": out[1], "remainder": out[2] or 0})
    case = ladder_case("worked", 3, 500, book=Book(-1000, 1400))
    run = harness.run(case)
    orders = []
    for event in run["events"]:
        if event[0] == "place":
            fields = dict(event[4])
            orders.append({"price": fields[0x80], "size": fields[0x08], "side": event[5]})
    return {"ladder": {"levels": len(PRICES), "first_price": PRICES[0], "price_step": PRICES[1] - PRICES[0], "order_size": 1000},
            "cursor_table": table, "block": {"balance_units": 3500, "best_bid_key": -1000, "best_ask_key": 1400, "orders": orders}}


def field_offsets(image, start):
    """Non-stack displacement counts of one function, read through the byte decoder."""
    counts = {}
    for row in decode_range(image, *image.exact_fde(start)):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] not in (None, RSP):
                counts[operand[4]] = counts.get(operand[4], 0) + 1
    return counts


def compare_copies(image, runs, mismatches):
    """The same cases and the same specification, through the other two copies."""
    base = field_offsets(image, ENSURE)
    rows = []
    for copy in COPIES[1:]:
        harness = Harness(image)
        harness.select(copy)
        cases = [case for case in runs if not uses_result_map(case)]
        failed = 0
        for case in cases:
            trouble = compare_run(harness, case)
            if trouble:
                failed += 1
                mismatches.append("copy %#x %s" % (copy["entry"], trouble))
        counts = field_offsets(image, copy["entry"])
        differ = {"%#x" % key: [base.get(key, 0), counts.get(key, 0)] for key in sorted(set(base) | set(counts)) if base.get(key, 0) != counts.get(key, 0)}
        rows.append({"entry": "%#x" % copy["entry"], "cancel_all": "%#x" % copy["cancel_all"], "cancel_one": "%#x" % copy["cancel_one"], "place": "%#x" % copy["place"],
                     "map_first_step": "%#x" % copy["next"], "map_later_step": "%#x" % copy["step"], "cases": len(cases), "mismatches": failed,
                     "field_offset_counts_that_differ_from_first": differ, "instructions_run": harness.machine.steps, "_seen": set(harness.machine.seen)})
    return rows


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    runs, cursors = run_cases(), cursor_cases()
    mismatches = []
    outcomes = {}
    for case in runs:
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        name = outcome_name(spec_run(copy_case(case)))
        outcomes[name] = outcomes.get(name, 0) + 1
    for case in cursors:
        trouble = compare_cursor(harness, case)
        if trouble:
            mismatches.append(trouble)
    seen = set(harness.machine.seen)
    worked = worked_run(harness)
    copies = compare_copies(image, runs, mismatches)
    steps = harness.machine.steps + sum(row["instructions_run"] for row in copies)
    for row in copies:
        seen_copy = row.pop("_seen")
        seen |= seen_copy
    functions = []
    for role, start in (("refresh", ENSURE), ("cursor", CURSOR), ("refresh, second copy", COPIES[1]["entry"]), ("refresh, third copy", COPIES[2]["entry"])):
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows),
                          "instructions_stepped": sum(1 for row in rows if row.va in seen)})
    relative = harness.relative
    edges = []
    for name, target in (("cancel all of a user's orders in one book", CANCEL_ALL), ("cancel one order id", CANCEL_ONE), ("place one order record", PLACE),
                         ("first step of the result map drop", MAP_NEXT), ("later steps of the result map drop", MAP_STEP), ("end of the result map drop", MAP_END),
                         ("span wrapper", SPAN), ("block step", DRIVER)):
        begin, end = image.exact_fde(target)
        edges.append({"target": "%#x" % target, "end": "%#x" % end, "meaning": name})
    sites = direct_sites(image, [ENSURE, COPIES[1]["entry"], COPIES[2]["entry"], CANCEL_ALL, CANCEL_ONE, PLACE])
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    results_rows = run_mutants(image, seen, verbose) if full else []
    tally = {key: sum(1 for row in results_rows if row["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "edges": edges,
        "callers": check_callers(image),
        "copies": copies,
        "constants": read_constants(image),
        "slots": {"%#x" % slot: {"target": "%#x" % relative[slot], "meaning": SLOT_NAMES[slot]} for slot in sorted(SLOT_NAMES)},
        "pins": read_pins(image),
        "locations": [{"slot": "%#x" % slot, "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                       "column": image.location(slot, relative)[2]} for slot in LOCATIONS],
        "level_map": [{"offset": "%#x" % offset, "type": kind, "meaning": meaning} for offset, kind, meaning in LEVEL_MAP],
        "ladder_map": [{"offset": "%#x" % offset, "type": kind, "meaning": meaning} for offset, kind, meaning in LADDER_MAP],
        "record_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in RECORD_MAP],
        "book_map": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in BOOK_MAP],
        "slot_map": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in SLOT_MAP],
        "result_map": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in RESULT_MAP],
        "nodes": {"ladder_and_side_tree": dict(LADDER_NODE, value_stride=VALUE_SIZE, capacity=11), "balance_tree": BALANCE_NODE},
        "strides": {"level": LEVEL_SIZE, "ladder_value": VALUE_SIZE, "order_record": ORDER_SIZE, "book": BOOK_STRIDE, "slab": SLOT_STRIDE, "pair": PAIR_STRIDE, "token": TOKEN_STRIDE, "fill": FILL_STRIDE},
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"refresh": len(runs), "cursor": len(cursors), "not_run_on_the_copies": sum(1 for case in runs if uses_result_map(case))},
        "refresh_outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\topcode\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row for row in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
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


YEAR_ARM = "runs only for year <= 0; every such time is before 1970 and clamps to 0, so the arm cannot show"
YEAR_SIGN = "shifts out the sign of year - 1, which the year arm keeps at or above 0"
HEIGHT_EIGHT = "reached only with the low three bits nonzero, so height 8 never arrives and 8 and 9 compare alike"
SATURATE = "saturation of an index or count: the sum stays below the level count, so the carry never happens and the paired cmov undoes a flip"
BROADCAST = "every word of the register is already equal after pshuflw"
UNINIT = "payload word behind a zero tag: the builder never writes it and no reader uses it"
POWER_ARM = "bit 0 was handled above; a value that reaches this test with bit 0 set and bit 4 clear still fails the later compare"
SECOND_PASS = "the value is stored for a third pass, and the pass flag ends the loop before it is read"
HEIGHT_FLAG = "only the zero test of the height reads this value, so +1 and +9 behave alike"
REASON_RANGES = ((0x26CB592, 0x26CB5B8, YEAR_ARM), (0x26CBE8F, 0x26CBEC7, DROP_REST), (0x26CC027, 0x26CC040, EMPTY_VEC), (0x26CC05D, 0x26CC07F, NO_TAG),
                 (0x26CC08C, 0x26CC0B5, NO_TAG), (0x26CC224, 0x26CC23A, EMPTY_VEC), (0x26CC679, 0x26CC68C, EMPTY_VEC), (0x26CC68C, 0x26CC72C, LANDING),
                 (0x26CB920, 0x26CB92F, SATURATE), (0x26CB952, 0x26CB970, SATURATE), (0x26CB992, 0x26CB9A1, SATURATE))
REASONS = {0x26CB6B0: SECOND_PASS, 0x26CB395: HEIGHT_EIGHT, 0x26CB488: HEIGHT_EIGHT, 0x26CB735: HEIGHT_EIGHT, 0x26CB835: HEIGHT_EIGHT, 0x26CC3E5: HEIGHT_EIGHT,
           0x26CB5DA: YEAR_SIGN, 0x26CB9C6: SATURATE, 0x26CBA06: SATURATE, 0x26CBCB1: SATURATE, 0x26CBAB6: BROADCAST, 0x26CBE79: DROP_REST, 0x26CBEFC: NOT_TWO,
           0x26CBF2E: UNINIT, 0x26CBF46: UNINIT, 0x26CBFD3: UNINIT, 0x26CBFD7: UNINIT, 0x26CBFED: UNINIT, 0x26CC158: UNINIT, 0x26CC056: NO_TAG, 0x26CC082: NO_TAG,
           0x26CC543: HEIGHT_FLAG, 0x32638F0: POWER_ARM}

if __name__ == "__main__":
    sys.exit(main())
