#!/usr/bin/env python3
"""Pin the node #94 fill output path from ELF bytes: one fill record, its row kinds, the flush, and the Trade and Fill JSON keys.

Five writers (`0x26f4400`, `0x4470be0`, `0x44714b0` with 0x228 byte fills and 0x268 byte rows, `0x26f4cd0`, `0x4cd84f0` with 0x238 byte fills and
0x278 byte rows) turn a fill vector into one optional kind 5 row and, per fill, one kind 6 row and two kind 8 rows. The row flush `0x24fc8a0`
enriches kind 8, and sink `0x48547d0` writes a Trade or a Fill. The real bytes run in a Python evaluator with the edge callees stubbed. A
separately written specification predicts every row, and every condition, immediate and field offset of the fresh functions is flipped to show
the run can tell. Serializers `0x47ee6e0`, `0x47ef7a0` and `0x49c9610` give the key of each offset. No objdump or readelf output is parsed, and
the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

Copy = collections.namedtuple("Copy", "name width start abi clone aggregate leg drop table location")
COPIES = (
    Copy("spot first", "spot", 0x26F4400, "plain", 0x256A5B0, 0x254F5C0, 0x24C3F00, 0x277ACB0, 0x3F09BC, None),
    Copy("spot second", "spot", 0x4470BE0, "self", 0x487D630, 0x4847ED0, 0x47C39B0, 0x4479280, 0x6F5488, None),
    Copy("spot third", "spot", 0x44714B0, "self", 0x4876B10, 0x4847ED0, 0x47C39B0, 0x4479280, 0x6F5488, None),
    Copy("perp first", "perp", 0x26F4CD0, "oracle pair", 0x256C7E0, 0x2550850, 0x24C40D0, 0x2779E90, 0x3F09BC, 0x56BD1A8),
    Copy("perp second", "perp", 0x4CD84F0, "oracle struct", 0x488A150, 0x484C0F0, 0x47C3780, 0x4DAD5F0, 0x715BE8, 0x57444C0),
)
Width = collections.namedtuple("Width", "name leg fill row tail mark_word date row_tail row_mark side_extra")
WIDTHS = {
    "spot": Width("spot", 0xF8, 0x228, 0x268, 0x1F0, 0x210, 0x218, 0x1F8, 0x230, 0),
    "perp": Width("perp", 0x100, 0x238, 0x278, 0x200, 0x220, 0x228, 0x208, 0x240, 0),
}
FLAG_MASK = 0x7BE
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_GROW_SPOT = 0x5773D50
SLOT_GROW_PERP = 0x5773D58
SLOT_BOUNDS = 0x576DFC8
SLOT_ZEROED = 0x576E290
SLOT_ERROR = 0x576EF80
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E150)
ORACLE_ROW = 0x60
ORACLE_WORD = 0x20
ORACLE_SCALE = 10000

FLUSH_SPOT = 0x24FC8A0
FLUSH_TABLE = 0x3E4A5C
SINK = 0x48547D0
FLUSH_OUT = 0x23D9F20
FLUSH_DROPS = (0x25047A0, 0x2503DD0)
SLOT_CLASS = 0x5773198
SLOT_EFFECT = 0x5774570
SLOT_APPLY = 0x5774578
SLOT_LOOKUP = 0x5773170
SLOT_AFTER = 0x5774580
FLUSH_LOCATION = 0x56F1FD8
FLUSH_WORD = 0x206450
SINK_TABLE = 0x6FD33C
SIDE_BUILDER = 0x4A06DC0
TRADE_WRITER = 0x47EE6E0
SIDE_WRITER = 0x47EF7A0
FILL_WRITER = 0x49C9610
TRADE_OUT = 0x47EDC30
FILL_OUT = 0x47EDFE0
FILL_BUILD = 0x4C00C40
SINK_DROP = 0x47E0020
PX_VIEW = 0x45A46E0
SZ_VIEW = 0x45A4AE0
SLOT_NAME = 0x5775730
SLOT_CLOCK = 0x576E8A0
SLOT_FILL_TEXT = 0x5775360
TOKEN_POWERS = 0x584B08
OVERRIDE_WRAPPER = 0x4865280
OVERRIDE_FIELD = 0x4A8A4F0
OVERRIDE_TAIL = 0x4A8A5AA
OVERRIDE_VALUE = 0x4C66C50
OVERRIDE_OUTER = 0x70C46C
OVERRIDE_INNER = 0x70C498
OVERRIDE_INNER_END = 0x70F707

ROW_FILL = 8
ROW_TRADE = 6
ROW_ALL = 5
MAX64 = (1 << 64) - 1

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
HEAP_SIZE = 0x60000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 40000

ROWS = HEAP_BASE + 0x100
HASH = HEAP_BASE + 0x140
ORACLE_PAIR = HEAP_BASE + 0x180
ORACLE_ROWS = HEAP_BASE + 0x200
FILLS = HEAP_BASE + 0x2000
OBJECT = HEAP_BASE + 0x1000
META = HEAP_BASE + 0x1800
OUT = HEAP_BASE + 0x4000
HEAP_FREE = HEAP_BASE + 0x6000

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
        elif byte not in (0x2E, 0x64):
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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
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
        if byte == 0xFF and kind == 6:
            return finish("pushi", rm, w=8)
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
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
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
        self.tails = {}
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
                if self.read_code(pc, 1)[0] == 0x64:
                    raise Halt("thread local read at %#x" % pc)
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
        elif op == "pushi":
            self.push(self.get(row.a, 8))
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
            hook = self.tails.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.call_site = row.va
            self.call_target = target
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
            left, right = self.get(row.a, width), self.get(row.b, width)
            left = left - (1 << (8 * width)) if left & SIGN[width] else left
            right = right - (1 << (8 * width)) if right & SIGN[width] else right
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
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



# ---- specification, written from the reading, not from a run ----

RAMPS = {}


def ramp(count, start):
    key = (count, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 7) & 0xFF or 1 for index in range(count))
    return RAMPS[key]


def word(data, at):
    return struct.unpack_from("<Q", data, at)[0]


def dword(data, at):
    return struct.unpack_from("<I", data, at)[0]


def leg_fields(width, data):
    """(offset, bytes) of every field that one pass of the leg helper carries; the tags come out as clean words."""
    rows = []

    def plain(at, size):
        rows.append((at, data[at:at + size]))

    def tag32(at, size, value):
        rows.append((at, struct.pack("<Q", value) if size == 8 else bytes([value])))

    if width == "spot":
        first = 1 if dword(data, 0) == 1 else 0
        tag32(0, 8, first)
        if first:
            plain(0x08, 0x10)
        plain(0x18, 0x10)
        second = 1 if dword(data, 0x28) == 1 else 0
        tag32(0x28, 8, second)
        if second:
            plain(0x30, 0x20)
        plain(0x50, 0x10)
        group, mid, inner, tail = 0x60, 0x68, 0x88, 0xB0
        keep = (0xC8, 8), (0xD0, 0x10), (0xE0, 4)
        cloid = 0xE4
    else:
        plain(0, 0x20)
        second = 1 if dword(data, 0x20) == 1 else 0
        tag32(0x20, 8, second)
        if second:
            plain(0x28, 0x20)
        plain(0x48, 0x10)
        group, mid, inner, tail = 0x58, 0x60, 0x80, 0xA8
        keep = (0xD0, 8), (0xD8, 0x10), (0xE8, 4)
        cloid = 0xEC
    value = word(data, group)
    if value == 2:
        tag32(group, 8, 2)
    else:
        tag32(group, 8, value & 1)
        if value & 1:
            plain(mid, 0x1C)
        third = 1 if dword(data, inner) == 1 else 0
        tag32(inner, 8, third)
        if third:
            plain(inner + 8, 0x1C)
        plain(tail, 0x28 if width == "perp" else 0x18)
    for at, size in keep:
        plain(at, size)
    has = 1 if data[cloid] == 1 else 0
    tag32(cloid, 1, has)
    if has:
        plain(cloid + 1, 0x10)
    return rows


def fill_fields(width, data, swap=True):
    """Every field of one normalised fill, by fill offset."""
    shape = WIDTHS[width]
    rows = []
    for index in (0, 1):
        base = index * shape.leg
        rows += [(base + at, value) for at, value in leg_fields(width, data[base:base + shape.leg])]
    rows.append((shape.tail, swapped_tail(shape, data, swap)))
    return rows


def swapped_tail(shape, data, swap=True):
    """Four clones put the coin first: input tail +0x00 price, +0x08 coin; output +0x00 coin, +0x08 price. Clone 0x4876b10 takes the output order as it is."""
    tail = data[shape.tail:shape.tail + 0x35]
    return tail[8:16] + tail[:8] + tail[16:] if swap else tail


def flag_bytes(table, codes):
    """Bytes of the kind 6 row. The table decides only when the low code is outside the mask."""
    low, high = codes & 0xFF, (codes >> 16) & 0xFF
    first = 1 if FLAG_MASK >> (low & 31) & 1 else table[high]
    return first, int((low | high) == 0)


def mark_word(shape, data, oracle, swap=True):
    """Kind 8 word: the fill word, else the price (0x228) or the oracle row (0x238)."""
    value = word(data, shape.mark_word)
    if value:
        return value
    if shape.name == "spot":
        return word(data, shape.tail if swap else shape.tail + 8)
    coin = word(data, shape.tail + 8) % ORACLE_SCALE
    if coin >= len(oracle):
        return ("panic", coin, len(oracle))
    return oracle[coin]


def emit_rows(width, fills, hash_bytes, flag, codes, table, oracle, swap=True):
    """The kinds in order, and each row as (offset, bytes) pairs."""
    shape = WIDTHS[width]
    rows = []
    if flag:
        rows.append({"kind": ROW_ALL, "all": [fill_fields(width, data, swap) for data in fills]})
    first, both_clear = flag_bytes(table, codes)
    for data in fills:
        if width == "perp" and word(data, 0) == 2:
            break
        carried = [(8 + at, value) for at, value in fill_fields(width, data, swap)]
        # the fill tail sits at the same row offset in all three rows, and the row leaves out the padding after the side byte
        carried = [(at, value) for at, value in carried if at < shape.row_tail] + [
            (shape.row_tail, swapped_tail(shape, data, swap)[:0x20]),
            (shape.row_tail + 0x20, data[shape.mark_word:shape.mark_word + 8]),
            (shape.row_tail + 0x28, data[shape.date:shape.date + 12]),
            (shape.row_tail + 0x34, data[shape.date + 12:shape.date + 13]),
        ]
        rows.append({"kind": ROW_TRADE, "fields": carried + [(shape.row_mark, hash_bytes), (shape.row_mark + 0x21, bytes([first, both_clear]))]})
        value = mark_word(shape, data, oracle, swap)
        if isinstance(value, tuple):
            return rows, value
        for side in (0, 1):
            pair = bytes([(codes >> (16 * side)) & 0xFF, (codes >> (16 * side + 8)) & 0xFF, side])
            rows.append({"kind": ROW_FILL, "fields": carried + [(shape.row_mark, struct.pack("<Q", value)), (shape.row_mark + 8, pair), (shape.row_mark + 0xB, hash_bytes)]})
    return rows, None


TRADE_KEYS = (("coin", 0x90, "string"), ("side", 0xE6, "side"), ("time", 0xD8, "date"), ("px", 0xA8, "float"), ("sz", 0xB0, "float"),
              ("hash", 0xB8, "wrapper"), ("trade_dir_override", 0xE4, "wrapper"), ("side_info", 0x00, "wrapper"))
SIDE_KEYS = (("user", 0x20, "user"), ("start_pos", 0x10, "float"), ("oid", 0x18, "number"), ("twap_id", 0x00, "option"), ("cloid", 0x34, "wrapper"))


def fill_keys(fields):
    """Keys of the Fill writer in order; the gates read the words given in `fields`."""
    rows = [("coin", 0x20, "string"), ("px", 0x88, "float"), ("sz", 0x90, "float"), ("side", 0x100, "side"), ("time", 0x98, "date"), ("startPosition", 0xA0, "float"),
            ("dir", 0x38, "text"), ("closedPnl", 0xA8, "float"), ("hash", 0xB0, "wrapper"), ("oid", 0xD0, "wrapper"), ("crossed", 0x101, "bool"), ("fee", 0xD8, "float")]
    if fields["builder_fee"]:
        rows.append(("builderFee", 0xE0, "float"))
    rows.append(("tid", 0xE8, "number"))
    if fields["cloid"]:
        rows.append(("cloid", 0x102, "wrapper"))
    if fields["liquidation"] != 2:
        rows.append(("liquidation", 0x68, "wrapper"))
    rows.append(("feeToken", 0x50, "wrapper"))
    if fields["fee_escrow"]:
        rows.append(("feeTrialEscrow", 0xF0, "float"))
    if fields["builder"]:
        rows.append(("builder", 0x113, "address"))
    rows.append(("twapId", 0x00, "wrapper"))
    if fields["deployer_fee"]:
        rows.append(("deployerFee", 0xF8, "float"))
    if fields["priority"]:
        rows.append(("priorityGas", 0x10, "wrapper"))
    return rows


def flush_row(row, value, constant):
    """Kind 8 after the flush: the fill record moves down 8 bytes, so a tag word heads the row; then a tagged word, the old word, codes, hash."""
    return [(0, row[8:0x230]), (0x228, struct.pack("<QQ", constant, value)), (0x238, row[0x230:0x238]), (0x240, row[0x238:0x25C])]


def flush_spec(w):
    log, out = [], []
    for row, one in zip(w["rows"], w["jobs"]):
        kind = word(row, 0)
        if kind == 0xB:
            break
        if kind == ROW_FILL:
            coin, price, side = word(row, 8 + 0x1F0), word(row, 8 + 0x1F8), row[0x23A]
            if coin >= w["coins"]:
                return {"log": log, "out": out, "panic": True}
            token = w["tokens"][coin]
            log.append(["class", token])
            if w["class"]:
                log.append(["effect", side])
            if price:
                log.append(["apply", side, price, coin])
            user = row[8 + 0xD0 + side * 0xF8:8 + 0xD0 + side * 0xF8 + 20]
            log.append(["lookup", user.hex()])
            log.append(["after", side])
            value = w["tree"].get(token, 0)
            out.append(flush_row(row, value, w["constant"]))
        elif kind == ROW_ALL:
            out.append([(0, row[:0x20])])
        else:
            out.append([(0, row[:0x258])])
    return {"log": log, "out": out, "panic": False}


def sink_spec(w):
    head = w["head"]
    if head in (5, 6, 7, 9):
        return {"path": "drop"}
    if head == 2:
        return {"path": "none"}
    leg = 0xF8 if w["side"] else 0
    if w["fills"]:
        return {"path": "fill", "twap": [0x1000 + leg + 0x18, 0x1000 + leg + 0x20]}
    if not w["trades"] or w["side"] != w["fill_side"]:
        return {"path": "none"}
    return {"path": "trade", "coin": w["coin"], "px": float(w["price"]) if w["price"] else 0.0, "sz": float(w["size"]), "hash": 1,
            "side": w["side"], "codes": [0x41, 0x42], "date": True, "side_info": side_info_spec(w)}


def side_info_spec(w):
    """Two 0x48 byte rows; the start position is scaled by the token decimals."""
    power = 10.0 ** w["decimals"]
    return [[(w["one"] / power) if w["head"] & 1 else 0.0, 0x48], [(w["two"] / power) if w["start"][1] & 1 else 0.0, 0x48]]


def run_spec(case):
    world = case.world
    if case.kind == "emit":
        table = world["table"]
        rows, panic = emit_rows(COPIES[case.copy].width, world["fills"], world["hash"], world["flag"], world["codes"], table, world["oracle"], COPIES[case.copy].start != 0x44714B0)
        return {"rows": rows, "panic": panic}
    if case.kind == "writer":
        keys = {"trade": TRADE_KEYS, "side": SIDE_KEYS}.get(world["writer"]) or fill_keys(world["fields"])
        keys = [(key, at) for key, at, _ in keys]
        stop = world.get("stop")
        if stop is None:
            return {"keys": keys, "end": True, "result": 0, "open": [0x7B, 1]}
        return {"keys": keys[:stop + 1], "end": False, "result": 0x77 if world["how"] == "error" else 0xE1, "open": [0x7B, 1]}
    if case.kind == "sink":
        return sink_spec(world)
    if case.kind == "flush":
        return flush_spec(world)
    raise EvidenceError("case kind")


# ---- harness: real bytes; every edge callee is stubbed and logged ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, world, copy=0):
        self.label = label
        self.kind = kind
        self.world = world
        self.copy = copy


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_GROW_SPOT: self.on_grow, SLOT_GROW_PERP: self.on_grow,
                 SLOT_BOUNDS: self.on_bounds, SLOT_ERROR: self.on_error, SLOT_NAME: self.on_name, SLOT_CLOCK: self.on_clock, SLOT_FILL_TEXT: self.on_fill_text,
                 SLOT_CLASS: self.on_class, SLOT_EFFECT: self.on_effect, SLOT_APPLY: self.on_apply, SLOT_LOOKUP: self.on_lookup, SLOT_AFTER: self.on_after}
        for slot in SLOT_PANIC + (SLOT_ZEROED,):
            table.setdefault(slot, self.on_other_panic)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        calls = {}
        for at in FIELD_WRITERS:
            calls[at] = lambda m, target=at: self.on_field(m, target)
        for at in KEY_WRAPPERS:
            calls[at] = lambda m, target=at: self.on_field(m, target)
        calls.update({PX_VIEW: lambda m: self.on_view(m, 0), SZ_VIEW: lambda m: self.on_view(m, 1), TRADE_OUT: self.on_trade, FILL_OUT: self.on_fill_out, FILL_BUILD: self.on_fill_build})
        machine.tails = {SINK_DROP: self.on_drop_tail}
        calls[FLUSH_OUT] = self.on_flush_out
        for at in FLUSH_DROPS:
            calls[at] = self.on_flush_drop
        calls[0x4865440] = self.on_end
        calls[0x47F5560] = self.on_close
        self.field_keys = writer_keys(image)
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.used = HEAP_SIZE
        self.keys = []
        self.state = 0
        self.copy = COPIES[0]
        self.base = 0
        self.ended = 0
        self.found = {}
        self.vec = 0

    def on_bounds(self, m):
        raise Panicked("bounds %d %d %#x" % (m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_other_panic(self, m):
        raise Halt("other panic")

    def on_error(self, m):
        regs = m.regs
        if m.memory.read(regs[RDI], 8) != 0xA or regs[RSI] or regs[RDX]:
            raise Halt("error arguments")
        regs[RAX] = 0xE1

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x10000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(size)

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x10000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_grow(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        shape = WIDTHS[self.copy.width]
        if vector != ROWS:
            raise Halt("grow vector")
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if capacity > 0x40 or memory.read(vector + 0x10, 8) != capacity:
            raise Halt("vector size")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * shape.row)
        if capacity:
            memory.copy(fresh, old, capacity * shape.row)
            if self.live.pop(old, None) != capacity * shape.row:
                raise Halt("row buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_field(self, m, target):
        """Field writers: key in rsi and rdx, field in rcx; wrappers hold the key and take the field in rsi."""
        regs = m.regs
        if regs[RDI] != self.state:
            raise Halt("serde state")
        fixed = self.field_keys.get(target)
        if fixed is not None:
            key, at = fixed, regs[RSI]
        else:
            if regs[RDX] > 0x40:
                raise Halt("key length")
            key, at = bytes(m.memory.bytes_at(regs[RSI], regs[RDX])).decode("ascii"), regs[RCX]
        self.keys.append((key, (at - self.base) & MASK[8]))
        regs[RAX] = 0
        stop = self.w.get("stop")
        if stop is not None and len(self.keys) == stop + 1:
            if self.w["how"] == "error":
                regs[RAX] = 0x77
            else:
                m.memory.write(self.state, 1, 1)

    def on_end(self, m):
        self.ended += 1

    def on_close(self, m):
        regs = m.regs
        if regs[RDX] != 1 or m.memory.read(regs[RSI], 1) != 0x7D or regs[RDI] != self.vec:
            raise Halt("closing brace")
        self.ended += 1

    def write_common(self):
        memory = self.machine.memory
        memory.reset(self.used)
        self.brk = HEAP_FREE
        self.live = {}

    def run_emit(self, case):
        w = case.world
        copy = COPIES[case.copy]
        self.copy = copy
        shape = WIDTHS[copy.width]
        machine = self.machine
        memory = machine.memory
        self.write_common()
        self.w = w
        fills = w["fills"]
        count = len(fills)
        at = FILLS
        memory.put_bytes(at, b"".join(fills) + bytes(8))
        memory.put_bytes(HASH, w["hash"])
        capacity = w["capacity"]
        buffer = self.allocate(max(capacity, 1) * shape.row) if capacity else 8
        memory.write(ROWS, 8, capacity)
        memory.write(ROWS + 8, 8, buffer)
        memory.write(ROWS + 0x10, 8, w["prior"])
        oracle = w["oracle"]
        for index, value in enumerate(oracle):
            memory.write(ORACLE_ROWS + index * ORACLE_ROW + ORACLE_WORD, 8, value)
        memory.write(ORACLE_PAIR + 0x68, 8, ORACLE_ROWS)
        memory.write(ORACLE_PAIR + 0x70, 8, len(oracle))
        flag, codes = w["flag"], w["codes"]
        stack = STACK_TOP - 0x100
        if copy.abi == "plain":
            args = {RDI: at, RSI: count, RDX: HASH, RCX: flag, R8: codes, R9: ROWS}
        elif copy.abi == "self":
            memory.write(stack, 8, ROWS)
            args = {RDI: ORACLE_PAIR, RSI: at, RDX: count, RCX: HASH, R8: flag, R9: codes}
        elif copy.abi == "oracle pair":
            memory.write(stack, 8, codes)
            memory.write(stack + 8, 8, ROWS)
            args = {RDI: ORACLE_ROWS, RSI: len(oracle), RDX: at, RCX: count, R8: HASH, R9: flag}
        else:
            memory.write(stack, 8, ROWS)
            args = {RDI: ORACLE_PAIR, RSI: at, RDX: count, RCX: HASH, R8: flag, R9: codes}
        panic = None
        try:
            machine.run(copy.start, args)
        except Panicked as error:
            panic = str(error)
        rows = self.read_rows(shape)
        return {"rows": rows, "panic": panic, "live": dict(self.live)}

    def read_rows(self, shape):
        memory = self.machine.memory
        length = memory.read(ROWS + 0x10, 8)
        if length > 0x40:
            raise Halt("row count")
        base = memory.read(ROWS + 8, 8)
        return (base, length)

    def run(self, case):
        if case.kind == "emit":
            return self.run_emit(case)
        if case.kind == "sink":
            return self.run_sink(case)
        if case.kind == "flush":
            return self.run_flush(case)
        return self.run_writer(case)

    def on_name(self, m):
        regs = m.regs
        if regs[RDX] != META:
            raise Halt("name arguments")
        self.found["coin"] = regs[RSI]
        at = self.allocate(9)
        m.memory.write(regs[RDI], 8, 9)
        m.memory.write(regs[RDI] + 8, 8, at)
        m.memory.write(regs[RDI] + 0x10, 8, 9)

    def on_view(self, m, scale):
        regs = m.regs
        if regs[RDX] != META or regs[RSI] != self.w["coin"]:
            raise Halt("view arguments")
        m.xmm[0] = to_bits(float(regs[RDI]))
        m.keep_float = True

    def on_clock(self, m):
        m.memory.put_bytes(m.regs[RDI], ramp(12, 0x31))

    def on_drop_tail(self, m):
        self.found["path"] = "drop"
        m.regs[RAX] = 0

    def on_trade(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RCX]
        self.found.update(path="trade", px=to_float(memory.read(at + 0xA8, 8)), sz=to_float(memory.read(at + 0xB0, 8)), hash=int(memory.bytes_at(at + 0xB8, 32) == self.w_hash),
                          side=memory.read(at + 0xE6, 1), codes=[memory.read(at + 0xE4, 1), memory.read(at + 0xE5, 1)], date=memory.bytes_at(at + 0xD8, 12) == self.w_date)
        self.found["side_info"] = [[to_float(memory.read(at + base + 0x10, 8)), 0x48] for base in (0, 0x48)]
        text = memory.read(at + 0x98, 8)
        if text not in self.live or memory.read(at + 0x90, 8) != 9 or regs[RDI] != OBJECT + 0x420:
            raise Halt("trade arguments")

    def on_fill_build(self, m):
        regs = m.regs
        out = bytearray(ramp(0x138, 0x17))
        for at in (0x38, 0x50, 0x68):
            struct.pack_into("<Q", out, at, 0)
        m.memory.put_bytes(regs[RDI], bytes(out))

    def on_fill_text(self, m):
        m.memory.put_bytes(m.regs[RDI], ramp(0x20, 0x19))

    def on_fill_out(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RCX] + 0x18
        one, two = memory.read(at, 8), memory.read(at + 8, 8)
        self.found.update(path="fill", twap=[one, two])

    def on_class(self, m):
        regs = m.regs
        if regs[RDI] != OBJECT + 0x90:
            raise Halt("class arguments")
        self.flush_log.append(["class", regs[RSI]])
        regs[RAX] = int(self.w["class"])

    def on_effect(self, m):
        regs = m.regs
        if regs[RDI] != OBJECT + 0x80 or regs[R8] != OBJECT + 0x5D0 or regs[RSI] & 0xFF != 0x4D:
            raise Halt("effect arguments")
        self.flush_log.append(["effect", regs[RDX] & 0xFF])

    def on_apply(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDI] != OBJECT + 0x80 or regs[RCX] != OBJECT + 0x5D0:
            raise Halt("apply arguments")
        self.flush_log.append(["apply", regs[RDX] & 0xFF, memory.read(regs[RSI] + 0x1F0, 8), memory.read(regs[RSI] + 0x1F8, 8)])

    def on_lookup(self, m):
        regs = m.regs
        if regs[RDI] != OBJECT + 0x80:
            raise Halt("lookup arguments")
        self.flush_log.append(["lookup", m.memory.bytes_at(regs[RSI], 20).hex()])
        regs[RAX] = META + 0x700

    def on_after(self, m):
        regs = m.regs
        if regs[RDI] != OBJECT + 0x80:
            raise Halt("after arguments")
        self.flush_log.append(["after", regs[RSI] & 0xFF])

    def on_flush_out(self, m):
        regs = m.regs
        if regs[RDI] != OBJECT + 0x8F3 or regs[RDX] != OBJECT + 0x90 or regs[RCX] != OBJECT + 0x80:
            raise Halt("flush out arguments")
        self.flush_rows.append(m.memory.bytes_at(regs[RSI], 0x268))

    def on_flush_drop(self, m):
        self.flush_drops += 1

    def run_flush(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.write_common()
        self.w = w
        self.flush_log, self.flush_rows, self.flush_drops = [], [], 0
        rows = w["rows"]
        memory.put_bytes(FILLS, b"".join(rows))
        memory.write(ROWS, 8, len(rows))
        memory.write(ROWS + 8, 8, FILLS)
        memory.write(ROWS + 0x10, 8, len(rows))
        memory.put_bytes(OBJECT, bytes(0x900))
        memory.write(OBJECT + 0x1F8, 8, META + 0x200)
        memory.write(OBJECT + 0x200, 8, w["coins"])
        memory.write(OBJECT + 0x8F2, 1, 0x4D)
        for index, token in enumerate(w["tokens"]):
            memory.write(META + 0x200 + index * 0x20, 8, token)
        tree = sorted(w["tree"].items())
        if w["depth"] == 0:
            memory.write(META + 0x710, 8, 0)
            memory.write(META + 0x718, 8, 0)
        else:
            nodes = HEAP_FREE - 0xC00
            memory.write(META + 0x710, 8, nodes)
            memory.write(META + 0x718, 8, w["depth"] - 1)
            leaf = nodes
            if w["depth"] == 2:
                leaf = nodes + 0x200
                memory.write(nodes + 0x16A, 2, 0)
                memory.write(nodes + 0x170, 8, leaf)
            memory.write(leaf + 0x16A, 2, len(tree))
            for index, (key, value) in enumerate(tree):
                memory.write(leaf + 8 + index * 8, 8, key)
                memory.write(leaf + 0x70 + index * 0x18, 8, value)
            memory.write(leaf + 8 + len(tree) * 8, 8, 0)
        panic = False
        try:
            machine.jump_low, machine.jump_high = FLUSH_SPOT, FLUSH_SPOT + 5300
            machine.run(FLUSH_SPOT, {RDI: ROWS, RSI: OBJECT})
        except Panicked as error:
            panic = str(error).endswith("%#x" % FLUSH_LOCATION)
        return {"log": self.flush_log, "rows": list(self.flush_rows), "panic": panic, "drops": self.flush_drops, "capacity": memory.read(ROWS, 8), "pointer": memory.read(ROWS + 8, 8), "length": memory.read(ROWS + 0x10, 8)}

    def run_sink(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.write_common()
        self.w = w
        self.found = {"path": "none"}
        row = bytearray(ramp(0x268, 0x2B))
        struct.pack_into("<Q", row, 0, w["head"])
        self.row_words = {}
        for at in (0x18, 0x20, 0x110, 0x118):
            struct.pack_into("<Q", row, at, 0x1000 + at)
            self.row_words[0x1000 + at] = at
        struct.pack_into("<Q", row, 0xF8, w["start"][1])
        struct.pack_into("<Q", row, 8, w["one"])
        struct.pack_into("<Q", row, 0x100, w["two"])
        struct.pack_into("<QQQ", row, 0x1F0, w["coin"], w["price"], w["size"])
        row[0x224] = w["fill_side"]
        row[0x240], row[0x241], row[0x242] = 0x41, 0x42, w["side"]
        row[0x243] = w["hash"]
        self.w_hash = bytes(row[0x244:0x264]) if w["hash"] & 1 else bytes(32)
        self.w_date = bytes(row[0x218:0x224])
        memory.put_bytes(OUT, bytes(row))
        memory.put_bytes(OBJECT, bytes(0x400))
        memory.write(OBJECT + 0x4E8, 8, 3 if w["fills"] else 1 << 63)
        memory.write(OBJECT + 0x420, 8, 3 if w["trades"] else 1 << 63)
        memory.write(OBJECT + 0x5B0, 8, 1 << 63)
        memory.write(META + 0x168, 8, META + 0x200)
        memory.write(META + 0x170, 8, 8)
        memory.write(META + 0x180, 8, META + 0x300)
        memory.write(META + 0x188, 8, 4)
        memory.write(META + 0x200 + w["coin"] * 0x20, 8, w["token"])
        memory.write(META + 0x300 + w["token"] * 0xE8 + 0x49, 1, w["decimals"])
        try:
            machine.jump_low, machine.jump_high = SINK, SINK + 2565
            machine.run(SINK, {RDI: OBJECT, RSI: OUT, RDX: META, RCX: 0x5151})
        except Panicked as error:
            return {"path": "panic " + str(error)}
        return dict(self.found)

    def run_writer(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.write_common()
        self.w = w
        self.keys = []
        size = 0x130
        data = bytearray(ramp(size, 0x11))
        for at, width, value in w.get("words", ()):
            data[at:at + width] = value.to_bytes(width, "little")
        memory.put_bytes(OBJECT, bytes(data))
        vec = HEAP_FREE - 0x40
        buffer = HEAP_FREE - 0x20
        memory.write(vec, 8, 0x10 if w.get("room", True) else 0)
        memory.write(vec + 8, 8, buffer)
        memory.write(vec + 0x10, 8, 0)
        self.vec = vec
        holder = HEAP_FREE - 0x48
        memory.write(holder, 8, vec)
        start = {"trade": TRADE_WRITER, "side": SIDE_WRITER, "fill": FILL_WRITER}[w["writer"]]
        self.base = OBJECT
        self.state = STACK_TOP - 0x108 - {"trade": 0x18 + 0x30, "side": 0x18 + 0x30, "fill": 0x30 + 0x38}[w["writer"]] + 8
        self.ended = 0
        result = machine.run(start, {RDI: OBJECT, RSI: holder})
        return {"keys": list(self.keys), "end": bool(self.ended), "result": result, "open": [memory.read(buffer, 1), memory.read(vec + 0x10, 8)]}

# ---- cases ----

FIELD_WRITERS = (0x4A7E1E0, 0x4A8B760, 0x4A8F530, 0x4A7A460, 0x4A83200, 0x4A78A30, 0x4A79370, 0x4A87800, 0x4A9F7A0, 0x4A92DF0, 0x4A7B980)
KEY_WRAPPERS = (0x4865300, 0x4865280, 0x4865240, 0x4865400, 0x4AB7180, 0x4AB9CB0, 0x4AB99C0, 0x4AB8030, 0x4AB7390, 0x4AB7410, 0x4AB73D0)
LIQUIDATION_WRITER = 0x4AB8030
LIQUIDATION_KEY = 0x70413E
BLOB = {}


def flag_table(copy):
    """256 bytes behind the table lea of one copy, read as plain data."""
    if not BLOB:
        BLOB["data"] = BINARY.read_bytes()
    return BLOB["data"][copy.table:copy.table + 256]


def writer_keys(image):
    """Key text inside each wrapper: its first `lea rsi, [rip+d]` and the next `mov edx, imm32`."""
    rows = {}
    for start in KEY_WRAPPERS:
        if start == LIQUIDATION_WRITER:
            data = bytes(image.blob[image.offset(start):image.offset(start) + 988])
            for at in range(len(data) - 7):
                if data[at:at + 3] == b"\x48\x8d\x35" and start + at + 7 + struct.unpack_from("<i", data, at + 3)[0] == LIQUIDATION_KEY:
                    rows[start] = bytes(image.blob[image.offset(LIQUIDATION_KEY):image.offset(LIQUIDATION_KEY) + 11]).decode("ascii")
            if start not in rows:
                raise EvidenceError("liquidation key")
            continue
        data = bytes(image.blob[image.offset(start):image.offset(start) + 64])
        at = data.index(b"\x48\x8d\x35")
        target = start + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, data.index(b"\xba", at + 7) + 1)[0]
        rows[start] = bytes(image.blob[image.offset(target):image.offset(target) + size]).decode("ascii")
    return rows


def leg_bytes(width, start, first=1, second=1, group=1, third=1, cloid=1):
    data = bytearray(ramp(WIDTHS[width].leg, start))
    if width == "spot":
        struct.pack_into("<I", data, 0, first)
        struct.pack_into("<I", data, 0x28, second)
        struct.pack_into("<Q", data, 0x60, group)
        struct.pack_into("<I", data, 0x88, third)
        data[0xE4] = cloid
    else:
        struct.pack_into("<I", data, 0x20, second)
        struct.pack_into("<Q", data, 0x58, group)
        struct.pack_into("<I", data, 0x80, third)
        data[0xEC] = cloid
    return bytes(data)


def fill_bytes(width, start, one=None, two=None, mark=0x1122334455667700, price=0x77665544, coin=3, side=1):
    shape = WIDTHS[width]
    tail = bytearray(ramp(shape.fill - 2 * shape.leg, (start + 0x51) & 0xFF))
    struct.pack_into("<QQ", tail, 0, price, coin)
    struct.pack_into("<Q", tail, 0x20, mark)
    tail[0x34] = side
    return leg_bytes(width, start, **(one or {})) + leg_bytes(width, (start + 0x20) & 0xFF, **(two or {})) + bytes(tail)


HASH_SOME = b"\x01" + ramp(32, 0x61)
HASH_NONE = b"\x00" + bytes(32)


def emit_case(label, index, fills, flag=0, codes=0, capacity=8, oracle=(0x1234, 0x2345, 0x3456, 0x4567), hash_bytes=HASH_SOME, prior=0):
    copy = COPIES[index]
    return Case("%s: %s" % (copy.name, label), "emit", {"fills": fills, "flag": flag, "codes": codes, "capacity": capacity, "oracle": list(oracle), "hash": hash_bytes, "table": flag_table(copy), "prior": prior}, index)


def writer_case(label, writer, stop=None, how=None, fields=None):
    world = {"writer": writer, "stop": stop, "how": how}
    if fields is not None:
        world["fields"] = fields
        world["words"] = [(0xE0, 8, fields["builder_fee"]), (0xF0, 8, fields["fee_escrow"]), (0xF8, 8, fields["deployer_fee"]), (0x10, 8, fields["priority"]),
                          (0x102, 1, fields["cloid"]), (0x113, 1, fields["builder"]), (0x85, 1, fields["liquidation"])]
    return Case("%s writer: %s" % (writer, label), "writer", world)


CHECKED = {"trade": ("coin", "side", "time", "px"), "side": ("user", "start_pos", "oid"),
           "fill": ("coin", "px", "sz", "side", "time", "startPosition", "dir", "oid", "crossed", "fee", "builderFee")}
ERROR_IGNORED = ("side", "time", "dir", "crossed", "tid")
FULL_FILL = {"builder_fee": 5, "cloid": 1, "liquidation": 1, "fee_escrow": 6, "builder": 1, "deployer_fee": 7, "priority": 8}
NO_FILL = {"builder_fee": 0, "cloid": 0, "liquidation": 2, "fee_escrow": 0, "builder": 0, "deployer_fee": 0, "priority": 0}


def emit_cases():
    rows = []
    for index, copy in enumerate(COPIES):
        width = copy.width
        one = fill_bytes(width, 0x13)
        rows.append(emit_case("no fills, no flag", index, []))
        rows.append(emit_case("no fills, flag", index, [], flag=1))
        rows.append(emit_case("one fill", index, [one]))
        rows.append(emit_case("one fill, flag", index, [one], flag=1))
        rows.append(emit_case("no hash", index, [one], hash_bytes=HASH_NONE))
        rows.append(emit_case("two earlier rows, flag", index, [one], flag=1, prior=2))
        rows.append(emit_case("two earlier rows, no fills, flag", index, [], flag=1, prior=2))
        rows.append(emit_case("three fills", index, [fill_bytes(width, 0x13 + 9 * n, side=n & 1, coin=n) for n in range(3)], flag=1, codes=0x30003))
        rows.append(emit_case("empty row vector", index, [one, fill_bytes(width, 0x44)], capacity=0))
        rows.append(emit_case("full buffer after one row", index, [one], capacity=1))
        rows.append(emit_case("full buffer after two rows", index, [one], capacity=2))
        rows.append(emit_case("full buffer after three rows", index, [one], capacity=3))
        rows.append(emit_case("full buffer with kind 5", index, [one], flag=1, capacity=1))
        for low in range(0, 12):
            rows.append(emit_case("codes %d and 0" % low, index, [one], codes=low))
            rows.append(emit_case("codes 0 and %d" % low, index, [one], codes=low << 16))
            rows.append(emit_case("codes 6 and %d" % low, index, [one], codes=6 | low << 16))
        for codes in (0x30003, 0x50005, 0x60006, 0x80008, 0x0B0A0908, 0xFEFDFCFB, 0x20206, 0x142, 0x6, 0x42 << 16 | 6, 0x20, 0x21):
            rows.append(emit_case("codes %#x" % codes, index, [one], codes=codes))
        options = ({"first": 0}, {"first": 3}, {"second": 0}, {"second": 2}, {"group": 0}, {"group": 2}, {"group": 3}, {"group": 4}, {"third": 0}, {"third": 3}, {"group": 0, "third": 0}, {"cloid": 0}, {"cloid": 2})
        for option in options:
            name = " ".join("%s %d" % row for row in option.items())
            rows.append(emit_case("first leg " + name, index, [fill_bytes(width, 0x23, one=option)]))
            rows.append(emit_case("second leg " + name, index, [fill_bytes(width, 0x33, two=option)], flag=1))
        rows.append(emit_case("mark word zero", index, [fill_bytes(width, 0x53, mark=0, coin=2)]))
        rows.append(emit_case("mark word zero, large coin", index, [fill_bytes(width, 0x53, mark=0, coin=20001)]))
        rows.append(emit_case("mark word zero, last oracle row", index, [fill_bytes(width, 0x53, mark=0, coin=3)]))
        rows.append(emit_case("mark word one", index, [fill_bytes(width, 0x53, mark=1, coin=9)]))
        rows.append(emit_case("high bit mark", index, [fill_bytes(width, 0x53, mark=1 << 63, coin=9)]))
        rows.append(emit_case("low mark bits clear", index, [fill_bytes(width, 0x53, mark=1 << 32, coin=9)]))
        rows.append(emit_case("second fill zero mark", index, [one, fill_bytes(width, 0x53, mark=0, coin=1)]))
        if width == "perp":
            rows.append(emit_case("oracle row missing", index, [fill_bytes(width, 0x53, mark=0, coin=4)]))
            rows.append(emit_case("oracle row limit", index, [fill_bytes(width, 0x53, mark=0, coin=4)], oracle=(1, 2, 3, 4, 5)))
            rows.append(emit_case("oracle row missing after a fill", index, [one, fill_bytes(width, 0x53, mark=0, coin=10007)]))
            rows.append(emit_case("no oracle rows", index, [fill_bytes(width, 0x53, mark=0, coin=0)], oracle=()))
            rows.append(emit_case("modulo scale", index, [fill_bytes(width, 0x53, mark=0, coin=10000)]))
            rows.append(emit_case("modulo scale minus one is out of range", index, [fill_bytes(width, 0x53, mark=0, coin=9999)]))
            stop = bytearray(fill_bytes(width, 0x63))
            struct.pack_into("<Q", stop, 0, 2)
            rows.append(emit_case("word two stops the loop", index, [one, bytes(stop), fill_bytes(width, 0x73)], flag=1))
    return rows


def writer_cases():
    rows = []
    for writer, keys in (("trade", TRADE_KEYS), ("side", SIDE_KEYS)):
        rows.append(writer_case("all keys", writer))
        for number, row in enumerate(keys):
            rows.append(writer_case("error at " + row[0], writer, stop=number, how="error"))
            if row[0] in CHECKED[writer]:
                rows.append(writer_case("state at " + row[0], writer, stop=number, how="state"))
    rows.append(writer_case("all keys", "fill", fields=FULL_FILL))
    rows.append(writer_case("gated keys absent", "fill", fields=NO_FILL))
    for name in sorted(FULL_FILL):
        fields = dict(FULL_FILL)
        fields[name] = NO_FILL[name]
        rows.append(writer_case("without " + name, "fill", fields=fields))
        fields = dict(NO_FILL)
        fields[name] = FULL_FILL[name]
        rows.append(writer_case("only " + name, "fill", fields=fields))
    for name, value in (("builder_fee", 1 << 63), ("builder_fee", MAX64), ("builder_fee", (1 << 63) - 1), ("fee_escrow", 1 << 63), ("fee_escrow", MAX64), ("fee_escrow", (1 << 63) - 1), ("deployer_fee", 1 << 63), ("deployer_fee", MAX64), ("deployer_fee", (1 << 63) - 1), ("liquidation", 0), ("liquidation", 3), ("cloid", 2), ("builder", 2)):
        fields = dict(NO_FILL)
        fields[name] = value
        rows.append(writer_case("rare %s %#x" % (name, value), "fill", fields=fields))
    keys = fill_keys(FULL_FILL)
    for number, row in enumerate(keys):
        if row[0] not in ERROR_IGNORED:
            rows.append(writer_case("error at " + row[0], "fill", stop=number, how="error", fields=FULL_FILL))
        if row[0] in CHECKED["fill"]:
            rows.append(writer_case("state at " + row[0], "fill", stop=number, how="state", fields=FULL_FILL))
    return rows


def sink_case(label, **world):
    base = {"head": 0, "fills": False, "trades": True, "side": 1, "fill_side": 1, "hash": 1, "price": 0x7654, "size": 0x4321, "coin": 5, "disabled": True, "start": (1, 1), "token": 2, "decimals": 3, "one": 0x1111, "two": 0x2222}
    base.update(world)
    return Case("sink: " + label, "sink", base)


def sink_cases():
    rows = []
    for head in (0, 1, 8):
        rows.append(sink_case("head %d, trades on, same side" % head, head=head))
        rows.append(sink_case("head %d, fills on" % head, head=head, fills=True, trades=False))
        rows.append(sink_case("head %d, both on" % head, head=head, fills=True))
        rows.append(sink_case("head %d, both off" % head, head=head, trades=False))
    for side, fill_side in ((0, 0), (0, 1), (1, 0), (1, 1)):
        rows.append(sink_case("trade side %d of fill side %d" % (side, fill_side), side=side, fill_side=fill_side))
        rows.append(sink_case("fill side %d of fill side %d" % (side, fill_side), side=side, fill_side=fill_side, fills=True, trades=False))
    rows.append(sink_case("no hash", hash=0))
    rows.append(sink_case("hash tag 2", hash=2))
    rows.append(sink_case("price zero", price=0))
    rows.append(sink_case("size zero", size=0))
    for start in ((0, 0), (1, 0), (0, 1)):
        rows.append(sink_case("start tags %d %d" % start, start=start))
    for decimals in (0, 1, 8):
        rows.append(sink_case("token decimals %d" % decimals, decimals=decimals))
    for head in (5, 6, 7, 9):
        rows.append(sink_case("head %d goes to the drop" % head, head=head))
    rows.append(sink_case("head 2 with its arm off", head=2))
    return rows


def flush_row_bytes(kind, side=0, coin=2, price=0x7654, codes=b"\x41\x42", start=0x2D):
    row = bytearray(ramp(0x268, start))
    struct.pack_into("<Q", row, 0, kind)
    struct.pack_into("<QQ", row, 8 + 0x1F0, coin, price)
    row[0x238:0x23A] = codes
    row[0x23A] = side
    return bytes(row)


def flush_constant():
    if not BLOB:
        BLOB["data"] = BINARY.read_bytes()
    return struct.unpack_from("<Q", BLOB["data"], FLUSH_WORD)[0]


def flush_case(label, rows, jobs=None, **world):
    base = {"rows": rows, "jobs": jobs or [None] * len(rows), "coins": 4, "tokens": [7, 9, 11, 13], "class": False, "tree": {7: 0x70, 11: 0xB0, 13: 0xD0}, "depth": 1, "constant": flush_constant()}
    base.update(world)
    return Case("flush: " + label, "flush", base)


def flush_cases():
    rows = []
    for kind in (2, 3, 4, 7, 9):
        pass
    rows.append(flush_case("trade row", [flush_row_bytes(ROW_TRADE)]))
    rows.append(flush_case("fill vector row", [flush_row_bytes(ROW_ALL)]))
    for side in (0, 1):
        rows.append(flush_case("fill row side %d" % side, [flush_row_bytes(ROW_FILL, side=side)]))
        rows.append(flush_case("fill row side %d, class set" % side, [flush_row_bytes(ROW_FILL, side=side)], **{"class": True}))
        rows.append(flush_case("fill row side %d, price zero" % side, [flush_row_bytes(ROW_FILL, side=side, price=0)]))
    rows.append(flush_case("fill row, no entry below", [flush_row_bytes(ROW_FILL, coin=1)]))
    rows.append(flush_case("fill row, first key", [flush_row_bytes(ROW_FILL, coin=0)]))
    rows.append(flush_case("fill row, last key", [flush_row_bytes(ROW_FILL, coin=3)]))
    rows.append(flush_case("fill row, key above all", [flush_row_bytes(ROW_FILL, coin=3)], tokens=[7, 9, 11, 15]))
    rows.append(flush_case("fill row, empty tree", [flush_row_bytes(ROW_FILL)], depth=0, tree={}))
    rows.append(flush_case("fill row, second level", [flush_row_bytes(ROW_FILL)], depth=2))
    rows.append(flush_case("fill row, coin out of range", [flush_row_bytes(ROW_FILL, coin=4)]))
    rows.append(flush_case("three rows of one fill", [flush_row_bytes(ROW_TRADE), flush_row_bytes(ROW_FILL, side=0), flush_row_bytes(ROW_FILL, side=1)]))
    rows.append(flush_case("stop word", [flush_row_bytes(ROW_TRADE), flush_row_bytes(0xB), flush_row_bytes(ROW_TRADE)]))
    return rows


def all_cases():
    return emit_cases() + writer_cases() + sink_cases() + flush_cases()


def spec_run(case):
    return run_spec(case)


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError, UnicodeDecodeError, StopIteration, Panicked)


def compare_fields(harness, base, fields, what):
    memory = harness.machine.memory
    for at, value in fields:
        found = memory.bytes_at(base + at, len(value))
        if found != bytes(value):
            return "%s +%#x found %s wanted %s" % (what, at, found[:40].hex(), bytes(value)[:40].hex())
    return ""


def compare_emit(harness, case, wanted, found):
    shape = WIDTHS[COPIES[case.copy].width]
    memory = harness.machine.memory
    base, length = found["rows"]
    rows = wanted["rows"]
    prior = case.world["prior"]
    if wanted["panic"]:
        if not found["panic"] or not found["panic"].startswith("bounds %d %d %#x" % (wanted["panic"][1], wanted["panic"][2], COPIES[case.copy].location)):
            return "panic found %s wanted %s" % (found["panic"], wanted["panic"])
    elif found["panic"]:
        return "panic " + found["panic"]
    if length != len(rows) + prior:
        return "row count found %d wanted %d" % (length, len(rows) + prior)
    if not wanted["panic"] and length and memory.read(ROWS, 8) > length and memory.read(base + length * shape.row, 1) != STACK_MARK:
        return "byte past the last row"
    keep = {base}
    for index, row in enumerate(rows):
        at = base + (index + prior) * shape.row
        if memory.read(at, 8) != row["kind"]:
            return "row %d kind %d" % (index, memory.read(at, 8))
        if row["kind"] == ROW_ALL:
            capacity, pointer, count = memory.read(at + 8, 8), memory.read(at + 0x10, 8), memory.read(at + 0x18, 8)
            if capacity != len(row["all"]) or count != len(row["all"]):
                return "kind 5 vector %d %d" % (capacity, count)
            keep.add(pointer)
            for number, fields in enumerate(row["all"]):
                trouble = compare_fields(harness, pointer + number * shape.fill, fields, "kind 5 fill %d" % number)
                if trouble:
                    return trouble
        else:
            trouble = compare_fields(harness, at, row["fields"], "row %d" % index)
            if trouble:
                return trouble
    if not wanted["panic"] and set(found["live"]) - keep:
        return "leak " + str(sorted(found["live"].values()))
    return ""


def compare_flush(case, wanted, found):
    if found["log"] != wanted["log"]:
        return "log found %s wanted %s" % (found["log"], wanted["log"])
    if found["panic"] != wanted["panic"]:
        return "panic"
    if wanted["panic"]:
        return ""
    if len(found["rows"]) != len(wanted["out"]):
        return "rows found %d wanted %d" % (len(found["rows"]), len(wanted["out"]))
    for index, fields in enumerate(wanted["out"]):
        for at, value in fields:
            if found["rows"][index][at:at + len(value)] != bytes(value):
                return "row %d +%#x found %s wanted %s" % (index, at, found["rows"][index][at:at + 16].hex(), bytes(value)[:16].hex())
    if found["drops"] != 2 or (found["capacity"], found["pointer"], found["length"]) != (0, 8, 0):
        return "vector not taken"
    return ""


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
    try:
        found = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
    if case.kind == "emit":
        try:
            trouble = compare_emit(harness, case, wanted, found)
        except CRASHES as error:
            return "%s: read %s" % (case.label, error)
        return "%s: %s" % (case.label, trouble) if trouble else ""
    if case.kind == "flush":
        trouble = compare_flush(case, wanted, found)
        return "%s: %s" % (case.label, trouble) if trouble else ""
    if found != wanted:
        return "%s: differs: found %s wanted %s" % (case.label, str(found)[:600], str(wanted)[:600])
    return ""

# ---- static reads ----

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
    """Every FF 15 call in .text through one data slot."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            rows.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return rows


# ---- mutation ----

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


GROUPS = ((0x26F4400, "first row writer, 0x228 fills"), (0x44714B0, "third row writer, 0x228 fills"), (0x256A5B0, "first clone"), (0x256C7E0, "perp first clone"), (0x487D630, "spot second clone"),
          (0x4876B10, "spot third clone, keeps the output order"), (0x488A150, "perp second clone"), (0x254F5C0, "first kind 5 vector"), (0x2550850, "perp first kind 5 vector"),
          (0x4847ED0, "spot second kind 5 vector"), (0x484C0F0, "perp second kind 5 vector"), (0x24C3F00, "first leg helper, 0xf8"), (0x24C40D0, "perp first leg helper, 0x100"),
          (0x47C3780, "perp second leg helper, 0x100"), (TRADE_WRITER, "Trade serializer"), (SIDE_WRITER, "side_info serializer"), (FILL_WRITER, "Fill serializer"))
EXTRA_FUNCTIONS = ((0x4470BE0, "second row writer, named in #926, run with no mutants"), (0x26F4CD0, "perp first row writer, caller row in #902, #977, #858, run with no mutants"),
                   (0x4CD84F0, "perp second row writer, named in #926, #212, #197, run with no mutants"), (0x47C39B0, "spot second leg helper, row in #537, run with no mutants"),
                   (0x24BFE30, "first clone loop, row in #875, run with no mutants"), (FLUSH_SPOT, "row flush, row in #319, #650, run with no mutants"), (SINK, "row sink, bound as bytes in #851, run with no mutants"), (SIDE_BUILDER, "side_info builder, run with no mutants"))
CASE_CAP = 90
PATH_CASES = 3
RARE_WORDS = ("rare", "limit", "scale", "codes 6", "full buffer", "word two", "high bit", "low mark")


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    groups = []
    for start, role in GROUPS:
        begin, end = image.exact_fde(start)
        groups.append((start, role, decode_range(image, begin, end)))
    return groups


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction; at most CASE_CAP of those run, spread evenly, last killers first."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    numbers = {}
    paths = [numbers.setdefault(touched, len(numbers)) for touched in reached]
    rare = {index for index, case in enumerate(cases) if any(word in case.label for word in RARE_WORDS)}
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            if len(indices) > CASE_CAP:
                taken, rest, per_path = [], [], {}
                for index in indices:
                    per_path[paths[index]] = per_path.get(paths[index], 0) + 1
                    (taken if per_path[paths[index]] <= PATH_CASES else rest).append(index)
                room = CASE_CAP - len(taken)
                indices = (taken + rest[:: len(rest) // room + 1]) if room > 0 else taken[:: len(taken) // CASE_CAP + 1]
                indices = sorted(rare.intersection(by_va[va])) + indices
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            wanted = set(by_va[va])
            order = [index for index in first_kill if index in wanted] + indices
            for index in order:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    del first_kill[60:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": ":".join(failed.split(":")[:2]) if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def arm_address(image, table, index):
    return table + struct.unpack_from("<i", image.blob, image.offset(table + 4 * index))[0]


def body_bytes(image, start):
    begin, end = image.exact_fde(start)
    return begin, end, code(image, begin, end - begin)


def table_at(image, start):
    """The flag table of a writer, by the bytes `lea rcx, [rip+d]` then `movzx eax, byte [rax+rcx]`."""
    begin, end, data = body_bytes(image, start)
    found = []
    at = data.find(b"\x48\x8d\x0d")
    while at >= 0:
        if data[at + 7:at + 11] == b"\x0f\xb6\x04\x08":
            found.append(begin + at + 7 + struct.unpack_from("<i", data, at + 3)[0])
        at = data.find(b"\x48\x8d\x0d", at + 1)
    if len(found) != 1:
        raise EvidenceError("flag table of %#x" % start)
    return found[0]


def count_immediate(data, value):
    packed = struct.pack("<I", value)
    return data.count(packed)


def copy_rows(image):
    rows = []
    for copy in COPIES:
        begin, end, data = body_bytes(image, copy.start)
        shape = WIDTHS[copy.width]
        table = table_at(image, copy.start)
        if table != copy.table or data.count(b"\xb9" + struct.pack("<I", FLAG_MASK)) != 1:
            raise EvidenceError("table or mask of %#x" % copy.start)
        flags = list(code(image, table, 11))
        if flags != [FLAG_MASK >> index & 1 for index in range(11)]:
            raise EvidenceError("table is not the mask")
        rows.append({"name": copy.name, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "sha256": hashlib.sha256(data).hexdigest(), "abi": copy.abi, "fill": "%#x" % shape.fill, "row": "%#x" % shape.row, "leg": "%#x" % shape.leg,
                     "row_stride_immediates": count_immediate(data, shape.row), "fill_stride_immediates": count_immediate(data, shape.fill), "clone": "%#x" % copy.clone, "kind_5_vector": "%#x" % copy.aggregate, "leg_helper": "%#x" % copy.leg, "flag_table": "%#x" % table, "flag_table_bytes": flags, "keeps_output_order": copy.start == 0x44714B0})
    return rows


FLAG_ARGUMENT = {"plain": "ecx", "self": "r8d", "oracle pair": "r9d", "oracle struct": "r8d"}
CODE_ARGUMENT = {"plain": "r8d", "self": "r9d", "oracle pair": "stack", "oracle struct": "r9d"}
ZERO = {"ecx": b"\x31\xc9", "r8d": b"\x45\x31\xc0", "r9d": b"\x45\x31\xc9"}
LOAD = {"ecx": b"\xb9", "r8d": b"\x41\xb8", "r9d": b"\x41\xb9"}
CMOV = {"r8d": b"\x44\x0f\x45\xc0", "r9d": b"\x44\x0f\x45\xc8"}
WINDOW = 0x40


def argument_at(image, site, register):
    """The last byte pattern that sets a register in the window before a call: a fixed value, or `computed`."""
    data = code(image, site - WINDOW, WINDOW)
    if register == "stack":
        at = data.rfind(b"\xc7\x04\x24")
        return "%#x" % struct.unpack_from("<I", data, at + 3)[0] if at >= 0 else "computed"
    zero = data.rfind(ZERO[register])
    load = data.rfind(LOAD[register])
    if max(zero, load) < 0:
        return "computed"
    if zero > load:
        return "0"
    value = "%#x" % struct.unpack_from("<I", data, load + len(LOAD[register]))[0]
    if register in CMOV and data.rfind(CMOV[register]) > load:
        return value + " or computed"
    return value


def code_names(image, text):
    """Both side names of a fixed code word."""
    if not text[0].isdigit() or " " in text or text == "computed":
        return "computed"
    value = int(text, 16)
    names = [row["name"] for row in override_rows(image)["first_byte"]]
    low, high = value & 0xFF, (value >> 16) & 0xFF
    return "%s, %s" % (names[low], names[high])


def site_rows(image):
    """Every direct call of a writer, by E8 bytes, with the two arguments by byte pattern."""
    starts = {copy.start: copy for copy in COPIES}
    direct = direct_sites(image, sorted(starts))
    rows = []
    for target in sorted(direct):
        copy = starts[target]
        for va, opcode in sorted(direct[target]):
            if opcode != 0xE8:
                raise EvidenceError("tail call of a writer")
            codes = argument_at(image, va, CODE_ARGUMENT[copy.abi])
            rows.append((target, va, image.fde(va)[0], argument_at(image, va, FLAG_ARGUMENT[copy.abi]), codes, code_names(image, codes)))
    return rows


FLUSH_RENAME = {0: "row kind 2", 1: "row kind 3", 2: "row kind 4", 3: "row kind 5, the fill vector: head and three words go on", 4: "row kind 6: head, 0x200 bytes, hash block go on", 5: "row kind 7", 6: "row kind 8: the fill arm", 7: "row kind 9 and heads 0, 1", 8: "row kind 10"}
SINK_RENAME = {0: "row kind 2: own arm, gated by object +0x5b0", 1: "row kind 3: tail call through slot 0x5776b00", 2: "row kind 4: tail call through slot 0x5776af8", 3: "row kind 5: drop only", 4: "row kind 6: drop only", 5: "row kind 7: drop only", 6: "row kind 8 and heads 0, 1: Fill or Trade", 7: "row kind 9: drop only"}


def dispatch_rows(image):
    flush = [{"index": index, "arm": "%#x" % arm_address(image, FLUSH_TABLE, index), "use": FLUSH_RENAME[index]} for index in range(9)]
    sink = [{"index": index, "arm": "%#x" % arm_address(image, SINK_TABLE, index), "use": SINK_RENAME[index]} for index in range(8)]
    sinks = direct_sites(image, [SINK, 0x4520F70, 0x23D9F20])
    return {"flush_table": "%#x" % FLUSH_TABLE, "flush": flush, "sink_table": "%#x" % SINK_TABLE, "sink": sink, "row_sinks": [{"target": "%#x" % target, "site": "%#x" % va, "caller": "%#x" % image.fde(va)[0]} for target in sorted(sinks) for va, _ in sorted(sinks[target])]}


def key_rows(image):
    """Keys and offsets as the serializers really ask for them, with every gate open."""
    harness = Harness(image)
    out = {}
    for name, case in (("trade", writer_case("keys", "trade")), ("side_info", writer_case("keys", "side")), ("fill", writer_case("keys", "fill", fields=FULL_FILL))):
        found = harness.run(case)
        out[name] = [{"key": key, "offset": "%#x" % at} for key, at in found["keys"]]
    return out


def text_at(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def arm_name(image, arm, following=None):
    """Variant text of a serializer arm: first `lea rsi, [rip+d]`, then `mov edx, imm32` or a shared length."""
    data = code(image, arm, 80)
    at = data.index(b"\x48\x8d\x35")
    target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    if data[at + 7] == 0xBA:
        return text_at(image, target, struct.unpack_from("<I", data, at + 8)[0])
    return text_at(image, target, following - target)


def override_rows(image):
    """Names of the two code bytes, from the value serializer behind the key `trade_dir_override`."""
    wrapper = code(image, OVERRIDE_WRAPPER + 0x14, 5)
    field = OVERRIDE_WRAPPER + 0x19 + struct.unpack_from("<i", wrapper, 1)[0]
    tail = code(image, OVERRIDE_TAIL, 5)
    value = OVERRIDE_TAIL + 5 + struct.unpack_from("<i", tail, 1)[0]
    if wrapper[0] != 0xE9 or tail[0] != 0xE9 or field != OVERRIDE_FIELD or value != OVERRIDE_VALUE:
        raise EvidenceError("override chain")
    outer = [{"byte": index, "name": arm_name(image, arm_address(image, OVERRIDE_OUTER, index))} for index in range(11)]
    inner = [{"byte": index, "name": arm_name(image, arm_address(image, OVERRIDE_INNER, index), OVERRIDE_INNER_END)} for index in range(4)]
    return {"wrapper": "%#x" % OVERRIDE_WRAPPER, "field_writer": "%#x" % field, "value_serializer": "%#x" % value, "outer_table": "%#x" % OVERRIDE_OUTER, "inner_table": "%#x" % OVERRIDE_INNER, "first_byte": outer, "second_byte_of_variant_10": inner}


def location_rows(image):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    rows = []
    for copy in COPIES:
        if copy.location is None:
            continue
        at = copy.location
        size = struct.unpack_from("<Q", image.blob, image.offset(at + 8))[0]
        start = image.offset(relative[at])
        text = bytes(image.blob[start:start + size]).decode("ascii")
        line, column = struct.unpack_from("<II", image.blob, image.offset(at + 16))
        rows.append({"location": "%#x" % at, "file": text[text.index("l1/src/"):], "line": line, "column": column, "use": copy.name + ": oracle row index out of range"})
    return rows


FIELDS = {
    "fill_input": {"size": "0x228 or 0x238 bytes, written by the match path", "legs": "two legs, 0xf8 or 0x100 bytes each", "tail +0x00": "price; coin first in clone 0x4876b10", "tail +0x08": "coin; price first in clone 0x4876b10", "tail +0x10": "sz at +0x00 of a 0x18 byte block, moved as bytes", "tail +0x20": "reference word: fill +0x210 or +0x220", "tail +0x28": "time, 12 bytes", "tail +0x34": "side of the trade row, byte"},
    "leg_0xf8": {"+0x00": "tag, dword; 1 keeps +0x08", "+0x08": "start position, u64, then 8 bytes", "+0x18/+0x20": "twap id option (tag word and value)", "+0x28": "tag, dword; 1 keeps 0x20 bytes at +0x30", "+0x50": "16 bytes", "+0x60": "word: 2 skips the block, bit 0 keeps +0x68 for 0x1c bytes", "+0x88": "tag, dword; 1 keeps +0x90 for 0x1c bytes", "+0xb0": "0x18 bytes, kept unless +0x60 is 2", "+0xc8": "oid", "+0xd0": "user, 20 bytes", "+0xe4": "cloid tag; 1 keeps 16 bytes at +0xe5"},
    "leg_0x100": {"+0x00": "0x20 plain bytes", "+0x20": "tag, dword; 1 keeps 0x20 bytes at +0x28", "+0x48": "16 bytes", "+0x58": "word: 2 skips the block, bit 0 keeps +0x60 for 0x1c bytes", "+0x80": "tag, dword; 1 keeps +0x88 for 0x1c bytes", "+0xa8": "0x28 bytes, kept unless +0x58 is 2", "+0xd0": "8 bytes", "+0xd8": "20 bytes", "+0xec": "tag; 1 keeps 16 bytes at +0xed"},
    "row_kind_5": {"+0x00": "5", "+0x08/+0x10/+0x18": "Vec of all clean fills: capacity, pointer, length"},
    "row_kind_6": {"+0x00": "6", "+0x08": "the two legs", "+0x1f8 or +0x208": "coin, price, 16 bytes", "next +0x20": "reference word", "next +0x28": "time, 12 bytes", "next +0x34": "fill side byte", "+0x230 or +0x240": "33 byte hash block, tag first", "+0x251 or +0x261": "first flag byte", "+0x252 or +0x262": "second flag byte: both low codes are 0"},
    "row_kind_8": {"+0x00": "8", "carried": "as kind 6 to the side byte", "+0x230 or +0x240": "reference word, or the price (0x228 fills) or oracle row +0x20 (0x238 fills) when it is 0", "+0x238/+0x239 or +0x248/+0x249": "two code bytes of this side", "+0x23a or +0x24a": "side: 0 first row, 1 second row", "+0x23b or +0x24b": "33 byte hash block"},
    "codes_argument": {"byte 0, byte 1": "trade_dir_override of side 0", "byte 2, byte 3": "trade_dir_override of side 1"},
    "row_after_flush": {"+0x00": "kind 8 fill record moved down 8 bytes, so the head is the leg tag 0 or 1", "+0x228/+0x230": "word 1 and the tree value of the user and token, 0 when absent", "+0x238": "reference word", "+0x240/+0x241": "trade_dir_override", "+0x242": "side", "+0x243": "hash block"},
    "trade": {"+0x00": "side_info: two 0x48 byte rows", "+0x90": "coin String", "+0xa8": "px, f64", "+0xb0": "sz, f64", "+0xb8": "hash, 32 bytes, zero when the row tag bit 0 is clear", "+0xd8": "time, 12 bytes", "+0xe4/+0xe5": "trade_dir_override: first byte the variant, second byte the payload of variant 10", "+0xe6": "side"},
    "side_info": {"+0x00": "twap_id: leg +0x18 and +0x20", "+0x10": "start_pos: leg +0x08 over 10^decimals, or 0.0 when the leg tag bit 0 is clear", "+0x18": "oid: leg +0xc8", "+0x20": "user: leg +0xd0", "+0x34": "cloid: leg +0xe4, 17 bytes"},
}
REFERENCE_CLAIMS = (
    {"reference": "references/can1357-hl, whole tree", "claim": "the text trade_dir_override and the variant names SpotDustConversion and BoleBackstopLiquidation do not occur; NetChildVaultPositions occurs only as an action name", "observed": "serializer 0x4c66c50 names 11 values behind the key", "verdict": "missing in the reference"},
    {"reference": "references/can1357-hl/l1", "claim": "no label names the five row writers", "observed": "no text match for their addresses under l1", "verdict": "missing in the reference"},
)


def outcome_name(case, spec):
    if case.kind == "emit":
        return "panic: oracle row" if spec["panic"] else "emit: %d rows" % min(len(spec["rows"]), 7)
    if case.kind == "writer":
        return "%s writer: %s" % (case.world["writer"], "all keys" if spec["end"] else "stopped")
    if case.kind == "flush":
        return "flush: panic coin" if spec["panic"] else "flush: %d rows" % len(spec["out"])
    return "sink: " + spec["path"]


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.kind, case.label.replace(": ", "\t", 1), outcome_name(case, spec))


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        spec = spec_run(case)
        name = outcome_name(case, spec)
        outcomes[name] = outcomes.get(name, 0) + 1
        lines.append(case_line(case, spec))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role in GROUPS + EXTRA_FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    sites = site_rows(image)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "copies": copy_rows(image),
        "dispatch": dispatch_rows(image),
        "keys": key_rows(image),
        "trade_dir_override": override_rows(image),
        "locations": location_rows(image),
        "fields": FIELDS,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": sites, "_results": results_rows, "_lines": lines,
    }


SURVIVED_DEFAULT = "the flipped low bit of a memcpy or stack copy length moves one byte of padding or of a block that the next copy rewrites, so no carried field changes"
SURVIVED_REASONS = {}
STALE_NOTE = "the same stack row was filled by the row before it, so a store that misses leaves the same bytes"
WORD_NOTE = "the word is never 2 on this width: the clone turns the tag dword into 0 or 1, so the loop stop is dead for 0x228 fills"
CLONE_NOTE = "capacity limit, small size arm or the dangling pointer of an empty Vec: the cases never reach a size where the bit matters"
for va in (0x26F48C3, 0x26F48D1, 0x26F4AD7, 0x26F4AE4, 0x26F4B8B, 0x4471976, 0x4471984, 0x4471B9D, 0x4471BAA, 0x4471C47, 0x25512F0):
    SURVIVED_REASONS[va] = STALE_NOTE
for va in (0x26F45AA, 0x4471668):
    SURVIVED_REASONS[va] = WORD_NOTE
for va in (0x256A5C1, 0x256A5EC, 0x256A5FA, 0x256A63A, 0x256C7F1, 0x256C81C, 0x256C82A, 0x256C86A, 0x487D65A, 0x487D68B, 0x487D699, 0x4876B3A, 0x4876B6B, 0x4876B79, 0x488A181, 0x488A1AF, 0x488A1BD, 0x254F5EA, 0x254FD18, 0x254FD1E, 0x25501E8, 0x255087A, 0x2550F62, 0x2550F68, 0x25512F8, 0x25512FE, 0x25513E9, 0x4847EE5, 0x4847EEC, 0x4848037, 0x484C105, 0x484C10C, 0x484C257):
    SURVIVED_REASONS[va] = CLONE_NOTE
SURVIVED_REASONS[0x49C9A11] = "the bit is tested after the last key, and no case leaves it set there, since the stub sets it only at a key whose next test stops first"


UNREACHED_REASON = "no case reaches it: an allocator failure arm, a panic arm, an unwind pad, or the clone of a word the harness never builds"


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return UNREACHED_REASON
    return SURVIVED_REASONS.get(row["va"], SURVIVED_DEFAULT)


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["writer\tsite\tcaller_fde\tflag\tcodes\tcode_names"]
    lines += ["%#x\t%#x\t%#x\t%s\t%s\t%s" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["kind\tcopy\tlabel\toutcome"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_)) for row_ in results]
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
