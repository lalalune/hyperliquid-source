#!/usr/bin/env python3
"""Pin the node #94 trigger order path from ELF bytes: which untriggered orders fire and what one firing does.

Selection `0x4321930` (copy `0x4320f80`, inlined in the host `0x27078a0`) walks `user_states` of one book, compares each trigger price
with a reference price, and returns (user, oid) rows sorted by size. Firing `0x42ff010` (copy `0x4300950`, inlined with its wrapper in
`0x27371f0`) turns one stored 0xb8 byte order into a 1.1 or 0.9 limit, caps it at the opposite best, asks the price gate, writes the
event rows, calls insert, and removes the order from field `u`. Wrappers `0x4d44470` and `0x4d47070` find the book and flush the rows.
The real bytes run in a Python evaluator with every edge callee stubbed. A separately written specification predicts every result, and
every condition, immediate and field offset is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary
is never executed. Standard library only.
"""

import argparse
import bisect
import collections
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

Copy = collections.namedtuple("Copy", "name select fire wrap insert build relation tick top remove count tree_insert tree_set flush dex_field byte_field count_field tree_field rows_field")
COPIES = (
    Copy("first", 0x4321930, 0x42FF010, 0x4D44470, 0x4311140, 0x43029D0, 0x430D380, 0x42C7600, 0x4A078A0, 0x4946940, 0x47D7CA0, 0x495A170, 0x4935BE0, 0x432A100, 0x1040, 0x1372, 0x11C0, 0x1320, 0x3DF0),
    Copy("second", 0x4320F80, 0x4300950, 0x4D47070, 0x4314DA0, 0x43029D0, 0x430D380, 0x42C7600, 0x4A078A0, 0x4946940, 0x47D7CA0, 0x495A170, 0x4935BE0, 0x4329870, 0x5C0, 0x8F2, 0x740, 0x8A0, 0x3370),
    Copy("third", None, None, 0x27371F0, 0x26EBDC0, 0x26E37A0, 0x26E7F30, 0x230B390, 0x23978C0, 0x28660A0, 0x1F849B0, 0x287A770, 0x2854ED0, 0x24FB610, 0x5C0, 0x8F2, 0x740, 0x8A0, 0x3370),
)
HOST_SITES = ((0x4CF37F0, 0x4321930, "select"), (0x4CF94A0, 0x4320F80, "select"), (0x4CF37F0, 0x42FF010, "fire"), (0x4CF94A0, 0x4300950, "fire"), (0x4CF37F0, 0x4D44470, "wrap"), (0x4CF94A0, 0x4D47070, "wrap"), (0x27078A0, 0x27371F0, "wrap"))
TOP_PAIR = 0x4A07680
DROP_WORD = 0x3379490

SLOT_NAMES = {0x5773A48: 0x3713F20, 0x5774860: 0x3714E70, 0x57747E0: 0x342A600, 0x5773D58: 0x454ECB0, 0x576F488: 0x14385C0}
SLOT_CAP = 0x5773A48
SLOT_GATE = 0x5774860
SLOT_TRACKER = 0x57747E0
SLOT_ROWS = 0x5773D58
SLOT_LOG = 0x576F488
SLOT_RECORD = 0x5773190
SLOT_GROW = 0x57749A0
SLOT_POSITION_DIRECT = 0x36F57F0
SLOT_SORT = 0x57765F8
SLOT_SORT_SECOND = 0x57749B0
SLOT_MEMCMP = 0x576E488
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_REALLOC = 0x576E030
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576E468, 0x576DFB8, 0x576E020, 0x576E108)
ONCE_WORD = 0x577AB98
SLOT_ONCE = 0x576E8B8
RECORD_ROWS = {0x571C978: "size", 0x571CA68: "notional", 0x56BD7E0: "size", 0x56BD8D0: "notional"}
TEXT_LIMIT = 0x6F058E
TEXT_OPP = 0x6F0593
STATUS_TABLE = 0x6F1668
CONSTANTS = ((0x20A8B8, 1.1), (0x20AC60, 0.9), (0x20A278, -1.0), (0x20A2F8, 0.01))

ROW_STRIDE = 0x138
BOOK_STRIDE = 0xD8
DEX_STRIDE = 0x2F0
MARK_STRIDE = 0x60
EVENT_STRIDE = 0x278
FILL_STRIDE = 0x238
USER_SIZE = 20
ORDER_SIZE = 0xB8
MAX64 = (1 << 64) - 1
NONE_WORD = 1 << 63
WORD_REJECTED = NONE_WORD + 1
WORD_NO_USER = NONE_WORD + 2
WORD_NO_ORDER = NONE_WORD + 3

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
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 200000

STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0x4800
ROWS = HEAP_BASE + 0x6000
DEXES = HEAP_BASE + 0x7000
MARKS = HEAP_BASE + 0x9000
BOOKS = HEAP_BASE + 0xB000
CTRL = HEAP_BASE + 0xE100
USER_ARG = HEAP_BASE + 0xE300
OUT = HEAP_BASE + 0xE400
EVENTS = HEAP_BASE + 0xE480
CLOSURE = HEAP_BASE + 0xE500
WORDS = HEAP_BASE + 0xE540
RELATIONS = HEAP_BASE + 0xE600
COUNTER = HEAP_BASE + 0xE700
POSITIONS = HEAP_BASE + 0xE800
HEAP_FREE = HEAP_BASE + 0x10000

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



# ---- specification, written from a reading of the bytes and kept independent of the evaluator ----

STATUS_BY_INDEX = bytes.fromhex("1112120506151616")
FACTOR_BUY = 1.1
FACTOR_SELL = 0.9


def user_id(number):
    return bytes((number * 37 + index * 11 + 3) & 0xFF for index in range(USER_SIZE))


def order(oid, side=0, trigger=1000000, kind=0, market=1, limit=777777, reduce=0, skip=0, present=1, size=5000, items=2, first=0, second=0):
    """One stored untriggered order: value field names by offset."""
    return {"oid": oid, "side": side, "trigger": trigger, "kind": kind, "market": market, "limit": limit, "reduce": reduce, "skip": skip, "present": present, "size": size, "items": items, "first": first, "second": second}


def holder(number, orders=(), root=True, height=0, length=None):
    return {"user": number, "orders": list(orders), "root": root, "height": height, "length": length}


def order_bytes(item):
    data = bytearray(ramp(ORDER_SIZE, 0x31 + (item["oid"] & 0x3F)))
    data[0x00:0x08] = item["present"].to_bytes(8, "little")
    data[0x08:0x10] = item["size"].to_bytes(8, "little")
    data[0x10] = item["skip"]
    data[0x48:0x4C] = item["first"].to_bytes(4, "little")
    data[0x80:0x88] = item["limit"].to_bytes(8, "little")
    data[0x90] = item["reduce"]
    data[0x91] = item["second"]
    data[0xA2] = item["side"]
    data[0xA8:0xB0] = item["trigger"].to_bytes(8, "little")
    data[0xB0] = item["market"]
    data[0xB1] = item["kind"]
    return bytes(data)


def order_items(item):
    return [0x1000 + item["oid"] * 16 + at for at in range(item["items"])]


def signed(value):
    return value - (1 << 64) if value >> 63 else value


def average(left, right):
    return (left & right) + ((left ^ right) >> 1)


def after_seconds(date, secs, nanos, amount):
    """Date word plus seconds inside one year; the date word moves by 0x10 per day."""
    total = secs + amount
    return (date + 0x10 * (total // 86400), total % 86400, nanos)


def as_signed32(value):
    return value - (1 << 32) if value >> 31 else value


def reference_price(w, mid):
    local = w["asset"] % 10000
    marks = w["marks"]
    if local >= len(marks):
        return mid
    row = marks[local]
    then = after_seconds(row["date"], row["secs"], row["nanos"], 20)
    now = w["now"]
    if (as_signed32(now[0]), now[1], now[2]) <= (as_signed32(then[0]), then[1], then[2]):
        return row["px"]
    return mid


def fires(item, reference):
    trigger, side = item["trigger"], item["side"]
    if trigger == reference:
        return True
    if item["kind"] == 1:
        return (trigger < reference) != bool(side)
    return (reference < trigger) != bool(side)


def reduce_size(w, number, item):
    """(present, size) of a reduce only order; the size comes from the position."""
    position = w["positions"].get(number)
    if position is None or position.get("root_absent"):
        return 0, 0
    size = position["rows"].get(w["asset"])
    if not size:
        return 0, 0
    long = size > 0
    if long != bool(item["side"]):
        return 0, 0
    amount = abs(size)
    if item["present"]:
        amount = min(item["size"], amount)
    return 1, amount


def selection(w):
    """The result of 0x4321930: None, or rows of (user, oid) with mid, reference and asset."""
    left, right = w["top"]
    if not left or not right:
        return {"none": True}
    mid = average(left, right)
    if w["asset"] // 10000 >= w["dexes"]:
        return {"panic": True}
    reference = reference_price(w, mid)
    rows = []
    if not w.get("users_absent"):
        for entry in sorted(w["users"], key=lambda one: user_id(one["user"])):
            if not entry["root"] or not entry["orders"] or (entry["length"] == 0):
                continue
            for item in sorted(entry["orders"], key=lambda one: one["oid"]):
                if item["skip"] or not fires(item, reference):
                    continue
                present, size = item["present"], item["size"]
                if item["reduce"]:
                    present, size = reduce_size(w, entry["user"], item)
                rows.append((size if present else 0, user_id(entry["user"]).hex(), item["oid"]))
    rows.sort(key=lambda row: row[0])
    capacity = 0
    if rows:
        capacity = 4
        while capacity < len(rows):
            capacity *= 2
    return {"none": False, "rows": [[user, oid] for _, user, oid in rows], "capacity": capacity * 0x28 // 0x20, "mid": mid, "reference": reference, "asset": w["asset"]}


def round_half_away(value):
    whole = math.floor(value)
    return whole + 1 if value - whole >= 0.5 else whole


def to_price(trigger, side):
    """The rounded product, saturating, at least 1."""
    product = float(trigger) * (FACTOR_SELL if side else FACTOR_BUY)
    rounded = max(round_half_away(product), 0)
    return max(min(int(rounded), MAX64), 1)


def on_tick(price, tick, side):
    count = price // tick
    if side:
        count = min(count + 1, MAX64)
    return min(count * tick, MAX64)


def priced(w, item):
    """(rounded limit, sent price, text of the capped side)."""
    side = item["side"]
    start = to_price(item["trigger"], side)
    scaled = on_tick(start, w["tick"], side)
    limit = max(scaled, 1)
    opposite = w["top_pair"][0 if side else 1] or limit
    flag = (scaled > opposite) != bool(side)
    sent = opposite if flag else limit
    text = "opp" if opposite != limit and flag else "limit"
    return start, limit, sent, text


def date_millis(date, secs, nanos):
    year = date >> 13
    ordinal = (date >> 4) & 0x1FF
    before = year - 1
    days = ordinal + before * 1461 // 4 - before // 100 + (before // 100) // 4 - 719163
    return max((days * 86400 + secs) * 1000 + nanos // 1000000, 0)


def find_order(entry, oid):
    if not entry["root"]:
        return None
    for item in entry["orders"]:
        if item["oid"] == oid:
            return item
    return None


def tail(w, log, entry, removed, dex):
    """Removal from field u, the resting test, the per-user count and the changed-asset set."""
    number = entry["user"]
    log.append(["remove", user_id(number).hex(), w["oid"]])
    if w["oid"] not in w["resting"]:
        log.append(["tracker", user_id(number).hex()])
    if removed is None:
        return
    log.append(["count", user_id(number).hex()])
    log.append(["changed", "found" if number in w["changed"] else "new", user_id(number).hex(), w["asset"]])


def build_row(w, item, dex):
    data = order_bytes(item)
    tag = 1 if item["first"] == 1 else 0
    second = 1 if item["second"] == 1 else 0
    return ["build", user_id(w["user"]).hex(), w["oid"], dex, data[:0x30].hex(), order_items(item), tag, data[0x50:0x70].hex() if tag else "", data[0x70:0x90].hex(), item["reduce"], second,
            data[0x92:0xA2].hex() if second else "", item["side"], data[0xA8:0xB2].hex()]


def event(item, status, w, record):
    data = bytearray(order_bytes(item))
    tag = 1 if item["first"] == 1 else 0
    return ["event", 3, 2, tag, data[0x50:0x70].hex() if tag else "", record, list(w["now"]), user_id(w["user"]).hex(), status]


def firing(w):
    """The result of 0x42ff010: word, optional fields, the ordered edge log, and final words."""
    log = []
    out = {"log": log, "count": w["count"]}
    entry = next((one for one in w["users"] if one["user"] == w["user"]), None) if not w.get("users_absent") else None
    if entry is None:
        out["word"] = WORD_NO_USER
        return out
    item = find_order(entry, w["oid"])
    dex = w["asset"] // 10000
    if item is None:
        out["word"] = WORD_NO_ORDER
        tail(w, log, entry, None, dex)
        return out
    if dex >= w["dexes"]:
        return {"panic": True, "log": log}
    side = item["side"]
    start, limit, sent, text = priced(w, item)
    log.append(["tick", dex, w["asset"], start])
    log.append(["gate", dex, w["gate_byte"], w["asset"], side, sent, list(w["now"])])
    if not w["gate"]:
        out.update({"word": WORD_REJECTED, "px": sent, "text": text, "oid": w["oid"], "user": user_id(w["user"]).hex(), "side": side})
        return out
    log.append(["cap", dex, w["asset"]])
    log.append(build_row(w, item, dex))
    log.append(event(item, 3, w, 1))
    data = order_bytes(item)
    second = 1 if item["second"] == 1 else 0
    tag = 1 if item["first"] == 1 else 0
    price = limit if item["market"] else item["limit"]
    log.append(["insert", data[:0x30].hex(), order_items(item), tag, data[0x50:0x70].hex() if tag else "", data[0x70:0x80].hex(), price,
                date_millis(*w["now"]), item["reduce"], second, data[0x92:0xA2].hex() if second else "", side, 1, w["oid"], user_id(w["user"]).hex(), 2 - w["cap"]])
    outcome = w["insert"]
    if outcome.get("error") is not None:
        word = outcome["error"]
        index = word & (MAX64 >> 1) if word >> 63 else 2
        log.append(build_row(w, item, dex))
        log.append(event(item, STATUS_BY_INDEX[index], w, 2))
        relation = w["relation"]
        log.append(["relation", user_id(w["user"]).hex(), w["oid"]])
        finals = [relation_word(one) for one in relation]
        if relation:
            finals[0] = 0
            if relation[0]["tag"] == 1:
                log.append(["relation", user_id(w["user"]).hex(), relation[0]["parent"]])
                if len(relation) > 1:
                    finals[1] = 0
        out["relations"] = finals
        out["word"] = NONE_WORD
        out["error"] = word
        out["body"] = ramp(0x40, 0x77).hex()
    else:
        first_total, second_total = 0, 0
        for one, two in outcome["fills"]:
            if first_total + one > MAX64:
                log.append(["record", "size"])
            first_total = min(first_total + one, MAX64)
            if second_total + two > MAX64:
                log.append(["record", "notional"])
            second_total = min(second_total + two, MAX64)
        out["word"] = outcome["word"]
        out["fills"] = len(outcome["fills"])
        out["body"] = ramp(0x38, 0x77).hex()
        product = w["mid"] * first_total
        if outcome["fills"] and product <= 0x7FFFFFFFFFFFFFFE:
            if second_total >> 63:
                return {"panic": True, "log": log}
            if product:
                ratio = float(second_total) / float(product) + -1.0
                if side & 1:
                    ratio = -ratio
                if ratio > 0.01:
                    log.append(["slippage"])
    tail(w, log, entry, item, dex)
    out["count"] = max(w["count"] - 1, 0)
    return out


def relation_word(one):
    return one["tag"] | 0x55 << 32


def wrapped(w):
    """The wrapper: bounds, one depth word around the run, and one flush."""
    dex, local = w["asset"] // 10000, w["asset"] % 10000
    if dex >= w["rows"] or local >= w["books"]:
        return {"panic": True, "log": []}
    out = firing(w)
    if out.get("panic"):
        return out
    rows = sum(1 for row in out["log"] if row[0] == "event")
    out["log"].append(["flush", dex, rows])
    out["depth"] = max(min(w["depth"] + 1, MAX64) - 1, 0)
    return out


def run_spec(case):
    w = case.world
    if case.kind == "select":
        return selection(w)
    if case.kind == "wrap":
        return wrapped(w)
    out = firing(w)
    if not out.get("panic"):
        capacity, length = w.get("event_start", (0, 0))
        for row in out["log"]:
            if row[0] == "event":
                if length == capacity:
                    capacity = capacity * 2 or 4
                length += 1
        out["event_cap"], out["event_len"] = capacity, length
    return out


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


Shape = collections.namedtuple("Shape", "parent keys key_size values value_size parent_index length edges")
USER_SHAPE = Shape(0x370, 0x378, USER_SIZE, 0, 0x50, 0x454, 0x456, 0x458)
ORDER_SHAPE = Shape(0x0, 0x8, 8, 0x60, ORDER_SIZE, 0x848, 0x84A, 0x850)
POSITION_SHAPE = Shape(0x0, 0x2C8, 8, 0x8, 0x40, 0x320, 0x322, 0x328)
CHANGED_SHAPE = Shape(0x0, 0x110, USER_SIZE, 0x8, 0x18, 0x1EC, 0x1EE, 0x1F0)
FANOUT = 12
EMPTY = 0xFF
FX_MULTIPLIER = 0xF1357AEA2E62A9C5


RAMPS = {}


def ramp(count, start):
    key = (count, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 7) & 0xFF or 1 for index in range(count))
    return RAMPS[key]


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_CAP: self.on_cap, SLOT_GATE: self.on_gate, SLOT_TRACKER: self.on_tracker, SLOT_ROWS: self.on_rows, SLOT_LOG: self.on_slippage,
                 SLOT_RECORD: self.on_record, SLOT_GROW: self.on_grow, SLOT_SORT: self.on_sort, SLOT_SORT_SECOND: self.on_sort, SLOT_MEMCMP: self.on_memcmp, SLOT_MALLOC: self.on_malloc,
                 SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_REALLOC: self.on_realloc}
        for slot in SLOT_PANIC:
            table[slot] = self.on_panic
        table[SLOT_ONCE] = self.on_once
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.memory.statics[ONCE_WORD] = 0
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        calls = {DROP_WORD: self.on_nothing, TOP_PAIR: self.on_select_top, SLOT_POSITION_DIRECT: self.on_position}
        for copy in COPIES:
            calls.update({copy.top: self.on_top, copy.tick: self.on_tick, copy.build: self.on_build, copy.insert: self.on_insert, copy.relation: self.on_relation,
                          copy.remove: self.on_remove, copy.count: self.on_count, copy.tree_insert: self.on_tree_insert, copy.tree_set: self.on_tree_set, copy.flush: self.on_flush})
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.keep = set()
        self.values = {}
        self.pending = 0
        self.copy = COPIES[0]
        self.relation_calls = 0
        self.records = 0
        self.fill_buffer = 0
        self.row_buffer = 8

    # ---- stubs ----

    def on_nothing(self, m):
        if m.memory.read(m.regs[RDI], 2) != 0x141:
            raise Halt("drop word")

    def on_once(self, m):
        raise Halt("lazy static arm")

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_memcmp(self, m):
        regs = m.regs
        count = regs[RDX]
        if count > 0x100:
            raise Halt("memcmp size")
        left, right = m.memory.bytes_at(regs[RDI], count), m.memory.bytes_at(regs[RSI], count)
        regs[RAX] = 0
        for one, two in zip(left, right):
            if one != two:
                regs[RAX] = (one - two) & MASK[4]
                break

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        if m.regs[RDI] > 0x40000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(m.regs[RDI])

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_realloc(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        old = self.live.pop(at, None)
        if old is None or size > 0x40000:
            raise Halt("realloc %#x" % at)
        fresh = self.allocate(size)
        m.memory.copy(fresh, at, min(old, size))
        m.regs[RAX] = fresh

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x40000:
            raise Halt("copy size")
        if regs[RDX] == EVENT_STRIDE:
            self.note_event(m.memory, regs[RSI])
            if (regs[RDI] - self.row_buffer) % EVENT_STRIDE:
                raise Halt("row address")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def note_event(self, memory, at):
        tag = memory.read(at + 0x10, 8)
        record = memory.bytes_at(at + 0x38, 0xA8)
        which = next((number for number in (1, 2) if record == ramp(0xA8, 0x70 + number)), 0)
        self.log.append(["event", memory.read(at, 8), memory.read(at + 8, 8), tag, memory.bytes_at(at + 0x18, 0x20).hex() if tag == 1 else "", which,
                         [memory.read(at + 0xE0, 4), memory.read(at + 0xE4, 4), memory.read(at + 0xE8, 4)], memory.bytes_at(at + 0xEC, USER_SIZE).hex(), memory.read(at + 0x100, 1)])

    def vector_step(self, m, element):
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if capacity > 0x1000:
            raise Halt("vector size")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * element)
        if capacity:
            memory.copy(fresh, old, capacity * element)
            if self.live.pop(old, None) != capacity * element:
                raise Halt("vector buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)
        if element == EVENT_STRIDE:
            self.row_buffer = fresh

    def on_grow(self, m):
        self.vector_step(m, 0x28)

    def on_rows(self, m):
        self.vector_step(m, EVENT_STRIDE)

    def on_sort(self, m):
        memory = m.memory
        at, count = m.regs[RDI], m.regs[RSI]
        if count > 0x1000:
            raise Halt("sort size")
        rows = sorted((memory.bytes_at(at + index * 0x28, 0x28) for index in range(count)), key=lambda row: row[:8][::-1])
        memory.put_bytes(at, b"".join(rows))

    def on_select_top(self, m):
        regs = m.regs
        if regs[RSI] != self.book + 0x80:
            raise Halt("top argument")
        m.memory.write(regs[RDI], 8, self.w["top"][0])
        m.memory.write(regs[RDI] + 8, 8, self.w["top"][1])

    def on_top(self, m):
        regs = m.regs
        if regs[RSI] != self.book + 0x80 or regs[RDX] != self.book:
            raise Halt("top argument")
        m.memory.write(regs[RDI], 8, self.w["top_pair"][0])
        m.memory.write(regs[RDI] + 8, 8, self.w["top_pair"][1])

    def dex_index(self, value):
        at, rest = divmod(value - DEXES, DEX_STRIDE)
        if rest:
            raise Halt("dex row address")
        return at

    def on_tick(self, m):
        regs = m.regs
        self.log.append(["tick", self.dex_index(regs[RDI]), regs[RSI], regs[RDX]])
        regs[RAX] = self.w["tick"]

    def on_gate(self, m):
        regs = m.regs
        memory = m.memory
        now = [memory.read(regs[R9], 4), memory.read(regs[R9] + 4, 4), memory.read(regs[R9] + 8, 4)]
        self.log.append(["gate", self.dex_index(regs[RDI]), regs[RSI] & 0xFF, regs[RDX], regs[RCX] & 0xFF, regs[R8], now])
        regs[RAX] = self.w["gate"]

    def on_cap(self, m):
        regs = m.regs
        self.log.append(["cap", self.dex_index(regs[RDI]), regs[RSI]])
        regs[RAX] = self.w["cap"]

    def items_of(self, memory, at):
        count = memory.read(at + 8, 8)
        if count > 0x100:
            raise Halt("items length")
        pointer = memory.read(at, 8)
        if not count and pointer != 8:
            raise Halt("empty vector pointer")
        return [memory.read(pointer + index * 8, 8) for index in range(count)]

    def on_build(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RSI] != self.book:
            raise Halt("builder book")
        self.records += 1
        request = regs[RDX]
        tag = memory.read(request + 0x48, 8)
        second = memory.read(request + 0x91, 1)
        self.log.append(["build", memory.bytes_at(regs[RCX], USER_SIZE).hex(), regs[R8], self.dex_index(regs[R9]), memory.bytes_at(request, 0x30).hex(), self.items_of(memory, request + 0x38),
                         tag, memory.bytes_at(request + 0x50, 0x20).hex() if tag == 1 else "", memory.bytes_at(request + 0x70, 0x20).hex(), memory.read(request + 0x90, 1), second,
                         memory.bytes_at(request + 0x92, 0x10).hex() if second == 1 else "", memory.read(request + 0xA2, 1), memory.bytes_at(request + 0xA8, 10).hex()])
        memory.put_bytes(regs[RDI], ramp(0xA8, 0x70 + self.records))

    def on_insert(self, m):
        regs = m.regs
        memory = m.memory
        w = self.w
        if regs[RSI] != self.book or regs[RCX] & MASK[4] or regs[R9] != STATE or self.events not in (None, memory.read(regs[RSP] + 8, 8)):
            raise Halt("insert arguments")
        at = regs[RDX]
        tag = memory.read(at + 0x48, 8)
        second = memory.read(at + 0x91, 1)
        self.log.append(["insert", memory.bytes_at(at, 0x30).hex(), self.items_of(memory, at + 0x38), tag, memory.bytes_at(at + 0x50, 0x20).hex() if tag == 1 else "",
                         memory.bytes_at(at + 0x70, 0x10).hex(), memory.read(at + 0x80, 8), memory.read(at + 0x88, 8), memory.read(at + 0x90, 1), second,
                         memory.bytes_at(at + 0x92, 0x10).hex() if second == 1 else "", memory.read(at + 0xA2, 1), memory.read(at + 0xA8, 8), memory.read(at + 0xB0, 8),
                         memory.bytes_at(at + 0xB8, USER_SIZE).hex(), memory.read(at + 0xCC, 1)])
        capacity = memory.read(at + 0x30, 8)
        if capacity:
            if self.live.pop(memory.read(at + 0x38, 8), None) != capacity * 8:
                raise Halt("request vector")
        out = regs[RDI]
        outcome = w["insert"]
        if outcome.get("error") is not None:
            memory.write(out, 8, NONE_WORD)
            memory.write(out + 8, 8, outcome["error"])
            memory.put_bytes(out + 0x10, ramp(0x40, 0x77))
            return
        fills = outcome["fills"]
        self.fill_buffer = self.allocate(max(len(fills), 1) * FILL_STRIDE)
        self.keep.add(self.fill_buffer)
        for index, (one, two) in enumerate(fills):
            row = self.fill_buffer + index * FILL_STRIDE
            memory.put_bytes(row, ramp(FILL_STRIDE, 0x21 + index))
            memory.write(row + 0x210, 8, one)
            memory.write(row + 0x218, 8, two)
        memory.write(out, 8, outcome["word"])
        memory.write(out + 8, 8, self.fill_buffer)
        memory.write(out + 0x10, 8, len(fills))
        memory.put_bytes(out + 0x18, ramp(0x38, 0x77))

    def on_record(self, m):
        if m.regs[RDI] & MASK[4]:
            raise Halt("recorder argument")
        self.log.append(["record", RECORD_ROWS[m.regs[RSI]]])

    def on_slippage(self, m):
        self.log.append(["slippage"])

    def on_relation(self, m):
        regs = m.regs
        if regs[RDI] != self.book:
            raise Halt("relation book")
        self.log.append(["relation", m.memory.bytes_at(regs[RSI], USER_SIZE).hex(), regs[RDX]])
        index = self.relation_calls
        self.relation_calls += 1
        regs[RAX] = RELATIONS + index * 0x40 if index < len(self.w["relation"]) else 0

    def on_remove(self, m):
        regs = m.regs
        memory = m.memory
        user = next((key for key, at in self.values.items() if at + 0x38 == regs[RSI]), None)
        if user is None:
            raise Halt("remove field")
        oid = memory.read(regs[RDX], 8)
        self.log.append(["remove", user.hex(), oid])
        entry = next(one for one in self.w["users"] if user_id(one["user"]) == user)
        item = find_order(entry, oid)
        out = regs[RDI]
        memory.put_bytes(out, ramp(0x60, 0x19))
        if item is None:
            memory.write(out, 4, 2)
            return
        memory.write(out, 4, 0)
        memory.write(out + 0x30, 8, item["items"])
        memory.write(out + 0x38, 8, self.allocate(item["items"] * 8) if item["items"] else 8)

    def on_tracker(self, m):
        regs = m.regs
        if regs[RDI] != self.book + 0x48:
            raise Halt("tracker field")
        self.log.append(["tracker", m.memory.bytes_at(regs[RSI], USER_SIZE).hex()])

    def on_count(self, m):
        regs = m.regs
        if regs[RDI] != STATE + self.copy.count_field:
            raise Halt("count field")
        self.log.append(["count", m.memory.bytes_at(regs[RSI], USER_SIZE).hex()])
        regs[RAX] = COUNTER

    def on_tree_insert(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RSI]
        if memory.read(at, 8) != STATE + self.copy.tree_field or memory.read(at + 0x10, 8) or memory.bytes_at(at + 0x20, USER_SIZE) != user_id(self.w["user"]):
            raise Halt("tree field")
        if memory.read(regs[RDX], 8) or memory.read(regs[RDX] + 0x10, 8):
            raise Halt("tree closure")
        node = self.allocate(0x400)
        memory.write(regs[RDI], 8, node)
        memory.write(regs[RDI] + 0x10, 8, 0)
        self.pending = (node + 8, memory.bytes_at(at + 0x20, USER_SIZE).hex())

    def on_tree_set(self, m):
        regs = m.regs
        if regs[RSI] & 0xFF:
            raise Halt("set argument")
        at = regs[RDI]
        if self.pending and self.pending[0] == at:
            self.log.append(["changed", "new", self.pending[1], regs[RDX]])
            self.live.pop(at - 8, None)
            return
        user = self.changed.get(at)
        if user is None:
            raise Halt("set value")
        self.log.append(["changed", "found", user, regs[RDX]])

    def on_position(self, m):
        regs = m.regs
        if regs[RDI] != DEXES + self.w["asset"] // 10000 * DEX_STRIDE + 0xF8:
            raise Halt("position field")
        user = m.memory.bytes_at(regs[RSI], USER_SIZE)
        regs[RAX] = self.positions.get(user, POSITIONS)

    def on_flush(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDX] != STATE:
            raise Halt("flush state")
        at = regs[RDI]
        capacity, length = memory.read(at, 8), memory.read(at + 0x10, 8)
        self.log.append(["flush", regs[RSI], length])
        if not capacity and memory.read(at + 8, 8) != 8:
            raise Halt("flush pointer")
        if capacity and self.live.pop(memory.read(at + 8, 8), None) != capacity * EVENT_STRIDE:
            raise Halt("flush buffer")

    # ---- worlds ----

    def place(self, shape, rows, parent, index, height, fill, filler=None):
        """A tree of uniform depth; rows are (key bytes, value argument) in key order."""
        memory = self.machine.memory
        own, kids = list(rows), []
        if height:
            fan = 3 if height >= 2 or len(rows) < (FANOUT - 1) * 3 + 2 else min(FANOUT, (len(rows) + 11) // 11)
            base, extra = divmod(len(rows) - (fan - 1), fan)
            own, at = [], 0
            for child in range(fan):
                size = base + (1 if child < extra else 0)
                kids.append(rows[at:at + size])
                at += size
                if child < fan - 1:
                    own.append(rows[at])
                    at += 1
        node = self.allocate(shape.edges + (FANOUT * 8 if kids else 0))
        self.keep.add(node)
        memory.put_bytes(node, ramp(shape.edges, 0x2B))
        memory.write(node + shape.parent, 8, parent)
        memory.write(node + shape.parent_index, 2, index)
        memory.write(node + shape.length, 2, len(own))
        for at, (key, value) in enumerate(own):
            memory.put_bytes(node + shape.keys + at * shape.key_size, key)
            fill(node + shape.values + at * shape.value_size, key, value)
        for at in range(len(own), FANOUT - 1):
            memory.put_bytes(node + shape.keys + at * shape.key_size, filler or b"\xfd" * shape.key_size)
        for at, kid in enumerate(kids):
            memory.write(node + shape.edges + at * 8, 8, self.place(shape, kid, node, at, height - 1, fill, filler))
        return node

    def fill_order(self, at, key, item):
        memory = self.machine.memory
        memory.put_bytes(at, order_bytes(item))
        pointer = 8
        if item["items"]:
            pointer = self.allocate(item["items"] * 8)
            for index, value in enumerate(order_items(item)):
                memory.write(pointer + index * 8, 8, value)
            self.keep.add(pointer)
        memory.write(at + 0x30, 8, item["items"] + 3)
        memory.write(at + 0x38, 8, pointer)
        memory.write(at + 0x40, 8, item["items"])

    def fill_user(self, at, key, entry):
        memory = self.machine.memory
        self.values[key] = at
        memory.put_bytes(at, ramp(0x50, 0x51))
        if not entry["root"]:
            memory.write(at + 0x38, 8, 0)
            memory.write(at + 0x40, 8, 0x99)
            memory.write(at + 0x48, 8, 5)
            return
        rows = [(item["oid"].to_bytes(8, "little"), item) for item in sorted(entry["orders"], key=lambda one: one["oid"])]
        node = self.place(ORDER_SHAPE, rows, 0, 0xFFFF, entry["height"], self.fill_order, self.w["oid"].to_bytes(8, "little"))
        self.keep.add(node)
        memory.write(at + 0x38, 8, node)
        memory.write(at + 0x40, 8, entry["height"])
        memory.write(at + 0x48, 8, len(rows) if entry["length"] is None else entry["length"])

    def fill_position(self, at, key, value):
        memory = self.machine.memory
        memory.put_bytes(at, ramp(0x40, 0x5D))
        memory.write(at + 8, 8, value)

    def fill_changed(self, at, key, value):
        self.machine.memory.put_bytes(at, ramp(0x18, 0x67))
        self.changed[at] = key.hex()

    def hash_slot(self, oid):
        value = (oid * FX_MULTIPLIER) & MAX64
        return ((value << 20) | (value >> 44)) & MAX64

    def hash_table(self, base, oids):
        memory = self.machine.memory
        size = 16
        ctrl = bytearray([EMPTY]) * (size + 16)
        for oid in oids:
            value = self.hash_slot(oid)
            at = value & (size - 1)
            while ctrl[at] != EMPTY:
                at = (at + 1) % size
            ctrl[at] = value >> 57
            if at < 16:
                ctrl[size + at] = value >> 57
            memory.write(CTRL - 0x10 * (at + 1), 8, oid)
        memory.put_bytes(CTRL, bytes(ctrl))
        memory.write(base + 0x28, 8, CTRL)
        memory.write(base + 0x30, 8, size - 1)
        memory.write(base + 0x40, 8, len(oids))

    def world(self, w, copy):
        memory = self.machine.memory
        memory.put_bytes(STATE, ramp(STATE_SIZE, 0x11))
        memory.write(STATE + 0x58, 8, w["depth"])
        memory.write(STATE + 0x60, 4, w["now"][0])
        memory.write(STATE + 0x64, 4, w["now"][1])
        memory.write(STATE + 0x68, 4, w["now"][2])
        memory.write(STATE + copy.dex_field, 8, DEXES)
        memory.write(STATE + copy.dex_field + 8, 8, w["dexes"])
        memory.write(STATE + copy.byte_field, 1, w["gate_byte"])
        memory.write(STATE + copy.rows_field, 8, ROWS)
        memory.write(STATE + copy.rows_field + 8, 8, w["rows"])
        dex, local = w["asset"] // 10000, w["asset"] % 10000
        self.book = BOOKS
        row_at = ROWS + dex * ROW_STRIDE
        if dex < w["rows"]:
            memory.put_bytes(row_at, ramp(ROW_STRIDE, 0x35))
            memory.write(row_at + 8, 8, BOOKS - local * BOOK_STRIDE if local * BOOK_STRIDE <= 0x2000 else BOOKS)
            memory.write(row_at + 0x10, 8, w["books"])
            self.book = BOOKS
        memory.put_bytes(BOOKS, ramp(BOOK_STRIDE, 0x2F))
        memory.write(BOOKS + 0xB0, 8, w["asset"])
        self.values = {}
        self.keep = set()
        self.changed = {}
        self.positions = {}
        if w.get("users_absent"):
            memory.write(BOOKS + 0xB8, 8, 0)
            memory.write(BOOKS + 0xC0, 8, 0x77)
            memory.write(BOOKS + 0xC8, 8, len(w["users"]))
        else:
            rows = [(user_id(one["user"]), one) for one in sorted(w["users"], key=lambda one: user_id(one["user"]))]
            root = self.place(USER_SHAPE, rows, 0, 0xFFFF, w["user_height"], self.fill_user)
            self.keep.add(root)
            memory.write(BOOKS + 0xB8, 8, root)
            memory.write(BOOKS + 0xC0, 8, w["user_height"])
            memory.write(BOOKS + 0xC8, 8, len(rows))
        self.hash_table(BOOKS, w["resting"])
        if w.get("hidden"):
            self.hash_table(BOOKS, w["hidden"])
            memory.write(BOOKS + 0x40, 8, 0)
        if w["changed"]:
            rows = [(user_id(number), None) for number in sorted(w["changed"], key=user_id)]
            root = self.place(CHANGED_SHAPE, rows, 0, 0xFFFF, w["changed_height"], self.fill_changed, user_id(w["user"]))
            memory.write(STATE + copy.tree_field, 8, root)
            memory.write(STATE + copy.tree_field + 8, 8, w["changed_height"])
        else:
            memory.write(STATE + copy.tree_field, 8, 0)
            memory.write(STATE + copy.tree_field + 8, 8, 0x66)
        for index in range(min(w["dexes"], 3)):
            memory.put_bytes(DEXES + index * DEX_STRIDE, ramp(DEX_STRIDE, 0x3B + index))
        if dex < w["dexes"]:
            at = DEXES + dex * DEX_STRIDE
            memory.write(at + 0x68, 8, MARKS - (w["asset"] % 10000 - 2) * MARK_STRIDE if w["marks"] and w["asset"] % 10000 >= 2 else MARKS)
            memory.write(at + 0x70, 8, len(w["marks"]))
            base = memory.read(at + 0x68, 8)
            if len(w["marks"]) <= w["asset"] % 10000 < 100:
                mark = base + w["asset"] % 10000 * MARK_STRIDE
                memory.put_bytes(mark, ramp(MARK_STRIDE, 0x45))
                memory.write(mark + 0x20, 8, 3)
                memory.write(mark + 0x30, 4, w["now"][0])
                memory.write(mark + 0x34, 4, w["now"][1])
                memory.write(mark + 0x38, 4, w["now"][2])
            if w["asset"] % 10000 < len(w["marks"]):
                row = w["marks"][w["asset"] % 10000]
                mark = base + w["asset"] % 10000 * MARK_STRIDE
                memory.put_bytes(mark, ramp(MARK_STRIDE, 0x45))
                memory.write(mark + 0x20, 8, row["px"])
                memory.write(mark + 0x30, 4, row["date"])
                memory.write(mark + 0x34, 4, row["secs"])
                memory.write(mark + 0x38, 4, row["nanos"])
        at = POSITIONS + 0x20
        memory.put_bytes(POSITIONS, ramp(0x20, 0x4F))
        memory.write(POSITIONS + 8, 8, 0)
        for number, position in sorted(w["positions"].items()):
            memory.put_bytes(at, ramp(0x20, 0x4F))
            if position.get("root_absent"):
                memory.write(at + 8, 8, 0)
            else:
                rows = [(key.to_bytes(8, "little"), value & MAX64) for key, value in sorted(position["rows"].items())]
                memory.write(at + 8, 8, self.place(POSITION_SHAPE, rows, 0, 0xFFFF, position.get("height", 0), self.fill_position, w["asset"].to_bytes(8, "little")))
                memory.write(at + 0x10, 8, position.get("height", 0))
            self.positions[user_id(number)] = at
            at += 0x20
        memory.put_bytes(RELATIONS, ramp(0x80, 0x1D))
        for index, one in enumerate(w["relation"]):
            memory.write(RELATIONS + index * 0x40 + 0x20, 8, relation_word(one))
            memory.write(RELATIONS + index * 0x40 + 0x28, 8, one["parent"])
        memory.put_bytes(COUNTER, ramp(0x30, 0x23))
        memory.write(COUNTER + 0x20, 8, w["count"])

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        copy = COPIES[case.copy]
        self.w = w
        self.copy = copy
        self.log = []
        self.live = {}
        self.pending = 0
        self.relation_calls = 0
        self.records = 0
        self.fill_buffer = 0
        self.row_buffer = 8
        memory.reset(self.brk - HEAP_BASE)
        self.brk = HEAP_FREE
        self.world(w, copy)
        memory.put_bytes(OUT, ramp(0x60, 0x7B))
        try:
            if case.kind == "select":
                machine.run(copy.select, {RDI: OUT, RSI: BOOKS, RDX: STATE})
                return self.read_selection()
            memory.put_bytes(USER_ARG, user_id(w["user"]))
            self.events = EVENTS
            start = w.get("event_start", (0, 0))
            memory.write(EVENTS, 8, start[0])
            self.row_buffer = self.allocate(start[0] * EVENT_STRIDE) if start[0] else 8
            memory.write(EVENTS + 8, 8, self.row_buffer)
            memory.write(EVENTS + 0x10, 8, start[1])
            if case.kind == "fire":
                memory.write(STACK_TOP - 0x100, 8, STATE)
                memory.write(STACK_TOP - 0xF8, 8, EVENTS)
                machine.run(copy.fire, {RDI: OUT, RSI: BOOKS, RDX: USER_ARG, RCX: w["oid"], R9: w["mid"]})
            else:
                self.events = None
                self.watch_events = True
                memory.write(WORDS, 8, w["asset"])
                memory.write(WORDS + 8, 8, w["oid"])
                memory.write(WORDS + 0x10, 8, POISON)
                memory.write(WORDS + 0x18, 8, w["mid"])
                for index, value in enumerate((WORDS, USER_ARG, WORDS + 8, WORDS + 0x10, WORDS + 0x18)):
                    memory.write(CLOSURE + index * 8, 8, value)
                machine.run(copy.wrap, {RDI: OUT, RSI: CLOSURE, RDX: STATE})
            return self.read_firing(case)
        except Panicked:
            if case.kind == "select":
                return {"panic": True}
            return {"panic": True, "log": self.log}

    def leaks(self, answer, extra=()):
        stray = set(self.live) - self.keep - set(extra)
        if stray:
            answer["leaked"] = len(stray)
        return answer

    def read_selection(self):
        memory = self.machine.memory
        word = memory.read(OUT, 8)
        if word == NONE_WORD:
            return self.leaks({"none": True})
        pointer, count = memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8)
        if count > 0x400:
            raise Halt("row count")
        rows = [[memory.bytes_at(pointer + index * 0x20, USER_SIZE).hex(), memory.read(pointer + index * 0x20 + 0x18, 8)] for index in range(count)]
        answer = {"none": False, "rows": rows, "capacity": word, "mid": memory.read(OUT + 0x18, 8), "reference": memory.read(OUT + 0x20, 8), "asset": memory.read(OUT + 0x28, 8)}
        if not count and pointer != 8:
            answer["pointer"] = pointer
        return self.leaks(answer, (pointer,))

    def read_firing(self, case):
        memory = self.machine.memory
        word = memory.read(OUT, 8)
        answer = {"log": self.log, "word": word, "count": memory.read(COUNTER + 0x20, 8)}
        if word == WORD_REJECTED:
            pointer, length = memory.read(OUT + 0x10, 8), memory.read(OUT + 0x18, 8)
            if length > 16:
                raise Halt("text length")
            answer.update({"px": memory.read(OUT + 8, 8), "text": memory.bytes_at(pointer, length).decode("latin-1"), "oid": memory.read(OUT + 0x20, 8),
                           "user": memory.bytes_at(OUT + 0x28, USER_SIZE).hex(), "side": memory.read(OUT + 0x3C, 1)})
        elif word == NONE_WORD:
            answer["error"] = memory.read(OUT + 8, 8)
            answer["body"] = memory.bytes_at(OUT + 0x10, 0x40).hex()
            answer["relations"] = [memory.read(RELATIONS + index * 0x40 + 0x20, 8) for index in range(len(self.w["relation"]))]
        elif word not in (WORD_NO_USER, WORD_NO_ORDER):
            if memory.read(OUT + 8, 8) != self.fill_buffer:
                raise Halt("fill pointer")
            answer["fills"] = memory.read(OUT + 0x10, 8)
            answer["body"] = memory.bytes_at(OUT + 0x18, 0x38).hex()
        if case.kind == "wrap":
            answer["depth"] = memory.read(STATE + 0x58, 8)
            return self.leaks(answer)
        answer["event_cap"], answer["event_len"] = memory.read(EVENTS, 8), memory.read(EVENTS + 0x10, 8)
        return self.leaks(answer, (memory.read(EVENTS + 8, 8),))


def spec_run(case):
    return run_spec(case)


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError, UnicodeDecodeError)


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
    try:
        found = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
    if found != wanted:
        keys = sorted(key for key in set(wanted) | set(found) if found.get(key) != wanted.get(key))
        detail = ""
        if keys:
            left, right = found.get(keys[0]), wanted.get(keys[0])
            detail = "%s found %s wanted %s" % (keys[0], str(left)[:500], str(right)[:500])
        return "%s: differs: %s" % (case.label, detail)
    return ""


# ---- cases ----

NOW = ((2026 << 13) | (200 << 4) | 3, 43200, 500000000)
ASSET = 10002


def fresh_mark(px=1000000, back=0):
    """A mark row `back` seconds before NOW."""
    return {"px": px, "date": NOW[0], "secs": NOW[1] - back, "nanos": NOW[2]}


def base(users=None, **changes):
    w = {"asset": ASSET, "dexes": 2, "rows": 2, "books": 3, "now": NOW, "top": (1000000, 1000002), "top_pair": (900000, 1100000), "marks": [fresh_mark(1), fresh_mark(1), fresh_mark()],
         "users": [holder(5, [order(9)])] if users is None else users, "user_height": 0, "positions": {}, "resting": [], "changed": [], "changed_height": 0, "relation": [],
         "user": 5, "oid": 9, "mid": 1000001, "tick": 10, "gate": 1, "gate_byte": 7, "cap": 0, "count": 3, "depth": 4, "insert": {"word": 0x25, "fills": []}}
    w.update(changes)
    return w


def selection_cases(copy):
    out = []

    def add(label, w):
        out.append(Case("%s select: %s" % (COPIES[copy].name, label), "select", w, copy))

    add("no top on the first side", base(top=(0, 5)))
    add("no top on the second side", base(top=(5, 0)))
    add("no top at all", base(top=(0, 0)))
    add("mean of 1 and 2 floors", base(top=(1, 2), marks=[]))
    add("mean near the top of u64", base(top=(MAX64, MAX64 - 2), marks=[]))
    add("dex out of range", base(dexes=1))
    add("dex one below the count", base(asset=10002, dexes=2))
    for asset in (0, 9999, 10000, 19999, 20000):
        add("asset %d" % asset, base(asset=asset, dexes=3, marks=[fresh_mark(4)]))
        add("asset %d with dex count at the edge" % asset, base(asset=asset, dexes=asset // 10000))
    add("local index past the marks", base(marks=[fresh_mark(1)], users=[holder(5, [order(9, trigger=7)])]))
    add("local index one below the mark count", base(marks=[fresh_mark(1), fresh_mark(1), fresh_mark(3)], users=[holder(5, [order(9, trigger=3)])]))
    for back, label in ((0, "now"), (19, "19 s ago"), (20, "exactly 20 s ago"), (21, "21 s ago"), (40000, "11 h ago")):
        for trigger in (7, 2000000):
            add("mark %s trigger %d" % (label, trigger), base(marks=[fresh_mark(1), fresh_mark(1), fresh_mark(1000, back)], users=[holder(5, [order(9, trigger=trigger)])]))
    add("mark one nano older than the limit", base(marks=[fresh_mark(1), fresh_mark(1), {"px": 1000, "date": NOW[0], "secs": NOW[1] - 20, "nanos": NOW[2] - 1}], users=[holder(5, [order(9, trigger=7)])]))
    add("mark one nano newer than the limit", base(marks=[fresh_mark(1), fresh_mark(1), {"px": 1000, "date": NOW[0], "secs": NOW[1] - 20, "nanos": NOW[2] + 1}], users=[holder(5, [order(9, trigger=7)])]))
    add("mark dated yesterday", base(marks=[fresh_mark(1), fresh_mark(1), {"px": 1000, "date": NOW[0] - 0x10, "secs": NOW[1], "nanos": NOW[2]}], users=[holder(5, [order(9, trigger=7)])]))
    add("mark dated tomorrow", base(marks=[fresh_mark(1), fresh_mark(1), {"px": 1000, "date": NOW[0] + 0x10, "secs": 5, "nanos": 0}], users=[holder(5, [order(9, trigger=7)])]))
    add("mark late on the day before crosses midnight", base(now=(NOW[0], 10, 0), marks=[fresh_mark(1), fresh_mark(1), {"px": 1000, "date": NOW[0] - 0x10, "secs": 86395, "nanos": 0}], users=[holder(5, [order(9, trigger=7)])]))
    add("mark too old across midnight", base(now=(NOW[0], 16, 0), marks=[fresh_mark(1), fresh_mark(1), {"px": 1000, "date": NOW[0] - 0x10, "secs": 86395, "nanos": 0}], users=[holder(5, [order(9, trigger=7)])]))
    for side in (0, 1):
        for kind in (0, 1):
            for delta in (-1, 0, 1):
                add("side %d kind %d trigger %+d" % (side, kind, delta), base(users=[holder(5, [order(9, side=side, kind=kind, trigger=1000000 + delta, size=11 + side)])]))
    add("kind 2 reads like take profit", base(users=[holder(5, [order(9, kind=2, trigger=1000001)])]))
    add("skip byte set", base(users=[holder(5, [order(9, skip=1, trigger=1000000)])]))
    add("skip byte set beside a firing order", base(users=[holder(5, [order(9, skip=4), order(12, trigger=1000000)])]))
    add("size word zero", base(users=[holder(5, [order(9, trigger=1000000, size=0)])]))
    add("absent size word", base(users=[holder(5, [order(9, trigger=1000000, present=0, size=44)])]))
    add("users root absent", base(users_absent=True))
    add("user with no order root", base(users=[holder(5, root=False)]))
    add("user with an empty leaf", base(users=[holder(5, [])]))
    add("user with length word 0", base(users=[holder(5, [order(9, trigger=1000000)], length=0)]))
    add("no users", base(users=[holder(5, [])], user=5))
    for number, position, label in ((5, None, "no position row"), (5, {"root_absent": True}, "position root absent"), (5, {"rows": {ASSET + 1: 50}}, "other asset only"), (5, {"rows": {ASSET - 5: 50}}, "lower asset only"), (5, {"rows": {ASSET - 1: 50, ASSET: 0, ASSET + 1: 7}}, "zero size"),
                                    (5, {"rows": {ASSET: 50}}, "long"), (5, {"rows": {ASSET: -50}}, "short"), (5, {"rows": {ASSET - 3: 1, ASSET: 60, ASSET + 9: 2}}, "middle key"),
                                    (5, {"rows": {ASSET: 60, ASSET + 1: 2, ASSET + 2: 2, ASSET + 3: 2, ASSET + 4: 2, ASSET + 5: 2, ASSET + 6: 2, ASSET + 7: 2}, "height": 1}, "two levels"),
                                    (5, {"rows": {ASSET: -(1 << 63)}}, "minimum szi")):
        for side in (0, 1):
            for present, size in ((1, 30), (1, 90), (1, 50), (0, 30)):
                add("reduce %s side %d present %d size %d" % (label, side, present, size),
                    base(users=[holder(5, [order(9, side=side, trigger=1000000, reduce=1, present=present, size=size), order(8, trigger=1000000, size=1), order(21, trigger=1000000, size=40), order(22, trigger=1000000, size=55), order(23, trigger=1000000, size=75)])],
                         positions={} if position is None else {number: position}))
    many = [holder(number, [order(number * 3, trigger=1000000, size=1000 - number * 7), order(number * 3 + 1, trigger=999999, size=number)]) for number in range(1, 15)]
    add("users in two levels", base(users=many, user_height=1))
    add("users in three levels", base(users=[holder(number, [order(number, trigger=1000000, size=number % 5)]) for number in range(1, 31)], user_height=2))
    add("orders in two levels", base(users=[holder(5, [order(oid, trigger=1000000, size=(oid * 7) % 11) for oid in range(1, 15)], height=1)]))
    add("orders in three levels", base(users=[holder(5, [order(oid, trigger=1000000, size=500 - oid) for oid in range(1, 31)], height=2)]))
    add("twenty rows use the short sort", base(users=[holder(5, [order(oid, trigger=1000000, size=(oid * 13) % 7) for oid in range(1, 21)], height=1)]))
    add("twenty one rows use the long sort", base(users=[holder(5, [order(oid, trigger=1000000, size=(oid * 13) % 7) for oid in range(1, 22)], height=1)]))
    add("equal sizes keep walk order", base(users=[holder(5, [order(oid, trigger=1000000, size=3) for oid in range(1, 5)])]))
    add("sizes above 2^63 sort as unsigned", base(users=[holder(5, [order(1, trigger=1000000, size=1 << 63), order(2, trigger=1000000, size=5)])]))
    add("sort with the high byte different", base(users=[holder(5, [order(1, trigger=1000000, size=0x0100000000000000), order(2, trigger=1000000, size=0xFF), order(3, trigger=1000000, size=0x10000)])]))
    add("five rows grow the list", base(users=[holder(5, [order(oid, trigger=1000000, size=9 - oid) for oid in range(1, 6)])]))
    add("nine rows grow it twice", base(users=[holder(5, [order(oid, trigger=1000000, size=oid) for oid in range(1, 10)], height=0)]))
    return out


def fire_world(item, **changes):
    return base(users=[holder(5, [item])], oid=item["oid"], **changes)


def fire_cases(copy, kind="fire"):
    out = []

    def add(label, w):
        out.append(Case("%s %s: %s" % (COPIES[copy].name, kind, label), kind, w, copy))

    add("date before the rejected path", fire_world(order(9), now=(NOW[0], 7, 999999999), gate=0))
    add("date moves the millis", fire_world(order(9), now=(NOW[0] + 0x10, 7, 1999999)))
    add("year 2101", fire_world(order(9), now=((2101 << 13) | (60 << 4) | 3, 0, 0)))
    add("year 2401", fire_world(order(9), now=((2401 << 13) | (60 << 4) | 3, 0, 0)))
    add("year 1", fire_world(order(9), now=((1 << 13) | (2 << 4) | 3, 0, 0)))
    add("year 1970", fire_world(order(9), now=((1970 << 13) | (1 << 4) | 3, 1, 0)))
    add("users root absent", base(users_absent=True))
    add("user absent", base(user=6))
    add("user below every key", base(users=[holder(5, [order(9)])], user=next(number for number in range(1, 300) if user_id(number) < user_id(5))))
    add("user in a child", base(users=[holder(number, [order(9)]) for number in range(1, 15)], user_height=1, user=7))
    add("user in a last child", base(users=[holder(number, [order(9)]) for number in range(1, 15)], user_height=1, user=max(range(1, 15), key=user_id)))
    add("user absent from two levels", base(users=[holder(number, [order(9)]) for number in range(1, 15)], user_height=1, user=20))
    add("order root absent", base(users=[holder(5, root=False)]))
    add("order absent", base(oid=8))
    add("order above every key", base(oid=400))
    add("order absent with a resting oid", base(oid=8, resting=[8, 3]))
    add("order in a child", base(users=[holder(5, [order(oid) for oid in range(1, 15)], height=1)], oid=7))
    add("order in a last child", base(users=[holder(5, [order(oid) for oid in range(1, 15)], height=1)], oid=14))
    add("order absent from two levels", base(users=[holder(5, [order(oid * 2) for oid in range(1, 15)], height=1)], oid=7))
    add("dex out of range", base(dexes=1))
    add("last dex", base(asset=10002, dexes=2))
    for asset in (0, 9999, 10000, 19999, 20000):
        add("asset %d" % asset, base(asset=asset, dexes=3))
        add("asset %d with dex count at the edge" % asset, base(asset=asset, dexes=asset // 10000))
        add("asset %d insert error" % asset, base(asset=asset, dexes=3, insert={"error": NONE_WORD + 1}))
    for side in (0, 1):
        for trigger in (1, 2, 3, 4, 5, 9, 10, 11, 12345, 999999, 1000000, 1000005, 123456789, 1 << 40, (1 << 53) + 1, 1 << 62, 1 << 63, MAX64 - 1, MAX64):
            add("side %d trigger %d" % (side, trigger), fire_world(order(9, side=side, trigger=trigger), tick=7, top_pair=(0, 0)))
    for side in (0, 1):
        for tick in (1, 2, 3, 10, 1000, 1 << 32, (1 << 32) + 1, 1 << 40, MAX64):
            add("side %d tick %d" % (side, tick), fire_world(order(9, side=side, trigger=1 << 44), tick=tick, top_pair=(0, 0)))
    for side in (0, 1):
        add("side %d trigger 0" % side, fire_world(order(9, side=side, trigger=0), tick=1, top_pair=(0, 0)))
        add("side %d price just above 32 bits" % side, fire_world(order(9, side=side, trigger=5000000000), tick=3, top_pair=(0, 0)))
        add("side %d price above 33 bits" % side, fire_world(order(9, side=side, trigger=10000000000), tick=3, top_pair=(0, 0)))
    add("sell step past the top of the word", fire_world(order(9, side=1, trigger=MAX64), tick=10 ** 19, top_pair=(0, 0)))
    add("product at the bound shows the ratio", fire_world(order(9, side=1), mid=1, insert={"word": 0x25, "fills": [(0x7FFFFFFFFFFFFFFE, 1)]}))
    add("product past the bound hides the ratio", fire_world(order(9, side=1), mid=1, insert={"word": 0x25, "fills": [(0x7FFFFFFFFFFFFFFF, 1)]}))
    add("sell tick overflow", fire_world(order(9, side=1, trigger=MAX64), tick=MAX64 - 1, top_pair=(0, 0)))
    add("sell at the full word", fire_world(order(9, side=1, trigger=MAX64), tick=1, top_pair=(0, 0)))
    add("tick above the price buys zero", fire_world(order(9, side=0, trigger=9), tick=1000, top_pair=(0, 0)))
    for side in (0, 1):
        for left, right, label in ((900000, 1100000, "inside"), (1500000, 1600000, "first"), (100, 200, "low"), (0, 1100000, "no first"), (900000, 0, "no second"), (0, 0, "no tops"), (990000, 990000, "equal low"),
                                   (1100000, 1100000, "at the buy limit"), (900010, 900010, "at the sell limit")):
            add("side %d tops %s" % (side, label), fire_world(order(9, side=side), top_pair=(left, right)))
            add("side %d tops %s rejected" % (side, label), fire_world(order(9, side=side), top_pair=(left, right), gate=0))
    add("no tick and no top, zero price", fire_world(order(9, side=0, trigger=1), tick=100, top_pair=(0, 0), gate=0))
    for market, limit in ((1, 5), (0, 5), (0, 0), (2, 8), (0, MAX64)):
        add("market byte %d limit %d" % (market, limit), fire_world(order(9, market=market, limit=limit)))
    for flag in (0, 1):
        add("cap flag %d" % flag, fire_world(order(9), cap=flag))
    add("gate byte kept", fire_world(order(9), gate_byte=0xE1))
    for first, second, items in ((1, 0, 0), (0, 1, 0), (1, 1, 3), (2, 2, 1), (0, 0, 2), (0, 0, 0), (5, 3, 7)):
        add("tags %d %d items %d" % (first, second, items), fire_world(order(9, first=first, second=second, items=items)))
        add("tags %d %d items %d error" % (first, second, items), fire_world(order(9, first=first, second=second, items=items), insert={"error": NONE_WORD + 3}))
    add("present, size and reduce bytes pass through", fire_world(order(9, present=0, size=77, reduce=1, skip=9)))
    for index in range(8):
        add("insert error index %d" % index, fire_world(order(9), insert={"error": NONE_WORD + index}))
    add("insert error plain word", fire_world(order(9), insert={"error": 17}))
    add("insert error zero", fire_world(order(9), insert={"error": 0}))
    for relation, label in (([{"tag": 0, "parent": 3}], "no parent"), ([{"tag": 1, "parent": 3}], "parent gone"), ([{"tag": 1, "parent": 3}, {"tag": 1, "parent": 4}], "parent found"),
                            ([{"tag": 2, "parent": 3}], "tag 2"), ([{"tag": 0, "parent": 3}, {"tag": 1, "parent": 4}], "second kept")):
        add("relation %s" % label, fire_world(order(9), insert={"error": NONE_WORD + 1}, relation=relation))
    add("relation ignored when insert works", fire_world(order(9), relation=[{"tag": 1, "parent": 3}]))
    for fills, label in (([], "none"), ([(5, 5000005)], "one fill"), ([(2, 2000002), (3, 3000003)], "two fills"), ([(MAX64, 5), (9, 5)], "first total saturates"), ([(1, MAX64 >> 1), (1, (MAX64 >> 1) + 2)], "second total saturates"),
                         ([(1, 1 << 63)], "second total at 2^63"), ([(0, 1 << 63)], "zero size, large total"), ([(0, 5)], "zero size"), ([(10, 1)], "low total"), ([((1 << 63) // 1000001, 1)], "product at the limit"),
                         ([((1 << 63) // 1000001 + 1, 1)], "product past the limit"), ([(1 << 44, 1)], "product overflow")):
        for side in (0, 1):
            add("fills %s side %d" % (label, side), fire_world(order(9, side=side), insert={"word": 0x25, "fills": fills}))
    mid = 1000
    for side in (0, 1):
        for total in (9899, 9900, 9901, 9990, 10000, 10099, 10100, 10101, 10200):
            add("slippage side %d total %d" % (side, total), fire_world(order(9, side=side), mid=mid, insert={"word": 0x25, "fills": [(10, total)]}))
    add("product exactly at the signed bound", fire_world(order(9), mid=1, insert={"word": 0x25, "fills": [(0x7FFFFFFFFFFFFFFE, 0x7FFFFFFFFFFFFFFE)]}))
    add("product one past the signed bound", fire_world(order(9), mid=1, insert={"word": 0x25, "fills": [(0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF)]}))
    add("second total overflows after the first", fire_world(order(9), insert={"word": 0x25, "fills": [(MAX64, 5), (9, MAX64)]}))
    add("single resting oid", fire_world(order(9), resting=[9]))
    add("table bytes with an items word of 0", fire_world(order(9), hidden=[9]))
    add("large oid in the table", fire_world(order(1 << 37), resting=[1 << 37]))
    add("large oid not in the table", fire_world(order(1 << 37), resting=[(1 << 37) + 16]))
    if kind == "fire":
        add("row list with one row and room", fire_world(order(9), event_start=(2, 1)))
        add("row list full", fire_world(order(9), event_start=(2, 2)))
        add("row list one short at the error row", fire_world(order(9), event_start=(2, 1), insert={"error": NONE_WORD + 1}))
    add("resting oid keeps the tracker", fire_world(order(9), resting=[9, 2]))
    add("other resting oid", fire_world(order(9), resting=[2, 3]))
    add("count at zero stays", fire_world(order(9), count=0))
    add("count at one", fire_world(order(9), count=1))
    add("changed tree holds the user", fire_world(order(9), changed=[5]))
    add("changed tree holds another", fire_world(order(9), changed=[4]))
    add("changed tree in two levels", fire_world(order(9), changed=[number for number in range(1, 15)], changed_height=1))
    add("changed tree two levels, last", base(users=[holder(max(range(1, 15), key=user_id), [order(9)])], user=max(range(1, 15), key=user_id), changed=list(range(1, 15)), changed_height=1))
    add("changed tree two levels, absent", fire_world(order(9), changed=[number * 2 + 20 for number in range(1, 15)], changed_height=1))
    add("all paths after an error", fire_world(order(9), insert={"error": NONE_WORD + 2}, changed=[5], resting=[9]))
    return out


def wrap_cases(copy):
    out = fire_cases(copy, "wrap")
    if copy < 2:
        out = out[::10]

    def add(label, w):
        out.append(Case("%s wrap: %s" % (COPIES[copy].name, label), "wrap", w, copy))

    add("dex row out of range", base(rows=1))
    add("book out of range", base(books=2))
    add("book one below the count", base(books=3))
    add("asset at a multiple", base(asset=10000, dexes=3, books=1))
    add("asset at the next dex", base(asset=20000, dexes=3, rows=3, books=1))
    add("asset at the next dex past the rows", base(asset=20000, dexes=3, rows=2, books=1))
    add("depth at the top", fire_world(order(9), depth=MAX64))
    add("depth one below the top", fire_world(order(9), depth=MAX64 - 1))
    add("depth zero", fire_world(order(9), depth=0))
    add("rows flushed after an error", fire_world(order(9), insert={"error": NONE_WORD + 2}))
    return out


def all_cases():
    out = []
    for copy in (0, 1):
        out += selection_cases(copy)
    for copy in (0, 1):
        out += fire_cases(copy)
    for copy in (0, 1, 2):
        out += wrap_cases(copy)
    return out

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


GROUPS = (
    (0x4321930, "selection: which orders fire"),
    (0x4913950, "selection: short sort by size"),
    (0x454CF20, "selection: rows shrink to 0x20 bytes"),
    (0x42FF010, "firing of one order"),
    (0x4D44470, "wrapper: book lookup, depth word, flush"),
)
CASE_CAP = 150
PATH_CASES = 4


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
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

FIELDS = {
    "state": {"+0x58": "depth word raised around one firing, saturating both ways", "+0x60/+0x64/+0x68": "block time: packed date, seconds of the day, nanoseconds", "dex rows": "+0x1040 pointer, +0x1048 count in the first copy; +0x5c0 and +0x5c8 in the others; stride 0x2f0",
              "byte passed to the gate": "+0x1372 in the first copy, +0x8f2 in the others", "per-user word map": "+0x11c0 in the first copy, +0x740 in the others; the value word +0x20 drops by 1 and stops at 0", "changed-asset map": "+0x1320 in the first copy, +0x8a0 in the others: user to a set the asset is passed to",
              "book rows": "+0x3df0 pointer, +0x3df8 count in the first wrapper; +0x3370 and +0x3378 in the others; stride 0x138; row +0x08 books, +0x10 count; book stride 0xd8"},
    "dex_row": {"+0x68/+0x70": "mark rows pointer and count, stride 0x60; row +0x20 price, +0x30 packed date, +0x34 seconds, +0x38 nanoseconds", "+0xf8": "user position map, read through 0x36f57f0"},
    "book": {"+0x28/+0x30/+0x40": "resting oid hash table: control pointer, mask, items", "+0x48": "tracker map argument of 0x342a600", "+0x80": "both sides, argument of the two top helpers", "+0xb0": "asset", "+0xb8/+0xc0/+0xc8": "user_states root, height, length"},
    "user_state_value": {"+0x38/+0x40/+0x48": "field u: root, height, length; key is the oid, value 0xb8 bytes"},
    "order_value": {"+0x00/+0x08": "optional size: present word, size", "+0x10": "byte: nonzero means selection skips the order; also copied word +0x10", "+0x30/+0x38/+0x40": "vector of 8 byte items: capacity, pointer, length; cloned three times",
                    "+0x48/+0x50": "tag dword (1 = present) and 0x20 bytes", "+0x70": "0x10 bytes", "+0x80": "stored limit price, used when byte +0xb0 is 0", "+0x88": "not forwarded: the insert request takes the block time in milliseconds here", "+0x90": "byte: reduce only",
                    "+0x91/+0x92": "tag byte (1 = present) and 0x10 bytes", "+0xa2": "side byte: 0 buy, 1 sell (inference from the fire test and the position test)", "+0xa8": "trigger price", "+0xb0": "byte: market order, the computed price replaces +0x80", "+0xb1": "byte: 1 stop, else take profit (names from the open order view packet rule, inference here)"},
    "position_node": {"+0x008": "11 values of 0x40 bytes, signed size at value +0x08", "+0x2c8": "11 asset keys", "+0x322": "length", "+0x328": "edges"},
    "selection_row": {"+0x00": "sort size, dropped by 0x454cf20", "+0x08": "user, 20 bytes", "+0x20": "oid"},
    "selection_result": {"+0x00/+0x08/+0x10": "rows: capacity (high bit word means None), pointer, length; row 0x20 bytes, user at +0, oid at +0x18", "+0x18": "mid", "+0x20": "reference price", "+0x28": "asset"},
    "insert_request": {"+0x00": "order +0x00 to +0x30", "+0x30": "items vector", "+0x48": "tag word and 0x20 bytes", "+0x70": "order +0x70", "+0x80": "sent limit price", "+0x88": "block time in milliseconds", "+0x90": "reduce byte", "+0x91": "tag byte and 0x10 bytes", "+0xa2": "side", "+0xa8": "word 1", "+0xb0": "oid", "+0xb8": "user", "+0xcc": "byte 2 minus the cap flag"},
    "event_row": {"stride": "0x278", "+0x00/+0x08": "words 3 and 2", "+0x10": "tag word and 0x20 bytes", "+0x38": "0xa8 byte open order record from the builder", "+0xe0": "block time, 12 bytes", "+0xec": "user", "+0x100": "status byte: 3 at firing, the table value after an insert error"},
}
RESULT_WORDS = (
    {"word": "0x8000000000000001", "meaning": "price gate said no: +0x08 price, +0x10/+0x18 text, +0x20 oid, +0x28 user, +0x3c side; the order stays in field u"},
    {"word": "0x8000000000000002", "meaning": "no user in user_states, or no root: nothing else happens"},
    {"word": "0x8000000000000003", "meaning": "user but no such order: the remove call still runs, and the tracker call too when no resting order has this oid"},
    {"word": "0x8000000000000000", "meaning": "insert error, word +0x08 from insert: a second event row, relation words cleared, order removed from field u"},
    {"word": "other", "meaning": "insert result: fills totalled, order removed from field u"},
)
REFERENCE_CLAIMS = (
    {"reference": "l1/ (whole tree)", "claim": "no user_states, untriggered_orders or firing of a stored trigger order; l1/book/book/mod.rs only carries an is_trigger flag", "observed": "selection 0x4321930 and firing 0x42ff010 read field u of user_states", "verdict": "missing in the reference"},
    {"reference": "l1/books.rs:396 settle_user_book_effects", "claim": "no trigger step between a mark update and the book", "observed": "0x4cf37f0 calls the selection for every book of a dex, then fires row by row", "verdict": "missing in the reference"},
)


def fixed_text(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def read_double(image, va):
    return struct.unpack_from("<d", image.blob, image.offset(va))[0]


def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def masked(image, start):
    """Function bytes with call, jump and rip displacements outside the function zeroed; (bytes, outer targets in order, rows)."""
    begin, end = image.exact_fde(start)
    out = bytearray(code(image, begin, end - begin))
    targets = []
    rows = decode_range(image, begin, end)
    for row in rows:
        at = row.va - begin
        if row.op in ("call", "jmp") and row.target is not None and not begin <= row.target < end:
            out[at + row.size - 4:at + row.size] = bytes(4)
            targets.append(row.target)
        if row.rip_at is not None:
            out[at + row.rip_at:at + row.rip_at + 4] = bytes(4)
    return bytes(out), targets, rows


def copy_table(image):
    """First and second copies: same bytes after masking, except the rows listed, which differ only in a state field displacement."""
    rows = []
    for first, second, allowed in ((0x42FF010, 0x4300950, ((0x1040, 0x5C0), (0x1048, 0x5C8), (0x1372, 0x8F2), (0x11C0, 0x740), (0x1320, 0x8A0), (0x1328, 0x8A8))),
                                   (0x4321930, 0x4320F80, ((0x1040, 0x5C0), (0x1048, 0x5C8))),
                                   (0x4D44470, 0x4D47070, ((0x3DF0, 0x3370), (0x3DF8, 0x3378)))):
        left, left_targets, decoded = masked(image, first)
        right, right_targets, _ = masked(image, second)
        if len(left) != len(right):
            raise EvidenceError("copy size %#x" % second)
        changed = []
        for row in decoded:
            at = row.va - first
            one, two = left[at:at + row.size], right[at:at + row.size]
            if one == two:
                continue
            pair = next((pair for pair in allowed if one.replace(struct.pack("<I", pair[0]), struct.pack("<I", pair[1])) == two), None)
            if pair is None:
                raise EvidenceError("copy row %#x differs" % row.va)
            changed.append({"offset": "%#x" % at, "first": one.hex(), "second": two.hex(), "field": "%#x / %#x" % pair})
        rows.append({"first": "%#x" % first, "second": "%#x" % second, "size": len(left), "first_sha256": hashlib.sha256(left).hexdigest(), "second_sha256": hashlib.sha256(right).hexdigest(), "state_rows": changed,
                     "callees_that_differ": [["%#x" % one, "%#x" % two] for one, two in zip(left_targets, right_targets) if one != two]})
    return rows


def constant_rows(image):
    rows = []
    for va, value in CONSTANTS:
        if read_double(image, va) != value:
            raise EvidenceError("constant at %#x" % va)
        rows.append({"va": "%#x" % va, "value": value, "bytes": code(image, va, 8).hex()})
    table = code(image, STATUS_TABLE, 8)
    if table != STATUS_BY_INDEX:
        raise EvidenceError("status table")
    return {"doubles": rows, "status_table": {"va": "%#x" % STATUS_TABLE, "bytes": table.hex()}, "texts": {"%#x" % TEXT_LIMIT: fixed_text(image, TEXT_LIMIT, 5), "%#x" % TEXT_OPP: fixed_text(image, TEXT_OPP, 3)}}


def fire_table():
    rows = []
    for side in (0, 1):
        for kind in (0, 1):
            for name, trigger in (("trigger below reference", 99), ("trigger equal", 100), ("trigger above reference", 101)):
                rows.append({"side": side, "kind_byte": kind, "compare": name, "fires": fires({"trigger": trigger, "side": side, "kind": kind}, 100)})
    return rows


def price_table():
    rows = []
    for side in (0, 1):
        for trigger, tick, left, right in ((1000000, 10, 900000, 1100000), (1000000, 10, 1500000, 1600000), (1000000, 10, 100, 200), (1000000, 10, 0, 0), (1000000, 7, 0, 0), (1 << 63, 1, 0, 0), (1, 100, 0, 0)):
            w = {"tick": tick, "top_pair": (left, right)}
            start, limit, sent, text = priced(w, {"side": side, "trigger": trigger})
            rows.append({"side": side, "trigger": trigger, "tick": tick, "first": left, "second": right, "rounded": start, "limit": limit, "sent": sent, "text_if_rejected": text})
    return rows


def host_rows(image):
    """Calls into the path by exact byte patterns: direct sites by target, slot sites of the two gates."""
    targets = sorted({target for _, target, _ in HOST_SITES} | {0x4321930, 0x4320F80, 0x42FF010, 0x4300950, 0x4D44470, 0x4D47070, 0x27371F0})
    direct = direct_sites(image, targets)
    rows = []
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for host, target, role in HOST_SITES:
        if not any(image.fde(va)[0] == host for va, _ in direct[target]):
            raise EvidenceError("no %s site for %#x in %#x" % (role, target, host))
    slots = []
    for slot, target in sorted(SLOT_NAMES.items()):
        if image_slot(image, slot) != target:
            raise EvidenceError("slot %#x" % slot)
        sites = [va for va in slot_sites(image, slot) if any(image.exact_fde(start)[0] <= va < image.exact_fde(start)[1] for start in (0x42FF010, 0x4300950, 0x27371F0))]
        slots.append({"slot": "%#x" % slot, "target": "%#x" % target, "sites_in_firing_copies": ["%#x" % va for va in sites]})
    return rows, slots


def image_slot(image, slot):
    for address, kind, addend, _ in image.relocations():
        if address == slot and kind == 8:
            return addend
    raise EvidenceError("no relocation at %#x" % slot)


def outcome_name(case, spec):
    if case.kind == "select":
        if spec.get("panic"):
            return "select panics"
        return "select none" if spec["none"] else "select %s" % ("no rows" if not spec["rows"] else "one row" if len(spec["rows"]) == 1 else "many rows")
    if spec.get("panic"):
        return "%s panics" % case.kind
    word = spec["word"]
    names = {WORD_REJECTED: "price gate no", WORD_NO_USER: "no user", WORD_NO_ORDER: "no order", NONE_WORD: "insert error"}
    return "%s %s" % (case.kind, names.get(word, "insert result"))


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
    extra = ((0x4320F80, "second copy of the selection"), (0x4300950, "second copy of the firing"), (0x4D47070, "second copy of the wrapper"), (0x27371F0, "third copy: wrapper and firing in one function"))
    for start, role in GROUPS + extra:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    site_rows, slot_rows = host_rows(image)
    copies = copy_table(image)
    constants = constant_rows(image)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "copies": copies,
        "constants": constants,
        "slots": slot_rows,
        "fields": FIELDS,
        "result_words": list(RESULT_WORDS),
        "fire_table": fire_table(),
        "price_table": price_table(),
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
    }


SURVIVED_DEFAULT = "not probed one by one: no reached case that ran shows a difference"
TIME_BOUND = "the range test on the time helper result: 20 s cannot leave the range, so the panic arm is not taken"
DEEP = "the small-count test before an 8 step descent loop: trees here are lower than height 8"
FIRST_LEAF = "the first key test in a leaf after a descent: a leaf on this walk always has a key"
PANIC_WORD = "a word or text length in a panic arm: the stub stops at the panic and reads neither"
SIZE_GUARD = "the size guard of the item vector clone: no item count here comes near it"
SAME_SLOT = "the conditional copy of an optional body: the same bytes are already in the target stack slot"
SAME_WORD = "a second bound test of the same dex word on the same path: the first test already passed"
FOUND_WALK = "the second user walk in the removal: the first walk found the user, so its end arms do not run"
RESULT_START = "start words of the result area in the wrapper: every path that reads them writes them first"
SURVIVED_REASONS = {
    0x4321A73: TIME_BOUND, 0x4321A80: TIME_BOUND, 0x4321AB1: "the sign fix of the day count: the seconds are never negative here",
    0x4321BE6: DEEP, 0x4321CD9: DEEP, 0x4321E35: DEEP, 0x4321F18: DEEP, 0x4321C43: FIRST_LEAF, 0x4321E93: FIRST_LEAF,
    0x4322206: "the choice between short and long sort: both give the same rows, and the long sort is a stub", 0x432220A: "the choice between short and long sort: both give the same rows, and the long sort is a stub",
    0x4322232: PANIC_WORD, 0x4322253: PANIC_WORD, 0x43006BE: PANIC_WORD, 0x43006E5: PANIC_WORD, 0x43007B1: PANIC_WORD, 0x4D44649: PANIC_WORD, 0x4D4466A: PANIC_WORD,
    0x454CF37: "the start pointer: +0x00 and +0x08 of the iterator hold the same word here", 0x454D066: "the shrink test: list capacities here are 0x28 times a power of two, so the low bits are clear",
    0x42FF2AD: "the sign mask of the float to integer cast: bits 0 to 62 of the mask are copies of the sign",
    0x42FF3F7: SIZE_GUARD, 0x42FF3FE: SIZE_GUARD, 0x42FF408: SIZE_GUARD,
    0x42FF6B5: "the dangling pointer of an empty second clone: an empty vector is never read or freed",
    0x42FF6E3: SAME_SLOT, 0x42FF6E5: SAME_SLOT, 0x42FF70C: SAME_SLOT, 0x42FF710: SAME_SLOT,
    0x42FF8A7: SAME_WORD, 0x42FFC89: SAME_WORD,
    0x42FFF04: "the saturated first total: the product overflows with this word or the one beside it", 0x42FFF3A: "the saturated second total: the sign test panics with this word or the one beside it",
    0x43000AA: "the side byte test against 2: side is 0 or 1 here",
    0x4300210: FOUND_WALK, 0x430027D: FOUND_WALK, 0x43002A5: FOUND_WALK,
    0x4300324: "the shuffle control of the hash byte: all bytes are equal, so any control gives the same group",
    0x4D444D6: "the pointer to the unread fifth argument", 0x4D44511: RESULT_START, 0x4D4451A: RESULT_START, 0x4D44523: RESULT_START,
}


UNREACHED_REASON = "no case reaches it: an allocator failure arm, a panic arm or an unwind pad"


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
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["kind\tcopy_and_kind\tlabel\toutcome"] + case_lines) + "\n"
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
