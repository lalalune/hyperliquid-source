#!/usr/bin/env python3
"""Pin the node #94 token genesis finish from ELF bytes: supply gates, balances, the book +0x78 word.

`0x4d611e0` and its two copies are the body behind nested spot deploy case 4. They parse the decimal maximum
supply, call `0x371b950` for the gates and the balance credit, emit one row per credited user, and write the
book +0x78 word on every USDC spot of the token. That word is floor(1e12 * 10^(wei - sz) / supply), at least 1.
The real bytes run in a Python evaluator with only the edges stubbed. A separately written specification
predicts every edge call and the final state, and every condition, immediate and field offset of the main
functions is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never
executed. Standard library only.
"""

import argparse
import bisect
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

STATUS_OK = 0x186
STATUS_TEXT = 0xE9
STATUS_PARSE = 0xB7
STATUS_OVERFLOW = 0xBE
TOKEN_STRIDE = 0xE8
BOOK_STRIDE = 0xD8
SPOT_STRIDE = 0x20
GENESIS_STRIDE = 0x48
ROW_TAG = 0x8000000000000010
PRICE_NUMERATOR = 1000000000000
MIN_LOTS = 100000000
HYPE_WORD = 0x45505948
HOLE_USER = b"\xff" * 20

TEXT_SUPPLY_SUM = (0x599058, 0x14)
TEXT_ONE_PERCENT = (0x59906C, 0x30)
TEXT_NOT_ZERO = (0x59909C, 0x3F)
TEXT_INCORRECT = (0x5990DB, 0x1C)
TEXT_MISSING = (0x5990F7, 0x21)
TEXT_LOTS = (0x599118, 0x25)
TEXTS = (TEXT_SUPPLY_SUM, TEXT_ONE_PERCENT, TEXT_NOT_ZERO, TEXT_INCORRECT, TEXT_MISSING, TEXT_LOTS)
WORDS = {TEXT_SUPPLY_SUM: b"genesis supply error", TEXT_ONE_PERCENT: b"Hyperliquidity must be at least 1% of max supply", TEXT_NOT_ZERO: b"Hyperliquidity balance should be 0 if no hyperliquidity is set.",
         TEXT_INCORRECT: b"genesis max supply incorrect", TEXT_MISSING: b"missing token genesis information", TEXT_LOTS: b"max supply must be at least 100M lots"}

FINISH = 0x371B950
SUM_READ = 0x371F6B0
HOLDERS = 0x3720A70
NAME = 0x3C0D6E0
WORD_HELPER = 0x3C09830
CREDIT = 0x371D120
SUPPLY_INSERT = 0x33A19D0
ENTRY_INSERT = 0x33BBF70
TREE_DROP = 0x33B0800
STATUS_DROP = 0x3762510
HASH = 0x3987CB0
POWERS = 0x584B08
OUTCOME_WRAP = 0x4D6BF80

COPIES = (
    dict(name="third", entry=0x4D611E0, network=0x1372, frame_arg=0x1378, rows=0x4855A50, rows_arg=0x5B8, touch=0x47D7CA0, touch_arg=0x11C0, books=0x3E08, iterate=0x494A910, book_location=0x5742338, spot_location=0x5742350,
         sites=(0x4AD84EF, 0x4D6C21E)),
    dict(name="second", entry=0x4D618F0, network=0x8F2, frame_arg=0x8F8, rows=0x3576710, rows_arg=0x8F3, touch=0x47D7CA0, touch_arg=0x740, books=0x3388, iterate=0x494A910, book_location=0x5742338, spot_location=0x5742350,
         sites=(0x4AD7BBF, 0x4D6C60E)),
    dict(name="first", entry=0x2746B40, network=0x8F2, frame_arg=0x8F8, rows=0x3576710, rows_arg=0x8F3, touch=0x1F849B0, touch_arg=0x740, books=0x3388, iterate=0x2869350, book_location=0x56BB478, spot_location=0x5690308,
         sites=(0x23E801F, 0x274C89E)),
)
THIRD = COPIES[0]

SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMCMP = 0x576E488
SLOT_MEMMOVE = 0x576E0E0
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
LOC_TOKEN = 0x56F21F0
LOC_DECIMALS = 0x56F2270
LOCATION_NAMES = {LOC_TOKEN: "token past the list", LOC_DECIMALS: "decimals underflow or scale overflow", 0x5742338: "book past the list, second and third copy", 0x5742350: "spot past the list, second and third copy",
                  0x56BB478: "book past the list, first copy", 0x5690308: "spot past the list, first copy"}

GENESIS_NODE = dict(parent=0, values=0x60, value=0x48, keys=8, index=0x378, length=0x37A, edges=0x380, leaf=0x380, inner=0x3E0, key=8)
USER_NODE = dict(parent=0, values=8, value=8, keys=0x60, index=0x13C, length=0x13E, edges=0x140, leaf=0x140, inner=0x1A0, key=0x14)
SET_NODE = dict(parent=0, values=8, value=0, keys=8, index=0xE4, length=0xE6, edges=0xE8, leaf=0xE8, inner=0x148, key=0x14)
WORD_NODE = dict(parent=0, values=0x60, value=8, keys=8, index=0xB8, length=0xBA, edges=0xC0, leaf=0xC0, inner=0x120, key=8)
NODE_KEYS = 11
LEAF_EDGE = 0x7300000000
TREE_ROW_LIMIT = 4000

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
STEP_LIMIT = 20000000
MUTANT_STEP_LIMIT = 300000
FAKE_MEMCPY = 0x7E000010
FAKE_MEMCMP = 0x7E000030
FAKE_MEMMOVE = 0x7E000050

OUT = HEAP_BASE + 0x800
EX = HEAP_BASE + 0x1000
BUMP = EX + 0x8000
GENESIS_MAP = EX + 0x3F0
SUPPLY_MAP = EX + 0x408

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


# ---- specification, written from a read of the code and not derived from a run ----

def user_id(number):
    """A 20-byte address with no repeated run."""
    return bytes((number * 37 + index * 11 + 3) & 0xFF for index in range(20))


class Case:
    def __init__(self, label, **changes):
        self.label = label
        self.text = b"200000000000000"
        self.token = 5
        self.flag = 0
        self.network = 1
        self.token_count = 9
        self.evm = 0
        self.rows = {5: dict(sz=2, wei=8, name=b"LEMON", spots=[0, 1, 3]), 2: dict(sz=0, wei=6, name=b"KIWI", spots=[2])}
        self.spots = [(5, 0), (5, 3), (2, 0), (5, 0)]
        self.book_count = 4
        self.genesis = {5: dict(users=[(user_id(7), 150000000000000), (HOLE_USER, 50000000000000)], existing=[], black=[])}
        self.other_genesis = ()
        self.supplies = [(2, 77)]
        self.holders = {}
        self.spare = HOLE_USER
        self.__dict__.update(changes)


class SpecPanic(Exception):
    pass


def spec_parse(text):
    """Kind of the parse error, or the value. A lone sign is invalid; `+` is dropped; `-` is not a digit."""
    if not text:
        return ("error", 0)
    if len(text) == 1 and text in (b"+", b"-"):
        return ("error", 1)
    digits = text[1:] if text[:1] == b"+" else text
    value = 0
    for at, byte in enumerate(digits):
        if not 0x30 <= byte <= 0x39:
            return ("error", 1)
        value = value * 10 + byte - 0x30
        if value >> 64:
            return ("error", 2)
    return ("value", value)


def spec_scale(row):
    if row["wei"] < row["sz"]:
        raise SpecPanic(("panic", LOC_DECIMALS))
    exponent = row["wei"] - row["sz"]
    if exponent >= 20:
        raise SpecPanic(("panic", LOC_DECIMALS))
    return 10 ** exponent


def spec_word(supply, scale):
    product = PRICE_NUMERATOR * scale
    if product <= MASK[8]:
        quotient = product // supply
    else:
        quotient = (PRICE_NUMERATOR // supply) * scale
        if quotient > MASK[8]:
            return 0
    return quotient or 1


def spec_sum(entry):
    """Sum of the user balances, then of the existing token amounts; None when a u64 add carries."""
    total = 0
    for _, amount in entry["users"]:
        total += amount
        if total > MASK[8]:
            return None
    for _, amount in entry["existing"]:
        total += amount
        if total > MASK[8]:
            return None
    return total


def spec_merge(totals, user, amount):
    value = totals.get(user, 0) + amount
    if value > MASK[8]:
        return False
    totals[user] = value
    return True


def spec_finish(case, supply, copy, events):
    """(status tuple, sorted credited balances, word)."""
    if case.token >= case.token_count:
        raise SpecPanic(("panic", LOC_TOKEN))
    row = case.rows[case.token]
    scale = spec_scale(row)
    lowest = min(MIN_LOTS * scale, MASK[8])
    if supply < lowest:
        return (STATUS_TEXT, WORDS[TEXT_LOTS]), None, None
    entry = case.genesis.get(case.token)
    if entry is None:
        return (STATUS_TEXT, WORDS[TEXT_MISSING]), None, None
    total = spec_sum(entry)
    if total is None:
        return (STATUS_TEXT, WORDS[TEXT_SUPPLY_SUM]), None, None
    if supply != total or supply == 0:
        return (STATUS_TEXT, WORDS[TEXT_INCORRECT]), None, None
    balances = dict(entry["users"])
    if case.flag:
        if balances.get(HOLE_USER):
            return (STATUS_TEXT, WORDS[TEXT_NOT_ZERO]), None, None
    elif case.network and balances.get(HOLE_USER, 0) < supply // 100 and row["name"] != b"HYPE":
        return (STATUS_TEXT, WORDS[TEXT_ONE_PERCENT]), None, None
    totals = {}
    blocked = set(entry["black"])
    for user, amount in sorted(entry["users"]):
        if user not in blocked:
            spec_merge(totals, user, amount)
    for other, amount in sorted(entry["existing"]):
        events.append(("holders", other, amount))
        answer = case.holders.get(other, ())
        if isinstance(answer, int):
            return ("filled", answer), None, None
        for user, share in answer:
            if not spec_merge(totals, user, share):
                return (STATUS_OVERFLOW,), None, None
    word = spec_word(supply, scale)
    for user, amount in sorted(totals.items()):
        events.append(("credit", user.hex(), case.token, amount, word))
    return None, sorted(totals.items()), word


def spec_run(case, copy):
    events = []
    parsed = spec_parse(case.text)
    if parsed[0] == "error":
        return dict(stop=None, events=events, status=(STATUS_PARSE, parsed[1]))
    supply = parsed[1]
    try:
        status, balances, word = spec_finish(case, supply, copy, events)
        if status:
            return dict(stop=None, events=events, status=status, state=spec_state(case, None, None, None))
        row = case.rows[case.token]
        events.append(("name", case.token))
        for user, amount in balances:
            if case.evm == 1:
                events.append(("hash", case.network, EVM_WORDS[1], EVM_WORDS[0]))
            events.append(("row", user.hex(), row["name"], to_bits(float(amount) / 10.0 ** row["wei"]), case.evm == 1))
            events.append(("touch", user.hex()))
        written = {}
        if word:
            for spot in row["spots"]:
                if spot >= len(case.spots):
                    raise SpecPanic(("bounds", spot, len(case.spots), copy["spot_location"]))
                if case.spots[spot][1] == 0:
                    if spot >= case.book_count:
                        raise SpecPanic(("panic", copy["book_location"]))
                    written[spot] = word
        return dict(stop=None, events=events, status=(STATUS_OK,), state=spec_state(case, written, supply, word))
    except SpecPanic as caught:
        return dict(stop=caught.args[0], events=events)


def spec_state(case, written, supply, word):
    """Book +0x78 of each spot and the supply map after the run."""
    books = {spot: book_mark(spot) for spot in range(min(case.book_count, 16))}
    books.update(written or {})
    supplies = dict(case.supplies)
    if supply is not None:
        supplies[case.token] = supply
    return dict(books=books, supplies=sorted(supplies.items()))


def book_mark(spot):
    return 0x1111111100 + spot


EVM_WORDS = (0x7711223344556600, 0x7722334455667700)


def tree_height(count, width):
    height = 0
    while (width + 1) ** (height + 1) - 1 < count:
        height += 1
    return height


def split(keys, width, height):
    """Separators and child key lists of one node."""
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


# ---- harness: real bytes, edges stubbed, every edge argument recorded ----

RAMPS = {}


def ramp(size, start):
    """Non-periodic filler, so that a wrong field offset reads a wrong value."""
    key = (size, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 37 + (index >> 4)) & 0xFF | 1 for index in range(size))
    return RAMPS[key]


class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        machine.memory.statics.update(self.relative)
        machine.memory.statics[0x577AB98] = 0
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.memory.statics[SLOT_MEMMOVE] = FAKE_MEMMOVE
        relative = self.relative
        self.slot_hooks = {relative[SLOT_ALLOC]: self.on_alloc, relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed, relative[SLOT_FREE]: self.on_free, relative[SLOT_PANIC]: self.on_panic,
                           relative[SLOT_BOUNDS]: self.on_bounds, FAKE_MEMCPY: self.on_memcpy, FAKE_MEMCMP: self.on_memcmp, FAKE_MEMMOVE: self.on_memcpy,
                           HOLDERS: self.on_holders, NAME: self.on_name, 0x4855A50: self.on_row, 0x3576710: self.on_row}
        machine.slots = dict(self.slot_hooks)
        self.direct = {STATUS_DROP: self.on_status_drop, CREDIT: self.on_credit, HASH: self.on_hash, 0x47D7CA0: self.on_touch, 0x1F849B0: self.on_touch}
        machine.calls = dict(self.direct)
        self.real = RealExcept()
        self.real.stubs = frozenset(machine.calls) | frozenset(machine.slots)
        machine.real = self.real
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.copy = THIRD

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def build_tree(self, at, rows, shape, write_value, tempt):
        """(root, height, length) at `at`; every row is (key bytes, payload)."""
        memory = self.machine.memory
        if not rows:
            self.put(at, 8, 0)
            self.put(at + 8, 8, 0x41)
            self.put(at + 0x10, 8, 0)
            return

        def make(items, parent, slot, level):
            size = shape["inner"] if level else shape["leaf"]
            node = self.alloc(size)
            memory.put_bytes(node, ramp(size, level + 9))
            self.put(node + shape["parent"], 8, parent)
            self.put(node + shape["index"], 2, slot)
            separators, children = split(items, NODE_KEYS, level)
            self.put(node + shape["length"], 2, len(separators))
            for index, row in enumerate(separators):
                memory.put_bytes(node + shape["keys"] + index * shape["key"], row[0])
                write_value(node + shape["values"] + index * shape["value"], row)
            for index in range(len(separators), NODE_KEYS):
                memory.put_bytes(node + shape["keys"] + index * shape["key"], tempt)
            if level:
                for index in range(NODE_KEYS + 1):
                    self.put(node + shape["edges"] + index * 8, 8, LEAF_EDGE)
                for index, child in enumerate(children):
                    self.put(node + shape["edges"] + index * 8, 8, make(child, node, index, level - 1))
            return node

        level = tree_height(len(rows), NODE_KEYS)
        self.put(at, 8, make(list(rows), 0, 0, level))
        self.put(at + 8, 8, level)
        self.put(at + 0x10, 8, len(rows))

    def read_words(self, at):
        """(key, value) of a u64 to u64 tree, bounded, for a tree the run may have changed."""
        read = self.machine.memory.read
        root, height, count = read(at, 8), read(at + 8, 8), read(at + 0x10, 8)
        if not root:
            return []
        if height > 3 or count > TREE_ROW_LIMIT:
            raise Halt("supply map shape")
        rows, nodes = [], [root]

        def walk(node, level):
            length = read(node + WORD_NODE["length"], 2)
            if length > NODE_KEYS:
                raise Halt("node length")
            for index in range(length + 1):
                if level:
                    walk(read(node + WORD_NODE["edges"] + index * 8, 8), level - 1)
                if index < length:
                    rows.append((read(node + 8 + index * 8, 8), read(node + 0x60 + index * 8, 8)))
                if len(rows) > TREE_ROW_LIMIT:
                    raise Halt("row limit")
            self.live.pop(node, None)
        walk(root, height)
        return rows

    # shared stubs

    def on_alloc(self, m):
        at = self.alloc(m.regs[RDI])
        self.live[at] = m.regs[RDI]
        m.regs[RAX] = at

    def on_free(self, m):
        pointer, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(pointer, None) != size:
            raise Halt("free of a block that does not match: %#x %#x" % (pointer, size))
        if m.regs[RDX] & MASK[4]:
            raise Halt("free flag")

    def on_memcpy(self, m):
        if m.regs[RDX] > HEAP_SIZE:
            raise Halt("copy length")
        if m.regs[RDX]:
            m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]

    def on_memcmp(self, m):
        if m.regs[RDX] > 4096:
            raise Halt("compare length")
        left = m.memory.bytes_at(m.regs[RDI], m.regs[RDX])
        right = m.memory.bytes_at(m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = 0 if left == right else (MASK[4] if left < right else 1)

    def on_alloc_failed(self, m):
        raise Panicked(("alloc failed", m.regs[RDI] & MASK[4], m.regs[RSI]))

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    # edges of this path

    def on_holders(self, m):
        read = m.memory.read
        if m.regs[RSI] != EX + 0x80 or m.regs[RDX] != self.case.token or m.regs[R9] != EX + self.copy["frame_arg"]:
            raise Halt("holders arguments")
        if read(m.regs[RSP], 8):
            raise Halt("holders stack word")
        other, amount = m.regs[RCX], m.regs[R8]
        self.events.append(("holders", other, amount))
        answer = self.case.holders.get(other, ())
        at = m.regs[RDI]
        if isinstance(answer, int):
            m.memory.put_bytes(at, ramp(0x60, 77))
            self.put(at, 2, answer)
            return
        self.put(at, 2, STATUS_OK)
        capacity = len(answer) + 2
        block = self.alloc(capacity * 0x20)
        self.live[block] = capacity * 0x20
        for index, (user, share) in enumerate(answer):
            m.memory.put_bytes(block + index * 0x20, user)
            self.put(block + index * 0x20 + 0x18, 8, share)
        self.put(at + 8, 8, capacity)
        self.put(at + 0x10, 8, block)
        self.put(at + 0x18, 8, len(answer))

    def on_status_drop(self, m):
        if m.memory.read(m.regs[RDI], 2) != STATUS_TEXT:
            raise Halt("drop word")

    def on_credit(self, m):
        if m.regs[RDI] != EX + 0x80 or m.regs[RCX] & MASK[4]:
            raise Halt("credit arguments")
        self.events.append(("credit", m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX], m.regs[R8], m.regs[R9]))

    def on_name(self, m):
        if m.regs[RDX] != EX + 0x90:
            raise Halt("name argument")
        token = m.regs[RSI]
        self.events.append(("name", token))
        name = self.case.rows[self.case.token]["name"] if token == self.case.token else b"?"
        block = self.alloc(len(name))
        self.live[block] = len(name)
        m.memory.put_bytes(block, name)
        at = m.regs[RDI]
        self.put(at, 8, len(name))
        self.put(at + 8, 8, block)
        self.put(at + 0x10, 8, len(name))

    def on_hash(self, m):
        self.events.append(("hash", m.regs[RSI] & 0xFF, m.regs[RDX], m.regs[RCX]))
        if m.regs[R8] & MASK[4]:
            raise Halt("hash word")
        m.memory.put_bytes(m.regs[RDI], ramp(0x20, 41))

    def on_row(self, m):
        read = m.memory.read
        if m.regs[RDI] != EX + self.copy["rows_arg"]:
            raise Halt("row list")
        users, frame, code, row = m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8]
        if read(users, 8) != 1 or read(users + 0x10, 8) != 1:
            raise Halt("row user list")
        block = read(users + 8, 8)
        user = m.memory.bytes_at(block, 20)
        if self.live.pop(block, None) != 20:
            raise Halt("row user block")
        if read(row, 8) != ROW_TAG:
            raise Halt("row tag")
        size = read(row + 8, 8)
        if read(row + 0x18, 8) != size:
            raise Halt("row name size")
        pointer = read(row + 0x10, 8)
        name = m.memory.bytes_at(pointer, size)
        if self.live.pop(pointer, None) != size:
            raise Halt("row name block")
        if m.memory.bytes_at(frame, 12) != m.memory.bytes_at(EX + 0x60, 12):
            raise Halt("row time")
        hashed = m.memory.bytes_at(code, 0x20)
        if hashed not in (bytes(0x20), ramp(0x20, 41)) or (hashed != bytes(0x20)) != (self.case.evm == 1):
            raise Halt("row hash")
        self.events.append(("row", user.hex(), name, read(row + 0x20, 8), hashed != bytes(0x20)))

    def on_touch(self, m):
        if m.regs[RDI] != EX + self.copy["touch_arg"]:
            raise Halt("touch set")
        self.events.append(("touch", m.memory.bytes_at(m.regs[RSI], 20).hex()))

    # the run

    def write_genesis(self, at, row):
        memory = self.machine.memory
        memory.put_bytes(at, ramp(GENESIS_STRIDE, 53))
        entry = row[1]
        self.build_tree(at, [(user, amount) for user, amount in sorted(entry["users"])], USER_NODE, lambda place, item: self.put(place, 8, item[1]), self.case.spare)
        self.build_tree(at + 0x18, [(struct.pack("<Q", other), amount) for other, amount in sorted(entry["existing"])], WORD_NODE, lambda place, item: self.put(place, 8, item[1]), struct.pack("<Q", 2))
        self.build_tree(at + 0x30, [(user, 0) for user in sorted(entry["black"])], SET_NODE, lambda place, item: None, user_id(7))

    def run_finish(self, case):
        copy = self.copy
        machine = self.machine
        memory = machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.case = case
        memory.put_bytes(OUT, ramp(0x80, 13))
        memory.put_bytes(EX, ramp(0x7000, 31))
        self.put(EX, 4, case.evm)
        self.put(EX + 0x28, 8, EVM_WORDS[1])
        self.put(EX + 8, 8, EVM_WORDS[0])
        self.put(EX + copy["network"], 1, case.network)
        tokens = self.alloc(TOKEN_STRIDE * max(case.token_count, 1))
        memory.put_bytes(tokens, ramp(TOKEN_STRIDE * max(case.token_count, 1), 57))
        self.put(EX + 0x210, 8, tokens)
        self.put(EX + 0x218, 8, case.token_count)
        for index, row in sorted(case.rows.items()):
            at = tokens + index * TOKEN_STRIDE
            name = self.alloc(max(len(row["name"]), 1))
            memory.put_bytes(name, row["name"])
            self.put(at + 0x38, 8, name)
            self.put(at + 0x40, 8, len(row["name"]))
            self.put(at + 0x48, 1, row["sz"])
            self.put(at + 0x49, 1, row["wei"])
            array = self.alloc(max(len(row["spots"]), 1) * 8)
            for slot, spot in enumerate(row["spots"]):
                self.put(array + slot * 8, 8, spot)
            self.put(at + 0x58, 8, array)
            self.put(at + 0x60, 8, len(row["spots"]))
        spots = self.alloc(SPOT_STRIDE * max(len(case.spots), 1))
        memory.put_bytes(spots, ramp(SPOT_STRIDE * max(len(case.spots), 1), 63))
        self.put(EX + 0x1F8, 8, spots)
        self.put(EX + 0x200, 8, len(case.spots))
        for index, (base, quote) in enumerate(case.spots):
            self.put(spots + index * SPOT_STRIDE, 8, base)
            self.put(spots + index * SPOT_STRIDE + 8, 8, quote)
        books = self.alloc(BOOK_STRIDE * max(case.book_count, 1))
        memory.put_bytes(books, ramp(BOOK_STRIDE * max(case.book_count, 1), 69))
        self.put(EX + copy["books"], 8, books)
        self.put(EX + copy["books"] + 8, 8, case.book_count)
        for spot in range(min(case.book_count, 16)):
            self.put(books + spot * BOOK_STRIDE + 0x78, 8, book_mark(spot))
        self.books = books
        rows = [(struct.pack("<Q", token), entry) for token, entry in sorted(list(case.genesis.items()) + list(case.other_genesis))]
        self.build_tree(GENESIS_MAP, rows, GENESIS_NODE, self.write_genesis, struct.pack("<Q", case.token))
        self.build_tree(SUPPLY_MAP, [(struct.pack("<Q", key), value) for key, value in sorted(case.supplies)], WORD_NODE, lambda place, item: self.put(place, 8, item[1]), struct.pack("<Q", case.token))
        text = self.alloc(max(len(case.text), 1))
        memory.put_bytes(text, case.text)
        STACK_ARG = STACK_TOP - 0x100
        self.put(STACK_ARG, 8, case.flag | 0xABCD00)
        result = machine.run(copy["entry"], {RDI: OUT, RSI: EX, RDX: case.network | 0x7700, RCX: case.token, R8: text, R9: len(case.text)})
        if result != OUT:
            raise Halt("result pointer")
        state = self.read_state(case)
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events, "status": self.status(), "state": state}

    def read_state(self, case):
        books = {spot: self.machine.memory.read(self.books + spot * BOOK_STRIDE + 0x78, 8) for spot in range(min(case.book_count, 16))}
        return dict(books=books, supplies=self.read_words(SUPPLY_MAP))

    def status(self):
        memory = self.machine.memory
        word = memory.read(OUT, 2)
        if word == STATUS_TEXT:
            return (word, memory.bytes_at(memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8)))
        if word == STATUS_PARSE:
            return (word, memory.read(OUT + 2, 1))
        if word in (STATUS_OK, STATUS_OVERFLOW):
            return (word,)
        expected = bytearray(ramp(0x60, 77))
        expected[0:2] = struct.pack("<H", word)
        if memory.bytes_at(OUT, 0x60) != bytes(expected):
            raise Halt("status block not copied whole")
        return ("filled", word)

    def run(self, case):
        try:
            return self.run_finish(case)
        except Panicked as caught:
            return {"stop": caught.args[0], "events": self.events}
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)


CRASHES = (Halt, EvidenceError, RecursionError, IndexError, KeyError, ZeroDivisionError, StopIteration, OverflowError, ValueError, TypeError, struct.error)
COMPARED = ("stop", "events", "status", "state")


def compare_run(harness, case):
    try:
        actual = harness.run(case)
    except CRASHES as caught:
        return "%s: crash %s" % (case.label, caught)
    expected = spec_run(case, harness.copy)
    for key in COMPARED:
        if key in expected and actual.get(key) != expected.get(key):
            return "%s: %s differs: %s / %s" % (case.label, key, str(actual.get(key))[:400], str(expected.get(key))[:400])
    return None


# ---- cases ----

MANY = [user_id(number) for number in range(20, 34)]


def supply_case(label, sz, wei, supply, **changes):
    """One user holds the whole supply beside a 1% hole balance."""
    hole = supply // 100
    rows = {5: dict(sz=sz, wei=wei, name=b"LEMON", spots=[0, 1, 3]), 2: dict(sz=0, wei=6, name=b"KIWI", spots=[2])}
    return Case(label, rows=rows, text=str(supply).encode(), genesis={5: dict(users=[(user_id(7), supply - hole), (HOLE_USER, hole)], existing=[], black=[])}, **changes)


def parse_cases():
    rows = [Case("parse empty", text=b""), Case("parse lone plus", text=b"+"), Case("parse lone minus", text=b"-"), Case("parse lone digit", text=b"7"), Case("parse lone letter", text=b"x"),
            Case("parse plus zero", text=b"+0"), Case("parse minus digits", text=b"-5"), Case("parse letter short", text=b"12a4"), Case("parse colon", text=b"12:4"), Case("parse slash", text=b"12/4"),
            Case("parse plus value", text=b"+200000000000000"), Case("parse leading zeros", text=b"000200000000000000"), Case("parse sixteen digits", text=b"2000000000000000"),
            Case("parse seventeen digits", text=b"20000000000000000"), Case("parse letter long", text=b"20000000000000x00"), Case("parse colon long", text=b"20000000000000:00"),
            Case("parse u64 max", text=b"18446744073709551615"), Case("parse u64 max plus one", text=b"18446744073709551616"), Case("parse add overflow at last digit", text=b"18446744073709551619"),
            Case("parse multiply overflow", text=b"184467440737095516150"), Case("parse multiply overflow then letter", text=b"184467440737095516150x"), Case("parse multiply overflow on a letter", text=b"18446744073709551615x"),
            Case("parse multiply overflow on a slash", text=b"18446744073709551615/"), Case("parse multiply overflow on a colon", text=b"18446744073709551615:"), Case("parse multiply overflow on a semicolon", text=b"18446744073709551615;"), Case("parse plus seventeen", text=b"+20000000000000000"), Case("parse plus exactly seventeen digits", text=b"+0000000000000020"), Case("parse plus sixteen total", text=b"+000000000000020")]
    return rows


def gate_cases():
    rows = []
    for sz, wei in ((2, 8), (0, 0), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (1, 8), (0, 8), (0, 9), (0, 11)):
        lowest = MIN_LOTS * 10 ** (wei - sz)
        rows.append(supply_case("lots edge %d %d" % (sz, wei), sz, wei, lowest))
        rows.append(supply_case("lots edge below %d %d" % (sz, wei), sz, wei, lowest - 1))
        rows.append(supply_case("lots high %d %d" % (sz, wei), sz, wei, lowest * 7 + 3))
    for sz, wei in ((0, 12), (0, 13), (0, 15), (0, 16), (0, 19), (3, 19)):
        rows.append(supply_case("saturated minimum %d %d" % (sz, wei), sz, wei, MASK[8]))
        rows.append(supply_case("saturated minimum below %d %d" % (sz, wei), sz, wei, MASK[8] - 1))
    rows.append(supply_case("scale 10^11 fits", 0, 11, 10 ** 19))
    rows.append(supply_case("wei below sz", 3, 2, 10 ** 12))
    rows.append(supply_case("scale overflow 20", 0, 20, 10 ** 12))
    rows.append(supply_case("scale overflow 21", 1, 22, 10 ** 12))
    rows.append(supply_case("scale overflow 32", 0, 32, 10 ** 12))
    rows.append(supply_case("scale overflow 33", 0, 33, 10 ** 12))
    rows.append(supply_case("scale overflow 64", 0, 64, 10 ** 12))
    rows.append(Case("token past the list", token=9, rows={9: dict(sz=2, wei=8, name=b"LEMON", spots=[])}))
    rows.append(Case("token last of the list", token=8, rows={8: dict(sz=2, wei=8, name=b"LEMON", spots=[0])}, genesis={8: dict(users=[(HOLE_USER, 200000000000000)], existing=[], black=[])}))
    rows.append(Case("no genesis at all", genesis={}))
    rows.append(Case("genesis of another token", genesis={4: dict(users=[], existing=[], black=[])}))
    rows.append(Case("genesis above only", genesis={6: dict(users=[], existing=[], black=[])}))
    wide = {token: dict(users=[(user_id(9), 1)], existing=[], black=[]) for token in range(30, 44)}
    entry = dict(users=[(user_id(7), 198000000000000), (HOLE_USER, 2000000000000)], existing=[], black=[])
    rows.append(Case("genesis in a deep map", genesis={**wide, 5: entry}))
    wide_high = {token: dict(users=[(user_id(9), 1)], existing=[], black=[]) for token in range(1, 5)}
    wide_high.update({token: dict(users=[(user_id(9), 1)], existing=[], black=[]) for token in range(6, 18)})
    rows.append(Case("genesis at a separator of a deep map", genesis={**wide_high, 5: entry}))
    rows.append(Case("sum below the text", text=b"200000000000001"))
    rows.append(Case("sum above the text", text=b"199999999999999", rows={5: dict(sz=2, wei=7, name=b"LEMON", spots=[0, 1, 3])}))
    rows.append(Case("user sum carries", genesis={5: dict(users=[(user_id(7), 1 << 63), (user_id(8), 1 << 63)], existing=[], black=[])}))
    rows.append(Case("existing sum carries", genesis={5: dict(users=[(user_id(7), 1 << 63)], existing=[(3, 1 << 63)], black=[])}))
    rows.append(Case("second existing row carries", genesis={5: dict(users=[], existing=[(3, 1 << 63), (4, 1 << 63)], black=[])}))
    rows.append(Case("existing exact to u64 max", text=b"18446744073709551615", rows={5: dict(sz=0, wei=12, name=b"LEMON", spots=[0])}, genesis={5: dict(users=[(HOLE_USER, MASK[8] - 5)], existing=[(3, 5)], black=[])}, holders={3: [(user_id(11), 5)]}))
    rows.append(Case("zero supply and zero sum, lots 0 impossible", text=b"0", genesis={5: dict(users=[], existing=[], black=[])}))
    rows.append(supply_case("zero supply passes lots only if lots are 0", 0, 0, 0))
    return rows


def hole_cases():
    rows = []
    supply = 200000000000000
    one = supply // 100
    for label, hole in (("hole exactly 1%", one), ("hole below 1%", one - 1), ("hole above 1%", one + 1), ("hole zero", 0), ("hole all", supply)):
        users = [(HOLE_USER, hole)] + ([(user_id(7), supply - hole)] if hole != supply else [])
        for flag in (0, 1):
            for network in (0, 1, 2):
                rows.append(Case("%s flag %d network %d" % (label, flag, network), flag=flag, network=network, genesis={5: dict(users=users, existing=[], black=[])}))
    absent = {5: dict(users=[(user_id(7), supply)], existing=[], black=[])}
    for flag in (0, 1):
        for network in (0, 1):
            rows.append(Case("no hole row flag %d network %d" % (flag, network), flag=flag, network=network, genesis=absent))
    for name in (b"HYPE", b"HYPF", b"GYPE", b"HYP", b"HYPES", b"HYPE\x00", b"hype"):
        rows.append(Case("name %s" % name.decode().replace("\x00", "0"), rows={5: dict(sz=2, wei=8, name=name, spots=[0, 1, 3])}, genesis=absent))
    for supply_text, supply_value in ((b"199999999999999", 199999999999999), (b"199999999999900", 199999999999900), (b"199999999999899", 199999999999899)):
        low = supply_value // 100
        rows.append(Case("floor one percent %d" % supply_value, rows={5: dict(sz=2, wei=7, name=b"LEMON", spots=[0, 1, 3])}, text=supply_text, genesis={5: dict(users=[(HOLE_USER, low), (user_id(7), supply_value - low)], existing=[], black=[])}))
        rows.append(Case("floor one percent less %d" % supply_value, rows={5: dict(sz=2, wei=7, name=b"LEMON", spots=[0, 1, 3])}, text=supply_text, genesis={5: dict(users=[(HOLE_USER, low - 1), (user_id(7), supply_value - low + 1)], existing=[], black=[])}))
    many = [(user, 1000 + index) for index, user in enumerate(MANY)]
    last = sum(amount for _, amount in many)
    hole_at_end = many + [(HOLE_USER, 200000000000000 - last)]
    rows.append(Case("hole in a deep tree", genesis={5: dict(users=hole_at_end, existing=[], black=[])}))
    rows.append(Case("users past one leaf, no hole row", flag=1, genesis={5: dict(users=many[:-1] + [(many[-1][0], 200000000000000 - sum(amount for _, amount in many[:-1]))], existing=[], black=[])}))
    return rows


def balance_cases():
    rows = []
    supply = 200000000000000
    hole = (HOLE_USER, 50000000000000)
    def rest(*parts):
        left = supply - hole[1] - sum(amount for _, amount in parts)
        return list(parts) + [hole, (user_id(40), left)]
    rows.append(Case("blacklist drops one", genesis={5: dict(users=rest((user_id(7), 5000)), existing=[], black=[user_id(7)])}))
    rows.append(Case("blacklist unmatched", genesis={5: dict(users=rest((user_id(7), 5000)), existing=[], black=[user_id(8)])}))
    rows.append(Case("blacklist the hole", genesis={5: dict(users=rest((user_id(7), 5000)), existing=[], black=[HOLE_USER])}))
    rows.append(Case("blacklist all", genesis={5: dict(users=rest(), existing=[], black=[HOLE_USER, user_id(40)])}))
    rows.append(Case("blacklist deep set", genesis={5: dict(users=rest((user_id(7), 5000)), existing=[], black=MANY + [user_id(7)])}))
    rows.append(Case("blacklist deep set, last key", genesis={5: dict(users=rest((MANY[-1], 5000)), existing=[], black=MANY)}))
    rows.append(Case("blacklist deep set, unmatched", genesis={5: dict(users=rest((user_id(7), 5000)), existing=[], black=MANY)}))
    three = [(user, 1000 + index) for index, user in enumerate(MANY)]
    rows.append(Case("users split a tree", genesis={5: dict(users=rest(*three), existing=[], black=[])}))
    rows.append(Case("users split a tree, some blocked", genesis={5: dict(users=rest(*three), existing=[], black=MANY[3:9])}))
    rows.append(Case("existing one holder", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[])}, holders={3: [(user_id(9), 900)]}))
    rows.append(Case("existing adds to a user", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[])}, holders={3: [(user_id(7), 600), (user_id(9), 300)]}))
    rows.append(Case("existing not blocked by the list", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[user_id(9)])}, holders={3: [(user_id(9), 900)]}))
    rows.append(Case("existing first in order is the key above", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(4, 100), (3, 800)], black=[])}, holders={3: [(user_id(9), 800)], 4: [(user_id(9), 100)]}))
    rows.append(Case("existing empty answer", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[])}, holders={3: []}))
    rows.append(Case("existing refused", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[])}, holders={3: 0x77}))
    rows.append(Case("existing second refused after a good one", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 400), (4, 500)], black=[])}, holders={3: [(user_id(9), 400)], 4: 0x161}))
    rows.append(Case("holder share pushes past u64", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[])}, holders={3: [(user_id(7), MASK[8])]}))
    rows.append(Case("holder share exact to u64 max", text=b"18446744073709551615", rows={5: dict(sz=0, wei=12, name=b"LEMON", spots=[0])}, genesis={5: dict(users=[(HOLE_USER, MASK[8] - 5)], existing=[(3, 5)], black=[HOLE_USER])}, holders={3: [(user_id(9), MASK[8] - 5), (user_id(9), 5)]}))
    rows.append(Case("holder two overflow, second holder", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[])}, holders={3: [(user_id(9), MASK[8]), (user_id(9), 1)]}))
    rows.append(Case("existing fills many rows", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(token, 60) for token in range(30, 45)], black=[])}, holders={token: [(user_id(token), 60)] for token in range(30, 45)}))
    rows.append(Case("holders above the tree", genesis={5: dict(users=[hole, (user_id(7), supply - hole[1] - 900)], existing=[(3, 900)], black=[])}, holders={3: [(MANY[index], 60) for index in range(14)]}))
    return rows


def word_cases():
    rows = []
    for sz, wei, supply in ((0, 0, 7299270073), (0, 0, 10 ** 8), (0, 0, 10 ** 8 + 1), (0, 0, 10 ** 12), (0, 0, 10 ** 12 + 1), (0, 0, 2 * 10 ** 12), (0, 0, 10 ** 13), (0, 0, 2 ** 32), (0, 0, 2 ** 32 - 1), (0, 0, 3 * 10 ** 8), (2, 8, 10 ** 15), (2, 8, 10 ** 14 + 7), (2, 8, 3 * 10 ** 14),
                            (0, 7, 10 ** 15), (0, 7, 10 ** 19), (0, 8, 10 ** 16), (0, 8, 3 * 10 ** 16), (0, 8, 10 ** 19), (0, 7, 3 * 10 ** 15), (0, 9, 10 ** 17), (0, 11, 10 ** 19)):
        rows.append(supply_case("word %d %d %d" % (sz, wei, supply), sz, wei, supply))
    return rows


def book_cases():
    rows = []
    genesis_rows = lambda spots: {5: dict(sz=2, wei=8, name=b"LEMON", spots=spots), 2: dict(sz=0, wei=6, name=b"KIWI", spots=[2])}
    rows.append(Case("no spots of the token", rows=genesis_rows([])))
    rows.append(Case("only a non-USDC spot", rows=genesis_rows([1])))
    rows.append(Case("last spot of the list", rows=genesis_rows([3])))
    rows.append(Case("spot past the list", rows=genesis_rows([0, 4])))
    rows.append(Case("spot past the list after a good one, wide", spots=[(5, 0)] * 3, book_count=8, rows=genesis_rows([0, 3])))
    rows.append(Case("book past the list", book_count=1, rows=genesis_rows([0, 3])))
    rows.append(Case("book at the end", book_count=3, rows=genesis_rows([3])))
    rows.append(Case("book bound not read for a non-USDC spot", spots=[(5, 1), (5, 3)], book_count=0, rows=genesis_rows([0, 1])))
    rows.append(Case("evm row", evm=1))
    rows.append(Case("evm word other", evm=2))
    rows.append(Case("two users, evm row", evm=1, genesis={5: dict(users=[(user_id(7), 100000000000000), (user_id(8), 50000000000000), (HOLE_USER, 50000000000000)], existing=[], black=[])}))
    rows.append(Case("supply map replaces", supplies=[(5, 3), (2, 77)]))
    rows.append(Case("supply map empty", supplies=[]))
    rows.append(Case("supply map deep", supplies=[(token, token) for token in range(20, 44)]))
    rows.append(Case("small amounts float", genesis={5: dict(users=[(user_id(7), 199999999999999 - 2000000000000 + 1), (HOLE_USER, 2000000000000), (user_id(8), 0)], existing=[], black=[])}, rows={5: dict(sz=2, wei=8, name=b"LEMON", spots=[0, 1, 3])}))
    rows.append(supply_case("odd amount rounds to a float", 0, 8, 18446744073709551557))
    return rows


def network_cases():
    return [Case("network %d" % value, network=value) for value in (0, 1, 2, 3)]


def spare_cases():
    """The spare key slots hold a plain user, so a shifted read of the last key sees no 0xff run."""
    plain = user_id(3)
    rows = [Case("plain spare, default", spare=plain), Case("plain spare, no flag edge", spare=plain, genesis={5: dict(users=[(user_id(7), 198000000000000), (HOLE_USER, 2000000000000)], existing=[], black=[])}),
            Case("plain spare, flag", spare=plain, flag=1)]
    return rows


def deep_cases():
    """Trees of height 2: the walks climb two levels. Kept few and last, these runs are the slowest."""
    many = [(user_id(number), 1000 + number) for number in range(50, 200)]
    used = sum(amount for _, amount in many) + 50000000000000
    users = many + [(HOLE_USER, 50000000000000), (user_id(200), 200000000000000 - used - 15000)]
    existing = [(token, 100) for token in range(100, 250)]
    return [Case("height two users", genesis={5: dict(users=users + [(user_id(201), 15000)], existing=[], black=[])}),
            Case("height two blocked set", genesis={5: dict(users=users + [(user_id(201), 15000)], existing=[], black=[user for user, _ in many] + [user_id(201)])}),
            Case("height two existing", genesis={5: dict(users=[(user_id(7), 200000000000000 - 15000 - 50000000000000), (HOLE_USER, 50000000000000)], existing=existing, black=[])}, holders={100: [(user_id(9), 100)], 249: [(user_id(9), 100)]})]


def more_cases():
    hole = (HOLE_USER, 50000000000000)
    entry = dict(users=[(user_id(7), 150000000000000), hole], existing=[], black=[])
    around = {token: dict(users=[(user_id(9), 1)], existing=[], black=[]) for token in range(6, 30)}
    far = Case("genesis in the last child of a deep map", token=30, token_count=40, rows={30: dict(sz=2, wei=8, name=b"LEMON", spots=[0])}, genesis={**around, 30: entry})
    grow = Case("holders grow the new map two levels", genesis={5: dict(users=[hole, (user_id(7), 150000000000000 - 4000)], existing=[(3, 4000)], black=[])}, holders={3: [(user_id(number), 100) for number in range(60, 100)]})
    return [far, grow]


def all_cases():
    return parse_cases() + gate_cases() + hole_cases() + balance_cases() + word_cases() + book_cases() + network_cases() + spare_cases() + more_cases() + deep_cases()


# ---- static reads ----

def read_texts(image):
    rows = []
    for key in TEXTS:
        at, size = key
        value = bytes(image.blob[image.offset(at):image.offset(at) + size])
        if value != WORDS[key]:
            raise EvidenceError("text at %#x" % at)
        rows.append({"at": "%#x" % at, "length": size, "value": value.decode("ascii")})
    return rows


def read_powers(image):
    return [struct.unpack_from("<d", image.blob, image.offset(POWERS) + index * 8)[0] for index in range(20)]


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


ACTION_TAIL = bytes.fromhex("4d8b4f184983f9650f8382000000488b4c24284d8b4710410fb6c4890424400fb6d5488d7c24204c89f6")
OUTCOME_TAIL = bytes.fromhex("c7042401000000488d7c24484c89e64c89f94d89f04d89e9")


def read_call_sites(image):
    """The two hosts of each copy: the action arm takes the flag from the action, the second passes literal 1."""
    rows = []
    for copy in COPIES:
        action, outcome = copy["sites"]
        window = bytes(image.blob[image.offset(action) - len(ACTION_TAIL):image.offset(action)])
        if window != ACTION_TAIL:
            raise EvidenceError("action site bytes at %#x" % action)
        rows.append({"copy": copy["name"], "site": "%#x" % action, "host": "%#x" % image.fde(action)[0], "flag": "byte from the action, loaded into r12b", "network": "bpl", "text_length_limit": 100})
        window = bytes(image.blob[image.offset(outcome) - len(OUTCOME_TAIL):image.offset(outcome)])
        if window != OUTCOME_TAIL:
            raise EvidenceError("second site bytes at %#x" % outcome)
        host = image.fde(outcome)[0]
        if bytes(image.blob[image.offset(host + 0xDC):image.offset(host + 0xE3)]) != bytes.fromhex("48c7c7ffffffff"):
            raise EvidenceError("digit source at %#x" % host)
        rows.append({"copy": copy["name"], "site": "%#x" % outcome, "host": "%#x" % host, "flag": "literal 1", "network": "state byte", "digit_writer_argument": "u64 max at %#x" % (host + 0xDC)})
    return rows


def read_action_arm(image):
    """Nested deploy table entry 4 reaches the arm that holds the third copy's action site."""
    table = 0x70403C
    at = image.offset(table)
    arms = [table + struct.unpack_from("<i", image.blob, at + index * 4)[0] for index in range(10)]
    if arms[4] != 0x4AD849A:
        raise EvidenceError("table entry 4: %#x" % arms[4])
    fields = bytes(image.blob[image.offset(arms[4]):image.offset(arms[4]) + 9])
    if fields != bytes.fromhex("498b5720450fb66728"):
        raise EvidenceError("arm fields")
    limit = bytes(image.blob[image.offset(0x4AD8559):image.offset(0x4AD8559) + 6])
    if limit != bytes.fromhex("66c743084301"):
        raise EvidenceError("long text status")
    return {"table": "%#x" % table, "entry": 4, "arm": "%#x" % arms[4], "token_field": "+0x20", "flag_field": "+0x28", "text_fields": "+0x10 pointer, +0x18 length", "text_at_or_above_101_bytes": "status 0x143 at 0x4ad8559", "host": "%#x" % image.fde(arms[4])[0]}


ANCHOR_STORE = bytes.fromhex("48896c3278")
ANCHOR_READ_SITE = 0x42FBABB


def read_anchor_sites(image):
    """Exact bytes of `mov [rdx+rsi+0x78], rbp` in .text, and the one load named by the mid helper."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(ANCHOR_STORE)
    while at >= 0:
        rows.append(base + at)
        at = text.find(ANCHOR_STORE, at + 1)
    if bytes(image.blob[image.offset(ANCHOR_READ_SITE):image.offset(ANCHOR_READ_SITE) + 4]) != bytes.fromhex("488b5b78"):
        raise EvidenceError("load of book +0x78")
    return {"store_pattern": ANCHOR_STORE.hex(), "stores": ["%#x" % row for row in rows], "stores_in": ["%#x" % image.fde(row)[0] for row in rows], "load": {"site": "%#x" % ANCHOR_READ_SITE, "host": "%#x" % image.fde(ANCHOR_READ_SITE)[0], "bytes": "488b5b78"}}


def read_display(image, tags):
    rows = []
    table, display = 0x59A8D0, 0x37FFD40
    at = image.offset(table)
    begin, end = image.exact_fde(display)
    for tag in tags:
        arm = table + struct.unpack_from("<i", image.blob, at + tag * 4)[0]
        if not begin <= arm < end:
            raise EvidenceError("display arm: %#x" % tag)
        window = bytes(image.blob[image.offset(arm):image.offset(arm) + 24])
        if window[:11] != bytes.fromhex("488b3e488b4608488b4018") or window[11:14] != b"\x48\x8d\x35" or window[18] != 0xBA:
            rows.append({"tag": "%#x" % tag, "arm": "%#x" % arm, "value": "not a plain text arm"})
            continue
        text_at = arm + 18 + struct.unpack_from("<i", window, 14)[0]
        size = struct.unpack_from("<I", window, 19)[0]
        rows.append({"tag": "%#x" % tag, "arm": "%#x" % arm, "value": bytes(image.blob[image.offset(text_at):image.offset(text_at) + size]).decode("ascii")})
    return rows


def body_diff(image, left, right):
    """Instruction rows of two copies that differ, with rip targets and call targets resolved."""
    a, b = decode_range(image, *image.exact_fde(left)), decode_range(image, *image.exact_fde(right))
    rows = []
    left_end, right_end = image.exact_fde(left)[1], image.exact_fde(right)[1]
    for one, two in zip(a, b):
        first = bytes(image.blob[image.offset(one.va):image.offset(one.va) + one.size])
        second = bytes(image.blob[image.offset(two.va):image.offset(two.va) + two.size])
        if one.size != two.size or one.op != two.op:
            rows.append({"left": "%#x" % one.va, "right": "%#x" % two.va, "class": "shape"})
        elif one.op in ("call", "jmp", "jcc") and one.target is not None:
            inside = left <= one.target < left_end and right <= two.target < right_end
            if (one.target - left != two.target - right) if inside else one.target != two.target:
                rows.append({"left": "%#x" % one.va, "right": "%#x" % two.va, "class": "call target", "from": "%#x" % one.target, "to": "%#x" % two.target})
        elif first != second:
            one_slot = one.rip_at is not None and one.va + one.size + struct.unpack_from("<i", first, one.rip_at)[0]
            two_slot = two.rip_at is not None and two.va + two.size + struct.unpack_from("<i", second, two.rip_at)[0]
            if one.rip_at is None or one_slot != two_slot:
                rows.append({"left": "%#x" % one.va, "right": "%#x" % two.va, "class": "field", "from": first.hex(), "to": second.hex()})
    return {"left": "%#x" % left, "right": "%#x" % right, "instructions": [len(a), len(b)], "rows": rows}


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


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    named = ((THIRD["entry"], "finish, third copy"), (FINISH, "gates and balances"), (SUM_READ, "supply sum"), (WORD_HELPER, "book word"))
    return [(start, role, decode_range(image, *image.exact_fde(start))) for start, role in named]


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    harness.copy = THIRD
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = compare_run(harness, case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

REFERENCE_CLAIMS = (
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:279", "claim": "apply_decimal_token_mutation is an abstract method with no body", "observed": "the body is 0x4d611e0 with copies 0x4d618f0 and 0x2746b40, reached from nested table 0x70403c entry 4", "verdict": "body absent from the reference"},
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:121", "claim": "nested case 4 parses a decimal string and mutates token state through a dedicated routine", "observed": "the text is a u64 from_str shape, kind byte after status 0xb7; the routine is 0x371b950 through slot 0x5774bf8", "verdict": "match"},
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:80", "claim": "field name flag: bool", "observed": "the stack byte refuses a nonzero 0xff..ff balance when set and skips the 1% gate; the second host passes literal 1", "verdict": "partial: name only"},
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:222", "claim": "user and existing token genesis balances are held as Vec rows", "observed": "0x371b950 reads B-trees in one 0x48-byte value at spot metadata +0x370: user balances, existing token amounts, a blocked user set", "verdict": "mismatch"},
    {"reference": "l1/book/book/mod.rs", "claim": "no field at +0x78 is named", "observed": "book +0x78 is written here and read at 0x42fbabb", "verdict": "absent"},
)
LANDING = "unwind landing pad or panic tail: no case unwinds"
LAZY = "lazy init of a static: the harness word is 0"
UNSPLIT = "no case in the list separates this mutant; no claim rests on this row"
UNROLL = "the eight-level step of a tree descent: trees here are at most 3 levels, so only the single-step loop runs"
FIRST_LEAF = "length of the first leaf of a walk: index 0 only needs a nonzero word, and leaf and ramp words are both nonzero"
SAME_KEY = "this lookup repeats one that has already found the key, so running out of levels never happens"
USERS_SORTED = "users arrive in key order with no repeat, so each new key lands past the last one of the new map"
DEAD_TOKEN = "the same token bound already held on this path"
ITER_BACK = "back handle of the map iterator: the walk only goes forward"
LOW_BIT_GONE = "the low bit is lost: a scale this large leaves the result saturated, overflowed or multiplied by 0"
PAST_EXPONENT = "exponents reaching this test with the changed bit set give the same panic"
WIDTH = "choice of a 32-bit or 64-bit divide: the quotient is the same"
REASON_RANGES = ((0x4D617CB, 0x4D617DB, LANDING), (0x4D6180A, 0x4D6181A, LANDING), (0x4D61841, 0x4D618E8, LANDING), (0x371BA6F, 0x371BAD9, LAZY), (0x371CB1A, 0x371CB5B, LAZY), (0x371CBBE, 0x371CC01, LANDING), (0x3C09935, 0x3C09979, LAZY),
                 (0x371BEF5, 0x371BF3E, UNROLL), (0x371BFCE, 0x371C011, UNROLL), (0x371C222, 0x371C234, UNROLL), (0x371C385, 0x371C3CE, UNROLL), (0x371C45E, 0x371C4A1, UNROLL), (0x371C717, 0x371C729, UNROLL), (0x371C855, 0x371C89E, UNROLL), (0x371C92E, 0x371C971, UNROLL),
                 (0x371C983, 0x371C98B, UNROLL), (0x371F805, 0x371F84E, UNROLL), (0x371F8DE, 0x371F921, UNROLL), (0x371F933, 0x371F93B, UNROLL), (0x371FA05, 0x371FA4E, UNROLL), (0x371FADE, 0x371FB21, UNROLL), (0x371FB33, 0x371FB3B, UNROLL))
REASONS = {0x4D61216: "a lone minus and any other non-digit both give kind 1", 0x4D61240: "16 digits cannot overflow, so both digit loops agree at this limit", 0x4D613CB: ITER_BACK, 0x371CAA7: ITER_BACK, 0x4D614EC: DEAD_TOKEN, 0x4D6171B: DEAD_TOKEN, 0x3C09834: DEAD_TOKEN,
           0x4D614D0: "no case has an empty token name", 0x371B97C: LAZY, 0x371BC0E: LAZY, 0x3C09933: LAZY, 0x371BA42: PAST_EXPONENT, 0x3C098E5: PAST_EXPONENT, 0x371BA47: LOW_BIT_GONE, 0x3C098D4: LOW_BIT_GONE, 0x3C098E9: LOW_BIT_GONE,
           0x371BBB7: "length word of a status record only the checked drop stub receives", 0x371BEE5: UNROLL, 0x371BFC8: UNROLL, 0x371C375: UNROLL, 0x371C458: UNROLL, 0x371C845: UNROLL, 0x371C928: UNROLL, 0x371F7F5: UNROLL, 0x371F8D8: UNROLL, 0x371F9F5: UNROLL, 0x371FAD8: UNROLL,
           0x371BF42: FIRST_LEAF, 0x371C3D3: FIRST_LEAF, 0x371C8A4: FIRST_LEAF, 0x371F854: FIRST_LEAF, 0x371FA54: FIRST_LEAF, 0x371C171: USERS_SORTED, 0x371C188: USERS_SORTED, 0x371C18E: USERS_SORTED, 0x371C1BE: USERS_SORTED, 0x371C212: USERS_SORTED,
           0x371F6C7: SAME_KEY, 0x371F723: SAME_KEY, 0x371CB10: "the user loop cannot carry: the sum of the same rows passed step 6", 0x3C099B4: "the zero return needs supply 0 or a product past u64 with a nonzero first quotient; the gates leave neither",
           0x3C09883: WIDTH, 0x3C09992: WIDTH}


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, UNSPLIT)


def outcome_name(spec):
    if spec["stop"]:
        return "panic %s" % spec["stop"][0]
    word = spec["status"]
    if word[0] == STATUS_TEXT:
        return "status text: %s" % word[1].decode()
    if word[0] == STATUS_PARSE:
        return "status 0xb7, kind %d" % word[1]
    if word[0] == "filled":
        return "stub status passed through"
    return "status %#x" % word[0]


def word_rows(harness):
    """Real runs at the lowest supply of each exponent: the word given to the credit stub and to the book."""
    rows = []
    harness.copy = THIRD
    for exponent in range(0, 20):
        scale = 10 ** exponent
        for label, supply in (("lowest", min(MIN_LOTS * scale, MASK[8])), ("double", min(2 * MIN_LOTS * scale, MASK[8]))):
            run = harness.run(supply_case("table", 0, exponent, supply))
            if run["status"][0] != STATUS_OK:
                raise EvidenceError("word row status: %s" % (run["status"],))
            word = next(event[4] for event in run["events"] if event[0] == "credit")
            if word != run["state"]["books"][0] or word != spec_word(supply, scale):
                raise EvidenceError("word row: %d" % exponent)
            rows.append((exponent, scale, label, supply, word))
    return rows


def worked_run(harness):
    """One finish: 2e14 wei, 2 sz and 8 wei decimals, two users, USDC spots 0 and 3, spot 1 quoted in token 3."""
    harness.copy = THIRD
    case = Case("worked")
    run = harness.run(case)
    return {"text": case.text.decode(), "events": [[value.hex() if isinstance(value, bytes) else value for value in event] for event in run["events"]], "books": {str(key): value for key, value in run["state"]["books"].items()}, "supplies": run["state"]["supplies"], "status": "%#x" % run["status"][0]}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    for case in cases:
        for copy in COPIES:
            harness.copy = copy
            trouble = compare_run(harness, case)
            if trouble:
                mismatches.append("%s %s" % (copy["name"], trouble))
        name = outcome_name(spec_run(case, COPIES[0]))
        outcomes[name] = outcomes.get(name, 0) + 1
    runs = len(cases) * len(COPIES)
    seen = set(harness.machine.seen)
    steps = harness.machine.steps
    worked = worked_run(harness)
    words = word_rows(harness)
    functions = []
    named = [(copy["entry"], "finish, %s copy" % copy["name"]) for copy in COPIES] + [(FINISH, "gates and balances"), (SUM_READ, "supply sum"), (WORD_HELPER, "book word"), (SUPPLY_INSERT, "supply map insert"), (ENTRY_INSERT, "balance map entry"), (TREE_DROP, "balance map drain"),
                                                                                       (0x494A910, "balance map next, second and third copy"), (0x2869350, "balance map next, first copy")]
    for start, role in named:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    sites = direct_sites(image, sorted({copy["entry"] for copy in COPIES}))
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    finish_slot = [slot for slot, value in harness.relative.items() if value == FINISH]
    finish_calls = [{"site": "%#x" % va, "host": "%#x" % image.fde(va)[0]} for slot in finish_slot for va in slot_sites(image, slot)]
    relative = harness.relative
    locations = []
    for slot, name in sorted(LOCATION_NAMES.items()):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    results_rows = run_mutants(image, seen, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "call_sites": read_call_sites(image),
        "action_arm": read_action_arm(image),
        "finish_slot": ["%#x" % slot for slot in finish_slot],
        "finish_calls": finish_calls,
        "anchor_sites": read_anchor_sites(image),
        "copies": [{key: ("%#x" % value if isinstance(value, int) and not isinstance(value, bool) else value) for key, value in copy.items() if key != "sites"} for copy in COPIES],
        "copy_diff_second_first": body_diff(image, COPIES[1]["entry"], COPIES[2]["entry"]),
        "powers_of_ten": read_powers(image),
        "texts": read_texts(image),
        "status_text": read_display(image, (STATUS_TEXT, STATUS_OVERFLOW, STATUS_PARSE, 0x143)),
        "locations": locations,
        "node_shapes": {"genesis_map": GENESIS_NODE, "user_balance_map": USER_NODE, "blocked_set": SET_NODE, "word_map": WORD_NODE},
        "fields": FIELDS,
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases), "runs": runs},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_words": words,
    }


FIELDS = {
    "state": {"+0x00": "dword: 1 asks for the hash stub 0x3987cb0", "+0x08, +0x28": "hash stub arguments", "+0x60": "12-byte time, copied per row", "+0x80": "first argument block of 0x371b950", "+0x90": "metadata block of the word helper", "+0x1f8/+0x200": "spot rows: pointer, length",
              "+0x210/+0x218": "token rows: pointer, length", "+0x3f0": "genesis map, +0x370 of the block", "+0x408": "supply map, +0x388 of the block"},
    "per_copy": {"network byte": "+0x1372 third, +0x8f2 others", "holders argument": "+0x1378 third, +0x8f8 others", "row list": "+0x5b8 third, +0x8f3 others", "touch set": "+0x11c0 third, +0x740 others", "book list": "+0x3e08/+0x3e10 third, +0x3388/+0x3390 others"},
    "spot_row": {"stride": "0x20", "+0x08": "quote token: the word is written only when it is 0"},
    "token_row": {"stride": "0xe8", "+0x38/+0x40": "name: pointer, length", "+0x48": "sz decimals", "+0x49": "wei decimals", "+0x58/+0x60": "spot list: pointer, length"},
    "genesis_value": {"size": "0x48", "+0x00": "user balance map (root, height, length)", "+0x18": "existing token amount map", "+0x30": "blocked user set"},
    "balance_row_0x20": {"+0x00": "20-byte user", "+0x18": "amount"},
    "book": {"stride": "0xd8", "+0x78": "word written here"},
    "result": {"+0x00": "status word", "+0x08..+0x18": "balance map moved to the caller", "+0x20": "word"},
    "ledger_row": {"size": "0xb0", "+0x00": "tag 0x8000000000000010", "+0x08..+0x18": "name String", "+0x20": "amount as f64: u64 / 10^wei"},
}


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    words = evidence.pop("_words")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\topcode\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["exponent\tscale\trow\tsupply\tword"]
    lines += ["%d\t%d\t%s\t%d\t%d" % row_ for row_ in words]
    files["word.tsv"] = "\n".join(lines) + "\n"
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
