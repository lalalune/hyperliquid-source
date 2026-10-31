#!/usr/bin/env python3
"""Pin the node #94 order placement path from ELF bytes: account mode router, book wrapper, and the host that rests a trigger or inserts.

Router `0x4ca9710` (and `0x4ca8eb0`, `0x4ca8510`, `0x4ca7cb0`) reads the user's mode byte and picks one of three routes: direct, the dex
route around one wrapper call, or the collateral route behind the bucket gate `0x37d9ef0`. Wrapper `0x4d446f0` (and `0x4d472f0`, `0x4d47ad0`,
`0x4d476e0`) finds the book, keeps the depth word, flushes rows and writes the status. Host `0x430be90` (and `0x4309700`, `0x430abf0`,
`0x4308460`) either stores a trigger order in field `u` of `user_states` under a fresh oid, or calls insert, and then writes the rows.
The real bytes run in a Python evaluator with every edge callee stubbed. A separately written specification predicts every result, and
every condition, immediate and field offset is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary
is never executed. Standard library only.
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

Place = collections.namedtuple("Place", "name start stride rows_slot insert entry leaf tree builder tick settle count_field byte_field dex_field")
PLACES = (
    Place("perp first", 0x430BE90, 0x278, 0x5773D58, 0x4311140, 0x45A3B30, 0x495A570, 0x4932C30, 0x42FE2D0, 0x42C7600, 0x4CD84F0, 0x11C0, 0x1372, 0x1040),
    Place("perp second", 0x4309700, 0x278, 0x5773D58, 0x4314DA0, 0x45A3B30, 0x495A570, 0x4932C30, 0x42FE2D0, 0x42C7600, 0x4CD84F0, 0x740, 0x8F2, 0x5C0),
    Place("spot first", 0x430ABF0, 0x268, 0x5773D50, 0x4318A00, 0x45A3980, 0x495A740, 0x493C4B0, 0x42FE970, 0x4CA6B90, 0x4470BE0, 0x740, 0x8F2, None),
    Place("spot second", 0x4308460, 0x268, 0x5773D50, 0x430D610, 0x45A3980, 0x495A740, 0x493C4B0, 0x42FE970, 0x4CA6B90, 0x4470BE0, 0x11C0, 0x1372, None),
)
Wrap = collections.namedtuple("Wrap", "name start host flush rows_field shifted")
WRAPS = (
    Wrap("first, status at +0x08", 0x4D446F0, 0x430BE90, 0x432A100, 0x3DF0, True),
    Wrap("first, status at +0x00", 0x4D472F0, 0x430BE90, 0x432A100, 0x3DF0, False),
    Wrap("second, status at +0x08", 0x4D47AD0, 0x4309700, 0x4329870, 0x3370, True),
    Wrap("second, status at +0x00", 0x4D476E0, 0x4309700, 0x4329870, 0x3370, False),
)
Route = collections.namedtuple("Route", "name start wrap row step before after flag_field names_field entry_field total_field dex_field gate")
ROUTES = (
    Route("first, bucket gate", 0x4CA9710, 0x4D446F0, 0x46F2E60, 0x46EA0B0, 0x46EFB70, 0x46EF4A0, 0x454B, 0x1038, 0x11F0, 0x1250, 0x1040, True),
    Route("first, no gate", 0x4CA8EB0, 0x4D472F0, 0x46F2E60, 0x46EA0B0, 0x46EFB70, 0x46EF4A0, 0x454B, 0x1038, 0x11F0, 0x1250, 0x1040, False),
    Route("second, bucket gate", 0x4CA8510, 0x4D47AD0, 0x46F2FE0, 0x46EAA10, 0x46EF9A0, 0x46EF720, 0x3ACB, 0x5B8, 0x770, 0x7D0, 0x5C0, True),
    Route("second, no gate", 0x4CA7CB0, 0x4D476E0, 0x46F2FE0, 0x46EAA10, 0x46EF9A0, 0x46EF720, 0x3ACB, 0x5B8, 0x770, 0x7D0, 0x5C0, False),
)
GATE = 0x37D9EF0
DROP_WORD = 0x3379490
CLONE = 0x4995950
COUNT_ENTRY = 0x379A110
COUNT_INSERT = 0x35779F0
HASH = 0x3987CB0
SPLIT = 0x42188A0
DROP_STEP = 0x4DAF4A0
DROP_AFTER = 0x472F840
ENTRY_LOOKUP = 0x47D7550

SLOT_NAMES = {0x5774740: 0x3332680, 0x5774748: GATE, 0x5774810: 0x342AA50, 0x5773D58: 0x454ECB0, 0x5773D50: 0x454F340}
SLOT_DEX_ROW = 0x5774740
SLOT_TRACKER = 0x5774810
SLOT_MEMCMP = 0x576E488
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576E468, 0x576DFB8, 0x576E020, 0x576E108)
AFTER_ARGUMENT = 0x5744688
STATUS_TABLE = 0x6F1680
TAG_TEXTS = 0x59A8D0
ERROR_TEXTS = 0x5A572C
MODE_NAMES = 0x570D358

ROW_STRIDE = 0x138
BOOK_STRIDE = 0xD8
DEX_STRIDE = 0x2F0
USER_SIZE = 20
ORDER_SIZE = 0xB8
USER_VALUE = 0x50
MAX64 = (1 << 64) - 1
NONE_WORD = 1 << 63
TAG_OK = 0x186
TAG_ERROR = 0xC4
TAG_TOO_MANY = 0x170
ERROR_TPSL = 9
MAX_TRIGGER = 1000000000000000
NEW_COUNT_DATE = 0xF6401A
WIRE_LOCAL = 0x270F
WIRE_LIMIT = 0x5F45A5F
WIRE_BASE = 100000

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
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 100000

STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0x4800
ROWS = HEAP_BASE + 0x6000
DEXES = HEAP_BASE + 0x7000
BOOKS = HEAP_BASE + 0xB000
USER_ARG = HEAP_BASE + 0xE300
OUT = HEAP_BASE + 0xE400
REQUEST = HEAP_BASE + 0xE500
GROUP = HEAP_BASE + 0xE580
EVENTS = HEAP_BASE + 0xE600
COUNTER = HEAP_BASE + 0xE700
MODE_ROW = HEAP_BASE + 0xE780
NAMES_ROW = HEAP_BASE + 0xE7C0
GATES = HEAP_BASE + 0xE840
LOCAL_ASSET = HEAP_BASE + 0xE8C0
WRAPPER_IN = HEAP_BASE + 0xE900
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

STATUS_BY_ERROR = bytes.fromhex("11121213141516161718191a1b1c1d1d1d1d1e1f20212223")
LOW_U32 = 0xFFFFFFFF


def user_id(number):
    return bytes((number * 37 + index * 11 + 3) & 0xFF for index in range(USER_SIZE))


def date_millis(date, secs, nanos):
    year = (date - (1 << 32) if date >> 31 else date) >> 13
    ordinal = (date >> 4) & 0x1FF
    before = year - 1
    days = ordinal + before * 1461 // 4 - before // 100 + (before // 100) // 4 - 719163
    return max((days * 86400 + secs) * 1000 + nanos // 1000000, 0)


def saturated(value):
    return min(value + 1, MAX64)


def order_type(kind, market):
    """Stored order type word of a trigger order: 2 take profit market, 3 take profit limit, 4 stop market, 5 stop limit."""
    return (3 + 2 * (kind & 1)) ^ (market & 1)


def limit_type(group_tag, third):
    """Order type word sent to insert: 9 twap slice, 1 market for a tif byte above 2, else 0 limit."""
    if group_tag == 3:
        return 9
    return 1 if third & 0xFF >= 3 else 0


def error_index(word):
    return word ^ NONE_WORD if word >> 63 else 2


def wire_asset(asset):
    if asset <= WIRE_LOCAL:
        return asset & LOW_U32
    if asset > WIRE_LIMIT:
        return LOW_U32
    return (asset + WIRE_BASE) & LOW_U32


def bucket_step(count, last, now, window, limit):
    """(new count, allowed): the same bucket counts on, saturating; a later bucket starts at 1."""
    fresh = date_millis(*last) // window < date_millis(*now) // window
    count = 1 if fresh else saturated(count)
    return count, count <= limit


def default_group(**changes):
    group = {"tag": 2, "payload": ramp(0x20, 0x61), "cap": 0, "ptr": 8, "len": 0, "first": 0x31, "second": 0x32, "nonce": 0x1234}
    group.update(changes)
    return group


def default_request(**changes):
    request = {"word0": 1, "word1": 700, "third": 5000, "market": 0, "kind": 0, "middle": ramp(6, 0x81), "limit": 123456, "asset": 7, "side": 0, "reduce": 0, "tag": 0, "cloid": ramp(0x10, 0x91), "tail": ramp(5, 0xA1)}
    request.update(changes)
    return request


def default_world(**changes):
    w = {"request": default_request(), "group": default_group(), "user": 5, "users": {}, "absent_root": False, "user_height": 0, "now": (0x1FA1F0, 3600, 250000000), "oid": 9000, "mode_word": 1, "hash_byte": 0x17, "hash_second": 0x2222, "hash_first": 0x3333,
         "dexes": 3, "books": 40, "rows_count": 2, "tick": 10, "insert": {"word": 0x55, "ptr": 0x7700, "len": 2, "root": 0, "height": 3, "items": 0, "oid": 4242}, "count": 6, "count_new": False, "rows_cap": 8, "rows_len": 0, "depth": 3}
    w.update(changes)
    return w


def order_group_words(group):
    return [group["tag"], group["payload"].hex() if group["tag"] < 2 else "", group["cap"], group["ptr"], group["len"]]


def record_log(w, copy, oid, tag, group):
    request = w["request"]
    now = w["now"]
    if tag == 1:
        payload = group["payload"].hex()
    else:
        payload = ""
    if tag < 2 and group["tag"] < 2:
        triple = [group["cap"], group["ptr"], group["len"]]
    else:
        triple = [0, 8, 0]
    return ["build", request["word0"], request["word1"], request["third"], request["market"], request["kind"], request["middle"].hex(), request["limit"], request["asset"], request["side"], request["reduce"], request["tag"], request["cloid"].hex(), request["tail"].hex(),
            tag, payload] + triple + [dex_label(w, copy), oid, list(now), user_id(w["user"]).hex()]


def dex_label(w, copy):
    return book_asset(w) // 10000 if copy.dex_field is not None else "spot"


def book_asset(w):
    return w.get("book_asset", w["request"]["asset"])


def row_log(w, kind, tag, group, which, hash_bytes, status):
    return ["row", 3, kind, group["payload"].hex() if kind == 1 else "", which, list(w["now"]), user_id(w["user"]).hex(), 1 if hash_bytes is not None else 0, hash_bytes.hex() if hash_bytes else "", status]


def spec_place(case):
    copy = PLACES[case.copy]
    w = case.world
    request, group = w["request"], w["group"]
    log = []
    answer = {"log": log}
    state_oid = w["oid"]
    records = 0
    third = request["third"]
    is_limit = request["kind"] == 2
    asset = book_asset(w)
    dex = asset // 10000
    flag = request["tag"] & 1
    stored_tag = group["tag"] if group["tag"] < 2 else 0
    rows_len = w["rows_len"]
    result = None

    def panic():
        return {"panic": True, "log": log}

    if is_limit:
        log.append(["insert", request["word0"], request["word1"], stored_tag, group["payload"].hex() if stored_tag == 1 else "", limit_type(group["tag"], third), read_word(group["payload"], 0),
                    request["limit"], date_millis(*w["now"]), request["reduce"], flag, request["cloid"].hex() if flag else "", request["side"], user_id(w["user"]).hex(), third & 0xFF, group["first"] if group["tag"] < 2 else 0, group["second"]])
        insert = w["insert"]
        if insert.get("error") is not None:
            result = {"error": insert["error"], "from_insert": True}
        else:
            result = {"word": insert["word"], "ptr": insert["ptr"], "len": insert["len"], "root": insert["root"], "height": insert["height"], "items": insert["items"], "oid": insert["oid"], "tail": ramp(0x18, 0x6B).hex()}
    else:
        if copy.dex_field is not None and dex >= w["dexes"]:
            return panic()
        if third > MAX_TRIGGER:
            result = {"error": NONE_WORD | ERROR_TPSL, "from_insert": False}
        else:
            log.append(["tick", dex_label(w, copy), asset, third])
            if third % w["tick"]:
                result = {"error": NONE_WORD | ERROR_TPSL, "from_insert": False}
            else:
                oid = state_oid
                state_oid = saturated(state_oid)
                key = w["user"]
                known = key in w["users"]
                if not known:
                    log.append(["entry new", user_id(key).hex()])
                value = ["value", request["word0"], request["word1"], stored_tag, group["payload"].hex() if stored_tag == 1 else "", order_type(request["kind"], request["market"]), request["limit"], date_millis(*w["now"]), request["reduce"], flag, request["cloid"].hex() if flag else "", request["side"], third, (request["kind"] << 8) | request["market"]]
                held = w["users"].get(key)
                if held is not None and held["root"] and oid not in held["oids"]:
                    log.append(["split", oid] + value[1:])
                if flag:
                    log.append(["tracker", user_id(key).hex(), oid, request["cloid"].hex()])
                log.append(["count", user_id(key).hex()])
                if w["count_new"]:
                    log.append(["count new", 0x1110, 0x2220, 0x3330, ramp(12, 0x45).hex(), NEW_COUNT_DATE])
                    answer["count"] = 1
                else:
                    answer["count"] = saturated(w["count"])
                result = {"word": 0, "ptr": 8, "len": 0, "root": 0, "items": 0, "oid": oid, "flag": flag, "cloid": request["cloid"].hex() if flag else "", "resting": 1}
                count = len(held["oids"]) if held is not None and held["root"] else 0
                if held is None or not held["root"]:
                    answer["tree"] = [[oid] + value[1:]]
                    answer["length"] = 1
                elif oid in held["oids"]:
                    answer["tree"] = [[oid] + value[1:]]
                    answer["replaced"] = True
                    answer["length"] = count
                else:
                    answer["length"] = count + 1

    error = result.get("error")
    if error is not None:
        answer["word"] = NONE_WORD
        answer["error"] = error
        if result["from_insert"]:
            answer["body"] = ramp(0x40, 0x77).hex()
        answer_tag = group["tag"]
        if answer_tag >= 3:
            answer.update(oid_after=state_oid, rows_len=rows_len)
            return answer
        if copy.dex_field is not None and dex >= w["dexes"]:
            return panic()
        oid = state_oid
        state_oid = saturated(state_oid)
        records += 1
        log.append(record_log(w, copy, oid, stored_tag, group))
        status = STATUS_BY_ERROR[error_index(error)]
        log.append(row_log(w, stored_tag, stored_tag, group, records, None, status))
        log.append(row_log(w, 4, stored_tag, group, records, None, status))
        answer.update(oid_after=state_oid, rows_len=rows_len + 2)
        return answer

    tag = group["tag"]
    if tag >= 3:
        hash_bytes = None
    else:
        hash_bytes = bytes(0x20)
        if w["mode_word"] == 1:
            log.append(["hash", w["hash_byte"], w["hash_second"], w["hash_first"], group["nonce"] if tag < 2 else 0])
            hash_bytes = ramp(0x20, 0xC1)
    if copy.dex_field is not None and dex >= w["dexes"]:
        return panic()
    log.append(["settle", dex_label(w, copy), result["ptr"], result["len"], 0 if tag >= 3 else 1, hash_bytes.hex() if hash_bytes else "", 1 if tag >= 2 else 0])
    if tag >= 3:
        answer["word"] = result["word"]
        answer["result"] = result
        answer.update(oid_after=state_oid, rows_len=rows_len)
        return answer
    records += 1
    log.append(record_log(w, copy, result["oid"], stored_tag, group))
    log.append(row_log(w, stored_tag, stored_tag, group, records, hash_bytes, 0))
    log.append(row_log(w, 4, stored_tag, group, records, hash_bytes, 0))
    if result["items"]:
        if not result["root"]:
            return panic()
        log.append(["clone", result["root"], result.get("height")])
        log.append(["row", 0xA, 0xC1000, 0xC2000, 0xC3, request["asset"]])
    else:
        log.append(["row", 0xA, 0, "", 0, request["asset"]])
    answer["word"] = result["word"]
    answer["result"] = result
    answer.update(oid_after=state_oid, rows_len=rows_len + 3)
    return answer


def read_word(data, at):
    return int.from_bytes(data[at:at + 8], "little")


def spec_wrap(case):
    copy = WRAPS[case.copy]
    w = case.world
    asset = w["request"]["asset"]
    dex = asset // 10000
    depth = saturated(w["depth"])
    log = []
    if dex >= w["rows_count"]:
        return {"panic": "unwrap", "depth": depth, "log": log}
    local = asset % 10000
    if local >= w["books"]:
        return {"panic": "bounds", "depth": depth, "log": log}
    outcome = w["host"]
    log.append(["host", local, w["request"]["word1"], w["group"]["nonce"], user_id(w["user"]).hex()])
    log.append(["flush", dex, outcome.get("rows", 0)])
    answer = {"depth": max(depth - 1, 0), "log": log}
    if outcome["word"] == NONE_WORD:
        answer.update(tag=TAG_ERROR, extra=wire_asset(asset), first=outcome["error"], rest=ramp(0x48, 0x55)[8:0x18].hex())
    else:
        answer.update(tag=TAG_OK, first=outcome["word"], rest=ramp(0x48, 0x55).hex())
    return answer


def group_words(group):
    return [group["tag"], group["payload"].hex(), group["cap"], group["ptr"], group["len"], group["first"], group["second"], group["nonce"]]


def route_of(mode, low, high, dex_flag, asset):
    """direct, dex or collateral, from the mode byte and the flags."""
    if mode >= 4:
        return "direct" if low & 1 else "collateral"
    if high & 1 or mode < 2:
        return "direct"
    if mode == 3:
        return "collateral"
    return "dex" if dex_flag and asset >= 10000 else "direct"


def spec_route(case):
    copy = ROUTES[case.copy]
    w = case.world
    mode = w["mode"]
    asset = w["request"]["asset"]
    dex = asset // 10000
    log = [["mode row", user_id(w["user"]).hex()]]
    answer = {"log": log, "total": w["total"]}
    wrapper = ["wrap", w["request"]["word1"], asset, user_id(w["user"]).hex()] + group_words(w["group"])
    route = route_of(mode, w["flag_low"], w["flag_high"], w["dex_flag"], asset)
    if route == "direct":
        log.append(wrapper)
        answer["out"] = "wrapper"
        return answer
    user_text = user_id(w["user"]).hex()
    if route == "dex":
        log.append(["names", dex])
        log.append(["step", user_text, w["names"], int(w["names"] == 0), 0, 1, dex, 0])
        if w["before"] != TAG_OK:
            log.append(["drop step", w["before"]])
        log.append(wrapper)
        if w.get("dex_flag_after", w["dex_flag"]):
            log.append(["names", dex])
            log.append(["step", user_text, w["names"], 1, dex, int(w["names"] == 0), 0, 0])
            if w["after"] != TAG_OK:
                log.append(["drop step", w["after"]])
        answer["out"] = "wrapper"
        return answer
    count_one, count_two = w["bucket_one"], w["bucket_two"]
    now = w["now"]
    log.append(["entry", user_text])
    if copy.gate:
        count_one, first = bucket_step(count_one, w["last_one"], now, w["window_one"], w["limit_one"])
        count_two, second = bucket_step(count_two, w["last_two"], now, w["window_two"], w["limit_two"])
        answer["bucket"] = [count_one, count_two, list(now)]
        if not first and not second:
            answer["out"] = "too many"
            if w["group"]["tag"] < 2 and w["group"]["cap"]:
                answer["freed"] = [w["group"]["ptr"], w["group"]["cap"] * 0x48]
            answer["ops"] = w["ops"]
            return answer
    answer["ops"] = saturated(w["ops"])
    answer["total"] = saturated(w["total"])
    if dex >= w["dexes"]:
        answer["panic"] = True
        return answer
    log.append(["before", user_text, w["dex_word"], dex, 2, int(mode == 4)])
    log.append(wrapper)
    if mode == 4:
        log.append(["after", user_text, w["dex_word"], dex])
    else:
        log.append(["step", user_text, w["dex_word"], 1, dex, 0, None, 0])
        if w["after"] != TAG_OK:
            log.append(["drop after", w["after"]])
    answer["out"] = "wrapper"
    return answer


def spec_gate(case):
    w = case.world
    count, allowed = bucket_step(w["count"], w["last"], w["now"], w["window"], w["limit"])
    return {"count": count, "time": list(w["now"]), "allowed": allowed}


def run_spec(case):
    return {"place": spec_place, "wrap": spec_wrap, "route": spec_route, "gate": spec_gate}[case.kind](case)


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
USER_SHAPE = Shape(0x370, 0x378, USER_SIZE, 0, USER_VALUE, 0x454, 0x456, 0x458)
ORDER_SHAPE = Shape(0x0, 0x8, 8, 0x60, ORDER_SIZE, 0x848, 0x84A, 0x850)
FANOUT = 12
OLD_VECTOR_CAP = 3

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
        table = {SLOT_DEX_ROW: self.on_names, SLOT_TRACKER: self.on_tracker, 0x5773D58: self.on_rows, 0x5773D50: self.on_rows, SLOT_MEMCMP: self.on_memcmp,
                 SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, 0x576E470: self.on_bounds, 0x576E048: self.on_unwrap}
        for slot in SLOT_PANIC:
            table.setdefault(slot, self.on_other_panic)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        calls = {DROP_WORD: self.on_nothing, CLONE: self.on_clone, COUNT_ENTRY: self.on_count, COUNT_INSERT: self.on_count_insert, HASH: self.on_hash, SPLIT: self.on_split,
                 DROP_STEP: self.on_drop_step, DROP_AFTER: self.on_drop_after, ENTRY_LOOKUP: self.on_entry}
        for copy in PLACES:
            calls.update({copy.insert: self.on_insert, copy.leaf: self.on_leaf, copy.builder: self.on_build, copy.tick: self.on_tick, copy.settle: self.on_settle})
        for copy in WRAPS:
            calls.update({copy.host: self.on_host, copy.flush: self.on_flush})
        for copy in ROUTES:
            calls.update({copy.row: self.on_mode_row, copy.step: self.on_step, copy.before: self.on_before, copy.after: self.on_after, copy.wrap: self.on_wrap})
        self.all_calls = calls
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.keep = set()
        self.records = 0
        self.row_buffer = 8
        self.stride = 0x278
        self.freed = None
        self.value_at = 0
        self.kind = ""
        self.book = BOOKS

    def exposed(self, target):
        """Stubs for a run: the host under test must run real, the others stay stubbed."""
        machine = self.machine
        calls = dict(self.all_calls)
        calls.pop(target, None)
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)

    # ---- stubs ----

    def on_nothing(self, m):
        if m.memory.read(m.regs[RDI], 2) != 0x141:
            raise Halt("drop word")

    def on_bounds(self, m):
        raise Panicked("bounds")

    def on_unwrap(self, m):
        if m.regs[RSI] != 0x2B or m.memory.read(m.regs[RDX], 2) != 0x141:
            raise Halt("unwrap arguments")
        raise Panicked("unwrap")

    def on_other_panic(self, m):
        raise Panicked("other")

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
        if m.regs[RDI] != ORDER_SHAPE.edges:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(m.regs[RDI])

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.kind == "route":
            if self.freed is not None:
                raise Halt("second free")
            self.freed = [at, size]
            return
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x4000:
            raise Halt("copy size")
        if regs[RDX] == self.stride and self.kind == "place":
            self.note_row(m.memory, regs[RSI])
            index, rest = divmod(regs[RDI] - self.row_buffer, self.stride)
            if rest or index != m.memory.read(EVENTS + 0x10, 8) or index >= m.memory.read(EVENTS, 8):
                raise Halt("row address")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def note_row(self, memory, at):
        first, second = memory.read(at, 8), memory.read(at + 8, 8)
        if first == 0xA:
            self.log.append(["row", 0xA, second, memory.read(at + 0x10, 8) if second else "", memory.read(at + 0x18, 8), memory.read(at + 0x20, 8)])
            return
        record = memory.bytes_at(at + 0x30, 0xA8)
        which = next((number for number in (1, 2, 3) if record == ramp(0xA8, 0x70 + number)), 0)
        flag = memory.read(at + 0xF8, 1)
        self.log.append(["row", first, second, memory.bytes_at(at + 0x10, 0x20).hex() if second == 1 else "", which, [memory.read(at + 0xD8, 4), memory.read(at + 0xDC, 4), memory.read(at + 0xE0, 4)],
                         memory.bytes_at(at + 0xE4, USER_SIZE).hex(), flag, memory.bytes_at(at + 0xF9, 0x20).hex() if flag else "", memory.read(at + 0x119, 1)])

    def on_rows(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if capacity > 0x100 or memory.read(vector + 0x10, 8) != capacity:
            raise Halt("vector size")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * self.stride)
        if capacity:
            memory.copy(fresh, old, capacity * self.stride)
            if self.live.pop(old, None) != capacity * self.stride:
                raise Halt("vector buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)
        self.row_buffer = fresh

    def label_of(self, value):
        if value == STATE + 0x90:
            return "spot"
        at, rest = divmod(value - DEXES, DEX_STRIDE)
        if rest or at < 0:
            raise Halt("dex row address")
        return at

    def on_tick(self, m):
        regs = m.regs
        self.log.append(["tick", self.label_of(regs[RDI]), regs[RSI], regs[RDX]])
        regs[RAX] = self.w["tick"]

    def on_build(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RSI] != BOOKS:
            raise Halt("builder book")
        self.records += 1
        at = regs[RDX]
        tag = memory.read(at + 0x48, 8)
        self.log.append(["build", memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 0x10, 8), memory.read(at + 0x18, 1), memory.read(at + 0x19, 1), memory.bytes_at(at + 0x1A, 6).hex(), memory.read(at + 0x20, 8), memory.read(at + 0x28, 8),
                         memory.read(at + 0x30, 1), memory.read(at + 0x31, 1), memory.read(at + 0x32, 1), memory.bytes_at(at + 0x33, 0x10).hex(), memory.bytes_at(at + 0x43, 5).hex(), tag, memory.bytes_at(at + 0x50, 0x20).hex() if tag == 1 else "",
                         memory.read(at + 0x70, 8), memory.read(at + 0x78, 8), memory.read(at + 0x80, 8), self.label_of(memory.read(at + 0x88, 8)), memory.read(at + 0x90, 8),
                         [memory.read(at + 0x98, 4), memory.read(at + 0x9C, 4), memory.read(at + 0xA0, 4)], memory.bytes_at(at + 0xA4, USER_SIZE).hex()])
        memory.put_bytes(regs[RDI], ramp(0xA8, 0x70 + self.records))

    def on_insert(self, m):
        regs = m.regs
        memory = m.memory
        w = self.w
        if regs[RSI] != BOOKS or regs[R9] != STATE or memory.read(regs[RSP] + 8, 8) != EVENTS:
            raise Halt("insert arguments")
        at = regs[RDX]
        if memory.read(at + 0x10, 8) or memory.read(at + 0x20, 8) or memory.read(at + 0x30, 8) or memory.read(at + 0x38, 8) != 8 or memory.read(at + 0x40, 8) or memory.read(at + 0xA8, 8):
            raise Halt("insert zero fields")
        tag = memory.read(at + 0x48, 8)
        flag = memory.read(at + 0x91, 1)
        self.log.append(["insert", memory.read(at, 8), memory.read(at + 8, 8), tag, memory.bytes_at(at + 0x50, 0x20).hex() if tag == 1 else "", memory.read(at + 0x70, 8), memory.read(at + 0x78, 8), memory.read(at + 0x80, 8), memory.read(at + 0x88, 8),
                         memory.read(at + 0x90, 1), flag, memory.bytes_at(at + 0x92, 0x10).hex() if flag else "", memory.read(at + 0xA2, 1), memory.bytes_at(at + 0xB8, USER_SIZE).hex(), memory.read(at + 0xCC, 1), regs[RCX] & MASK[4], regs[R8] & MASK[4]])
        out = regs[RDI]
        outcome = w["insert"]
        if outcome.get("error") is not None:
            memory.write(out, 8, NONE_WORD)
            memory.write(out + 8, 8, outcome["error"])
            memory.put_bytes(out + 0x10, ramp(0x40, 0x77))
            return
        for index, key in enumerate(("word", "ptr", "len", "root", "height", "items", "oid")):
            memory.write(out + index * 8, 8, outcome[key])
        memory.put_bytes(out + 0x38, ramp(0x18, 0x6B))

    def on_leaf(self, m):
        regs = m.regs
        memory = m.memory
        out, handle, value = regs[RDI], regs[RSI], regs[RDX]
        key = memory.bytes_at(handle + 0x20, USER_SIZE)
        if memory.read(handle, 8) != BOOKS + 0xB8 or key != user_id(self.w["user"]) or memory.read(handle + 0x10, 8):
            raise Halt("user slot")
        if memory.read(value, 8) or memory.read(value + 8, 8) != 8 or memory.read(value + 0x10, 8) or memory.read(value + 0x20, 8) or memory.read(value + 0x30, 8) or memory.read(value + 0x38, 8) or memory.read(value + 0x48, 8):
            raise Halt("new user value")
        self.log.append(["entry new", key.hex()])
        leaf = self.allocate(3 * USER_VALUE)
        self.keep.add(leaf)
        memory.put_bytes(leaf + 2 * USER_VALUE, memory.bytes_at(value, USER_VALUE))
        self.value_at = leaf + 2 * USER_VALUE
        memory.write(out, 8, leaf)
        memory.write(out + 0x10, 8, 2)

    def on_split(self, m):
        regs = m.regs
        memory = m.memory
        node, index = memory.read(regs[RSI], 8), memory.read(regs[RSI] + 0x10, 8)
        count = memory.read(node + 0x84A, 2)
        key = regs[RDX]
        if key != self.w["oid"] or memory.read(regs[RSI] + 8, 8) or index > count or (index and memory.read(node + index * 8, 8) >= key) or (index < count and memory.read(node + 8 + index * 8, 8) <= key):
            raise Halt("split key")
        self.log.append(["split"] + [regs[RDX]] + self.value_words(regs[RCX])[1:])

    def value_words(self, at):
        memory = self.machine.memory
        tag = memory.read(at + 0x48, 8)
        flag = memory.read(at + 0x91, 1)
        if memory.read(at + 0x10, 8) or memory.read(at + 0x20, 8) or memory.read(at + 0x30, 8) or memory.read(at + 0x38, 8) != 8 or memory.read(at + 0x40, 8):
            raise Halt("value zero fields")
        return ["value", memory.read(at, 8), memory.read(at + 8, 8), tag, memory.bytes_at(at + 0x50, 0x20).hex() if tag == 1 else "", memory.read(at + 0x70, 8), memory.read(at + 0x80, 8), memory.read(at + 0x88, 8), memory.read(at + 0x90, 1), flag,
                memory.bytes_at(at + 0x92, 0x10).hex() if flag else "", memory.read(at + 0xA2, 1), memory.read(at + 0xA8, 8), memory.read(at + 0xB0, 8)]

    def on_tracker(self, m):
        regs = m.regs
        if regs[RDI] != BOOKS + 0x48:
            raise Halt("tracker field")
        self.log.append(["tracker", m.memory.bytes_at(regs[RSI], USER_SIZE).hex(), regs[RDX], m.memory.bytes_at(regs[RCX], 0x10).hex()])

    def on_count(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RSI] != STATE + self.copy.count_field:
            raise Halt("count field")
        self.log.append(["count", memory.bytes_at(regs[RDX], USER_SIZE).hex()])
        out = regs[RDI]
        if self.w["count_new"]:
            memory.write(out, 8, 0x1110)
            memory.write(out + 8, 8, 0x2220)
            memory.write(out + 0x10, 8, 0x3330)
            memory.put_bytes(out + 0x18, ramp(0x10, 0x45))
        else:
            memory.write(out, 8, 0)
            memory.write(out + 8, 8, COUNTER + 0x20)

    def on_count_insert(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RDX]
        if any(memory.read(at + 0x18 + index * 8, 8) for index in range(6)) or memory.read(at + 0x4C, 8) or memory.read(at + 0x54, 2):
            raise Halt("count value")
        self.log.append(["count new", regs[RDI], regs[RSI], memory.read(at, 8), memory.bytes_at(at + 8, 12).hex(), memory.read(at + 0x48, 4)])
        regs[RAX] = COUNTER + 0x20
        memory.write(COUNTER, 8, 0)

    def on_hash(self, m):
        regs = m.regs
        self.log.append(["hash", regs[RSI] & 0xFF, regs[RDX], regs[RCX], regs[R8]])
        m.memory.put_bytes(regs[RDI], ramp(0x20, 0xC1))

    def on_settle(self, m):
        regs = m.regs
        memory = m.memory
        if memory.read(regs[RSP] + 8, 8) != EVENTS or regs[R9] & 0xFF:
            raise Halt("settle arguments")
        flag = memory.read(regs[RCX], 1)
        label = "spot" if self.copy.dex_field is None else self.label_of(regs[RDI])
        if self.copy.dex_field is None and regs[RDI] != STATE + 0x80:
            raise Halt("settle field")
        self.log.append(["settle", label, regs[RSI], regs[RDX], flag, memory.bytes_at(regs[RCX] + 1, 0x20).hex() if flag else "", regs[R8] & 0xFF])

    def on_clone(self, m):
        regs = m.regs
        memory = m.memory
        self.log.append(["clone", regs[RSI], regs[RDX]])
        memory.write(regs[RDI], 8, 0xC1000)
        memory.write(regs[RDI] + 8, 8, 0xC2000)
        memory.write(regs[RDI] + 0x10, 8, 0xC3)

    # ---- wrapper stubs ----

    def on_host(self, m):
        regs = m.regs
        memory = m.memory
        w = self.w
        rows = memory.read(regs[RSP] + 8, 8)
        if (memory.read(rows, 8), memory.read(rows + 8, 8), memory.read(rows + 0x10, 8)) != (0, 8, 0) or regs[R9] != STATE:
            raise Halt("host arguments")
        if memory.bytes_at(regs[RDX], 0x48) != memory.bytes_at(WRAPPER_IN, 0x48) or memory.bytes_at(regs[R8], 0x50) != memory.bytes_at(WRAPPER_IN + 0x48, 0x50):
            raise Halt("host copies")
        outcome = w["host"]
        book, rest = divmod(regs[RSI] - BOOKS, BOOK_STRIDE)
        if rest:
            raise Halt("book stride")
        self.log.append(["host", book, memory.read(regs[RDX] + 8, 8), memory.read(regs[R8] + 0x48, 8), memory.bytes_at(regs[RCX], USER_SIZE).hex()])
        out = regs[RDI]
        memory.put_bytes(out + 8, ramp(0x48, 0x55))
        memory.write(out, 8, outcome["word"])
        if outcome["word"] == NONE_WORD:
            memory.write(out + 8, 8, outcome["error"])
        memory.write(rows, 8, outcome.get("rows", 0) + 1)
        memory.write(rows + 8, 8, 0x4000)
        memory.write(rows + 0x10, 8, outcome.get("rows", 0))

    def on_flush(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDX] != STATE or memory.read(regs[RDI] + 8, 8) != 0x4000 or memory.read(regs[RDI], 8) != memory.read(regs[RDI] + 0x10, 8) + 1:
            raise Halt("flush arguments")
        self.log.append(["flush", regs[RSI], memory.read(regs[RDI] + 0x10, 8)])

    # ---- router stubs ----

    def on_mode_row(self, m):
        regs = m.regs
        if regs[RDI] != STATE:
            raise Halt("mode row state")
        self.log.append(["mode row", m.memory.bytes_at(regs[RSI], USER_SIZE).hex()])
        regs[RAX] = MODE_ROW

    def on_names(self, m):
        regs = m.regs
        if regs[RDI] != STATE + self.copy.names_field:
            raise Halt("names field")
        self.log.append(["names", regs[RSI]])
        regs[RAX] = NAMES_ROW

    def on_step(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RSI] != STATE:
            raise Halt("step state")
        at = regs[RSP] + 8
        first = self.step_results.pop(0)
        self.log.append(["step", memory.bytes_at(regs[RDX], USER_SIZE).hex(), regs[RCX], regs[R8] & MASK[4], regs[R9], memory.read(at, 8), memory.read(at + 8, 8) if self.w["mode"] == 2 else None, memory.read(at + 0x10, 8)])
        memory.put_bytes(regs[RDI], ramp(0x60, 0x2D))
        memory.write(regs[RDI], 2, first)

    def on_drop_step(self, m):
        self.log.append(["drop step", m.memory.read(m.regs[RDI], 2)])

    def on_drop_after(self, m):
        self.log.append(["drop after", m.memory.read(m.regs[RDI], 2)])

    def on_entry(self, m):
        regs = m.regs
        if regs[RDI] != STATE + self.copy.entry_field:
            raise Halt("entry field")
        self.log.append(["entry", m.memory.bytes_at(regs[RSI], USER_SIZE).hex()])
        regs[RAX] = GATES

    def on_before(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDI] != STATE or regs[RCX] & MASK[4] != 1:
            raise Halt("before arguments")
        self.log.append(["before", memory.bytes_at(regs[RSI], USER_SIZE).hex(), regs[RDX], regs[R8], memory.read(regs[R9], 8), memory.read(regs[RSP] + 8, 4)])

    def on_after(self, m):
        regs = m.regs
        if regs[RDI] != STATE or regs[RCX] & MASK[4] != 1 or regs[R9] != AFTER_ARGUMENT:
            raise Halt("after arguments")
        self.log.append(["after", m.memory.bytes_at(regs[RSI], USER_SIZE).hex(), regs[RDX], regs[R8]])

    def on_wrap(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RSI]
        if regs[RDX] != STATE:
            raise Halt("wrap arguments")
        if memory.bytes_at(at, 0x48) != memory.bytes_at(REQUEST, 0x48) or memory.read(at + 0xA0, 8) != USER_ARG:
            raise Halt("wrap request")
        group = at + 0x48
        self.log.append(["wrap", memory.read(at + 8, 8), memory.read(memory.read(at + 0x98, 8), 8), memory.bytes_at(memory.read(at + 0xA0, 8), USER_SIZE).hex(), memory.read(group, 8), memory.bytes_at(group + 8, 0x20).hex(), memory.read(group + 0x28, 8),
                         memory.read(group + 0x30, 8), memory.read(group + 0x38, 8), memory.read(group + 0x40, 4), memory.read(group + 0x44, 4), memory.read(group + 0x48, 8)])
        memory.put_bytes(regs[RDI], ramp(0x68, 0x39))
        if "dex_flag_after" in self.w:
            memory.write(STATE + self.copy.flag_field, 1, self.w["dex_flag_after"])

    # ---- worlds ----

    def place(self, shape, rows, parent, index, height, fill, filler=None):
        """A tree of uniform depth; rows are (key bytes, value argument) in key order."""
        memory = self.machine.memory
        own, kids = list(rows), []
        if height:
            fan = 3
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
        memory.put_bytes(at, ramp(ORDER_SIZE, 0x31))
        memory.write(at, 4, 0)
        pointer = self.allocate(OLD_VECTOR_CAP * 8)
        self.old_vectors[int.from_bytes(key, "little")] = pointer
        self.keep.add(pointer)
        memory.write(at + 0x30, 8, OLD_VECTOR_CAP)
        memory.write(at + 0x38, 8, pointer)

    def fill_user(self, at, key, entry):
        memory = self.machine.memory
        memory.put_bytes(at, ramp(USER_VALUE, 0x51))
        if key == user_id(self.w["user"]):
            self.value_at = at
        if not entry["root"]:
            memory.write(at + 0x38, 8, 0)
            memory.write(at + 0x40, 8, 0x99)
            memory.write(at + 0x48, 8, 0)
            return
        rows = [(oid.to_bytes(8, "little"), None) for oid in sorted(entry["oids"])]
        node = self.place(ORDER_SHAPE, rows, 0, 0xFFFF, entry.get("height", 0), self.fill_order, self.w["oid"].to_bytes(8, "little"))
        memory.write(at + 0x38, 8, node)
        memory.write(at + 0x40, 8, entry.get("height", 0))
        memory.write(at + 0x48, 8, len(rows))

    def write_request(self, at, request):
        memory = self.machine.memory
        memory.put_bytes(at, ramp(0x48, 0x19))
        memory.write(at, 8, request["word0"])
        memory.write(at + 8, 8, request["word1"])
        memory.write(at + 0x10, 8, request["third"])
        memory.write(at + 0x18, 1, request["market"])
        memory.write(at + 0x19, 1, request["kind"])
        memory.put_bytes(at + 0x1A, request["middle"])
        memory.write(at + 0x20, 8, request["limit"])
        memory.write(at + 0x28, 8, request["asset"])
        memory.write(at + 0x30, 1, request["side"])
        memory.write(at + 0x31, 1, request["reduce"])
        memory.write(at + 0x32, 1, request["tag"])
        memory.put_bytes(at + 0x33, request["cloid"])
        memory.put_bytes(at + 0x43, request["tail"])

    def write_group(self, at, group):
        memory = self.machine.memory
        memory.write(at, 8, group["tag"])
        memory.put_bytes(at + 8, group["payload"])
        memory.write(at + 0x28, 8, group["cap"])
        memory.write(at + 0x30, 8, group["ptr"])
        memory.write(at + 0x38, 8, group["len"])
        memory.write(at + 0x40, 4, group["first"])
        memory.write(at + 0x44, 4, group["second"])
        memory.write(at + 0x48, 8, group["nonce"])

    def common(self, w):
        memory = self.machine.memory
        memory.put_bytes(STATE, ramp(STATE_SIZE, 0x11))
        memory.write(STATE + 0x60, 4, w["now"][0])
        memory.write(STATE + 0x64, 4, w["now"][1])
        memory.write(STATE + 0x68, 4, w["now"][2])
        memory.put_bytes(USER_ARG, user_id(w["user"]))
        self.write_request(REQUEST, w["request"])
        self.write_group(GROUP, w["group"])

    def run_place(self, case, w):
        copy = PLACES[case.copy]
        memory = self.machine.memory
        machine = self.machine
        self.copy = copy
        self.stride = copy.stride
        self.exposed(copy.start)
        self.common(w)
        memory.write(STATE, 4, w["mode_word"])
        memory.write(STATE + 8, 8, w["hash_first"])
        memory.write(STATE + 0x28, 8, w["hash_second"])
        memory.write(STATE + 0x38, 8, w["oid"])
        memory.write(STATE + copy.byte_field, 1, w["hash_byte"])
        if copy.dex_field is not None:
            memory.write(STATE + copy.dex_field, 8, DEXES)
            memory.write(STATE + copy.dex_field + 8, 8, w["dexes"])
        memory.put_bytes(BOOKS, ramp(BOOK_STRIDE, 0x2F))
        memory.write(BOOKS + 0xB0, 8, book_asset(w))
        self.keep = set()
        self.old_vectors = {}
        self.value_at = 0
        if w["absent_root"]:
            memory.write(BOOKS + 0xB8, 8, 0)
            memory.write(BOOKS + 0xC0, 8, 0x77)
            memory.write(BOOKS + 0xC8, 8, 0)
        else:
            numbers = sorted(w["users"], key=user_id)
            rows = [(user_id(number), w["users"][number]) for number in numbers]
            spare = ramp(USER_SIZE, 0xE1)
            if not rows:
                rows = [(spare, {"root": False})]
            root = self.place(USER_SHAPE, rows, 0, 0xFFFF, w["user_height"], self.fill_user, user_id(w["user"]))
            memory.write(BOOKS + 0xB8, 8, root)
            memory.write(BOOKS + 0xC0, 8, w["user_height"])
            memory.write(BOOKS + 0xC8, 8, len(rows))
        memory.put_bytes(COUNTER, ramp(0x40, 0x23))
        memory.write(COUNTER, 8, w["count"])
        memory.write(EVENTS, 8, w["rows_cap"])
        self.row_buffer = self.allocate(w["rows_cap"] * copy.stride) if w["rows_cap"] else 8
        memory.write(EVENTS + 8, 8, self.row_buffer)
        memory.write(EVENTS + 0x10, 8, w["rows_len"])
        memory.write(STACK_TOP - 0x100, 8, EVENTS)
        try:
            machine.run(copy.start, {RDI: OUT, RSI: BOOKS, RDX: REQUEST, RCX: USER_ARG, R8: GROUP, R9: STATE})
        except Panicked:
            return {"panic": True, "log": self.log}
        return self.read_place(w)

    def read_tree(self):
        memory = self.machine.memory
        rows = []
        pending = [(memory.read(self.value_at + 0x38, 8), memory.read(self.value_at + 0x40, 8))]
        while pending and len(rows) < 2:
            node, height = pending.pop()
            count = memory.read(node + 0x84A, 2)
            if count > 11 or height > 3 or memory.read(self.value_at + 0x38, 8) == node and memory.read(node, 8):
                raise Halt("tree shape")
            if node not in self.keep and count != 1:
                raise Halt("new leaf length")
            for at in range(count):
                key = memory.read(node + 8 + at * 8, 8)
                if key == self.w["oid"]:
                    rows.append([key] + self.value_words(node + 0x60 + at * ORDER_SIZE)[1:])
                elif memory.read(node + 0x60 + at * ORDER_SIZE, 4):
                    raise Halt("neighbour order changed")
            if height:
                pending.extend((memory.read(node + 0x850 + at * 8, 8), height - 1) for at in range(count + 1))
        return rows

    def read_place(self, w):
        memory = self.machine.memory
        word = memory.read(OUT, 8)
        answer = {"log": self.log, "oid_after": memory.read(STATE + 0x38, 8), "rows_len": memory.read(EVENTS + 0x10, 8), "word": word}
        if word == NONE_WORD:
            answer["error"] = memory.read(OUT + 8, 8)
            if w["request"]["kind"] == 2:
                answer["body"] = memory.bytes_at(OUT + 0x10, 0x40).hex()
        else:
            result = dict(zip(("word", "ptr", "len", "root", "height", "items", "oid"), (memory.read(OUT + index * 8, 8) for index in range(7))))
            if w["request"]["kind"] == 2:
                result["tail"] = memory.bytes_at(OUT + 0x38, 0x18).hex()
            else:
                del result["height"]
                flag = memory.read(OUT + 0x38, 1)
                result.update(flag=flag, cloid=memory.bytes_at(OUT + 0x39, 0x10).hex() if flag else "", resting=memory.read(OUT + 0x49, 1))
            answer["result"] = result
        if any(row[0] == "count" for row in self.log):
            answer["count"] = memory.read(COUNTER, 8)
            answer["length"] = memory.read(self.value_at + 0x48, 8)
            if not any(row[0] == "split" for row in self.log):
                answer["tree"] = self.read_tree()
            if w["oid"] in self.old_vectors:
                if self.old_vectors[w["oid"]] in self.live:
                    raise Halt("old vector kept")
                answer["replaced"] = True
        stray = set(self.live) - self.keep - {memory.read(EVENTS + 8, 8)}
        if w["rows_cap"] and self.row_buffer != memory.read(EVENTS + 8, 8):
            stray.discard(self.row_buffer)
        if stray and self.value_at:
            stray -= {memory.read(self.value_at + 0x38, 8)}
        if stray:
            answer["leaked"] = len(stray)
        return answer

    def run_wrap(self, case, w):
        copy = WRAPS[case.copy]
        memory = self.machine.memory
        self.copy = copy
        self.exposed(copy.start)
        self.common(w)
        memory.write(STATE + 0x58, 8, w["depth"])
        asset = w["request"]["asset"]
        dex = asset // 10000
        memory.write(STATE + copy.rows_field, 8, (ROWS - dex * ROW_STRIDE) & MAX64)
        memory.write(STATE + copy.rows_field + 8, 8, w["rows_count"])
        memory.write(LOCAL_ASSET, 8, asset)
        memory.put_bytes(WRAPPER_IN, memory.bytes_at(REQUEST, 0x48))
        memory.put_bytes(WRAPPER_IN + 0x48, memory.bytes_at(GROUP, 0x50))
        memory.write(WRAPPER_IN + 0x98, 8, LOCAL_ASSET)
        memory.write(WRAPPER_IN + 0xA0, 8, USER_ARG)
        memory.write(WRAPPER_IN + 0xA8, 8, 0)
        memory.put_bytes(OUT, ramp(0x68, 0x7B))
        if dex < w["rows_count"]:
            memory.put_bytes(ROWS, ramp(ROW_STRIDE, 0x35))
            memory.write(ROWS + 8, 8, BOOKS)
            memory.write(ROWS + 0x10, 8, w["books"])
        try:
            self.machine.run(copy.start, {RDI: OUT, RSI: WRAPPER_IN, RDX: STATE})
        except Panicked as error:
            return {"panic": error.args[0], "depth": memory.read(STATE + 0x58, 8), "log": self.log}
        shift = 8 if copy.shifted else 0
        answer = {"depth": memory.read(STATE + 0x58, 8), "log": self.log, "tag": memory.read(OUT + shift, 2), "first": memory.read(OUT + shift + 8, 8)}
        if answer["tag"] != TAG_OK:
            answer["extra"] = memory.read(OUT + shift + 4, 4)
        if copy.shifted and memory.read(OUT, 8):
            answer["head"] = memory.read(OUT, 8)
        answer["rest"] = memory.bytes_at(OUT + shift + 0x10, 0x48 if answer["tag"] == TAG_OK else 0x10).hex()
        return answer

    def run_route(self, case, w):
        copy = ROUTES[case.copy]
        memory = self.machine.memory
        self.copy = copy
        self.exposed(copy.start)
        self.common(w)
        memory.put_bytes(MODE_ROW, ramp(0x40, 0x13))
        memory.write(MODE_ROW + 0x3C, 1, w["mode"])
        memory.put_bytes(NAMES_ROW, ramp(0x80, 0x15))
        memory.write(NAMES_ROW + 0x50, 8, w["names"])
        memory.write(STATE + 0x5B0, 1, w["flag_low"])
        memory.write(STATE + 0x5B1, 1, w["flag_high"])
        memory.write(STATE + copy.flag_field, 1, w["dex_flag"])
        memory.write(STATE + copy.total_field, 8, w["total"])
        memory.write(STATE + copy.dex_field, 8, DEXES)
        memory.write(STATE + copy.dex_field + 8, 8, w["dexes"])
        for index, name in enumerate(("window_one", "limit_one", "window_two", "limit_two")):
            memory.write(STATE + 0x4E8 + index * 8, 8, w[name])
        dex = w["request"]["asset"] // 10000
        if dex < 3:
            memory.put_bytes(DEXES + dex * DEX_STRIDE, ramp(0x60, 0x3B))
            memory.write(DEXES + dex * DEX_STRIDE + 0x50, 8, w["dex_word"])
        memory.put_bytes(GATES, ramp(0x38, 0x2F))
        for at, count, last in ((0, w["bucket_one"], w["last_one"]), (0x18, w["bucket_two"], w["last_two"])):
            memory.write(GATES + at, 8, count)
            for index, value in enumerate(last):
                memory.write(GATES + at + 8 + index * 4, 4, value)
        memory.write(GATES + 0x30, 8, w["ops"])
        self.step_results = [w["before"], w["after"]] if w["mode"] == 2 else [w["after"]]
        memory.put_bytes(OUT, ramp(0x60, 0x7B))
        answer = {"log": self.log}
        try:
            self.machine.run(copy.start, {RDI: OUT, RSI: REQUEST, RDX: USER_ARG, RCX: GROUP, R8: STATE})
        except Panicked:
            answer["panic"] = True
        else:
            data = memory.bytes_at(OUT, 0x60)
            wanted = ramp(0x68, 0x39)[8:0x68] if copy.gate else ramp(0x68, 0x39)[:0x60]
            answer["out"] = "wrapper" if data == wanted else "too many" if memory.read(OUT, 2) == TAG_TOO_MANY else data.hex()
        answer["total"] = memory.read(STATE + copy.total_field, 8)
        if any(row[0] == "entry" for row in self.log):
            answer["ops"] = memory.read(GATES + 0x30, 8)
            if copy.gate:
                answer["bucket"] = [memory.read(GATES, 8), memory.read(GATES + 0x18, 8), [memory.read(GATES + 8 + index * 4, 4) for index in range(3)]]
                if answer["bucket"][2] != [memory.read(GATES + 0x20 + index * 4, 4) for index in range(3)]:
                    raise Halt("second bucket time")
        if self.freed:
            answer["freed"] = self.freed
        return answer

    def run_gate(self, case, w):
        memory = self.machine.memory
        machine = self.machine
        self.exposed(GATE)
        memory.write(GATES, 8, w["count"])
        for index, value in enumerate(w["last"]):
            memory.write(GATES + 8 + index * 4, 4, value)
        for index, value in enumerate(w["now"]):
            memory.write(USER_ARG + index * 4, 4, value)
        machine.run(GATE, {RDI: GATES, RSI: USER_ARG, RDX: w["window"], RCX: w["limit"]})
        allowed = machine.regs[RAX] & 0xFF
        return {"count": memory.read(GATES, 8), "time": [memory.read(GATES + 8 + index * 4, 4) for index in range(3)], "allowed": bool(allowed)}

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.w = w
        self.kind = case.kind
        self.log = []
        self.live = {}
        self.keep = set()
        self.records = 0
        self.row_buffer = 8
        self.freed = None
        memory.reset(self.brk - HEAP_BASE)
        self.brk = HEAP_FREE
        return {"place": self.run_place, "wrap": self.run_wrap, "route": self.run_route, "gate": self.run_gate}[case.kind](case, w)


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
            detail = "%s found %s wanted %s" % (keys[0], str(left)[:900], str(right)[:900])
        return "%s: differs: %s" % (case.label, detail)
    return ""


# ---- cases ----

def make_date(year, ordinal):
    return (year << 13) | (ordinal << 4) | 2


NOW = (make_date(2026, 304), 3600, 250000000)
PLACE_COPIES = range(len(PLACES))


def limit_world(**changes):
    request = default_request(kind=2, third=changes.pop("third", 2), market=changes.pop("market", 1), tag=changes.pop("flag", 0), side=changes.pop("side", 0), reduce=changes.pop("reduce", 0))
    w = default_world(request=request, now=NOW)
    w.update(changes)
    return w


def trigger_world(**changes):
    request = default_request(kind=changes.pop("kind", 0), third=changes.pop("third", 5000), market=changes.pop("market", 0), tag=changes.pop("flag", 0), side=changes.pop("side", 1), reduce=changes.pop("reduce", 1))
    asset = changes.pop("asset", None)
    if asset is not None:
        request["asset"] = asset
    w = default_world(request=request, now=NOW, users={5: {"root": False}})
    w.update(changes)
    return w


def ok_insert(**changes):
    outcome = {"word": 0x55, "ptr": 0x7700, "len": 2, "root": 0, "height": 3, "items": 0, "oid": 4242}
    outcome.update(changes)
    return outcome


def groups_all():
    return (default_group(), default_group(tag=0, cap=4, ptr=0x5100, len=3), default_group(tag=1, cap=2, ptr=0x5200, len=1), default_group(tag=3))


def place_cases():
    rows = []
    for copy in PLACE_COPIES:
        short = PLACES[copy].name

        def add(label, world):
            rows.append(Case("%s: %s" % (short, label), "place", world, copy))

        for kind in (3, 7):
            for market in (0, 3):
                add("rare trigger kind %d market %d" % (kind, market), trigger_world(kind=kind, market=market))
        for year, ordinal in ((2101, 7), (2401, 7), (2001, 7), (2027, 33)):
            add("limit date %d" % year, limit_world(now=(make_date(year, ordinal), 11, 999000000)))
            add("trigger date %d" % year, trigger_world(now=(make_date(year, ordinal), 11, 999000000)))
        for asset in (10005, 20000, 20005):
            add("limit dex row %d" % asset, limit_world(request=default_request(kind=2, third=2, asset=asset), group=default_group(tag=1)))
            add("limit dex row %d error" % asset, limit_world(request=default_request(kind=2, third=2, asset=asset), insert={"error": NONE_WORD | 2}, group=default_group(tag=1)))
            add("trigger dex row %d" % asset, trigger_world(asset=asset, group=default_group(tag=1)))
            add("trigger dex row %d off tick" % asset, trigger_world(asset=asset, third=5001, group=default_group(tag=1)))
        for third in (0, 1, 2, 3, 4, 0xFF, 0x103, 0x200):
            add("limit tif %#x" % third, limit_world(third=third))
            add("limit tif %#x twap" % third, limit_world(third=third, group=default_group(tag=3, payload=ramp(0x20, 0x3F))))
        for index, group in enumerate(groups_all()):
            for mode in (0, 1, 2):
                add("limit group %d mode %d" % (index, mode), limit_world(group=group, mode_word=mode))
            add("limit group %d rows" % index, limit_world(group=group, insert=ok_insert(root=0x9100, height=2, items=4)))
            add("limit group %d no root" % index, limit_world(group=group, insert=ok_insert(root=0, height=2, items=4)))
            add("limit group %d rows full" % index, limit_world(group=group, rows_cap=2, rows_len=2))
            add("limit group %d rows one spare" % index, limit_world(group=group, rows_cap=3, rows_len=2))
            add("limit group %d rows empty" % index, limit_world(group=group, rows_cap=0, rows_len=0))
            add("limit group %d rows one short" % index, limit_world(group=group, rows_cap=4, rows_len=2, insert=ok_insert(root=0x9100, items=1)))
            add("limit group %d rows third full" % index, limit_world(group=group, rows_cap=4, rows_len=1, insert=ok_insert(root=0x9100, items=1)))
            for error in (0, 3, 9, 23):
                add("limit group %d error %d" % (index, error), limit_world(group=group, insert={"error": NONE_WORD | error}))
            add("limit group %d error word" % index, limit_world(group=group, insert={"error": 0x4000000000000123}))
            add("limit group %d error rows full" % index, limit_world(group=group, insert={"error": NONE_WORD | 2}, rows_cap=1, rows_len=1))
            add("limit group %d error second row full" % index, limit_world(group=group, insert={"error": NONE_WORD | 2}, rows_cap=2, rows_len=1))
        for error in range(24):
            add("limit error %d" % error, limit_world(insert={"error": NONE_WORD | error}, group=default_group(tag=1, cap=1, ptr=0x5200, len=1)))
        for flag in (1, 2, 3, 0x81):
            add("limit cloid byte %#x" % flag, limit_world(flag=flag))
            add("limit cloid byte %#x error" % flag, limit_world(flag=flag, insert={"error": NONE_WORD | 2}))
        add("limit side reduce", limit_world(side=1, reduce=1, group=default_group(tag=1)))
        add("limit book asset differs", limit_world(book_asset=11, insert=ok_insert(root=0x9100, items=2)))
        add("limit oid at top", limit_world(oid=MAX64, insert={"error": NONE_WORD | 2}))
        add("limit oid last", limit_world(oid=MAX64 - 1, insert={"error": NONE_WORD | 2}))
        add("limit fills none", limit_world(insert=ok_insert(ptr=8, len=0)))
        add("limit fills word high", limit_world(insert=ok_insert(word=NONE_WORD - 1)))
        add("limit fills word one above", limit_world(insert=ok_insert(word=NONE_WORD + 1)))
        add("limit dex edge", limit_world(request=default_request(kind=2, third=2, asset=29999)))
        add("limit dex past", limit_world(request=default_request(kind=2, third=2, asset=30000)))
        add("limit dex past error", limit_world(request=default_request(kind=2, third=2, asset=30000), insert={"error": NONE_WORD | 2}))

        for kind in (0, 1, 3):
            for market in (0, 1, 3):
                add("trigger kind %d market %d" % (kind, market), trigger_world(kind=kind, market=market))
        add("trigger price zero", trigger_world(third=0))
        add("trigger price cap", trigger_world(third=MAX_TRIGGER))
        add("trigger price over cap", trigger_world(third=MAX_TRIGGER + 10))
        add("trigger price one above cap", trigger_world(third=MAX_TRIGGER + 1, tick=1))
        add("trigger price word top", trigger_world(third=MAX64))
        add("trigger off tick", trigger_world(third=5001))
        add("trigger below tick", trigger_world(third=7))
        add("trigger tick seven", trigger_world(third=7 * 11, tick=7))
        add("trigger tick seven off", trigger_world(third=7 * 11 + 1, tick=7))
        add("trigger wide price", trigger_world(third=0x500000000, tick=0x100000000))
        add("trigger wide off", trigger_world(third=0x500000001, tick=0x100000000))
        add("trigger wide tick narrow price", trigger_world(third=0x500000000, tick=0x80000000))
        add("trigger wide tick off", trigger_world(third=0x500000000, tick=0x70000000))
        add("trigger narrow off", trigger_world(third=0x10001, tick=0x10000))
        for index, group in enumerate(groups_all()):
            add("trigger group %d" % index, trigger_world(group=group, kind=index & 1))
            add("trigger group %d cloid" % index, trigger_world(group=group, flag=1))
            add("trigger group %d off tick" % index, trigger_world(group=group, third=5001))
            add("trigger group %d off rows full" % index, trigger_world(group=group, third=5001, rows_cap=1, rows_len=1))
            add("trigger group %d rows full" % index, trigger_world(group=group, rows_cap=1, rows_len=1))
            add("trigger group %d mode" % index, trigger_world(group=group, mode_word=0))
        add("trigger cloid byte three", trigger_world(flag=3))
        add("trigger cloid byte two", trigger_world(flag=2))
        add("trigger new count", trigger_world(count_new=True))
        add("trigger count top", trigger_world(count=MAX64))
        add("trigger count last", trigger_world(count=MAX64 - 1))
        add("trigger oid top", trigger_world(oid=MAX64))
        add("trigger oid last", trigger_world(oid=MAX64 - 1))
        add("trigger no user map", trigger_world(absent_root=True, users={}))
        add("trigger new user", trigger_world(users={3: {"root": False}, 9: {"root": False}, 12: {"root": False}}))
        add("trigger user low", trigger_world(user=1, users={1: {"root": False}, 200: {"root": False}, 80: {"root": False}}))
        add("trigger user high", trigger_world(user=5, users={1: {"root": False}, 5: {"root": False}, 3: {"root": False}, 4: {"root": False}}))
        add("trigger user in deep tree", trigger_world(user=6, users={number: {"root": False} for number in range(1, 12)}, user_height=1))
        add("trigger user absent deep tree", trigger_world(user=7, users={number: {"root": False} for number in (1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12)}, user_height=1))
        add("trigger oid new in tree", trigger_world(users={5: {"root": True, "oids": [100, 200]}}, oid=9000))
        add("trigger oid below tree", trigger_world(users={5: {"root": True, "oids": [8000, 9500, 9800]}}, oid=7000))
        add("trigger oid between tree", trigger_world(users={5: {"root": True, "oids": [8000, 9500]}}, oid=9000))
        add("trigger oid replace", trigger_world(users={5: {"root": True, "oids": [9000, 9500]}}, oid=9000))
        add("trigger oid replace last", trigger_world(users={5: {"root": True, "oids": [10, 20, 9000]}}, oid=9000))
        add("trigger oid replace deep", trigger_world(users={5: {"root": True, "height": 1, "oids": list(range(8990, 9010))}}, oid=9000))
        add("trigger oid new deep", trigger_world(users={5: {"root": True, "height": 1, "oids": [number for number in range(8990, 9010) if number != 9000]}}, oid=9000))
        add("trigger book asset differs", trigger_world(book_asset=11))
        add("trigger dex edge", trigger_world(asset=29999))
        add("trigger dex past", trigger_world(asset=30000))
        add("trigger dex past off tick", trigger_world(asset=30000, third=5001))
        add("trigger dex past over cap", trigger_world(asset=30000, third=MAX_TRIGGER + 10))
        add("trigger side reduce zero", trigger_world(side=0, reduce=0))
        add("trigger date old", trigger_world(now=(make_date(1, 1), 1, 1)))
        add("trigger date zero year", trigger_world(now=(make_date(0, 1), 1, 1)))
        add("trigger date negative year", trigger_world(now=(make_date(-5, 1) & 0xFFFFFFFF, 1, 1)))
        add("limit date zero year", limit_world(now=(make_date(0, 1), 1, 1)))
        add("limit date negative year", limit_world(now=(make_date(-5, 1) & 0xFFFFFFFF, 1, 1)))
    return rows


def wrap_cases():
    rows = []
    for copy in range(len(WRAPS)):
        short = WRAPS[copy].name

        def add(label, asset, host, **changes):
            base = {"request": default_request(asset=asset), "group": default_group(tag=1, nonce=0x77), "user": 5, "now": NOW, "rows_count": 20000, "books": 40, "host": host, "depth": 3}
            base.update(changes)
            rows.append(Case("%s: %s" % (short, label), "wrap", base, copy))

        ok = {"word": 0x55, "rows": 2}
        for asset in (0, 7, 39, 9999):
            add("local %d" % asset, asset, ok)
        add("local at count", 40, ok)
        add("local under count", 39, ok, books=40)
        add("dex row", 10003, ok)
        add("dex last", 19999 * 10000 + 3, ok)
        add("dex past", 20000 * 10000 + 3, ok)
        add("dex count one", 3, ok, rows_count=1)
        add("dex count one past", 10003, ok, rows_count=1)
        add("no rows", 7, {"word": 0x56, "rows": 0})
        add("word zero", 7, {"word": 0, "rows": 1})
        add("word high", 7, {"word": NONE_WORD + 1, "rows": 1})
        add("word below sentinel", 7, {"word": NONE_WORD - 1, "rows": 1})
        add("word top", 7, {"word": MAX64, "rows": 1})
        for asset in (0, 7, 9999, 10000, 10003, 99899999):
            add("error asset %d" % asset, asset, {"word": NONE_WORD, "error": NONE_WORD | 3, "rows": 2}, books=10000)
        add("error above wire", 99900000, {"word": NONE_WORD, "error": NONE_WORD | 3, "rows": 2}, books=10000)
        add("error above wire more", 123456789, {"word": NONE_WORD, "error": 5, "rows": 0}, books=10000, rows_count=20000)
        add("depth zero", 7, ok, depth=0)
        add("depth top", 7, ok, depth=MAX64)
        add("depth last", 7, ok, depth=MAX64 - 1)
        add("depth zero error", 7, {"word": NONE_WORD, "error": NONE_WORD | 3, "rows": 2}, depth=0)
        add("depth top panic", 40, ok, depth=MAX64)
    return rows


def route_world(**changes):
    w = {"request": default_request(asset=7), "group": default_group(tag=1, cap=3, ptr=0x5300, len=2, nonce=0x66), "user": 5, "now": NOW, "mode": 0, "flag_low": 0, "flag_high": 0, "dex_flag": 1, "names": 0x8800, "before": TAG_OK, "after": TAG_OK, "total": 40, "ops": 50, "dexes": 3, "dex_word": 0xABC0,
         "window_one": 1000, "limit_one": 5, "window_two": 60000, "limit_two": 20, "bucket_one": 1, "bucket_two": 1, "last_one": NOW, "last_two": NOW}
    w.update(changes)
    return w


def route_cases():
    rows = []
    for copy in range(len(ROUTES)):
        short = ROUTES[copy].name

        def add(label, **changes):
            rows.append(Case("%s: %s" % (short, label), "route", route_world(**changes), copy))

        for mode in range(6):
            for low in (0, 1, 2, 3):
                for high in (0, 1, 2, 3):
                    for asset in (7, 10007):
                        for flag in (0, 1):
                            add("mode %d low %d high %d asset %d flag %d" % (mode, low, high, asset, flag), mode=mode, flag_low=low, flag_high=high, dex_flag=flag, request=default_request(asset=asset))
        add("dex asset edge", mode=2, request=default_request(asset=9999))
        add("dex exact multiple", mode=2, request=default_request(asset=20000))
        add("collateral exact multiple", mode=3, request=default_request(asset=20000))
        add("collateral exact multiple margin", mode=4, request=default_request(asset=20000))
        add("dex asset first", mode=2, request=default_request(asset=10000))
        add("dex names zero", mode=2, names=0, request=default_request(asset=10007))
        add("dex before fails", mode=2, before=0x141, request=default_request(asset=10007))
        add("dex after fails", mode=2, after=0x141, request=default_request(asset=10007))
        add("dex both fail", mode=2, before=0x162, after=0x170, request=default_request(asset=20007))
        add("dex flag falls", mode=2, dex_flag_after=0, request=default_request(asset=10007))
        add("dex flag falls before fails", mode=2, dex_flag_after=0, before=0x141, request=default_request(asset=10007))
        add("dex flag byte two", mode=2, dex_flag=2, request=default_request(asset=10007))
        for mode in (3, 4):
            add("mode %d after fails" % mode, mode=mode, after=0x162)
            add("mode %d second dex" % mode, mode=mode, request=default_request(asset=20003))
            add("mode %d dex past" % mode, mode=mode, request=default_request(asset=30003))
            add("mode %d dex count one" % mode, mode=mode, dexes=1, request=default_request(asset=10003))
            add("mode %d total top" % mode, mode=mode, total=MAX64, ops=MAX64)
            add("mode %d total last" % mode, mode=mode, total=MAX64 - 1, ops=MAX64 - 1)
            add("mode %d no cap group" % mode, mode=mode, group=default_group(tag=0))
            for label, one, two in (("both allow", 1, 1), ("first full", 5, 1), ("second full", 1, 20), ("both full", 5, 20), ("first edge", 4, 20), ("second edge", 5, 19), ("both over", 90, 90)):
                add("mode %d %s" % (mode, label), mode=mode, bucket_one=one, bucket_two=two)
                add("mode %d %s no vector" % (mode, label), mode=mode, bucket_one=one, bucket_two=two, group=default_group(tag=1, cap=0, ptr=8, len=0))
                add("mode %d %s group none" % (mode, label), mode=mode, bucket_one=one, bucket_two=two, group=default_group(tag=2, cap=3, ptr=0x5300))
                add("mode %d %s group twap" % (mode, label), mode=mode, bucket_one=one, bucket_two=two, group=default_group(tag=3, cap=3, ptr=0x5300))
                add("mode %d %s group zero" % (mode, label), mode=mode, bucket_one=one, bucket_two=two, group=default_group(tag=0, cap=2, ptr=0x5400))
            add("mode %d first bucket rolled" % mode, mode=mode, bucket_one=90, bucket_two=90, last_one=(NOW[0], NOW[1] - 1, NOW[2]))
            add("mode %d second bucket rolled" % mode, mode=mode, bucket_one=90, bucket_two=90, last_two=(NOW[0], NOW[1] - 3600, NOW[2]))
            add("mode %d windows swapped" % mode, mode=mode, bucket_one=19, bucket_two=4, window_one=60000, limit_one=20, window_two=1000, limit_two=5)
            add("mode %d limits zero" % mode, mode=mode, limit_one=0, limit_two=0)
            add("mode %d time differs" % mode, mode=mode, now=(NOW[0], 3601, 1))
            add("mode %d times differ" % mode, mode=mode, now=(NOW[0] + 0x10, 7, 900000000), last_one=(NOW[0], 86399, 999000000), last_two=(NOW[0], 86000, 0))
    return rows


def gate_cases():
    rows = []
    near = make_date(1970, 1)

    def add(label, **changes):
        base = {"count": 3, "last": NOW, "now": NOW, "window": 1000, "limit": 4}
        base.update(changes)
        rows.append(Case("gate: " + label, "gate", base, 0))

    add("same bucket under")
    add("same bucket at limit", count=3, limit=4)
    add("same bucket over", count=4, limit=4)
    add("count top", count=MAX64, limit=MAX64)
    add("count top under", count=MAX64, limit=MAX64 - 1)
    add("count last", count=MAX64 - 1, limit=MAX64 - 1)
    add("limit zero fresh", last=(NOW[0], NOW[1] - 1, NOW[2]), limit=0)
    add("limit one fresh", last=(NOW[0], NOW[1] - 1, NOW[2]), limit=1)
    add("next bucket", last=(NOW[0], NOW[1] - 1, NOW[2]), count=99)
    add("bucket edge in", last=(NOW[0], 3600, 0), now=(NOW[0], 3600, 999000000), count=7)
    add("bucket edge out", last=(NOW[0], 3600, 999000000), now=(NOW[0], 3601, 0), count=7)
    add("time back", last=(NOW[0], NOW[1] + 5, NOW[2]), count=2)
    add("window minute in", window=60000, last=(NOW[0], 3601, 0), now=(NOW[0], 3659, 0))
    add("window minute out", window=60000, last=(NOW[0], 3659, 0), now=(NOW[0], 3660, 0))
    add("window day", window=86400000, last=(NOW[0], 86399, 0), now=(NOW[0] + 0x10, 0, 0))
    add("window wide in", window=0x200000000, last=(NOW[0], 1, 0), now=(NOW[0], 2, 0))
    add("window wide out", window=0x180000000, last=(make_date(2026, 1), 1, 0), now=(make_date(2026, 200), 1, 0))
    add("window one", window=1, last=(NOW[0], NOW[1], 1000000), now=(NOW[0], NOW[1], 2000000))
    add("narrow times in", last=(near, 3, 0), now=(near, 3, 500000000), window=1000)
    add("narrow times out", last=(near, 3, 0), now=(near, 4, 500000000), window=1000)
    add("narrow last wide now", last=(near, 3, 0), now=NOW, window=1000)
    add("wide last narrow now", last=NOW, now=(near, 3, 0), window=1000)
    add("date before epoch", last=(make_date(1960, 1), 3, 0), now=(make_date(1961, 1), 3, 0), window=1000)
    add("year zero", last=(make_date(0, 2), 3, 0), now=(make_date(0, 3), 3, 0), window=1000)
    add("year negative", last=(make_date(-3, 2) & 0xFFFFFFFF, 3, 0), now=(make_date(-3, 3) & 0xFFFFFFFF, 3, 0), window=1000)
    add("century year", last=(make_date(2101, 2), 3, 0), now=(make_date(2101, 2), 4, 0), window=1000)
    add("four hundred year", last=(make_date(2001, 2), 3, 0), now=(make_date(2401, 2), 4, 0), window=86400000)
    add("leap ladder", last=(make_date(2100, 60), 1, 0), now=(make_date(2100, 61), 1, 0), window=86400000)
    day = 86400000
    for year in (2001, 2101, 2401, 2028, 2100):
        for ordinal in (7, 8):
            first = make_date(year, ordinal)
            next_day = make_date(year, ordinal + 1)
            add("day inside %d %d" % (year, ordinal), last=(first, 0, 0), now=(first, 80000, 0), window=day)
            add("day cross %d %d" % (year, ordinal), last=(first, 86399, 999000000), now=(next_day, 0, 0), window=day)
            add("day cross back %d %d" % (year, ordinal), last=(next_day, 0, 0), now=(first, 86399, 999000000), window=day)
            add("day inside next %d %d" % (year, ordinal), last=(first, 86399, 999000000), now=(first, 86399, 999000000), window=day)
    for nanos in (999000000, 998000000, 1000000, 2000000, 999999999):
        add("millisecond equal %d" % nanos, last=(NOW[0], 5, nanos), now=(NOW[0], 5, nanos), window=1)
        add("millisecond next %d" % nanos, last=(NOW[0], 5, nanos - 1000000), now=(NOW[0], 5, nanos), window=1)
    for days in (1, 2, 3, 4, 40, 300):
        add("date step %d" % days, last=(make_date(2028, days), 40000, 123000000), now=(make_date(2028, days + 1), 40000, 123000000), window=86400000 + 1)
    for year in (1971, 1973, 1999, 2000, 2004, 2100, 2400):
        add("year %d last" % year, last=(make_date(year, 9), 7, 5000000), now=(make_date(year, 9), 7, 6000000), window=2, count=8)
        add("year %d now" % year, last=(make_date(year, 9), 7, 5000000), now=(make_date(year + 1, 9), 7, 5000000), window=31622400000, count=8)
    return rows


ALL_CASES = None


def all_cases():
    global ALL_CASES
    if ALL_CASES is None:
        ALL_CASES = gate_cases() + route_cases() + wrap_cases() + place_cases()
    return ALL_CASES

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
    (GATE, "bucket gate"),
    (0x4CA9710, "router with the bucket gate"),
    (0x4CA8EB0, "router without the gate"),
    (0x4D446F0, "wrapper, status at +0x08"),
    (0x4D472F0, "wrapper, status at +0x00"),
    (0x430BE90, "perp host: rests a trigger or inserts"),
    (0x430ABF0, "spot host: rests a trigger or inserts"),
    (0x45A3B30, "user_states entry"),
    (0x4932C30, "write into field u"),
)
EXTRA_FUNCTIONS = ((0x4CA8510, "second router, gate"), (0x4CA7CB0, "second router, no gate"), (0x4D47AD0, "second wrapper, +0x08"), (0x4D476E0, "second wrapper, +0x00"), (0x4309700, "second perp host"), (0x4308460, "second spot host"), (0x45A3980, "spot user_states entry"), (0x493C4B0, "spot write into field u"))
CASE_CAP = 120
PATH_CASES = 3
RARE_WORDS = ("rare", "date", "dex row", "exact", "asset first", "tick", "wide")


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
    rare = {index for index, case in enumerate(cases) if case.kind == "gate" or any(word in case.label for word in RARE_WORDS)}
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
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

CONTEXT_FORMATTER = 0x4C696F0
CONTEXT_NAMES = (
    (0x4C6985C, 0x4C69879, 0x4C6970A), (0x4C69886, 0x4C6988D, 0x4C6970E), (0x4C6989D, 0x4C698A4, 0x4C69712), (0x4C698B4, 0x4C698BB, None), (0x4C698CD, 0x4C698D4, 0x4C69716), (0x4C698E6, 0x4C698ED, 0x4C6971A), (0x4C698FF, 0x4C69906, 0x4C6971E),
    (0x4C69918, 0x4C6991F, 0x4C69722), (0x4C69934, 0x4C6993B, 0x4C69726), (0x4C69950, 0x4C69957, 0x4C6972A), (0x4C6996C, 0x4C69973, 0x4C6972E), (0x4C69988, 0x4C6998F, 0x4C69732), (0x4C699A4, 0x4C699AB, 0x4C69736),
)
FIELDS = {
    "state": {"+0x00/+0x08": "Context.tx_index: dword 1 means present, the word goes to the hash helper", "+0x28": "Context.height, hash helper argument", "+0x38": "Context.next_oid, read then raised, saturating", "+0x58": "Context.maybe_operate_with_abstraction_reentrancy_counter, raised around one wrapper run, saturating both ways",
              "+0x60": "Context.time: date, seconds, nanoseconds", "+0x5b0/+0x5b1": "router flag bytes, bit 0 only", "+0x4e8/+0x4f0": "first bucket: window in ms, limit", "+0x4f8/+0x500": "second bucket: window in ms, limit",
              "dex route flag": "+0x454b first copies, +0x3acb second", "names": "+0x1038 first, +0x5b8 second: argument of accessor 0x3332680, row +0x50 is the word passed on", "bucket rows": "+0x11f0 first, +0x770 second: map argument of 0x47d7550, per user", "operation total": "+0x1250 first, +0x7d0 second",
              "dex rows": "+0x1040 and +0x1048 first, +0x5c0 and +0x5c8 second; stride 0x2f0, row +0x50 is the word passed to the steps", "per-user order count": "+0x11c0 or +0x740, value word at bucket -0x20", "hash byte": "+0x1372 or +0x8f2", "book rows": "+0x3df0 and +0x3df8 first, +0x3370 and +0x3378 second; stride 0x138, row +0x08 books, +0x10 count, book stride 0xd8"},
    "bucket_row": {"+0x00": "first count", "+0x08": "first time, 12 bytes", "+0x18": "second count", "+0x20": "second time, 12 bytes", "+0x30": "operations that passed, saturating"},
    "request": {"size": "0x48 bytes, passed by copy", "+0x00/+0x08": "words kept in the stored order and the record", "+0x10": "trigger price for a trigger order; for kind 2 the low byte is the tif byte", "+0x18": "market byte of a trigger order", "+0x19": "2 limit, else bit 0: 0 take profit, 1 stop",
                "+0x1a": "6 bytes, only into the record", "+0x20": "limit price", "+0x28": "asset of the request, into the 0xa row", "+0x30": "side byte", "+0x31": "reduce only byte", "+0x32": "bit 0: client id present", "+0x33": "client id, 16 bytes", "+0x43": "5 bytes, only into the record"},
    "group": {"size": "0x50 bytes", "+0x00": "tag: 0 or 1 standalone, 2 no group data, 3 twap slice", "+0x08": "0x20 bytes, kept when the tag is 1; its first word goes to insert +0x78 for every tag", "+0x28/+0x30/+0x38": "vector of 0x48 byte rows: capacity, pointer, length", "+0x40": "dword to insert when the tag is below 2, else 0", "+0x44": "dword to insert", "+0x48": "word to the hash helper when the tag is below 2"},
    "stored_order": {"size": "0xb8, key is the oid", "+0x00/+0x08": "request words", "+0x10/+0x20/+0x30/+0x38/+0x40": "0, 0, then an empty vector 0, 8, 0", "+0x48/+0x50": "tag and 0x20 bytes", "+0x70": "order type word", "+0x80": "limit price", "+0x88": "block time in ms", "+0x90": "reduce only", "+0x91/+0x92": "client id flag and bytes", "+0xa2": "side", "+0xa8": "trigger price", "+0xb0/+0xb1": "market byte, kind byte"},
    "insert_request": {"+0x00": "request words, then 0, 0, empty vector", "+0x48/+0x50": "tag and 0x20 bytes", "+0x70": "order type word 0, 1 or 9", "+0x78": "first word of the group payload", "+0x80": "limit price", "+0x88": "block time in ms", "+0x90": "reduce only", "+0x91/+0x92": "client id flag and bytes", "+0xa2": "side", "+0xa8": "0", "+0xb8": "user", "+0xcc": "tif byte", "ecx": "group +0x40 or 0", "r8d": "group +0x44"},
    "row": {"+0x00": "3, or 0xa for the last row", "+0x08": "kind of a 3 row: tag 0 or 1, then 4 for the second row of the pair; for 0xa the tree root", "+0x10": "payload of kind 1; for 0xa the height", "+0x18": "for 0xa the length", "+0x20": "for 0xa the request asset", "+0x30": "0xa8 byte record", "+0xd8": "time", "+0xe4": "user", "+0xf8/+0xf9": "hash flag and 0x20 bytes", "+0x119": "status byte"},
    "result": {"+0x00": "insert word, 0 after a resting trigger, sentinel 0x8000000000000000 on error", "+0x08/+0x10": "fills pointer and length, 8 and 0 after a resting trigger; on error +0x08 is the error word", "+0x18/+0x20/+0x28": "tree root, height, length", "+0x30": "oid", "+0x38/+0x39/+0x49": "after a resting trigger: client id flag, client id, byte 1"},
}
REFERENCE_CLAIMS = (
    {"reference": "l1/ (whole tree)", "claim": "no text untriggered_orders, no writer of a trigger order and no Too many abstraction text", "observed": "0x430be90 writes the 0xb8 byte order into field u, 0x4ca9710 writes tag 0x170", "verdict": "missing in the reference"},
    {"reference": "l1/order_wire.rs:62", "claim": "Trigger { is_market, trigger_px, tpsl }", "observed": "the same three facts at request +0x18, +0x10 and +0x19, with kind 2 meaning limit", "verdict": "names agree; layout is new here"},
    {"reference": "l1/exchange/impl_execute_action.rs:104", "claim": "UserDexAbstraction and AgentEnableDexAbstraction handler labels only", "observed": "the router reads the mode byte on the order path", "verdict": "no body in the reference"},
)


def fixed_text(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def rip_target(image, va):
    """Target of a 7 byte `lea reg, [rip+disp32]`."""
    data = code(image, va, 7)
    if data[1] != 0x8D:
        raise EvidenceError("not a lea at %#x" % va)
    return va + 7 + struct.unpack_from("<i", data, 3)[0]


def arm_text(image, table, index):
    """Fixed text of one jump table arm: the first `lea rsi, [rip+d]` then `mov edx, n`; None when the arm has no such pair."""
    arm = table + struct.unpack_from("<i", image.blob, image.offset(table + 4 * index))[0]
    data = code(image, arm, 64)
    at = data.find(b"\x48\x8d\x35")
    if at < 0 or data[at + 7] != 0xBA:
        return None
    return fixed_text(image, rip_target(image, arm + at), struct.unpack_from("<I", data, at + 8)[0])


def context_rows(image):
    """Name and offset of every field of the Debug writer of Context."""
    rows = []
    for name_at, length_at, offset_at in CONTEXT_NAMES:
        length = code(image, length_at, 5)
        if length[0] != 0xBA:
            raise EvidenceError("length at %#x" % length_at)
        name = fixed_text(image, rip_target(image, name_at), struct.unpack_from("<I", length, 1)[0])
        offset = 0
        if offset_at is not None:
            data = code(image, offset_at, 4)
            if data[1] != 0x8D:
                raise EvidenceError("field lea at %#x" % offset_at)
            offset = data[3]
        rows.append({"field": name, "offset": "%#x" % offset, "name_site": "%#x" % name_at, "offset_site": "%#x" % offset_at if offset_at else "register holds the base"})
    return rows


def mode_rows(image):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    rows = []
    for index in range(9):
        at = MODE_NAMES + index * 16
        size = struct.unpack_from("<Q", image.blob, image.offset(at + 8))[0]
        rows.append({"row": index, "text": fixed_text(image, relative[at], size)})
    rows.append({"row": 9, "text": fixed_text(image, relative[MODE_NAMES + 9 * 16], struct.unpack_from("<Q", image.blob, image.offset(MODE_NAMES + 9 * 16 + 8))[0])})
    return rows


def error_rows(image):
    table = code(image, STATUS_TABLE, 24)
    if table != STATUS_BY_ERROR:
        raise EvidenceError("status table")
    return [{"index": index, "word": "%#x" % (NONE_WORD | index), "status_byte": "%#x" % table[index], "text": arm_text(image, ERROR_TEXTS, index) or "no fixed text in the arm"} for index in range(24)]


def tag_rows(image):
    return [{"tag": "%#x" % tag, "text": arm_text(image, TAG_TEXTS, tag) or "no fixed text in the arm", "use": use} for tag, use in ((TAG_TOO_MANY, "router: both buckets over"), (0x141, "Result word dropped after each dex row bound"), (TAG_ERROR, "wrapper: error word with the wire asset"), (TAG_OK, "wrapper: fine"))]


def route_table():
    rows = []
    for mode in range(6):
        for low in (0, 1):
            for high in (0, 1):
                for flag, asset in ((0, 7), (1, 7), (0, 10007), (1, 10007)):
                    rows.append({"mode": mode, "low_bit_5b0": low, "low_bit_5b1": high, "dex_flag": flag, "asset": asset, "route": route_of(mode, low, high, flag, asset)})
    return rows


def type_table():
    rows = [{"kind": kind, "market": market, "word": order_type(kind, market)} for kind in (0, 1) for market in (0, 1)]
    for tag, third in ((2, 0), (2, 2), (2, 3), (2, 4), (3, 0), (3, 4)):
        rows.append({"arm": "limit", "group_tag": tag, "tif_byte": third, "word": limit_type(tag, third)})
    return rows


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
            target = row.va + row.size + struct.unpack_from("<i", code(image, row.va, row.size), row.rip_at)[0]
            targets.append(target)
            out[at + row.rip_at:at + row.rip_at + 4] = bytes(4)
    return bytes(out), targets, rows


FIRST_STATE = ((0x454B, 0x3ACB), (0x1038, 0x5B8), (0x11F0, 0x770), (0x1250, 0x7D0), (0x1048, 0x5C8), (0x1040, 0x5C0))
COPY_PAIRS = (
    (0x430BE90, 0x4309700, ((0x1048, 0x5C8), (0x1040, 0x5C0), (0x11C0, 0x740), (0x1372, 0x8F2))),
    (0x430ABF0, 0x4308460, ((0x740, 0x11C0), (0x8F2, 0x1372))),
    (0x4D446F0, 0x4D47AD0, ((0x3DF8, 0x3378), (0x3DF0, 0x3370))),
    (0x4D472F0, 0x4D476E0, ((0x3DF8, 0x3378), (0x3DF0, 0x3370))),
    (0x4CA9710, 0x4CA8510, FIRST_STATE),
    (0x4CA8EB0, 0x4CA7CB0, FIRST_STATE),
    (0x45A3B30, 0x45A3980, ()),
    (0x4932C30, 0x493C4B0, ()),
)


def copy_table(image):
    """Same bytes after masking, except the rows listed, which differ only in a state field displacement."""
    rows = []
    for first, second, allowed in COPY_PAIRS:
        left, left_targets, decoded = masked(image, first)
        right, right_targets, _ = masked(image, second)
        if len(left) != len(right) or len(left_targets) != len(right_targets):
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
            changed.append({"offset": "%#x" % at, "field": "%#x / %#x" % pair})
        rows.append({"first": "%#x" % first, "second": "%#x" % second, "size": len(left), "first_sha256": hashlib.sha256(left).hexdigest(), "second_sha256": hashlib.sha256(right).hexdigest(), "state_rows": changed,
                     "targets_that_differ": [["%#x" % one, "%#x" % two] for one, two in zip(left_targets, right_targets) if one != two and not one - first == two - second]})
    return rows


PATH_SITES = tuple((copy.start, copy.wrap, 3) for copy in ROUTES) + tuple((copy.start, copy.host, 1) for copy in WRAPS)


def host_rows(image):
    """Calls into the path by exact byte patterns: direct sites by target, slot sites of the gate."""
    targets = sorted({copy.start for copy in ROUTES} | {copy.start for copy in WRAPS} | {copy.start for copy in PLACES})
    direct = direct_sites(image, targets)
    rows = []
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for host, target, count in PATH_SITES:
        if sum(1 for va, _ in direct[target] if image.fde(va)[0] == host) != count:
            raise EvidenceError("sites of %#x in %#x" % (target, host))
    slots = []
    for slot, target in sorted(SLOT_NAMES.items()):
        if image_slot(image, slot) != target:
            raise EvidenceError("slot %#x" % slot)
    for va in slot_sites(image, 0x5774748):
        rows.append((GATE, va, "slot 0x5774748", image.fde(va)[0], image.fde(va)[1]))
    return rows


def image_slot(image, slot):
    for address, kind, addend, _ in image.relocations():
        if address == slot and kind == 8:
            return addend
    raise EvidenceError("no relocation at %#x" % slot)


def outcome_name(case, spec):
    if case.kind == "gate":
        return "gate allowed" if spec["allowed"] else "gate over"
    if spec.get("panic"):
        return "%s panic" % case.kind
    if case.kind == "wrap":
        return "wrap status %#x" % spec["tag"]
    if case.kind == "route":
        names = [row[0] for row in spec["log"]]
        if spec["out"] == "too many":
            return "route too many"
        if "before" in names:
            return "route collateral"
        return "route dex" if "names" in names else "route direct"
    if spec["word"] == NONE_WORD:
        return "place error"
    return "place resting trigger" if case.world["request"]["kind"] != 2 else "place insert"


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
    site_rows = host_rows(image)
    copies = copy_table(image)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "copies": copies,
        "context_fields": context_rows(image),
        "mode_name_rows": mode_rows(image),
        "error_words": error_rows(image),
        "tags": tag_rows(image),
        "fields": FIELDS,
        "route_table": route_table(),
        "type_table": type_table(),
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
    }


SURVIVED_DEFAULT = "not explained: no case separates it"
YEAR_ARM = "arm for a date with year 0 or below: the result clamps to 0 ms, so its constants cannot show"
SIGN_SHIFT = "takes the sign of the hundred quotient, which is 0 for every year above 0, and lower years clamp to 0 ms"
WIDE_TEST = "picks the 32 or 64 bit divide, and both give the same quotient"
UNWIND_ONLY = "the value is read only by an unwind pad or a drop on a panic path"
WRAP_VECTOR = "empty rows vector set up for the unwind pad; the normal path overwrites these stack bytes first"
DEAD_WORD = "the packed +0x1a word is used only when the kind byte is 2, and that arm replaces the register first"
DEAD_BRANCH = "this compare runs only with a tag below 2, so the equal arm is dead"
COPY_SIZE = "one more byte lands on a stack byte that the next store replaces"
NEW_LEAF = "a new leaf has index 0, so the capacity test and the stride multiply cannot show"
SURVIVED_REASONS = {}
for rows, why in (
    ((0x37D9F1B, 0x37D9F24, 0x37D9F2B, 0x37D9F32, 0x37D9F3C, 0x37D9F5C, 0x37D9F64, 0x37D9F6B, 0x37D9F71, 0x37D9F7B, 0x430C125, 0x430C12D, 0x430C134, 0x430C13A, 0x430C144, 0x430C707, 0x430C70E, 0x430C715, 0x430C71B, 0x430C723,
      0x430AE2D, 0x430AE35, 0x430AE3C, 0x430AE42, 0x430AE4C, 0x430B3AE, 0x430B3B5, 0x430B3BC, 0x430B3C2, 0x430B3CB), YEAR_ARM),
    ((0x37D9F9A, 0x37DA038, 0x430C162, 0x430C7D7, 0x430AE6D, 0x430B48C), SIGN_SHIFT),
    ((0x37D9FFC, 0x37DA087, 0x430C0B4, 0x430ADC6), WIDE_TEST),
    ((0x4D4471A, 0x4D44726, 0x4D4472F, 0x4D4731A, 0x4D47326, 0x4D4732F, 0x430C30F, 0x430C355, 0x430CCCA, 0x430CD05, 0x430B029, 0x430B92B, 0x430B961), UNWIND_ONLY),
    ((0x4D447AF, 0x4D447B8, 0x4D447C1, 0x4D473AF, 0x4D473B8, 0x4D473C1), WRAP_VECTOR),
    ((0x430BF19, 0x430BF1D, 0x430BF22, 0x430BF6E, 0x430AC7A, 0x430AC7D, 0x430AC81, 0x430ACC7), DEAD_WORD),
    ((0x430C347, 0x430CCFA, 0x430B058, 0x430B956), DEAD_BRANCH),
    ((0x430C5A0, 0x430CE9D, 0x430B232, 0x430BAF8), COPY_SIZE),
    ((0x4932D88, 0x4932DA8), NEW_LEAF),
):
    for va in rows:
        SURVIVED_REASONS[va] = why


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
