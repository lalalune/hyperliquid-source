#!/usr/bin/env python3
"""Pin the node #94 cancel path from ELF bytes: the wire list, one cancel item, the book map from client id to oid, and the status of each item.

Preparers `0x2518ad0` (oid) and `0x251a940` (client id) turn the wire list into 0x20 byte records. Worker `0x251a180` and closure `0x24bbcf0`
run item `0x275a380` once per record and collect 0x60 byte results. The item routes the asset, finds the book, reads the map at book +0x48
when the record holds a client id, calls the removal with reason 2, always closes with one row and one flush, and only then picks the status:
0x186 fine, 0xc5 not found, with the wire asset. Spot uses `0x2726af0`. The real bytes run in a Python evaluator with the edge callees stubbed.
A separately written specification predicts every result, and every condition, immediate and field offset is flipped to show the run can
tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

Copy = collections.namedtuple("Copy", "name core_oid core_cloid prepare_oid prepare_cloid worker closure item spot remove spot_remove flush spot_flush count done mark mark_low hook closed rows rows_len dex_len names spot_rows spot_len")
COPIES = (
    Copy("first", 0x2721120, 0x2725010, 0x2518AD0, 0x251A940, 0x251A180, 0x24BBCF0, 0x275A380, 0x2726AF0, 0x26DE150, 0x26DE280, 0x24FB610, 0x24FC8A0,
         0x878, 0x880, 0x3A98, 0x3AA0, 0x3A88, 0x3AC8, 0x3370, 0x3378, 0x5C8, 0x5B8, 0x3388, 0x3390),
    Copy("second", 0x4D25E40, 0x4D2B140, 0x47F8410, 0x47F7070, 0x47F65D0, 0x4447770, 0x4D85940, 0x4D2E640, 0x42F7590, 0x42F7290, 0x4329870, 0x432B440,
         0x878, 0x880, 0x3A98, 0x3AA0, 0x3A88, 0x3AC8, 0x3370, 0x3378, 0x5C8, 0x5B8, 0x3388, 0x3390),
    Copy("third", 0x4D25F80, 0x4D2B280, 0x47F8410, 0x47F7070, 0x47F66E0, 0x4449010, 0x4D85290, 0x4D2E810, 0x42F7420, 0x42F7700, 0x432A100, 0x432A990,
         0x12F8, 0x1300, 0x4518, 0x4520, 0x4508, 0x4548, 0x3DF0, 0x3DF8, 0x1048, 0x1038, 0x3E08, 0x3E10),
)
LOOKUP = 0x342A430
HASH_USER = 0x399C7A0
HASH_CLOID = 0x399C650
DROP_WORD = 0x3379490
CLOCK = 0x4EE3800
ELAPSED = 0x4EE3730
WIRE_SPOT = 0x3C0CEA0

SLOT_NAMES = {0x5773950: 0x3C0CC70, 0x5774AA0: LOOKUP, 0x576E8F8: 0x13C9E20, 0x5773228: 0x37E4FB0, 0x5773230: 0x37E4E50, 0x5773D58: 0x454ECB0, 0x5773D50: 0x454F340}
SLOT_RESOLVE = 0x5773950
SLOT_SAMPLE = 0x576E8F8
SLOT_FIRST = 0x5773228
SLOT_SECOND = 0x5773230
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576E468, 0x576DFB8, 0x576E020, 0x576E108, 0x576E290)
TAG_TEXTS = 0x59A8D0
NOT_FOUND_ARM = 0x3802A2F
NOT_FOUND_TEXT_SITE = 0x399837B
NOT_FOUND_TEMPLATE_SITE = 0x3802BEF

ROW_STRIDE = 0x138
BOOK_STRIDE = 0xD8
RESULT_SIZE = 0x60
RECORD_SIZE = 0x20
USER_SIZE = 20
PERP_ROW = 0x278
SPOT_ROW = 0x268
MAX64 = (1 << 64) - 1
TAG_OK = 0x186
TAG_NOT_FOUND = 0xC5
TAG_SPOT_OFF = 0xF9
TAG_TOO_LONG = 0x143
LIST_LIMIT = 0x2711
REASON = 2
SAMPLE_ARGUMENT = 0x32
GATE_MASK = 0x501D
NO_TIME = 1000000000
WIRE_LOCAL = 0x270F
WIRE_LIMIT = 0x5F45A5F
WIRE_BASE = 100000
WIRE_NONE = 0xFFFFFFFF

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
BOOKS = HEAP_BASE + 0x8000
BOOK_AREA = 0x800
SPOT_BOOKS = HEAP_BASE + 0xC000
USER_ARG = HEAP_BASE + 0xE300
OUT = HEAP_BASE + 0xE400
ASSET_ARG = HEAP_BASE + 0xE500
RECORD_ARG = HEAP_BASE + 0xE520
TUPLE = HEAP_BASE + 0xE560
HOOK_DATA = HEAP_BASE + 0xE600
HOOK_TABLE = HEAP_BASE + 0xE640
VEC_ARG = HEAP_BASE + 0xE700
HOOK_TARGET = 0xCA110000
TABLES = HEAP_BASE + 0x10000
TABLE_AREA = 0x18000
HEAP_FREE = HEAP_BASE + 0x28000

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



# ---- specification, written from the read of the bytes, shares nothing with the evaluator ----

class SpecPanic(Exception):
    def __init__(self, label):
        Exception.__init__(self, label)
        self.label = label


def wire_asset(packed):
    if packed <= WIRE_LOCAL:
        return packed
    if packed > WIRE_LIMIT:
        return WIRE_NONE
    return packed + WIRE_BASE


def saturating_add(left, right):
    return min(left + right, MAX64)


def timed_by_gate(first, second):
    """None when the sampler decides, else True: the clock always runs."""
    if first == 0 and not (second <= 0xE and GATE_MASK >> second & 1):
        return True
    return None


class Walk:
    """Book keeping of one specified run."""

    def __init__(self, world, copy):
        self.w = world
        self.copy = copy
        self.log = []
        self.ticks = 0
        self.done = world["done"]
        self.samples = iter(world["samples"])

    def tick(self):
        self.ticks += 1
        self.log.append(["clock"])
        return [1000 + self.ticks, 100 + self.ticks]

    def find(self, book, user, item):
        """Oid to remove, None when the client id map has no such entry."""
        if "cloid" not in item:
            return item["oid"]
        return self.w["maps"].get(book, {}).get(user, {}).get(item["cloid"]) if self.w["maps"].get(book, {}).get(user) else None

    def close(self, book, oid, row, label):
        """Removal when an oid is known, then the row, then the flush.  True when nothing was removed."""
        missing = True
        rows = 0
        if oid is not None:
            missing = oid in self.w["absent"]
            rows = self.w["rows"].get(oid, 0)
            self.log.append([label, list(book), oid, REASON])
        grown = rows == 0 or rows == 4
        if grown:
            self.log.append(["grow", rows, row])
        self.log.append(["flush", label, book[1] if label == "perp" else None, rows + 1])
        return missing

    def run_perp(self, packed, item):
        dex, local = packed // 10000, packed % 10000
        w = self.w
        if dex >= w["rows_len"]:
            raise SpecPanic("perp_dex")
        if local >= w["books"].get(dex, 0):
            raise SpecPanic("books")
        book = ("perp", dex, local)
        missing = self.close(book, self.find(book, w["user"], item), PERP_ROW, "perp")
        if not missing:
            return {"tag": TAG_OK}
        if dex >= w["dex_len"]:
            raise SpecPanic("clearinghouses")
        return {"tag": TAG_NOT_FOUND, "asset": wire_asset(packed)}

    def run_spot(self, index, item):
        w = self.w
        if w["closed"]:
            return {"tag": TAG_SPOT_OFF}, False
        if index >= w["spot_len"]:
            raise SpecPanic("books")
        book = ("spot", index)
        missing = self.close(book, self.find(book, w["user"], item), SPOT_ROW, "spot")
        if not missing:
            return {"tag": TAG_OK}, True
        self.log.append(["wire", index])
        return {"tag": TAG_NOT_FOUND, "asset": 0x77000000 | index}, True

    def run_item(self, item, first, second):
        w = self.w
        timed = timed_by_gate(first, second)
        if timed is None:
            self.log.append(["sample"])
            timed = next(self.samples)
        start = self.tick() if timed else None
        now = self.tick()
        self.log.append(["resolve", item["asset"]])
        route = w["routes"][item["asset"]]
        hook = False
        if route[0] == "error":
            result = {"tag": route[1], "payload": ramp(0x5E, item["asset"] & 0xFF).hex()}
        elif route[0] == "spot":
            result, hook = self.run_spot(route[1], item)
        else:
            result = self.run_perp(route[1], item)
            hook = True
        if hook:
            if w["hook"]:
                self.log.append(["hook", int(result["tag"] != TAG_OK), now])
            if result["tag"] == TAG_OK:
                self.done = saturating_add(self.done, 1)
        if timed:
            self.log.append(["elapsed", self.tick(), start])
        return result


def run_core_spec(world, copy):
    walk = Walk(world, copy)
    items = world["items"]
    count = world.get("claimed", len(items))
    source = world["capacity"]
    stride = 0x14 if world["by"] == "cloid" else 0x10
    total = world["count"]
    out = {"log": walk.log}
    if count >= LIST_LIMIT:
        if source:
            walk.log.append(["free", source * stride])
        out.update({"word": TAG_TOO_LONG, "rejected": count, "count": total, "done": walk.done, "mark": False, "live": []})
        return out
    if count:
        walk.log.append(["malloc", count * RECORD_SIZE])
    if source:
        walk.log.append(["free", source * stride])
    total = saturating_add(total, count)
    walk.log.append(["first"])
    marked = world["first"]
    if not marked:
        walk.log.append(["second"])
        marked = world["second"]
    if count:
        walk.log.append(["malloc", count * RESULT_SIZE])
    results = []
    try:
        for item in items:
            results.append(walk.run_item(item, 2, 0))
    except SpecPanic as panic:
        return {"log": walk.log, "panic": panic.label}
    if count:
        walk.log.append(["free", count * RECORD_SIZE])
    out.update({"word": TAG_OK, "capacity": count, "length": count, "results": results, "count": total, "done": walk.done, "mark": marked, "live": [count * RESULT_SIZE] if count else []})
    if not count:
        out["empty_pointer"] = 8
    return out


def run_item_spec(world, copy):
    walk = Walk(world, copy)
    try:
        result = walk.run_item(world["items"][0], world["first_byte"], world["second_byte"])
    except SpecPanic as panic:
        return {"log": walk.log, "panic": panic.label}
    return {"log": walk.log, "result": result, "done": walk.done}


def run_lookup_spec(world):
    shape = world["shape"]
    if shape.get("user_items") == 0 or shape.get("items") == 0:
        return {"found": False, "oid": None}
    found = world["maps"].get(("book",), {}).get(world["user"], {}).get(world["cloid"])
    return {"found": found is not None, "oid": found}


def run_spec(case):
    if case.kind == "core":
        return run_core_spec(case.world, COPIES[case.copy])
    if case.kind == "item":
        return run_item_spec(case.world, COPIES[case.copy])
    return run_lookup_spec(case.world)

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


RAMPS = {}


def ramp(count, start):
    key = (count, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 7) & 0xFF or 1 for index in range(count))
    return RAMPS[key]


def rotate(value, count):
    return ((value << count) | (value >> (64 - count))) & MAX64


def sip_rounds(state, count):
    v0, v1, v2, v3 = state
    for _ in range(count):
        v0 = (v0 + v1) & MAX64
        v1 = rotate(v1, 13) ^ v0
        v0 = rotate(v0, 32)
        v2 = (v2 + v3) & MAX64
        v3 = rotate(v3, 16) ^ v2
        v0 = (v0 + v3) & MAX64
        v3 = rotate(v3, 21) ^ v0
        v2 = (v2 + v1) & MAX64
        v1 = rotate(v1, 17) ^ v2
        v2 = rotate(v2, 32)
    return [v0, v1, v2, v3]


def sip13(k0, k1, data):
    """SipHash 1-3 over the raw bytes, the sum that 0x399c7a0 and 0x399c650 finish with."""
    state = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]
    whole = len(data) // 8 * 8
    for at in range(0, whole, 8):
        word = struct.unpack_from("<Q", data, at)[0]
        state[3] ^= word
        state = sip_rounds(state, 1)
        state[0] ^= word
    last = int.from_bytes(data[whole:], "little") | len(data) << 56
    state[3] ^= last
    state = sip_rounds(state, 1)
    state[0] ^= last
    state[2] ^= 0xFF
    state = sip_rounds(state, 3)
    return state[0] ^ state[1] ^ state[2] ^ state[3]


KEYS = ((0x1122334455667788, 0x99AABBCCDDEEFF10), (0x0123456789ABCDEF, 0xFEDCBA9876543211))


class Table:
    """One hashbrown table: control bytes, buckets below them; `block` full groups come before an entry."""

    def __init__(self, harness, slots, stride, keys):
        self.h = harness
        self.mask = slots - 1
        self.stride = stride
        self.keys = keys
        self.size = slots * stride
        self.base = harness.table_space(self.size + slots + 16)
        self.ctrl = self.base + self.size
        self.bytes = bytearray(b"\xff" * (slots + 16))

    def take(self, at, value):
        self.bytes[at] = value
        if at < 16:
            self.bytes[self.mask + 1 + at] = value

    def slot(self, key, block):
        hashed = sip13(self.keys[0], self.keys[1], key)
        top = hashed >> 57
        pos = hashed & self.mask
        stride = 0
        for _ in range(block):
            for step in range(16):
                at = (pos + step) & self.mask
                if self.bytes[at] == 0xFF:
                    self.take(at, top)
            stride += 16
            pos = (pos + stride) & self.mask
        for step in range(16):
            at = (pos + step) & self.mask
            if self.bytes[at] == 0xFF:
                self.take(at, top)
                return at
        raise EvidenceError("table group full")

    def twin(self, key):
        """First free slot of the group of `key`, marked with the control byte of `key`; a decoy goes there."""
        hashed = sip13(self.keys[0], self.keys[1], key)
        for step in range(16):
            at = (hashed + step) & self.mask
            if self.bytes[at] == 0xFF:
                self.take(at, hashed >> 57)
                return at
        raise EvidenceError("table group full")

    def spacers(self, plan):
        """Fill the next free slots of a key's group with another control byte, so the matches sit a fixed distance apart."""
        if plan:
            hashed = sip13(self.keys[0], self.keys[1], plan[0])
            for _ in range(plan[1]):
                self.take(next(at for at in ((hashed + step) & self.mask for step in range(16)) if self.bytes[at] == 0xFF), (hashed >> 57) ^ 1)

    def bucket(self, at):
        return self.ctrl - (at + 1) * self.stride

    def finish(self, memory, header, items):
        memory.put_bytes(self.ctrl, bytes(self.bytes))
        memory.write(header, 8, self.ctrl)
        memory.write(header + 8, 8, self.mask)
        memory.write(header + 0x10, 8, 0)
        memory.write(header + 0x18, 8, items)
        memory.write(header + 0x20, 8, self.keys[0])
        memory.write(header + 0x28, 8, self.keys[1])


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_RESOLVE: self.on_resolve, SLOT_SAMPLE: self.on_sample, SLOT_FIRST: self.on_first, SLOT_SECOND: self.on_second, 0x5773D58: self.on_grow, 0x5773D50: self.on_grow,
                 SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, 0x576E470: self.on_bounds, 0x576E048: self.on_unwrap}
        for slot in SLOT_PANIC:
            table.setdefault(slot, self.on_other_panic)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        machine.slots[HOOK_TARGET] = self.on_hook
        self.real = RealExcept()
        machine.real = self.real
        calls = {DROP_WORD: self.on_drop, CLOCK: self.on_clock, ELAPSED: self.on_elapsed, WIRE_SPOT: self.on_wire}
        for copy in COPIES:
            calls.update({copy.remove: self.on_remove_perp, copy.spot_remove: self.on_remove_spot, copy.flush: self.on_flush_perp, copy.spot_flush: self.on_flush_spot})
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.w = None
        self.row_size = PERP_ROW
        self.copy = COPIES[0]
        self.brk = HEAP_FREE
        self.table_brk = TABLES
        self.live = {}
        self.log = []
        self.ticks = 0
        self.vector = 0
        self.samples = iter(())
        self.locations = {}

    # ---- stubs ----

    def location(self, at):
        if at not in self.locations:
            size = struct.unpack_from("<Q", self.image.blob, self.image.offset(at + 8))[0]
            start = self.image.offset(self.relative[at])
            self.locations[at] = bytes(self.image.blob[start:start + size]).decode("ascii").rsplit("/", 1)[1][:-3]
        return self.locations[at]

    def on_drop(self, m):
        if m.memory.read(m.regs[RDI], 2) != 0x141:
            raise Halt("drop word")

    def on_bounds(self, m):
        raise Panicked(self.location(m.regs[RDI]))

    def on_unwrap(self, m):
        if m.regs[RSI] != 0x2B or m.memory.read(m.regs[RDX], 2) != 0x141:
            raise Halt("unwrap arguments")
        raise Panicked(self.location(m.regs[R8]))

    def on_other_panic(self, m):
        raise Halt("other panic")

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def table_space(self, size):
        at = (self.table_brk + 15) & ~15
        self.table_brk = at + size
        if self.table_brk > TABLES + TABLE_AREA:
            raise Halt("table area full")
        return at

    def on_malloc(self, m):
        if m.regs[RDI] > 0x4000:
            raise Halt("allocation size")
        self.log.append(["malloc", m.regs[RDI]])
        m.regs[RAX] = self.allocate(m.regs[RDI])

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))
        self.log.append(["free", size])

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x4000:
            raise Halt("copy size")
        if regs[RDX] > 0x100 and regs[RDX] != self.row_size:
            raise Halt("row size")
        if regs[RDX] == self.row_size:
            vector = self.vector
            stride = regs[RDX]
            capacity, buffer, length = (m.memory.read(vector + index * 8, 8) for index in range(3))
            if length >= capacity or regs[RDI] != buffer + length * stride:
                raise Halt("row address")
            if m.memory.read(regs[RSI], 8) != 3 or m.memory.read(regs[RSI] + 8, 8) != 4:
                raise Halt("row words")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_grow(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        slot_stride = PERP_ROW if m.call_target == self.relative[0x5773D58] else SPOT_ROW
        self.row_size = slot_stride
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if vector != (self.vector or vector) or capacity > 0x100 or memory.read(vector + 0x10, 8) != capacity:
            raise Halt("vector size")
        self.vector = vector
        self.log.append(["grow", capacity, slot_stride])
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * slot_stride)
        if capacity:
            memory.copy(fresh, old, capacity * slot_stride)
            if self.live.pop(old, None) != capacity * slot_stride:
                raise Halt("vector buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_sample(self, m):
        if m.regs[RDI] & MASK[4] != SAMPLE_ARGUMENT:
            raise Halt("sample argument")
        self.log.append(["sample"])
        m.regs[RAX] = 0x5500 | int(next(self.samples))

    def on_first(self, m):
        self.predicate(m, "first", self.w["first"])

    def on_second(self, m):
        self.predicate(m, "second", self.w["second"])

    def predicate(self, m, name, value):
        if m.regs[RDI] != USER_ARG:
            raise Halt("predicate argument")
        self.log.append([name])
        m.regs[RAX] = 0x5500 | int(value)

    def on_clock(self, m):
        if m.regs[RDI] & MASK[4] != 1:
            raise Halt("clock argument")
        self.ticks += 1
        self.log.append(["clock"])
        m.regs[RAX] = 1000 + self.ticks
        m.regs[RDX] = 100 + self.ticks
        m.keep_rdx = True

    def on_elapsed(self, m):
        memory = m.memory
        later = [memory.read(m.regs[RSI], 8), memory.read(m.regs[RSI] + 8, 4)]
        earlier = [memory.read(m.regs[RDX], 8), memory.read(m.regs[RDX] + 8, 4)]
        self.log.append(["elapsed", later, earlier])

    def on_resolve(self, m):
        regs = m.regs
        memory = m.memory
        copy = self.copy
        if regs[RDX] != STATE + copy.names or regs[RCX] != STATE + 0x90:
            raise Halt("resolve arguments")
        asset = regs[RSI] & MASK[4]
        self.log.append(["resolve", asset])
        route = self.w["routes"][asset]
        at = regs[RDI]
        if route[0] == "error":
            memory.write(at, 2, route[1])
            memory.put_bytes(at + 2, ramp(0x5E, asset & 0xFF))
            return
        memory.write(at, 2, TAG_OK)
        memory.write(at + 8, 4, {"spot": 1, "perp": 0, "third": 2}[route[0]])
        memory.write(at + 0x10, 8, route[1])

    def book_name(self, at):
        if SPOT_BOOKS <= at < SPOT_BOOKS + 0x1000:
            index, rest = divmod(at - SPOT_BOOKS, BOOK_STRIDE)
            if rest:
                raise Halt("spot book address")
            return ["spot", index]
        if self.w.get("shift"):
            if at != BOOKS:
                raise Halt("shifted book address")
            return ["perp", self.w["shift"][0], self.w["shift"][1]]
        dex, rest = divmod(at - BOOKS, BOOK_AREA)
        local, rest = divmod(rest, BOOK_STRIDE)
        if rest or not 0 <= dex < 8:
            raise Halt("book address")
        return ["perp", dex, local]

    def on_remove(self, m, label, stride):
        regs = m.regs
        memory = m.memory
        w = self.w
        if regs[RCX] != STATE or memory.bytes_at(regs[RSI], USER_SIZE) != w["user"]:
            raise Halt("remove arguments")
        oid = regs[RDX]
        self.log.append([label, self.book_name(regs[RDI]), oid, regs[R9] & 0xFF])
        vector = regs[R8]
        self.vector = vector
        self.row_size = stride
        rows = w["rows"].get(oid, 0)
        if memory.read(vector, 8) or memory.read(vector + 8, 8) != 8 or memory.read(vector + 0x10, 8):
            raise Halt("rows vector not empty")
        if rows:
            buffer = self.allocate(4 * stride)
            memory.write(vector, 8, 4)
            memory.write(vector + 8, 8, buffer)
            memory.write(vector + 0x10, 8, rows)
            for index in range(rows):
                memory.write(buffer + index * stride, 8, 0x40 + index)
        regs[RAX] = 0x7700 | int(oid in w["absent"])

    def on_remove_perp(self, m):
        self.on_remove(m, "perp", PERP_ROW)

    def on_remove_spot(self, m):
        self.on_remove(m, "spot", SPOT_ROW)

    def on_flush(self, m, label, dex, stride):
        memory = m.memory
        at = m.regs[RDI]
        capacity, buffer, length = (memory.read(at + index * 8, 8) for index in range(3))
        if not 0 < length <= capacity or capacity > 0x100:
            raise Halt("flush vector")
        for index in range(length - 1):
            if memory.read(buffer + index * stride, 8) != 0x40 + index:
                raise Halt("flush row")
        if memory.read(buffer + (length - 1) * stride, 8) != 3 or memory.read(buffer + (length - 1) * stride + 8, 8) != 4:
            raise Halt("flush last row")
        if self.live.pop(buffer, None) != capacity * stride:
            raise Halt("flush buffer")
        self.log.append(["flush", label, dex, length])
        self.vector = 0

    def on_flush_perp(self, m):
        if m.regs[RDX] != STATE:
            raise Halt("flush state")
        self.on_flush(m, "perp", m.regs[RSI], PERP_ROW)

    def on_flush_spot(self, m):
        if m.regs[RSI] != STATE:
            raise Halt("flush state")
        self.on_flush(m, "spot", None, SPOT_ROW)

    def on_wire(self, m):
        regs = m.regs
        if regs[RDI] & MASK[4] != 1 or regs[RDX] != STATE + 0x90:
            raise Halt("wire arguments")
        self.log.append(["wire", regs[RSI]])
        regs[RAX] = 0x77000000 | regs[RSI]

    def on_hook(self, m):
        regs = m.regs
        if regs[RDI] != HOOK_DATA or m.memory.bytes_at(regs[RSI], USER_SIZE) != self.w["user"]:
            raise Halt("hook arguments")
        self.log.append(["hook", regs[RDX], [regs[RCX], regs[R8] & MASK[4]]])

    # ---- world ----

    def write_inner(self, at, entries, spec):
        memory = self.machine.memory
        table = Table(self, spec.get("slots", 16), 0x18, KEYS[1])
        count = 0
        for key, decoy in spec.get("twins", ()):
            bucket = table.bucket(table.twin(key))
            memory.put_bytes(bucket, decoy)
            memory.write(bucket + 0x10, 8, 0x9999)
        table.spacers(spec.get("spacers"))
        for key, oid in entries.items():
            bucket = table.bucket(table.slot(key, spec.get("block", 0)))
            memory.put_bytes(bucket, key)
            memory.write(bucket + 0x10, 8, oid)
            count += 1
        for key, oid in spec.get("near", ()):
            at_slot = table.slot(key, 0)
            bucket = table.bucket(at_slot)
            memory.put_bytes(bucket, key)
            memory.write(bucket + 0x10, 8, oid)
        table.finish(memory, at, spec.get("items", count))

    def write_map(self, at, users, spec):
        """Book map user -> inner map; `spec` holds rare shapes: slot counts, groups to skip, a near key."""
        memory = self.machine.memory
        table = Table(self, spec.get("user_slots", 8), 0x78, KEYS[0])
        for key, decoy in spec.get("user_twins", ()):
            bucket = table.bucket(table.twin(key))
            memory.put_bytes(bucket, ramp(0x78, 0x41))
            memory.put_bytes(bucket, decoy)
        table.spacers(spec.get("user_spacers"))
        for user, entries in users.items():
            bucket = table.bucket(table.slot(user, spec.get("user_block", 0)))
            memory.put_bytes(bucket, ramp(0x78, 0x31))
            memory.put_bytes(bucket, user)
            self.write_inner(bucket + 0x48, entries, spec)
        for user in spec.get("near_users", ()):
            bucket = table.bucket(table.slot(user, 0))
            memory.put_bytes(bucket, ramp(0x78, 0x41))
            memory.put_bytes(bucket, user)
        table.finish(memory, at, spec.get("user_items", len(users) + len(spec.get("near_users", ()))))

    def setup(self, w, copy):
        memory = self.machine.memory
        memory.put_bytes(STATE, ramp(STATE_SIZE, 0x13))
        memory.write(STATE + copy.count, 8, w["count"])
        memory.write(STATE + copy.done, 8, w["done"])
        memory.write(STATE + copy.hook, 8, HOOK_DATA if w["hook"] else 0)
        memory.write(STATE + copy.hook + 8, 8, HOOK_TABLE)
        memory.write(HOOK_TABLE + 0x38, 8, HOOK_TARGET)
        memory.write(STATE + copy.closed, 1, w["closed"])
        shift = w.get("shift")
        memory.write(STATE + copy.rows, 8, (ROWS - shift[0] * ROW_STRIDE if shift else ROWS) & MAX64)
        memory.write(STATE + copy.rows_len, 8, w["rows_len"])
        memory.write(STATE + copy.dex_len, 8, w["dex_len"])
        memory.write(STATE + copy.spot_rows, 8, SPOT_BOOKS)
        memory.write(STATE + copy.spot_len, 8, w["spot_len"])
        memory.put_bytes(USER_ARG, w["user"])
        if shift:
            memory.put_bytes(ROWS, ramp(ROW_STRIDE, 0x51))
            memory.write(ROWS + 8, 8, (BOOKS - shift[1] * BOOK_STRIDE) & MAX64)
            memory.write(ROWS + 0x10, 8, shift[1] + 1)
            self.write_book(BOOKS, w, ("perp", shift[0], shift[1]))
            return
        for dex in range(max(w["rows_len"], 2)):
            row = ROWS + dex * ROW_STRIDE
            memory.put_bytes(row, ramp(ROW_STRIDE, 0x51 + dex))
            memory.write(row + 8, 8, BOOKS + dex * BOOK_AREA)
            memory.write(row + 0x10, 8, w["books"].get(dex, 0))
            for local in range(w["books"].get(dex, 0)):
                self.write_book(BOOKS + dex * BOOK_AREA + local * BOOK_STRIDE, w, ("perp", dex, local))
        for index in range(w["spot_len"]):
            self.write_book(SPOT_BOOKS + index * BOOK_STRIDE, w, ("spot", index))

    def write_book(self, at, w, name):
        memory = self.machine.memory
        memory.put_bytes(at, ramp(BOOK_STRIDE, 0x61))
        users = w["maps"].get(name)
        if users:
            self.write_map(at + 0x48, users, w.get("shape", {}))
        else:
            memory.write(at + 0x60, 8, 0)

    def clean(self, w):
        self.w = w
        self.log = []
        self.live = {}
        self.ticks = 0
        self.vector = 0
        self.table_brk = TABLES
        self.samples = iter(w.get("samples", ()))
        self.machine.memory.reset(self.brk - HEAP_BASE)
        self.brk = HEAP_FREE

    def read_results(self, buffer, count):
        memory = self.machine.memory
        rows = []
        for index in range(count):
            at = buffer + index * RESULT_SIZE
            rows.append(self.read_result(at))
        return rows

    def read_result(self, at):
        memory = self.machine.memory
        tag = memory.read(at, 2)
        row = {"tag": tag}
        if tag == TAG_NOT_FOUND:
            row["asset"] = memory.read(at + 4, 4)
        elif tag not in (TAG_OK, TAG_SPOT_OFF):
            row["payload"] = memory.bytes_at(at + 2, 0x5E).hex()
        return row

    def run_core(self, case, w):
        copy = COPIES[case.copy]
        self.copy = copy
        memory = self.machine.memory
        self.setup(w, copy)
        items = w["items"]
        stride = 0x14 if w["by"] == "cloid" else 0x10
        capacity = w["capacity"]
        buffer = self.allocate(capacity * stride) if capacity else 8
        for index, item in enumerate(items):
            at = buffer + index * stride
            if w["by"] == "cloid":
                memory.put_bytes(at, item["cloid"])
                memory.write(at + 0x10, 4, item["asset"])
            else:
                memory.write(at, 8, item["oid"])
                memory.write(at + 8, 4, item["asset"])
                memory.write(at + 12, 4, 0x55555555)
        memory.write(VEC_ARG, 8, capacity)
        memory.write(VEC_ARG + 8, 8, buffer)
        memory.write(VEC_ARG + 0x10, 8, w.get("claimed", len(items)))
        entry = copy.core_cloid if w["by"] == "cloid" else copy.core_oid
        try:
            self.machine.run(entry, {RDI: OUT, RSI: STATE, RDX: USER_ARG, RCX: VEC_ARG})
        except Panicked as panic:
            return {"log": self.log, "panic": str(panic)}
        count = memory.read(STATE + copy.count, 8)
        done = memory.read(STATE + copy.done, 8)
        word = memory.read(OUT, 2)
        mark = memory.bytes_at(STATE + copy.mark, 8) == memory.bytes_at(STATE + 0x60, 8) and memory.bytes_at(STATE + copy.mark_low, 4) == memory.bytes_at(STATE + 0x68, 4)
        bare_mark = memory.bytes_at(STATE + copy.mark, 8) == ramp(STATE_SIZE, 0x13)[copy.mark:copy.mark + 8] and memory.bytes_at(STATE + copy.mark_low, 4) == ramp(STATE_SIZE, 0x13)[copy.mark_low:copy.mark_low + 4]
        if not mark and not bare_mark:
            raise Halt("mark half written")
        found = {"log": self.log, "word": word, "count": count, "done": done, "mark": mark, "live": sorted(self.live.values())}
        if word == TAG_OK:
            capacity, buffer, length = (memory.read(OUT + 8 + index * 8, 8) for index in range(3))
            if length > 0x40:
                raise Halt("result length")
            found.update({"capacity": capacity, "length": length, "results": self.read_results(buffer, length)})
            if not capacity:
                found["empty_pointer"] = buffer
        else:
            found["rejected"] = memory.read(OUT + 0x18, 8)
        return found

    def run_item(self, case, w):
        copy = COPIES[case.copy]
        self.copy = copy
        memory = self.machine.memory
        self.setup(w, copy)
        item = w["items"][0]
        memory.write(ASSET_ARG, 4, item["asset"])
        memory.put_bytes(RECORD_ARG, ramp(0x18, 0x21))
        if "cloid" in item:
            memory.write(RECORD_ARG, 1, 1)
            memory.put_bytes(RECORD_ARG + 1, item["cloid"])
        else:
            memory.write(RECORD_ARG, 1, 0)
            memory.write(RECORD_ARG + 8, 8, item["oid"])
        memory.write(TUPLE, 8, USER_ARG)
        memory.write(TUPLE + 8, 8, ASSET_ARG)
        memory.write(TUPLE + 0x10, 8, RECORD_ARG)
        try:
            self.machine.run(copy.item, {RDI: OUT, RSI: STATE, RDX: w["first_byte"], RCX: w["second_byte"], R8: TUPLE})
        except Panicked as panic:
            return {"log": self.log, "panic": str(panic)}
        return {"log": self.log, "result": self.read_result(OUT), "done": memory.read(STATE + copy.done, 8)}

    def run_lookup(self, case, w):
        memory = self.machine.memory
        table = HEAP_BASE + 0x1000
        users = w["maps"].get(("book",), {})
        self.write_map(table, users, w.get("shape", {}))
        memory.put_bytes(USER_ARG, w["user"])
        memory.put_bytes(RECORD_ARG, w["cloid"])
        al = self.machine.run(LOOKUP, {RDI: table, RSI: USER_ARG, RDX: RECORD_ARG}) & 0xFF
        return {"found": al != 0, "oid": self.machine.regs[RDX] if al else None}

    def run(self, case):
        w = case.world
        self.clean(w)
        return {"core": self.run_core, "item": self.run_item, "lookup": self.run_lookup}[case.kind](case, w)


def spec_run(case):
    return run_spec(case)


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError, UnicodeDecodeError, StopIteration)


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

USER = ramp(USER_SIZE, 0x91)
OTHER_USER = ramp(USER_SIZE, 0x92)


def cloid(number):
    return ramp(16, 0x10 + number)


def world(**changes):
    base = {
        "by": "oid", "items": [], "capacity": None, "user": USER, "count": 40, "done": 7, "first": False, "second": False, "samples": [], "hook": True, "closed": 0,
        "rows_len": 3, "dex_len": 3, "spot_len": 4, "books": {0: 4, 1: 3, 2: 3}, "maps": {}, "absent": set(), "rows": {}, "routes": {},
    }
    base.update(changes)
    if base["capacity"] is None:
        base["capacity"] = len(base["items"])
    return base


def perp(number):
    return ("perp", number)


def batch_cases(copy):
    add = []

    def one(label, **changes):
        changes.setdefault("samples", [False] * len(changes.get("items", ())))
        add.append(Case("%s: %s" % (COPIES[copy].name, label), "core", world(**changes), copy))

    one("empty list")
    one("empty list, spare capacity", capacity=3)
    one("empty list, first predicate", first=True)
    one("empty list, second predicate", second=True)
    one("empty list, both predicates", first=True, second=True)
    one("empty list, counter near the top", count=MAX64 - 1)
    one("empty client id list", by="cloid")
    one("empty client id list, spare capacity", by="cloid", capacity=2)
    one("rare length at the limit", items=[], claimed=LIST_LIMIT, capacity=4)
    one("rare length above the limit", items=[], claimed=LIST_LIMIT + 7, capacity=0)
    one("rare client id length at the limit", by="cloid", items=[], claimed=LIST_LIMIT, capacity=4)
    one("rare client id length above the limit", by="cloid", items=[], claimed=LIST_LIMIT + 7, capacity=0)
    one("oid present, dex 0", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)})
    one("oid present, spare capacity", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, capacity=5)
    one("oid absent, dex 0", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, absent={501})
    one("oid present, no hook", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, hook=False)
    one("oid absent, no hook", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, absent={501}, hook=False)
    one("oid present, sampled", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, samples=[True])
    one("oid absent, sampled", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, samples=[True], absent={501})
    one("user byte 0 is no gate byte", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, user=b"\x00\x01" + USER[2:], samples=[True])
    one("oid present, second dex", items=[{"asset": 7, "oid": 502}], routes={7: perp(10001)})
    one("oid absent, second dex", items=[{"asset": 7, "oid": 502}], routes={7: perp(10001)}, absent={502})
    one("oid present, resolver kind 2 reads as perp", items=[{"asset": 7, "oid": 502}], routes={7: ("third", 1)})
    one("rare dex at the row limit", items=[{"asset": 7, "oid": 502}], routes={7: perp(30000)})
    one("rare dex above the row limit", items=[{"asset": 7, "oid": 502}], routes={7: perp(70002)})
    one("rare local at the book limit", items=[{"asset": 7, "oid": 502}], routes={7: perp(10003)})
    one("rare local below the book limit", items=[{"asset": 7, "oid": 502}], routes={7: perp(10002)})
    one("rare first book of a dex", items=[{"asset": 7, "oid": 502}], routes={7: perp(20000)})
    one("rare absent, dex at the second limit", items=[{"asset": 7, "oid": 502}], routes={7: perp(20001)}, dex_len=2, absent={502})
    one("rare present, dex at the second limit", items=[{"asset": 7, "oid": 502}], routes={7: perp(20001)}, dex_len=2)
    one("rare absent, dex below the second limit", items=[{"asset": 7, "oid": 502}], routes={7: perp(10001)}, dex_len=2, absent={502})
    one("rows from removal, room left", items=[{"asset": 2, "oid": 503}], routes={2: perp(2)}, rows={503: 2})
    one("rows from removal, vector full", items=[{"asset": 2, "oid": 503}], routes={2: perp(2)}, rows={503: 4})
    one("spot rows from removal, room left", items=[{"asset": 2, "oid": 503}], routes={2: ("spot", 1)}, rows={503: 2})
    one("spot rows from removal, vector full", items=[{"asset": 2, "oid": 503}], routes={2: ("spot", 1)}, rows={503: 4})
    one("spot present", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 1)})
    one("spot absent", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 1)}, absent={601})
    one("spot present, no hook", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 1)}, hook=False)
    one("spot absent, sampled", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 1)}, absent={601}, samples=[True])
    one("spot closed", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 1)}, closed=1)
    one("spot closed, byte 2", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 1)}, closed=2)
    one("rare spot at the limit", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 4)})
    one("rare spot last book", items=[{"asset": 10001, "oid": 601}], routes={10001: ("spot", 3)})
    one("resolver error", items=[{"asset": 9, "oid": 700}], routes={9: ("error", 0x141)})
    one("resolver error, sampled", items=[{"asset": 9, "oid": 700}], routes={9: ("error", 0x60)}, samples=[True])
    one("counter at the top", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, count=MAX64 - 2, done=MAX64 - 1)
    one("done counter full", items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, done=MAX64)
    one("mixed list", items=[{"asset": 2, "oid": 501}, {"asset": 3, "oid": 502}, {"asset": 4, "oid": 503}, {"asset": 5, "oid": 504}, {"asset": 2, "oid": 505}],
        routes={2: perp(2), 3: ("spot", 2), 4: perp(10002), 5: ("error", 0x77)}, absent={503, 505}, rows={502: 2}, samples=[False, True, False, True, False], first=True)
    client = {"maps": {("perp", 0, 2): {USER: {cloid(1): 811, cloid(2): 812}}, ("spot", 2): {USER: {cloid(3): 813}}}}
    one("client id found", by="cloid", items=[{"asset": 2, "cloid": cloid(1)}], routes={2: perp(2)}, **client)
    one("client id found, removal says absent", by="cloid", items=[{"asset": 2, "cloid": cloid(1)}], routes={2: perp(2)}, absent={811}, **client)
    one("client id unknown", by="cloid", items=[{"asset": 2, "cloid": cloid(9)}], routes={2: perp(2)}, **client)
    one("client id of another book", by="cloid", items=[{"asset": 3, "cloid": cloid(1)}], routes={3: perp(1)}, **client)
    one("client id, spare capacity", by="cloid", items=[{"asset": 2, "cloid": cloid(2)}], routes={2: perp(2)}, capacity=6, **client)
    one("client id spot found", by="cloid", items=[{"asset": 3, "cloid": cloid(3)}], routes={3: ("spot", 2)}, **client)
    one("client id spot unknown", by="cloid", items=[{"asset": 3, "cloid": cloid(1)}], routes={3: ("spot", 2)}, **client)
    one("client id spot of another book", by="cloid", items=[{"asset": 3, "cloid": cloid(3)}], routes={3: ("spot", 1)}, **client)
    one("client id spot, removal says absent", by="cloid", items=[{"asset": 3, "cloid": cloid(3)}], routes={3: ("spot", 2)}, absent={813}, **client)
    one("client id spot closed", by="cloid", items=[{"asset": 3, "cloid": cloid(3)}], routes={3: ("spot", 2)}, closed=1, **client)
    one("client id, other user", by="cloid", user=OTHER_USER, items=[{"asset": 2, "cloid": cloid(1)}], routes={2: perp(2)}, **client)
    one("client id list", by="cloid", items=[{"asset": 2, "cloid": cloid(1)}, {"asset": 3, "cloid": cloid(3)}, {"asset": 2, "cloid": cloid(7)}, {"asset": 2, "cloid": cloid(2)}],
        routes={2: perp(2), 3: ("spot", 2)}, rows={812: 4}, samples=[True, False, True, False], second=True, **client)
    return add


def gate_cases():
    add = []
    for copy in range(3):
        for first in (0, 1, 2, 0x80):
            for second in range(0x12):
                if first and second not in (0, 1):
                    continue
                for sampled in (False, True):
                    add.append(Case("%s: gate %d %d %d" % (COPIES[copy].name, first, second, sampled), "item",
                                    world(items=[{"asset": 2, "oid": 501}], routes={2: perp(2)}, samples=[sampled] * 2, first_byte=first, second_byte=second), copy))
    return add


def item_cases():
    """The wire form of the asset: only the `not found` arm shows it.  A shifted row pointer puts any dex and local index on one mapped book."""
    add = []
    for copy in range(3):
        for packed in (0, 1, 2, 9999, 10000, 10001, 19999, 20000, 99899998, 99899999, 99900000, 99900001, 0xFFFFFFFF, 1 << 33):
            dex, local = packed // 10000, packed % 10000
            for missing in (True, False):
                add.append(Case("%s: wire exact %d %s" % (COPIES[copy].name, packed, "absent" if missing else "present"), "item",
                                world(items=[{"asset": 2, "oid": 501}], routes={2: perp(packed)}, absent={501} if missing else set(), first_byte=1, second_byte=0, samples=[False],
                                      rows_len=dex + 1, dex_len=dex + 1, books={dex: local + 1}, shift=(dex, local)), copy))
    return add


def lookup_cases():
    add = []
    key = cloid(1)
    near_user = USER[:16] + bytes(4)
    near_head = bytes(4) + USER[4:]
    base = {USER: {key: 0x1234567890}, OTHER_USER: {cloid(2): 0x77}}

    def one(label, maps, shape=None, user=USER, wanted=key):
        add.append(Case("first: lookup %s" % label, "lookup", {"maps": {("book",): maps}, "shape": shape or {}, "user": user, "cloid": wanted}, 0))

    one("empty map", {}, {"user_items": 0})
    one("rare empty map with a tempting row", {USER: {key: 5}}, {"user_items": 0})
    one("user found", base)
    one("second user", base, user=OTHER_USER, wanted=cloid(2))
    one("unknown user", base, user=ramp(USER_SIZE, 0x93))
    one("key of another user", base, user=OTHER_USER)
    one("unknown key", base, wanted=cloid(3))
    one("rare inner map empty with a tempting row", {USER: {key: 5}}, {"items": 0})
    one("rare inner map empty", {USER: {}})
    one("rare wide maps", base, {"user_slots": 64, "slots": 64})
    one("rare user past a full group", base, {"user_slots": 64, "user_block": 1})
    one("rare user past two full groups", base, {"user_slots": 128, "user_block": 2})
    one("rare key past a full group", base, {"slots": 64, "block": 1})
    one("rare key past two full groups", base, {"slots": 128, "block": 2})
    one("rare unknown key past a full group", base, {"slots": 64, "block": 1}, wanted=cloid(3))
    one("rare unknown user past a full group", base, {"user_slots": 64, "user_block": 1}, user=ramp(USER_SIZE, 0x93))
    many = {ramp(USER_SIZE, 0x20 + index): {ramp(16, 0x30 + index): 0x500 + index, ramp(16, 0x60 + index): 0x600 + index} for index in range(6)}
    for index in range(6):
        one("many row %d" % index, many, {"user_slots": 16, "slots": 16}, user=ramp(USER_SIZE, 0x20 + index), wanted=ramp(16, 0x60 + index))
    for name, near in (("tail", near_user), ("head", near_head)):
        one("rare near user %s" % name, base, {"near_users": [near]}, user=USER)
        one("rare twin user %s" % name, base, {"user_twins": [(USER, near)], "user_slots": 64})
        one("rare twin user %s, spaced" % name, base, {"user_twins": [(USER, near)], "user_slots": 64, "user_spacers": (USER, 2)})
        one("rare twin user %s, unknown key" % name, base, {"user_twins": [(USER, near)], "user_slots": 64}, wanted=cloid(3))
    for name, near in (("tail", key[:8] + bytes(8)), ("head", bytes(8) + key[8:])):
        one("rare twin key %s" % name, base, {"twins": [(key, near)], "slots": 64})
        one("rare twin key %s, spaced" % name, base, {"twins": [(key, near)], "slots": 64, "spacers": (key, 2)})
        one("rare twin key %s, twice" % name, base, {"twins": [(key, near), (key, near[::-1])], "slots": 64})
        one("rare twin key %s, unknown" % name, base, {"twins": [(cloid(3), near)], "slots": 64}, wanted=cloid(3))
    return add


def all_cases():
    add = []
    for copy in range(3):
        add += batch_cases(copy)
    return add + item_cases() + gate_cases() + lookup_cases()

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


GROUPS = tuple((value, role) for copy in COPIES for value, role in (
    (copy.worker, copy.name + " worker: result vector"),
    (copy.closure, copy.name + " closure: one item per record"),
    (copy.item, copy.name + " item: gate, route, book, status"),
    (copy.spot, copy.name + " spot arm"))) + (
    (0x2518AD0, "first oid preparer"), (0x251A940, "first client id preparer"), (0x47F8410, "second oid preparer"), (0x47F7070, "second client id preparer"), (LOOKUP, "book map: user and client id to oid"))
EXTRA_FUNCTIONS = tuple((value, role) for copy in COPIES for value, role in ((copy.core_oid, copy.name + " oid core, run with no mutants"), (copy.core_cloid, copy.name + " client id core, run with no mutants")))
CASE_CAP = 120
PATH_CASES = 3
RARE_WORDS = ("rare", "wire exact", "gate", "lookup", "second limit")


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
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

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


def image_slot(image, slot):
    for address, kind, addend, _ in image.relocations():
        if address == slot and kind == 8:
            return addend
    raise EvidenceError("no relocation at %#x" % slot)


FIELDS = {
    "wire_oid": {"size": "0x10 bytes", "+0x00": "oid", "+0x08": "asset, dword"},
    "wire_client_id": {"size": "0x14 bytes", "+0x00": "client id, 16 bytes", "+0x10": "asset, dword"},
    "record": {"size": "0x20 bytes, one per wire row, none dropped", "+0x00": "asset, dword", "+0x08": "byte: 0 oid, 1 client id", "+0x09": "client id, 16 bytes", "+0x10": "oid when the byte is 0"},
    "result": {"size": "0x60 bytes", "+0x00": "status word", "+0x02": "bytes of a resolver error", "+0x04": "wire asset, dword, for 0xc5"},
    "item_tuple": {"+0x00": "pointer to the 20 byte user", "+0x08": "pointer to the asset dword", "+0x10": "pointer to the record from +0x08"},
    "state": {"count": "+0x878 first and second, +0x12f8 third: list length, saturating (core, no mutants here)", "done": "+0x880 or +0x1300: raised by one per item with status 0x186, saturating", "hook": "+0x3a88 and +0x3a90 or +0x4508 and +0x4510: optional boxed object, method at table +0x38, called once per item that reached a book",
              "spot off": "+0x3ac8 or +0x4548: any nonzero byte gives 0xf9 on the spot route", "rows": "+0x3370 and +0x3378 or +0x3df0 and +0x3df8: dex rows, stride 0x138, row +0x08 books, row +0x10 count, book stride 0xd8", "dex length": "+0x5c8 or +0x1048: second bound, read only by the not found arm",
              "names": "+0x5b8 or +0x1038: resolver argument", "spot rows": "+0x3388 and +0x3390 or +0x3e08 and +0x3e10: spot books, stride 0xd8", "resolver": "+0x90: resolver and spot wire argument"},
    "book_map": {"book offset": "+0x48, the field the book serde writers name user_trackers", "+0x00/+0x08": "control bytes, mask", "+0x18": "items; 0 means not found at once", "+0x20": "two SipHash 1-3 keys", "bucket": "0x78 bytes: user at +0x00, inner map at +0x48"},
    "inner_map": {"+0x48/+0x50 of the bucket": "control bytes, mask", "+0x60": "items; 0 means not found", "+0x68": "two SipHash 1-3 keys", "bucket": "0x18 bytes: client id, then oid at +0x10"},
    "closing_row": {"+0x00": "3", "+0x08": "4", "rest": "stack bytes, nothing written", "stride": "0x278 perp, 0x268 spot"},
}
REFERENCE_CLAIMS = (
    {"reference": "l1/exchange/handlers/03_cancel.rs:84", "claim": "abstract cancel_perp and cancel_spot", "observed": "item 0x275a380 and spot arm 0x2726af0 are the bodies: book, map, removal with reason 2, closing row, flush, status", "verdict": "no body in the reference"},
    {"reference": "l1/exchange/handlers/03_cancel.rs:57", "claim": "CancelItemResult holds target, route and ActionResult with user, asset and effects", "observed": "the result is 0x60 bytes: status word plus the error bytes or a wire asset dword", "verdict": "shape not found"},
    {"reference": "l1/exchange/handlers/03_cancel.rs:129", "claim": "the spot route always calls cancel_spot", "observed": "state byte +0x3ac8 stops it first with status 0xf9 Spot disabled, with no hook and no counter", "verdict": "missing in the reference"},
    {"reference": "l1/exchange/handlers/03_cancel.rs:20", "claim": "the zero control byte makes Cancel resolve by oid", "observed": "agrees: preparer 0x2518ad0 writes 0, preparer 0x251a940 writes 1", "verdict": "agrees"},
)
COPY_PAIRS = (
    (0x24BBCF0, 0x4447770), (0x24BBCF0, 0x4449010), (0x251A180, 0x47F65D0), (0x251A180, 0x47F66E0), (0x4D85940, 0x4D85290), (0x4D2E640, 0x4D2E810), (0x2721120, 0x4D25E40), (0x2725010, 0x4D2B140), (0x4D25E40, 0x4D25F80), (0x4D2B140, 0x4D2B280),
)
STATE_PAIRS = ((0x3A88, 0x4508), (0x3A90, 0x4510), (0x880, 0x1300), (0x878, 0x12F8), (0x5B8, 0x1038), (0x3AC8, 0x4548), (0x3370, 0x3DF0), (0x3378, 0x3DF8), (0x5C8, 0x1048), (0x3388, 0x3E08), (0x3390, 0x3E10), (0x3A98, 0x4518), (0x3AA0, 0x4520), (0x3380, 0x3E00), (0x34E0, 0x3F60))
SIZES_THAT_DIFFER = ((0x275A380, 0x4D85940), (0x2726AF0, 0x4D2E640), (0x2518AD0, 0x47F8410), (0x251A940, 0x47F7070))


def copy_table(image):
    """Same bytes after masking, except the rows listed, which differ only in a state field displacement."""
    rows = []
    for first, second in COPY_PAIRS:
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
            pair = next((pair for pair in STATE_PAIRS if one.replace(struct.pack("<I", pair[0]), struct.pack("<I", pair[1])) == two), None)
            if pair is None:
                raise EvidenceError("copy row %#x differs" % row.va)
            changed.append({"offset": "%#x" % at, "field": "%#x / %#x" % pair})
        rows.append({"first": "%#x" % first, "second": "%#x" % second, "size": len(left), "first_sha256": hashlib.sha256(left).hexdigest(), "second_sha256": hashlib.sha256(right).hexdigest(), "state_rows": changed})
    return rows


def size_rows(image):
    """Pairs that do not compare byte for byte; the same specification runs on both."""
    rows = []
    for first, second in SIZES_THAT_DIFFER:
        one, two = image.exact_fde(first), image.exact_fde(second)
        rows.append({"first": "%#x" % first, "first_size": one[1] - one[0], "second": "%#x" % second, "second_size": two[1] - two[0]})
    return rows


def location_rows(image):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    rows = []
    for at, used in ((0x56E9B28, "dex at or above the rows length, perp route"), (0x56E9AE0, "dex at or above the dex length, not found arm"), (0x56BB478, "local index or spot index at or above the book count"), (0x5742338, "spot index, second and third spot arms")):
        size = struct.unpack_from("<Q", image.blob, image.offset(at + 8))[0]
        start = image.offset(relative[at])
        text = bytes(image.blob[start:start + size]).decode("ascii")
        line, column = struct.unpack_from("<II", image.blob, image.offset(at + 16))
        rows.append({"location": "%#x" % at, "file": text[text.index("l1/src/"):], "line": line, "column": column, "use": used})
    return rows


def text_of_not_found(image):
    """Status 0xc5 prints a fixed text and the wire asset: arm -> formatter -> text; arm -> template."""
    arm = code(image, NOT_FOUND_ARM, 0x24)
    if arm[:4] != b"\x48\x8d\x47\x02":
        raise EvidenceError("not found arm")
    formatter = NOT_FOUND_ARM + 0x1B + 7 + struct.unpack_from("<i", arm, 0x1E)[0]
    if formatter != 0x3998370:
        raise EvidenceError("not found formatter %#x" % formatter)
    body = code(image, NOT_FOUND_TEXT_SITE, 12)
    if body[7] != 0xBA:
        raise EvidenceError("not found text length")
    text = fixed_text(image, rip_target(image, NOT_FOUND_TEXT_SITE), struct.unpack_from("<I", body, 8)[0])
    template = rip_target(image, NOT_FOUND_TEMPLATE_SITE)
    return {"arm": "%#x" % NOT_FOUND_ARM, "formatter": "%#x" % formatter, "text": text, "template": "%#x" % template, "template_bytes": code(image, template, 11).hex()}


def tag_rows(image):
    rows = [{"tag": "%#x" % tag, "text": arm_text(image, TAG_TEXTS, tag) or "no fixed text in the arm", "use": use} for tag, use in ((TAG_TOO_LONG, "core: list of 10001 or more (no mutants here)"), (0x141, "Result word dropped after each bound"), (TAG_SPOT_OFF, "item: spot route with the state byte set"))]
    rows.append({"tag": "%#x" % TAG_NOT_FOUND, "text": text_of_not_found(image)["text"] + " asset=<wire asset>", "use": "item and spot arm: nothing was removed, the row and the flush still ran"})
    rows.append({"tag": "%#x" % TAG_OK, "text": "no fixed text in the arm", "use": "item: removed"})
    return rows


def wire_table():
    return [{"packed": packed, "wire": wire_asset(packed)} for packed in (0, 9999, 10000, 10001, 99899999, 99900000)]


def gate_table():
    return [{"first_byte": first, "second_byte": second, "clock": "runs" if timed_by_gate(first, second) else "sampled, argument 50"} for first in (0, 2) for second in range(16)]


def host_rows(image):
    """Calls into the path by exact byte patterns."""
    targets = sorted({value for copy in COPIES for value in (copy.closure, copy.item, copy.spot, copy.worker, copy.prepare_oid, copy.prepare_cloid)} | {copy.remove for copy in COPIES})
    direct = direct_sites(image, targets)
    rows = []
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for slot, target in sorted(SLOT_NAMES.items()):
        if image_slot(image, slot) != target:
            raise EvidenceError("slot %#x" % slot)
    for va in slot_sites(image, 0x5774AA0):
        rows.append((LOOKUP, va, "slot 0x5774aa0", image.fde(va)[0], image.fde(va)[1]))
    return rows


def outcome_name(case, spec):
    if case.kind == "lookup":
        return "lookup found" if spec["found"] else "lookup none"
    if spec.get("panic"):
        return "%s panic %s" % (case.kind, spec["panic"])
    if case.kind == "item":
        return "item status %#x" % spec["result"]["tag"]
    if spec["word"] != TAG_OK:
        return "core list too long"
    return "core list of %d" % min(spec["length"], 2)


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
        "pairs_of_other_size": size_rows(image),
        "copy_names": [copy._asdict() for copy in COPIES],
        "locations": location_rows(image),
        "tags": tag_rows(image),
        "not_found": text_of_not_found(image),
        "fields": FIELDS,
        "wire_table": wire_table(),
        "gate_table": gate_table(),
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
    }



def survivor_reasons():
    """Why each surviving row cannot change a run; the classes come from probing the rows, see the README."""
    table = {}
    for copy_at, rows in (
        ((0x251A192, 0x47F65E2, 0x47F66F2), "buffer and iterator start are the same word of a fresh list, so +0x00 reads the same pointer"),
        ((0x24BBD01, 0x4447781, 0x4449021), "buffer and iterator start are the same word of a fresh list, so +0x00 reads the same pointer"),
        ((0x2518ADE, 0x47F841E, 0x251A951, 0x47F7081), "buffer and iterator start are the same word of a fresh list, so +0x00 reads the same pointer"),
        ((0x251A196, 0x47F65E6, 0x47F66F6, 0x2518AF0, 0x47F8430, 0x2518B00, 0x47F8440, 0x251A97B, 0x47F70AB, 0x251A98B, 0x47F70BB), "size limit of an allocation; only a list above 2^58 bytes reaches it, and the list limit is 10000 rows"),
        ((0x251A1E8, 0x47F6638, 0x47F6748), "start of a word that the closure overwrites before anything reads it"),
        ((0x24BBD4D, 0x44477CD, 0x444906D), "scales the start index, which is always 0 here"),
        ((0x24BBDD3, 0x4447853, 0x44490F3), "the second gate byte: the first gate byte is always 2 or 3 on this path, so the item never reads it"),
        ((0x24BBE1E, 0x444789E, 0x444913E), "both arms write the status; they differ only in stale bytes after a status of 0x186, which nothing reads"),
        ((0x275A39E, 0x4D8595E, 0x4D852AE), "0xe to 0xf: bit 15 of the mask is 0, so 0xf falls to the same arm"),
        ((0x275A582, 0x2726B04, 0x2726B0B), "address written to a stack word that is overwritten before any read"),
        ((0x4D85B35, 0x4D85B41, 0x4D85B4D, 0x4D85485, 0x4D85491, 0x4D8549D, 0x4D2E651, 0x4D2E65A, 0x4D2E663, 0x4D2E821, 0x4D2E82A, 0x4D2E833), "first of two identical writes of the empty vector; the second one wins"),
        ((0x2518B27, 0x47F8467), "size test for a request below 8 bytes; a list of records is 0x20 bytes or 0"),
        ((0x2518B35, 0x47F8475, 0x251AA48, 0x47F7174), "pointer of an empty record list; it is never read and never freed"),
        ((0x342A475, 0x342A559), "low dwords are equal after the word shuffle, so this shuffle bit picks the same value"),
    ):
        for va in copy_at:
            table[va] = rows
    return table


SURVIVED_DEFAULT = "pending"
SURVIVED_REASONS = survivor_reasons()


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
