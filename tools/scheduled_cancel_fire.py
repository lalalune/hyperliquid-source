#!/usr/bin/env python3
"""Pin the node #94 scheduled cancel firing path from ELF bytes: due test, day reset, market walk, user sweep.

`0x2702760` and its copies run in the block hosts. They walk the per-user schedule map, mark each due
entry, then for each due user call the market selector with reason 0xf and no TWAP sweep. The selector
is shared with the 0x10 and 0xd callers. Under it the closures walk books and the per-user sweep removes
orders in key order. When the date moved, the same map is cleaned by the retain step. The real bytes run
in a Python evaluator with only the edges stubbed. A separately written specification predicts every edge
call, and every condition, immediate and field offset of one copy of each function is flipped to show the
run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

CLOCK = 0x4EE3800
ELAPSED = 0x4EE3730
RESULT_DROP = 0x3379490
STATUS_FN = 0x4A9A1A0
STATUS_TABLE = 0x7038DC
REASON_SCHEDULED = 0xF
REASON_LIQUIDATED = 0xD
REASON_INTERNAL = 0x10
SELECT_ALL = 2
ERROR_WORD = 0x141
MISSING_WORD = 0xCE
TERMINATED_WORD = 0x8000000000000001
ROW_TAG = 4
NO_ENTRY = 0x8000000000000000
BOOK_STRIDE = 0xD8
META_STRIDE = 0x2F0
COLLECTION_STRIDE = 0x138
SLOT_STRIDE = 0xF8
ID_RATIO = 10000
DAY_LIMIT_NOTE = 10

SLOT_MEMCMP = 0x576E488
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_UNWRAP = 0x576E048
SLOT_NO_CATCH = 0x576E128
SLOT_ONCE = 0x576E8B8
SLOT_REALLOC = 0x576E030
SLOT_REALLOC_ALIGNED = 0x576E288
SLOT_GROW_USERS = 0x5773C68
SLOT_GROW_PERP_ROW = 0x5773D58
SLOT_GROW_SPOT_ROW = 0x5773D50
SLOT_SORT = 0x5774F50
SLOT_NAMES = {SLOT_MEMCMP: "memcmp, stubbed", SLOT_ALLOC: "allocate, stubbed", SLOT_ALLOC_FAILED: "allocation failure", SLOT_FREE: "free, stubbed", SLOT_MEMCPY: "memcpy, stubbed",
              SLOT_MEMMOVE: "memmove, stubbed", SLOT_PANIC: "panic with Location", SLOT_BOUNDS: "index bounds panic", SLOT_UNWRAP: "Result unwrap panic", SLOT_ONCE: "lazy static init, stubbed",
              SLOT_GROW_USERS: "grow the due user vector, stubbed", SLOT_GROW_PERP_ROW: "grow the 0x278 row vector, stubbed", SLOT_GROW_SPOT_ROW: "grow the 0x268 row vector, stubbed", SLOT_SORT: "large sort, stubbed",
              SLOT_REALLOC: "reallocate, stubbed", SLOT_REALLOC_ALIGNED: "reallocate with alignment, stubbed"}
ONCE_WORD = 0x577AB98

LOC_BOOK_INDEX = 0x56BB478
LOC_PERP_ROW = 0x56E9AE0
LOC_SELECT = 0x56E9B28
LOC_NEXT_ROOT = 0x56C23A0
LOC_NEXT_LOOP = 0x56C23B8
LOCATION_NAMES = {LOC_BOOK_INDEX: "book index past the collection", LOC_SELECT: "selector, dex index past the collections", LOC_PERP_ROW: "TWAP row, dex index past the metadata",
                  LOC_NEXT_ROOT: "schedule map walk, past the root", LOC_NEXT_LOOP: "schedule map walk, no front handle"}

# Field maps are the same in the first two copies; the third adds 0xa80 to the map, and its selector to the rest.
COPIES = (
    dict(name="first", fire=0x2702760, host=0x22297C0, site=0x2229DB0, select=0x270F1C0, retain=0x27E8AD0, range=0x1B25410, perp=0x27031B0, spot=0x2703080, flush_dex=0x24FB610, flush_spot=0x24FC8A0,
         vote=0x2355F40, vote_site=0x2359B3D, liq=0x2731030, liq_site=0x2731153, fire_site=0x2702B4F, map=0x39A8),
    dict(name="second", fire=0x4CEF8F0, host=0x470E9A0, site=0x470EF90, select=0x4D005D0, retain=0x4898630, range=0x42B98C0, perp=0x4C63F20, spot=0x4C641C0, flush_dex=0x4329870, flush_spot=0x432B440,
         vote=0x4CAA870, vote_site=0x4CAE44F, liq=0x4D3B330, liq_site=0x4D3B453, fire_site=0x4CEFCDF, map=0x39A8),
    dict(name="third", fire=0x4CEF2F0, host=0x47162D0, site=0x4716958, select=0x4D000A0, retain=0x489AEC0, range=0x42B98C0, perp=0x4C64300, spot=0x4C64080, flush_dex=0x432A100, flush_spot=0x432A990,
         vote=0x4CB3200, vote_site=0x4CB6DDF, liq=0x4D3B5C0, liq_site=0x4D3B6E3, fire_site=0x4CEF6DF, map=0x4428),
)
FIRST = COPIES[0]
SWEEP_PERP = 0x26E3EF0
SWEEP_SPOT = 0x26E4240
REMOVE_PERP = 0x26DF430
REMOVE_SPOT = 0x26DE3D0
TWAP_SPOT = 0x26DDBE0
SET_NEXT = 0x286B520
PERP_COLLECT = 0x2574B40
SPOT_COLLECT = 0x2569980
PERP_TAKE = 0x2867BD0
SPOT_TAKE = 0x2868790
PERP_USER_OUT = 0x2867820
SPOT_USER_OUT = 0x2868060
PERP_DRAIN = 0x286E140
SPOT_DRAIN = 0x28AF080
PERP_MAKE = 0x23118B0
SPOT_MAKE = 0x2311450
NOT_FOUND_DROP = 0x277EBA0
PERP_MAP_OUT = 0x2866F90
SPOT_MAP_OUT = 0x2865CA0
PERP_ENTRY_DROP = 0x2784F00
SPOT_ENTRY_DROP = 0x2785030

MAP_NODE = dict(parent=0, values=8, value=0x18, keys=0x110, index=0x1EC, length=0x1EE, edges=0x1F0, leaf=0x1F0, inner=0x250)
USER_NODE = dict(parent=0x370, values=0, value=0x50, keys=0x378, index=0x454, length=0x456, edges=0x458, leaf=0x458, inner=0x4B8)
SET_NODE = dict(parent=0, keys=8, index=0x60, length=0x62, edges=0x68, size=0xC8)
SECOND_NODE = dict(parent=0, keys=8, index=0x848, length=0x84A, edges=0x850, size=0x8B0)
NODE_KEYS = 11
LEAF_EDGE = 0x7300000000

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
MUTANT_STEP_LIMIT = 150000
FAKE_MEMCPY = 0x7E000010
FAKE_MEMMOVE = 0x7E000020
FAKE_MEMCMP = 0x7E000030
FAKE_REALLOC = 0x7E000040

EX = HEAP_BASE + 0x1000
USER = EX + 0x8000
PREV = USER + 0x40
RECORD = PREV + 0x40
EVENTS = RECORD + 0x80
BUMP = EVENTS + 0x100

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
    """20 non-periodic bytes; the first byte orders them."""
    return bytes((number * 17 + 3 + index * (number | 1) * 29) & 0xFF if index else number & 0xFF for index in range(20))


def signed32(value):
    return value - (1 << 32) if value & 0x80000000 else value


class Entry:
    def __init__(self, user, count=0, date=0, sec=0, nanos=0):
        self.user, self.count, self.date, self.sec, self.nanos = user, count, date, sec, nanos


class Case:
    """Inputs of one run; `kind` picks the entry point and the rest default to a plain state."""

    def __init__(self, label, kind, **fields):
        self.label, self.kind = label, kind
        self.entries = []
        self.now = (20000, 3600, 5000)
        self.prev = 20000
        self.claimed = None
        self.null_root = False
        self.lazy = 0
        self.width = 11
        self.selector = 2
        self.asset = 0
        self.reason = REASON_SCHEDULED
        self.flag = 0
        self.dexes = []
        self.collections = 2
        self.alloc_fails = False
        self.grown = False
        self.books = 0
        self.twaps = None
        self.metas = 2
        self.ids = []
        self.rows = {}
        self.users = {}
        self.slab = []
        self.absent = False
        self.spot = False
        self.chain = True
        self.claimed_none = False
        self.drain = 0
        self.others = []
        self.first = []
        self.second = []
        self.__dict__.update(fields)


class SpecPanic(Exception):
    pass


def is_due(entry, now):
    if entry.date == 0:
        return False
    date, moment = signed32(entry.date), (entry.sec, entry.nanos)
    if date != signed32(now[0]):
        return date < signed32(now[0])
    return moment <= (now[1], now[2])


def spec_fire(case, copy):
    entries = sorted((Entry(e.user, e.count, e.date, e.sec, e.nanos) for e in case.entries), key=lambda e: e.user)
    length = len(entries) if case.claimed is None else case.claimed
    events = [("clock",)]
    if case.null_root:
        entries = []
    walk = entries if case.claimed is None else entries[:case.claimed]
    due = []
    for entry in walk:
        if is_due(entry, case.now):
            due.append(entry.user)
            entry.count = min(entry.count + 1, MASK[8])
            entry.date = 0
    for user in due:
        events.append(("select", user.hex(), SELECT_ALL, REASON_SCHEDULED, 0))
    if due:
        capacity = 4
        while capacity < len(due):
            capacity *= 2
        events.append(("free", capacity * 20))
    events.append(("clock",))
    events.append(("elapsed",))
    if due and case.lazy:
        events.append(("once",))
    if signed32(case.prev) < signed32(case.now[0]) and not case.null_root:
        kept = []
        for entry in entries:
            entry.count = 0
            if entry.date:
                kept.append(entry)
        length -= len(entries) - len(kept)
        entries = kept
    return {"stop": None, "events": events, "entries": [(e.user.hex(), e.count, e.date, e.sec, e.nanos) for e in entries], "length": length}


def spec_select(case, copy):
    events = []
    result = {"stop": None, "events": events}

    def perp(dex, selector, asset):
        if dex >= case.collections:
            result["stop"] = ("unwrap", ERROR_WORD, LOC_SELECT)
            raise SpecPanic()
        events.append(("drop", ERROR_WORD))
        events.append(("perp", selector, asset if selector else None, dex, case.reason, case.flag))
        events.append(("flush dex", dex, 8 + dex))

    def spot(selector, asset):
        events.append(("spot", selector, asset if selector else None, case.reason, case.flag))
        events.append(("flush spot", 77))

    try:
        if case.selector == 2:
            if case.dexes:
                events.append(("alloc", len(case.dexes) * 8))
                if case.alloc_fails:
                    result["stop"] = ("alloc failed", 8, len(case.dexes) * 8)
                    return result
                for dex in case.dexes:
                    perp(dex, 0, 0)
                events.append(("free", len(case.dexes) * 8))
            spot(0, 0)
        elif case.selector & 1:
            spot(1, case.asset)
        else:
            perp(case.asset // ID_RATIO, 1, case.asset)
    except SpecPanic:
        pass
    return result


def spec_closure(case, copy):
    events = []
    result = {"stop": None, "events": events, "tail": None}
    spot_kind = case.kind == "closure spot"
    index = case.asset if spot_kind else case.asset % ID_RATIO
    if case.selector == 1:
        if index >= case.books:
            result["stop"] = ("panic", LOC_BOOK_INDEX)
            return result
        chosen = [index]
    else:
        chosen = range(case.books)
    for number in chosen:
        events.append(("sweep", number, case.reason))
    if case.flag and spot_kind:
        events.append(("twap spot", case.selector, case.asset))
    if case.flag and not spot_kind:
        spec_twap(case, events, result, False)
    return result


def spec_twap(case, events, result, spot_kind):
    users = {key: list(value) for key, value in case.users.items()}
    me = user_id(1)
    if me not in users:
        return
    events.append(("collect", len(users[me]), case.selector, case.asset))
    pushed = 0
    capacity = 2 if case.grown else 64
    for number in case.ids:
        if me not in users:
            events.append(("missing",))
            continue
        if number not in users[me]:
            events.append(("take", number, False))
            events.append(("missing",))
            continue
        users[me].remove(number)
        events.append(("take", number, True))
        if not users[me]:
            del users[me]
            events.append(("user out", case.drain))
            events += [("drain step",)] * (1 if spot_kind else case.drain + 1)
        if not spot_kind:
            dex = case.rows.get(number, 0) // ID_RATIO
            if dex >= case.metas:
                result["stop"] = ("unwrap", ERROR_WORD, LOC_PERP_ROW)
                return
            events.append(("drop", ERROR_WORD))
            events.append(("make", dex, number))
        else:
            events.append(("make spot", number))
        if pushed == capacity:
            events.append(("grow",))
            capacity *= 2
        events.append(("row", number))
        pushed += 1
    if case.ids:
        events.append(("list free", len(case.ids) * 8))


def spec_user_sweep(case, copy):
    events = []
    result = {"stop": None, "events": events}
    me = user_id(1)
    if case.absent:
        return result
    first, second = case.first, case.second
    keys = []
    for index in first:
        if index >= len(case.slab):
            continue
        tag, flag, key = case.slab[index]
        if tag & MASK[4] == 2:
            continue
        if not case.chain and flag == 1:
            continue
        keys.append(key)
    if case.chain:
        keys += list(second)
    order = sorted(set(keys))
    for key in order:
        events.append(("remove", key, case.reason))
    if case.chain:
        events.append(("map out",))
        if not case.claimed_none:
            events.append(("entry drop",))
    return result


def spec_run(case, copy=None):
    copy = copy or FIRST
    if case.kind == "fire":
        return spec_fire(case, copy)
    if case.kind == "select":
        return spec_select(case, copy)
    if case.kind in ("closure spot", "closure perp"):
        return spec_closure(case, copy)
    if case.kind == "twap spot":
        result = {"stop": None, "events": []}
        spec_twap(case, result["events"], result, True)
        return result
    return spec_user_sweep(case, copy)


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

def ramp(size, start):
    """Non-periodic filler, so that a wrong field offset reads a wrong value."""
    return bytes((start + index * 37) & 0xFF | 1 for index in range(size))


def copy_fields(copy):
    shift = 0xA80 if copy["name"] == "third" else 0
    return dict(metas=0x5C0 + shift, perps=0x3370 + shift, spots=0x3380 + shift, spot_tracker=0x34E0 + shift)


class Harness:
    def __init__(self, image, copy=FIRST):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        for slot in (SLOT_ALLOC, SLOT_ALLOC_FAILED, SLOT_FREE, SLOT_PANIC, SLOT_BOUNDS, SLOT_UNWRAP, SLOT_ONCE, SLOT_GROW_USERS, SLOT_GROW_PERP_ROW, SLOT_GROW_SPOT_ROW, SLOT_SORT):
            machine.memory.statics[slot] = relative[slot]
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.memory.statics[SLOT_MEMMOVE] = FAKE_MEMMOVE
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.memory.statics[SLOT_REALLOC] = FAKE_REALLOC
        machine.memory.statics[SLOT_REALLOC_ALIGNED] = FAKE_REALLOC
        machine.slots = {relative[SLOT_SORT]: self.on_sort, relative[SLOT_ALLOC]: self.on_alloc, relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed, relative[SLOT_FREE]: self.on_free, relative[SLOT_PANIC]: self.on_panic,
                         relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_UNWRAP]: self.on_unwrap, relative[SLOT_ONCE]: self.on_once, relative[SLOT_GROW_USERS]: self.on_grow_users,
                         relative[SLOT_GROW_PERP_ROW]: self.on_grow_row, relative[SLOT_GROW_SPOT_ROW]: self.on_grow_row,
                         FAKE_MEMCPY: self.on_memcpy, FAKE_MEMMOVE: self.on_memcpy, FAKE_MEMCMP: self.on_memcmp, FAKE_REALLOC: self.on_realloc}
        self.reach = {}
        self.select(copy)
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.clock = 0

    def select(self, copy):
        self.copy = copy
        self.fields = copy_fields(copy)

    def closure(self, roots):
        """Every function reachable by direct calls from the roots, stopping at `calls`."""
        calls = self.machine.calls
        key = (tuple(roots), tuple(sorted(calls)))
        if key not in self.reach:
            found, work = set(), list(roots)
            while work:
                start = work.pop()
                if start in found or start in calls:
                    continue
                found.add(start)
                for target in call_targets(self.image, start):
                    if self.image.named[".plt"]["address"] <= target < self.image.named[".plt"]["address"] + self.image.named[".plt"]["size"]:
                        continue
                    work.append(target)
            self.reach[key] = frozenset(found)
        self.machine.real = self.reach[key]

    # layout helpers

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def build_map(self, at, rows, shape, write_value, width, tempt=None):
        """(root, height, length) at `at` for a map with 20-byte keys, leaf edges unmapped."""
        memory = self.machine.memory

        def make(items, parent, slot, level):
            size = shape["inner"] if level else shape["leaf"]
            node = self.alloc(size)
            self.nodes[node] = size
            memory.put_bytes(node, ramp(size, level + 9))
            self.put(node + shape["parent"], 8, parent)
            self.put(node + shape["index"], 2, slot)
            separators, children = split(items, width, level)
            self.put(node + shape["length"], 2, len(separators))
            for index, row in enumerate(separators):
                memory.put_bytes(node + shape["keys"] + index * 20, row[0])
                self.key_at = node + shape["keys"] + index * 20
                write_value(node + shape["values"] + index * shape["value"], row)
            if tempt is not None:
                for index in range(len(separators), NODE_KEYS):
                    memory.put_bytes(node + shape["keys"] + index * 20, tempt)
            if level:
                for index, child in enumerate(children):
                    self.put(node + shape["edges"] + index * 8, 8, make(child, node, index, level - 1))
            return node

        level = tree_height(len(rows), width)
        self.put(at, 8, make(list(rows), 0, 0, level))
        self.put(at + 8, 8, level)
        self.put(at + 0x10, 8, len(rows))

    def build_set(self, at, keys, shape, width=11):
        memory = self.machine.memory

        def make(items, parent, slot, level):
            node = self.alloc(shape["size"])
            memory.put_bytes(node, bytes(shape["size"]))
            memory.put_bytes(node + shape["edges"], struct.pack("<Q", LEAF_EDGE) * 12)
            self.put(node + shape["parent"], 8, parent)
            self.put(node + shape["index"], 2, slot)
            separators, children = split(items, width, level)
            self.put(node + shape["length"], 2, len(separators))
            for index, key in enumerate(separators):
                self.put(node + shape["keys"] + index * 8, 8, key)
            for index in range(len(separators), NODE_KEYS):
                self.put(node + shape["keys"] + index * 8, 8, 0x7654321)
            if level:
                for index, child in enumerate(children):
                    self.put(node + shape["edges"] + index * 8, 8, make(child, node, index, level - 1))
            return node

        if keys:
            level = tree_height(len(keys), width)
            self.put(at, 8, make(list(keys), 0, 0, level))
            self.put(at + 8, 8, level)
            self.put(at + 0x10, 8, len(keys))
        else:
            self.put(at, 8, 0)
            self.put(at + 8, 8, 0x4142)
            self.put(at + 0x10, 8, 0x77)

    def read_map(self, at, shape):
        memory = self.machine.memory
        rows = []

        def walk(node, level):
            count = memory.read(node + shape["length"], 2)
            if count > NODE_KEYS or level > 16 or len(rows) > 4096:
                raise Halt("tree shape")
            for index in range(count + 1):
                if level:
                    walk(memory.read(node + shape["edges"] + index * 8, 8), level - 1)
                if index < count:
                    value = node + shape["values"] + index * shape["value"]
                    rows.append((memory.bytes_at(node + shape["keys"] + index * 20, 20).hex(), memory.read(value, 8), memory.read(value + 8, 4), memory.read(value + 12, 4), memory.read(value + 16, 4)))

        root = memory.read(at, 8)
        if root:
            walk(root, memory.read(at + 8, 8))
        return rows

    def start(self, case):
        memory = self.machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.nodes = {}
        self.case = case
        self.clock = 0
        self.grown = 0
        self.machine.memory.statics[ONCE_WORD] = case.lazy

    # shared stubs

    def from_entry(self, m):
        return self.entry_range[0] <= m.call_site < self.entry_range[1]

    def on_alloc(self, m):
        size = m.regs[RDI]
        if self.from_entry(m):
            self.events.append(("alloc", size))
            if self.case.alloc_fails:
                m.regs[RAX] = 0
                return
        at = self.alloc(size)
        self.live[at] = size
        m.regs[RAX] = at

    def on_free(self, m):
        pointer, size = m.regs[RDI], m.regs[RSI]
        if self.nodes.get(pointer) == size:
            del self.nodes[pointer]
            return
        if self.live.pop(pointer, None) != size:
            raise Halt("free of a block that does not match: %#x %#x" % (pointer, size))
        if m.regs[RDX] & MASK[4]:
            raise Halt("free flag")
        if self.from_entry(m):
            self.events.append(("list free" if self.case.kind.startswith(("twap", "closure")) else "free", size))

    def on_realloc(self, m):
        pointer, size = m.regs[RDI], m.regs[RSI]
        old = self.live.pop(pointer, None)
        if old is None:
            raise Halt("realloc of an unknown block")
        at = self.alloc(size)
        self.live[at] = size
        m.memory.copy(at, pointer, min(old, size))
        m.regs[RAX] = at

    def on_sort(self, m):
        pointer, count = m.regs[RDI], m.regs[RSI]
        if count > 4096:
            raise Halt("sort length")
        values = sorted(m.memory.read(pointer + index * 8, 8) for index in range(count))
        for index, value in enumerate(values):
            self.put(pointer + index * 8, 8, value)

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
        raise Panicked(("alloc failed", m.regs[RDI], m.regs[RSI]))

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_unwrap(self, m):
        if m.regs[RSI] != 0x2B:
            raise Halt("unwrap text")
        raise Panicked(("unwrap", m.memory.read(m.regs[RDX], 2), m.regs[R8]))

    def on_once(self, m):
        if m.regs[RDI] != ONCE_WORD or m.regs[RSI] & MASK[4] != 1:
            raise Halt("once arguments")
        self.events.append(("once",))

    def on_grow_users(self, m):
        vec = m.regs[RDI]
        read = m.memory.read
        capacity, pointer, size = read(vec, 8), read(vec + 8, 8), read(vec + 0x10, 8)
        if not capacity and pointer != 1:
            raise Halt("empty vector pointer")
        new = max(capacity * 2, 4)
        at = self.alloc(new * 20)
        self.live[at] = new * 20
        if capacity:
            m.memory.copy(at, pointer, size * 20)
            self.live.pop(pointer)
        self.put(vec, 8, new)
        self.put(vec + 8, 8, at)

    def on_grow_row(self, m):
        vec = m.regs[RDI]
        if vec != EVENTS:
            raise Halt("row vector")
        read = m.memory.read
        spot = self.case.kind == "twap spot"
        if m.regs[RDI] != EVENTS or m.call_target != self.relative[SLOT_GROW_SPOT_ROW if spot else SLOT_GROW_PERP_ROW]:
            raise Halt("row grow slot")
        capacity, pointer, size = read(vec, 8), read(vec + 8, 8), read(vec + 0x10, 8)
        if size != capacity:
            raise Halt("grow while not full")
        stride = 0x268 if spot else 0x278
        at = self.alloc((capacity * 2) * stride)
        m.memory.copy(at, pointer, size * stride)
        self.put(vec, 8, capacity * 2)
        self.put(vec + 8, 8, at)
        self.row_base = at
        self.events.append(("grow",))

    # fire

    def on_clock(self, m):
        if m.regs[RDI] & MASK[4] != 1:
            raise Halt("clock id")
        self.clock += 1
        self.events.append(("clock",))
        m.regs[RAX] = 0x1000 + self.clock
        m.regs[RDX] = self.clock
        m.keep_rdx = True

    def on_elapsed(self, m):
        read = m.memory.read
        if (read(m.regs[RSI], 8), read(m.regs[RSI] + 8, 4), read(m.regs[RDX], 8), read(m.regs[RDX] + 8, 4)) != (0x1002, 2, 0x1001, 1):
            raise Halt("elapsed arguments")
        self.events.append(("elapsed",))

    def on_fire_select(self, m):
        if m.regs[RDI] != EX:
            raise Halt("selector state")
        self.events.append(("select", m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX], m.regs[R8] & MASK[4], m.regs[R9] & MASK[4]))

    def write_entry(self, value, row):
        entry = row[1]
        self.put(value, 8, entry.count)
        self.put(value + 8, 4, entry.date)
        self.put(value + 12, 4, entry.sec)
        self.put(value + 16, 4, entry.nanos)

    def run_fire(self, case):
        copy = self.copy
        machine = self.machine
        machine.calls = {CLOCK: self.on_clock, ELAPSED: self.on_elapsed, copy["select"]: self.on_fire_select}
        self.closure([copy["fire"], copy["retain"], copy["range"]])
        machine.jump_low, machine.jump_high = self.image.exact_fde(copy["range"])
        self.entry_range = self.image.exact_fde(copy["fire"])
        self.start(case)
        memory = machine.memory
        memory.put_bytes(EX, ramp(0x60, 31))
        for index, value in enumerate(case.now):
            self.put(EX + 0x60 + index * 4, 4, value)
        at = EX + copy["map"]
        rows = sorted(((e.user, e) for e in case.entries), key=lambda row: row[0])
        self.build_map(at, rows, MAP_NODE, self.write_entry, case.width)
        if case.null_root:
            self.put(at, 8, 0)
        if case.claimed is not None:
            self.put(at + 0x10, 8, case.claimed)
        self.put(PREV, 4, case.prev)
        self.put(PREV + 4, 4, 0x51525354)
        machine.run(copy["fire"], {RDI: EX, RSI: PREV})
        if self.live:
            raise Halt("blocks still live")
        length = memory.read(at + 0x10, 8)
        return {"stop": None, "events": self.events, "entries": self.read_map(at, MAP_NODE), "length": length}

    # select

    def closure_record(self, m):
        read = m.memory.read
        rec = m.regs[RDI]
        return dict(selector=read(rec, 8), asset=read(rec + 8, 8), first=read(rec + 0x10, 8), second=read(rec + 0x18, 8), ex=read(rec + 0x20, 8), vec=read(rec + 0x28, 8),
                    user=m.memory.bytes_at(rec + 0x30, 20), flag=read(rec + 0x44, 1), reason=read(rec + 0x45, 1))

    def check_vec(self, m, row):
        read = m.memory.read
        if row["ex"] != EX or row["user"] != user_id(1):
            raise Halt("closure record")
        vec = row["vec"]
        if (read(vec, 8), read(vec + 8, 8), read(vec + 0x10, 8)) != (0, 8, 0):
            raise Halt("event vector start")
        return vec

    def on_perp(self, m):
        row = self.closure_record(m)
        vec = self.check_vec(m, row)
        base = self.collections
        dex = (row["first"] - base) // COLLECTION_STRIDE
        if row["first"] != base + dex * COLLECTION_STRIDE or row["second"] != row["first"] + 0x18:
            raise Halt("collection pointers")
        self.events.append(("perp", row["selector"], row["asset"] if row["selector"] else None, dex, row["reason"], row["flag"]))
        self.put(vec, 8, 0x1100 + dex)
        self.put(vec + 8, 8, 0x2200 + dex)
        self.put(vec + 0x10, 8, 8 + dex)

    def on_spot(self, m):
        row = self.closure_record(m)
        vec = self.check_vec(m, row)
        if row["first"] != EX + self.fields["spots"] or row["second"] != EX + self.fields["spot_tracker"]:
            raise Halt("spot pointers")
        self.events.append(("spot", row["selector"], row["asset"] if row["selector"] else None, row["reason"], row["flag"]))
        self.put(vec, 8, 0x3300)
        self.put(vec + 8, 8, 0x4400)
        self.put(vec + 0x10, 8, 77)

    def on_flush_dex(self, m):
        read = m.memory.read
        rec, dex = m.regs[RDI], m.regs[RSI]
        if m.regs[RDX] != EX or (read(rec, 8), read(rec + 8, 8)) != (0x1100 + dex, 0x2200 + dex):
            raise Halt("flush dex")
        self.events.append(("flush dex", dex, read(rec + 0x10, 8)))

    def on_flush_spot(self, m):
        read = m.memory.read
        rec = m.regs[RDI]
        if m.regs[RSI] != EX or (read(rec, 8), read(rec + 8, 8)) != (0x3300, 0x4400):
            raise Halt("flush spot")
        self.events.append(("flush spot", read(rec + 0x10, 8)))

    def on_drop(self, m):
        self.events.append(("drop", m.memory.read(m.regs[RDI], 2)))

    def run_select(self, case):
        copy = self.copy
        fields = self.fields
        machine = self.machine
        machine.calls = {RESULT_DROP: self.on_drop, copy["perp"]: self.on_perp, copy["spot"]: self.on_spot, copy["flush_dex"]: self.on_flush_dex, copy["flush_spot"]: self.on_flush_spot}
        machine.real = frozenset({copy["select"]})
        self.entry_range = self.image.exact_fde(copy["select"])
        self.start(case)
        memory = machine.memory
        metas = self.alloc(META_STRIDE * max(len(case.dexes), 1))
        for index, dex in enumerate(case.dexes):
            memory.put_bytes(metas + index * META_STRIDE, ramp(META_STRIDE, index + 11))
            self.put(metas + index * META_STRIDE + 0x30, 8, dex)
        self.put(EX + fields["metas"], 8, metas)
        self.put(EX + fields["metas"] + 8, 8, len(case.dexes))
        self.collections = self.alloc(COLLECTION_STRIDE * max(case.collections, 1))
        self.put(EX + fields["perps"], 8, self.collections)
        self.put(EX + fields["perps"] + 8, 8, case.collections)
        memory.put_bytes(USER, user_id(1))
        machine.run(copy["select"], {RDI: EX, RSI: USER, RDX: case.selector, RCX: case.asset, R8: case.reason, R9: case.flag})
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events}

    # closures and the TWAP sweep

    def on_sweep(self, m):
        spot = self.case.kind == "closure spot"
        book, user = m.regs[RDI], m.memory.bytes_at(m.regs[RSI], 20)
        number = (book - self.books) // BOOK_STRIDE
        if book != self.books + number * BOOK_STRIDE or user != user_id(1):
            raise Halt("sweep book")
        if spot:
            if m.regs[RDX] & MASK[4] != 1 or m.regs[RCX] != EX or m.regs[R8] != EVENTS:
                raise Halt("spot sweep arguments")
            reason = m.regs[R9]
        else:
            if m.regs[RDX] != EX or m.regs[RCX] != EVENTS:
                raise Halt("perp sweep arguments")
            reason = m.regs[R8]
        self.events.append(("sweep", number, reason & MASK[4]))

    def on_twap_spot(self, m):
        if m.regs[RDI] != self.tracker or m.regs[R8] != EX or m.regs[R9] != EVENTS or m.memory.bytes_at(m.regs[RSI], 20) != user_id(1):
            raise Halt("spot twap arguments")
        self.events.append(("twap spot", m.regs[RDX], m.regs[RCX]))

    def write_ids(self, value, row):
        ids = row[1]
        if row[0] == user_id(1):
            self.me_key = self.key_at
        self.put(value, 8, 0x7100000000 if ids else 0)
        self.put(value + 8, 8, 0x4100 + len(ids))
        self.put(value + 0x10, 8, len(ids))

    def build_tracker(self, case):
        memory = self.machine.memory
        self.tracker = self.alloc(0x60)
        memory.put_bytes(self.tracker, ramp(0x60, 91))
        if case.users:
            rows = sorted(((key, value) for key, value in case.users.items()), key=lambda row: row[0])
            self.build_map(self.tracker + 0x18, rows, MAP_NODE, self.write_ids, case.width, user_id(1))
        else:
            self.put(self.tracker + 0x18, 8, 0)
        self.live_ids = {key: list(value) for key, value in case.users.items()}
        self.selector_word = None

    def on_collect(self, m):
        read = m.memory.read
        out, rec = m.regs[RDI], m.regs[RSI]
        me = user_id(1)
        count = len(self.case.users[me])
        flag = 1 if count else 0
        root = 0x7100000000 if count else 0
        height = 0x4100 + count if count else 0
        words = [read(rec + index * 8, 8) for index in range(8)]
        wanted = [flag, 0, root, height, flag, 0, root, height]
        if words != wanted or (count and read(rec + 0x40, 8) != count):
            raise Halt("collect record")
        closure = read(rec + 0x48, 8)
        self.events.append(("collect", count, read(closure, 8), read(closure + 8, 8)))
        ids = self.case.ids
        at = self.alloc(max(len(ids), 1) * 8)
        if ids:
            self.live[at] = len(ids) * 8
        for index, number in enumerate(ids):
            self.put(at + index * 8, 8, number)
        self.put(out, 8, len(ids))
        self.put(out + 8, 8, at if ids else 8)
        self.put(out + 0x10, 8, len(ids))

    def on_take(self, m):
        out, value, number = m.regs[RDI], m.regs[RSI], m.memory.read(m.regs[RDX], 8)
        me = user_id(1)
        if m.memory.read(value, 8) != 0x7100000000 or m.memory.bytes_at(self.me_key, 19) != me[:19]:
            raise Halt("take value pointer")
        ids = self.live_ids.get(me, [])
        memory = m.memory
        if number not in ids:
            self.events.append(("take", number, False))
            memory.put_bytes(out, ramp(0x60, 200))
            self.put(out + 0x22, 1, 2)
            return
        ids.remove(number)
        self.put(value + 0x10, 8, len(ids))
        self.events.append(("take", number, True))
        row = bytearray(ramp(0x60, number & 0x7F))
        row[0:8] = struct.pack("<Q", self.case.rows.get(number, 0))
        row[0x22] = 1
        self.taken = bytes(row)
        memory.put_bytes(out, self.taken)

    def on_user_out(self, m):
        out = m.regs[RDI]
        if m.regs[RSI] != self.tracker + 0x18 or m.memory.bytes_at(m.regs[RDX], 20) != user_id(1):
            raise Halt("user out arguments")
        self.live_ids.pop(user_id(1))
        self.write_user_gone()
        self.events.append(("user out", self.case.drain))
        self.left = self.case.drain
        self.put(out, 8, 1)
        self.out = out
        self.put(out + 8, 8, 0x5100 if self.case.drain else 0)
        self.put(out + 0x10, 8, 0x41)
        self.put(out + 0x18, 8, self.case.drain)

    def write_user_gone(self):
        """The user's key leaves the map: its bytes change, its neighbours stay."""
        key = self.machine.memory.read(self.me_key, 1)
        self.put(self.me_key + 19, 1, self.machine.memory.read(self.me_key + 19, 1) ^ 1)

    def on_perp_drain(self, m):
        rec = m.regs[RSI]
        read = m.memory.read
        drain = self.case.drain
        if drain:
            wanted = (1, 0, 0x5100, 0x41, 1, 0, 0x5100, 0x41, drain)
            words = tuple(read(rec + index * 8, 8) for index in range(9))
        else:
            wanted = (0, 0, 0)
            words = (read(rec, 8), read(rec + 0x20, 8), read(rec + 0x40, 8))
        if words != wanted:
            raise Halt("drain record")
        self.left -= 1
        self.put(m.regs[RDI], 8, 0 if self.left < 0 else 1)
        self.events.append(("drain step",))

    def on_spot_drain(self, m):
        if m.regs[RDI] != self.out + 8:
            raise Halt("spot drain")
        self.events.append(("drain step",))

    def check_taken(self, m):
        if m.memory.bytes_at(m.regs[RSI], 0x60) != self.taken:
            raise Halt("row copy")

    def on_perp_make(self, m):
        self.check_taken(m)
        meta = m.regs[RDX]
        dex = (meta - self.metas) // META_STRIDE
        if meta != self.metas + dex * META_STRIDE:
            raise Halt("metadata pointer")
        number = struct.unpack_from("<Q", self.taken, 0)[0]
        self.events.append(("make", dex, self.current_id()))
        m.memory.put_bytes(m.regs[RDI], self.made())

    def on_spot_make(self, m):
        self.check_taken(m)
        if m.regs[RDX] != EX + 0x90:
            raise Halt("spot metadata")
        self.events.append(("make spot", self.current_id()))
        m.memory.put_bytes(m.regs[RDI], self.made())

    def current_id(self):
        for event in reversed(self.events):
            if event[0] == "take":
                return event[1]
        raise Halt("no take")

    def made(self):
        return ramp(0x58, self.current_id() & 0x3F)

    def on_missing(self, m):
        if m.memory.read(m.regs[RDI], 2) != MISSING_WORD:
            raise Halt("missing word")
        self.events.append(("missing",))

    def on_row_copy(self, m):
        if m.regs[RDX] == self.row_size:
            number = self.current_id()
            row = m.memory.bytes_at(m.regs[RSI], self.row_size)
            read = struct.unpack_from
            ok = (row[:8] == struct.pack("<Q", ROW_TAG) and row[8:0x60] == self.made() and read("<Q", row, 0x60)[0] == TERMINATED_WORD and read("<Q", row, 0x78)[0] == number and
                  read("<III", row, 0x80) == self.case.now and row[0x8C:0xA0] == user_id(1))
            if not ok:
                raise Halt("row bytes")
            if m.regs[RDI] != self.row_base + m.memory.read(EVENTS + 0x10, 8) * self.row_size:
                raise Halt("row slot")
            self.events.append(("row", number))
        self.on_memcpy(m)

    def set_vec(self, capacity):
        at = self.alloc(capacity * self.row_size)
        self.put(EVENTS, 8, capacity)
        self.put(EVENTS + 8, 8, at)
        self.put(EVENTS + 0x10, 8, 0)
        self.row_base = at

    def run_closure(self, case):
        machine = self.machine
        spot = case.kind == "closure spot"
        entry = FIRST["spot"] if spot else FIRST["perp"]
        machine.calls = {SWEEP_SPOT if spot else SWEEP_PERP: self.on_sweep, TWAP_SPOT: self.on_twap_spot, PERP_COLLECT: self.on_collect, PERP_TAKE: self.on_take, PERP_USER_OUT: self.on_user_out,
                         PERP_DRAIN: self.on_perp_drain, PERP_MAKE: self.on_perp_make, NOT_FOUND_DROP: self.on_missing, RESULT_DROP: self.on_drop}
        machine.real = frozenset({entry})
        machine.slots[FAKE_MEMCPY] = self.on_row_copy
        self.row_size = 0x278
        self.entry_range = self.image.exact_fde(entry)
        self.start(case)
        memory = machine.memory
        memory.put_bytes(EX, ramp(0x60, 31))
        for index, value in enumerate(case.now):
            self.put(EX + 0x60 + index * 4, 4, value)
        self.books = self.alloc(BOOK_STRIDE * max(case.books, 1))
        self.metas = self.alloc(META_STRIDE)
        self.put(EX + 0x5C0, 8, self.metas)
        self.put(EX + 0x5C8, 8, case.metas)
        collection = self.alloc(0x20)
        memory.put_bytes(collection, ramp(0x20, 61))
        self.put(collection + 8, 8, self.books)
        self.put(collection + 0x10, 8, case.books)
        self.build_tracker(case)
        self.set_vec(2 if case.grown else 64)
        self.put(RECORD, 8, case.selector)
        self.put(RECORD + 8, 8, case.asset)
        self.put(RECORD + 0x10, 8, collection)
        self.put(RECORD + 0x18, 8, self.tracker)
        self.put(RECORD + 0x20, 8, EX)
        self.put(RECORD + 0x28, 8, EVENTS)
        memory.put_bytes(RECORD + 0x30, user_id(1))
        self.put(RECORD + 0x44, 1, case.flag)
        self.put(RECORD + 0x45, 1, case.reason)
        machine.run(entry, {RDI: RECORD})
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events}

    def run_twap_spot(self, case):
        machine = self.machine
        machine.calls = {SPOT_COLLECT: self.on_collect, SPOT_TAKE: self.on_take, SPOT_USER_OUT: self.on_user_out, SPOT_DRAIN: self.on_spot_drain, SPOT_MAKE: self.on_spot_make, NOT_FOUND_DROP: self.on_missing}
        machine.real = frozenset({TWAP_SPOT})
        machine.slots[FAKE_MEMCPY] = self.on_row_copy
        self.row_size = 0x268
        self.entry_range = self.image.exact_fde(TWAP_SPOT)
        self.start(case)
        memory = machine.memory
        memory.put_bytes(EX, ramp(0x60, 31))
        for index, value in enumerate(case.now):
            self.put(EX + 0x60 + index * 4, 4, value)
        memory.put_bytes(USER, user_id(1))
        self.build_tracker(case)
        self.set_vec(2 if case.grown else 64)
        machine.run(TWAP_SPOT, {RDI: self.tracker, RSI: USER, RDX: case.selector, RCX: case.asset, R8: EX, R9: EVENTS})
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events}

    # per-user sweep

    def on_remove(self, m):
        spot = self.case.kind == "sweep spot"
        if m.regs[RDI] != self.book or m.memory.bytes_at(m.regs[RDX], 20) != user_id(1) or m.regs[RCX] != EX or m.regs[R8] != EVENTS:
            raise Halt("remove arguments")
        self.events.append(("remove", m.regs[RSI], m.regs[R9] & MASK[4]))

    def on_map_out(self, m):
        if m.regs[RSI] != self.book + 0xB8 or m.memory.bytes_at(m.regs[RDX], 20) != user_id(1):
            raise Halt("map out arguments")
        self.events.append(("map out",))
        self.put(m.regs[RDI], 8, NO_ENTRY if self.case.claimed_none else 0x1234)
        self.out = m.regs[RDI]

    def on_entry_drop(self, m):
        if m.regs[RDI] != self.out:
            raise Halt("entry drop")
        self.events.append(("entry drop",))

    def write_user_entry(self, value, row):
        memory = self.machine.memory
        case = self.case
        memory.put_bytes(value, ramp(0x50, 121))
        if row[0] == user_id(1):
            self.build_set(value + 0x20, case.first, SET_NODE)
            self.build_set(value + 0x38, case.second, SECOND_NODE)
        else:
            self.build_set(value + 0x20, [0x6000], SET_NODE)
            self.build_set(value + 0x38, [0x6100], SECOND_NODE)

    def run_sweep(self, case):
        machine = self.machine
        spot = case.kind == "sweep spot"
        entry = SWEEP_SPOT if spot else SWEEP_PERP
        machine.calls = {REMOVE_SPOT if spot else REMOVE_PERP: self.on_remove, SPOT_MAP_OUT if spot else PERP_MAP_OUT: self.on_map_out, SPOT_ENTRY_DROP if spot else PERP_ENTRY_DROP: self.on_entry_drop}
        self.closure([entry])
        machine.slots[FAKE_MEMCPY] = self.on_memcpy
        self.entry_range = (0, 0)
        self.start(case)
        memory = machine.memory
        self.book = self.alloc(BOOK_STRIDE)
        memory.put_bytes(self.book, ramp(BOOK_STRIDE, 7))
        slab = self.alloc(SLOT_STRIDE * max(len(case.slab), 1))
        for index, (tag, flag, key) in enumerate(case.slab):
            memory.put_bytes(slab + index * SLOT_STRIDE, ramp(SLOT_STRIDE, index + 3))
            self.put(slab + index * SLOT_STRIDE, 8, tag)
            self.put(slab + index * SLOT_STRIDE + 0xB0, 1, flag)
            self.put(slab + index * SLOT_STRIDE + 0xD8, 8, key)
        self.put(self.book + 8, 8, slab)
        self.put(self.book + 0x10, 8, len(case.slab))
        others = [user_id(number) for number in case.others]
        rows = sorted([(user, None) for user in others] + ([] if case.absent else [(user_id(1), None)]), key=lambda row: row[0])
        if rows:
            self.build_map(self.book + 0xB8, rows, USER_NODE, self.write_user_entry, case.width, user_id(1))
        else:
            self.put(self.book + 0xB8, 8, 0)
        memory.put_bytes(USER, user_id(1))
        if spot:
            machine.run(entry, {RDI: self.book, RSI: USER, RDX: 1 if case.chain else 0, RCX: EX, R8: EVENTS, R9: case.reason})
        else:
            machine.run(entry, {RDI: self.book, RSI: USER, RDX: EX, RCX: EVENTS, R8: case.reason})
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events}

    # runs

    def run(self, case):
        try:
            if case.kind == "fire":
                return self.run_fire(case)
            if case.kind == "select":
                return self.run_select(case)
            if case.kind == "twap spot":
                return self.run_twap_spot(case)
            if case.kind.startswith("closure"):
                return self.run_closure(case)
            return self.run_sweep(case)
        except Panicked as caught:
            return {"stop": caught.args[0], "events": self.events}
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)


CRASHES = (Halt, EvidenceError, RecursionError, IndexError, KeyError, ZeroDivisionError, StopIteration, OverflowError, ValueError, struct.error)


def compare_run(harness, case):
    try:
        actual = harness.run(case)
    except CRASHES as caught:
        return "%s: crash %s" % (case.label, caught)
    expected = spec_run(case, harness.copy)
    for key in ("stop", "events", "entries", "length"):
        if actual.get(key) != expected.get(key):
            return "%s: %s differs: %s / %s" % (case.label, key, str(actual.get(key))[:400], str(expected.get(key))[:400])
    return None


# ---- cases ----

def lcg(state):
    return (state * 6364136223846793005 + 1442695040888963407) & MASK[8]


def fire_cases():
    now = (20000, 3600, 5000)
    prev = 20000
    entry = lambda number, *rest: Entry(user_id(number), *rest)
    cases = [
        Case("fire empty map", "fire", entries=[]),
        Case("fire null root", "fire", entries=[entry(2, 0, 19000)], null_root=True),
        Case("fire zero length", "fire", entries=[entry(2, 0, 19000)], claimed=0),
        Case("fire disarmed", "fire", entries=[entry(2, 3, 0, 1, 1)]),
        Case("fire past date", "fire", entries=[entry(2, 3, 19999, 86399, 999)]),
        Case("fire future date", "fire", entries=[entry(2, 3, 20001, 0, 0)]),
        Case("fire same moment", "fire", entries=[entry(2, 3, 20000, 3600, 5000)]),
        Case("fire one nano past", "fire", entries=[entry(2, 3, 20000, 3600, 4999)]),
        Case("fire one nano ahead", "fire", entries=[entry(2, 3, 20000, 3600, 5001)]),
        Case("fire one second ahead, smaller nanos", "fire", entries=[entry(2, 3, 20000, 3601, 1)]),
        Case("fire one second past, larger nanos", "fire", entries=[entry(2, 3, 20000, 3599, 9999)]),
        Case("fire nanos above sign bit", "fire", entries=[entry(2, 3, 20000, 3600, 0x90000000)]),
        Case("fire seconds above sign bit", "fire", entries=[entry(2, 3, 20000, 0x90000000, 0)]),
        Case("fire negative date", "fire", entries=[entry(2, 3, 0xFFFF0000, 0, 0)]),
        Case("fire negative now", "fire", now=(0xFFFF0000, 10, 10), prev=0xFFFF0000, entries=[entry(2, 3, 20000, 0, 0), entry(3, 1, 0xFFFE0000, 9, 9)]),
        Case("fire count saturates", "fire", entries=[entry(2, MASK[8], 19000)]),
        Case("fire three in order", "fire", entries=[entry(4, 1, 19000), entry(2, 2, 20001), entry(9, 3, 19999), entry(7, 4, 0), entry(5, 5, 20000, 1, 1)]),
        Case("fire five grow the vector", "fire", entries=[entry(number, number, 19000 + number) for number in range(2, 9)]),
        Case("fire lazy flag, nothing due", "fire", lazy=1, entries=[entry(2, 1, 20001)]),
        Case("fire lazy flag, one due", "fire", lazy=1, entries=[entry(2, 1, 19000)]),
        Case("fire lazy flag, later day", "fire", lazy=1, prev=19999, entries=[entry(2, 1, 19000), entry(3, 4, 0)]),
        Case("day same prev", "fire", prev=20000, entries=[entry(2, 4, 0)]),
        Case("day later prev", "fire", prev=20001, entries=[entry(2, 4, 0)]),
        Case("day one before", "fire", prev=19999, entries=[entry(2, 4, 0), entry(3, 5, 20001), entry(4, 6, 19000)]),
        Case("day negative prev", "fire", prev=0xFFFF0000, entries=[entry(2, 4, 0)]),
        Case("day negative now", "fire", now=(0xFFFF0000, 0, 0), prev=20000, entries=[entry(2, 4, 0)]),
        Case("day empty map", "fire", prev=19999, entries=[]),
        Case("day null root", "fire", prev=19999, entries=[entry(2, 1, 0)], null_root=True),
        Case("day clears all", "fire", prev=19999, entries=[entry(number, number, 0) for number in range(2, 8)]),
    ]
    wide = lambda number, *rest: Entry(bytes([number >> 8, number & 0xFF]) + user_id(number + 2)[2:], *rest)
    cases += [Case("fire lazy flag, empty map", "fire", lazy=1, entries=[]),
              Case("fire height eight, all due", "fire", width=1, entries=[wide(number, 1, 19000) for number in range(256)]),
              Case("day height eight, none removed", "fire", width=1, prev=19999, entries=[wide(number, 1, 20001) for number in range(256)]),
              Case("day height three, none removed", "fire", width=2, prev=19999, entries=[wide(number, 1, 20001) for number in range(100)]),
              Case("day height three, one removed", "fire", width=3, prev=19999, entries=[wide(number, 1, 0 if number == 70 else 20001) for number in range(100)])]
    state = 0x51
    for index in range(14):
        state = lcg(state)
        size = 12 + (state >> 8) % 90
        rows = []
        for number in range(size):
            state = lcg(state)
            pick = state >> 60
            date = 0 if pick < 5 else 19990 + (state >> 40) % 20
            rows.append(Entry(bytes([number & 0xFF, (number >> 8) & 0xFF]) + user_id(number + 2)[2:], (state >> 20) % 12, date, 3599 + (state >> 30) % 3, 4999 + (state >> 35) % 3))
        state = lcg(state)
        cases.append(Case("fire walk %d" % index, "fire", entries=rows, prev=19999 if index % 2 else 20000, width=6 + index % 6, lazy=index % 3 == 1))
    return cases


def select_cases():
    two = dict(collections=3, dexes=[0, 2])
    cases = [
        Case("all, no dex", "select", selector=2, dexes=[]),
        Case("all, one dex", "select", selector=2, dexes=[0], flag=1, reason=REASON_INTERNAL),
        Case("all, two dex", "select", selector=2, **two),
        Case("all, four dex list", "select", selector=2, dexes=[1, 0, 2, 1], collections=3, reason=REASON_LIQUIDATED),
        Case("all, five dex list", "select", selector=2, dexes=[0, 1, 2, 3, 4], collections=5),
        Case("all, seven dex list", "select", selector=2, dexes=[6, 5, 4, 3, 2, 1, 0], collections=7),
        Case("all, nine dex list", "select", selector=2, dexes=[8, 7, 6, 5, 4, 3, 2, 1, 0], collections=9),
        Case("all, dex past end", "select", selector=2, dexes=[0, 3], collections=3),
        Case("all, dex at end", "select", selector=2, dexes=[2], collections=2),
        Case("all, alloc fails", "select", selector=2, dexes=[0], alloc_fails=True),
        Case("spot one", "select", selector=1, asset=7, flag=1),
        Case("spot one large", "select", selector=1, asset=0x123456789AB, reason=REASON_INTERNAL),
        Case("selector 3 is odd", "select", selector=3, asset=9),
        Case("perp one, dex 0", "select", selector=0, asset=3, flag=1),
        Case("perp one, dex 1", "select", selector=0, asset=10005),
        Case("perp one, last local", "select", selector=0, asset=19999, reason=REASON_LIQUIDATED),
        Case("perp one, dex 2", "select", selector=0, asset=20000, collections=3),
        Case("perp one, dex past end", "select", selector=0, asset=20000, collections=2),
        Case("selector 4 is even", "select", selector=4, asset=10000),
    ]
    return cases


def closure_cases():
    cases = []
    for kind in ("closure spot", "closure perp"):
        short = kind.split()[1]
        cases += [Case("%s all empty" % short, kind, selector=0, books=0),
                  Case("%s all one" % short, kind, selector=0, books=1),
                  Case("%s all three" % short, kind, selector=0, books=3, reason=REASON_INTERNAL),
                  Case("%s one first" % short, kind, selector=1, books=2, asset=0),
                  Case("%s one last" % short, kind, selector=1, books=2, asset=1, reason=REASON_LIQUIDATED),
                  Case("%s one past" % short, kind, selector=1, books=2, asset=2),
                  Case("%s no flag leaves the tracker" % short, kind, selector=0, books=1, users={user_id(1): [5]}, ids=[5], flag=0)]
    me = user_id(1)
    cases += [Case("spot one with dex words", "closure spot", selector=1, books=20001, asset=20000) if False else Case("spot flag", "closure spot", selector=1, books=2, asset=1, flag=1),
              Case("spot flag all", "closure spot", selector=0, books=1, asset=9, flag=1),
              Case("spot raw asset is not reduced", "closure spot", selector=1, books=3, asset=10001),
              Case("perp reduced local", "closure perp", selector=1, books=3, asset=10001),
              Case("perp reduced local, dex 2", "closure perp", selector=1, books=1, asset=20000)]
    perp = dict(books=1, selector=0, flag=1)
    rows = {100: 5, 101: 10003, 102: 20001}
    def crowd(count):
        rows = {bytes([0 if index % 2 else 200, index]) + bytes(range(18)): [index + 1] for index in range(count)}
        rows[me] = [100]
        return rows
    exact = {100: 10000}
    for count in (6, 20, 31, 45, 70):
        cases.append(Case("twap crowd %d" % count, "closure perp", users=crowd(count), ids=[100], rows=exact, metas=2, width=3, **perp))
        cases.append(Case("twap crowd %d, two ids" % count, "closure perp", users=crowd(count), ids=[100, 100], rows=exact, metas=2, width=2, **perp))
        cases.append(Case("spot twap crowd %d" % count, "twap spot", users=crowd(count), ids=[100, 100], selector=1, asset=9, width=3))
        rows = crowd(count)
        rows.pop(me)
        cases.append(Case("twap crowd %d, absent" % count, "closure perp", users=rows, width=3, **perp))
        cases.append(Case("spot twap crowd %d, absent" % count, "twap spot", users=rows, selector=1, asset=9, width=3))
    above = {user_id(200): [1], user_id(201): [2]}
    cases += [Case("twap all keys above", "closure perp", users=above, **perp),
              Case("spot twap all keys above", "twap spot", users=above, selector=1, asset=9),
              Case("twap exact dex 1", "closure perp", users={me: [100]}, ids=[100], rows={100: 10000}, metas=2, **perp),
              Case("twap exact dex 1, one meta", "closure perp", users={me: [100]}, ids=[100], rows={100: 10000}, metas=1, **perp)]
    cases += [Case("twap no tracker users", "closure perp", **perp),
              Case("twap user absent", "closure perp", users={user_id(2): [1]}, **perp),
              Case("twap user beside others", "closure perp", users={user_id(0): [1], me: [100], user_id(3): [2], user_id(9): [3]}, ids=[100], rows=rows, **perp),
              Case("twap empty list", "closure perp", users={me: []}, **perp),
              Case("twap nothing picked", "closure perp", users={me: [100]}, **perp),
              Case("twap one of two", "closure perp", users={me: [100, 101]}, ids=[101], rows=rows, metas=2, **perp),
              Case("twap both", "closure perp", users={me: [100, 101]}, ids=[100, 101], rows=rows, metas=2, **perp),
              Case("twap three, dex past end", "closure perp", users={me: [100, 101, 102]}, ids=[100, 101, 102], rows=rows, metas=2, **perp),
              Case("twap dex at last", "closure perp", users={me: [102]}, ids=[102], rows=rows, metas=3, **perp),
              Case("twap id not in the set", "closure perp", users={me: [100]}, ids=[55, 100], rows=rows, **perp),
              Case("twap list longer than the set", "closure perp", users={me: [100]}, ids=[100, 101], rows=rows, metas=2, **perp),
              Case("twap user out with drain", "closure perp", users={me: [100]}, ids=[100], rows=rows, drain=2, **perp),
              Case("twap row vector grows", "closure perp", users={me: [100, 101, 102]}, ids=[100, 101, 102], rows=rows, metas=3, grown=True, **perp),
              Case("twap one selector", "closure perp", books=4, selector=1, asset=10003, flag=1, users={me: [100]}, ids=[100], rows=rows)]
    spot = dict(selector=1, asset=9)
    kind = "twap spot"
    cases += [Case("spot twap no users", kind, **spot),
              Case("spot twap user absent", kind, users={user_id(2): [1]}, **spot),
              Case("spot twap beside others", kind, users={user_id(0): [1], me: [100], user_id(3): [2]}, ids=[100], selector=0, asset=3),
              Case("spot twap empty list", kind, users={me: []}, **spot),
              Case("spot twap nothing picked", kind, users={me: [100]}, **spot),
              Case("spot twap one of two", kind, users={me: [100, 101]}, ids=[101], **spot),
              Case("spot twap both", kind, users={me: [100, 101]}, ids=[100, 101], **spot),
              Case("spot twap id not in the set", kind, users={me: [100]}, ids=[55, 100], **spot),
              Case("spot twap list longer", kind, users={me: [100]}, ids=[100, 101], **spot),
              Case("spot twap user out drained", kind, users={me: [100]}, ids=[100], drain=1, **spot),
              Case("spot twap grows", kind, users={me: [100, 101, 102]}, ids=[100, 101, 102], grown=True, **spot)]
    return cases


def sweep_cases():
    # Slot rows are (tag, +0xb0 flag, key). Keys are not slab indexes, so a mix-up shows.
    slab = [(0, 0, 900), (1, 0, 300), (2, 0, 111), (0x700000002, 0, 112), (0x700000000, 1, 700), (3, 7, 500), (0, 1, 800), (4, 0, 100)]
    cases = []
    for kind, chains in (("sweep perp", (True,)), ("sweep spot", (True, False))):
        for chain in chains:
            name = "%s %s" % (kind.split()[1], "chain" if chain else "filter")
            base = dict(chain=chain, slab=slab, others=[2, 3], reason=REASON_SCHEDULED)
            cases += [Case("%s no map" % name, kind, chain=chain, absent=True, others=[]),
                      Case("%s user absent" % name, kind, chain=chain, absent=True, others=[2, 3, 9]),
                      Case("%s user last" % name, kind, chain=chain, slab=slab, others=[0], first=[0]),
                      Case("%s user alone" % name, kind, chain=chain, slab=slab, others=[], first=[1]),
                      Case("%s empty trees" % name, kind, **base),
                      Case("%s first only" % name, kind, first=[0, 1, 4, 5, 6, 7], **base),
                      Case("%s skips vacant" % name, kind, first=[2, 3, 7], **base),
                      Case("%s skips past the slab" % name, kind, first=[7, 8, 9, 70000], **base),
                      Case("%s second only" % name, kind, second=[50, 60, 40], **base),
                      Case("%s both, equal keys collapse" % name, kind, first=[0, 1, 7], second=[100, 300, 950], reason=REASON_INTERNAL, chain=chain, slab=slab, others=[2, 3]),
                      Case("%s wide first" % name, kind, first=[0, 1, 7], second=[], chain=chain, slab=slab, others=list(range(2, 60)), width=7),
                      Case("%s many keys" % name, kind, chain=chain, others=[2], slab=[(0, index % 3 == 0, 5000 - index * 7) for index in range(60)], first=list(range(60)), second=[index * 11 for index in range(15)])]
            cases.append(Case("%s absent past a smaller key" % name, kind, chain=chain, absent=True, others=[0], slab=slab))
            cases.append(Case("%s absent beside neighbours" % name, kind, chain=chain, absent=True, others=[2, 3, 4], slab=slab))
            cases.append(Case("%s crowd" % name, kind, chain=chain, slab=slab, others=list(range(2, 45)), first=[0, 1], width=3))
            cases.append(Case("%s crowd, absent" % name, kind, chain=chain, absent=True, slab=slab, others=list(range(2, 45)), width=3))
            if chain:
                cases.append(Case("%s map gives none" % name, kind, first=[0], claimed_none=True, **base))
    return cases


def all_cases():
    return fire_cases() + select_cases() + closure_cases() + sweep_cases()


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


def call_targets(image, start):
    """Direct call targets of one function, read through the byte decoder."""
    found = []
    for row in decode_range(image, *image.exact_fde(start)):
        if row.op == "call" and row.target and row.target not in found:
            found.append(row.target)
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


def pin_rows():
    rows = []
    for start, name in ((PERP_COLLECT, "perp"), (SPOT_COLLECT, "spot")):
        rows += [(start, "%s collector: cmp dword [rcx], 1, the closure selector" % name, b"\x83\x39\x01", 1),
                 (start, "%s collector: mov rdx, [rdx]; cmp rdx, [rcx+8], first value word against the closure asset" % name, b"\x48\x8b\x12\x48\x3b\x51\x08", 1)]
    return rows


def read_pins(image):
    rows = []
    for start, meaning, pattern, expected in pin_rows():
        found = find_all(image, start, pattern)
        if len(found) != expected:
            raise EvidenceError("pin %r at %#x has %d sites" % (meaning, start, len(found)))
        rows.append({"function": "%#x" % start, "sites": ["%#x" % va for va in found], "bytes": pattern.hex(), "meaning": meaning})
    return rows


def read_sites(image, sites):
    """The caller arguments of each selector site, from fixed byte patterns before the call."""
    rows = []
    for copy in COPIES:
        for key, reason, flag_bytes, flag in (("fire_site", REASON_SCHEDULED, b"\x45\x31\xc9", 0), ("liq_site", REASON_LIQUIDATED, b"\x45\x31\xc9", 0), ("vote_site", REASON_INTERNAL, b"\x41\xb9\x01\x00\x00\x00", 1)):
            site = copy[key]
            if (site, 0xE8) not in sites[copy["select"]]:
                raise EvidenceError("%#x does not call the selector" % site)
            window = bytes(image.blob[image.offset(site - 30):image.offset(site)])
            if b"\x41\xb8" + struct.pack("<I", reason) not in window or not window.endswith(flag_bytes) or b"\xba\x02\x00\x00\x00" not in window:
                raise EvidenceError("arguments at %#x" % site)
            rows.append({"copy": copy["name"], "kind": key[:-5], "site": "%#x" % site, "function": "%#x" % image.fde(site)[0], "selector_immediate": SELECT_ALL, "reason": reason, "flag": flag})
        if len(sites[copy["select"]]) != 3:
            raise EvidenceError("selector call sites")
    return rows


def read_routes(image, sites):
    rows = []
    for copy in COPIES:
        found = [row[0] for row in sites[copy["fire"]]]
        if found != [copy["site"]] or image.fde(copy["site"])[0] != copy["host"]:
            raise EvidenceError("host of %#x" % copy["fire"])
        rows.append({"copy": copy["name"], "fire": "%#x" % copy["fire"], "site": "%#x" % copy["site"], "host": "%#x" % copy["host"]})
    return rows


def read_vote(image):
    """Case of the vote table that holds the 0x10 caller, and the branch that gives selector 2."""
    rows = []
    for vote, table, arm, step in ((0x2355F40, 0x3DD1B8, 0x2356AD6, 0x2356ADB), ):
        begin, end = image.exact_fde(vote)
        base = image.offset(table)
        cases = [index for index in range(120) if table + struct.unpack_from("<i", image.blob, base + index * 4)[0] == arm]
        if cases != [27] or image.fde(arm)[0] != vote:
            raise EvidenceError("vote case")
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 11])
        if data[:5] != b"\x41\x80\x7f\x08\x00" or data[5:7] != b"\x0f\x84" or step + 6 + struct.unpack_from("<i", data, 7)[0] != 0x2359B22:
            raise EvidenceError("vote arm bytes")
        target = bytes(image.blob[image.offset(0x2359B22):image.offset(0x2359B22) + 5])
        if target != b"\xba\x02\x00\x00\x00":
            raise EvidenceError("vote selector")
        rows.append({"function": "%#x" % vote, "table": "%#x" % table, "case": cases[0], "arm": "%#x" % arm, "byte_read": "payload +0x08", "zero_goes_to": "0x2359b22, edx = 2",
                     "nonzero": "slot 0x5773950 resolves a selector and asset"})
    return rows


def status_names(image, wanted=(REASON_LIQUIDATED, REASON_SCHEDULED, REASON_INTERNAL)):
    """Follow the jump table of the status serializer: byte value to its text."""
    start, end = image.exact_fde(STATUS_FN)
    base = image.offset(STATUS_TABLE)

    def read(va, count):
        at = image.offset(va)
        return bytes(image.blob[at:at + count])

    rows = []
    for value in wanted:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + value * 4)[0]
        if not start <= arm < end:
            raise EvidenceError("status arm")
        row = decode(read, arm)
        following = decode(read, row.next)
        if following.op == "jmp":
            following = decode(read, following.target)
        if row.op != "lea" or row.a != ("r", RSI) or following.op != "mov" or following.a != ("r", RDX):
            raise EvidenceError("status arm %#x" % arm)
        rows.append({"value": value, "arm": "%#x" % arm, "text": read(row.b[4], following.b[1]).decode("ascii")})
    return rows


def copy_diff(image):
    """Instruction pairs of each copy against the first: same shape, and what differs."""
    rows = []
    for key in ("fire", "select", "retain"):
        base = decode_range(image, *image.exact_fde(FIRST[key]))
        for copy in COPIES[1:]:
            other = decode_range(image, *image.exact_fde(copy[key]))
            if len(other) != len(base):
                raise EvidenceError("copy length")
            shape = 0
            fields = {}
            for left, right in zip(base, other):
                if left.op != right.op or left.size != right.size or left.cc != right.cc:
                    shape += 1
                for one, two in ((left.a, right.a), (left.b, right.b)):
                    if one and two and one[0] == "m" and one[1] not in (None, RSP) and one[4] != two[4]:
                        fields["%#x" % one[4]] = "%#x" % two[4]
            rows.append({"function": key, "copy": copy["name"], "start": "%#x" % copy[key], "instructions": len(other), "shape_differences": shape, "field_map": dict(sorted(fields.items()))})
    return rows


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


MUTATED = ((FIRST["fire"], "firing walk", ("fire",)), (FIRST["retain"], "day retain step", ("fire",)), (FIRST["select"], "market selector", ("select",)), (FIRST["spot"], "spot closure", ("closure spot",)),
           (FIRST["perp"], "perp closure", ("closure perp",)), (TWAP_SPOT, "spot TWAP sweep", ("twap spot",)), (SWEEP_PERP, "perp user sweep", ("sweep perp",)), (SWEEP_SPOT, "spot user sweep", ("sweep spot",)))


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    pool = all_cases()
    for start, _, kinds in MUTATED:
        cases = [case for case in pool if case.kind in kinds]
        rows = decode_range(image, *image.exact_fde(start))
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
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

REFERENCE_CLAIMS = (
    {"reference": "l1/exchange/handlers/18_schedule_cancel.rs:39-44", "claim": "aux_word is an unexplained leading counter or state word; state_day_word is cleared on disarm",
     "bytes": "0x2702760 adds 1 to the u64 at value +0 for each firing, saturating, and writes 0 to the date dword, so the same word is the fired count for the day and the armed marker"},
    {"reference": "l1/exchange/handlers/18_schedule_cancel.rs (whole file)", "claim": "no firing code, and no day reset",
     "bytes": "0x2702760 is the firing walk; the retain step 0x27e8ad0 zeroes every count and removes disarmed entries once the date passed in rsi is below the state date"},
    {"reference": "l1/books.rs:242-245", "claim": "0x2703080 applies a snapshot update to selected books",
     "bytes": "it calls the user sweep 0x26e4240 with the 20-byte user and a reason byte, then 0x26ddbe0 when the flag byte is set. No snapshot is read"},
    {"reference": "l1/books.rs:247-258", "claim": "0x27031b0 mirrors snapshot dispatch and emits per-user order records built from the book events",
     "bytes": "it calls the user sweep 0x26e3ef0, and only with the flag byte walks the user's TWAP set and pushes 0x278 rows tagged 4 with status word 0x8000000000000001; no book event is read"},
)
LANDING = "unwind landing pad or panic tail: no case unwinds"
COUNTER = "saturation of the fired counter: needs 2^64 due entries"
HEIGHT_EIGHT = "reached only with the low three bits of the height nonzero, so height 8 never arrives and 8 and 9 compare alike"
SECOND_PASS = "second pass of the eight-step descent: needs a tree of height 16"
START_ZERO = "edge index of the first iterator state, read as 0 and the neighbouring word is also 0"
STATE_CLEAR = "front handle cleared here and rewritten before the next read"
DEAD_INDEX = "index stored in the iterator state on the way through a kept entry; the next read of it follows a removal, which rewrites the state"
OUTPUT_UNREAD = "the extracted key and value are copied out, and the caller reads only the first byte of the result"
BACK_HANDLE = "back handle of the set iterator: the drain only walks forward"
USER_COUNT = "user map length read again after the walk finds the key"

REASON_RANGES = ((0x2702D1C, 0x2702D59, LANDING), (0x2703901, 0x2703959, LANDING), (0x26DE104, 0x26DE145, LANDING), (0x26E41FA, 0x26E4231, LANDING), (0x26E45E2, 0x26E4611, LANDING))
REASONS = {0x2702807: COUNTER, 0x27028B6: HEIGHT_EIGHT, 0x27029D9: HEIGHT_EIGHT, 0x27E8BA8: HEIGHT_EIGHT, 0x270294D: SECOND_PASS, 0x2702A14: SECOND_PASS, 0x2702A20: SECOND_PASS,
           0x27E8BE4: SECOND_PASS, 0x27E8BEF: SECOND_PASS, 0x27E8ADE: START_ZERO, 0x27E8AE2: STATE_CLEAR, 0x27E8BF9: DEAD_INDEX, 0x27E8C70: OUTPUT_UNREAD, 0x27E8C75: OUTPUT_UNREAD, 0x27E8C7A: OUTPUT_UNREAD,
           0x26E4054: BACK_HANDLE, 0x26E40B0: BACK_HANDLE, 0x26E411C: BACK_HANDLE, 0x26E43C3: BACK_HANDLE, 0x26E4413: BACK_HANDLE, 0x26E448A: BACK_HANDLE, 0x26E44F6: BACK_HANDLE}


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "")


def outcome_name(case, spec):
    if spec["stop"]:
        return "%s: panic %s" % (case.kind, spec["stop"][0])
    return "%s: returned" % case.kind


def worked_run(harness):
    """Three users: one due, one armed for later, one disarmed, on the block that passes midnight."""
    case = Case("worked", "fire", prev=19999, entries=[Entry(user_id(2), 9, 20000, 3600, 4999), Entry(user_id(3), 4, 20000, 3600, 5001), Entry(user_id(4), 7, 0, 0, 0)])
    run = harness.run(case)
    return {"now": list(case.now), "prev_date": case.prev, "before": [{"user": e.user.hex(), "count": e.count, "date": e.date, "sec": e.sec, "nanos": e.nanos} for e in case.entries],
            "selector_calls": [event[1:] for event in run["events"] if event[0] == "select"], "after": [list(row) for row in run["entries"]], "length": run["length"]}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harnesses = [Harness(image, copy) for copy in COPIES]
    mismatches = []
    outcomes = {}
    per_copy = {}
    for harness in harnesses:
        count = 0
        for case in cases:
            if harness.copy is not FIRST and case.kind not in ("fire", "select"):
                continue
            count += 1
            trouble = compare_run(harness, case)
            if trouble:
                mismatches.append("%s %s" % (harness.copy["name"], trouble))
        per_copy[harness.copy["name"]] = count
    for case in cases:
        name = outcome_name(case, spec_run(case))
        outcomes[name] = outcomes.get(name, 0) + 1
    worked = worked_run(harnesses[0])
    seen = set()
    for harness in harnesses:
        seen |= harness.machine.seen
    first_seen = set(harnesses[0].machine.seen)
    steps = sum(harness.machine.steps for harness in harnesses)
    named = []
    for copy in COPIES:
        named += [("firing walk", copy["fire"], copy["name"]), ("market selector", copy["select"], copy["name"]), ("day retain step", copy["retain"], copy["name"]), ("range helper", copy["range"], copy["name"])]
    named += [("spot closure", FIRST["spot"], "first"), ("perp closure", FIRST["perp"], "first"), ("spot TWAP sweep", TWAP_SPOT, "first"), ("perp user sweep", SWEEP_PERP, "first"), ("spot user sweep", SWEEP_SPOT, "first")]
    functions = []
    done = set()
    for role, start, owner in named:
        if start in done:
            continue
        done.add(start)
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "owner": owner, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    targets = sorted({copy["fire"] for copy in COPIES} | {copy["select"] for copy in COPIES} | {SWEEP_PERP, SWEEP_SPOT, TWAP_SPOT, REMOVE_PERP, REMOVE_SPOT})
    sites = direct_sites(image, targets)
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    routes = read_routes(image, sites)
    selector_sites = read_sites(image, sites)
    status = status_names(image)
    vote = read_vote(image)
    differences = copy_diff(image)
    relative = harnesses[0].relative
    locations = []
    for slot, name in sorted(LOCATION_NAMES.items()):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    results_rows = run_mutants(image, first_seen, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "routes": routes,
        "selector_sites": selector_sites,
        "vote_arm": vote,
        "pins": read_pins(image),
        "status_names": status,
        "copies": [{key: ("%#x" % value if isinstance(value, int) else value) for key, value in copy.items()} for copy in COPIES],
        "copy_diff": differences,
        "slots": {"%#x" % slot: {"target": "%#x" % relative[slot] if slot in relative else "dynamic symbol", "meaning": SLOT_NAMES[slot]} for slot in sorted(SLOT_NAMES)},
        "locations": locations,
        "map_node": MAP_NODE,
        "user_node": USER_NODE,
        "set_node": SET_NODE,
        "second_node": SECOND_NODE,
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases), "per_copy": per_copy},
        "outcomes": dict(sorted(outcomes.items())),
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
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
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
