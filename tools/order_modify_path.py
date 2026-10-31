#!/usr/bin/env python3
"""Pin the node #94 modify path from ELF bytes: the wire entry, one replacement, its statuses and the relink of parent, peer and child orders.

Wrappers `0x22be760` (single) and closure `0x24be320` (batch) reach the body `0x271c490` and its copies `0x4d1c1c0`, `0x4d1dff0`. The body routes
the asset, checks the new order first, finds the old order through the book map or by oid, compares two bytes and the parent rule, removes with
reason 2, flushes, inserts, then either relinks the old parent, peer and children onto the new oid or cancels the children, and calls the hook
at method +0x40. The first copy holds the relink inline with retain `0x25182c0` and attach `0x26e3d40`; the other two call `0x43073d0`. The real
bytes run in a Python evaluator with the edge callees stubbed. A separately written specification predicts every result and the final links,
and every condition, immediate and field offset is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is
never executed. Standard library only.
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

Copy = collections.namedtuple("Copy", "name inline body wrapper closure perp_check spot_check perp_remove spot_remove perp_child spot_child perp_flush spot_flush perp_insert spot_insert perp_drop spot_drop perp_done spot_done tail find find_mut retain_perp retain_spot attach link perp_self spot_self perp_helper spot_helper perp_view spot_view hook closed rows rows_len names spot_rows spot_len dexes")
COPIES = (
    Copy("first", True, 0x271C490, 0x22BE760, 0x24BE320, 0x21F7C40, 0x21F8520, 0x26DF430, 0x26DE3D0, 0x26DE150, 0x26DE280, 0x24FB610, 0x24FC8A0, 0x26C9CF0, 0x26D0E50,
         0x2553220, 0x2552B50, 0x2333F50, 0x2333C40, 0x28B05A0, 0x26E54D0, 0x26E7F30, 0x25182C0, 0x2517C10, 0x26E3D40, None, None, None, None, None, 0x24FB450, 0x24FB4E0,
         0x3A88, 0x3AC8, 0x3370, 0x3378, 0x5B8, 0x3388, 0x3390, 0x3368),
    Copy("second", False, 0x4D1C1C0, 0x4C83210, 0x47F88A0, 0x4C18260, 0x4C17B10, 0x42F97F0, 0x42F8840, 0x42F7590, 0x42F7290, 0x4329870, 0x432B440, 0x4CA8510, 0x445E270,
         0x48525F0, 0x484F3C0, 0x4322660, 0x4322350, 0x49B0100, 0x43075D0, 0x430D380, None, None, 0x43032B0, 0x43073D0, 0x42FD530, 0x42FC790, 0x4303040, 0x43031E0, 0x43297E0, 0x445E150,
         0x3A88, 0x3AC8, 0x3370, 0x3378, 0x5B8, 0x3388, 0x3390, 0x3368),
    Copy("third", False, 0x4D1DFF0, 0x4C83110, 0x47F7C40, 0x4C18B40, 0x4C19420, 0x42FA880, 0x42F7890, 0x42F7420, 0x42F7700, 0x432A100, 0x432A990, 0x4CA9710, 0x445E9F0,
         0x48525F0, 0x484F3C0, 0x4322660, 0x4322350, 0x49B0100, 0x43075D0, 0x430D380, None, None, 0x43032B0, 0x43073D0, 0x42FD530, 0x42FC790, 0x4302F70, 0x4303110, 0x43297E0, 0x445E1E0,
         0x4508, 0x4548, 0x3DF0, 0x3DF8, 0x1038, 0x3E08, 0x3E10, 0x3DE8),
)
CLONE = 0x4847460
DROP_WORD = 0x3379490
SLOT_RESOLVE = 0x5773950
SLOT_LOOKUP = 0x5774AA0
SLOT_DEX_ROW = 0x5773D98
SLOT_NAME_ROW = 0x5773320
SLOT_GROW = 0x5774458
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_NAMES = {SLOT_RESOLVE: 0x3C0CC70, SLOT_LOOKUP: 0x342A430}
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576E468, 0x576DFB8, 0x576E020, 0x576E108, 0x576E290)
TAG_TEXTS = 0x59A8D0
REPLACE_TEMPLATE = 0x1E8B0D
ASSET_TEMPLATE = 0x1FA53A

ROW_STRIDE = 0x138
BOOK_STRIDE = 0xD8
RESULT_SIZE = 0x60
ENTRY_SIZE = 0x50
USER_SIZE = 20
PERP_ROW = 0x278
SPOT_ROW = 0x268
PERP_DONE = 0x238
SPOT_DONE = 0x228
MAX64 = (1 << 64) - 1
TAG_OK = 0x186
TAG_GONE = 0x38
TAG_SHAPE = 0x39
TAG_REPLACE = 0x3A
TAG_INSERT_TEXT = 0xC4
TAG_SPOT_OFF = 0xF9
REASON = 2
ASSET_SCALE = 10000
SINGLE_OK = 0xD
SINGLE_ERROR = 0xE

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

STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0x4800
ROWS = HEAP_BASE + 0x6000
BOOKS = HEAP_BASE + 0x8000
BOOK_AREA = 0x400000
SPOT_BOOKS = HEAP_BASE + 0xC000
NAME_ROWS = HEAP_BASE + 0xD000
USER_ARG = HEAP_BASE + 0xE300
OUT = HEAP_BASE + 0xE400
ORDER_ARG = HEAP_BASE + 0xE500
KEY_ARG = HEAP_BASE + 0xE540
HOOK_DATA = HEAP_BASE + 0xE600
HOOK_TABLE = HEAP_BASE + 0xE640
ITER = HEAP_BASE + 0xE700
SINK = HEAP_BASE + 0xE740
COUNTER = HEAP_BASE + 0xE780
ENTRY = HEAP_BASE + 0xE800
HOOK_TARGET = 0xCA110000
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



# ---- specification, written from the read of the bytes, shares nothing with the evaluator ----

class SpecPanic(Exception):
    def __init__(self, label):
        Exception.__init__(self, label)
        self.label = label


def key_uses_map(byte, copy):
    """The first copy tests bit 0 of the key byte, the other two compare it with 1."""
    return bool(byte & 1) if copy.inline else byte == 1


def bound_location(copy):
    return "0x56bb478" if copy.inline else "0x5742338"


def split_asset(packed):
    return packed // ASSET_SCALE, packed % ASSET_SCALE


def relink(orders, old, new_oid):
    """Links after an insert that left a resting order: `old` is the body read before the removal."""
    fresh = orders.get(new_oid)
    kept = [kid for kid in old["kids"] if kid in orders]
    if old["parent"] is not None:
        parent = orders.get(old["parent"])
        if parent is not None and new_oid not in parent["kids"]:
            parent["kids"].append(new_oid)
        if fresh is not None:
            fresh["parent"] = old["parent"]
    if old["peer"] is not None and old["peer"] in orders:
        if fresh is not None:
            fresh["peer"] = old["peer"]
        orders[old["peer"]]["peer"] = new_oid
    if fresh is not None:
        for kid in kept:
            if kid not in fresh["kids"]:
                fresh["kids"].append(kid)
    for kid in kept:
        orders[kid]["parent"] = new_oid


def plain(orders):
    return {oid: [row["parent"], row["peer"], list(row["kids"])] for oid, row in sorted(orders.items())}


def run_body_spec(w, copy):
    log = []
    orders = {oid: dict(row, kids=list(row["kids"])) for oid, row in w["orders"].items()}
    out = {"log": log, "orders": plain(orders), "leak": []}
    log.append(["resolve", w["asset"]])
    route = w["route"]
    if isinstance(route, tuple):
        out["result"] = {"tag": route[1], "payload": error_bytes(route[1], w["asset"])[2:].hex()}
        return out
    spot = route == "spot"
    kind = "spot" if spot else "perp"
    if spot and w["closed"]:
        out["result"] = {"tag": TAG_SPOT_OFF}
        return out
    log.append(["check", kind])
    if w["check"] is not None:
        out["result"] = {"tag": w["check"], "payload": error_bytes(w["check"], 0x77)[2:].hex()}
        return out
    packed = w["packed"]
    if spot:
        if packed >= w["spot_len"]:
            return dict(out, panic=bound_location(copy), result=None)
        book = ["spot", packed]
        dex = None
    else:
        dex, local = split_asset(packed)
        if dex >= w["rows_len"]:
            return dict(out, panic="0x56e9b28", result=None)
        if local >= w["books"].get(dex, 0):
            return dict(out, panic=bound_location(copy), result=None)
        book = ["perp", dex, local]
    key = w["key"]
    oid = key["oid"]
    if key_uses_map(key["byte"], copy):
        log.append(["lookup", book, key["cloid"].hex()])
        oid = w["lookup"]
    old = orders.get(oid) if oid is not None else None
    tag = None
    if old is None:
        tag = TAG_GONE
    elif old["b"] != w["b"] or old["a"] != w["a"] or (old["parent"] is not None and w["kind"] == 2):
        tag = TAG_SHAPE
    if tag is None:
        old = dict(old, kids=list(old["kids"]))
        log.append(["remove", kind, book, oid, REASON])
        del orders[oid]
        for gone in w["removal_vanish"]:
            orders.pop(gone, None)
        log.append(["flush", kind, dex, w["removal_rows"]])
        extra = old["extra"]
        log.append(["insert", kind, int(extra is not None), extra.hex() if extra is not None else ""])
        job = w["insert"]
        for gone in job["vanish"]:
            orders.pop(gone, None)
        made = job["word"] == TAG_OK and job["rests"] and not job["lost"]
        if made:
            orders[job["oid"]] = blank_order()
        if job["word"] != TAG_OK:
            rows = 0
            for kid in old["kids"]:
                log.append(["child", kind, book, kid, REASON])
                rows += w["child_rows"]
            log.append(["flush", kind, dex, rows])
            if job["word"] == TAG_INSERT_TEXT:
                tag = TAG_REPLACE
                out["result"] = {"tag": TAG_REPLACE, "text": text_words()}
            else:
                tag = job["word"]
                out["result"] = {"tag": tag, "payload": insert_bytes(w)[2:].hex()}
        else:
            if job["rests"]:
                relink(orders, old, job["oid"])
                if not copy.inline:
                    log.append(["self", kind, book])
            if not spot:
                log.append(["names", dex])
            log.append(["done", kind, insert_bytes(w)[8:0x58].hex()])
            log.append(["tail"])
            tag = TAG_OK
            out["result"] = {"tag": TAG_OK, "done": done_bytes().hex()}
    else:
        out["result"] = {"tag": tag}
    out["orders"] = plain(orders)
    if w["hook"]:
        log.append(["hook", int(tag != TAG_OK)])
    return out


def run_wrapper_spec(w, copy):
    entry = w["entry"]
    tagged = entry[0x3C] == 1
    order = entry[0x18:0x3C] + bytes([int(tagged)]) + (entry[0x3D:0x4D] if tagged else bytes(16)) + entry[0x4D:0x4F]
    found = {"log": [["body", entry[:0x18].hex(), order.hex()]]}
    if w["word"] == TAG_OK:
        found["tag"] = SINGLE_OK
    else:
        found.update({"tag": SINGLE_ERROR, "bytes": body_output(0, w["word"]).hex()})
    return found


def run_batch_spec(w, copy):
    log, rows = [], []
    for index, entry in enumerate(w["entries"]):
        log.append(["body", entry[:0x18].hex(), entry[0x18:0x50].hex()])
        rows.append(body_output(index, TAG_OK + index).hex())
    if not copy.inline and rows:
        log.insert(0, ["malloc", len(rows) * RESULT_SIZE])
    found = {"log": log + ([["free", w["capacity"] * ENTRY_SIZE]] if w["capacity"] else []), "rows": rows, "count": w["start"] + len(rows) if copy.inline else len(rows)}
    if not copy.inline and not rows:
        found["empty_pointer"] = 8
    return found


def run_spec(case):
    copy = COPIES[case.copy]
    return {"body": run_body_spec, "wrapper": run_wrapper_spec, "batch": run_batch_spec}[case.kind](case.world, copy)

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


def blank_order():
    return {"parent": None, "peer": None, "kids": [], "a": 0, "b": 0, "extra": None, "stale_parent": None, "stale_peer": None}


def error_bytes(word, start):
    """A status word from a callee with its own 0x5e bytes behind it."""
    return struct.pack("<H", word) + ramp(0x5E, start & 0xFF)


def text_words():
    return [0x31, 0x32, 0x33]


def insert_bytes(w):
    """The 0x60 bytes the stubbed insert writes."""
    job = w["insert"]
    out = bytearray(ramp(RESULT_SIZE, 0x71))
    struct.pack_into("<H", out, 0, job["word"])
    if job["word"] == TAG_OK:
        struct.pack_into("<QQ", out, 8, job["capacity"], job["buffer"])
        struct.pack_into("<Q", out, 0x38, job["oid"])
        out[0x51] = 0xFE | int(job["rests"])
    elif job["word"] == TAG_INSERT_TEXT:
        struct.pack_into("<I", out, 4, 0x4444)
        struct.pack_into("<QQQ", out, 8, *text_words())
    return bytes(out)


def done_bytes():
    return ramp(0x30, 0x33)


def body_output(index, word):
    return struct.pack("<H", word) + ramp(0x5E, 0x41 + index * 3)


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_RESOLVE: self.on_resolve, SLOT_LOOKUP: self.on_lookup, SLOT_DEX_ROW: self.on_dex_row, SLOT_NAME_ROW: self.on_name_row, SLOT_GROW: self.on_grow,
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
        calls = {DROP_WORD: self.on_drop}
        for copy in COPIES:
            calls.update({copy.perp_check: self.on_check_perp, copy.spot_check: self.on_check_spot, copy.perp_remove: self.on_remove_perp, copy.spot_remove: self.on_remove_spot,
                          copy.perp_child: self.on_child_perp, copy.spot_child: self.on_child_spot, copy.perp_flush: self.on_flush_perp, copy.spot_flush: self.on_flush_spot,
                          copy.perp_insert: self.on_insert_perp, copy.spot_insert: self.on_insert_spot, copy.perp_drop: self.on_rows_drop, copy.spot_drop: self.on_rows_drop,
                          copy.perp_done: self.on_done_perp, copy.spot_done: self.on_done_spot, copy.tail: self.on_tail, copy.find: self.on_find, copy.find_mut: self.on_find})
            if not copy.inline:
                calls.update({copy.perp_self: self.on_self_perp, copy.spot_self: self.on_self_spot})
        self.plain_calls = calls
        self.body_calls = dict(calls)
        for copy in COPIES:
            self.body_calls[copy.body] = self.on_body
        machine.calls = calls
        self.plain_stubs = frozenset(machine.slots) | frozenset(calls)
        self.body_stubs = frozenset(machine.slots) | frozenset(self.body_calls)
        self.real.stubs = self.plain_stubs
        self.w = None
        self.copy = COPIES[0]
        self.brk = HEAP_FREE
        self.live = {}
        self.kept = set()
        self.log = []
        self.bodies = {}
        self.book_at = 0
        self.done_size = {}
        self.calls_seen = 0
        self.insert_out = 0

    # ---- plain stubs ----

    def location(self, at):
        return "%#x" % at

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

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x2000:
            raise Halt("allocation size")
        if self.w.get("log_free"):
            self.log.append(["malloc", size])
        at = self.allocate(size)
        if self.w.get("tempt"):
            m.memory.write(at + size, 8, self.w["tempt"])
            self.brk += 8
        m.regs[RAX] = at

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))
        if self.w.get("log_free"):
            self.log.append(["free", size])

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x2000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_grow(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if capacity > 0x40 or memory.read(vector + 0x10, 8) != capacity:
            raise Halt("vector size")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * 8)
        self.kept.add(fresh)
        if capacity:
            memory.copy(fresh, old, capacity * 8)
            if self.live.pop(old, None) != capacity * 8:
                raise Halt("kid buffer")
            self.kept.discard(old)
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_resolve(self, m):
        regs = m.regs
        memory = m.memory
        copy = self.copy
        if regs[RDX] != STATE + copy.names or regs[RCX] != STATE + 0x90:
            raise Halt("resolve arguments")
        asset = regs[RSI] & MASK[4]
        self.log.append(["resolve", asset])
        route = self.w["route"]
        at = regs[RDI]
        if isinstance(route, tuple):
            memory.put_bytes(at, error_bytes(route[1], asset))
            return
        memory.put_bytes(at, ramp(RESULT_SIZE, 0x2B))
        memory.write(at, 2, TAG_OK)
        memory.write(at + 8, 4, {"spot": 1, "perp": 0, "third": 2}[route])

    def on_check(self, m, kind):
        regs = m.regs
        memory = m.memory
        w = self.w
        if regs[RSI] != ORDER_ARG or regs[RCX] != STATE or memory.bytes_at(regs[RDX], USER_SIZE) != w["user"]:
            raise Halt("check arguments")
        self.log.append(["check", kind])
        at = regs[RDI]
        if w["check"] is not None:
            memory.put_bytes(at, error_bytes(w["check"], 0x77))
            return
        memory.write(at, 2, TAG_OK)
        memory.put_bytes(at + 8, self.record())
        self.record_at = at + 8

    def on_check_perp(self, m):
        self.on_check(m, "perp")

    def on_check_spot(self, m):
        self.on_check(m, "spot")

    def record(self):
        w = self.w
        data = bytearray(ramp(0x48, 0x35))
        data[0x19] = w["kind"]
        struct.pack_into("<Q", data, 0x28, w["packed"])
        data[0x30] = w["a"]
        data[0x31] = w["b"]
        return bytes(data)

    def book_name(self, at):
        if at != self.book_at:
            raise Halt("book address %#x" % at)
        return self.book_label(at)

    def book_label(self, at):
        if SPOT_BOOKS <= at < SPOT_BOOKS + 0x1000:
            index, rest = divmod(at - SPOT_BOOKS, BOOK_STRIDE)
            if rest:
                raise Halt("spot book address")
            return ["spot", index]
        dex, rest = divmod(at - BOOKS, BOOK_AREA)
        local, rest = divmod(rest, BOOK_STRIDE)
        if rest or not 0 <= dex < 8:
            raise Halt("book address")
        return ["perp", dex, local]

    def on_lookup(self, m):
        regs = m.regs
        book = regs[RDI] - 0x48
        name = self.book_label(book)
        self.book_at = book
        if m.memory.bytes_at(regs[RSI], USER_SIZE) != self.w["user"]:
            raise Halt("lookup user")
        self.log.append(["lookup", name, m.memory.bytes_at(regs[RDX], 16).hex()])
        found = self.w["lookup"]
        regs[RAX] = 0x5500 | int(found is not None)
        regs[RDX] = found if found is not None else POISON
        m.keep_rdx = True

    def on_find(self, m):
        regs = m.regs
        if self.book_at == 0:
            self.book_label(regs[RDI])
            self.book_at = regs[RDI]
        if regs[RDI] != self.book_at or m.memory.bytes_at(regs[RSI], USER_SIZE) != self.w["user"]:
            raise Halt("find arguments")
        regs[RAX] = self.bodies.get(regs[RDX], 0)

    def on_remove(self, m, kind, stride):
        regs = m.regs
        memory = m.memory
        w = self.w
        if regs[RCX] != STATE or memory.bytes_at(regs[RDX], USER_SIZE) != w["user"]:
            raise Halt("remove arguments")
        oid = regs[RSI]
        self.log.append(["remove", kind, self.book_name(regs[RDI]), oid, regs[R9] & 0xFF])
        self.bodies.pop(oid, None)
        for gone in w["removal_vanish"]:
            self.bodies.pop(gone, None)
        self.push_rows(regs[R8], stride, w["removal_rows"])

    def on_remove_perp(self, m):
        self.on_remove(m, "perp", PERP_ROW)

    def on_remove_spot(self, m):
        self.on_remove(m, "spot", SPOT_ROW)

    def push_rows(self, vector, stride, count):
        memory = self.machine.memory
        capacity, buffer, length = (memory.read(vector + index * 8, 8) for index in range(3))
        if not capacity and (buffer != 8 or length):
            raise Halt("rows vector not empty")
        if not count:
            return
        if not capacity:
            capacity, buffer = 8, self.allocate(8 * stride)
            memory.write(vector, 8, capacity)
            memory.write(vector + 8, 8, buffer)
        for index in range(count):
            memory.write(buffer + (length + index) * stride, 8, 0x40 + length + index)
        memory.write(vector + 0x10, 8, length + count)

    def on_child(self, m, kind, stride):
        regs = m.regs
        memory = m.memory
        if regs[RCX] != STATE or memory.bytes_at(regs[RSI], USER_SIZE) != self.w["user"]:
            raise Halt("child arguments")
        self.log.append(["child", kind, self.book_name(regs[RDI]), regs[RDX], regs[R9] & 0xFF])
        self.push_rows(regs[R8], stride, self.w["child_rows"])

    def on_child_perp(self, m):
        self.on_child(m, "perp", PERP_ROW)

    def on_child_spot(self, m):
        self.on_child(m, "spot", SPOT_ROW)

    def flush(self, m, kind, dex, stride):
        memory = m.memory
        at = m.regs[RDI]
        capacity, buffer, length = (memory.read(at + index * 8, 8) for index in range(3))
        if capacity > 8 or length > capacity:
            raise Halt("flush vector")
        for index in range(length):
            if memory.read(buffer + index * stride, 8) != 0x40 + index:
                raise Halt("flush row")
        if capacity and self.live.pop(buffer, None) != capacity * stride:
            raise Halt("flush buffer")
        self.log.append(["flush", kind, dex, length])

    def on_flush_perp(self, m):
        if m.regs[RDX] != STATE:
            raise Halt("flush state")
        self.flush(m, "perp", m.regs[RSI], PERP_ROW)

    def on_flush_spot(self, m):
        if m.regs[RSI] != STATE:
            raise Halt("flush state")
        self.flush(m, "spot", None, SPOT_ROW)

    def on_insert(self, m, kind):
        regs = m.regs
        memory = m.memory
        w = self.w
        job = w["insert"]
        if regs[R8] != STATE or memory.bytes_at(regs[RSI], 0x48) != self.record() or memory.bytes_at(regs[RDX], USER_SIZE) != w["user"]:
            raise Halt("insert arguments")
        ctx = regs[RCX]
        flag = memory.read(ctx, 8)
        if flag > 1 or memory.read(ctx + 0x28, 8) or memory.read(ctx + 0x30, 8) != 8 or memory.read(ctx + 0x38, 8) or memory.read(ctx + 0x40, 4) or memory.read(ctx + 0x48, 8):
            raise Halt("insert context")
        self.log.append(["insert", kind, flag, memory.bytes_at(ctx + 8, 32).hex() if flag else ""])
        for gone in job["vanish"]:
            self.bodies.pop(gone, None)
        job = dict(job)
        if job["word"] == TAG_OK:
            job["buffer"] = 8
            if job["capacity"]:
                job["buffer"] = self.allocate(job["capacity"] * (PERP_DONE if kind == "perp" else SPOT_DONE))
            if job["rests"] and not job["lost"]:
                self.bodies[job["oid"]] = self.new_body(blank_order())
        memory.put_bytes(regs[RDI], insert_bytes(dict(w, insert=job)))
        self.insert_out = regs[RDI]

    def on_insert_perp(self, m):
        self.on_insert(m, "perp")

    def on_insert_spot(self, m):
        self.on_insert(m, "spot")

    def on_rows_drop(self, m):
        at = m.regs[RDI]
        if m.memory.read(at + 0x10, 8):
            raise Halt("rows left")

    def on_dex_row(self, m):
        regs = m.regs
        if regs[RDI] != STATE + self.copy.dexes:
            raise Halt("dex row arguments")
        regs[RAX] = ROWS + regs[RSI] * ROW_STRIDE

    def on_name_row(self, m):
        regs = m.regs
        if regs[RDI] != STATE + self.copy.names:
            raise Halt("name row arguments")
        self.log.append(["names", regs[RSI]])
        regs[RAX] = NAME_ROWS + regs[RSI] * 0x10

    def on_done(self, m, kind, third):
        regs = m.regs
        memory = m.memory
        if regs[RDX] != third:
            raise Halt("done third argument")
        source = bytearray(memory.bytes_at(regs[RSI], 0x50))
        struct.pack_into("<Q", source, 8, 0)
        wanted = bytearray(insert_bytes(dict(self.w, insert=dict(self.w["insert"], buffer=0)))[8:0x58])
        if source != wanted:
            raise Halt("done source")
        self.log.append(["done", kind, insert_bytes(dict(self.w, insert=dict(self.w["insert"], buffer=8)))[8:0x58].hex()])
        memory.put_bytes(regs[RDI], done_bytes())

    def on_done_perp(self, m):
        self.on_done(m, "perp", NAME_ROWS + split_asset(self.w["packed"])[0] * 0x10)

    def on_done_spot(self, m):
        self.on_done(m, "spot", STATE + 0x90)

    def on_tail(self, m):
        if m.memory.read(m.regs[RDI], 8) != struct.unpack_from("<Q", insert_bytes(dict(self.w, insert=dict(self.w["insert"], buffer=8))), 0x20)[0]:
            raise Halt("tail argument")
        self.log.append(["tail"])

    def on_self(self, m, kind):
        regs = m.regs
        if regs[RSI] & 0xFF:
            raise Halt("self check flag")
        self.log.append(["self", kind, self.book_name(regs[RDI])])

    def on_self_perp(self, m):
        self.on_self(m, "perp")

    def on_self_spot(self, m):
        self.on_self(m, "spot")

    def on_hook(self, m):
        regs = m.regs
        if regs[RDI] != HOOK_DATA or m.memory.bytes_at(regs[RSI], USER_SIZE) != self.w["user"]:
            raise Halt("hook arguments")
        self.log.append(["hook", regs[RDX]])

    def on_body(self, m):
        regs = m.regs
        memory = m.memory
        w = self.w
        if regs[RSI] != STATE or memory.bytes_at(regs[RDX], USER_SIZE) != w["user"]:
            raise Halt("body arguments")
        key = memory.bytes_at(regs[RCX], 0x18).hex()
        order = bytearray(memory.bytes_at(regs[R8], 0x37 if self.kind == "wrapper" else 0x38))
        if self.kind == "wrapper" and not order[0x24]:
            order[0x25:0x35] = bytes(16)
        self.log.append(["body", key, bytes(order).hex()])
        if self.kind == "wrapper":
            memory.put_bytes(regs[RDI], body_output(0, w["word"]))
        else:
            memory.put_bytes(regs[RDI], body_output(self.calls_seen, TAG_OK + self.calls_seen))
            self.calls_seen += 1
        regs[RAX] = regs[RDI]

    # ---- world ----

    def new_body(self, row):
        memory = self.machine.memory
        at = self.allocate(0xB0)
        self.kept.add(at)
        memory.put_bytes(at, ramp(0xB0, 0x63))
        memory.write(at + 0x10, 8, int(row["parent"] is not None))
        if row["parent"] is not None:
            memory.write(at + 0x18, 8, row["parent"])
        memory.write(at + 0x20, 8, int(row["peer"] is not None))
        if row["peer"] is not None:
            memory.write(at + 0x28, 8, row["peer"])
        if row["stale_parent"] is not None:
            memory.write(at + 0x18, 8, row["stale_parent"])
        if row["stale_peer"] is not None:
            memory.write(at + 0x28, 8, row["stale_peer"])
        kids = row["kids"]
        buffer = 8
        if kids:
            buffer = self.allocate(len(kids) * 8)
            self.kept.add(buffer)
            for index, kid in enumerate(kids):
                memory.write(buffer + index * 8, 8, kid)
        memory.write(at + 0x30, 8, len(kids))
        memory.write(at + 0x38, 8, buffer)
        memory.write(at + 0x40, 8, len(kids))
        extra = row["extra"]
        memory.write(at + 0x48, 4, int(extra is not None))
        if extra is not None:
            memory.put_bytes(at + 0x50, extra)
        memory.write(at + 0x90, 1, row["b"])
        memory.write(at + 0xA2, 1, row["a"])
        return at

    def setup(self, w, copy):
        memory = self.machine.memory
        memory.put_bytes(STATE, ramp(STATE_SIZE, 0x13))
        memory.write(STATE + copy.hook, 8, HOOK_DATA if w["hook"] else 0)
        memory.write(STATE + copy.hook + 8, 8, HOOK_TABLE)
        memory.write(HOOK_TABLE + 0x40, 8, HOOK_TARGET)
        memory.write(STATE + copy.closed, 1, w["closed"])
        memory.write(STATE + copy.rows, 8, ROWS)
        memory.write(STATE + copy.rows_len, 8, w["rows_len"])
        memory.write(STATE + copy.spot_rows, 8, SPOT_BOOKS)
        memory.write(STATE + copy.spot_len, 8, w["spot_len"])
        memory.write(STATE + copy.spot_len + 8, 8, 0)
        memory.put_bytes(USER_ARG, w["user"])
        for dex in range(max(w["rows_len"], 2)):
            row = ROWS + dex * ROW_STRIDE
            memory.put_bytes(row, ramp(ROW_STRIDE, 0x51 + dex))
            memory.write(row + 8, 8, BOOKS + dex * BOOK_AREA)
            memory.write(row + 0x10, 8, w["books"].get(dex, 0))
            memory.write(row + 0x18, 8, 0)

    def clean(self, w, kind):
        self.w = w
        self.kind = kind
        self.log = []
        self.live = {}
        self.kept = set()
        self.bodies = {}
        self.book_at = 0
        self.calls_seen = 0
        self.machine.memory.reset(self.brk - HEAP_BASE)
        self.brk = HEAP_FREE
        wrapped = kind != "body"
        self.machine.calls = self.body_calls if wrapped else self.plain_calls
        self.real.stubs = self.body_stubs if wrapped else self.plain_stubs

    def read_orders(self):
        memory = self.machine.memory
        rows = {}
        for oid, at in sorted(self.bodies.items()):
            count = memory.read(at + 0x40, 8)
            if count > 0x40:
                raise Halt("kid count")
            parent = memory.read(at + 0x18, 8) if memory.read(at + 0x10, 8) else None
            peer = memory.read(at + 0x28, 8) if memory.read(at + 0x20, 8) else None
            buffer = memory.read(at + 0x38, 8)
            rows[oid] = [parent, peer, [memory.read(buffer + index * 8, 8) for index in range(count)]]
        return rows

    def read_result(self, at):
        memory = self.machine.memory
        tag = memory.read(at, 2)
        row = {"tag": tag}
        if tag == TAG_OK:
            row["done"] = memory.bytes_at(at + 8, 0x30).hex()
        elif tag == TAG_REPLACE:
            row["text"] = [memory.read(at + 8 + index * 8, 8) for index in range(3)]
        elif tag not in (TAG_GONE, TAG_SHAPE, TAG_SPOT_OFF):
            row["payload"] = memory.bytes_at(at + 2, 0x5E).hex()
        return row

    def run_body(self, case, w):
        copy = COPIES[case.copy]
        self.copy = copy
        memory = self.machine.memory
        self.setup(w, copy)
        for oid, row in w["orders"].items():
            self.bodies[oid] = self.new_body(row)
        memory.put_bytes(ORDER_ARG, ramp(0x38, 0x19))
        memory.write(ORDER_ARG + 0x20, 4, w["asset"])
        key = w["key"]
        data = bytearray(ramp(0x18, 0x27))
        data[0] = key["byte"]
        if key_uses_map(key["byte"], copy):
            data[1:0x11] = key["cloid"]
        else:
            struct.pack_into("<Q", data, 8, key["oid"])
        memory.put_bytes(KEY_ARG, bytes(data))
        spot = w["route"] == "spot"
        if not isinstance(w["route"], tuple) and w["check"] is None and spot and w["packed"] < w["spot_len"]:
            self.book_at = SPOT_BOOKS + w["packed"] * BOOK_STRIDE
        elif not isinstance(w["route"], tuple) and w["check"] is None and not spot:
            dex, local = split_asset(w["packed"])
            if dex < w["rows_len"] and local < w["books"].get(dex, 0):
                self.book_at = BOOKS + dex * BOOK_AREA + local * BOOK_STRIDE
        try:
            self.machine.run(copy.body, {RDI: OUT, RSI: STATE, RDX: USER_ARG, RCX: KEY_ARG, R8: ORDER_ARG})
        except Panicked as panic:
            return {"log": self.log, "orders": self.read_orders(), "leak": [], "panic": str(panic), "result": None}
        leak = sorted(size for at, size in self.live.items() if at not in self.kept)
        return {"log": self.log, "orders": self.read_orders(), "leak": leak, "result": self.read_result(OUT)}

    def run_wrapper(self, case, w):
        copy = COPIES[case.copy]
        self.copy = copy
        memory = self.machine.memory
        memory.put_bytes(USER_ARG, w["user"])
        memory.put_bytes(ENTRY, w["entry"])
        self.machine.run(copy.wrapper, {RDI: OUT, RSI: ENTRY, RDX: USER_ARG, RCX: STATE})
        tag = memory.read(OUT, 1)
        found = {"log": self.log, "tag": tag}
        if tag == SINGLE_ERROR:
            found["bytes"] = memory.bytes_at(OUT + 8, RESULT_SIZE).hex()
        return found

    def run_batch(self, case, w):
        copy = COPIES[case.copy]
        self.copy = copy
        memory = self.machine.memory
        memory.put_bytes(USER_ARG, w["user"])
        entries = w["entries"]
        capacity = w["capacity"]
        buffer = self.allocate(capacity * ENTRY_SIZE) if capacity else 8
        skip = w.get("skip", 0)
        for index, entry in enumerate(entries):
            memory.put_bytes(buffer + (skip + index) * ENTRY_SIZE, entry)
        begin = buffer + skip * ENTRY_SIZE
        end = begin + len(entries) * ENTRY_SIZE
        memory.put_bytes(ITER, ramp(0x30, 0x4F))
        for index, value in enumerate((buffer, begin, capacity, end)):
            memory.write(ITER + index * 8, 8, value)
        w = dict(w, log_free=True)
        self.w = w
        if copy.inline:
            out = self.allocate((w["start"] + len(entries)) * RESULT_SIZE) if w["start"] + len(entries) else 8
            for index, value in enumerate((COUNTER, w["start"], out, STATE, USER_ARG)):
                memory.write(SINK + index * 8, 8, value)
            self.machine.run(copy.closure, {RDI: ITER, RSI: SINK})
            count = memory.read(COUNTER, 8)
            rows = [memory.bytes_at(out + (w["start"] + index) * RESULT_SIZE, RESULT_SIZE).hex() for index in range(count - w["start"])] if count <= w["start"] + 8 else []
        else:
            memory.write(ITER + 0x20, 8, STATE)
            memory.write(ITER + 0x28, 8, USER_ARG)
            self.machine.run(copy.closure, {RDI: OUT, RSI: ITER})
            capacity_out, out, count = (memory.read(OUT + index * 8, 8) for index in range(3))
            if capacity_out != len(entries) or count > 8:
                raise Halt("result vector")
            rows = [memory.bytes_at(out + index * RESULT_SIZE, RESULT_SIZE).hex() for index in range(count)]
            if not count:
                return {"log": self.log, "rows": rows, "count": count, "empty_pointer": out}
        return {"log": self.log, "rows": rows, "count": count}

    def run(self, case):
        w = case.world
        self.clean(w, case.kind)
        return {"body": self.run_body, "wrapper": self.run_wrapper, "batch": self.run_batch}[case.kind](case, w)


def spec_run(case):
    return run_spec(case)


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError, UnicodeDecodeError, StopIteration, Panicked)


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


def cloid(number):
    return ramp(16, 0x10 + number)


def order(a=1, b=0, parent=None, peer=None, kids=(), extra=None, stale_parent=None, stale_peer=None):
    return {"parent": parent, "peer": peer, "kids": list(kids), "a": a, "b": b, "extra": extra, "stale_parent": stale_parent, "stale_peer": stale_peer}


def job(word=TAG_OK, rests=True, oid=900, capacity=0, vanish=(), lost=False):
    return {"word": word, "rests": rests, "oid": oid, "capacity": capacity, "buffer": 8, "vanish": list(vanish), "lost": lost}


def world(**changes):
    base = {
        "user": USER, "asset": 7, "route": "perp", "closed": 0, "check": None, "packed": 20001, "a": 1, "b": 0, "kind": 0,
        "key": {"byte": 0, "oid": 501, "cloid": cloid(1)}, "lookup": None, "orders": {501: order()}, "insert": job(),
        "removal_vanish": [], "removal_rows": 0, "child_rows": 0, "hook": True, "rows_len": 3, "spot_len": 4, "books": {0: 4, 1: 3, 2: 3},
    }
    base.update(changes)
    return base


def body_cases(copy):
    add = []

    def one(label, **changes):
        add.append(Case("%s: %s" % (COPIES[copy].name, label), "body", world(**changes), copy))

    def both(label, **changes):
        one("perp " + label, **changes)
        one("spot " + label, **dict({"route": "spot", "packed": 2}, **changes))

    one("resolver error", route=("error", 0x141))
    one("resolver error, other word", route=("error", 0x77), asset=9)
    one("spot closed", route="spot", packed=2, closed=1)
    one("spot closed by a high value byte", route="spot", packed=2, closed=0x80)
    one("perp ignores the closed byte", closed=1)
    one("third route word runs the perp arm", route="third")
    both("check error", check=0x55)
    both("check error, no hook", check=0x41, hook=False)
    one("dex at the rows limit", packed=30000)
    one("dex just below the rows limit", packed=29999, books={2: 10000})
    one("local at the book count", packed=20003)
    one("local just below the book count", packed=20002)
    one("packed asset exact scale", packed=10000)
    one("first dex first book", packed=0)
    one("spot index at the count", route="spot", packed=4)
    one("spot index last", route="spot", packed=3)
    both("old oid absent", orders={})
    both("old oid absent with another order", orders={502: order()})
    both("old oid absent, no hook", orders={}, hook=False)
    both("client id unknown", key={"byte": 1, "oid": 0, "cloid": cloid(2)}, lookup=None)
    both("client id found", key={"byte": 1, "oid": 0, "cloid": cloid(2)}, lookup=501)
    both("client id found, order gone", key={"byte": 1, "oid": 0, "cloid": cloid(3)}, lookup=777)
    both("rare key byte 2", key={"byte": 2, "oid": 501, "cloid": cloid(1)}, lookup=501)
    both("rare key byte 3", key={"byte": 3, "oid": 501, "cloid": cloid(4)}, lookup=501)
    both("rare key byte 0x80", key={"byte": 0x80, "oid": 501, "cloid": cloid(1)}, lookup=501)
    both("byte a differs", a=0)
    both("byte a differs high", orders={501: order(a=0x81)}, a=1)
    both("byte b differs", b=1)
    both("byte b differs high", orders={501: order(b=0x40)})
    both("parent and kind 2", orders={501: order(parent=400), 400: order(kids=[501])}, kind=2)
    both("parent and kind 1", orders={501: order(parent=400), 400: order(kids=[501])}, kind=1)
    both("parent and kind 3", orders={501: order(parent=400), 400: order(kids=[501])}, kind=3)
    both("no parent and kind 2", kind=2)
    both("reject with kids frees the copy", b=1, orders={501: order(b=0, kids=[601, 602]), 601: order(), 602: order()})
    both("reject on kind with kids", orders={501: order(parent=400, kids=[601]), 400: order(), 601: order()}, kind=2)
    both("plain replace", insert=job(capacity=2))
    both("plain replace, hook off", hook=False)
    both("replace does not rest", insert=job(rests=False))
    both("replace does not rest, kids stay", orders={501: order(parent=400, peer=502, kids=[601]), 400: order(kids=[501]), 502: order(peer=501), 601: order(parent=501)}, insert=job(rests=False, capacity=1))
    both("replace with rows", removal_rows=3)
    both("extra bytes pass to the insert", orders={501: order(extra=ramp(32, 0xD1))})
    both("one kid", orders={501: order(kids=[601]), 601: order(parent=501)})
    both("two kids", orders={501: order(kids=[601, 602]), 601: order(parent=501), 602: order(parent=501)})
    both("five kids, buffer grows", orders={501: order(kids=[601, 602, 603, 604, 605]), 601: order(parent=501), 602: order(parent=501), 603: order(parent=501), 604: order(parent=501), 605: order(parent=501)})
    both("kid repeated", orders={501: order(kids=[601, 601]), 601: order(parent=501)})
    both("first kid gone", orders={501: order(kids=[601, 602, 603]), 602: order(parent=501), 603: order(parent=501)})
    both("middle kid gone", orders={501: order(kids=[601, 602, 603, 604]), 601: order(parent=501), 603: order(parent=501), 604: order(parent=501)})
    both("last kid gone", orders={501: order(kids=[601, 602, 603]), 601: order(parent=501), 602: order(parent=501)})
    both("all kids gone", orders={501: order(kids=[601, 602])})
    both("kid gone during insert", orders={501: order(kids=[601, 602]), 601: order(parent=501), 602: order(parent=501)}, insert=job(vanish=[601]))
    both("kid gone during removal", orders={501: order(kids=[601, 602]), 601: order(parent=501), 602: order(parent=501)}, removal_vanish=[602])
    both("parent kept", orders={501: order(parent=400), 400: order(kids=[501])})
    both("parent with other kids", orders={501: order(parent=400), 400: order(kids=[301, 501, 302]), 301: order(parent=400), 302: order(parent=400)})
    both("parent full buffer", orders={501: order(parent=400), 400: order(kids=[301, 302, 303, 304]), 301: order(), 302: order(), 303: order(), 304: order()})
    both("parent already lists the new oid", orders={501: order(parent=400), 400: order(kids=[900, 501])})
    both("parent gone", orders={501: order(parent=400)})
    both("parent gone during the insert", orders={501: order(parent=400), 400: order(kids=[501])}, insert=job(vanish=[400]))
    both("peer kept", orders={501: order(peer=502), 502: order(peer=501)})
    both("peer gone", orders={501: order(peer=502)})
    both("peer gone during the insert", orders={501: order(peer=502), 502: order(peer=501)}, insert=job(vanish=[502]))
    both("parent, peer and kids", orders={501: order(parent=400, peer=502, kids=[601, 602]), 400: order(kids=[501]), 502: order(peer=501, parent=400), 601: order(parent=501), 602: order(parent=501)})
    both("rare peer word without its tag", orders={501: order(stale_peer=700), 700: order()})
    both("rare parent word without its tag", orders={501: order(stale_parent=700), 700: order()})
    both("rare parent word without its tag, kind 2", orders={501: order(stale_parent=700), 700: order()}, kind=2)
    both("rare peer one sided", orders={501: order(peer=502), 502: order()})
    both("rare word past the kid list", orders={501: order(kids=[601, 602, 603]), 601: order(parent=501), 603: order(parent=501), 604: order()}, tempt=604)
    both("rare word past the kid list, first gone", orders={501: order(kids=[601, 602]), 602: order(parent=501), 604: order()}, tempt=604)
    both("new order lost in the insert", orders={501: order(parent=400, peer=502, kids=[601]), 400: order(kids=[501]), 502: order(peer=501), 601: order(parent=501)}, insert=job(lost=True))
    both("insert failed", insert=job(word=0x60))
    both("insert failed, no hook", insert=job(word=0x60), hook=False)
    both("insert failed, ok neighbour word", insert=job(word=0x187))
    both("insert failed with one kid", orders={501: order(kids=[601]), 601: order(parent=501)}, insert=job(word=0x61))
    both("insert failed with kids and rows", orders={501: order(kids=[601, 602, 603]), 602: order(parent=501)}, insert=job(word=0x62), child_rows=1)
    both("insert failed keeps parent and peer untouched", orders={501: order(parent=400, peer=502, kids=[601]), 400: order(kids=[501]), 502: order(peer=501), 601: order(parent=501)}, insert=job(word=0x63))
    both("insert text error", insert=job(word=TAG_INSERT_TEXT))
    both("insert text error with kids", orders={501: order(kids=[601, 602]), 601: order(parent=501), 602: order(parent=501)}, insert=job(word=TAG_INSERT_TEXT), child_rows=2)
    both("insert neighbour of the text error", insert=job(word=TAG_INSERT_TEXT + 1))
    both("insert word high byte of the text error", insert=job(word=TAG_INSERT_TEXT | 0x100))
    return add


def entry(start, tag=1):
    data = bytearray(ramp(ENTRY_SIZE, start))
    data[0x3C] = tag
    return bytes(data)


def wire_cases(copy):
    add = []

    def one(label, kind, **changes):
        add.append(Case("%s: %s" % (COPIES[copy].name, label), kind, dict({"user": USER}, **changes), copy))

    one("single ok", "wrapper", entry=entry(0x21), word=TAG_OK)
    one("single no client id", "wrapper", entry=entry(0x23, 0), word=TAG_OK)
    one("single tag 2 counts as none", "wrapper", entry=entry(0x25, 2), word=TAG_OK)
    one("single tag 0x81 counts as none", "wrapper", entry=entry(0x25, 0x81), word=TAG_OK)
    one("single status passes", "wrapper", entry=entry(0x27), word=TAG_GONE)
    one("single status passes, no client id", "wrapper", entry=entry(0x29, 0), word=TAG_SHAPE)
    one("single neighbour word", "wrapper", entry=entry(0x2B), word=TAG_OK + 1)
    one("single high byte word", "wrapper", entry=entry(0x2D), word=TAG_OK ^ 0x100)
    one("batch empty", "batch", entries=[], capacity=0, start=0)
    one("batch after a consumed entry", "batch", entries=[entry(0x43), entry(0x45)], capacity=3, start=0, skip=1)
    one("batch empty with spare capacity", "batch", entries=[], capacity=3, start=0)
    one("batch one", "batch", entries=[entry(0x31)], capacity=1, start=0)
    one("batch two", "batch", entries=[entry(0x33), entry(0x35, 0)], capacity=2, start=0)
    one("batch three with spare capacity", "batch", entries=[entry(0x37), entry(0x39, 0), entry(0x3B, 2)], capacity=5, start=0)
    if COPIES[copy].inline:
        one("batch starts after earlier rows", "batch", entries=[entry(0x3D), entry(0x3F)], capacity=2, start=2)
        one("batch empty after earlier rows", "batch", entries=[], capacity=1, start=4)
    return add


def all_cases():
    cases = []
    for copy in range(len(COPIES)):
        cases += body_cases(copy) + wire_cases(copy)
    return cases

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
    (copy.body, copy.name + " body: one replacement"),
    (copy.wrapper, copy.name + " single wrapper"),
    (copy.closure, copy.name + " batch closure"),
    (copy.perp_view, copy.name + " perp book view"),
    (copy.spot_view, copy.name + " spot book view")) if not (copy.name == "third" and value == 0x43297E0)) + (
    (0x25182C0, "first retain of kids, perp arm"), (0x2517C10, "first retain of kids, spot arm"), (0x26E3D40, "first attach of kids"), (CLONE, "second and third spot clone of the kid list"))
EXTRA_FUNCTIONS = (
    (0x43073D0, "second and third relink, run with no mutants"), (0x43032B0, "second and third attach, run with no mutants"), (0x4303040, "second perp child cancel, run with no mutants"),
    (0x43031E0, "second spot child cancel, run with no mutants"), (0x4302F70, "third perp child cancel, run with no mutants"), (0x4303110, "third spot child cancel, run with no mutants"),
)
CASE_CAP = 120
PATH_CASES = 3
RARE_WORDS = ("rare", "neighbour", "high", "limit", "count", "exact", "lost", "repeated", "full buffer", "already lists")


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
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] + ":" + failed.split(":")[1] if failed else ""})
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


def arm_address(image, table, index):
    return table + struct.unpack_from("<i", image.blob, image.offset(table + 4 * index))[0]


def arm_text(image, table, index):
    """Fixed text of one jump table arm when the arm opens with the plain writer: three loads, the lea and the length."""
    arm = arm_address(image, table, index)
    data = code(image, arm, 24)
    if data[:3] != b"\x48\x8b\x3e" or data[11:14] != b"\x48\x8d\x35" or data[18] != 0xBA:
        raise EvidenceError("plain arm %#x" % index)
    return fixed_text(image, rip_target(image, arm + 11), struct.unpack_from("<I", data, 19)[0])


def arm_template(image, table, index, offset):
    """Format template of an arm, by the `lea rdx, [rip+d]` at a fixed offset."""
    arm = arm_address(image, table, index)
    if code(image, arm + offset, 3) != b"\x48\x8d\x15":
        raise EvidenceError("template lea of arm %#x" % index)
    return rip_target(image, arm + offset)


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
    "wire_entry": {"size": "0x50 bytes", "+0x00": "key, 0x18 bytes: byte +0x00 picks the map, client id at +0x01, oid at +0x08", "+0x18": "start of the order block, 0x38 bytes", "+0x38": "asset, dword (order +0x20)", "+0x3c": "client id tag of the new order", "+0x3d": "client id of the new order, 16 bytes", "+0x4d/+0x4e": "two final bytes"},
    "checked_record": {"size": "0x48 bytes, at +0x08 of the check result", "+0x19": "kind byte; the parent rule tests 2", "+0x28": "packed asset, u64: dex = value / 10000, local = value % 10000, or spot index", "+0x30": "byte compared with old +0xa2", "+0x31": "byte compared with old +0x90"},
    "old_order_body": {"+0x10/+0x18": "parent tag and oid", "+0x20/+0x28": "peer tag and oid", "+0x30/+0x38/+0x40": "kids Vec of oids", "+0x48": "dword tag: 1 copies the next 0x20 bytes", "+0x50": "0x20 bytes passed to the insert group", "+0x90": "byte compared with record +0x31", "+0xa2": "byte compared with record +0x30"},
    "insert_group": {"size": "0x50 bytes, the group of #926", "+0x00": "1 when old +0x48 is 1, else 0; never 2 or 3 here", "+0x08": "0x20 bytes from old +0x50 when the tag is 1", "+0x28/+0x30/+0x38": "empty Vec 0, 8, 0", "+0x40": "dword 0, +0x44 is not written", "+0x48": "0"},
    "insert_result": {"size": "0x60 bytes", "+0x00": "status word", "+0x04": "asset dword of 0xc4", "+0x08": "OK: start of 0x50 bytes passed to the row conversion, Vec at +0x08/+0x10 with stride 0x238 perp, 0x228 spot; 0xc4: String", "+0x20": "OK: value dropped after the conversion", "+0x38": "new oid", "+0x51": "bit 0: a resting order exists"},
    "status_out": {"size": "0x60 bytes", "+0x00": "status word", "0x186": "+0x08 holds 0x30 bytes of the row conversion", "0x3a": "+0x08 holds the String of 0xc4; the asset dword is dropped", "other": "every byte of the callee result; 0x38, 0x39 and 0xf9 use only the word"},
    "single_out": {"+0x00": "byte: 0xd fine, 0xe error", "+0x08": "the 0x60 status bytes on error"},
    "batch_row": {"stride": "0x60 bytes, the status bytes of one entry, in entry order"},
    "state": {"hook": "+0x3a88 and +0x3a90 or +0x4508 and +0x4510: optional object, method at table +0x40 (data, user, 1 unless status 0x186)", "spot off": "+0x3ac8 or +0x4548", "rows": "+0x3370 and +0x3378 or +0x3df0 and +0x3df8: dex rows, stride 0x138, book pointer +0x08, count +0x10, book stride 0xd8", "spot": "+0x3388 and +0x3390 or +0x3e08 and +0x3e10", "names": "+0x5b8 or +0x1038", "dex row accessor": "+0x3368 or +0x3de8"},
}
REFERENCE_CLAIMS = (
    {"reference": "l1/exchange/handlers/12_modify.rs:25", "claim": "the old order is never resolved by client id, lookup is always (user, oid)", "observed": "key byte: first copy bit 0, other copies equal to 1, selects book map lookup through slot 0x5774aa0 at 0x271c75f and 0x271c920; a miss gives status 0x38", "verdict": "wrong"},
    {"reference": "l1/exchange/handlers/12_modify.rs:261", "claim": "the peer comes from the insert result (new_peer_oid)", "observed": "the peer is old body +0x28, used only when it still exists after the insert; both peers are rewritten", "verdict": "wrong source"},
    {"reference": "l1/exchange/handlers/12_modify.rs:260", "claim": "rebind_child_oids moves every copied child", "observed": "retain 0x25182c0 keeps only kids that still exist; the old parent also gets the new oid, and the new order gets the old parent", "verdict": "incomplete"},
    {"reference": "l1/exchange/handlers/12_modify.rs:259", "claim": "relink runs when the insert returns a new oid", "observed": "the gate is bit 0 of insert result +0x51; with the bit clear the kid list is freed and no link changes", "verdict": "refined"},
    {"reference": "l1/exchange/handlers/12_modify.rs:238", "claim": "removal then insert", "observed": "agrees, and the removal rows flush before the insert; the tag and 0x20 bytes at old +0x48 and +0x50 go into the group argument of the insert, which the reference lacks", "verdict": "incomplete"},
    {"reference": "l1/exchange/handlers/12_modify.rs:243", "claim": "status 196 becomes 58", "observed": "agrees: 0xc4 becomes 0x3a with the String at +0x08 kept and the asset dword dropped; text 'Error placing new order during modify: '", "verdict": "agrees"},
    {"reference": "l1/exchange/handlers/12_modify.rs:246", "claim": "on failure the copied children are pruned and the old order stays gone", "observed": "agrees: every copied kid goes through the child cancel with reason 2, then one flush; old parent and peer links are not touched here", "verdict": "agrees"},
    {"reference": "l1/exchange/handlers/12_modify.rs:143", "claim": "no hook step", "observed": "method +0x40 of the object at state +0x3a88 runs once on every path that passed the check, with flag 0 only for status 0x186", "verdict": "missing in the reference"},
)
COPY_PAIRS = (
    (0x4D1C1C0, 0x4D1DFF0), (0x4C83210, 0x4C83110), (0x47F88A0, 0x47F7C40), (0x4303040, 0x4302F70), (0x43031E0, 0x4303110), (0x445E150, 0x445E1E0), (0x25182C0, 0x2517C10),
)
STATE_PAIRS = ((0x3A88, 0x4508), (0x3A90, 0x4510), (0x5B8, 0x1038), (0x3AC8, 0x4548), (0x3370, 0x3DF0), (0x3378, 0x3DF8), (0x3388, 0x3E08), (0x3390, 0x3E10), (0x3368, 0x3DE8))
SIZES_THAT_DIFFER = ((0x271C490, 0x4D1C1C0), (0x24BE320, 0x47F88A0), (0x24FB4E0, 0x445E150))


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
    for at, used in ((0x56E9B28, "dex at or above the rows length, unwrap of status 0x141"), (0x56BB478, "first copy: local index or spot index at or above the count"), (0x5742338, "second and third copies: the same bounds")):
        size = struct.unpack_from("<Q", image.blob, image.offset(at + 8))[0]
        start = image.offset(relative[at])
        text = bytes(image.blob[start:start + size]).decode("ascii")
        line, column = struct.unpack_from("<II", image.blob, image.offset(at + 16))
        rows.append({"location": "%#x" % at, "file": text[text.index("l1/src/"):], "line": line, "column": column, "use": used})
    return rows


def tag_rows(image):
    rows = []
    for tag, use in ((TAG_GONE, "old order not found: map miss or oid miss"), (TAG_SHAPE, "byte +0x90 or +0xa2 differs, or the old order has a parent and kind is 2"), (TAG_SPOT_OFF, "spot route with the state byte set; no check and no hook")):
        rows.append({"tag": "%#x" % tag, "text": arm_text(image, TAG_TEXTS, tag), "use": use})
    replace = arm_template(image, TAG_TEXTS, TAG_REPLACE, 0x23)
    plain = arm_template(image, TAG_TEXTS, TAG_INSERT_TEXT, 0x42)
    if replace != REPLACE_TEMPLATE or plain != ASSET_TEMPLATE:
        raise EvidenceError("template address")
    rows.append({"tag": "%#x" % TAG_REPLACE, "text": fixed_text(image, replace + 1, code(image, replace, 1)[0]) + "<String>", "template": "%#x" % replace, "template_bytes": code(image, replace, 42).hex(), "use": "insert failed with 0xc4 after the old order was removed"})
    rows.append({"tag": "%#x" % TAG_INSERT_TEXT, "text": "<String> asset=<dword>", "template": "%#x" % plain, "template_bytes": code(image, plain, 11).hex(), "use": "insert status that turns into 0x3a"})
    rows.append({"tag": "%#x" % TAG_OK, "text": "no fixed text in the arm", "use": "replaced; the hook flag is 0 only here"})
    return rows


def host_rows(image):
    """Calls into the path by exact byte patterns."""
    targets = sorted({value for copy in COPIES for value in (copy.body, copy.wrapper, copy.closure, copy.link) if value} | {0x25182C0, 0x2517C10, 0x26E3D40, CLONE})
    direct = direct_sites(image, targets)
    rows = []
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for slot, target in sorted(SLOT_NAMES.items()):
        if image_slot(image, slot) != target:
            raise EvidenceError("slot %#x" % slot)
    for copy in COPIES:
        rows.extend((SLOT_LOOKUP, va, "slot %#x" % SLOT_LOOKUP, image.fde(va)[0], image.fde(va)[1]) for va in slot_sites(image, SLOT_LOOKUP) if image.fde(va)[0] == copy.body)
    return rows


def outcome_name(case, spec):
    if case.kind != "body":
        return "%s %s" % (case.kind, spec.get("tag", "rows"))
    if spec.get("panic"):
        return "panic " + spec["panic"]
    return "status %#x" % spec["result"]["tag"]


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.kind, case.label.replace(": ", "\t", 1), outcome_name(case, spec))


def relink_pairs(image):
    """Each relink call in the second copy against the inline row in the first: named here, checked by the shared specification."""
    rows = []
    for name, first, second in (("retain surviving kids", "0x25182c0, 0x2517c10", "0x43073d0 first loop"), ("old parent lists the new oid", "0x26e3d40 with a one item list", "0x43032b0 with a one item list"), ("old peer, if still there", "inline at 0x271cf43", "0x43073d0 at 0x43074ac"), ("kids move to the new oid", "0x26e3d40", "0x43032b0")):
        rows.append({"step": name, "first_copy": first, "second_and_third": second})
    return rows


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
        "copy_names": [dict(copy._asdict()) for copy in COPIES],
        "relink_steps": relink_pairs(image),
        "locations": location_rows(image),
        "tags": tag_rows(image),
        "fields": FIELDS,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
    }


VIEW_FIELD = "the view reads only context +0x00..+0x10, +0x20 and +0x28, so this context word is unread"
UNWIND_FLAG = "drop flag read only by unwind pads, and no case unwinds"
DANGLING = "dangling pointer of an empty list: length 0, so nothing reads through it and nothing frees it"
DEAD_STORE = "empty Vec on the stack for an unwind pad; the words are overwritten on every normal path"
OVERFLOW = "capacity overflow test: only a length of 2^60 or more reaches the other arm"
UNREAD_BODY = "copies an old body field into the stack body that 0x43073d0 never reads: it reads +0x10..+0x47 only"
SURVIVED_DEFAULT = "pending"
SURVIVED_REASONS = {
    0x271C68A: VIEW_FIELD, 0x271C83E: VIEW_FIELD, 0x271CD91: VIEW_FIELD, 0x4D1D218: VIEW_FIELD,
    0x271CC7F: UNWIND_FLAG, 0x271D29A: UNWIND_FLAG, 0x4D1CDC3: UNWIND_FLAG, 0x4D1D0FC: UNWIND_FLAG, 0x4D1D602: UNWIND_FLAG, 0x4D1D7F0: UNWIND_FLAG,
    0x271CB46: DANGLING, 0x271D01C: DANGLING, 0x4D1CC26: DANGLING, 0x48474BF: DANGLING,
    0x4D1C3B1: DEAD_STORE, 0x4D1C3BA: DEAD_STORE, 0x4D1C3C3: DEAD_STORE, 0x4D1C538: DEAD_STORE, 0x4D1C541: DEAD_STORE, 0x4D1C54A: DEAD_STORE, 0x445E155: DEAD_STORE, 0x445E15E: DEAD_STORE, 0x445E167: DEAD_STORE,
    0x4D1C74C: OVERFLOW, 0x4D1C753: OVERFLOW, 0x47F88C2: OVERFLOW, 0x4847477: OVERFLOW, 0x484747E: OVERFLOW,
    0x4D1C880: UNREAD_BODY, 0x4D1C89C: UNREAD_BODY, 0x4D1C8CA: UNREAD_BODY, 0x4D1C8D3: UNREAD_BODY, 0x4D1C8FB: UNREAD_BODY, 0x4D1C917: UNREAD_BODY, 0x4D1C9D8: UNREAD_BODY, 0x4D1C9E5: UNREAD_BODY, 0x4D1CA02: UNREAD_BODY,
    0x4D1CC41: UNREAD_BODY, 0x4D1CC4A: UNREAD_BODY, 0x4D1CC68: UNREAD_BODY, 0x4D1CCE4: UNREAD_BODY, 0x4D1CCF1: UNREAD_BODY, 0x4D1CD07: UNREAD_BODY,
}


UNREACHED_REASON = "no case reaches it: an allocator failure arm, a panic arm, an unwind pad, the old body client id tag, or the drop of a rows vector that is empty on this path"
TWINS = {0x4D1DFF0: 0x4D1C1C0, 0x47F7C40: 0x47F88A0, 0x445E1E0: 0x445E150, 0x2517C10: 0x25182C0}


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return UNREACHED_REASON
    twin = TWINS.get(row["function"])
    return SURVIVED_REASONS.get(row["va"] - row["function"] + twin if twin else row["va"], SURVIVED_DEFAULT)


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
