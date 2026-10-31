#!/usr/bin/env python3
"""Pin the node #94 token freeze order path from ELF bytes: handler, per-spot sweep, TWAP removal, frozen user gate.

The freeze branch of the spot deploy action runs in `0x274b550` and its two copies. It adds the user to the
token's frozen set, then for each spot in the token's own list cancels the user's orders with reason 0x10,
removes the user's TWAPs on that spot, and flushes the rows. The gate on later actions is the predicate
`0x375f1c0`, reached from three host functions, which tests the base and the quote token of a spot. The
action asset list and the writer of the token's spot list complete the picture. The real bytes run in a Python
evaluator with only the edges stubbed. A separately written specification predicts every edge call, and every
condition, immediate and field offset of the main functions is flipped to show the run can tell. No objdump
or readelf output is parsed, and the binary is never executed. Standard library only.
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

STATUS_OK = 0x186
STATUS_TEXT = 0xDF
STATUS_FROZEN = 0x158
STATUS_NOT_FROZEN = 0x15A
STATUS_LENGTH = 0x143
MISSING_WORD = 0xCE
TERMINATED_WORD = 0x8000000000000001
ROW_TAG = 4
REASON_INTERNAL = 0x10
FROZEN_CAP = 1000
TOKEN_STRIDE = 0xE8
BOOK_STRIDE = 0xD8
SPOT_STRIDE = 0x20
ROW_STRIDE = 0x268
SPOT_LIMIT = 10000
META_IN_STATE = 0x90

MSG_CAP = (0x5998CD, 0x35)
MSG_REVOKED = (0x599902, 0x26)
MSG_TOO_MANY = (0x5996C9, 0xE)
MSG_SAME = (0x5996A5, 0x24)
MSG_USDC = (0x599641, 0x1D)
MSG_QUOTE = (0x59965E, 0x18)
MSG_DUPLICATE = (0x599691, 0x14)
MSG_FIRST = (0x599676, 0x1B)
MESSAGES = (MSG_CAP, MSG_REVOKED, MSG_TOO_MANY, MSG_SAME, MSG_USDC, MSG_QUOTE, MSG_DUPLICATE, MSG_FIRST)

SET_INSERT = 0x339B590
SET_REMOVE = 0x33ACFE0
PREDICATE = 0x375F1C0
REGISTER = 0x375EEB0
RESOLVER = 0x3C0CC70
ACCESSOR = 0x335ED30
ACTION_TABLE = 0x588BDC
ACTION_BASE_TAG = 0x74
ACTION_ROWS = 88
ACTION_DEFAULT = 0x14
ASSET_INSERT = 0x33987C0
ASSET_DRAIN = 0x33B6170
STATUS_DROP = 0x3C1ADA0
ARMS = {2: dict(name="batch modify", fn=0x3BDDF40, kind="list", ptr=8, len=0x10, stride=0x50, asset=0x38, slot=0x5775A70),
        12: dict(name="modify", fn=0x33E0170, kind="one", asset=0x38, slot=0x5775A78),
        14: dict(name="order", fn=0x33DF050, kind="list", ptr=0x30, len=0x38, stride=0x38, asset=0x20, slot=0x5775A60),
        35: dict(name="twap order", fn=0x3576F00, kind="one", asset=0x10, slot=0x5775A68)}
ASSET_ITER_LIMIT = 10000
ASSET_SPOT_LOW = 10000
ASSET_SPOT_HIGH = 110000
ASSET_OUTCOME_LOW = 100000000
RESOLVER_SPOT_FLAG = 1

GATE_HOSTS = (dict(name="first", start=0x2208580, enter=0x24BEBC8), dict(name="second", start=0x444B430, enter=0x454D659), dict(name="third", start=0x444C310, enter=0x454CD79))
GATE_ENTRY = 0x2208A0E
GATE_PASS = 0x2208B8F
GATE_END = 0x2208D33
GATE_NEXT = 0x2876550
SLOT_RESOLVER = 0x5773950
SLOT_PREDICATE = 0x57739D8
SLOT_ACTION_ASSETS = 0x57739D0
DISPLAY = 0x37FFD40
DISPLAY_TABLE = 0x59A8D0
DISPLAY_ROWS = 390

COPIES = (
    dict(name="first", entry=0x274B550, host=0x23E7D10, site=0x23E7FB3, books=0x3388, tracker=0x34E0, sweep=0x26E4240, twap=0x26DDBE0, flush=0x24FC8A0, book_location=0x56BB478, checked=False),
    dict(name="second", entry=0x4D69DA0, host=0x4AD81E0, site=0x4AD8483, books=0x3E08, tracker=0x3F60, sweep=0x4303B30, twap=0x42F4680, flush=0x432A990, book_location=0x5742338, checked=True),
    dict(name="third", entry=0x4D6A070, host=0x4AD78B0, site=0x4AD7B53, books=0x3388, tracker=0x34E0, sweep=0x43038B0, twap=0x42F4BF0, flush=0x432B440, book_location=0x5742338, checked=True),
)
FIRST = COPIES[0]
TWAP_COPIES = (COPIES[1], COPIES[2])
COLLECT = 0x486B870
TAKE = 0x4944230
USER_OUT = 0x49463E0
DRAIN = 0x49B7AD0
MAKE = 0x46CA2B0
MISSING_DROP = 0x4344430
VEC_GROW = 0x454F5D0

LOC_TOKEN = 0x56F2208
LOC_PRED_TOKEN = 0x56F21F0
LOC_PRED_SPOT = 0x56F1FD8
LOCATION_NAMES = {LOC_TOKEN: "freeze handler, token past the list", LOC_PRED_TOKEN: "frozen predicate, token past the list", LOC_PRED_SPOT: "frozen predicate, spot past the list",
                  0x56BB478: "freeze handler, spot past the books (first copy)", 0x5742338: "freeze handler, spot past the books (other copies)"}

SLOT_MEMCMP = 0x576E488
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_GROW_ROW = 0x5773D50
SLOT_GROW_SPOTS = 0x57744E8
SLOT_GROW_LIST = 0x5774460
SLOT_NAMES = {SLOT_MEMCMP: "memcmp, stubbed", SLOT_ALLOC: "allocate, stubbed", SLOT_ALLOC_FAILED: "allocation failure", SLOT_FREE: "free, stubbed", SLOT_MEMCPY: "memcpy, stubbed",
              SLOT_PANIC: "panic with Location", SLOT_BOUNDS: "index bounds panic", SLOT_GROW_ROW: "grow the 0x268 row vector, stubbed", SLOT_GROW_SPOTS: "grow the spot vector, stubbed",
              SLOT_GROW_LIST: "grow the token spot list, stubbed", SLOT_RESOLVER: "asset resolver", SLOT_PREDICATE: "frozen predicate", SLOT_ACTION_ASSETS: "action asset list"}

USER_MAP_NODE = dict(parent=0, values=8, value=0x18, keys=0x110, index=0x1EC, length=0x1EE, edges=0x1F0, leaf=0x1F0, inner=0x250, key=20)
TWAP_NODE = dict(parent=0x420, values=0, value=0x60, keys=0x428, index=0x480, length=0x482, edges=0x488, leaf=0x488, inner=0x4E8, key=8)
FROZEN_NODE = dict(parent=0, values=0, value=0, keys=8, index=0xE4, length=0xE6, edges=0xE8, leaf=0xE8, inner=0x148, key=20)
QUOTE_NODE = dict(parent=0, values=0x64, value=1, keys=8, index=0x60, length=0x62, edges=0x70, leaf=0x70, inner=0xD0, key=8)
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
MUTANT_STEP_LIMIT = 300000
FAKE_MEMCPY = 0x7E000010
FAKE_MEMCMP = 0x7E000030

OUT = HEAP_BASE + 0x800
EX = HEAP_BASE + 0x1000
USER = EX + 0x8000
ROWS = USER + 0x40
BUMP = ROWS + 0x100

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
    defaults = dict(copies=None, token=3, tokens=5, tag=1, freeze=1, frozen=0, spots=(), books=8, claimed=None, alloc_fails=False, reorder=False,
                    rows=(), others=(), user_present=True, asset=7, selector=1, stale=(), early=None, empty_out=False, grown=False, width=11, now=(20000, 3600, 5000),
                    spot_rows=((1, 0),), frozen_sets=None, tag_map=None, spot=0, user=1,
                    action=0x76, items=(), one=0, count=None,
                    base=2, quote=0, spot_count=None, list_full=False, spots_full=False, quotes=((0, 0),), name=b"NAME", name_len=8, token_name=b"PURR", base_list=(),
                    existing=(), quote_list=(9,),
                    assets=None, resolved=None, frozen_spots=())

    def __init__(self, label, kind, **fields):
        self.label, self.kind = label, kind
        for key, value in Case.defaults.items():
            setattr(self, key, fields.pop(key, value))
        if fields:
            raise EvidenceError("unknown case field: %s" % sorted(fields))


class SpecPanic(Exception):
    pass


def spec_handler(case, copy):
    events = []
    result = {"stop": None, "events": events, "status": None}
    try:
        if case.token >= case.tokens:
            raise SpecPanic(("panic", LOC_TOKEN))
        if case.tag != 1:
            result["status"] = (STATUS_TEXT,) + MSG_REVOKED
            return result
        if not case.freeze & 0xFF:
            events.append(("remove", case.token))
            result["status"] = (STATUS_OK,)
            return result
        if case.frozen >= FROZEN_CAP:
            result["status"] = (STATUS_TEXT,) + MSG_CAP
            return result
        events.append(("insert", case.token))
        count = len(case.spots) if case.claimed is None else case.claimed
        size = (count * 8) & MASK[8]
        if copy["checked"] and (count >> 61 or size > 0x7FFFFFFFFFFFFFF8):
            raise SpecPanic(("alloc failed", 0, size))
        if count:
            events.append(("alloc", size))
            if case.alloc_fails:
                raise SpecPanic(("alloc failed", 8, size))
        events.append(("copy", size))
        for number, spot in enumerate(case.spots):
            if spot >= case.books:
                raise SpecPanic(("panic", copy["book_location"]))
            events += [("sweep", spot), ("twap", spot), ("flush", 2 * number + 2)]
        if count:
            events.append(("free", size))
        result["status"] = (STATUS_OK,)
    except SpecPanic as caught:
        result["stop"] = caught.args[0]
    return result


def spec_twap(case, copy):
    events = []
    result = {"stop": None, "events": events, "length": 0}
    if not case.user_present:
        return result
    rows = sorted(case.rows)
    wanted = [number for number, spot in rows if not case.selector == 1 or spot == case.asset]
    if not wanted:
        return result
    remaining = len(rows)
    present = True
    capacity = 2 if case.grown else 64
    pushed = 0
    for number in wanted:
        if not present:
            events.append(("missing",))
            continue
        if number in case.stale:
            events += [("take", number, False), ("missing",)]
            continue
        remaining -= 1
        events.append(("take", number, True))
        if not remaining or number == case.early:
            present = False
            events.append(("user out",))
            if not case.empty_out:
                events.append(("drain step",))
        events.append(("make spot", number))
        if pushed == capacity:
            events.append(("grow",))
            capacity *= 2
        events.append(("row", number))
        pushed += 1
    room = 4
    while room < len(wanted):
        room *= 2
    events.append(("list free", room * 8))
    result["length"] = pushed
    return result


def frozen_in(case, token):
    return case.user in case.frozen_sets.get(token, ())


def spec_predicate(case, copy=None):
    result = {"stop": None, "events": [], "value": None}
    if case.spot >= len(case.spot_rows):
        result["stop"] = ("bounds", case.spot, len(case.spot_rows), LOC_PRED_SPOT)
        return result
    base, quote = case.spot_rows[case.spot]
    if base >= case.tokens:
        result["stop"] = ("panic", LOC_PRED_TOKEN)
        return result
    if (case.tag_map or {}).get(base, 1) == 1 and frozen_in(case, base):
        result["value"] = 1
        return result
    if quote >= case.tokens:
        result["stop"] = ("panic", LOC_PRED_TOKEN)
        return result
    result["value"] = 1 if (case.tag_map or {}).get(quote, 1) == 1 and frozen_in(case, quote) else 0
    return result


def keeps_asset(asset):
    return asset >= ASSET_OUTCOME_LOW or ASSET_SPOT_LOW <= asset < ASSET_SPOT_HIGH


def spec_accessor(case, copy=None):
    events = []
    result = {"stop": None, "events": events, "value": None}
    index = case.action - ACTION_BASE_TAG if case.action >= ACTION_BASE_TAG else ACTION_DEFAULT
    arm = ARMS.get(index)
    if arm is None:
        return result
    if index == 2 and (len(case.items) if case.count is None else case.count) > ASSET_ITER_LIMIT:
        events.append(("drop", STATUS_LENGTH))
        return result
    items = (case.one,) if arm["kind"] == "one" else case.items
    kept = sorted({asset for asset in items if keeps_asset(asset)})
    for asset in items:
        if keeps_asset(asset):
            events.append(("insert", asset))
    if kept:
        result["value"] = kept
    elif arm["kind"] == "list":
        events.append(("drain",))
    return result


def spec_register(case, copy=None):
    result = {"stop": None, "events": [], "status": None, "spots": list(case.existing), "base_list": list(case.base_list), "quote_list": list(case.quote_list)}
    count = len(case.existing) if case.spot_count is None else case.spot_count
    quotes = dict(case.quotes)
    if count >= SPOT_LIMIT:
        result["status"] = (STATUS_TEXT,) + MSG_TOO_MANY
        return result
    if case.base == case.quote:
        result["status"] = (STATUS_TEXT,) + MSG_SAME
        return result
    if case.base == 0:
        result["status"] = (STATUS_TEXT,) + MSG_USDC
        return result
    if quotes.get(case.quote, 1) == 1:
        result["status"] = (STATUS_TEXT,) + MSG_QUOTE
        return result
    if case.base >= case.tokens:
        result["stop"] = ("panic", LOC_TOKEN)
        return result
    pairs = {(row[0], row[1]) for row in case.existing}
    if (case.base, case.quote) in pairs or (case.quote, case.base) in pairs:
        result["status"] = (STATUS_TEXT,) + MSG_DUPLICATE
        return result
    if count == 0 and not (case.base == 1 and len(case.token_name) == 4 and case.token_name == b"PURR"):
        result["status"] = (STATUS_TEXT,) + MSG_FIRST
        return result
    if case.spots_full:
        result["events"].append(("grow spots",))
    if case.list_full:
        result["events"].append(("grow list",))
    result["spots"].append((case.base, case.quote))
    result["base_list"].append(count)
    result["status"] = (STATUS_OK, count)
    return result


def spec_gate(case, copy=None):
    events = []
    result = {"stop": None, "events": events, "status": None, "exit": "pass"}
    if case.assets is None:
        return result
    for position, asset in enumerate(case.assets):
        events.append(("next",))
        events.append(("resolve", asset))
        answer = case.resolved[asset]
        if answer[0] != "ok":
            result["status"] = answer[1]
            result["exit"] = "end"
            break
        spot, index = answer[1], answer[2]
        if spot != RESOLVER_SPOT_FLAG:
            continue
        events.append(("predicate", index))
        if index in case.frozen_spots:
            result["status"] = STATUS_FROZEN
            result["exit"] = "end"
            break
    else:
        position = len(case.assets)
        events.append(("next",))
    left = len(case.assets) - position - 1 if result["exit"] == "end" else 0
    events += [("next",)] * (max(left, 0) + 1)
    return result


def spec_run(case, copy=None):
    return {"handler": spec_handler, "twap": spec_twap, "predicate": spec_predicate, "accessor": spec_accessor, "register": spec_register, "gate": spec_gate}[case.kind](case, copy)


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


FAKE_RESOLVE = 0x7E000100
FAKE_PREDICATE = 0x7E000110
FAKE_ASSETS = 0x7E000120


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        for slot in (SLOT_ALLOC, SLOT_ALLOC_FAILED, SLOT_FREE, SLOT_PANIC, SLOT_BOUNDS, SLOT_GROW_ROW, SLOT_GROW_SPOTS, SLOT_GROW_LIST):
            machine.memory.statics[slot] = relative[slot]
        for arm in ARMS.values():
            machine.memory.statics[arm["slot"]] = relative[arm["slot"]]
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.memory.statics[SLOT_RESOLVER] = FAKE_RESOLVE
        machine.memory.statics[SLOT_PREDICATE] = FAKE_PREDICATE
        machine.memory.statics[SLOT_ACTION_ASSETS] = FAKE_ASSETS
        machine.slots = {relative[SLOT_ALLOC]: self.on_alloc, relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed, relative[SLOT_FREE]: self.on_free, relative[SLOT_PANIC]: self.on_panic,
                         relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_GROW_ROW]: self.on_grow_row, relative[SLOT_GROW_SPOTS]: self.on_grow_spots, relative[SLOT_GROW_LIST]: self.on_grow_list,
                         FAKE_MEMCPY: self.on_memcpy, FAKE_MEMCMP: self.on_memcmp, FAKE_RESOLVE: self.on_resolve, FAKE_PREDICATE: self.on_predicate, FAKE_ASSETS: self.on_assets}
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.copy = FIRST

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def start(self, case, entry):
        memory = self.machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.nodes = {}
        self.case = case
        self.entry_range = self.image.exact_fde(entry)
        memory.put_bytes(OUT, ramp(0x80, 13))
        memory.put_bytes(USER, user_id(case.user))
        self.machine.slots[FAKE_MEMCPY] = self.on_memcpy

    def build_tree(self, at, rows, shape, write_value, tempt=None):
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
                self.key_at = node + shape["keys"] + index * shape["key"]
                write_value(node + shape["values"] + index * shape["value"], row)
            if tempt is not None:
                for index in range(len(separators), NODE_KEYS):
                    memory.put_bytes(node + shape["keys"] + index * shape["key"], tempt)
            if level:
                for index, child in enumerate(children):
                    self.put(node + shape["edges"] + index * 8, 8, make(child, node, index, level - 1))
            return node

        level = tree_height(len(rows), NODE_KEYS)
        self.put(at, 8, make(list(rows), 0, 0, level))
        self.put(at + 8, 8, level)
        self.put(at + 0x10, 8, len(rows))

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
        if self.live.pop(pointer, None) != size:
            raise Halt("free of a block that does not match: %#x %#x" % (pointer, size))
        if m.regs[RDX] & MASK[4]:
            raise Halt("free flag")
        if self.from_entry(m):
            self.events.append(("list free" if self.case.kind == "twap" else "free", size))

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

    def status(self):
        read = self.machine.memory.read
        word = read(OUT, 2)
        if word == STATUS_TEXT:
            return (word, read(OUT + 8, 8), read(OUT + 0x10, 8))
        return (word,)

    # handler

    def on_insert(self, m):
        self.check_set(m)
        self.events.append(("insert", self.case.token))

    def on_remove(self, m):
        self.check_set(m)
        self.events.append(("remove", self.case.token))

    def check_set(self, m):
        if m.regs[RDI] != self.tokens + self.case.token * TOKEN_STRIDE + 0x18 or m.memory.bytes_at(m.regs[RSI], 20) != user_id(self.case.user):
            raise Halt("set arguments")

    def handler_copy(self, m):
        size = m.regs[RDX]
        self.events.append(("copy", size))
        if size and m.regs[RSI] != self.list_at or not size and m.regs[RDI] != 8:
            raise Halt("copy arguments")
        self.on_memcpy(m)

    def vec_words(self):
        read = self.machine.memory.read
        return read(self.vec, 8), read(self.vec + 8, 8), read(self.vec + 0x10, 8)

    def set_vec_words(self):
        self.pushed += 1
        self.put(self.vec, 8, self.pushed * 3)
        self.put(self.vec + 8, 8, 0x77000 + self.pushed)
        self.put(self.vec + 0x10, 8, self.pushed)

    def on_sweep(self, m):
        spot = (m.regs[RDI] - self.books) // BOOK_STRIDE
        self.vec = m.regs[R8]
        ok = (m.regs[RDI] == self.books + spot * BOOK_STRIDE and m.memory.bytes_at(m.regs[RSI], 20) == user_id(self.case.user) and m.regs[RDX] & MASK[4] == 1 and m.regs[RCX] == EX and
              m.regs[R9] & MASK[4] == REASON_INTERNAL and self.vec_words() == (0, 8, 0))
        if not ok:
            raise Halt("sweep arguments")
        self.events.append(("sweep", spot))
        self.last_spot = spot
        if self.case.reorder:
            m.memory.put_bytes(self.list_at, b"\x3f" * (8 * len(self.case.spots)))
        self.set_vec_words()

    def on_handler_twap(self, m):
        ok = (m.regs[RDI] == EX + self.copy["tracker"] and m.memory.bytes_at(m.regs[RSI], 20) == user_id(self.case.user) and m.regs[RDX] & MASK[4] == 1 and m.regs[RCX] == self.last_spot and m.regs[R8] == EX and
              m.regs[R9] == self.vec and self.vec_words() == (self.pushed * 3, 0x77000 + self.pushed, self.pushed))
        if not ok:
            raise Halt("TWAP arguments")
        self.events.append(("twap", self.last_spot))
        self.set_vec_words()

    def on_flush(self, m):
        read = m.memory.read
        at = m.regs[RDI]
        if m.regs[RSI] != EX or (read(at, 8), read(at + 8, 8), read(at + 0x10, 8)) != (self.pushed * 3, 0x77000 + self.pushed, self.pushed):
            raise Halt("flush arguments")
        self.events.append(("flush", self.pushed))

    def run_handler(self, case):
        copy = self.copy
        machine = self.machine
        self.start(case, copy["entry"])
        memory = machine.memory
        machine.calls = {SET_INSERT: self.on_insert, SET_REMOVE: self.on_remove, copy["sweep"]: self.on_sweep, copy["twap"]: self.on_handler_twap, copy["flush"]: self.on_flush}
        machine.real = frozenset({copy["entry"]})
        machine.slots[FAKE_MEMCPY] = self.handler_copy
        memory.put_bytes(EX, ramp(0x4000, 31))
        self.tokens = self.alloc(TOKEN_STRIDE * case.tokens)
        memory.put_bytes(self.tokens, ramp(TOKEN_STRIDE * case.tokens, 57))
        self.put(EX + 0x210, 8, self.tokens)
        self.put(EX + 0x218, 8, case.tokens)
        self.books = self.alloc(BOOK_STRIDE * max(case.books, 1))
        self.put(EX + copy["books"], 8, self.books)
        self.put(EX + copy["books"] + 8, 8, case.books)
        self.pushed = 0
        self.list_at = self.alloc(8 * max(len(case.spots), 1) + 8)
        if case.token < case.tokens:
            row = self.tokens + case.token * TOKEN_STRIDE
            self.put(row + 0x10, 4, case.tag)
            self.put(row + 0x28, 8, case.frozen)
            self.put(row + 0x58, 8, self.list_at)
            self.put(row + 0x60, 8, len(case.spots) if case.claimed is None else case.claimed)
            for index, spot in enumerate(case.spots):
                self.put(self.list_at + index * 8, 8, spot)
        result = machine.run(copy["entry"], {RDI: OUT, RSI: EX, RDX: case.token, RCX: USER, R8: case.freeze})
        if result != OUT:
            raise Halt("result pointer")
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events, "status": self.status()}

    # TWAP sweep

    def write_twap(self, value, row):
        self.put(value, 8, row[1])
        self.machine.memory.put_bytes(value + 8, ramp(0x58, row[1] & 0x3F))

    def write_user(self, value, row):
        me = row[0] == user_id(self.case.user)
        if me:
            self.me_key = self.key_at
            self.me_value = value
        keep_key = self.key_at
        pairs = sorted((struct.pack("<Q", number), spot) for number, spot in row[1])
        pairs.sort(key=lambda item: struct.unpack("<Q", item[0])[0])
        self.build_tree(value, pairs, TWAP_NODE, self.write_twap, struct.pack("<Q", 0x7654321))
        self.key_at = keep_key

    def on_take(self, m):
        out, value, number = m.regs[RDI], m.regs[RSI], m.memory.read(m.regs[RDX], 8)
        case = self.case
        memory = m.memory
        if value != self.me_value:
            raise Halt("take value pointer")
        if number in case.stale:
            self.events.append(("take", number, False))
            memory.put_bytes(out, ramp(0x60, 200))
            self.put(out + 0x22, 1, 2)
            return
        self.left -= 1
        self.put(value + 0x10, 8, 0 if number == case.early else self.left)
        self.events.append(("take", number, True))
        row = bytearray(ramp(0x60, number & 0x7F))
        row[0x22] = 1
        self.taken = bytes(row)
        memory.put_bytes(out, self.taken)

    def on_user_out(self, m):
        out = m.regs[RDI]
        if m.regs[RSI] != self.tracker + 0x18 or m.memory.bytes_at(m.regs[RDX], 20) != user_id(self.case.user):
            raise Halt("user out arguments")
        self.put(self.me_key + 19, 1, m.memory.read(self.me_key + 19, 1) ^ 1)
        self.events.append(("user out",))
        self.put(out, 8, 0 if self.case.empty_out else 1)
        self.out = out

    def on_drain(self, m):
        if m.regs[RDI] != self.out + 8:
            raise Halt("drain pointer")
        self.events.append(("drain step",))

    def on_make(self, m):
        if m.memory.bytes_at(m.regs[RSI], 0x60) != self.taken or m.regs[RDX] != EX + 0x90:
            raise Halt("make arguments")
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
        if m.regs[RDX] != ROW_STRIDE:
            raise Halt("row size")
        number = self.current_id()
        row = m.memory.bytes_at(m.regs[RSI], ROW_STRIDE)
        read = struct.unpack_from
        ok = (row[:8] == struct.pack("<Q", ROW_TAG) and row[8:0x60] == self.made() and read("<Q", row, 0x60)[0] == TERMINATED_WORD and read("<Q", row, 0x78)[0] == number and
              read("<III", row, 0x80) == self.case.now and row[0x8C:0xA0] == user_id(self.case.user))
        if not ok:
            raise Halt("row bytes")
        if m.regs[RDI] != self.row_base + m.memory.read(ROWS + 0x10, 8) * ROW_STRIDE:
            raise Halt("row slot")
        self.events.append(("row", number))
        self.on_memcpy(m)

    def on_grow_row(self, m):
        read = m.memory.read
        if m.regs[RDI] != ROWS:
            raise Halt("row vector")
        capacity, pointer, size = read(ROWS, 8), read(ROWS + 8, 8), read(ROWS + 0x10, 8)
        if size != capacity:
            raise Halt("grow while not full")
        at = self.alloc(capacity * 2 * ROW_STRIDE)
        m.memory.copy(at, pointer, size * ROW_STRIDE)
        self.put(ROWS, 8, capacity * 2)
        self.put(ROWS + 8, 8, at)
        self.row_base = at
        self.events.append(("grow",))

    def on_vec_grow(self, m):
        read = m.memory.read
        vec = m.regs[RDI]
        capacity, pointer = read(vec, 8), read(vec + 8, 8)
        if m.regs[RSI] != capacity or m.regs[RDX] != 1 or m.regs[RCX] != 8 or m.regs[R8] != 8:
            raise Halt("list grow arguments")
        at = self.alloc(capacity * 16)
        self.live[at] = capacity * 16
        m.memory.copy(at, pointer, capacity * 8)
        del self.live[pointer]
        self.put(vec, 8, capacity * 2)
        self.put(vec + 8, 8, at)

    def run_twap(self, case):
        copy = self.copy
        machine = self.machine
        entry = copy["twap"]
        self.start(case, entry)
        memory = machine.memory
        machine.calls = {TAKE: self.on_take, USER_OUT: self.on_user_out, DRAIN: self.on_drain, MAKE: self.on_make, MISSING_DROP: self.on_missing, VEC_GROW: self.on_vec_grow}
        machine.real = frozenset({entry, COLLECT, 0x4894610})
        machine.slots[FAKE_MEMCPY] = self.on_row_copy
        memory.put_bytes(EX, ramp(0x60, 31))
        for index, value in enumerate(case.now):
            self.put(EX + 0x60 + index * 4, 4, value)
        self.tracker = self.alloc(0x60)
        memory.put_bytes(self.tracker, ramp(0x60, 91))
        people = [(user_id(number), rows) for number, rows in case.others]
        if case.user_present:
            people.append((user_id(case.user), case.rows))
        self.left = len(case.rows)
        self.build_tree(self.tracker + 0x18, sorted(people, key=lambda row: row[0]), USER_MAP_NODE, self.write_user, user_id(case.user))
        capacity = 2 if case.grown else 64
        self.row_base = self.alloc(capacity * ROW_STRIDE)
        self.put(ROWS, 8, capacity)
        self.put(ROWS + 8, 8, self.row_base)
        self.put(ROWS + 0x10, 8, 0)
        machine.run(entry, {RDI: self.tracker, RSI: USER, RDX: case.selector, RCX: case.asset, R8: EX, R9: ROWS})
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events, "length": memory.read(ROWS + 0x10, 8)}

    # predicate

    def run_predicate(self, case):
        machine = self.machine
        self.start(case, PREDICATE)
        memory = machine.memory
        machine.calls = {}
        machine.real = frozenset({PREDICATE})
        meta = self.alloc(0x200)
        memory.put_bytes(meta, ramp(0x200, 71))
        spots = self.alloc(SPOT_STRIDE * max(len(case.spot_rows), 1))
        memory.put_bytes(spots, ramp(SPOT_STRIDE * max(len(case.spot_rows), 1), 77))
        for index, (base, quote) in enumerate(case.spot_rows):
            self.put(spots + index * SPOT_STRIDE, 8, base)
            self.put(spots + index * SPOT_STRIDE + 8, 8, quote)
        self.put(meta + 0x168, 8, spots)
        self.put(meta + 0x170, 8, len(case.spot_rows))
        tokens = self.alloc(TOKEN_STRIDE * case.tokens)
        memory.put_bytes(tokens, ramp(TOKEN_STRIDE * case.tokens, 83))
        self.put(meta + 0x180, 8, tokens)
        self.put(meta + 0x188, 8, case.tokens)
        for token in range(case.tokens):
            row = tokens + token * TOKEN_STRIDE
            self.put(row + 0x10, 4, (case.tag_map or {}).get(token, 1))
            keys = sorted(user_id(number) for number in case.frozen_sets.get(token, ()))
            self.build_tree(row + 0x18, [(key, 0) for key in keys], FROZEN_NODE, lambda value, entry: None, user_id(case.user))
        value = machine.run(PREDICATE, {RDI: meta, RSI: USER, RDX: case.spot})
        return {"stop": None, "events": self.events, "value": value & 0xFF}

    # action asset list

    def on_asset_insert(self, m):
        at = m.regs[RDI]
        if at != self.local:
            if self.local is not None:
                raise Halt("asset set moved")
            self.local = at
            if m.memory.read(at, 8) or m.memory.read(at + 0x10, 8):
                raise Halt("asset set not empty")
        asset = m.regs[RSI] & MASK[4]
        self.events.append(("insert", asset))
        self.kept.add(asset)
        self.put(at, 8, LEAF_EDGE)
        self.put(at + 8, 8, 0x41)
        self.put(at + 0x10, 8, len(self.kept))

    def on_asset_drain(self, m):
        rec = m.regs[RSI]
        if m.memory.read(rec, 8) or m.memory.read(rec + 0x20, 8) or m.memory.read(rec + 0x40, 8):
            raise Halt("drain record")
        self.events.append(("drain",))
        self.put(m.regs[RDI], 8, 0)

    def on_status_drop(self, m):
        self.events.append(("drop", m.memory.read(m.regs[RDI], 2)))

    def run_accessor(self, case):
        machine = self.machine
        self.start(case, ACCESSOR)
        memory = machine.memory
        machine.calls = {ASSET_INSERT: self.on_asset_insert, ASSET_DRAIN: self.on_asset_drain, STATUS_DROP: self.on_status_drop}
        machine.real = frozenset({ACCESSOR} | {arm["fn"] for arm in ARMS.values()})
        machine.jump_low, machine.jump_high = self.image.exact_fde(ACCESSOR)
        self.local = None
        self.kept = set()
        action = self.alloc(0x100)
        memory.put_bytes(action, ramp(0x100, 41))
        self.put(action, 8, case.action)
        index = case.action - ACTION_BASE_TAG if case.action >= ACTION_BASE_TAG else ACTION_DEFAULT
        arm = ARMS.get(index)
        if arm and arm["kind"] == "one":
            self.put(action + 8 + arm["asset"], 4, case.one)
        elif arm:
            rows = self.alloc(arm["stride"] * max(len(case.items), 1))
            memory.put_bytes(rows, ramp(arm["stride"] * max(len(case.items), 1), 47))
            for at, asset in enumerate(case.items):
                self.put(rows + at * arm["stride"] + arm["asset"], 4, asset)
            self.put(action + 8 + arm["ptr"], 8, rows)
            self.put(action + 8 + arm["len"], 8, len(case.items) if case.count is None else case.count)
        result = machine.run(ACCESSOR, {RDI: OUT, RSI: action})
        if result != OUT:
            raise Halt("result pointer")
        read = memory.read
        value = None
        word = read(OUT, 8)
        if word == 1:
            if (read(OUT + 8, 8), read(OUT + 0x10, 8), read(OUT + 0x18, 8)) != (LEAF_EDGE, 0x41, len(self.kept)):
                raise Halt("asset set words")
            value = sorted(self.kept)
        elif word:
            raise Halt("option word")
        return {"stop": None, "events": self.events, "value": value}

    # spot registration

    def on_grow_spots(self, m):
        if m.regs[RDI] != self.meta + 0x160:
            raise Halt("spot vector")
        self.events.append(("grow spots",))
        read = m.memory.read
        count = read(self.meta + 0x160, 8)
        at = self.alloc((count + 1) * SPOT_STRIDE)
        m.memory.copy(at, read(self.meta + 0x168, 8), count * SPOT_STRIDE)
        self.put(self.meta + 0x160, 8, count + 1)
        self.put(self.meta + 0x168, 8, at)

    def on_grow_list(self, m):
        row = self.token_row(self.case.base)
        if m.regs[RDI] != row + 0x50:
            raise Halt("spot list")
        self.events.append(("grow list",))
        read = m.memory.read
        count = read(row + 0x50, 8)
        at = self.alloc((count + 1) * 8)
        if count:
            m.memory.copy(at, read(row + 0x58, 8), count * 8)
        self.put(row + 0x50, 8, count + 1)
        self.put(row + 0x58, 8, at)

    def token_row(self, token):
        return self.machine.memory.read(self.meta + 0x180, 8) + token * TOKEN_STRIDE

    def read_list(self, token):
        read = self.machine.memory.read
        row = self.token_row(token)
        return [read(read(row + 0x58, 8) + index * 8, 8) for index in range(read(row + 0x60, 8))]

    def run_register(self, case):
        machine = self.machine
        self.start(case, REGISTER)
        memory = machine.memory
        machine.calls = {}
        machine.real = frozenset({REGISTER})
        self.meta = meta = self.alloc(0x300)
        memory.put_bytes(meta, ramp(0x300, 71))
        count = len(case.existing) if case.spot_count is None else case.spot_count
        rows = len(case.existing)
        spots = self.alloc(SPOT_STRIDE * (rows + 2))
        memory.put_bytes(spots, ramp(SPOT_STRIDE * (rows + 2), 77))
        for index, (base, quote) in enumerate(case.existing):
            self.put(spots + index * SPOT_STRIDE, 8, base)
            self.put(spots + index * SPOT_STRIDE + 8, 8, quote)
        self.put(meta + 0x160, 8, rows if case.spots_full else rows + 2)
        self.put(meta + 0x168, 8, spots)
        self.put(meta + 0x170, 8, count)
        tokens = self.alloc(TOKEN_STRIDE * max(case.tokens, 1))
        memory.put_bytes(tokens, ramp(TOKEN_STRIDE * max(case.tokens, 1), 83))
        self.put(meta + 0x180, 8, tokens)
        self.put(meta + 0x188, 8, case.tokens)
        for token in range(case.tokens):
            row = tokens + token * TOKEN_STRIDE
            items = case.base_list if token == case.base else case.quote_list if token == case.quote else ()
            room = len(items) if token == case.base and case.list_full else len(items) + 2
            at = self.alloc((room + 1) * 8)
            for index, value in enumerate(items):
                self.put(at + index * 8, 8, value)
            self.put(row + 0x50, 8, room)
            self.put(row + 0x58, 8, at)
            self.put(row + 0x60, 8, len(items))
            name = self.alloc(16)
            memory.put_bytes(name, case.token_name + b"\0" * (16 - len(case.token_name)))
            self.put(row + 0x38, 8, name)
            self.put(row + 0x40, 8, len(case.token_name))
        pairs = sorted((struct.pack("<Q", key), value) for key, value in case.quotes)
        pairs.sort(key=lambda item: struct.unpack("<Q", item[0])[0])
        self.build_tree(meta + 0x250, pairs, QUOTE_NODE, lambda value, row: self.put(value, 1, row[1]), struct.pack("<Q", case.quote))
        name = self.alloc(16)
        memory.put_bytes(name, ramp(16, 19))
        pair = self.alloc(16)
        self.put(pair, 8, case.base)
        self.put(pair + 8, 8, case.quote)
        result = machine.run(REGISTER, {RDI: OUT, RSI: meta, RDX: name, RCX: pair})
        if result != OUT:
            raise Halt("result pointer")
        read = memory.read
        status = self.status()
        if status[0] == STATUS_OK:
            status = (STATUS_OK, read(OUT + 8, 8))
        length = read(meta + 0x170, 8)
        at = read(meta + 0x168, 8)
        out_rows = [(read(at + index * SPOT_STRIDE, 8), read(at + index * SPOT_STRIDE + 8, 8)) for index in range(rows + (1 if status[0] == STATUS_OK else 0))]
        if status[0] == STATUS_OK:
            last = at + (length - 1) * SPOT_STRIDE
            if memory.bytes_at(last + 0x10, 12) != ramp(16, 19)[:12]:
                raise Halt("spot name bytes")
        return {"stop": None, "events": self.events, "status": status, "spots": out_rows, "base_list": self.read_list(case.base) if case.base < case.tokens else list(case.base_list),
                "quote_list": self.read_list(case.quote) if case.quote < case.tokens else list(case.quote_list)}

    # gate fragment of the first host

    def on_assets(self, m):
        at = m.regs[RDI]
        case = self.case
        if m.regs[RSI] != self.action or at != self.frame + 0x140:
            raise Halt("asset list arguments")
        self.put(at, 4, 0 if case.assets is None else 1)
        self.root = LEAF_EDGE if case.assets else 0
        self.put(at + 8, 8, self.root)
        self.put(at + 0x10, 8, 0x41)
        self.put(at + 0x18, 8, len(case.assets or ()))
        self.at = 0

    def on_next(self, m):
        rec, out = m.regs[RSI], m.regs[RDI]
        read = m.memory.read
        case = self.case
        flag = 1 if self.root else 0
        words = tuple(read(rec + index * 8, 8) for index in range(9))
        if rec != self.frame + 0xA0 or out != self.frame + 0x20 or words != (flag, 0, self.root, 0x41, flag, 0, self.root, 0x41, len(case.assets) if self.root else 0):
            raise Halt("next record")
        self.events.append(("next",))
        if self.at >= len(case.assets):
            self.put(out, 8, 0)
            return
        node = self.alloc(0x80)
        m.memory.put_bytes(node, ramp(0x80, 111))
        self.put(node + 8 + 4 * self.at, 4, case.assets[self.at])
        self.put(out, 8, node)
        self.put(out + 0x10, 8, self.at)
        self.at += 1

    def on_resolve(self, m):
        out = m.regs[RDI]
        asset = m.regs[RSI] & MASK[4]
        if out != self.frame + 0x20 or m.regs[RDX] != self.state + 0x5B8 or m.regs[RCX] != self.state + META_IN_STATE:
            raise Halt("resolver arguments")
        self.events.append(("resolve", asset))
        answer = self.case.resolved[asset]
        m.memory.put_bytes(out, ramp(0x80, 141))
        if answer[0] == "ok":
            self.put(out, 2, STATUS_OK)
            self.put(out + 8, 4, answer[1])
            self.put(out + 0x10, 8, answer[2])
        else:
            self.put(out, 2, answer[1])

    def on_predicate(self, m):
        if m.regs[RDI] != self.state + META_IN_STATE or m.regs[RSI] != self.frame + 0x20 or m.memory.bytes_at(m.regs[RSI], 20) != user_id(self.case.user):
            raise Halt("predicate arguments")
        index = m.regs[RDX]
        self.events.append(("predicate", index))
        m.regs[RAX] = (m.regs[RAX] & ~0xFF) | (1 if index in self.case.frozen_spots else 0)

    def run_gate(self, case):
        machine = self.machine
        self.start(case, GATE_HOSTS[0]["start"])
        memory = machine.memory
        machine.calls = {GATE_NEXT: self.on_next}
        machine.real = frozenset()
        self.state = self.alloc(0x800)
        memory.put_bytes(self.state, ramp(0x800, 61))
        self.action = self.alloc(0x40)
        memory.put_bytes(self.action, ramp(0x40, 67))
        regs = [POISON] * 16
        self.frame = STACK_TOP - 0x1000
        regs[RSP] = self.frame
        regs[R12], regs[R14], regs[RBX], regs[RBP], regs[R13], regs[R15] = self.state, self.action, OUT, 0x1234500, POISON, POISON
        machine.regs = regs
        memory.write(self.frame, 8, 0x1234500)
        memory.write(self.frame + 0x10, 8, self.action)
        memory.write(self.frame + 0x18, 8, USER)
        pc = GATE_ENTRY
        limit = machine.step_limit
        while pc not in (GATE_PASS, GATE_END):
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = machine.cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                machine.cache[pc] = row
            machine.seen.add(pc)
            machine.steps += 1
            pc = machine.step(row)
            if pc == RETURN_SENTINEL:
                raise Halt("left the fragment")
        if pc == GATE_PASS:
            if machine.regs[R12] != self.state or machine.regs[R14] != self.action or machine.regs[RBP] != 0x1234500:
                raise Halt("pass registers")
            return {"stop": None, "events": self.events, "status": None, "exit": "pass"}
        if memory.read(OUT, 1) != 0xE:
            raise Halt("end tag")
        status = memory.read(OUT + 8, 2)
        if status != STATUS_FROZEN:
            sent, got = ramp(0x80, 141), memory.bytes_at(OUT, 0x68)
            if got[0xA:0x10] != sent[0x2:0x8] or got[0x10:0x20] != sent[0x8:0x18] or got[0x20:0x68] != sent[0x18:0x60]:
                raise Halt("error payload")
        return {"stop": None, "events": self.events, "status": status, "exit": "end"}

    def run(self, case):
        try:
            return getattr(self, "run_" + case.kind)(case)
        except Panicked as caught:
            return {"stop": caught.args[0], "events": self.events}
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)


CRASHES = (Halt, EvidenceError, RecursionError, IndexError, KeyError, ZeroDivisionError, StopIteration, OverflowError, ValueError, TypeError, struct.error)
COMPARED = ("stop", "events", "status", "value", "exit", "spots", "base_list", "quote_list", "length")


def compare_run(harness, case):
    try:
        actual = harness.run(case)
    except CRASHES as caught:
        return "%s: crash %s" % (case.label, caught)
    expected = spec_run(case, harness.copy)
    for key in COMPARED:
        if key in expected and expected.get("stop") is None or key in ("stop", "events"):
            if actual.get(key) != expected.get(key):
                return "%s: %s differs: %s / %s" % (case.label, key, str(actual.get(key))[:300], str(expected.get(key))[:300])
    return None


# ---- cases ----

def handler_cases():
    spots = (4, 1, 6)
    cases = [
        Case("handler freeze, three spots", "handler", spots=spots),
        Case("handler freeze, one spot", "handler", spots=(0,)),
        Case("handler freeze, no spots", "handler", spots=()),
        Case("handler freeze, last token", "handler", token=4, spots=(7,)),
        Case("handler freeze, token 0", "handler", token=0, spots=(2,)),
        Case("handler unfreeze", "handler", freeze=0, spots=spots),
        Case("handler unfreeze at the cap", "handler", freeze=0, frozen=1000, spots=spots),
        Case("handler unfreeze, spare bits in the flag register", "handler", freeze=0x7F00, spots=spots),
        Case("handler freeze, spare bits in the flag register", "handler", freeze=0x7F01, spots=spots),
        Case("handler freeze byte 2", "handler", freeze=2, spots=(3,)),
        Case("handler privilege off", "handler", tag=0, spots=spots),
        Case("handler privilege word 2", "handler", tag=2, spots=spots),
        Case("handler privilege off, unfreeze", "handler", tag=0, freeze=0),
        Case("handler privilege high bits", "handler", tag=0x101, spots=spots),
        Case("handler token past the list", "handler", token=5),
        Case("handler token far past the list", "handler", token=900),
        Case("handler cap minus one", "handler", frozen=999, spots=spots),
        Case("handler at the cap", "handler", frozen=1000, spots=spots),
        Case("handler past the cap", "handler", frozen=1001, spots=spots),
        Case("handler cap in the low word only", "handler", frozen=0x1000000E8, spots=spots),
        Case("handler spot past the books", "handler", spots=(8,)),
        Case("handler second spot past the books", "handler", spots=(2, 9, 1)),
        Case("handler spot at the last book", "handler", spots=(7,)),
        Case("handler list is cloned first", "handler", spots=spots, reorder=True),
        Case("handler repeated spot", "handler", spots=(2, 2)),
        Case("handler allocation fails", "handler", spots=spots, alloc_fails=True),
        Case("handler list size past the limit", "handler", copies=("second", "third"), claimed=1 << 60),
        Case("handler list size wraps", "handler", copies=("second", "third"), claimed=1 << 61),
        Case("handler list size at the limit", "handler", copies=("second", "third"), claimed=(1 << 60) - 1, alloc_fails=True),
        Case("handler many spots", "handler", books=40, spots=tuple(range(0, 30, 3))),
    ]
    return cases


def twap_cases():
    wide = [(1000 + index * 7, 5 if index % 3 else 7) for index in range(40)]
    return [
        Case("twap empty map", "twap", user_present=False),
        Case("twap user absent, others left and right", "twap", user_present=False, others=((2, ((50, 7),)), (3, ((51, 7),)), (4, ((52, 7),)))),
        Case("twap user absent past every key", "twap", user_present=False, others=((7, ((50, 7),)), (14, ((51, 7),)))),
        Case("twap one row on the spot", "twap", rows=((100, 7),)),
        Case("twap one row on another spot", "twap", rows=((100, 8),)),
        Case("twap asset high bits differ", "twap", rows=((100, 7 + (1 << 40)),)),
        Case("twap two rows, one on the spot", "twap", rows=((100, 8), (101, 7))),
        Case("twap first of two on the spot", "twap", rows=((100, 7), (101, 8))),
        Case("twap all rows on the spot", "twap", rows=((100, 7), (101, 7), (102, 7))),
        Case("twap other users stay", "twap", rows=((100, 7),), others=((2, ((200, 7),)), (3, ((201, 7),)), (4, ((202, 8),)))),
        Case("twap crowded user map", "twap", rows=((100, 7), (105, 9)), others=tuple((number, ((300 + number, 7),)) for number in range(2, 16))),
        Case("twap selector 0 takes every spot", "twap", selector=0, rows=((100, 7), (101, 8), (102, 9))),
        Case("twap selector 2 takes every spot", "twap", selector=2, rows=((100, 7), (101, 8))),
        Case("twap stale id", "twap", rows=((100, 7), (101, 7), (102, 8)), stale=(101,)),
        Case("twap every id stale", "twap", rows=((100, 7), (101, 7)), stale=(100, 101)),
        Case("twap user goes early", "twap", rows=((100, 7), (101, 7), (102, 7)), early=100),
        Case("twap user goes early, keys on both sides", "twap", rows=((100, 7), (101, 7), (102, 7)), early=100, others=((7, ((50, 7),)), (2, ((51, 7),)))),
        Case("twap user goes early, lower keys only", "twap", rows=((100, 7), (101, 7), (102, 7)), early=100, others=((7, ((50, 7),)),)),
        Case("twap empty set from the map", "twap", rows=((100, 7),), empty_out=True),
        Case("twap row vector grows", "twap", rows=((100, 7), (101, 7), (102, 7), (103, 7), (104, 7)), grown=True),
        Case("twap list grows past four", "twap", rows=tuple((200 + index, 7) for index in range(5))),
        Case("twap list grows past eight", "twap", rows=tuple((200 + index, 7) for index in range(9))),
        Case("twap large ids", "twap", rows=(((1 << 63) + 5, 7), ((1 << 40) + 3, 7))),
        Case("twap two levels", "twap", rows=tuple(wide)),
        Case("twap two levels, last on the spot", "twap", rows=tuple((400 + index, 7 if index == 39 else 6) for index in range(40))),
        Case("twap two levels, first on the spot", "twap", rows=tuple((400 + index, 7 if index == 0 else 6) for index in range(40))),
    ]


def predicate_cases():
    me = 1
    other = (2, 3, 4)
    rows = ((1, 0), (2, 0), (3, 1))
    many = tuple(range(2, 60))
    return [
        Case("predicate no sets", "predicate", spot_rows=rows, frozen_sets={}),
        Case("predicate base frozen", "predicate", spot_rows=rows, frozen_sets={1: (me,)}),
        Case("predicate quote frozen", "predicate", spot_rows=rows, frozen_sets={0: (me,)}),
        Case("predicate both frozen", "predicate", spot_rows=rows, frozen_sets={0: (me,), 1: (me,)}),
        Case("predicate third token, spot 1", "predicate", spot=1, spot_rows=rows, frozen_sets={2: (me,)}),
        Case("predicate not this spot's base", "predicate", spot=1, spot_rows=rows, frozen_sets={1: (me,)}),
        Case("predicate spot 2 quote", "predicate", spot=2, spot_rows=rows, frozen_sets={1: (me,)}),
        Case("predicate spot 2 base", "predicate", spot=2, spot_rows=rows, frozen_sets={3: (me,)}),
        Case("predicate other users in the set", "predicate", spot_rows=rows, frozen_sets={1: other, 0: other}),
        Case("predicate user among others, base", "predicate", spot_rows=rows, frozen_sets={1: other + (me,)}),
        Case("predicate user among others, quote", "predicate", spot_rows=rows, frozen_sets={0: other + (me,)}),
        Case("predicate base, user past every key", "predicate", spot_rows=rows, frozen_sets={1: (7, 14)}),
        Case("predicate quote, user past every key", "predicate", spot_rows=rows, frozen_sets={0: (7, 14)}),
        Case("predicate base privilege off", "predicate", spot_rows=rows, frozen_sets={1: (me,)}, tag_map={1: 0}),
        Case("predicate quote privilege off", "predicate", spot_rows=rows, frozen_sets={0: (me,)}, tag_map={0: 0}),
        Case("predicate privilege word 2", "predicate", spot_rows=rows, frozen_sets={1: (me,)}, tag_map={1: 2}),
        Case("predicate base off, quote frozen", "predicate", spot_rows=rows, frozen_sets={0: (me,)}, tag_map={1: 0}),
        Case("predicate spot past the list", "predicate", spot=3, spot_rows=rows, frozen_sets={}),
        Case("predicate spot far past", "predicate", spot=4000, spot_rows=rows, frozen_sets={}),
        Case("predicate base past the tokens", "predicate", spot_rows=((5, 0),), frozen_sets={}),
        Case("predicate quote past the tokens", "predicate", spot_rows=((1, 5),), frozen_sets={}),
        Case("predicate last tokens", "predicate", spot_rows=((4, 3),), frozen_sets={3: (me,)}),
        Case("predicate tree base", "predicate", spot_rows=rows, frozen_sets={1: many + (me,)}),
        Case("predicate tree quote", "predicate", spot_rows=rows, frozen_sets={0: many + (me,)}),
        Case("predicate tree absent base", "predicate", spot_rows=rows, frozen_sets={1: many}),
        Case("predicate tree absent quote", "predicate", spot_rows=rows, frozen_sets={0: many}),
        Case("predicate tree absent both", "predicate", spot_rows=rows, frozen_sets={0: many, 1: many}),
    ]


def accessor_cases():
    low = (9999, 10000, 109999, 110000, 99999999, 100000000, 4294967295, 0)
    cases = []
    for index in range(ACTION_ROWS):
        if index not in ARMS:
            cases.append(Case("accessor action index %d" % index, "accessor", action=ACTION_BASE_TAG + index))
    cases.append(Case("accessor tag below the base", "accessor", action=0x73))
    cases.append(Case("accessor tag 0", "accessor", action=0))
    for index, arm in sorted(ARMS.items()):
        tag = ACTION_BASE_TAG + index
        if arm["kind"] == "one":
            for asset in low:
                cases.append(Case("accessor %s asset %d" % (arm["name"], asset), "accessor", action=tag, one=asset))
        else:
            cases.append(Case("accessor %s empty" % arm["name"], "accessor", action=tag))
            cases.append(Case("accessor %s perp only" % arm["name"], "accessor", action=tag, items=(1, 9999, 110000)))
            cases.append(Case("accessor %s boundaries" % arm["name"], "accessor", action=tag, items=low))
            cases.append(Case("accessor %s repeated" % arm["name"], "accessor", action=tag, items=(10007, 3, 10007, 100000001)))
            cases.append(Case("accessor %s last only" % arm["name"], "accessor", action=tag, items=(1, 2, 10001)))
            for asset in low:
                cases.append(Case("accessor %s one asset %d" % (arm["name"], asset), "accessor", action=tag, items=(asset,)))
    cases.append(Case("accessor batch past the limit", "accessor", action=ACTION_BASE_TAG + 2, items=(10000,), count=ASSET_ITER_LIMIT + 1))
    cases.append(Case("accessor order has no such limit", "accessor", action=ACTION_BASE_TAG + 14, items=tuple(10000 + number % 5 for number in range(ASSET_ITER_LIMIT + 1))))
    cases.append(Case("accessor batch at the limit", "accessor", action=ACTION_BASE_TAG + 2, items=tuple(20000 + number % 50 for number in range(ASSET_ITER_LIMIT))))
    return cases


def register_cases():
    ok = ((0, 0), (5, 0))
    many = tuple((key * 2, 0) for key in range(0, 40))
    old = ((3, 0), (4, 0))
    return [
        Case("register first spot, PURR", "register", base=1, quote=0, quotes=ok, tokens=6),
        Case("register first spot, name differs", "register", base=1, quote=0, quotes=ok, token_name=b"PURX"),
        Case("register first spot, name length", "register", base=1, quote=0, quotes=ok, token_name=b"PURRS"),
        Case("register first spot, other base", "register", base=2, quote=0, quotes=ok),
        Case("register second spot", "register", base=2, quote=0, quotes=ok, existing=((1, 0),), base_list=(), quote_list=(0,), tokens=6),
        Case("register list keeps the old spots", "register", base=2, quote=0, quotes=ok, existing=old, base_list=(7, 8), quote_list=(0, 1), tokens=6),
        Case("register quote token 5", "register", base=2, quote=5, quotes=ok, existing=old, tokens=6),
        Case("register quote list untouched", "register", base=4, quote=0, quotes=ok, existing=((3, 0),), quote_list=(1, 2, 3)),
        Case("register list full", "register", base=2, quote=0, quotes=ok, existing=old, list_full=True, base_list=(1,)),
        Case("register list full, empty", "register", base=2, quote=0, quotes=ok, existing=old, list_full=True),
        Case("register spot vector full", "register", base=2, quote=0, quotes=ok, existing=old, spots_full=True),
        Case("register both full", "register", base=2, quote=0, quotes=ok, existing=old, spots_full=True, list_full=True),
        Case("register same tokens", "register", base=2, quote=2, quotes=((2, 0),), existing=old, quote_list=()),
        Case("register USDC base", "register", base=0, quote=2, quotes=((2, 0),), existing=old),
        Case("register quote absent", "register", base=2, quote=1, quotes=ok, existing=old),
        Case("register quote past every key", "register", base=2, quote=30, quotes=ok, existing=old),
        Case("register quote flagged", "register", base=2, quote=5, quotes=((0, 0), (5, 1)), existing=old),
        Case("register quote flag 2", "register", base=2, quote=5, quotes=((0, 0), (5, 2)), existing=old, tokens=6),
        Case("register empty quote map", "register", base=2, quote=0, quotes=(), existing=old),
        Case("register quote deep left", "register", base=2, quote=4, quotes=many, existing=old, tokens=6),
        Case("register quote deep right", "register", base=2, quote=78, quotes=many, existing=old, tokens=6),
        Case("register quote deep absent", "register", base=2, quote=7, quotes=many, existing=old, tokens=6),
        Case("register base past the tokens", "register", base=9, quote=0, quotes=ok, existing=old),
        Case("register duplicate", "register", base=3, quote=0, quotes=ok, existing=old),
        Case("register duplicate second row", "register", base=4, quote=0, quotes=ok, existing=old),
        Case("register duplicate reversed", "register", base=3, quote=5, quotes=((0, 0), (3, 0), (5, 0)), existing=((5, 3),), tokens=6),
        Case("register same base, other quote", "register", base=3, quote=5, quotes=ok, existing=old, tokens=6),
        Case("register same quote as row base", "register", base=2, quote=3, quotes=((3, 0),), existing=old),
        Case("register 9999 spots", "register", base=2, quote=0, quotes=ok, tokens=6, existing=tuple((3 + number % 3, 100 + number) for number in range(SPOT_LIMIT - 1))),
        Case("register 10000 spots", "register", base=2, quote=0, quotes=ok, spot_count=10000, existing=old),
        Case("register many past the limit", "register", base=2, quote=2, quotes=ok, spot_count=20000, existing=old, quote_list=()),
    ][::1]


def gate_cases():
    spot = lambda index: ("ok", 1, index)
    perp = lambda index: ("ok", 0, index)
    resolved = {10000: spot(0), 10001: spot(1), 10002: spot(2), 10003: spot(3), 100000000: perp(0), 100000001: ("error", 0x17F), 100000002: ("error", 0x60), 100000003: ("ok", 2, 3)}
    return [
        Case("gate no list", "gate"),
        Case("gate empty list", "gate", assets=()),
        Case("gate one asset, clear", "gate", assets=(10000,), resolved=resolved),
        Case("gate one asset, frozen", "gate", assets=(10000,), resolved=resolved, frozen_spots=(0,)),
        Case("gate second asset frozen", "gate", assets=(10000, 10001, 10002), resolved=resolved, frozen_spots=(1,)),
        Case("gate last asset frozen", "gate", assets=(10000, 10001, 10002), resolved=resolved, frozen_spots=(2,)),
        Case("gate all clear", "gate", assets=(10000, 10001, 10002, 10003), resolved=resolved),
        Case("gate resolved as a perp", "gate", assets=(100000000,), resolved=resolved, frozen_spots=(0,)),
        Case("gate perp then frozen spot", "gate", assets=(100000000, 10001), resolved=resolved, frozen_spots=(1,)),
        Case("gate other result word", "gate", assets=(100000003,), resolved=resolved, frozen_spots=(3,)),
        Case("gate resolver error", "gate", assets=(100000001,), resolved=resolved),
        Case("gate resolver error, later ones drained", "gate", assets=(10000, 100000002, 10001, 10002), resolved=resolved),
        Case("gate frozen first, others drained", "gate", assets=(10000, 10001, 10002), resolved=resolved, frozen_spots=(0,)),
    ]


def all_cases():
    return handler_cases() + twap_cases() + predicate_cases() + accessor_cases() + register_cases() + gate_cases()


# ---- runs over the cases ----

def copies_of(case):
    if case.kind == "handler":
        return [copy for copy in COPIES if not case.copies or copy["name"] in case.copies]
    if case.kind == "twap":
        return list(TWAP_COPIES)
    return [FIRST]


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


def slot_sites(image, slots):
    """Every FF 15 call through a data slot, in .text order."""
    base, text = image.text_bytes()
    found = {slot: [] for slot in slots}
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if slot in found:
            found[slot].append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return found


def read_gate_sites(image):
    """Predicate sites, the resolver call before each, and the status word written after each."""
    sites = slot_sites(image, (SLOT_RESOLVER, SLOT_PREDICATE))
    rows = []
    for va in sites[SLOT_PREDICATE]:
        begin, end = image.fde(va)
        window = bytes(image.blob[image.offset(va):image.offset(va) + 32])
        if window[6:8] != b"\x84\xc0" or window[8] != 0x74:
            raise EvidenceError("predicate result test moved: %#x" % va)
        back = window[9]
        at = window.find(b"\x66\xc7", 10)
        if at < 0:
            raise EvidenceError("no status write after %#x" % va)
        size = 10 if window[at + 2] == 0x84 else 6
        word = struct.unpack_from("<H", window, at + size - 2)[0]
        resolvers = [site for site in sites[SLOT_RESOLVER] if begin <= site < va]
        rows.append({"host": "%#x" % begin, "host_end": "%#x" % end, "predicate_site": "%#x" % va, "resolver_site": "%#x" % resolvers[-1], "resolver_sites_in_host": len(resolvers),
                     "status_site": "%#x" % (va + at), "status_word": "%#x" % word, "je_back_to": "%#x" % (va + 10 + struct.unpack("<b", bytes([back]))[0])})
    return {"predicate_sites": len(sites[SLOT_PREDICATE]), "resolver_sites": len(sites[SLOT_RESOLVER]), "rows": rows}


def read_action_table(image):
    rows = []
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    begin, end = image.exact_fde(ACCESSOR)
    at = image.offset(ACTION_TABLE)
    arm_of = {}
    for index in range(ACTION_ROWS):
        target = ACTION_TABLE + struct.unpack_from("<i", image.blob, at + index * 4)[0]
        if not begin <= target < end:
            raise EvidenceError("action table row outside the accessor: %d" % index)
        arm_of.setdefault(target, []).append(index)
    following = ACTION_TABLE + struct.unpack_from("<i", image.blob, at + ACTION_ROWS * 4)[0]
    for target, indices in sorted(arm_of.items()):
        rows.append({"arm": "%#x" % target, "indices": indices if len(indices) < 8 else "%d rows" % len(indices)})
    called = {}
    for index, arm in sorted(ARMS.items()):
        target = ACTION_TABLE + struct.unpack_from("<i", image.blob, at + index * 4)[0]
        window = bytes(image.blob[image.offset(target):image.offset(target) + 16])
        if window[:4] != b"\x48\x83\xc6\x08" or window[7:9] != b"\xff\x15":
            raise EvidenceError("arm shape: %d" % index)
        slot = target + 7 + 6 + struct.unpack_from("<i", window, 9)[0]
        called[str(index)] = {"tag": "%#x" % (ACTION_BASE_TAG + index), "name_inferred": arm["name"], "arm": "%#x" % target, "slot": "%#x" % slot, "body": "%#x" % relative[slot]}
    return {"rows": rows, "selected": called, "row_after_table_inside_function": begin <= following < end}


def read_display(image, tags=(STATUS_FROZEN, STATUS_NOT_FROZEN, STATUS_LENGTH)):
    rows = []
    at = image.offset(DISPLAY_TABLE)
    begin, end = image.exact_fde(DISPLAY)
    for tag in tags:
        arm = DISPLAY_TABLE + struct.unpack_from("<i", image.blob, at + tag * 4)[0]
        if not begin <= arm < end:
            raise EvidenceError("display arm: %#x" % tag)
        window = bytes(image.blob[image.offset(arm):image.offset(arm) + 24])
        if window[:11] != bytes.fromhex("488b3e488b4608488b4018") or window[11:14] != b"\x48\x8d\x35" or window[18] != 0xBA:
            raise EvidenceError("display arm shape: %#x" % tag)
        text_at = arm + 18 + struct.unpack_from("<i", window, 14)[0]
        size = struct.unpack_from("<I", window, 19)[0]
        rows.append({"tag": "%#x" % tag, "arm": "%#x" % arm, "text": "%#x" % text_at, "length": size, "value": bytes(image.blob[image.offset(text_at):image.offset(text_at) + size]).decode("ascii")})
    return rows


def read_messages(image):
    return [{"at": "%#x" % at, "length": size, "value": bytes(image.blob[image.offset(at):image.offset(at) + size]).decode("ascii")} for at, size in MESSAGES]


def read_action_fields(image):
    """The call into each handler copy takes the token, the user and the flag from one action record."""
    rows = []
    for copy in COPIES:
        begin = copy["site"] - 37
        window = bytes(image.blob[image.offset(begin):image.offset(copy["site"])])
        if window[:13] != bytes.fromhex("498b5708493b96180200000f83") or window[17:26] != bytes.fromhex("450fb647244983c710"):
            raise EvidenceError("action field reads moved: %#x" % copy["site"])
        target = begin + 17 + struct.unpack_from("<i", window, 13)[0]
        arm = bytes(image.blob[image.offset(target):image.offset(target) + 6])
        if arm[:4] != b"\x66\xc7\x43\x08":
            raise EvidenceError("bound arm moved: %#x" % target)
        rows.append({"copy": copy["name"], "site": "%#x" % copy["site"], "host": "%#x" % image.fde(copy["site"])[0], "token_field": "+0x8", "bound_field": "+0x218", "flag_field": "+0x24", "user_field": "+0x10",
                     "past_end_arm": "%#x" % target, "past_end_status": "%#x" % struct.unpack_from("<H", arm, 4)[0]})
    return rows


def body_diff(image, left, right):
    """Instruction rows of two copies that differ, with rip targets and call targets resolved."""
    a, b = decode_range(image, *image.exact_fde(left)), decode_range(image, *image.exact_fde(right))
    rows = []
    for one, two in zip(a, b):
        first = bytes(image.blob[image.offset(one.va):image.offset(one.va) + one.size])
        second = bytes(image.blob[image.offset(two.va):image.offset(two.va) + two.size])
        if one.size != two.size or one.op != two.op:
            rows.append({"left": "%#x" % one.va, "right": "%#x" % two.va, "class": "shape"})
        elif one.op in ("call", "jmp", "jcc") and one.target is not None:
            left_end, right_end = image.exact_fde(left)[1], image.exact_fde(right)[1]
            inside = left <= one.target < left_end and right <= two.target < right_end
            if (one.target - left != two.target - right) if inside else one.target != two.target:
                rows.append({"left": "%#x" % one.va, "right": "%#x" % two.va, "class": "call target", "from": "%#x" % one.target, "to": "%#x" % two.target})
        elif first != second:
            one_slot = one.rip_at is not None and one.va + one.size + struct.unpack_from("<i", first, one.rip_at)[0]
            two_slot = two.rip_at is not None and two.va + two.size + struct.unpack_from("<i", second, two.rip_at)[0]
            if one.rip_at is None or one_slot != two_slot:
                rows.append({"left": "%#x" % one.va, "right": "%#x" % two.va, "class": "field", "from": first.hex(), "to": second.hex()})
    return {"left": "%#x" % left, "right": "%#x" % right, "instructions": [len(a), len(b)], "rows": rows}


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
    """(function start, role, decoded rows, case kinds, copy)."""
    groups = []
    for copy in COPIES[:2]:
        groups.append((copy["entry"], "freeze handler, %s copy" % copy["name"], decode_range(image, *image.exact_fde(copy["entry"])), ("handler",), copy))
    groups.append((COPIES[1]["twap"], "TWAP sweep, second copy", decode_range(image, *image.exact_fde(COPIES[1]["twap"])), ("twap",), COPIES[1]))
    groups.append((COLLECT, "TWAP id filter inside the collector", decode_range(image, 0x486B8A1, 0x486B8B3) + decode_range(image, 0x486B937, 0x486B960), ("twap",), COPIES[1]))
    groups.append((PREDICATE, "frozen predicate", decode_range(image, *image.exact_fde(PREDICATE)), ("predicate",), FIRST))
    groups.append((ACCESSOR, "action asset list", decode_range(image, *image.exact_fde(ACCESSOR)), ("accessor",), FIRST))
    for index, arm in sorted(ARMS.items()):
        groups.append((arm["fn"], "%s asset arm" % arm["name"], decode_range(image, *image.exact_fde(arm["fn"])), ("accessor",), FIRST))
    groups.append((REGISTER, "spot registration", decode_range(image, *image.exact_fde(REGISTER)), ("register",), FIRST))
    groups.append((GATE_HOSTS[0]["start"], "gate fragment", decode_range(image, GATE_ENTRY, GATE_END), ("gate",), FIRST))
    return groups


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    pool = all_cases()
    for start, _, rows, kinds, copy in mutated_groups(image):
        cases = [case for case in pool if case.kind in kinds and copy in copies_of(case)]
        harness.copy = copy
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
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:656", "claim": "cap message is the literal text capped at 1000", "observed": "the ELF text at 0x5998cd is 53 bytes and keeps the braces: {MAX_N_FROZEN_USERS}", "verdict": "mismatch"},
    {"reference": "l1/spot_meta.rs:887", "claim": "cap message keeps {MAX_N_FROZEN_USERS}", "observed": "same 53 bytes", "verdict": "match"},
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:292", "claim": "abstract remove_user_orders_for_freeze(token, user, spots); no body", "observed": "the body is inside each handler copy: wrapper with flag 1 and reason 0x10, TWAP sweep with flag 1, row flush, per spot", "verdict": "filled in"},
    {"reference": "l1/spot_meta.rs:566-569", "claim": "per spot remove_user_orders_for_freeze then emit_freeze_book_delta", "observed": "three calls per spot; the TWAP sweep is not named by the reference", "verdict": "partial"},
    {"reference": "l1/spot_meta.rs:361", "claim": "spot registration pushes only onto the base token's list", "observed": "0x375eeb0 writes through the base row only", "verdict": "match"},
    {"reference": "l1/abci/state.rs:8", "claim": "0x2208580 is handle_candidate_peer_abci_state_response", "observed": "the function runs the action asset list, the frozen predicate and status 0x158 at 0x2208a0e-0x2208d33", "verdict": "label does not describe this block"},
    {"reference": "l1/abci/state.rs:14,625", "claim": "0x444b430 maps 0x70 records to 0x48 records", "observed": "same gate block at 0x444be51-0x444bea0", "verdict": "label does not describe this block"},
)
LANDING = "unwind landing pad or panic tail: no case unwinds"
AFTER_GATE = "after the block: the fragment stops at the pass exit, and this is the action path behind it"
SET_DRAIN = "drain setup for a set with a root but length 0: the insert-only set never gives this"
NONE_ROWS = "action rows 0, 0x14 and 0x15 all return None, so the mutated row looks the same"
REASON_RANGES = ((0x4D6A034, 0x4D6A062, LANDING), (0x42F4BA4, 0x42F4BE5, LANDING), (0x2208B48, 0x2208B56, "status 0x111 arm of the block before the gate, jumped to from before the fragment"), (GATE_PASS, 0x2208CC6, AFTER_GATE))
REASONS = {0x4D69E77: "a list of 2^60 entries already fails the size test, so shift counts 0x3c and 0x3d agree", 0x4D69E7E: "sizes are multiples of 8, so the bounds ending f8 and f9 agree",
           0x42F47B3: "back handle of the iterator: the collector only walks forward", 0x335ED38: NONE_ROWS, 0x335ED3C: NONE_ROWS,
           0x3BDE026: SET_DRAIN, 0x3BDE039: SET_DRAIN, 0x3BDE04C: SET_DRAIN, 0x33DF108: SET_DRAIN, 0x33DF11B: SET_DRAIN, 0x33DF12E: SET_DRAIN}


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
    if case.kind == "predicate":
        return "predicate: %d" % spec["value"]
    if case.kind in ("handler", "register"):
        return "%s: status %#x" % (case.kind, spec["status"][0])
    if case.kind == "accessor":
        return "accessor: %s" % ("some" if spec["value"] else "none")
    if case.kind == "gate":
        return "gate: %s" % spec["exit"]
    return "%s: returned" % case.kind


def worked_run(harness):
    """One freeze of token 3 in the first copy: two spots in its list, spot 6 past nothing."""
    harness.copy = FIRST
    case = Case("worked", "handler", spots=(4, 6), frozen=12)
    run = harness.run(case)
    return {"token": case.token, "frozen_before": case.frozen, "spots": list(case.spots), "events": [list(event) for event in run["events"]], "status": "%#x" % run["status"][0]}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    per_kind = {}
    runs = 0
    for case in cases:
        for copy in copies_of(case):
            harness.copy = copy
            runs += 1
            per_kind[case.kind] = per_kind.get(case.kind, 0) + 1
            trouble = compare_run(harness, case)
            if trouble:
                mismatches.append("%s %s" % (copy["name"], trouble))
        name = outcome_name(case, spec_run(case, copies_of(case)[0]))
        outcomes[name] = outcomes.get(name, 0) + 1
    seen = set(harness.machine.seen)
    steps = harness.machine.steps
    worked = worked_run(harness)
    functions = []
    named = [(copy["entry"], "freeze handler, %s copy" % copy["name"]) for copy in COPIES] + [(copy["twap"], "TWAP sweep, %s copy" % copy["name"]) for copy in TWAP_COPIES]
    named += [(COLLECT, "TWAP id collector"), (PREDICATE, "frozen predicate"), (ACCESSOR, "action asset list"), (REGISTER, "spot registration")]
    named += [(arm["fn"], "%s asset arm" % arm["name"]) for _, arm in sorted(ARMS.items())]
    for start, role in named:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    fragment = decode_range(image, GATE_ENTRY, GATE_END)
    functions.append({"role": "gate fragment of the first host", "start": "%#x" % GATE_ENTRY, "end": "%#x" % GATE_END, "size": GATE_END - GATE_ENTRY, "instructions": len(fragment), "instructions_stepped": sum(1 for row_ in fragment if row_.va in seen)})
    hosts = [{"name": host["name"], "start": "%#x" % image.exact_fde(host["start"])[0], "end": "%#x" % image.exact_fde(host["start"])[1]} for host in GATE_HOSTS]
    sites = direct_sites(image, sorted({copy["entry"] for copy in COPIES} | {copy["twap"] for copy in COPIES} | {host["start"] for host in GATE_HOSTS}))
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    relative = harness.relative
    locations = []
    for slot, name in sorted(LOCATION_NAMES.items()):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    gate = read_gate_sites(image)
    action = read_action_table(image)
    display = read_display(image)
    messages = read_messages(image)
    diffs = [body_diff(image, COPIES[1]["entry"], COPIES[2]["entry"]), body_diff(image, COPIES[1]["twap"], COPIES[2]["twap"]), body_diff(image, COPIES[1]["twap"], COPIES[0]["twap"])]
    results_rows = run_mutants(image, seen, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "gate_hosts": hosts,
        "gate": gate,
        "action_table": action,
        "status_text": display,
        "messages": messages,
        "action_fields": read_action_fields(image),
        "copies": [{key: ("%#x" % value if isinstance(value, int) and not isinstance(value, bool) else value) for key, value in copy.items()} for copy in COPIES],
        "copy_diff": diffs,
        "slots": {"%#x" % slot: SLOT_NAMES[slot] for slot in sorted(SLOT_NAMES)},
        "locations": locations,
        "node_shapes": {"user_map": USER_MAP_NODE, "twap": TWAP_NODE, "frozen_set": FROZEN_NODE, "quote_map": QUOTE_NODE},
        "fields": FIELDS,
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases), "runs": runs, "per_kind": dict(sorted(per_kind.items()))},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows,
    }


FIELDS = {
    "state": {"+0x90": "token and spot metadata block", "+0x60": "12-byte time copied into each TWAP row", "+0x210": "token list pointer (metadata +0x180)", "+0x218": "token list length (metadata +0x188)",
              "+0x3388/+0x3390": "spot book list, first and third copy", "+0x34e0": "spot TWAP tracker, first and third copy", "+0x3e08/+0x3e10": "spot book list, second copy", "+0x3f60": "spot TWAP tracker, second copy"},
    "metadata": {"+0x160/+0x168/+0x170": "spot rows: capacity, pointer, length", "+0x180/+0x188": "token rows: pointer, length", "+0x250/+0x258": "quote map: root, height"},
    "spot_row": {"stride": "0x20", "+0x00": "base token", "+0x08": "quote token", "+0x10": "12-byte name"},
    "token_row": {"stride": "0xe8", "+0x10": "freeze privilege word, 1 = on", "+0x18/+0x20/+0x28": "frozen set: root, height, length", "+0x38/+0x40": "name: pointer, length", "+0x50/+0x58/+0x60": "spot list: capacity, pointer, length"},
    "action_record": {"+0x08": "token", "+0x10": "user, 20 bytes", "+0x24": "freeze flag byte"},
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
