#!/usr/bin/env python3
"""Pin the node #94 quote token enable path from ELF bytes: spot gates, book mid band, pair creation, 0xfe row.

`0x4d62140` and its two copies enable a spot token as a quote token. Before the registry write they require a
USDC pair, refuse a second quote token of one deployer, and read the USDC pair's book: both sides present and
the median of best bid, best ask and the book's +0x78 word within 0.2 of a price of 1. The writer `0x375fe00`
then records the status, the function makes the pair against the native token when it is missing, and copies
that token's 0xfe buy row to the new pair. The real bytes run in a Python evaluator with only the edges
stubbed. A separately written specification predicts every edge call, and every condition, immediate and
field offset of the main functions is flipped to show the run can tell. No objdump or readelf output is
parsed, and the binary is never executed. Standard library only.
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

STATUS_OK = 0x186
STATUS_TEXT = 0xDF
STATUS_NO_NATIVE = 0xFB
STATUS_INVALID = 0xEF
TOKEN_STRIDE = 0xE8
BOOK_STRIDE = 0xD8
SPOT_STRIDE = 0x20
UPPER = 0.2
LOWER = -0.2
PAIR_PRICE_DEFAULT = 2.0
QUOTE_WEI = 8
FLOOR_FIELD = 10.0
ROW_AMOUNT_LIMIT = 0x28F5C28F5C28F5B
ROW_HUNDREDS_LIMIT = 0x68DB8BAC710CB
TESTNET_QUOTE_LIMIT = 0x56E
SKIPPED_NAME = b"USDT0"
NETWORK_SKIPS = 2

TEXT_PAIR = (0x715141, 0x1F)
TEXT_ONE = (0x71511F, 0x22)
TEXT_EMPTY = (0x715100, 0x1F)
TEXT_FAR = (0x20C740, 0x20)
TEXT_FEE = (0x59987D, 0x2C)
TEXT_ALLOWED = (0x599866, 0x17)
TEXTS = (TEXT_PAIR, TEXT_ONE, TEXT_EMPTY, TEXT_FAR, TEXT_FEE, TEXT_ALLOWED)
WORDS = {"pair": b"quote token must have USDC pair", "one": b"can deploy at most one quote token", "empty": b"quote token has empty book side", "far": b"quote token price too far from 1",
         "fee": b"quote token deployer trading fee is not zero", "allowed": b"quote token not allowed"}

SCAN_SPOTS = 0x3BB5F50
SCAN_NEXT = 0x3BE6950
FILTER_NEXT = 0x4876840
FILTER_TEST = 0x4C6BE50
SCALE = 0x375FB50
WRITER = 0x375FE00
FIND_PAIR = 0x375E430
USDC_PAIR = 0x3760070
SYSTEM_READ = 0x333A520
SYSTEM_MAKE = 0x333A420
MEDIAN = 0x471DE00
COLLECT_TOPS = 0x4883410
STATUS_MOVE = 0x4DD5D00
DECIMAL = 0x3790B60
RESOLVE = 0x33690C0
RESOLVE_DROP = 0x3379490
STATUS_INSERT = 0x339D350
ALIGNED_INSERT = 0x33BE810
SYSTEM_INSERT = 0x339B7C0
GROW_SCAN = 0x32D6A00
GROW_FILTER = 0x454F5D0
COMMON_REAL = (SCAN_SPOTS, SCAN_NEXT, SCALE, WRITER, FIND_PAIR, USDC_PAIR, SYSTEM_READ, SYSTEM_MAKE)

COPIES = (
    dict(name="second", entry=0x4D62140, price=0x4DD5AE0, mid=0x42FBA60, tops=0x4A078A0, set_filter=0x444FCD0, books=0x3388, system=0x3A00, network=0x8F2, resolver=0x3840, gate=0x4D76AC0, register=0x4D63BE0, drop=0x4DAF4A0, book_location=0x5742320,
         sites=((0x4AD7DD7, 0), (0x4CACE52, 1))),
    dict(name="third", entry=0x4D62900, price=0x4DD5BF0, mid=0x42FBA60, tops=0x4A078A0, set_filter=0x444F500, books=0x3E08, system=0x4480, network=0x1372, resolver=0x42C0, gate=0x4D77030, register=0x4D642F0, drop=0x4DAF4A0, book_location=0x5742320,
         sites=((0x4AD8707, 0), (0x4CB57E2, 1))),
    dict(name="first", entry=0x2747390, price=0x2786830, mid=0x26E0570, tops=0x23978C0, set_filter=0x27E8070, books=0x3388, system=0x3A00, network=0x8F2, resolver=0x3840, gate=0x2751B30, register=0x2748310, drop=0x277EBA0, book_location=0x56BB460,
         sites=((0x2358581, 1), (0x23E8237, 0))),
)
SECOND = COPIES[0]

SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMCMP = 0x576E488
SLOT_MEMMOVE = 0x576E0E0
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_OVERFLOW = 0x576E150
LOC_TOKEN = 0x56F21F0
LOC_SPOT = 0x56F1FD8
LOC_SCALE_OVERFLOW = 0x56F2240
LOC_DECIMALS = 0x56F2258
LOCATION_NAMES = {LOC_TOKEN: "token past the list", LOC_SPOT: "spot past the list", LOC_SCALE_OVERFLOW: "scale overflow", LOC_DECIMALS: "decimals underflow", 0x5742320: "book past the list, second and third copy", 0x56BB460: "book past the list, first copy"}

STATUS_NODE = dict(parent=0, values=0x64, value=1, keys=8, index=0x60, length=0x62, edges=0x70, leaf=0x70, inner=0xD0, key=8)
ALIGNED_NODE = dict(parent=0, values=0x60, value=8, keys=8, index=0xE4, length=0xE6, edges=0xE8, leaf=0xE8, inner=0x148, key=8)
SYSTEM_NODE = dict(parent=0, values=0x60, value=0x48, keys=8, index=0x378, length=0x37A, edges=0x380, leaf=0x380, inner=0x3E0, key=8)
SIDE_LEAF = 0x1C8
SIDE_INNER = 0x228
SIDE_PARENT = 0x160
SIDE_KEYS = 0x168
SIDE_INDEX = 0x1C0
SIDE_LENGTH = 0x1C2
SIDE_EDGES = 0x1C8
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
FAKE_MEMMOVE = 0x7E000050

OUT = HEAP_BASE + 0x800
EX = HEAP_BASE + 0x1000
USER = EX + 0x8000
BUMP = USER + 0x140

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


ZERO_USER = bytes(20)


def user_bytes(number):
    return user_id(number) if number else ZERO_USER


class Case:
    defaults = dict(token=5, native=3, native_tag=1, extra_tokens=(), token_count=8, spots=((3, 0), (5, 0), (4, 0)), lists=None, spot_books=None, books=None, flag=1, user=7, network=1, resolved=0x13D,
                    gate_status=STATUS_OK, decimal_status=STATUS_OK, register_status=STATUS_OK, status_rows=(), aligned_rows=(), system_rows=((0, 25.0, 123456, 0.5),), system_root=True)

    def __init__(self, label, **fields):
        self.label = label
        for key, value in Case.defaults.items():
            setattr(self, key, fields.pop(key, value))
        if fields:
            raise EvidenceError("unknown case field: %s" % sorted(fields))
        self.rows = {}
        for index in range(self.token_count):
            self.rows[index] = dict(name=b"TOKEN%03d" % index, sz=2, wei=8, share=0, deployed=0, deployer=0)
        for index, row in self.extra_tokens:
            self.rows[index].update(row)

    def spot_list(self, token):
        if self.lists is not None and token in self.lists:
            return self.lists[token]
        return tuple(index for index, row in enumerate(self.spots) if row[0] == token)

    def book(self, spot):
        row = dict(bid=999000, ask=1001000, anchor=1000000, height=0, empty_leaf=False)
        row.update((self.spot_books or {}).get(spot, {}))
        return row

    def read_book_count(self):
        return len(self.spots) if self.books is None else self.books

    book_count = property(read_book_count)


class SpecPanic(Exception):
    pass


def spec_scale(case, token):
    """0x375fb50: 10^(token 0 wei - sz)."""
    if case.token_count == 0 or token >= case.token_count:
        raise SpecPanic(("panic", LOC_TOKEN))
    exponent = case.rows[0]["wei"] - case.rows[token]["sz"]
    if exponent < 0:
        raise SpecPanic(("overflow", LOC_DECIMALS))
    if exponent == 0:
        return 1
    if exponent >= 32 or 10 ** exponent > MASK[8]:
        raise SpecPanic(("panic", LOC_SCALE_OVERFLOW))
    return 10 ** exponent


def spec_mid(book):
    """0x42fba60: median of the nonzero tops and +0x78, floored mean on an even count, +0x78 if that is zero."""
    values = [value for value in (book["bid"], book["ask"]) if value]
    values.append(book["anchor"])
    values.sort()
    middle = len(values) // 2
    found = values[middle] if len(values) & 1 else (values[middle - 1] + values[middle]) // 2
    return found or book["anchor"]


def spec_ratio(mid, scale):
    return float(mid) / float(scale) + -1.0


def spec_top(side):
    return abs(side)


def spec_usdc_spot(case, token):
    for spot in case.spot_list(token):
        if spot >= len(case.spots):
            raise SpecPanic(("bounds", spot, len(case.spots), LOC_SPOT))
        if case.spots[spot][1] == 0:
            return spot
    return None


def spec_quotes(case):
    """0x3bb5f50 then the filter 0x4c6be50, sorted without duplicates."""
    found = []
    for quote in (row[1] for row in case.spots):
        if quote == 0 or (quote <= TESTNET_QUOTE_LIMIT and case.network == NETWORK_SKIPS):
            continue
        if quote >= case.token_count:
            raise SpecPanic(("panic", LOC_TOKEN))
        if case.rows[quote]["name"] != SKIPPED_NAME:
            found.append(quote)
    return sorted(set(found))


def spec_counted(case, quote, events):
    row = case.rows[quote]
    events.append(("resolve", user_bytes(case.user).hex()))
    if case.resolved == STATUS_OK:
        return not row["deployed"]
    events.append(("resolve drop",))
    if case.user == 0:
        return not row["deployed"]
    return bool(row["deployed"]) and row["deployer"] == case.user


def spec_price(case, spot, copy):
    """0x4dd5ae0 once the pair lookup returned a spot."""
    if spot >= case.book_count:
        raise SpecPanic(("bounds", spot, case.book_count, copy["book_location"]))
    mid = spec_mid(case.book(spot))
    if spot >= len(case.spots):
        raise SpecPanic(("bounds", spot, len(case.spots), LOC_SPOT))
    base, quote = case.spots[spot]
    if quote >= case.token_count or base >= case.token_count:
        raise SpecPanic(("panic", LOC_TOKEN))
    exponent = case.rows[quote]["wei"] - case.rows[base]["sz"]
    if exponent < 0:
        raise SpecPanic(("overflow", LOC_DECIMALS))
    return float(mid) / float(10 ** exponent)


def spec_writer(case, events):
    row = case.rows[case.token]
    if row["wei"] != QUOTE_WEI:
        return (STATUS_INVALID,)
    if spec_usdc_spot(case, case.token) is None:
        return (STATUS_INVALID,)
    if row["share"]:
        return (STATUS_TEXT, WORDS["fee"])
    known = dict(case.status_rows)
    if not case.flag & 0xFF and known.get(case.token):
        return (STATUS_TEXT, WORDS["allowed"])
    events.append(("status", case.token, 0))
    events.append(("aligned", case.token, case.token in case.aligned_rows, "time"))
    return None


def spec_system(case, events):
    """0x333a520, 0x333a420 and the insert."""
    if case.native_tag != 1:
        return
    if case.native >= case.token_count:
        raise SpecPanic(("panic", LOC_TOKEN))
    first = spec_usdc_spot(case, case.native)
    if first is None:
        return
    second = None
    for spot in case.spot_list(case.native):
        if spot >= len(case.spots):
            raise SpecPanic(("bounds", spot, len(case.spots), LOC_SPOT))
        if case.spots[spot][1] == case.token:
            second = spot
            break
    if second is None or not case.system_root:
        return
    rows = {row[0]: row for row in case.system_rows}
    if first not in rows:
        return
    _, window, amount, limit = rows[first]
    hundreds = amount // 100
    scaled = hundreds * 100 if hundreds <= ROW_HUNDREDS_LIMIT else hundreds
    kept = scaled // 100 * 100
    if kept > ROW_AMOUNT_LIMIT:
        return
    floored = window if window > FLOOR_FIELD else FLOOR_FIELD
    events.append(("system", second, to_bits(floored), second, kept, to_bits(limit)))


def spec_enable(case, copy):
    events = []
    result = dict(stop=None, events=events)
    try:
        if not case.native_tag & 0xFF:
            result["status"] = (STATUS_NO_NATIVE,)
            return result
        events.append(("drop", STATUS_NO_NATIVE))
        if case.token >= case.token_count:
            raise SpecPanic(("panic", LOC_TOKEN))
        spot = spec_usdc_spot(case, case.token)
        if spot is None:
            result["status"] = (STATUS_TEXT, WORDS["pair"])
            return result
        quotes = spec_quotes(case)
        counted = [quote for quote in quotes if spec_counted(case, quote, events)]
        present = case.token in counted
        if present:
            counted.remove(case.token)
        if counted:
            result["status"] = (STATUS_TEXT, WORDS["one"])
            return result
        level = 3 * int(present) + 1
        events.append(("gate", user_bytes(case.user).hex(), level))
        if case.gate_status != STATUS_OK:
            result["status"] = ("filled", case.gate_status)
            return result
        if spot >= case.book_count:
            raise SpecPanic(("bounds", spot, case.book_count, copy["book_location"]))
        book = case.book(spot)
        if not book["bid"]:
            result["status"] = (STATUS_TEXT, WORDS["empty"])
            return result
        ratio = spec_ratio(spec_mid(book), spec_scale(case, case.token))
        if not UPPER >= ratio:
            result["status"] = (STATUS_TEXT, WORDS["far"])
            return result
        if not book["ask"]:
            result["status"] = (STATUS_TEXT, WORDS["empty"])
            return result
        if not ratio >= LOWER:
            result["status"] = (STATUS_TEXT, WORDS["far"])
            return result
        failed = spec_writer(case, events)
        if failed:
            result["status"] = failed
            return result
        if case.native >= case.token_count:
            raise SpecPanic(("panic", LOC_TOKEN))
        exists = False
        for held in case.spot_list(case.native):
            if held >= len(case.spots):
                raise SpecPanic(("bounds", held, len(case.spots), LOC_SPOT))
            if case.spots[held][1] == case.token:
                exists = True
                break
        if not exists:
            pair = spec_usdc_spot(case, case.native)
            price = PAIR_PRICE_DEFAULT if pair is None else spec_price(case, pair, copy)
            events.append(("decimal", to_bits(price)))
            if case.decimal_status != STATUS_OK:
                result["status"] = ("filled", case.decimal_status)
                return result
            events.append(("register", case.native, case.token))
            if case.register_status != STATUS_OK:
                result["status"] = ("filled", case.register_status)
                return result
        spec_system(case, events)
        result["status"] = (STATUS_OK,)
        return result
    except SpecPanic as caught:
        result["stop"] = caught.args[0]
        return result


def spec_run(case, copy):
    return spec_enable(case, copy)


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
                           relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_OVERFLOW]: self.on_overflow, FAKE_MEMCPY: self.on_memcpy, FAKE_MEMCMP: self.on_memcmp, FAKE_MEMMOVE: self.on_memcpy,
                           DECIMAL: self.on_decimal, RESOLVE: self.on_resolve, STATUS_INSERT: self.on_status_insert}
        machine.slots = dict(self.slot_hooks)
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.copy = SECOND
        self.direct = {RESOLVE_DROP: self.on_resolve_drop, STATUS_INSERT: self.on_status_insert, ALIGNED_INSERT: self.on_aligned, SYSTEM_INSERT: self.on_system_insert, GROW_SCAN: self.on_grow, GROW_FILTER: self.on_grow}
        self.real = RealExcept()
        machine.real = self.real

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def build_tree(self, at, rows, shape, write_value):
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
                memory.put_bytes(node + shape["keys"] + index * shape["key"], struct.pack("<Q", 2))
            for index in range(NODE_KEYS + 1):
                self.put(node + shape["edges"] + index * 8, 8, LEAF_EDGE) if level else None
            if level:
                for index, child in enumerate(children):
                    self.put(node + shape["edges"] + index * 8, 8, make(child, node, index, level - 1))
            return node

        level = tree_height(len(rows), NODE_KEYS)
        self.put(at, 8, make(list(rows), 0, 0, level))
        self.put(at + 8, 8, level)
        self.put(at + 0x10, 8, len(rows))

    def build_side(self, at, top, height, empty_leaf):
        """One book side: a chain `height` deep whose first key is `top`; 0 means an empty side."""
        memory = self.machine.memory
        if not top:
            self.put(at, 8, 0)
            self.put(at + 8, 8, 0)
            self.put(at + 0x10, 8, 0)
            return
        below = 0
        parent_slot = None
        for level in range(height + 1):
            size = SIDE_INNER if level else SIDE_LEAF
            node = self.alloc(size)
            memory.put_bytes(node, ramp(size, level + 21))
            self.put(node + SIDE_PARENT, 8, 0)
            self.put(node + SIDE_INDEX, 2, 0)
            if level == 0 and empty_leaf:
                self.put(node + SIDE_LENGTH, 2, 0)
                self.put(node + SIDE_KEYS, 8, 0x1234)
            elif level == 1 and empty_leaf:
                self.put(node + SIDE_LENGTH, 2, 1)
                self.put(node + SIDE_KEYS, 8, top)
            else:
                self.put(node + SIDE_LENGTH, 2, 1)
                self.put(node + SIDE_KEYS, 8, top if level == 0 else top + 1)
            if level:
                self.put(node + SIDE_EDGES, 8, below)
                self.put(below + SIDE_PARENT, 8, node)
            below = node
        self.put(at, 8, below)
        self.put(at + 8, 8, height)
        self.put(at + 0x10, 8, 1)

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

    def on_overflow(self, m):
        raise Panicked(("overflow", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_grow(self, m):
        read = m.memory.read
        vec, size, extra = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        if (m.regs[RCX] & MASK[4], m.regs[R8] & MASK[4]) != (8, 8):
            raise Halt("grow layout")
        capacity, old = read(vec, 8), read(vec + 8, 8)
        if extra > 8 or size > 256 or capacity > 256:
            raise Halt("grow size")
        fresh = max(capacity * 2, size + extra, 4)
        at = self.alloc(fresh * 8)
        self.live[at] = fresh * 8
        m.memory.copy(at, old, capacity * 8)
        if self.live.pop(old, None) != capacity * 8:
            raise Halt("grow of a block that does not match")
        self.put(vec, 8, fresh)
        self.put(vec + 8, 8, at)

    # edges of this path

    def on_drop(self, m):
        self.events.append(("drop", m.memory.read(m.regs[RDI], 2)))

    def on_gate(self, m):
        case = self.case
        self.check_state(m.regs[RSI])
        self.events.append(("gate", m.memory.bytes_at(m.regs[RDX], 20).hex(), m.regs[RCX] & 0xFF))
        self.fill(m.regs[RDI], case.gate_status)

    def fill(self, at, word):
        if word != STATUS_OK:
            self.machine.memory.put_bytes(at, ramp(0x60, 77))
        self.put(at, 2, word)

    def check_state(self, value):
        if value != EX:
            raise Halt("state argument")

    def on_decimal(self, m):
        self.events.append(("decimal", m.xmm[0] & MASK[8]))
        self.fill(m.regs[RDI], self.case.decimal_status)
        if self.case.decimal_status == STATUS_OK:
            m.memory.put_bytes(m.regs[RDI] + 4, ramp(16, 91))

    def on_register(self, m):
        self.check_state(m.regs[RSI])
        if m.memory.bytes_at(m.regs[RDX], 20) != ZERO_USER:
            raise Halt("register user bytes")
        pair_at, text_at = m.regs[RCX], m.regs[R8]
        if m.memory.bytes_at(text_at, 16) != ramp(16, 91):
            raise Halt("register decimal bytes")
        self.events.append(("register", m.memory.read(pair_at, 8), m.memory.read(pair_at + 8, 8)))
        self.fill(m.regs[RDI], self.case.register_status)

    def on_resolve(self, m):
        if m.regs[RSI] != EX + self.copy["resolver"] or m.regs[RCX] != m.memory.read(EX + self.copy["resolver"] + 0x48, 8):
            raise Halt("resolver arguments %#x %#x" % (m.regs[RSI] - EX, m.regs[RCX]))
        self.events.append(("resolve", m.memory.bytes_at(m.regs[RDX], 20).hex()))
        self.put(m.regs[RDI], 2, self.case.resolved)

    def on_resolve_drop(self, m):
        if m.memory.read(m.regs[RDI], 2) != self.case.resolved:
            raise Halt("resolve drop word")
        self.events.append(("resolve drop",))

    def on_status_insert(self, m):
        if m.regs[RDI] != EX + 0x90 + 0x250:
            raise Halt("status map")
        self.events.append(("status", m.regs[RSI], m.regs[RDX] & 0xFF))

    def on_aligned(self, m):
        read = m.memory.read
        at = m.regs[RDI]
        if read(at, 8) == 0:
            node, slot, owner = read(at + 8, 8), read(at + 0x18, 8), read(at + 0x20, 8)
            key, occupied = read(node + 8 + slot * 8, 8), True
        else:
            owner, key, occupied = read(at, 8), read(at + 8, 8), False
            if read(at + 0x18 if read(owner, 8) else at + 0x10, 8):
                raise Halt("vacant entry word")
        if owner != EX + 0x90 + 0x208:
            raise Halt("aligned map")
        if m.memory.bytes_at(m.regs[RSI], 12) != m.memory.bytes_at(EX + 0x60, 12):
            raise Halt("aligned time")
        self.events.append(("aligned", key, occupied, "time"))

    def on_system_insert(self, m):
        read = m.memory.read
        if m.regs[RSI] != EX + self.copy["system"]:
            raise Halt("system tree")
        value = m.regs[RCX]
        if read(value, 8) or read(value + 8, 8) or read(value + 0x18, 8) or read(value + 0x20, 4):
            raise Halt("system row zero fields")
        self.events.append(("system", m.regs[RDX], read(value + 0x10, 8), read(value + 0x30, 8), read(value + 0x38, 8), read(value + 0x40, 8)))

    # the run

    def write_book(self, spot, book):
        at = self.books + spot * BOOK_STRIDE
        self.put(at + 0x78, 8, book["anchor"])
        self.build_side(at + 0x80, -book["bid"] & MASK[8] if book["bid"] else 0, book["height"], book["empty_leaf"])
        self.build_side(at + 0x98, book["ask"], book["height"], book["empty_leaf"])

    def write_system_row(self, at, row):
        _, window, amount, limit = row[1]
        self.put(at + 0x10, 8, to_bits(window))
        self.put(at + 0x38, 8, amount)
        self.put(at + 0x40, 8, to_bits(limit))

    def run_enable(self, case):
        copy = self.copy
        machine = self.machine
        memory = machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.case = case
        machine.calls = dict(self.direct)
        machine.calls.update({copy["gate"]: self.on_gate, copy["register"]: self.on_register, copy["drop"]: self.on_drop})
        self.real.stubs = frozenset(machine.calls) | frozenset(machine.slots)
        memory.put_bytes(OUT, ramp(0x80, 13))
        memory.put_bytes(EX, ramp(0x7000, 31))
        memory.put_bytes(USER, user_id(case.user) if case.user else ZERO_USER)
        self.put(EX + 0x80, 8, case.native_tag)
        self.put(EX + 0x88, 8, case.native)
        self.put(EX + copy["network"], 1, case.network)
        tokens = self.alloc(TOKEN_STRIDE * max(case.token_count, 1))
        memory.put_bytes(tokens, ramp(TOKEN_STRIDE * max(case.token_count, 1), 57))
        self.put(EX + 0x210, 8, tokens)
        self.put(EX + 0x218, 8, case.token_count)
        spots = self.alloc(SPOT_STRIDE * max(len(case.spots), 1))
        memory.put_bytes(spots, ramp(SPOT_STRIDE * max(len(case.spots), 1), 63))
        self.put(EX + 0x1F8, 8, spots)
        self.put(EX + 0x200, 8, len(case.spots))
        for index, (base, quote) in enumerate(case.spots):
            self.put(spots + index * SPOT_STRIDE, 8, base)
            self.put(spots + index * SPOT_STRIDE + 8, 8, quote)
        for index, row in sorted(case.rows.items()):
            at = tokens + index * TOKEN_STRIDE
            name = self.alloc(max(len(row["name"]), 1))
            memory.put_bytes(name, row["name"])
            self.put(at + 0x38, 8, name)
            self.put(at + 0x40, 8, len(row["name"]))
            self.put(at + 0x48, 1, row["sz"])
            self.put(at + 0x49, 1, row["wei"])
            held = case.spot_list(index)
            array = self.alloc(max(len(held), 1) * 8)
            for slot, spot in enumerate(held):
                self.put(array + slot * 8, 8, spot)
            self.put(at + 0x58, 8, array)
            self.put(at + 0x60, 8, len(held))
            self.put(at + 0xA8, 8, row["share"])
            self.put(at + 0xD2, 1, row["deployed"])
            memory.put_bytes(at + 0xD3, user_id(row["deployer"]) if row["deployer"] else ZERO_USER)
        self.books = self.alloc(BOOK_STRIDE * max(case.book_count, 1))
        memory.put_bytes(self.books, ramp(BOOK_STRIDE * max(case.book_count, 1), 69))
        self.put(EX + copy["books"], 8, self.books)
        self.put(EX + copy["books"] + 8, 8, case.book_count)
        for spot in range(min(case.book_count, len(case.spots))):
            self.write_book(spot, case.book(spot))
        self.build_tree(EX + 0x90 + 0x250, [(struct.pack("<Q", key), value) for key, value in sorted(case.status_rows)], STATUS_NODE, lambda at, row: self.put(at, 1, row[1]))
        self.build_tree(EX + 0x90 + 0x208, [(struct.pack("<Q", key), key) for key in sorted(case.aligned_rows)], ALIGNED_NODE, lambda at, row: None)
        rows = [(struct.pack("<Q", row[0]), row) for row in sorted(case.system_rows)] if case.system_root else []
        self.build_tree(EX + copy["system"], rows, SYSTEM_NODE, self.write_system_row)
        result = machine.run(copy["entry"], {RDI: OUT, RSI: EX, RDX: USER, RCX: case.token, R8: case.flag})
        if result != OUT:
            raise Halt("result pointer")
        if self.live:
            raise Halt("blocks still live")
        return {"stop": None, "events": self.events, "status": self.status()}

    def status(self):
        memory = self.machine.memory
        word = memory.read(OUT, 2)
        if word == STATUS_TEXT:
            return (word, memory.bytes_at(memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8)))
        if word == STATUS_OK or word in (STATUS_NO_NATIVE, STATUS_INVALID):
            return (word,)
        expected = bytearray(ramp(0x60, 77))
        expected[0:2] = struct.pack("<H", word)
        if memory.bytes_at(OUT, 0x60) != bytes(expected):
            raise Halt("status block not copied whole")
        return ("filled", word)

    def run(self, case):
        try:
            return self.run_enable(case)
        except Panicked as caught:
            return {"stop": caught.args[0], "events": self.events}
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)


CRASHES = (Halt, EvidenceError, RecursionError, IndexError, KeyError, ZeroDivisionError, StopIteration, OverflowError, ValueError, TypeError, struct.error)
COMPARED = ("stop", "events", "status")


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

PAIRED = ((3, 0), (5, 0), (4, 0), (3, 5))


def book_cases():
    rows = []
    usdc = {1: {}}

    def mid_case(label, **fields):
        rows.append(Case("book " + label, spot_books={1: fields}))

    for mid in (1200000, 1200001, 1199999, 800000, 799999, 800001, 1000000, 1, 2, 2000000, 1 << 40, (1 << 63) - 1):
        mid_case("anchor mid %d" % mid, bid=mid - 1 if mid > 1 else 1, ask=mid + 1, anchor=mid)
    for bid, ask, anchor in ((1, 2, 3), (1, 3, 2), (2, 1, 3), (2, 3, 1), (3, 1, 2), (3, 2, 1), (5, 5, 5), (1000000, 1000000, 0), (900000, 1100000, 0), (1100000, 900000, 0), (900000, 1000000, 5000000), (1000000, 1100000, 1), (700000, 1300000, 1000000),
                             (1000000, 1400000, 1300000), (500000, 1000000, 600000), (1000000, 1000000, 1 << 62), (1 << 62, 1 << 62, 1 << 62), (1000000, 1, 1 << 40), (1, 1000000, 1 << 40)):
        mid_case("order %d %d %d" % (bid, ask, anchor), bid=bid, ask=ask, anchor=anchor)
    for ask, anchor in ((0, 1000000), (0, 0), (0, 2000000), (0, 1), (0, 900000)):
        for bid in (1000000, 1300000, 700000, 1):
            mid_case("no ask bid %d anchor %d" % (bid, anchor), bid=bid, ask=ask, anchor=anchor)
    for bid, anchor in ((0, 1000000), (0, 0), (0, 5000000)):
        mid_case("no bid anchor %d" % anchor, bid=bid, anchor=anchor)
        mid_case("no sides anchor %d" % anchor, bid=bid, ask=0, anchor=anchor)
    for height in (1, 2, 3, 7, 8, 9, 15, 16):
        mid_case("deep %d" % height, height=height)
        mid_case("deep empty leaf %d" % height, height=height, empty_leaf=True)
    return rows


def scale_cases():
    rows = []
    for sz in range(0, 9):
        scale = 10 ** (8 - sz)
        for mid in (scale, scale * 12 // 10, scale * 12 // 10 + 1, scale * 8 // 10, scale * 8 // 10 - 1, max(scale * 8 // 10 - 1, 0) // 2):
            if mid > 0:
                rows.append(Case("scale sz %d mid %d" % (sz, mid), extra_tokens=((5, dict(sz=sz)),), spot_books={1: dict(bid=mid, ask=mid, anchor=mid)}))
    rows.append(Case("scale sz past token 0 wei", extra_tokens=((5, dict(sz=9)),)))
    rows.append(Case("scale sz far past token 0 wei", extra_tokens=((5, dict(sz=200)),)))
    for wei, sz in ((31, 0), (32, 0), (33, 1), (63, 0), (19, 0), (20, 0), (21, 1), (16, 0), (17, 0), (24, 8), (24, 5), (15, 0), (64, 0), (40, 8), (255, 0), (48, 0), (47, 0), (20, 1)):
        exponent = wei - sz
        scale = 10 ** exponent if exponent < 20 else 1
        rows.append(Case("scale token 0 wei %d sz %d" % (wei, sz), extra_tokens=((0, dict(wei=wei)), (5, dict(sz=sz))), spot_books={1: dict(bid=scale, ask=scale, anchor=scale)}))
    return rows


def pair_cases():
    rows = [Case("default")]
    rows += [Case("no native tag", native_tag=0), Case("no native tag, token past the list", native_tag=0, token=50), Case("native tag byte 2", native_tag=2), Case("native tag high bits", native_tag=0x100), Case("native tag high bits and 1", native_tag=0x101)]
    rows += [Case("native tag byte 2, pair and row", native_tag=2, spots=PAIRED), Case("native tag high bits and 1, pair and row", native_tag=0x101, spots=PAIRED)]
    rows += [Case("token past the list", token=8), Case("token far past the list", token=900), Case("last token", token=7, spots=((3, 0), (7, 0))), Case("no tokens", token=0, token_count=0, native=0)]
    rows += [Case("no spot in the list", lists={5: ()}), Case("spot in the list not USDC", spots=((3, 0), (5, 1), (4, 0))), Case("quote word above 32 bits", spots=((3, 0), (5, 1 << 32), (4, 0))),
             Case("second spot in the list is USDC", spots=((3, 0), (5, 2), (5, 0), (4, 0)), spot_books={1: dict(bid=7, ask=7, anchor=7), 2: {}}),
             Case("first of two USDC spots", spots=((3, 0), (5, 0), (5, 0)), spot_books={1: {}, 2: dict(bid=7, ask=7, anchor=7)}),
             Case("spot past the spots", lists={5: (1, 9)}, spots=((3, 0), (5, 1))), Case("spot at the spots length", lists={5: (3,)}), Case("spot far past the spots", lists={5: (900,)}),
             Case("three spots in the list", lists={5: (2, 1, 0)}, spots=((3, 1), (5, 0), (4, 1)), extra_tokens=((1, dict(deployed=1, deployer=9)),))]
    rows += [Case("book list shorter", books=1), Case("book list at the spot", books=0), Case("book list just past", books=2), Case("second book list stale", books=1, spot_books={1: dict(bid=0)})]
    rows += [Case("flag 0, default", flag=0), Case("flag high bits", flag=0x7F00), Case("flag 2", flag=2)]
    rows += [Case("gate refused, status %#x" % word, gate_status=word) for word in (0x109, 0x10A, 0x13D, 0xDF + 1)]
    rows += [Case("wei 7", extra_tokens=((5, dict(wei=7)),)), Case("wei 9", extra_tokens=((5, dict(wei=9)),)), Case("wei 0", extra_tokens=((5, dict(wei=0)),)), Case("wei 8 with bit 8 clear of neighbours", extra_tokens=((5, dict(wei=8, sz=0)),), spot_books={1: dict(bid=100000000, ask=100000000, anchor=100000000)})]
    rows += [Case("share %d" % share, extra_tokens=((5, dict(share=share)),)) for share in (1, 2, 1 << 32, 1 << 63)]
    for flag in (0, 1):
        for value in (0, 1, 2):
            rows.append(Case("status row %d flag %d" % (value, flag), flag=flag, status_rows=((5, value),)))
        rows.append(Case("status rows others flag %d" % flag, flag=flag, status_rows=((1, 1), (4, 1), (6, 1))))
        rows.append(Case("status tree deep flag %d" % flag, flag=flag, status_rows=tuple((key, key & 1) for key in range(1, 40))))
        rows.append(Case("status tree deep even flag %d" % flag, flag=flag, status_rows=tuple((key, key & 1 ^ 1) for key in range(1, 40))))
        rows.append(Case("status above every key flag %d" % flag, flag=flag, status_rows=((1, 1),)))
        rows.append(Case("status below every key flag %d" % flag, flag=flag, status_rows=((7, 1),)))
    rows += [Case("aligned row present", aligned_rows=(5,)), Case("aligned rows others", aligned_rows=(1, 4, 6)), Case("aligned tree deep", aligned_rows=tuple(range(0, 40))), Case("aligned tree deep without key", aligned_rows=tuple(k for k in range(0, 40) if k != 5)),
             Case("aligned one key above", aligned_rows=(9,)), Case("aligned tree deep above", aligned_rows=tuple(range(20, 60)))]
    rows += [Case("pair exists", spots=PAIRED), Case("pair exists, row stops short", spots=PAIRED, system_rows=((1, 25.0, 123456, 0.5),)), Case("pair exists, empty tree", spots=PAIRED, system_root=False),
             Case("pair exists, no native USDC pair", spots=((3, 9), (5, 0), (4, 0), (3, 5))), Case("pair exists first in the native list", spots=((3, 5), (5, 0), (3, 0))),
             Case("native list with a word above 32 bits", spots=((3, 1 << 32), (5, 0), (3, 0), (3, 5))),
             Case("native list past the spots", lists={3: (0, 9)}), Case("native list past at the end of the pair scan", lists={3: (9,)}), Case("native past the tokens", native=8), Case("native past the tokens, pair exists", native=20, spots=PAIRED),
             Case("native pair past the spots", lists={3: (0, 3, 9)}, spots=PAIRED), Case("native is the token", native=5), Case("native is token 0", native=0, spots=((0, 0), (5, 0)), spot_books={1: {}}),
             Case("native has no spots", lists={3: ()}), Case("native spots all to other tokens", spots=((3, 2), (5, 0), (3, 4))), Case("native USDC spot past the books", books=2, spots=((4, 0), (5, 0), (3, 0)))]
    for window in (9.0, 10.0, 10.5, 0.0, 1e300, 25.0, float("inf")):
        rows.append(Case("row window %r" % window, spots=PAIRED, system_rows=((0, window, 12345600, 0.25),)))
    rows.append(Case("row window NaN", spots=PAIRED, system_rows=((0, 1.5, 12345600, float("inf")),)))
    for amount in (0, 1, 99, 100, 101, 199, 200, 12345, ROW_HUNDREDS_LIMIT * 100, ROW_HUNDREDS_LIMIT * 100 + 99, (ROW_HUNDREDS_LIMIT + 1) * 100, ROW_AMOUNT_LIMIT - 1, ROW_AMOUNT_LIMIT, ROW_AMOUNT_LIMIT + 1, 0x28F5C28F5C28F000, 0x28F5C28F5C28F6FF, MASK[8], MASK[8] - 99, 1 << 63):
        rows.append(Case("row amount %#x" % amount, spots=PAIRED, system_rows=((0, 25.0, amount, 1.5),)))
    for flag in (0, 1):
        rows.append(Case("status five keys, token last, flag %d" % flag, flag=flag, status_rows=((1, 0), (2, 0), (3, 0), (4, 0), (5, 1))))
        rows.append(Case("status four keys below the token, flag %d" % flag, flag=flag, status_rows=((1, 1), (2, 1), (3, 1), (4, 1))))
    rows += [Case("aligned five keys, token last", aligned_rows=(1, 2, 3, 4, 5)), Case("aligned four keys below the token", aligned_rows=(1, 2, 3, 4)),
             Case("native USDC spot at index 3 with a row", spots=((6, 0), (4, 0), (5, 0), (3, 0), (3, 5)), system_rows=((3, 12.0, 700, 1.25),))]
    rows.append(Case("row deep tree", spots=((6, 0), (5, 0), (3, 0), (3, 5)), system_rows=tuple((key, 11.0 + key, 1000 * key + 300, 0.1 * key) for key in range(0, 40))))
    rows.append(Case("row deep tree key last", spots=((6, 0), (5, 0), (3, 0), (3, 5)), system_rows=tuple((key, 11.0 + key, 1000 * key + 300, 0.1 * key) for key in (0, 1))))
    rows.append(Case("row tree without key, other keys around", spots=((6, 0), (5, 0), (6, 1), (3, 0), (3, 5)), system_rows=((2, 11.0, 300, 1.0), (4, 12.0, 500, 2.0))))
    rows.append(Case("row tree key above every row", spots=((6, 0), (5, 0), (6, 1), (3, 0), (3, 5)), system_rows=((2, 11.0, 300, 1.0),)))
    rows.append(Case("row tree key below every row", spots=((3, 0), (5, 0), (3, 5)), system_rows=((2, 11.0, 300, 1.0), (4, 12.0, 500, 2.0))))
    rows += [Case("pair built, price from the native book", spot_books={0: dict(bid=2500000, ask=2600000, anchor=2550000)}), Case("pair built, native sz 0", extra_tokens=((3, dict(sz=0)),), spot_books={0: dict(bid=100000000, ask=300000000, anchor=250000000)}),
             Case("pair built, native sz 8", extra_tokens=((3, dict(sz=8)),), spot_books={0: dict(bid=3, ask=9, anchor=7)}), Case("pair built, native sz 9", extra_tokens=((3, dict(sz=9)),)),
             Case("pair built, zero native book", spot_books={0: dict(bid=0, ask=0, anchor=0)}), Case("pair built, one sided native book", spot_books={0: dict(bid=0, ask=1234, anchor=77)}),
             Case("pair built, native USDC missing, default price", spots=((3, 9), (5, 0), (4, 0))), Case("pair built, native no spots, default price", lists={3: ()}),
             Case("pair built, token 0 wei differs", extra_tokens=((0, dict(wei=12)), (5, dict(sz=6)), (3, dict(sz=1))), spot_books={0: dict(bid=7, ask=70, anchor=700)}),
             Case("pair built, token 0 wei 0", extra_tokens=((0, dict(wei=0)), (5, dict(sz=0)), (3, dict(sz=0))), spot_books={1: dict(bid=1, ask=1, anchor=1), 0: dict(bid=3, ask=3, anchor=3)}),
             Case("pair built, quote of the native spot past the tokens", extra_tokens=((3, dict(sz=9)),), books=3)]
    rows += [Case("decimal refused, status %#x" % word, decimal_status=word) for word in (0xAC, 0x13D, 0x187)]
    rows += [Case("register refused, status %#x" % word, register_status=word) for word in (0x13D, 0x13C, 0x13E, 0x187, 0xDF + 2)]
    return rows


def quote_cases():
    rows = []
    many = ((5, 0), (3, 0)) + tuple((9 + index, 40 + index) for index in range(12))
    def extras(*items):
        return tuple((token, dict(deployed=1, deployer=who)) for token, who in items)
    rows += [Case("quote by the same user", spots=((5, 0), (3, 0), (4, 6)), extra_tokens=extras((6, 7))), Case("quote by another user", spots=((5, 0), (3, 0), (4, 6)), extra_tokens=extras((6, 8))),
             Case("quote with no deployer", spots=((5, 0), (3, 0), (4, 6))), Case("own token is the quote, same user", spots=((5, 0), (3, 0), (4, 5)), extra_tokens=extras((5, 7))),
             Case("own token is the quote, another user", spots=((5, 0), (3, 0), (4, 5)), extra_tokens=extras((5, 8))), Case("own token and a second quote", spots=((5, 0), (3, 0), (4, 5), (4, 6)), extra_tokens=extras((5, 7), (6, 7))),
             Case("two quotes of another user", spots=((5, 0), (3, 0), (4, 6), (4, 1)), extra_tokens=extras((6, 8), (1, 8))), Case("one spot repeats a quote", spots=((5, 0), (3, 0), (4, 6), (1, 6), (2, 6)), extra_tokens=extras((6, 8))),
             Case("repeat of a counted quote", spots=((5, 0), (3, 0), (4, 6), (1, 6), (2, 6)), extra_tokens=extras((6, 7))), Case("gate level 1 by default"), Case("gate level 4, own token", spots=((5, 0), (3, 0), (4, 5)), extra_tokens=extras((5, 7))),
             Case("system user counts no deployer", resolved=STATUS_OK, spots=((5, 0), (3, 0), (4, 6))), Case("system user skips a deployer", resolved=STATUS_OK, spots=((5, 0), (3, 0), (4, 6)), extra_tokens=extras((6, 7))),
             Case("system user, own token", resolved=STATUS_OK, spots=((5, 0), (3, 0), (4, 5))), Case("zero user counts no deployer", user=0, spots=((5, 0), (3, 0), (4, 6))), Case("zero user skips a deployer", user=0, spots=((5, 0), (3, 0), (4, 6)), extra_tokens=extras((6, 7))),
             Case("deployer bytes match but the present byte is 0", spots=((5, 0), (3, 0), (4, 6)), extra_tokens=((6, dict(deployed=0, deployer=7)),)),
             Case("zero user, own token", user=0, spots=((5, 0), (3, 0), (4, 5)))]
    for name in (b"USDT0", b"USDT1", b"XSDT0", b"USDT", b"USDT00", b"UTDT0", b"USET0", b"USDU0", b"USDTx"):
        rows.append(Case("name %s" % name.decode(), spots=((5, 0), (3, 0), (4, 6)), extra_tokens=((6, dict(name=name, deployed=1, deployer=7)),)))
    for network in (0, 1, 2, 3):
        for quote in (6, 0x56E, 0x56F, 0x570):
            rows.append(Case("network %d quote %#x" % (network, quote), network=network, token_count=0x571, spots=((5, 0), (3, 0), (4, quote)), extra_tokens=((quote, dict(deployed=1, deployer=7)),)))
        rows.append(Case("network %d USDT0 high" % network, network=network, token_count=0x571, spots=((5, 0), (3, 0), (4, 0x56F)), extra_tokens=((0x56F, dict(name=SKIPPED_NAME, deployed=1, deployer=7)),)))
    rows += [Case("quote past the tokens", spots=((5, 0), (3, 0), (4, 8))), Case("quote at the tokens end, testnet skip", network=2, spots=((5, 0), (3, 0), (4, 8))), Case("quote far past", spots=((5, 0), (3, 0), (4, 5000))), Case("quote above the limit past the tokens, testnet", network=2, spots=((5, 0), (3, 0), (4, 0x56F)))]
    rows += [Case("USDC only spots", spots=((5, 0), (3, 0), (1, 0), (2, 0)), lists={1: (), 2: ()}), Case("first spot has a quote", spots=((4, 6), (5, 0), (3, 0)), extra_tokens=extras((6, 7))), Case("last spot has a quote", spots=((5, 0), (3, 0), (4, 0), (2, 6)), extra_tokens=extras((6, 7))),
             Case("many quotes none counted", token_count=60, spots=many), Case("many quotes one counted", token_count=60, spots=many, extra_tokens=extras((47, 7))), Case("many quotes two counted", token_count=60, spots=many, extra_tokens=extras((47, 7), (41, 7))),
             Case("quotes in falling order", token_count=60, spots=((5, 0), (3, 0)) + tuple((1, 50 - index) for index in range(6)), extra_tokens=extras((50, 7), (45, 7), (46, 7))),
             Case("many quotes all counted", token_count=60, spots=many, extra_tokens=extras(*[(40 + index, 7) for index in range(3)])), Case("many quotes all counted, own", token_count=60, spots=((5, 0), (3, 0)) + tuple((1, 5) for _ in range(3)), extra_tokens=extras((5, 7)))]
    return rows


def all_cases():
    return book_cases() + scale_cases() + pair_cases() + quote_cases()


# ---- band: which mids pass, by exact reasoning over the f64 expression ----

def passes(mid, scale):
    ratio = spec_ratio(mid, scale)
    return UPPER >= ratio and ratio >= LOWER


def band_edges(exponent):
    """Lowest and highest passing integer mid for scale 10^exponent, by bisection on the f64 test."""
    scale = 10 ** exponent
    low_fail, low_pass = 0, scale
    while low_pass - low_fail > 1:
        middle = (low_fail + low_pass) // 2
        if passes(middle, scale):
            low_pass = middle
        else:
            low_fail = middle
    high_pass, high_fail = scale, scale * 2
    while high_fail - high_pass > 1:
        middle = (high_pass + high_fail) // 2
        if passes(middle, scale):
            high_pass = middle
        else:
            high_fail = middle
    exact_low = fractions.Fraction(4, 5) * scale
    exact_high = fractions.Fraction(6, 5) * scale
    return {"exponent": exponent, "scale": scale, "lowest_pass": low_pass, "highest_pass": high_pass, "exact_low": math.ceil(exact_low), "exact_high": math.floor(exact_high)}


def read_table(image):
    table = 0x6F7470
    return [struct.unpack_from("<d", image.blob, image.offset(table) + index * 8)[0] for index in range(10)]


def read_floats(image):
    """The two ratio constants and the -1 addend, as the four instruction operands name them."""
    entry = SECOND["entry"]
    rows = {row.va: row for row in decode_range(image, *image.exact_fde(entry))}
    found = {}
    for label, va, value in (("minus one, first", 0x4D6242A, -1.0), ("upper", 0x4D62439, UPPER), ("minus one, second", 0x4D624CD, -1.0), ("lower", 0x4D624D5, LOWER)):
        if va not in rows:
            raise EvidenceError("float site moved: %#x" % va)
        blob = bytes(image.blob[image.offset(va):image.offset(va) + rows[va].size])
        target = va + rows[va].size + struct.unpack_from("<i", blob, rows[va].size - 4)[0]
        read = struct.unpack_from("<d", image.blob, image.offset(target))[0]
        if read != value:
            raise EvidenceError("float value at %#x" % target)
        found[label] = {"site": "%#x" % va, "at": "%#x" % target, "bits": "%#x" % struct.unpack_from("<Q", image.blob, image.offset(target))[0], "value": read}
    return found


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


def read_flag_sites(image):
    """Each call site's flag argument: `xor r8d, r8d` or `mov r8d, 1` before it."""
    rows = []
    for copy in COPIES:
        for va, flag in copy["sites"]:
            window = bytes(image.blob[image.offset(va - 8):image.offset(va)])
            got = 0 if window[-3:] == b"\x45\x31\xc0" else 1 if window[-6:] == b"\x41\xb8\x01\x00\x00\x00" else None
            if got != flag:
                raise EvidenceError("flag at %#x" % va)
            row = {"copy": copy["name"], "site": "%#x" % va, "host": "%#x" % image.fde(va)[0], "flag": flag}
            if flag:
                window = bytes(image.blob[image.offset(va - 0x50):image.offset(va)])
                at = window.find(bytes.fromhex("f68410d200000001"))
                if at < 0:
                    raise EvidenceError("deployer test before %#x" % va)
                row["deployer_present_test"] = "%#x" % (va - 0x50 + at)
            rows.append(row)
    return rows


def read_texts(image):
    rows = []
    for at, size in TEXTS:
        rows.append({"at": "%#x" % at, "length": size, "value": bytes(image.blob[image.offset(at):image.offset(at) + size]).decode("ascii")})
    return rows


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
    named = ((SECOND["entry"], "enable, second copy"), (SECOND["mid"], "book mid"), (SECOND["price"], "pair price"), (WRITER, "status writer"), (FIND_PAIR, "pair lookup"),
             (USDC_PAIR, "native USDC pair"), (SYSTEM_READ, "0xfe row read"), (SYSTEM_MAKE, "0xfe row build"), (FILTER_TEST, "deployer filter"), (SCAN_NEXT, "spot quote scan"), (SCALE, "price scale"))
    return [(start, role, decode_range(image, *image.exact_fde(start))) for start, role in named] + [(MEDIAN, "median, even and odd arms", decode_range(image, 0x471DE99, 0x471DEAC) + decode_range(image, 0x471DF0C, 0x471DF47))]


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    harness.copy = SECOND
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
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:677", "claim": "enable_quote_token checks wei decimals 8 and a USDC pair with status 239, then fee share, then status Disabled; no book read", "observed": "the book median band, both side checks, the deployer limit and the pair creation are all in 0x4d62140 before and after the writer; none is in the reference", "verdict": "mismatch"},
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:683", "claim": "text: quote token deployer trading fee share must be 0", "observed": "ELF text at 0x59987d is: quote token deployer trading fee is not zero", "verdict": "mismatch"},
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:680", "claim": "text: invalid quote token with status 239", "observed": "status 0xef (239) with no text from 0x375fe00", "verdict": "partial"},
    {"reference": "l1/exchange/handlers/26_spot_deploy.rs:685", "claim": "a Disabled status always refuses", "observed": "the writer refuses only with flag 0; the flag 1 site, the vote arm, passes any status value", "verdict": "mismatch"},
    {"reference": "l1/spot_meta.rs:444", "claim": "enable_quote_token_registry inserts into an aligned info map", "observed": "writer calls 0x33be810 with the map entry and the 12-byte time; the insert policy inside is not run here", "verdict": "partial"},
)
LANDING = "unwind landing pad or panic tail: no case unwinds"
DUPLICATE_READ = "the second read of the same tops and scale gives the same f64 as the first, so only the mutated one differs when its result crosses a gate"
ITER_BACK = "back handle of the set iterator: the walk only goes forward"
DEAD_TOKEN = "the same token bound already held on this path, so a larger bound changes nothing"
DEAD_SPOT = "the same spot list was already bound checked on this path, so a larger bound changes nothing"
UNREAD_TAG = "the array tag byte: the collector reads the value word, never this byte"
USDC_LIST = "the enable function already found a USDC spot in this list, so the walk stops before the length"
ROW_LIMIT = "amount / 100 is at most 2^64 / 100, so the cut value never passes this limit and the refusal arm is dead here"
LAZY = "lazy init of a static: the harness word is 0, and the other arm rejoins with the same row"
REASON_RANGES = ((0x4D628DE, 0x4D628F5, LANDING), (0x42FBB20, 0x42FBB48, LANDING), (0x333A4C0, 0x333A51C, LAZY))
REASONS = {0x4D622AD: ITER_BACK, 0x4D626A1: ITER_BACK, 0x4D628A5: ROW_LIMIT, 0x42FBA9A: UNREAD_TAG, 0x42FBAA4: UNREAD_TAG,
           0x4DD5B17: DEAD_SPOT, 0x4DD5B32: DEAD_TOKEN, 0x4DD5B53: "the quote of this spot is token 0, so the row product is 0 for any multiplier",
           0x375FE0C: DEAD_TOKEN, 0x375FE34: USDC_LIST, 0x375FE40: DEAD_SPOT, 0x3760071: DEAD_TOKEN, 0x3760099: DEAD_SPOT, 0x333A534: DEAD_TOKEN, 0x333A560: DEAD_SPOT,
           0x333A45A: ROW_LIMIT, 0x333A475: LAZY, 0x333A497: "the mutated store leaves row +0x20 to a stack word already zeroed at 0x4d622ad",
           0x4C6BE64: "every quote in the set passed the same bound in 0x3be6950", 0x3BE696E: "the index stops at the same length, so this bound never trips", 0x3BE6A3D: "panic tail of that dead bound", 0x3BE6A41: "panic tail of that dead bound",
           0x375FB51: DEAD_TOKEN, 0x375FBE1: "exponents below 16 return before this test, and every exponent reaching it gives the same arm or the same panic", 0x375FBE6: "the low bit of 10^16 rounds away in the f64 divisor",
           0x471DE99: "the count here is at most 3, below both limits"}
UNSPLIT = "no case in the list separates this mutant; no claim rests on this row"


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
    if word[0] == "filled":
        return "stub status passed through"
    return "status %#x" % word[0]


def worked_run(harness):
    """One enable: token 5 with USDC spot 1, mid 1.05, native 3 has no pair yet."""
    harness.copy = SECOND
    case = Case("worked", spot_books={1: dict(bid=1040000, ask=1060000, anchor=1050000), 0: dict(bid=2500000, ask=2600000, anchor=2550000)})
    run = harness.run(case)
    return {"token": case.token, "native": case.native, "usdc_spot": 1, "scale": spec_scale(case, 5), "mid": spec_mid(case.book(1)), "events": [list(event) for event in run["events"]], "status": "%#x" % run["status"][0]}


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
    functions = []
    named = [(copy["entry"], "enable, %s copy" % copy["name"]) for copy in COPIES] + [(copy["price"], "pair price, %s copy" % copy["name"]) for copy in COPIES]
    named += [(0x42FBA60, "book mid, second and third copy"), (0x26E0570, "book mid, first copy"), (0x4A078A0, "book tops, second and third copy"), (0x23978C0, "book tops, first copy"), (MEDIAN, "median"), (COLLECT_TOPS, "nonzero top collector"),
              (SCALE, "price scale"), (WRITER, "status writer"), (FIND_PAIR, "pair lookup"), (USDC_PAIR, "native USDC pair"), (SYSTEM_READ, "0xfe row read"), (SYSTEM_MAKE, "0xfe row build"), (FILTER_TEST, "deployer filter"), (SCAN_SPOTS, "spot quote collector"), (SCAN_NEXT, "spot quote scan"), (STATUS_MOVE, "status block move")]
    for start, role in named:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    sites = direct_sites(image, sorted({copy["entry"] for copy in COPIES} | {copy["price"] for copy in COPIES} | {0x42FBA60, 0x26E0570}))
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
    bands = [band_edges(exponent) for exponent in range(0, 20)]
    edge_rows = []
    for band in bands:
        for key, value in (("lowest_pass", band["lowest_pass"]), ("highest_pass", band["highest_pass"])):
            edge_rows.append((band["exponent"], key, value))
    diffs = [body_diff(image, COPIES[0]["entry"], COPIES[1]["entry"]), body_diff(image, COPIES[0]["entry"], COPIES[2]["entry"]), body_diff(image, COPIES[0]["price"], COPIES[1]["price"]), body_diff(image, COPIES[0]["price"], COPIES[2]["price"])]
    results_rows = run_mutants(image, seen, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "call_flags": read_flag_sites(image),
        "copies": [{key: ("%#x" % value if isinstance(value, int) and not isinstance(value, bool) else value) for key, value in copy.items() if key != "sites"} for copy in COPIES],
        "copy_diff": diffs,
        "float_constants": read_floats(image),
        "power_table": read_table(image),
        "texts": read_texts(image),
        "status_text": read_display(image, (STATUS_NO_NATIVE, STATUS_INVALID, 0x109, 0x10A, 0xAC)),
        "locations": locations,
        "node_shapes": {"status_map": STATUS_NODE, "aligned_map": ALIGNED_NODE, "system_map": SYSTEM_NODE, "book_side": {"parent": SIDE_PARENT, "keys": SIDE_KEYS, "index": SIDE_INDEX, "length": SIDE_LENGTH, "edges": SIDE_EDGES}},
        "fields": FIELDS,
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases), "runs": runs},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_bands": bands,
    }


FIELDS = {
    "state": {"+0x60": "12-byte time given to the status writer", "+0x80": "native token tag", "+0x88": "native token", "+0x90": "token and spot metadata block", "+0x1f8/+0x200": "spot rows: pointer, length (metadata +0x168/+0x170)",
              "+0x210/+0x218": "token rows: pointer, length (metadata +0x180/+0x188)", "+0x298": "aligned map (metadata +0x208)", "+0x2e0": "quote status map (metadata +0x250)", "+0x8f2, third copy +0x1372": "network byte", "+0x3388/+0x3390, third copy +0x3e08/+0x3e10": "spot book list",
              "+0x3a00, third copy +0x4480": "0xfe buy row map", "+0x3840, third copy +0x42c0": "argument block of the stubbed resolver 0x33690c0"},
    "spot_row": {"stride": "0x20", "+0x00": "base token", "+0x08": "quote token"},
    "token_row": {"stride": "0xe8", "+0x38/+0x40": "name: pointer, length", "+0x48": "sz decimals", "+0x49": "wei decimals", "+0x58/+0x60": "spot list: pointer, length", "+0xa8": "deployer trading fee share", "+0xd2": "deployer present", "+0xd3": "deployer, 20 bytes"},
    "book": {"stride": "0xd8", "+0x78": "third input of the median", "+0x80": "first side tree, read by the bid gate", "+0x98": "second side tree"},
    "system_row": {"stride": "0x48", "+0x10": "copied, floor 10", "+0x30": "spot written by 0x333a420", "+0x38": "amount, cut to a multiple of 100", "+0x40": "copied"},
}


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    bands = evidence.pop("_bands")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\topcode\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["exponent\tscale\tlowest_pass\thighest_pass\texact_low\texact_high"]
    lines += ["%(exponent)d\t%(scale)d\t%(lowest_pass)d\t%(highest_pass)d\t%(exact_low)d\t%(exact_high)d" % row_ for row_ in bands]
    files["band.tsv"] = "\n".join(lines) + "\n"
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
