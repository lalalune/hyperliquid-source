#!/usr/bin/env python3
"""Pin the node #94 order request to open order record path from ELF bytes: fields, type word, time, child rows.

`0x42fe970` (spot) and `0x42fe2d0` (perp) take a request of 0xb8 bytes, turn it into a resting or trigger order shape,
hand it to the record builders and then map its child rows of 0x48 bytes through `0x47f6950` and `0x47f7960`, which
call them back. The real bytes run in a Python evaluator, with the builders and the outcome walk running as helpers.
A separately written specification predicts every field, allocation, free and stop, and every condition, immediate
and field offset of the four functions is flipped to show the run can tell. No objdump or readelf output is parsed,
and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import datetime
import decimal
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

SPOT_REQUEST = 0x42FE970
PERP_REQUEST = 0x42FE2D0
SPOT_ROWS = 0x47F6950
PERP_ROWS = 0x47F7960
SLOT_FREE = 0x576E010
REQUEST_SIZE = 0xC0
KID_STRIDE = 0x48
SPOT_RESTING = 0x42FBCB0
PERP_RESTING = 0x42FC2F0
SPOT_TRIGGER = 0x4302380
PERP_TRIGGER = 0x43029D0
SPOT_LOOKUP = 0x4338EC0
PERP_LOOKUP = 0x43391A0
SPOT_CHILDREN = 0x487B000
PERP_CHILDREN = 0x4870250
SPOT_TEXT = 0x49E7F50
ORDER_TEXT = 0x327B890
OUTCOME_ID = 0x3729660
SIP_HASH = 0x399C4A0
SIP_WRITE = 0x3A00700
WRITER = 0x2A2C240
GROW = 0x454F5D0

SLOT_ALLOC = 0x576DFD8
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMCMP = 0x576E488
SLOT_FORMAT = 0x576E040
SLOT_BOUNDS = 0x576DFC8
SLOT_PANIC = 0x576E470
SLOT_OVERFLOW = 0x576E150
SLOT_ALLOC_ERROR = 0x576DFB8
SLOT_NOUNWIND = 0x576E128
SLOT_OUTCOME_ID = 0x57738C8
SLOT_ORDER_TEXT = 0x5774800
SLOT_CHAR_FMT = 0x576E780
SLOT_U64_FMT = 0x576E090
SLOT_FLOAT_FMT = 0x57739B0
FAKE_MEMCPY = 0xFACE0010
FAKE_MEMCMP = 0xFACE0020

STR_FMT = 0x4C69B70
FLOAT_WRAP = 0x38033F0
FLOAT_INNER = 0x1571D50
SLOT_FLOAT_INNER = 0x576EA18
TEMPLATE_COIN = 0x1E0FD2
TEMPLATE_PRICE = 0x1E5332
TEMPLATE_FLOAT = 0x1EA44D
CHAR_AT = 0x20A100
HASH_CHAR_AT = 0x20A04C
PURR_AT = 0x5B9790
ABOVE_AT = 0x7049BD
BELOW_AT = 0x7049C2
POWERS_AT = 0x6F7470
POWERS_COUNT = 256
ORDER_TABLE = 0x581F98
SIDE_WRITER = 0x29FA870
SIDE_BYTES_AT = 0x29FA935

LOC_LIST = 0x5714C70
LOC_TOKEN = 0x56F21F0
LOC_WEI = 0x56F2258
LOC_PERP = 0x56F21C0
LOC_DECIMALS = 0x56F3350
LOCATION_NAMES = {LOC_LIST: "spot past the list", LOC_TOKEN: "token past the row list", LOC_WEI: "wei decimals below size decimals", LOC_PERP: "asset of another dex or past the list", LOC_DECIMALS: "size decimals above 6"}

SLOT_STRIDE = 0xF8
SPOT_STRIDE = 0x20
TOKEN_STRIDE = 0xE8
PERP_STRIDE = 0x30
RECORD_SIZE = 0xA8
ASSET_DIVISOR = 10000
OUTCOME_BASE = 100000000
NONE_WORD = 0x8000000000000000
OTHER_PACKET_HOSTS = frozenset((0x42F7890, 0x42F8840, 0x42F97F0, 0x42FA880, 0x430D610, 0x4311140, 0x4314DA0, 0x4318A00))

FX_MULTIPLIER = 0xF1357AEA2E62A9C5
USER_KEYS = 0x378
USER_VALUES = 0x38
USER_LENGTH = 0x456
USER_EDGES = 0x458
USER_KEY_SIZE = 0x14
USER_VALUE_SIZE = 0x50
ORDER_KEYS = 0x08
ORDER_VALUES = 0x60
ORDER_LENGTH = 0x84A
ORDER_EDGES = 0x850
ORDER_VALUE_SIZE = 0xB8
NODE_SLOTS = 11
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
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 2000000
MUTANT_STEP_LIMIT = 80000

OUT = HEAP_BASE + 0x800
CTX = HEAP_BASE + 0x900
ARG = HEAP_BASE + 0x980
META = HEAP_BASE + 0x1000
BOOK = HEAP_BASE + 0x2000
BUMP = HEAP_BASE + 0x3000

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


# ---- specification: written from the reading, no call into the evaluator ----

def siphash13(k0, k1, word):
    """SipHash-1-3 of one little-endian u64, as the std hasher finishes it."""
    v0, v1, v2, v3 = k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573

    def rol(value, count):
        return (value << count | value >> (64 - count)) & MASK[8]

    def sip_round():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & MASK[8]
        v1 = rol(v1, 13) ^ v0
        v0 = rol(v0, 32)
        v2 = (v2 + v3) & MASK[8]
        v3 = rol(v3, 16) ^ v2
        v0 = (v0 + v3) & MASK[8]
        v3 = rol(v3, 21) ^ v0
        v2 = (v2 + v1) & MASK[8]
        v1 = rol(v1, 17) ^ v2
        v2 = rol(v2, 32)

    v3 ^= word
    sip_round()
    v0 ^= word
    last = 8 << 56
    v3 ^= last
    sip_round()
    v0 ^= last
    v2 ^= 0xFF
    sip_round()
    sip_round()
    sip_round()
    return v0 ^ v1 ^ v2 ^ v3


def fx_hash(key):
    """The one word hash of the slab index table: multiply, then rotate left by 20."""
    value = key * FX_MULTIPLIER & MASK[8]
    return (value << 20 | value >> 44) & MASK[8]


ORDER_TYPES = ("Limit", "Market", "Take Profit Market", "Take Profit Limit", "Stop Market", "Stop Limit", "Vault Close", "Spot Dust Conversion", "Borrow Liquidation", "Twap Slice")
POWERS = []


def float_text(value):
    """Rust Display of a finite f64: shortest digits, no exponent, no trailing `.0`."""
    text = format(decimal.Decimal(repr(value)), "f")
    return text[:-2] if text.endswith(".0") else text


def scaled(word, power):
    """A u64 over a power of ten, with 0 kept as exact 0.0."""
    return to_bits(float(word) / POWERS[power]) if word else 0


class Stop(Exception):
    pass


class Spec:
    """Predicts one record, its allocations in order, and the stop of a whole run."""

    def __init__(self, case):
        self.case = case
        self.world = case.world
        self.events = []

    def alloc(self, size):
        self.events.append(("alloc", size))

    def outcome_tag(self, token):
        world = self.world
        if world.empty_b or token not in world.map_b:
            return None, 2
        identity = world.map_b[token]
        if world.empty_c or identity not in world.map_c:
            return None, 3
        first, second = world.map_c[identity]
        if first == token:
            return identity, 0
        if second == token:
            return identity, 1
        return None, 3

    def spot_coin(self, index, token):
        identity, tag = self.outcome_tag(token)
        if tag < 2:
            number = identity * 10
            number = MASK[8] if number > MASK[8] else number + tag
            number = MASK[8] if number > MASK[8] else number
            number = min(number, MASK[8] - OUTCOME_BASE)
            return "#%d" % number, None
        if index == 0:
            self.alloc(9)
            return "PURR/USDC", 9
        if index < OUTCOME_BASE:
            return "\x40%d" % index, None
        return "#%d" % (index - OUTCOME_BASE), None

    def spot_scales(self):
        world = self.world
        index = world.asset
        if index >= world.list_len:
            raise Stop(("bounds", index, world.list_len, LOC_LIST))
        base, quote = world.spot
        coin, _ = self.spot_coin(index, base)
        if base >= world.row_count or quote >= world.row_count:
            raise Stop(("panic", LOC_TOKEN))
        size_decimals = world.tokens[base][0]
        wei = world.tokens[quote][1]
        if wei < size_decimals:
            raise Stop(("overflow", LOC_WEI))
        return coin, wei - size_decimals, size_decimals

    def perp_scales(self):
        world = self.world
        dex, index = divmod(world.asset, ASSET_DIVISOR)
        if dex != world.dex or index >= world.perp_len:
            raise Stop(("panic", LOC_PERP))
        name, size_decimals = world.perps[index]
        if name:
            self.alloc(len(name))
        return name, size_decimals

    def perp_decimals(self, size_decimals):
        if size_decimals >= 7:
            raise Stop(("overflow", LOC_DECIMALS))
        return 6 - size_decimals, size_decimals

    def children(self, ids, user, depth):
        rows, room = [], 0
        for oid in ids:
            row = self.view(user, oid, depth)
            if row is None:
                continue
            if not rows:
                self.alloc(4 * RECORD_SIZE)
                room = 4
            elif len(rows) == room:
                self.events.append(("grow", len(rows)))
                room *= 2
            rows.append(row)
        return rows

    def base_record(self, order, coin, price_power, size_power, oid_word):
        return {"coin": coin, "side": order["side"], "limitPx": scaled(order["px"], price_power), "oid": oid_word, "timestamp": order["time"], "reduceOnly": order["reduce"], "cloid": order["cloid"].hex()}

    def resting(self, order, oid_ignored, depth):
        perp = self.world.perp
        if perp:
            coin, size_decimals = self.perp_scales()
            price_power, size_power = self.perp_decimals(size_decimals)
        else:
            coin, price_power, size_power = self.spot_scales()
        text = "N/A" if order["kind"] & MASK[4] < 2 else "Triggered"
        self.alloc(len(text))
        kids = self.children(order["children"], order["user"], depth + 1)
        kind_text = ORDER_TYPES[order["kind"]]
        self.alloc(len(kind_text))
        record = self.base_record(order, coin, price_power, size_power, order["oid"])
        record.update({"sz": scaled(order["sz"], size_power), "triggerCondition": text, "isTrigger": 0, "triggerPx": 0, "children": kids, "isPositionTpsl": order["tpsl"], "orderType": kind_text, "origSz": scaled(order["orig"], size_power), "tif": order["tif"]})
        return record

    def trigger(self, order, user, oid, depth):
        perp = self.world.perp
        if perp:
            coin, size_decimals = self.perp_scales()
            price_power, size_power = self.perp_decimals(size_decimals)
        else:
            coin, price_power, size_power = self.spot_scales()
        size = scaled(order["sz"], size_power) if order["has"] else 0
        direction = "below" if order["side"] == order["flag"] else "above"
        text = "Price %s %s" % (direction, float_text(float(order["trigger"]) / POWERS[price_power]))
        kids = self.children(order["children"], user, depth + 1)
        kind_text = ORDER_TYPES[order["kind"]]
        self.alloc(len(kind_text))
        record = self.base_record(order, coin, price_power, size_power, oid)
        record.update({"sz": size, "triggerCondition": text, "isTrigger": 1, "triggerPx": to_bits(float(order["trigger"]) / POWERS[price_power]), "children": kids, "isPositionTpsl": (order["has"] & 0xFF) ^ 1, "orderType": kind_text, "origSz": size, "tif": 5})
        return record

    def view(self, user, oid, depth):
        world = self.world
        orders = world.triggers.get(user, {})
        if oid in orders:
            return self.trigger(orders[oid], user, oid, depth)
        if world.empty_book or oid not in world.resting:
            return None
        slot, order = world.resting[oid]
        if slot >= world.slab_len or order["tag"] == 2:
            return None
        return self.resting(order, oid, depth)


def spec_run(case):
    spec = Spec(case)
    if case.kind == "order_text":
        return {"stop": None, "answer": ORDER_TYPES[case.oid], "events": [("alloc", len(ORDER_TYPES[case.oid]))]}
    try:
        answer = spec.view(case.user, case.oid, 0)
        return {"stop": None, "answer": answer, "events": spec.events}
    except Stop as caught:
        return {"stop": caught.args[0], "events": spec.events}


# ---- harness: real bytes; allocation, copy, formatting and panics are stubbed ----

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
        relative = self.relative
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.slots = {relative[SLOT_PANIC]: self.on_panic, relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_OVERFLOW]: self.on_overflow,
                         relative[SLOT_ALLOC]: self.on_alloc, relative[SLOT_ALLOC_ERROR]: self.on_alloc_error, relative[SLOT_FORMAT]: self.on_format,
                         FAKE_MEMCPY: self.on_memcpy, FAKE_MEMCMP: self.on_memcmp}
        self.real = RealExcept()
        self.real.stubs = frozenset(machine.slots) | {GROW}
        machine.real = self.real
        machine.calls = {GROW: self.on_grow}
        machine.jump_low, machine.jump_high = image.exact_fde(ORDER_TEXT)
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        if not POWERS:
            blob = image.blob
            POWERS.extend(struct.unpack_from("<%dd" % POWERS_COUNT, blob, image.offset(POWERS_AT)))

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_overflow(self, m):
        raise Panicked(("overflow", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_alloc_error(self, m):
        raise Panicked(("alloc error",))

    def on_alloc(self, m):
        size = m.regs[RDI]
        if not 0 < size < 0x4000:
            raise Halt("allocation size")
        self.events.append(("alloc", size))
        m.regs[RAX] = self.alloc(size)

    def on_memcpy(self, m):
        count = m.regs[RDX]
        if count > 0x1000:
            raise Halt("copy size")
        if count:
            m.memory.copy(m.regs[RDI], m.regs[RSI], count)
        m.regs[RAX] = m.regs[RDI]

    def on_memcmp(self, m):
        if m.regs[RDX] != USER_KEY_SIZE:
            raise Halt("compare size")
        left = m.memory.bytes_at(m.regs[RDI], USER_KEY_SIZE)
        right = m.memory.bytes_at(m.regs[RSI], USER_KEY_SIZE)
        m.regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_grow(self, m):
        vector, length, extra, align, size = m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8]
        if (extra, align, size) != (1, 8, RECORD_SIZE):
            raise Halt("grow arguments")
        memory = m.memory
        room = memory.read(vector, 8)
        if length != room:
            raise Halt("grow while room is left")
        self.events.append(("grow", length))
        new = self.alloc(2 * room * RECORD_SIZE)
        memory.copy(new, memory.read(vector + 8, 8), length * RECORD_SIZE)
        memory.write(vector, 8, 2 * room)
        memory.write(vector + 8, 8, new)

    def on_format(self, m):
        memory = m.memory
        template, args = m.regs[RSI], m.regs[RDX]
        pieces = self.template_pieces(template)
        text = ""
        index = 0
        for piece in pieces:
            if piece is not None:
                text += piece
                continue
            value = memory.read(args + index * 16, 8)
            function = memory.read(args + index * 16 + 8, 8)
            index += 1
            text += self.format_argument(value, function)
        data = text.encode("ascii")
        at = self.alloc(max(len(data), 1))
        memory.put_bytes(at, data)
        self.put(m.regs[RDI], 8, len(data))
        self.put(m.regs[RDI] + 8, 8, at)
        self.put(m.regs[RDI] + 0x10, 8, len(data))

    def template_pieces(self, template):
        """The compact format template: 0xc0 is a placeholder, a byte below 0x80 a literal length, 0 the end."""
        memory = self.machine.memory
        pieces = []
        for _ in range(16):
            byte = memory.read(template, 1)
            template += 1
            if byte == 0:
                return pieces
            if byte == 0xC0:
                pieces.append(None)
            elif byte < 0x80:
                pieces.append(memory.bytes_at(template, byte).decode("ascii"))
                template += byte
            else:
                raise Halt("template byte")
        raise Halt("template length")

    def format_argument(self, value, function):
        memory = self.machine.memory
        relative = self.relative
        if function == relative[SLOT_CHAR_FMT]:
            return chr(memory.read(value, 4))
        if function == relative[SLOT_U64_FMT]:
            return "%d" % memory.read(value, 8)
        if function == STR_FMT:
            return memory.bytes_at(memory.read(value, 8), memory.read(value + 8, 8)).decode("ascii")
        if function == relative[SLOT_FLOAT_FMT]:
            return float_text(to_float(memory.read(value, 8)))
        raise Halt("format function %#x" % function)

    # world bytes

    def write_table(self, at, entries, stride, write_entry, world, mark, empty, hash_of):
        """A hash table of `buckets`: control bytes after the entries, entries growing down from them."""
        memory = self.machine.memory
        buckets = world.buckets
        mask = buckets - 1
        block = self.alloc(buckets * stride + buckets + 16)
        memory.put_bytes(block, ramp(buckets * stride, mark))
        ctrl = block + buckets * stride
        control = bytearray(b"\xff" * buckets)

        def slot_for(home):
            jump, position = 0, home
            while True:
                for step in range(16):
                    index = (position + step) & mask
                    if control[index] == 0xFF:
                        return index
                jump += 16
                position = (position + jump) & mask

        keep = buckets // 2
        for key in sorted(entries):
            value = hash_of(key)
            home, tag = value & mask, value >> 57
            for step in range(world.decoys):
                index = (home + step) & mask
                if control[index] == 0xFF and buckets - control.count(0xFF) < keep:
                    control[index] = tag
                    self.put(ctrl - (index + 1) * stride, 8, key ^ (0x1000 + step))
            for step in range(world.tombs):
                index = (home + world.decoys + step) & mask
                if control[index] == 0xFF and buckets - control.count(0xFF) < keep:
                    control[index] = 0x80
            index = slot_for(home)
            control[index] = tag
            place = ctrl - (index + 1) * stride
            self.put(place, 8, key)
            write_entry(place, key)
        memory.put_bytes(ctrl, bytes(control) + bytes(control[:16]))
        self.put(at, 8, ctrl)
        self.put(at + 8, 8, mask)
        self.put(at + 0x18, 8, 0 if empty else len(entries))

    def write_order_common(self, at, order, fields):
        memory = self.machine.memory
        for name, (offset, width) in fields.items():
            self.put(at + offset, width, order[name])

    def write_resting(self, at, order):
        memory = self.machine.memory
        ids = self.alloc(max(len(order["children"]), 1) * 8)
        for index, child in enumerate(order["children"]):
            self.put(ids + index * 8, 8, child)
        self.put(at, 4, order["tag"])
        self.put(at + 0x58, 8, ids)
        self.put(at + 0x60, 8, len(order["children"]))
        self.put(at + 0x90, 8, order["kind"])
        self.put(at + 0x98, 8, 0x5151)
        self.put(at + 0xA0, 8, order["px"])
        self.put(at + 0xA8, 8, order["time"])
        self.put(at + 0xB0, 1, order["reduce"])
        memory.put_bytes(at + 0xB1, order["cloid"])
        self.put(at + 0xC2, 1, order["side"])
        self.put(at + 0xC8, 8, order["sz"])
        self.put(at + 0xD0, 8, order["orig"])
        self.put(at + 0xD8, 8, order["oid"])
        memory.put_bytes(at + 0xE0, order["user"])
        self.put(at + 0xF4, 1, order["tpsl"])
        self.put(at + 0xF5, 1, order["tif"])

    def write_trigger(self, at, order):
        memory = self.machine.memory
        ids = self.alloc(max(len(order["children"]), 1) * 8)
        for index, child in enumerate(order["children"]):
            self.put(ids + index * 8, 8, child)
        self.put(at, 8, order["has"])
        self.put(at + 0x08, 8, order["sz"])
        self.put(at + 0x38, 8, ids)
        self.put(at + 0x40, 8, len(order["children"]))
        self.put(at + 0x70, 8, order["kind"])
        self.put(at + 0x78, 8, 0x5252)
        self.put(at + 0x80, 8, order["px"])
        self.put(at + 0x88, 8, order["time"])
        self.put(at + 0x90, 1, order["reduce"])
        memory.put_bytes(at + 0x91, order["cloid"])
        self.put(at + 0xA2, 1, order["side"])
        self.put(at + 0xA8, 8, order["trigger"])
        self.put(at + 0xB1, 1, order["flag"])

    def write_tree(self, items, height, key_at, value_at, length_at, edge_at, value_size, write_key, write_value, tempt):
        """One subtree with uniform depth; unused key slots hold the wanted key, leaf edges are unmapped."""
        memory = self.machine.memory
        leaf = height == 0
        size = edge_at + (0 if leaf else 12 * 8)
        node = self.alloc(size)
        memory.put_bytes(node, ramp(size, 11 + height))
        if leaf:
            kept, kids = items, []
        else:
            part = (len(items) - 2) // 3
            if part < 1:
                raise Halt("tree too small for its height")
            kept = [items[part], items[2 * part + 1]]
            kids = [items[:part], items[part + 1:2 * part + 1], items[2 * part + 2:]]
        if len(kept) > NODE_SLOTS:
            raise Halt("node too long")
        for slot in range(NODE_SLOTS):
            write_key(node + key_at(slot), tempt)
        for slot, (key, value) in enumerate(kept):
            write_key(node + key_at(slot), key)
            write_value(node + value_at + slot * value_size, key, value)
        self.put(node + length_at, 2, len(kept))
        if not leaf:
            for slot in range(12):
                self.put(node + edge_at + slot * 8, 8, LEAF_EDGE)
            for slot, part_items in enumerate(kids):
                self.put(node + edge_at + slot * 8, 8, self.write_tree(part_items, height - 1, key_at, value_at, length_at, edge_at, value_size, write_key, write_value, tempt))
        return node

    def write_orders(self, at, orders, height, tempt):
        items = sorted(orders.items())
        if not items:
            self.put(at, 8, 0)
            self.put(at + 8, 8, 0)
            return
        root = self.write_tree(items, height, lambda slot: ORDER_KEYS + slot * 8, ORDER_VALUES, ORDER_LENGTH, ORDER_EDGES, ORDER_VALUE_SIZE,
                               lambda place, key: self.put(place, 8, key), lambda place, key, value: self.write_trigger(place, value), tempt)
        self.put(at, 8, root)
        self.put(at + 8, 8, height)
        self.put(at + 0x10, 8, len(items))

    def write_users(self, world, case):
        items = sorted(world.triggers.items())
        if not items:
            self.put(BOOK + 0xB8, 8, 0)
            self.put(BOOK + 0xC0, 8, 0)
            return
        memory = self.machine.memory
        root = self.write_tree(items, world.user_height, lambda slot: USER_KEYS + slot * USER_KEY_SIZE, USER_VALUES, USER_LENGTH, USER_EDGES, USER_VALUE_SIZE,
                               lambda place, key: memory.put_bytes(place, key), lambda place, key, value: self.write_orders(place, value, world.order_height, case.oid), case.user)
        self.put(BOOK + 0xB8, 8, root)
        self.put(BOOK + 0xC0, 8, world.user_height)

    def write_world(self, case):
        world = case.world
        memory = self.machine.memory
        memory.put_bytes(META, ramp(0x200, 31))
        memory.put_bytes(BOOK, ramp(0x100, 33))
        sip_a = struct.unpack("<QQ", ramp(16, 74))
        sip_b = struct.unpack("<QQ", ramp(16, 84))
        self.write_table(META + 0x70, world.map_b, 0x10, lambda place, key: self.put(place + 8, 8, world.map_b[key]), world, 71, world.empty_b, lambda key: siphash13(sip_a[0], sip_a[1], key))
        self.put(META + 0x90, 8, sip_a[0])
        self.put(META + 0x98, 8, sip_a[1])

        def write_entry(place, key):
            for side, token in enumerate(world.map_c[key]):
                self.put(place + 8 + side * 0x28 + 0x20, 8, token)

        self.write_table(META + 0xD0, world.map_c, 0x90, write_entry, world, 81, world.empty_c, lambda key: siphash13(sip_b[0], sip_b[1], key))
        self.put(META + 0xF0, 8, sip_b[0])
        self.put(META + 0xF8, 8, sip_b[1])
        row = self.alloc(SPOT_STRIDE)
        memory.put_bytes(row, ramp(SPOT_STRIDE, 63))
        self.put(row, 8, world.spot[0])
        self.put(row + 8, 8, world.spot[1])
        self.put(META + 0x168, 8, (row - world.asset * SPOT_STRIDE) & MASK[8])
        self.put(META + 0x170, 8, world.list_len)
        room = TOKEN_STRIDE * (max(world.tokens) + 1)
        tokens = self.alloc(room)
        memory.put_bytes(tokens, ramp(room, 57))
        for token, (size_decimals, wei) in world.tokens.items():
            self.put(tokens + token * TOKEN_STRIDE + 0x48, 1, size_decimals)
            self.put(tokens + token * TOKEN_STRIDE + 0x49, 1, wei)
        self.put(META + 0x180, 8, tokens)
        self.put(META + 0x188, 8, world.row_count)
        perps = self.alloc(PERP_STRIDE * max(len(world.perps), 1))
        memory.put_bytes(perps, ramp(PERP_STRIDE * max(len(world.perps), 1), 53))
        for index, (name, size_decimals) in enumerate(world.perps):
            data = name.encode("ascii")
            text = self.alloc(max(len(data), 1))
            memory.put_bytes(text, data + b"\xa5")
            self.put(perps + index * PERP_STRIDE + 8, 8, text)
            self.put(perps + index * PERP_STRIDE + 0x10, 8, len(data))
            self.put(perps + index * PERP_STRIDE + 0x2A, 1, size_decimals)
        self.put(META + 8, 8, perps)
        self.put(META + 0x10, 8, world.perp_len)
        self.put(META + 0x30, 8, world.dex)
        self.put(BOOK + 0xB0, 8, world.asset)
        slab = self.alloc(SLOT_STRIDE * max(world.slab_len, 1))
        memory.put_bytes(slab, ramp(SLOT_STRIDE * max(world.slab_len, 1), 47))
        for oid, (slot, order) in world.resting.items():
            if slot < world.slab_len:
                self.write_resting(slab + slot * SLOT_STRIDE, order)
        self.put(BOOK + 8, 8, slab)
        self.put(BOOK + 0x10, 8, world.slab_len)
        self.write_table(BOOK + 0x28, world.resting, 0x10, lambda place, key: self.put(place + 8, 8, world.resting[key][0]), world, 91, world.empty_book, fx_hash)
        self.write_users(world, case)

    # the runs

    def read_string(self, at):
        memory = self.machine.memory
        size, room, data = memory.read(at + 0x10, 8), memory.read(at, 8), memory.read(at + 8, 8)
        if size > 0x400:
            raise Halt("string length")
        if size != room:
            raise Halt("string capacity differs from its length")
        if not size:
            if data != 1:
                raise Halt("empty string pointer")
            return ""
        return memory.bytes_at(data, size).decode("latin1")

    def read_record(self, at, depth=0):
        memory = self.machine.memory
        if depth > 6:
            raise Halt("record depth")
        count, room, kids = memory.read(at + 0x40, 8), memory.read(at + 0x30, 8), memory.read(at + 0x38, 8)
        if count > 64 or room < count:
            raise Halt("children length")
        if not count and (room or kids != 8):
            raise Halt("empty children vector")
        return {"coin": self.read_string(at), "side": memory.read(at + 0x90, 1), "limitPx": memory.read(at + 0x60, 8), "sz": memory.read(at + 0x68, 8), "oid": memory.read(at + 0x70, 8),
                "timestamp": memory.read(at + 0x78, 8), "triggerCondition": self.read_string(at + 0x18), "isTrigger": memory.read(at + 0x91, 1), "triggerPx": memory.read(at + 0x80, 8),
                "children": [self.read_record(kids + index * RECORD_SIZE, depth + 1) for index in range(count)], "isPositionTpsl": memory.read(at + 0x92, 1), "reduceOnly": memory.read(at + 0x93, 1),
                "orderType": self.read_string(at + 0x48), "origSz": memory.read(at + 0x88, 8), "tif": memory.read(at + 0xA5, 1), "cloid": memory.bytes_at(at + 0x94, 17).hex()}

    def run_case(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.case = case
        memory.put_bytes(OUT, ramp(0x100, 13))
        memory.put_bytes(ARG, b"\xa5" * 0x40)
        if case.kind == "order_text":
            result = machine.run(ORDER_TEXT, {RDI: OUT, RSI: case.oid, RDX: 0xABCD})
            if result != OUT:
                raise Halt("result pointer")
            size = memory.read(OUT + 0x10, 8)
            if memory.read(OUT, 8) != size:
                raise Halt("string capacity")
            answer = memory.bytes_at(memory.read(OUT + 8, 8), size).decode("ascii")
            return {"stop": None, "answer": answer, "events": self.events}
        self.write_world(case)
        memory.put_bytes(ARG, case.user)
        self.put(ARG + 0x20, 8, case.oid)
        self.put(CTX, 8, BOOK)
        self.put(CTX + 8, 8, ARG)
        self.put(CTX + 0x10, 8, META)
        self.put(CTX + 0x18, 8, CTX)
        result = machine.run(PERP_LOOKUP if case.world.perp else SPOT_LOOKUP, {RDI: OUT, RSI: CTX + 0x18, RDX: ARG + 0x20})
        if result != OUT:
            raise Halt("result pointer")
        if memory.bytes_at(OUT + RECORD_SIZE, 0x40) != ramp(0x100, 13)[RECORD_SIZE:RECORD_SIZE + 0x40]:
            raise Halt("wrote past the record")
        if memory.read(OUT, 8) == NONE_WORD:
            if memory.bytes_at(OUT + 8, 0x20) != ramp(0x100, 13)[8:0x28]:
                raise Halt("empty result wrote more than its word")
            answer = None
        else:
            if memory.bytes_at(OUT + 0xA6, 2) != ramp(0x100, 13)[0xA6:0xA8]:
                raise Halt("wrote the record padding")
            answer = self.read_record(OUT)
        return {"stop": None, "answer": answer, "events": self.events}

    def run(self, case):
        try:
            return self.run_case(case)
        except Panicked as caught:
            return {"stop": caught.args[0], "events": self.events}
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)


CRASHES = (Halt, EvidenceError, RecursionError, IndexError, KeyError, ZeroDivisionError, StopIteration, OverflowError, ValueError, TypeError, AttributeError, UnicodeDecodeError, struct.error)
COMPARED = ("stop", "answer", "events")


def compare_run(harness, case):
    try:
        actual = harness.run(case)
    except CRASHES as caught:
        return "%s: crash %s" % (case.label, caught)
    expected = spec_run(case)
    for key in COMPARED:
        if key in expected and actual.get(key) != expected.get(key):
            return "%s: %s differs: %s / %s" % (case.label, key, str(actual.get(key))[:400], str(expected.get(key))[:400])
    return None


# ---- cases ----

USER_A = bytes(range(0x10, 0x24))
USER_B = bytes(range(0x30, 0x44))
USER_C = bytes(range(0x50, 0x64))
USER_D = bytes(range(0x70, 0x84))
USER_E = bytes(range(0x90, 0xA4))
USER_F = bytes(range(0xB0, 0xC4))
USER_G = bytes(range(0xD0, 0xE4))
TOP_OID = 0x7777


def resting_order(**fields):
    order = {"tag": 0, "children": (), "kind": 0, "px": 12345678, "time": 1700000000123, "reduce": 0, "cloid": bytes(range(0x41, 0x52)), "side": 0, "sz": 1500, "orig": 2000, "oid": TOP_OID, "user": USER_A, "tpsl": 0, "tif": 1}
    order.update(fields)
    return order


def trigger_order(**fields):
    order = {"has": 1, "sz": 1500, "children": (), "kind": 2, "px": 12345678, "time": 1700000000123, "reduce": 0, "cloid": bytes(range(0x61, 0x72)), "side": 0, "trigger": 23456789, "flag": 0}
    order.update(fields)
    return order


class World:
    def __init__(self, perp=False, **fields):
        self.perp = perp
        self.asset = 1
        self.dex = 0
        self.spot = (1, 0)
        self.list_len = 8
        self.tokens = {0: (2, 8), 1: (4, 8), 2: (2, 8), 3: (0, 6), 4: (5, 5)}
        self.row_count = 5
        self.map_b = {7: 3, 9: 3, 300: 1}
        self.map_c = {3: (7, 9), 8: (1, 2)}
        self.empty_b = self.empty_c = self.empty_book = False
        self.perps = [("BTC", 5), ("ETH", 4), ("A", 6), ("", 0), ("LONGNAME-ROW", 3), ("Y", 7)]
        self.perp_len = 6
        self.buckets = 32
        self.decoys = 1
        self.tombs = 1
        self.slab_len = 8
        self.resting = {}
        self.triggers = {}
        self.user_height = 0
        self.order_height = 0
        for key, value in fields.items():
            setattr(self, key, value)
        if perp and "asset" not in fields:
            self.asset = 1


class Case:
    def __init__(self, label, kind="view", world=None, user=USER_A, oid=TOP_OID):
        self.label, self.kind, self.world, self.user, self.oid = label, kind, world, user, oid


def resting_case(label, perp, order=None, **fields):
    extra = fields.pop("extra", {})
    world = World(perp, **fields)
    world.resting = dict(extra)
    world.resting[TOP_OID] = (2, resting_order(**(order or {})))
    return Case(label, world=world)


def trigger_case(label, perp, order=None, **fields):
    extra = fields.pop("extra", {})
    rest = fields.pop("rest", {})
    world = World(perp, **fields)
    world.triggers = {USER_A: dict(extra)}
    world.triggers[USER_A][TOP_OID] = trigger_order(**(order or {}))
    world.resting = dict(rest)
    return Case(label, world=world)


CACHE = {}


# ---- the request record: specification, bytes, cases ----

WIRE_DAY_ZERO = 719163


def days_from_common_era(year, ordinal):
    """Day number with 0001-01-01 as 1, for any year, through the 400 year cycle."""
    cycles = (year - 1) // 400
    return datetime.date(year - 400 * cycles, 1, 1).toordinal() + ordinal - 1 + 146097 * cycles


def spec_millis(date, seconds, nanos):
    """Unix milliseconds of a packed date word, seconds of the day and nanoseconds; not above 0 gives 0."""
    signed = date - (1 << 32) if date & SIGN[4] else date
    year = signed >> 13
    ordinal = (date >> 4) & 0x1FF
    value = (days_from_common_era(year, ordinal) - WIRE_DAY_ZERO) * 86400 + seconds
    value = value * 1000 + nanos // 1000000
    value = (value + (1 << 63)) % (1 << 64) - (1 << 63)
    return value if value > 0 else 0


def request(**fields):
    row = {"has": 1, "sz": 1500, "word": 0x20, "market": 0, "tpsl": 2, "px": 12345678, "side": 0, "reduce": 0, "cloid": bytes(range(0x41, 0x52)), "pad": bytes(range(0x61, 0x67)), "note": bytes(range(0x81, 0xA9)),
           "kids": (), "room": None, "oid": 0x7777, "date": (2024 << 13) | (60 << 4) | 3, "seconds": 3600, "nanos": 123456789, "user": USER_A}
    row.update(fields)
    return row


def spec_request(spec, row):
    millis = spec_millis(row["date"], row["seconds"], row["nanos"])
    size = row["sz"] if row["has"] else 0
    if row["tpsl"] == 2:
        order = {"tag": 0, "children": (), "kind": 1 if row["word"] & 7 == 3 else 0, "px": row["px"], "time": millis, "reduce": row["reduce"], "cloid": row["cloid"], "side": row["side"], "sz": size, "orig": size, "oid": row["oid"], "user": row["user"], "tpsl": (row["has"] & 0xFF) ^ 1, "tif": row["word"] & 0xFF}
        record = spec.resting(order, row["oid"], 0)
    else:
        order = {"has": row["has"], "sz": row["sz"], "children": (), "kind": (row["tpsl"] * 2 + 3) ^ row["market"], "px": row["px"], "time": millis, "reduce": row["reduce"], "cloid": row["cloid"], "side": row["side"], "trigger": row["word"], "flag": row["tpsl"]}
        record = spec.trigger(order, row["user"], row["oid"], 0)
    kids = row["kids"]
    if kids:
        spec.alloc(RECORD_SIZE * len(kids))
    rows = []
    for kid in kids:
        rows.append(spec_request(spec, dict(kid, note=row["note"], oid=row["oid"], date=row["date"], seconds=row["seconds"], nanos=row["nanos"], user=row["user"], kids=(), room=0)))
    room = len(kids) if row["room"] is None else row["room"]
    if room:
        spec.events.append(("free", room * KID_STRIDE))
    record["children"] = rows
    return record


def spec_run(case):
    spec = Spec(case)
    try:
        return {"stop": None, "answer": spec_request(spec, case.row), "events": spec.events}
    except Stop as caught:
        return {"stop": caught.args[0], "events": spec.events}


BaseHarness = Harness


class WireHarness(BaseHarness):
    def __init__(self, image):
        BaseHarness.__init__(self, image)
        machine = self.machine
        free = self.relative[SLOT_FREE]
        machine.slots[free] = self.on_free
        self.real.stubs = self.real.stubs | {free}

    def on_free(self, m):
        self.events.append(("free", m.regs[RSI]))

    def write_head(self, at, row):
        """The first 0x48 bytes, the part a child row holds on its own."""
        memory = self.machine.memory
        self.put(at, 8, row["has"])
        self.put(at + 8, 8, row["sz"])
        self.put(at + 0x10, 8, row["word"])
        self.put(at + 0x18, 1, row["market"])
        self.put(at + 0x19, 1, row["tpsl"])
        memory.put_bytes(at + 0x1A, row["pad"])
        self.put(at + 0x20, 8, row["px"])
        self.put(at + 0x30, 1, row["side"])
        self.put(at + 0x31, 1, row["reduce"])
        memory.put_bytes(at + 0x32, row["cloid"])

    def write_request(self, at, row):
        memory = self.machine.memory
        memory.put_bytes(at, ramp(REQUEST_SIZE, 37))
        self.write_head(at, row)
        memory.put_bytes(at + 0x48, row["note"])
        kids = row["kids"]
        block = self.alloc(max(len(kids), 1) * KID_STRIDE)
        memory.put_bytes(block, ramp(max(len(kids), 1) * KID_STRIDE, 27))
        for index, kid in enumerate(kids):
            self.write_head(block + index * KID_STRIDE, kid)
        self.put(at + 0x70, 8, len(kids) if row["room"] is None else row["room"])
        self.put(at + 0x78, 8, block)
        self.put(at + 0x80, 8, len(kids))
        self.put(at + 0x88, 8, META)
        self.put(at + 0x90, 8, row["oid"])
        self.put(at + 0x98, 4, row["date"])
        self.put(at + 0x9C, 4, row["seconds"])
        self.put(at + 0xA0, 4, row["nanos"])
        memory.put_bytes(at + 0xA4, row["user"])

    def run_case(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.case = case
        memory.put_bytes(OUT, ramp(0x100, 13))
        self.write_world(case)
        at = self.alloc(REQUEST_SIZE)
        self.write_request(at, case.row)
        result = machine.run(PERP_REQUEST if case.world.perp else SPOT_REQUEST, {RDI: OUT, RSI: BOOK, RDX: at})
        if result != OUT:
            raise Halt("result pointer")
        if memory.bytes_at(OUT + RECORD_SIZE, 0x40) != ramp(0x100, 13)[RECORD_SIZE:RECORD_SIZE + 0x40]:
            raise Halt("wrote past the record")
        if memory.read(OUT + 0x30, 8) != memory.read(OUT + 0x40, 8):
            raise Halt("child vector room differs from its length")
        return {"stop": None, "answer": self.read_record(OUT), "events": self.events}


Harness = WireHarness


class WireCase:
    def __init__(self, label, perp, row, **fields):
        self.label, self.row = label, row
        self.kind = "request"
        self.world = World(perp, **fields)
        self.user, self.oid = row["user"], row["oid"]


def date_word(year, ordinal, flags=3):
    return ((year << 13) | (ordinal << 4) | flags) & MASK[4]


def all_cases():
    if CACHE:
        return CACHE["cases"]
    rows = []
    for perp in (False, True):
        name = "perp" if perp else "spot"

        def add(label, **fields):
            world = fields.pop("world", {})
            rows.append(WireCase("%s %s" % (name, label), perp, request(**fields), **world))

        add("plain")
        for word in (0, 1, 2, 3, 4, 7, 8, 11, 0x13, 0x103, 0xFF, 0xFFFFFFFFFFFFFF03):
            add("word %d" % word, word=word)
        for has, sz in ((0, 0), (0, 777), (1, 0), (1, 777), (1, 2 ** 63 + 5)):
            add("size %d %d" % (has, sz), has=has, sz=sz)
            add("trigger size %d %d" % (has, sz), has=has, sz=sz, tpsl=0)
        for tpsl in (0, 1):
            for market in (0, 1):
                add("type %d %d" % (tpsl, market), tpsl=tpsl, market=market)
                for side in (0, 1):
                    add("direction %d %d %d" % (tpsl, market, side), tpsl=tpsl, market=market, side=side, word=3000000000)
        for market in (0, 1):
            add("no trigger market byte %d" % market, market=market)
        for side in (0, 1):
            add("side %d" % side, side=side)
            add("trigger side %d" % side, side=side, tpsl=1)
        for reduce in (0, 1):
            add("reduce %d" % reduce, reduce=reduce)
            add("trigger reduce %d" % reduce, reduce=reduce, tpsl=1)
        add("cloid", cloid=bytes(range(0xA0, 0xB1)))
        add("trigger cloid", cloid=bytes(range(0xA0, 0xB1)), tpsl=0)
        add("oid", oid=0x123456789ABCDEF)
        add("trigger oid", oid=0x123456789ABCDEF, tpsl=0)
        add("price", px=2 ** 53 + 1)
        add("trigger price", px=2 ** 53 + 1, tpsl=1)
        add("other user", user=USER_B)
        for year, ordinal in ((2024, 60), (2023, 365), (2024, 366), (1970, 1), (1970, 2), (1969, 365), (2000, 1), (1900, 59), (2100, 60), (2001, 1), (1801, 1), (1901, 1), (2101, 1), (2201, 200), (2401, 3), (1601, 1), (101, 1), (9999, 365), (262142, 300), (1, 1), (0, 1), (-1, 200), (-400, 1), (-401, 365), (-262143, 2)):
            for tpsl in (2, 0):
                add("date %d %d %d" % (year, ordinal, tpsl), date=date_word(year, ordinal), tpsl=tpsl)
        for seconds, nanos in ((0, 0), (1, 0), (86399, 999999999), (0, 999999), (0, 1000000), (0, 1999999999), (86399, 1999999999)):
            for tpsl in (2, 1):
                add("time %d %d %d" % (seconds, nanos, tpsl), seconds=seconds, nanos=nanos, tpsl=tpsl)
        add("first second of 1970", date=date_word(1970, 1), seconds=0, nanos=0)
        add("first second of 1970, trigger", date=date_word(1970, 1), seconds=0, nanos=0, tpsl=0)
        add("before 1970", date=date_word(1969, 365), seconds=86399, nanos=0)
        for count in (1, 2, 3, 5):
            kids = tuple(request(px=1000 + index, sz=index + 9, side=index & 1) for index in range(count))
            add("%d plain kids" % count, kids=kids)
            add("%d trigger kids of a trigger" % count, kids=tuple(request(px=1000 + index, tpsl=index & 1, word=5000 + index, market=(index >> 1) & 1) for index in range(count)), tpsl=0)
        add("spare room, no kids", room=4)
        add("spare room, 2 kids", room=4, kids=(request(), request(tpsl=1)))
        add("spare room, trigger", room=3, tpsl=1)
        add("kid drops its own vector word", kids=(request(has=0, sz=5, word=3),))
        add("kid time and oid come from the parent", kids=(request(oid=9, date=date_word(1999, 1), seconds=7),), oid=0xABCDE, seconds=5)
        add("kid user comes from the parent", kids=(request(user=USER_C),), user=USER_B)
        add("kid note", kids=(request(tpsl=0),), note=bytes(range(0x11, 0x39)))
        add("long id of a kid", kids=(request(cloid=bytes(range(0x21, 0x32))),), oid=2 ** 63 + 1)
    for label, fields in (("past the list", {"asset": 40, "list_len": 4}), ("token past rows", {"spot": (5, 0)}), ("wei below", {"tokens": {0: (9, 1), 1: (2, 9)}, "row_count": 2})):
        rows.append(WireCase("spot %s" % label, False, request(), **fields))
        rows.append(WireCase("spot %s, trigger" % label, False, request(tpsl=1), **fields))
    for label, fields in (("other dex", {"asset": 10001, "dex": 0}), ("past the list", {"asset": 6}), ("decimals 7", {"perps": [("BTC", 7), ("ETH", 7)], "perp_len": 2})):
        rows.append(WireCase("perp %s" % label, True, request(), **fields))
        rows.append(WireCase("perp %s, trigger" % label, True, request(tpsl=1), **fields))
    rows.append(WireCase("spot index 0 kid", False, request(kids=(request(),)), asset=0))
    rows.append(WireCase("spot hash coin", False, request(tpsl=0), asset=100000007, list_len=100000008))
    CACHE["cases"] = rows
    return rows


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


def twin_rows(image, left, right):
    """Two functions of one source: same length, and every instruction equal once call targets and rip words are compared as absolute targets."""
    first = decode_range(image, *image.exact_fde(left))
    second = decode_range(image, *image.exact_fde(right))
    if len(first) != len(second):
        raise EvidenceError("twin length differs: %#x" % left)
    targets = {}
    other = 0
    for one, two in zip(first, second):
        one_bytes = bytes(image.blob[image.offset(one.va):image.offset(one.va) + one.size])
        two_bytes = bytes(image.blob[image.offset(two.va):image.offset(two.va) + two.size])
        if one_bytes == two_bytes:
            continue
        if one.op in ("call", "jmp", "jcc") and one.target is not None:
            local = left <= one.target < image.exact_fde(left)[1]
            if local and one.target - left != two.target - right:
                raise EvidenceError("twin jump differs at %#x" % one.va)
            if not local and one.target != two.target:
                targets[one.target] = two.target
            continue
        if one.rip_at is not None and one.size == two.size:
            other += 1
            continue
        raise EvidenceError("twin instruction differs at %#x" % one.va)
    return {"left": "%#x" % left, "right": "%#x" % right, "instructions": len(first), "call_targets_that_differ": {"%#x" % key: "%#x" % value for key, value in sorted(targets.items())}, "rip_words_that_differ": other}


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


GROUPS = ((SPOT_REQUEST, "spot request builder"), (PERP_REQUEST, "perp request builder"), (SPOT_ROWS, "spot child row map"), (PERP_ROWS, "perp child row map"))


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    return [(start, role, decode_range(image, *image.exact_fde(start))) for start, role in GROUPS]


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run."""
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
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            wanted = set(indices)
            order = [index for index in first_kill if index in wanted] + indices
            for index in order:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

REFERENCE_CLAIMS = (
    {"reference": "l1/order_wire.rs", "claim": "wire order types are decoded elsewhere; no path from a request to a record of named fields", "observed": "0x42fe970 and 0x42fe2d0 build it", "verdict": "absent from the reference"},
)
FIELDS = {
    "request": {"size": "0xb8 by reads; last read ends at +0xb8", "+0x00/+0x08": "size option: tag, value", "+0x10": "word: tif byte in its low byte with no trigger, trigger price with one", "+0x18": "market byte", "+0x19": "2 no trigger, 0 take profit, 1 stop", "+0x1a": "6 bytes copied on a trigger", "+0x20": "limit price", "+0x30": "side byte", "+0x31": "reduceOnly byte", "+0x32": "cloid, 17 bytes", "+0x48": "0x28 bytes handed to every child, not read here", "+0x70/+0x78/+0x80": "child rows: capacity, pointer, count; stride 0x48", "+0x88": "meta block", "+0x90": "oid", "+0x98": "chrono date word", "+0x9c": "seconds of the day", "+0xa0": "nanoseconds", "+0xa4": "user, 20 bytes"},
    "child_row": {"size": "0x48", "content": "the first 0x48 bytes of a request"},
}
NOT_READ = "this word reaches a field nothing reads: a user with no grandchildren, the note block, or slab and tree words the builders skip"
YEAR_ZERO = "year 0 or below: the time is negative and clamps to 0, so this arithmetic cannot show"
SAME_WORD = "the buffer word and the cursor word are equal when the map starts"
BOUND = "needs a child byte length above 2^62"
OLD_VECTOR = "the vector from the builders is always empty here, so this drop has no row"
UNWIND = "unwind landing pad: no case unwinds"
ALLOC_FAILS = "allocation failure arm: the stub never fails"
PERP_GAP = -0x6A0
ROW_GAP = 0x1010
SPOT_NOT_READ = (0x42FE9BF, 0x42FE9CB, 0x42FE9D8, 0x42FEA15, 0x42FEA19, 0x42FEA2D, 0x42FEA44, 0x42FEB43, 0x42FEB57, 0x42FEB63, 0x42FEB6C, 0x42FEBA4, 0x42FEBC6, 0x42FEBD2, 0x42FEBDE, 0x42FEBEA, 0x42FEC66, 0x42FED35, 0x42FED49, 0x42FED5F, 0x42FED68, 0x42FED74, 0x42FED80, 0x42FEDE9)
SPOT_YEAR = (0x42FEA7F, 0x42FEA86, 0x42FEA8D, 0x42FEA93, 0x42FEA9C, 0x42FEAC4, 0x42FEC71, 0x42FEC7A, 0x42FEC81, 0x42FEC87, 0x42FEC91, 0x42FECBB)
ROWS_NOT_READ = (0x47F6A18, 0x47F6A40, 0x47F6A8D, 0x47F6A90, 0x47F6AB9, 0x47F6ABF, 0x47F6AC3, 0x47F6AC7, 0x47F6ACC, 0x47F6AF1)
REASONS = {}
for va in SPOT_NOT_READ:
    REASONS[va] = REASONS[va + PERP_GAP] = NOT_READ
for va in SPOT_YEAR:
    REASONS[va] = REASONS[va + PERP_GAP] = YEAR_ZERO
for va in ROWS_NOT_READ:
    REASONS[va] = REASONS[va + ROW_GAP] = NOT_READ
for va, reason in ((0x47F6964, SAME_WORD), (0x47F6972, BOUND)):
    REASONS[va] = REASONS[va + ROW_GAP] = reason
REASON_RANGES = ((0x42FEEE0, 0x42FEF19, OLD_VECTOR), (0x42FEEE0 + PERP_GAP, 0x42FEF19 + PERP_GAP, OLD_VECTOR), (0x42FEF5D, 0x42FF001, UNWIND), (0x42FEF5D + PERP_GAP, 0x42FF001 + PERP_GAP, UNWIND),
                 (0x47F6BB0, 0x47F6BBA, ALLOC_FAILS), (0x47F6BB0 + ROW_GAP, 0x47F6BBA + ROW_GAP, ALLOC_FAILS), (0x47F6BBA, 0x47F6C27, UNWIND), (0x47F6BBA + ROW_GAP, 0x47F6C27 + ROW_GAP, UNWIND))


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


def outcome_name(case, spec):
    if spec["stop"]:
        return "stop %s %s" % (spec["stop"][0], LOCATION_NAMES.get(spec["stop"][-1], ""))
    answer = spec["answer"]
    return "%s %s record" % ("perp" if case.world.perp else "spot", "trigger" if answer["isTrigger"] else "resting")


def type_rows(harness):
    """Real runs: the type a request gets for each byte pair, and the tif word test."""
    rows = []
    for perp in (False, True):
        market_name = "perp" if perp else "spot"
        for tpsl in (0, 1):
            for market in (0, 1):
                record = harness.run(WireCase("type", perp, request(tpsl=tpsl, market=market)))["answer"]
                rows.append((market_name, "+0x19=%d +0x18=%d" % (tpsl, market), record["orderType"], record["isTrigger"]))
        for word in (0, 1, 2, 3, 4, 11):
            record = harness.run(WireCase("type", perp, request(word=word)))["answer"]
            rows.append((market_name, "+0x19=2 word=%d" % word, record["orderType"], record["isTrigger"]))
    return rows


def time_rows():
    """The time rule, evaluated by the real bytes in the cases and printed here by the specification."""
    return [{"year": year, "ordinal": ordinal, "seconds": seconds, "nanos": nanos, "millis": spec_millis(date_word(year, ordinal), seconds, nanos)} for year, ordinal, seconds, nanos in ((1970, 1, 0, 0), (1970, 1, 0, 1000000), (1969, 365, 86399, 999000000), (2024, 60, 3600, 123456789))]


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        name = outcome_name(case, spec_run(case))
        outcomes[name] = outcomes.get(name, 0) + 1
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    types = type_rows(harness)
    functions = []
    helpers = ((SPOT_RESTING, "spot resting builder, helper"), (PERP_RESTING, "perp resting builder, helper"), (SPOT_TRIGGER, "spot trigger builder, helper"), (PERP_TRIGGER, "perp trigger builder, helper"))
    for start, role in GROUPS + helpers:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    site_rows = []
    direct = direct_sites(image, (SPOT_REQUEST, PERP_REQUEST, SPOT_ROWS, PERP_ROWS))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    twins = [twin_rows(image, SPOT_REQUEST, PERP_REQUEST), twin_rows(image, SPOT_ROWS, PERP_ROWS)]
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "twins": twins,
        "fields": FIELDS,
        "time_examples": time_rows(),
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_types": types,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    types = evidence.pop("_types")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["market\trequest\torderType\tisTrigger"]
    lines += ["%s\t%s\t%s\t%d" % row_ for row_ in types]
    files["order_types.tsv"] = "\n".join(lines) + "\n"
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
