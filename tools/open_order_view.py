#!/usr/bin/env python3
"""Pin the node #94 open order view record from ELF bytes: resting and trigger builders, spot and perp, children.

Four builders turn a book order into one 0xa8 byte record whose 16 fields are named by the JSON writer `0x2a2c240`:
`0x42fbcb0` and `0x42fc2f0` for a resting slab order, `0x4302380` and `0x43029d0` for a trigger tree order, spot and
perp each. Two lookups `0x4338ec0` and `0x43391a0` find a child id in the trigger tree of a user, then in the slab,
and two collectors `0x487b000` and `0x4870250` gather the children. The real bytes run in a Python evaluator, with
the real outcome map walk and order type text. A separately written specification predicts every field, allocation
and stop, and every condition, immediate and field offset is flipped to show the run can tell. No objdump or readelf
output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
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


def scale_cases():
    rows = []
    for perp in (False, True):
        name = "perp" if perp else "spot"
        for builder, shape in ((resting_case, "resting"), (trigger_case, "trigger")):
            for px in (0, 1, 999, 1234567, 2 ** 53 + 1, 2 ** 63, MASK[8]):
                rows.append(builder("%s %s px %d" % (name, shape, px), perp, {"px": px}))
            for sz in (0, 1, 777, 2 ** 53 + 1, 2 ** 63 + 5, MASK[8]):
                rows.append(builder("%s %s sz %d" % (name, shape, sz), perp, {"sz": sz}))
            for side in (0, 1):
                rows.append(builder("%s %s side %d" % (name, shape, side), perp, {"side": side}))
            for reduce in (0, 1):
                rows.append(builder("%s %s reduce %d" % (name, shape, reduce), perp, {"reduce": reduce}))
            for kind in range(10):
                rows.append(builder("%s %s kind %d" % (name, shape, kind), perp, {"kind": kind}))
            rows.append(builder("%s %s cloid" % (name, shape), perp, {"cloid": bytes(range(0xA0, 0xB1))}))
            rows.append(builder("%s %s time" % (name, shape), perp, {"time": 0x0123456789ABCDEF}))
        for orig in (0, 1, 5555, MASK[8]):
            rows.append(resting_case("%s resting orig %d" % (name, orig), perp, {"orig": orig}))
        for tpsl in (0, 1):
            rows.append(resting_case("%s resting tpsl %d" % (name, tpsl), perp, {"tpsl": tpsl}))
        for tif in (0, 1, 2, 3, 4):
            rows.append(resting_case("%s resting tif %d" % (name, tif), perp, {"tif": tif}))
        for oid in (1, 0x8000000000000001):
            order = {"oid": 0xABC + oid}
            rows.append(resting_case("%s resting stored oid %d" % (name, oid), perp, order))
        for has in (0, 1):
            for sz in (0, 900):
                rows.append(trigger_case("%s trigger has %d sz %d" % (name, has, sz), perp, {"has": has, "sz": sz}))
        rows.append(trigger_case("%s trigger has high bits" % name, perp, {"has": 0x1100000000, "sz": 900}) if False else trigger_case("%s trigger has one again" % name, perp, {"has": 1, "sz": 901}))
        for side in (0, 1):
            for flag in (0, 1):
                rows.append(trigger_case("%s trigger side %d flag %d" % (name, side, flag), perp, {"side": side, "flag": flag}))
        for trigger in (0, 1, 1000000, 3000000000, 2 ** 63 + 9, MASK[8]):
            rows.append(trigger_case("%s trigger price %d" % (name, trigger), perp, {"trigger": trigger}))
    return rows


def spot_cases():
    rows = []
    for size_decimals, wei in ((0, 0), (0, 8), (2, 8), (5, 5), (8, 18), (3, 28), (0, 25), (0, 255), (255, 255), (1, 0), (6, 5), (255, 0)):
        tokens = {0: (9, wei), 1: (size_decimals, 9)}
        for builder, shape in ((resting_case, "resting"), (trigger_case, "trigger")):
            rows.append(builder("spot %s decimals %d %d" % (shape, size_decimals, wei), False, tokens=tokens, row_count=2))
    tokens = {0: (1, 2), 1: (2, 3)}
    for builder, shape in ((resting_case, "resting"), (trigger_case, "trigger")):
        rows.append(builder("spot %s own wei is not read" % shape, False, tokens={0: (0, 7), 1: (3, 1)}, row_count=2))
        for index in (0, 1, 2, 99999999, 100000000, 100000007, 2 ** 40):
            rows.append(builder("spot %s index %d" % (shape, index), False, asset=index, list_len=index + 1))
        rows.append(builder("spot %s list end" % shape, False, asset=4, list_len=4))
        rows.append(builder("spot %s list end by one" % shape, False, asset=4, list_len=5))
        rows.append(builder("spot %s past list" % shape, False, asset=40, list_len=4))
        for base, quote, count in ((5, 0, 5), (1, 5, 5), (4, 0, 5), (0, 4, 5), (5, 5, 5), (3, 1, 3), (1, 3, 3)):
            rows.append(builder("spot %s rows %d %d of %d" % (shape, base, quote, count), False, spot=(base, quote), row_count=count))
            rows.append(builder("spot %s rows %d %d of %d no size" % (shape, base, quote, count), False, {"sz": 0, "orig": 0}, spot=(base, quote), row_count=count))
        rows.append(builder("spot %s rows zero size only" % shape, False, {"sz": 0}, spot=(1, 0), row_count=5))
        for identity, tag, label in ((3, 0, "first"), (3, 1, "second")):
            token = (7, 9)[tag]
            rows.append(builder("spot %s outcome %s" % (shape, label), False, spot=(token, 0), tokens={0: (0, 6), token: (2, 2)}, row_count=token + 1))
        for identity, tag in ((0, 0), (0, 1), (1, 1), (0x1999999999999999, 0), (0x1999999999999999, 1), (0x1999999999999999 - 1, 1), (0x199999998E86AC00, 1), (0x1999999999999FFF, 1), (2 ** 61, 0), (2 ** 63, 1)):
            token = 4
            pair = (token, 2) if tag == 0 else (2, token)
            rows.append(builder("spot %s outcome id %d %d" % (shape, identity, tag), False, spot=(token, 0), map_b={token: identity, 300: 1}, map_c={identity: pair, identity ^ 5: (1, 2)}))
        rows.append(builder("spot %s outcome no match" % shape, False, spot=(4, 0), map_b={4: 3}, map_c={3: (7, 9)}))
        rows.append(builder("spot %s outcome id not stored" % shape, False, spot=(4, 0), map_b={4: 6}, map_c={3: (7, 9)}))
        rows.append(builder("spot %s outcome empty first" % shape, False, spot=(4, 0), map_b={4: 3}, map_c={3: (4, 9)}, empty_b=True))
        rows.append(builder("spot %s outcome empty second" % shape, False, spot=(4, 0), map_b={4: 3}, map_c={3: (4, 9)}, empty_c=True))
        rows.append(builder("spot %s outcome at index 0" % shape, False, spot=(4, 0), asset=0, map_b={4: 3}, map_c={3: (4, 9)}))
        rows.append(builder("spot %s outcome no decoys" % shape, False, spot=(4, 0), map_b={4: 3}, map_c={3: (4, 9)}, decoys=0, tombs=0))
        rows.append(builder("spot %s outcome many decoys" % shape, False, spot=(4, 0), map_b={4: 3}, map_c={3: (4, 9)}, decoys=6, tombs=0))
        rows.append(builder("spot %s outcome three decoys" % shape, False, spot=(4, 0), map_b={4: 3}, map_c={3: (4, 9)}, decoys=3, tombs=0))
        for base in (1, 2, 3, 4):
            rows.append(builder("spot %s outcome crowded maps %d" % (shape, base), False, spot=(base, 0), tokens={0: (0, 6), 1: (1, 2), 2: (1, 2), 3: (1, 2), 4: (1, 2)}, map_b={word: word for word in range(1, 32)}, map_c={word: (word, word + 100) for word in range(1, 32)}, decoys=0, tombs=0))
        for base in (40, 41, 42, 43):
            crowded = {0: (0, 6), base: (1, 2)}
            rows.append(builder("spot %s absent from a crowded map %d" % (shape, base), False, spot=(base, 0), tokens=crowded, row_count=45, map_b={word: word for word in range(1, 32)}, map_c={word: (word, word + 100) for word in range(1, 32)}, decoys=0, tombs=0))
            rows.append(builder("spot %s id absent from a crowded map %d" % (shape, base), False, spot=(base, 0), tokens=crowded, row_count=45, map_b={base: base + 20}, map_c={word: (word, word + 100) for word in range(1, 32)}, decoys=0, tombs=0))
        rows.append(builder("spot %s outcome full maps" % shape, False, spot=(4, 0), map_b={word: word % 5 for word in range(1, 12)}, map_c={word: (word + 1, word + 2) for word in range(0, 5)}, buckets=16))
    return rows


def perp_cases():
    rows = []
    for builder, shape in ((resting_case, "resting"), (trigger_case, "trigger")):
        for index in range(6):
            rows.append(builder("perp %s row %d" % (shape, index), True, asset=index))
        rows.append(builder("perp %s past list" % shape, True, asset=6))
        rows.append(builder("perp %s last by count" % shape, True, asset=1, perp_len=2))
        rows.append(builder("perp %s past by count" % shape, True, asset=2, perp_len=2))
        rows.append(builder("perp %s dex 1" % shape, True, asset=10003, dex=1))
        rows.append(builder("perp %s dex 7 end" % shape, True, asset=70001, dex=7))
        rows.append(builder("perp %s other dex" % shape, True, asset=10001, dex=0))
        rows.append(builder("perp %s other dex low" % shape, True, asset=2, dex=1))
        rows.append(builder("perp %s rem past list" % shape, True, asset=19999, dex=1))
        rows.append(builder("perp %s other dex no size" % shape, True, {"sz": 0, "orig": 0}, asset=10001, dex=0))
        rows.append(builder("perp %s past list no size" % shape, True, {"sz": 0, "orig": 0}, asset=6))
        for dex in (1, 2, 3, 7, 100, 10 ** 6):
            rows.append(builder("perp %s first row of dex %d" % (shape, dex), True, asset=dex * ASSET_DIVISOR, dex=dex))
            rows.append(builder("perp %s first row of dex %d no size" % (shape, dex), True, {"sz": 0, "orig": 0, "has": 0} if builder is trigger_case else {"sz": 0, "orig": 0}, asset=dex * ASSET_DIVISOR + 1, dex=dex))
        rows.append(builder("perp %s last row of a dex" % shape, True, asset=2 * ASSET_DIVISOR - 1, dex=1, perp_len=ASSET_DIVISOR, perps=[("BTC", 3)] * 2) if False else builder("perp %s row 2 of dex 3" % shape, True, asset=30002, dex=3))
        for size_decimals in range(0, 9):
            rows.append(builder("perp %s decimals %d" % (shape, size_decimals), True, perps=[("BTC", size_decimals), ("ETH", size_decimals)], perp_len=2))
        rows.append(builder("perp %s decimals 255" % shape, True, perps=[("BTC", 255), ("ETH", 255)], perp_len=2))
        rows.append(builder("perp %s decimals 7 no size" % shape, True, {"sz": 0, "orig": 0}, perps=[("BTC", 7), ("ETH", 7)], perp_len=2))
    return rows


def lookup_cases():
    rows = []
    for perp in (False, True):
        name = "perp" if perp else "spot"
        users = {user: {TOP_OID: trigger_order()} for user in (USER_A, USER_B, USER_C, USER_D, USER_E, USER_F, USER_G)}
        rows.append(Case("%s nothing anywhere" % name, world=World(perp)))
        rows.append(Case("%s user absent no slab" % name, world=World(perp, triggers={USER_B: {TOP_OID: trigger_order()}})))
        rows.append(Case("%s user absent, in slab" % name, world=World(perp, triggers={USER_B: {TOP_OID: trigger_order()}}, resting={TOP_OID: (2, resting_order())})))
        rows.append(Case("%s oid absent, in slab" % name, world=World(perp, triggers={USER_A: {5: trigger_order()}}, resting={TOP_OID: (2, resting_order())})))
        rows.append(Case("%s oid absent, not in slab" % name, world=World(perp, triggers={USER_A: {5: trigger_order()}})))
        rows.append(Case("%s user has empty tree" % name, world=World(perp, triggers={USER_A: {}}, resting={TOP_OID: (2, resting_order())})))
        rows.append(Case("%s trigger wins over slab" % name, world=World(perp, triggers={USER_A: {TOP_OID: trigger_order()}}, resting={TOP_OID: (2, resting_order())})))
        rows.append(Case("%s no user ever" % name, world=World(perp, resting={TOP_OID: (2, resting_order())})))
        rows.append(Case("%s free slot" % name, world=World(perp, resting={TOP_OID: (2, resting_order(tag=2))})))
        rows.append(Case("%s tag 1 slot" % name, world=World(perp, resting={TOP_OID: (2, resting_order(tag=1))})))
        rows.append(Case("%s tag 3 slot" % name, world=World(perp, resting={TOP_OID: (2, resting_order(tag=3))})))
        rows.append(Case("%s slab index at the end" % name, world=World(perp, slab_len=8, resting={TOP_OID: (8, resting_order())})))
        rows.append(Case("%s slab last row" % name, world=World(perp, slab_len=8, resting={TOP_OID: (7, resting_order())})))
        rows.append(Case("%s slab first row" % name, world=World(perp, slab_len=8, resting={TOP_OID: (0, resting_order())})))
        rows.append(Case("%s item count zero" % name, world=World(perp, empty_book=True, resting={TOP_OID: (2, resting_order())})))
        rows.append(Case("%s table no decoys" % name, world=World(perp, decoys=0, tombs=0, resting={TOP_OID: (2, resting_order())})))
        many = {oid: (oid - 0x7770, resting_order(oid=oid)) for oid in range(0x7770, 0x7780)}
        rows.append(Case("%s crowded table" % name, world=World(perp, buckets=32, decoys=0, tombs=0, slab_len=16, resting=many), oid=0x7773))
        for oid in (0x7770, 0x777F, 0x7790):
            rows.append(Case("%s crowded table %d" % (name, oid), world=World(perp, buckets=32, slab_len=16, resting=many), oid=oid))
        for oid in (0x123456789ABCDEF0, 0xFEDCBA9876543211, 2 ** 40 + 3, 2 ** 63):
            rows.append(Case("%s large oid %d" % (name, oid), world=World(perp, decoys=0, tombs=0, resting={oid: (2, resting_order(oid=oid))}), oid=oid))
            rows.append(Case("%s large oid absent %d" % (name, oid), world=World(perp, decoys=0, tombs=0, resting={oid ^ 1: (2, resting_order(oid=oid))}), oid=oid))
            rows.append(Case("%s large trigger oid %d" % (name, oid), world=World(perp, triggers={USER_A: {oid: trigger_order()}}), oid=oid))
        full = {0x7000 + oid: (oid, resting_order(oid=0x7000 + oid)) for oid in range(31)}
        for oid in range(0x7000, 0x7008):
            rows.append(Case("%s full table %d" % (name, oid), world=World(perp, buckets=32, decoys=0, tombs=0, slab_len=32, resting=full), oid=oid))
        rows.append(Case("%s full table absent" % name, world=World(perp, buckets=32, decoys=0, tombs=0, slab_len=32, resting=full), oid=0x9000))
        rows.append(Case("%s many decoys" % name, world=World(perp, decoys=6, tombs=0, resting={TOP_OID: (2, resting_order())})))
        rows.append(Case("%s three decoys" % name, world=World(perp, decoys=3, tombs=0, resting={TOP_OID: (2, resting_order())})))
        for index, user in enumerate((USER_A, USER_B, USER_C, USER_D, USER_E, USER_F, USER_G)):
            rows.append(Case("%s two level users, user %d" % (name, index), world=World(perp, triggers=users, user_height=1), user=user))
        rows.append(Case("%s one level, user beyond keys" % name, world=World(perp, triggers={USER_A: {TOP_OID: trigger_order()}, USER_B: {TOP_OID: trigger_order()}}), user=USER_G))
        rows.append(Case("%s one level, user below keys" % name, world=World(perp, triggers={USER_B: {TOP_OID: trigger_order()}, USER_C: {TOP_OID: trigger_order()}}), user=USER_A))
        rows.append(Case("%s two level, user between" % name, world=World(perp, triggers={user: {TOP_OID: trigger_order()} for user in (USER_A, USER_C, USER_D, USER_E, USER_F, USER_G, bytes(20))}, user_height=1), user=USER_B))
        rows.append(Case("%s two level, user beyond" % name, world=World(perp, triggers={user: {TOP_OID: trigger_order()} for user in (USER_A, USER_B, USER_C, USER_D, USER_E, USER_F, bytes(20))}, user_height=1), user=USER_G))
        for wanted in (1, 3, 5, 6, 7, 8, 11, 13, 20, 40):
            orders = {oid: trigger_order(trigger=1000 + oid * 7, sz=oid + 3) for oid in (1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21)}
            rows.append(Case("%s two level orders, oid %d" % (name, wanted), world=World(perp, triggers={USER_A: orders}, order_height=1), oid=wanted))
            rows.append(Case("%s one level orders, oid %d" % (name, wanted), world=World(perp, triggers={USER_A: {oid: order for oid, order in orders.items() if oid < 15}}), oid=wanted))
    for index in range(10):
        rows.append(Case("order type text %d" % index, kind="order_text", oid=index))
    return rows


def children_cases():
    rows = []
    for perp in (False, True):
        name = "perp" if perp else "spot"
        for count in (1, 2, 3, 4, 5, 8, 9):
            ids = tuple(range(0x100, 0x100 + count))
            resting = {oid: (index + 3, resting_order(oid=oid, sz=oid + 1)) for index, oid in enumerate(ids)}
            rows.append(resting_case("%s %d resting kids" % (name, count), perp, {"children": ids}, extra=resting, slab_len=16))
            triggers = {oid: trigger_order(sz=oid + 1) for oid in ids}
            rows.append(trigger_case("%s %d trigger kids" % (name, count), perp, {"children": ids}, extra=triggers))
        ids = (0x200, 0x201, 0x202, 0x203)
        resting = {0x201: (1, resting_order(oid=0x201)), 0x203: (3, resting_order(oid=0x203))}
        rows.append(resting_case("%s missing first kid" % name, perp, {"children": ids}, extra=resting))
        rows.append(resting_case("%s all kids missing" % name, perp, {"children": ids}))
        rows.append(trigger_case("%s missing kid of a trigger" % name, perp, {"children": ids}, rest=resting))
        rows.append(trigger_case("%s only last kid" % name, perp, {"children": ids}, rest={0x203: (3, resting_order(oid=0x203))}))
        rows.append(resting_case("%s only second kid" % name, perp, {"children": ids}, extra={0x201: (1, resting_order(oid=0x201))}))
        rows.append(resting_case("%s only second and third of nine" % name, perp, {"children": tuple(range(0x300, 0x309))}, extra={0x301: (1, resting_order(oid=0x301)), 0x307: (3, resting_order(oid=0x307)), 0x308: (5, resting_order(oid=0x308))}))
        nested = {0x400: (1, resting_order(oid=0x400, children=(0x401,))), 0x401: (3, resting_order(oid=0x401, side=1))}
        rows.append(resting_case("%s nested resting" % name, perp, {"children": (0x400,)}, extra=nested))
        world = World(perp, resting={TOP_OID: (2, resting_order(user=USER_B, children=(0x500,)))}, triggers={USER_B: {0x500: trigger_order(side=1)}, USER_A: {0x500: trigger_order(side=0, trigger=5)}})
        rows.append(Case("%s resting kid uses the stored user" % name, world=world))
        world = World(perp, triggers={USER_A: {TOP_OID: trigger_order(children=(0x500,)), 0x500: trigger_order(flag=1)}, USER_B: {0x500: trigger_order(side=1)}})
        rows.append(Case("%s trigger kid uses the caller user" % name, world=world))
        world = World(perp, triggers={USER_A: {TOP_OID: trigger_order(children=(0x500,))}, USER_B: {0x500: trigger_order()}}, resting={0x500: (3, resting_order(oid=0x500))})
        rows.append(Case("%s trigger kid in the slab" % name, world=world))
    return rows


CACHE = {}


def all_cases():
    if not CACHE:
        CACHE["cases"] = scale_cases() + spot_cases() + perp_cases() + lookup_cases() + children_cases()
    return CACHE["cases"]


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


WRITER_STUBS = {0x2A033E0: "text", 0x29FA870: "side", 0x2A01350: "float", 0x29F7EF0: "u64", 0x29F95F0: "text or string", 0x2A03240: "bool", 0x29F93B0: "children", 0x2A06460: "tif", 0x2A055E0: "cloid"}
WRITER_TLS = 0x4EC15E0
WRITER_DROP = 0x2A2CA00
WRITER_END_SLOT = 0x57750F0
FIELD_OFFSETS = {"coin": 0x00, "side": 0x90, "limitPx": 0x60, "sz": 0x68, "oid": 0x70, "timestamp": 0x78, "triggerCondition": 0x18, "isTrigger": 0x91, "triggerPx": 0x80, "children": 0x30, "isPositionTpsl": 0x92, "reduceOnly": 0x93, "orderType": 0x48, "origSz": 0x88, "tif": 0xA5, "cloid": 0x94}


def read_writer(image):
    """Run the JSON writer of the record with every field writer stubbed: name, record offset and writer, in order."""
    harness = Harness(image)
    machine = harness.machine
    memory = machine.memory
    rows = []

    def field(m):
        rows.append({"name": memory.bytes_at(m.regs[RSI], m.regs[RDX]).decode("ascii"), "offset": (m.regs[RCX] - OUT) & MASK[8], "writer": m.call_target})
        m.regs[RAX] = 0

    def tls(m):
        m.regs[RAX] = ARG

    def end(m):
        pass

    for target in WRITER_STUBS:
        def hook(m, target=target):
            m.call_target = target
            field(m)
        machine.calls[target] = hook
    machine.calls[WRITER_TLS] = tls
    machine.calls[WRITER_DROP] = end
    finish = harness.relative[WRITER_END_SLOT]
    machine.slots[finish] = end
    harness.real.stubs = harness.real.stubs | frozenset(WRITER_STUBS) | {WRITER_TLS, WRITER_DROP, finish}
    memory.reset(BUMP - HEAP_BASE)
    machine.run(WRITER, {RDI: CTX, RSI: OUT})
    harness.real.stubs = frozenset()
    named = {row["name"]: row["offset"] for row in rows}
    if named != FIELD_OFFSETS:
        raise EvidenceError("writer field map differs: %s" % named)
    return [{"name": row["name"], "offset": "%#x" % row["offset"], "writer": "%#x" % row["writer"], "kind": WRITER_STUBS[row["writer"]]} for row in rows]


def read_powers(image):
    """The f64 table every scale reads: 256 rows, reached by a u8 index with no bound check."""
    values = struct.unpack_from("<%dd" % (POWERS_COUNT + 1), image.blob, image.offset(POWERS_AT))
    exact = sum(1 for index in range(POWERS_COUNT) if values[index] == float("1e%d" % index))
    near = sum(1 for index in range(POWERS_COUNT) if abs(values[index] / float("1e%d" % index) - 1) < 1e-13)
    if near != POWERS_COUNT or values[POWERS_COUNT] == float("1e%d" % POWERS_COUNT):
        raise EvidenceError("power table shape")
    first_off = next(index for index in range(POWERS_COUNT) if values[index] != float("1e%d" % index))
    return {"at": "%#x" % POWERS_AT, "rows": POWERS_COUNT, "rows_equal_to_the_nearest_double": exact, "first_row_not_nearest": first_off, "row_25_bits": "%#x" % to_bits(values[25]), "next_word_is_a_power": False}


def read_constants(image):
    blob = image.blob

    def at(va, count):
        return bytes(blob[image.offset(va):image.offset(va) + count])

    def word(va):
        return struct.unpack("<i", at(va, 4))[0]

    checks = {"char before a spot index": (at(CHAR_AT, 4), b"\x40\0\0\0"), "char before an outcome number": (at(HASH_CHAR_AT, 4), b"#\0\0\0"), "first coin": (at(PURR_AT, 9), b"PURR/USDC"),
              "above": (at(ABOVE_AT, 5), b"above"), "below": (at(BELOW_AT, 5), b"below"), "coin template": (at(TEMPLATE_COIN, 3), b"\xc0\xc0\x00"),
              "price template": (at(TEMPLATE_PRICE, 12), b"\x06Price \xc0\x01 \xc0\x00"), "float template": (at(TEMPLATE_FLOAT, 2), b"\xc0\x00"),
              "side letter: mov cl,0x42; sub cl,bpl": (at(SIDE_BYTES_AT, 4), b"\xb1\x42\x40\x28")}
    checks["side letter: mov cl,0x42; sub cl,bpl"] = (at(SIDE_BYTES_AT, 5), b"\xb1\x42\x40\x28\xe9")
    for name, (found, wanted) in sorted(checks.items()):
        if found != wanted:
            raise EvidenceError("constant bytes: %s" % name)
    arms = [ORDER_TABLE + word(ORDER_TABLE + index * 4) for index in range(10)]
    begin, end = image.exact_fde(ORDER_TEXT)
    if not all(begin <= arm < end for arm in arms):
        raise EvidenceError("order type arm outside its function")
    return {"bytes": {name: found.hex() for name, (found, _) in sorted(checks.items())}, "order_type_arms": ["%#x" % arm for arm in arms], "order_table_rows": 10, "order_table": "%#x" % ORDER_TABLE}


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


GROUPS = ((SPOT_RESTING, "spot resting builder"), (PERP_RESTING, "perp resting builder"), (SPOT_TRIGGER, "spot trigger builder"), (PERP_TRIGGER, "perp trigger builder"),
          (SPOT_LOOKUP, "spot child lookup"), (PERP_LOOKUP, "perp child lookup"), (SPOT_CHILDREN, "spot child collector"), (PERP_CHILDREN, "perp child collector"),
          (SPOT_TEXT, "spot trigger condition text"), (ORDER_TEXT, "order type text"))


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
    {"reference": "l1/book/book/impl_insert_order.rs:141", "claim": "RestingOrder lists oid, user, side, px, resting_sz, orig_sz, reduce_only, is_position_tpsl, tif, cloid, timestamp with no offsets past +0x18", "observed": "the slab order fields sit at the offsets in `fields` here", "verdict": "names agree; offsets are new"},
    {"reference": "l1/book/book/impl_insert_order.rs:77", "claim": "tif raw values 0 to 4, anything else Other", "observed": "resting records copy the slot byte +0xf5 and trigger records store the constant 5", "verdict": "5 is outside the reference list"},
    {"reference": "l1/book/book/impl_insert_order.rs:124", "claim": "order_kind is a bare u64", "observed": "0x327b890 names words 0 to 9 through table 0x581f98", "verdict": "names absent from the reference"},
    {"reference": "whole tree", "claim": "no text triggerCondition and no record with these 16 names", "observed": "builders here and the writer 0x2a2c240", "verdict": "absent from the reference"},
)
FIELDS = {
    "record_0xa8": {"named_by": "json_writer in this file", "+0x00": "coin String", "+0x18": "triggerCondition String", "+0x30": "children Vec of 0xa8 records", "+0x48": "orderType String", "+0x94": "cloid, 17 bytes"},
    "slab_order": {"stride": "0xf8", "+0x00": "dword; 2 is a free slot", "+0x58/+0x60": "child ids: pointer, count", "+0x90": "order type word", "+0x98": "second word, passed on and never read", "+0xa0": "limit price", "+0xa8": "timestamp", "+0xb0": "reduceOnly byte", "+0xb1": "cloid, 17 bytes", "+0xc2": "side byte, 0 B, 1 A", "+0xc8": "size", "+0xd0": "original size", "+0xd8": "oid", "+0xe0": "user, 20 bytes", "+0xf4": "isPositionTpsl byte", "+0xf5": "tif byte"},
    "trigger_order": {"stride": "0xb8", "+0x00/+0x08": "size option: tag, value; tag 0 is a whole position order", "+0x38/+0x40": "child ids: pointer, count", "+0x70": "order type word", "+0x78": "second word, passed on and never read", "+0x80": "limit price", "+0x88": "timestamp", "+0x90": "reduceOnly byte", "+0x91": "cloid, 17 bytes", "+0xa2": "side byte", "+0xa8": "trigger price", "+0xb1": "take profit or stop byte, compared with side"},
    "book": {"+0x08/+0x10": "slab: pointer, length", "+0x28/+0x30/+0x40": "oid table: control, mask, items; entry 0x10: oid, slot", "+0xb0": "spot index or perp asset", "+0xb8/+0xc0": "user tree: root, height"},
    "user_node": {"+0x38": "values, 0x50 each; value +0 and +8: order tree root, height", "+0x378": "keys, 0x14 each", "+0x456": "length", "+0x458": "edges"},
    "order_node": {"+0x08": "u64 keys", "+0x60": "values, 0xb8 each", "+0x84a": "length", "+0x850": "edges"},
    "spot_meta": {"+0x70/+0x78/+0x88/+0x90": "token to id map: control, mask, items, hash keys; entry 0x10", "+0xd0/+0xd8/+0xe8/+0xf0": "id to outcome map; entry 0x90: id, first token at +0x28, second token at +0x50", "+0x168/+0x170": "spot rows: pointer, length; stride 0x20; +0 base token, +8 quote token", "+0x180/+0x188": "token rows: pointer, length; stride 0xe8; +0x48 size decimals, +0x49 wei decimals"},
    "perp_meta": {"+0x08/+0x10": "asset rows: pointer, length; stride 0x30; +0x08/+0x10 name pointer and length, +0x2a size decimals", "+0x30": "dex number, compared with asset / 10000"},
}
SHUFFLE = "pshufd 0x44 with one bit changed: the four dwords of the byte pattern are all equal, so the result is the same"
SECOND_WORD = "the word goes to 0x327b890 in rdx and that function never reads rdx"
NEVER_SIX = "the number is 10 * id + tag with tag below 2, so it is never 6 mod 10, and exactly 2^64 - 10^8 is 6 mod 10"
ANY_OVERFLOW = "every number reaching this add overflows with either constant, so both saturate"
HIGH_NUMBER = "2^64 - 1 and 2^64 - 2 both land above the limit, and both print the same number"
FIRST_STORE = "the store is overwritten before use; only the allocation failure arm reads it"
CLEANUP = "written for the unwind path of a panic that follows; no case observes it"
SAME_PANIC = "both arms reach a panic at the same Location"
RECHECKED = "the same bound is tested again a few instructions later, with the same Location"
EXTRA_BYTE = "one byte more is copied into a row that is still unused"
CALLER_CHECKED = "the builder tested this index against the same word just before the call"
TAG_READ = "the builders only test the tag as below 2, and 2 and 3 are both not below 2"
ERROR_BYTE = "the error byte is not read by these builders"
NEXT_GROUP = "start of the next probe group moved by one: a key in a table this small is still found on a later group, and a shifted window sees the same empty byte"
ALLOC_FAILS = "allocation failure arm: the stub never fails"
UNWIND = "unwind landing pad: no case unwinds"
REASONS = {0x43390EF: NEXT_GROUP, 0x43390F3: NEXT_GROUP, 0x43393CF: NEXT_GROUP, 0x43393D3: NEXT_GROUP, 0x3729721: NEXT_GROUP, 0x3729725: NEXT_GROUP, 0x37297E7: NEXT_GROUP, 0x37297EB: NEXT_GROUP, 0x42FBD26: SECOND_WORD, 0x42FC386: SECOND_WORD, 0x430241A: SECOND_WORD, 0x4302A68: SECOND_WORD,
           0x42FBDC8: NEVER_SIX, 0x430248A: NEVER_SIX, 0x42FBDD1: ANY_OVERFLOW, 0x4302493: ANY_OVERFLOW, 0x42FC219: HIGH_NUMBER, 0x43028FC: HIGH_NUMBER,
           0x42FBF53: FIRST_STORE, 0x42FBF84: FIRST_STORE, 0x42FC4A6: FIRST_STORE, 0x42FC4D4: FIRST_STORE, 0x4302A81: FIRST_STORE,
           0x42FC6F1: CLEANUP, 0x42FC6F7: CLEANUP, 0x4302AFA: CLEANUP, 0x4302B0D: CLEANUP, 0x4302B06: SAME_PANIC, 0x4302B1E: SAME_PANIC, 0x4302578: RECHECKED,
           0x433908B: SHUFFLE, 0x433936B: SHUFFLE, 0x37296AE: SHUFFLE, 0x3729781: SHUFFLE, 0x487B081: EXTRA_BYTE, 0x48702D1: EXTRA_BYTE,
           0x49E7F78: CALLER_CHECKED, 0x49E7F96: CALLER_CHECKED, 0x372972B: TAG_READ, 0x37297F4: TAG_READ, 0x37297F1: ERROR_BYTE, 0x3729823: ERROR_BYTE,
           0x42FC244: ALLOC_FAILS, 0x42FC25B: ALLOC_FAILS, 0x42FC260: ALLOC_FAILS, 0x42FC71E: ALLOC_FAILS, 0x42FC72E: ALLOC_FAILS, 0x4302936: ALLOC_FAILS, 0x430293B: ALLOC_FAILS, 0x4302EF9: ALLOC_FAILS,
           0x487B1C0: ALLOC_FAILS, 0x487B1C5: ALLOC_FAILS, 0x4870410: ALLOC_FAILS, 0x4870415: ALLOC_FAILS,
           0x42FC28F: UNWIND, 0x42FC2D0: UNWIND, 0x42FC76A: UNWIND, 0x42FC770: UNWIND, 0x430296B: UNWIND, 0x430299B: UNWIND, 0x43029BF: UNWIND, 0x4302F2C: UNWIND, 0x4302F52: UNWIND}
REASON_RANGES = ((0x327BA7C, 0x327BAEC, ALLOC_FAILS),)


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


def outcome_name(case, spec):
    if case.kind == "order_text":
        return "order type text"
    if spec["stop"]:
        return "stop %s %s" % (spec["stop"][0], LOCATION_NAMES.get(spec["stop"][-1], ""))
    answer = spec["answer"]
    if answer is None:
        return "no record"
    return "%s %s record" % ("perp" if case.world.perp else "spot", "trigger" if answer["isTrigger"] else "resting")


def order_type_rows(harness):
    """Real runs: each order type word through the resting and trigger builders."""
    rows = []
    for perp in (False, True):
        for kind in range(10):
            resting = harness.run(resting_case("kind", perp, {"kind": kind}))["answer"]
            trigger = harness.run(trigger_case("kind", perp, {"kind": kind}))["answer"]
            rows.append(("perp" if perp else "spot", kind, resting["orderType"], resting["triggerCondition"], trigger["orderType"], trigger["triggerCondition"]))
    return rows


def plain(record):
    """A record as named fields, in JSON writer order, with floats as numbers."""
    row = dict(record)
    for name in ("limitPx", "sz", "triggerPx", "origSz"):
        row[name] = to_float(row[name])
    row["side"] = "B" if record["side"] == 0 else "A"
    row["children"] = [plain(child) for child in record["children"]]
    return {name: row[name] for name in FIELD_OFFSETS}


def worked_runs(harness):
    resting = resting_case("worked", False, {"px": 12345678, "sz": 1500, "orig": 2000, "children": (0x100,), "side": 1}, extra={0x100: (1, resting_order(oid=0x100, kind=9, sz=7))})
    trigger = trigger_case("worked", True, {"has": 0, "kind": 4, "trigger": 95000000000, "px": 94000000000, "side": 1, "flag": 1}, asset=1)
    outcome = trigger_case("worked", False, {"side": 0, "flag": 1}, spot=(7, 0), tokens={0: (0, 6), 7: (2, 2)}, row_count=8)
    return {"spot resting with a Twap Slice child": plain(harness.run(resting)["answer"]), "perp whole position stop": plain(harness.run(trigger)["answer"]), "outcome token trigger": plain(harness.run(outcome)["answer"])}


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
    worked = worked_runs(harness)
    types = order_type_rows(harness)
    functions = []
    for start, role in GROUPS + ((OUTCOME_ID, "outcome id of a token, helper"), (SIP_HASH, "SipHash of one u64, helper"), (SIP_WRITE, "hasher write, helper")):
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    slots = {SLOT_OUTCOME_ID: OUTCOME_ID, SLOT_ORDER_TEXT: ORDER_TEXT, SLOT_FLOAT_FMT: FLOAT_WRAP, SLOT_FLOAT_INNER: FLOAT_INNER}
    for slot, value in slots.items():
        if relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    site_rows = []
    omitted = 0
    direct = direct_sites(image, (SPOT_RESTING, PERP_RESTING, SPOT_TRIGGER, PERP_TRIGGER, SPOT_LOOKUP, PERP_LOOKUP, SPOT_CHILDREN, PERP_CHILDREN, SPOT_TEXT))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            if image.fde(va)[0] in OTHER_PACKET_HOSTS:
                omitted += 1
                continue
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for va in slot_sites(image, SLOT_ORDER_TEXT):
        if image.fde(va)[0] in OTHER_PACKET_HOSTS:
            omitted += 1
            continue
        site_rows.append((ORDER_TEXT, va, "slot %#x" % SLOT_ORDER_TEXT, image.fde(va)[0], image.fde(va)[1]))
    locations = []
    for slot, name in sorted(LOCATION_NAMES.items()):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    writer = read_writer(image)
    powers = read_powers(image)
    constants = read_constants(image)
    twins = [twin_rows(image, SPOT_LOOKUP, PERP_LOOKUP), twin_rows(image, SPOT_CHILDREN, PERP_CHILDREN)]
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "slots": {"%#x" % slot: "%#x" % value for slot, value in sorted(slots.items())},
        "json_writer": {"function": "%#x" % WRITER, "fields": writer},
        "powers": powers,
        "constants": constants,
        "twins": twins,
        "locations": locations,
        "fields": FIELDS,
        "worked_examples": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "sites_in_functions_of_open_pr_47_not_listed": omitted,
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
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["market\tkind_word\tresting_orderType\tresting_triggerCondition\ttrigger_orderType\ttrigger_triggerCondition"]
    lines += ["%s\t%d\t%s\t%s\t%s\t%s" % row_ for row_ in types]
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
