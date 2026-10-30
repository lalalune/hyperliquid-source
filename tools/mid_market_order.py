#!/usr/bin/env python3
"""Pin the node #94 mid-price market order path from ELF bytes.

`0x37052b0` turns a user's position map and a fraction into (asset, side, size) rows. `0x4cdc540`
and `0x4cdcd60` walk those rows, drop small notionals and call one of four order builders. Each
builder takes the book midpoint, moves it 3% against the taker, rounds to the tick and hands a fixed
order record to the insert path. The real bytes run in a Python evaluator with only the edges
stubbed, and a separately written specification predicts every event and every record byte. Every
condition and immediate is then flipped to show the run can tell. No objdump or readelf output is
parsed, and the binary is never executed. Standard library only.
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

BUILDERS = (0x4304010, 0x43043E0, 0x43047B0, 0x4304B80)
LOOPS = (0x4CDC540, 0x4CDCD60)
PRODUCER = 0x37052B0
BEST = 0x4A07680
ROUND = 0x565F410
TICK = 0x42C7600
INSERTS = (0x4311140, 0x4314DA0)
THIRD_LOOP = 0x26F7280
DROP_ERROR = 0x3379490
CONTEXT = 0x4DF3680
RECORD = 0x3987CB0
APPLY = 0x4CD84F0
ITERATE = 0x4948400
FINISHES = (0x432A100, 0x4329870)
FINAL_DROP = 0x4DB32E0
LOOKUP = 0x36F57F0
SLOT_PRODUCER = 0x57748C8
SLOT_ROUND = 0x576F6D8
SLOT_FREE = 0x576E010
SLOT_PANIC = 0x576E470
SLOT_UNWRAP = 0x576E048
SLOT_BOUNDS = 0x576DFC8
SLOT_INDEX = 0x576E150
SLOT_ONCE = 0x576E8B8
SLOT_GROW = 0x5775788
ONCE_STATE = 0x577AB98
FACTOR_BUY_AT = 0x20A770
FACTOR_SELL_AT = 0x20AC58
FRACTION_LIMIT_AT = 0x20A730
ERROR_WORD = 0x141
UNWRAP_MESSAGE = 0x2B
NO_PRICE = 0x800000000000000A
TAG_NONE = 1 << 63
LOCATION_OUTER = 0x56E9AF8
LOCATION_COLLECTION = 0x56E9B28
LOCATION_BUILDER = 0x56E9AE0
LOCATION_CONTEXT = 0x57444C0
LOCATION_BOOK = 0x5742338
LOCATION_LADDER = 0x56F21C0
LOCATION_DECIMALS = 0x56F3350
LOCATION_NO_PARENT = 0x5733F50
LOCATION_POSITION_PARENT = 0x56E9FE8
NOTIONAL_FLOOR = 0x98967F
NOTIONAL_CEILING = 0x7FFFFFFFFFFFFFFE
NODE_KEYS = 0x168
NODE_PARENT = 0x160
NODE_PARENT_INDEX = 0x1C0
NODE_LEN = 0x1C2
NODE_EDGES = 0x1C8
POSITION_PARENT = 0x2C0
POSITION_KEYS = 0x2C8
POSITION_PARENT_INDEX = 0x320
POSITION_LEN = 0x322
POSITION_EDGES = 0x328
POSITION_STRIDE = 0x40
POSITION_SIZE = 0x10
MARKET_STRIDE = 0x2F0
COLLECTION_STRIDE = 0x138
BOOK_STRIDE = 0xD8
CONTEXT_STRIDE = 0x60
CONTEXT_PRICE = 0x20
ROW_STRIDE = 0x18
FILL_STRIDE = 0x238
ASSET_STRIDE = 0x30
ASSET_DECIMALS = 0x2A
BOOK_ASSET = 0xB0
BOOK_FIRST_TREE = 0x80
BOOK_SECOND_TREE = 0x98
RECORD_SIZE = 0xD0

# Both field sets sit in one larger object, 0xa80 bytes apart.
FIELD_SETS = (
    {"markets": 0x1040, "market_count": 0x1048, "collections": 0x3DF0, "collection_count": 0x3DF8, "byte": 0x1372},
    {"markets": 0x5C0, "market_count": 0x5C8, "collections": 0x3370, "collection_count": 0x3378, "byte": 0x8F2},
)
# Per builder: field set, insert monomorph, value at record +0x70, value at record +0xcc,
# price factors for side byte zero and nonzero.
BUILDER_ROWS = (
    (0x4304010, 0, 0x4311140, 6, 1, (1.03, 0.97)),
    (0x43043E0, 1, 0x4314DA0, 6, 1, (1.03, 0.97)),
    (0x43047B0, 1, 0x4314DA0, 1, 4, (1.2, 0.8)),
    (0x4304B80, 0, 0x4311140, 1, 4, (1.2, 0.8)),
)
LOOP_ROWS = ((0x4CDC540, 0, 0x4304010), (0x4CDCD60, 1, 0x43043E0))

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
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 6000


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
        for marker in ("/l1/", "/library/"):
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
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}


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
        value = immediate(8 if wide else 4)
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
        if kind in (2, 3, 4, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
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
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
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
        self.step_limit = STEP_LIMIT

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
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

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
            self.stub(hook)
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
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
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
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
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
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
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



# ---- cases and specification ----

def lcg(variant):
    state = variant & MASK[8]
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK[8]
        yield state >> 16


class Tree:
    """One side tree on the leftmost path: lens and parents run root first."""

    def __init__(self, key=0, height=0, lens=None, parents=None, root=True, length=1):
        self.key, self.height = key, height
        self.lens = lens if lens is not None else [1] * (height + 1)
        self.parents = parents if parents is not None else [0] * (height + 1)
        self.root, self.length = root, length

    def key_at(self, level, index):
        if level == self.height and index == 0:
            return self.key
        value = (self.key + ((self.height - level + 1) << 34) + ((index + 1) << 29)) & MASK[8]
        return value


def absolute(key):
    return key if key < SIGN[8] else (-key) & MASK[8]


class BuilderCase:
    def __init__(self, label, first, second, side=0, size=1234, asset=3, decimals=0, markets=1, market_dex=None,
                 assets=8, date=(2024 << 13 | 100 << 4, 3600, 5000000)):
        self.label, self.first, self.second = label, first, second
        self.side, self.size, self.asset, self.decimals = side, size, asset, decimals
        self.markets = markets
        self.market_dex = asset // 10000 if market_dex is None else market_dex
        self.assets, self.date = assets, date


def spec_best(tree):
    """Returns the absolute first key, 0 for an empty tree, or None after the climb panic."""
    if not tree.root or tree.length == 0:
        return 0
    level, index = tree.height, 0
    if tree.lens[level] != 0:
        return absolute(tree.key_at(level, 0))
    while True:
        if level == 0:
            return None
        index = tree.parents[level]
        level -= 1
        if index < tree.lens[level]:
            return absolute(tree.key_at(level, index))


def spec_round(value):
    """Half away from zero, written over exact integer parts."""
    size = abs(value)
    if value != value or size >= 2.0 ** 52:
        return value
    whole = math.floor(size)
    return math.copysign(float(whole + 1) if size - whole >= 0.5 else float(whole), value)


def spec_tick(price, decimals):
    digits = len(str(price))
    return min(10 ** max(digits - 5, 0), 10 ** (6 - decimals))


def spec_millis(date):
    word, seconds, nanos = date
    signed = word - (1 << 32) if word & SIGN[4] else word
    year = (signed >> 13) - 1
    days = 0
    if year < 0:
        excess = (1 - (year + 1)) // 400 + 1
        year += excess * 400
        days -= excess * 146097
    century = year // 100
    days += ((word >> 4) & 0x1FF) + (year * 1461 >> 2) - century + (century >> 2) - 719163
    millis = (days * 86400 + seconds) * 1000 + nanos // 1000000
    return max(millis, 0)


def spec_record(copy, case, limit):
    record = bytearray([STACK_MARK]) * RECORD_SIZE
    kind, source = BUILDER_ROWS[copy][3], BUILDER_ROWS[copy][4]
    struct.pack_into("<QQQ", record, 0, 1, case.size, 0)
    struct.pack_into("<Q", record, 0x20, 0)
    struct.pack_into("<QQQQ", record, 0x30, 0, 8, 0, 0)
    struct.pack_into("<Q", record, 0x70, kind)
    struct.pack_into("<QQH", record, 0x80, limit, spec_millis(case.date), 1)
    record[0xA2] = case.side & 0xFF
    struct.pack_into("<Q", record, 0xA8, 0)
    record[0xB8:0xCC] = bytes(range(1, 21))
    record[0xCC] = source
    return bytes(record)


def spec_limit(mid, side, decimals, factors):
    """The rounded limit: the factor pair is (zero side, nonzero side)."""
    factor = factors[1] if side & 0xFF else factors[0]
    scaled = spec_round(float(mid) * factor)
    price = MASK[8] if scaled > 18446744073709549568.0 else int(scaled)
    price = max(price, 1)
    tick = spec_tick(price, decimals)
    quotient = price // tick
    if side & 0xFF:
        quotient = MASK[8] if quotient == MASK[8] else quotient + 1
    limit = quotient * tick
    if limit > MASK[8]:
        limit = MASK[8]
    return max(limit, 1)


def spec_builder(copy, case):
    dex, local = case.asset // 10000, case.asset % 10000
    if dex >= case.markets:
        return {"stop": ("unwrap", LOCATION_BUILDER, ERROR_WORD, UNWRAP_MESSAGE)}
    bid = spec_best(case.first)
    if bid is None:
        return {"stop": ("panic", LOCATION_NO_PARENT), "drops": [ERROR_WORD]}
    ask = spec_best(case.second)
    if ask is None:
        return {"stop": ("panic", LOCATION_NO_PARENT), "drops": [ERROR_WORD]}
    if bid == 0 or ask == 0:
        return {"out": (TAG_NONE, NO_PRICE), "drops": [ERROR_WORD]}
    mid = (bid & ask) + ((bid ^ ask) >> 1)
    if dex != case.market_dex or local >= case.assets:
        return {"stop": ("panic", LOCATION_LADDER), "drops": [ERROR_WORD]}
    if case.decimals >= 7:
        return {"stop": ("index", LOCATION_DECIMALS), "drops": [ERROR_WORD]}
    limit = spec_limit(mid, case.side, case.decimals, BUILDER_ROWS[copy][5])
    return {"insert": (case.asset, 0, spec_record(copy, case, limit)), "drops": [ERROR_WORD]}


def builder_cases():
    cases = []
    plain = 2500000

    def add(label, first, second, **options):
        cases.append(BuilderCase(label, first, second, **options))

    add("simple buy", Tree(plain), Tree(plain + 200), side=0)
    add("simple sell", Tree(plain), Tree(plain + 200), side=1)
    add("negative first key", Tree((-plain) & MASK[8]), Tree(plain), side=0)
    add("negative second key", Tree(plain), Tree((-plain) & MASK[8]), side=1)
    add("minimum key", Tree(SIGN[8]), Tree(SIGN[8]), side=0)
    add("minimum key sell", Tree(SIGN[8]), Tree(SIGN[8]), side=1)
    add("side high bits are ignored", Tree(plain), Tree(plain), side=0x100)
    add("side byte two", Tree(plain), Tree(plain), side=2)
    add("first root absent", Tree(root=False), Tree(plain))
    add("second root absent", Tree(plain), Tree(root=False))
    add("both roots absent", Tree(root=False), Tree(root=False))
    add("first length zero", Tree(plain, length=0), Tree(plain))
    add("second length zero", Tree(plain), Tree(plain, length=0))
    add("first key zero", Tree(0), Tree(plain))
    add("second key zero", Tree(plain), Tree(0))
    add("root zero, length set", Tree(root=False, length=5), Tree(plain))
    add("mid one buy", Tree(1), Tree(1), side=0)
    add("mid one sell", Tree(1), Tree(1), side=1)
    add("mid floors", Tree(1), Tree(2), side=0)
    add("dex past markets", Tree(plain), Tree(plain), asset=10000, markets=1)
    add("dex on the last market", Tree(plain), Tree(plain), asset=10003, markets=2)
    add("dex differs from market", Tree(plain), Tree(plain), asset=10003, markets=2, market_dex=0)
    add("empty book skips the market check", Tree(0), Tree(plain), asset=10003, markets=2, market_dex=0)
    add("local on the bound", Tree(plain), Tree(plain), asset=8, assets=8)
    add("local below the bound", Tree(plain), Tree(plain), asset=7, assets=8)
    add("decimals six", Tree(plain), Tree(plain), decimals=6)
    add("decimals seven", Tree(plain), Tree(plain), decimals=7)
    add("decimals seven on an empty book", Tree(0), Tree(plain), decimals=7)
    add("year one", Tree(plain), Tree(plain), date=(1 << 13 | 1 << 4, 0, 0))
    add("year zero", Tree(plain), Tree(plain), date=(0 << 13 | 1 << 4, 0, 0))
    add("year -400", Tree(plain), Tree(plain), date=(((-400) << 13 | 1 << 4) & MASK[4], 1, 1))
    add("year -1", Tree(plain), Tree(plain), date=(((-1) << 13 | 300 << 4) & MASK[4], 86399, 999999999))
    add("epoch day", Tree(plain), Tree(plain), date=(1970 << 13 | 1 << 4, 0, 0))
    add("epoch day one milli", Tree(plain), Tree(plain), date=(1970 << 13 | 1 << 4, 0, 1000000))
    add("before the epoch clamps", Tree(plain), Tree(plain), date=(1969 << 13 | 365 << 4, 86399, 999999999))
    add("late year", Tree(plain), Tree(plain), date=(262142 << 13 | 366 << 4, 86399, 1999999999))
    for year in (1971, 2000, 2001, 2100, 2101, 2200, 2301, 2400, 2401, 2404, 2800, 2801):
        add("year %d" % year, Tree(plain), Tree(plain), date=(year << 13 | 1 << 4, 0, 0))
    add("flags are ignored", Tree(plain), Tree(plain), date=(2024 << 13 | 100 << 4 | 7, 3, 4))
    add("tall trees", Tree(plain, height=3), Tree(plain, height=2))
    for height in (1, 2, 3, 6, 7, 8, 9, 10, 15, 16, 17):
        add("first height %d" % height, Tree(plain, height=height), Tree(plain))
        add("second height %d" % height, Tree(plain), Tree(plain, height=height))
    add("first climbs once", Tree(plain, 1, [2, 0], [0, 1]), Tree(plain))
    add("second climbs once", Tree(plain), Tree(plain, 1, [2, 0], [0, 1]))
    add("first climbs twice", Tree(plain, 2, [3, 1, 0], [0, 1, 1]), Tree(plain))
    add("second climbs twice", Tree(plain), Tree(plain, 2, [3, 1, 0], [0, 1, 1]))
    add("first climb index equals length", Tree(plain, 2, [3, 2, 0], [0, 1, 2]), Tree(plain))
    add("second climb index equals length", Tree(plain), Tree(plain, 2, [3, 2, 0], [0, 1, 2]))
    add("first climb past root", Tree(plain, 1, [1, 0], [0, 1]), Tree(plain))
    add("second climb past root", Tree(plain), Tree(plain, 1, [1, 0], [0, 1]))
    add("first climb from a lone root", Tree(plain, 0, [0], [0]), Tree(plain))
    add("second climb from a lone root", Tree(plain), Tree(plain, 0, [0], [0]))
    # Prices next to each power of ten and each power of two, buy and sell, every decimals value.
    edges = []
    for exponent in range(0, 20):
        edges.extend((10 ** exponent - 1, 10 ** exponent, 10 ** exponent + 1))
    for exponent in range(31, 64):
        edges.extend(((1 << exponent) - 1, 1 << exponent))
    edges.extend((SIGN[8] - 2048, SIGN[8] - 1, SIGN[8]))
    # A key is read through its absolute value, so 2^63 is the largest price a tree can hand over.
    for mid in edges:
        if not 0 < mid <= SIGN[8]:
            continue
        for side in (0, 1):
            add("mid %#x side %d" % (mid, side), Tree(mid), Tree(mid), side=side)
    for mid in (SIGN[8], SIGN[8] - 1, SIGN[8] - 2047, SIGN[8] - 2048, 1 << 62):
        for side in (0, 1):
            add("tick one mid %#x side %d" % (mid, side), Tree(mid), Tree(mid), side=side, decimals=6)
    # Targets the rounded price lands on, so that each ladder step is hit from both sides.
    for exponent in range(4, 20):
        for delta in (-1, 0, 1):
            target = 10 ** exponent + delta
            for side, factor in ((0, 1.03), (1, 0.97), (0, 1.2), (1, 0.8)):
                mid = int(target / factor)
                if mid >= SIGN[8]:
                    continue
                for nudge in (-1, 0, 1):
                    add("target %#x side %d factor %s nudge %d" % (target, side, factor, nudge), Tree(mid + nudge), Tree(mid + nudge), side=side)
    for decimals in range(0, 8):
        for mid in (123456, 1234567, 99999999, 123456789012):
            for side in (0, 1):
                add("decimals %d mid %d side %d" % (decimals, mid, side), Tree(mid), Tree(mid), side=side, decimals=decimals)
    numbers = lcg(0x4D49)
    for index in range(120):
        shift = next(numbers) % 56
        first = (next(numbers) >> shift) | 1
        second = (next(numbers) >> shift) | 1
        add("random %d" % index, Tree(first), Tree(second), side=next(numbers) & 1, size=next(numbers),
            decimals=next(numbers) % 7, date=(2020 + next(numbers) % 10 << 13 | (1 + next(numbers) % 360) << 4,
                                              next(numbers) % 86400, next(numbers) % 1000000000))
    return cases


def round_cases():
    values = [0.0, -0.0, 0.25, 0.3, -0.3, 0.49999999999999994, -0.49999999999999994, 0.5, -0.5, 0.75, 1.0, 1.5, 2.5, -2.5,
              1.0000000000000002, 1.4999999999999998, 1.9999999999999998, 3.0000000000000004, 1234.5, 1234.4999999999998,
              5e-324, 2.0 ** 51 + 0.5, 2.0 ** 52 - 0.5, 2.0 ** 52 - 1.0, 2.0 ** 52, 2.0 ** 52 + 2.0, 2.0 ** 53, 1e300, -1e300,
              float("inf"), float("-inf"), float("nan")]
    numbers = lcg(0x524F)
    for index in range(80):
        values.append((next(numbers) >> (next(numbers) % 40)) / 1024.0 * (1 if next(numbers) & 1 else -1))
    return values


class LoopCase:
    def __init__(self, label, rows=(), flag=0, markets=1, collections=1, books=5, prices=(5000000, 1, 1, 2, 3),
                 row_capacity=None, absent=False, once=0, outcomes=()):
        self.label, self.rows, self.flag = label, list(rows), flag
        self.markets, self.collections, self.books = markets, collections, books
        self.prices, self.absent, self.once = list(prices), absent, once
        self.row_capacity = len(self.rows) if row_capacity is None else row_capacity
        self.outcomes = list(outcomes)


class Outcome:
    """What a stubbed builder writes: an error word pair, or two vectors and a map."""

    def __init__(self, error=None, error_pointer=0x70000, fills=(0, 0x71000, 0), root=0, height=0, count=0,
                 entries=(), pushed=None):
        self.error, self.error_pointer = error, error_pointer
        self.fills, self.root, self.height, self.count = fills, root, height, count
        self.entries, self.pushed = list(entries), pushed


OK = Outcome()


def loop_cases():
    big = 3
    cases = [
        LoopCase("no markets", [(0, 0, 1)], markets=0),
        LoopCase("no rows", []),
        LoopCase("no rows, capacity left", [], row_capacity=4),
        LoopCase("producer has no answer", absent=True),
        LoopCase("producer has no answer, once armed", absent=True, once=3),
        LoopCase("one row above the floor", [(0, 1, big)], outcomes=[OK]),
        LoopCase("record branch", [(0, 1, big)], flag=1, outcomes=[OK]),
        LoopCase("flag two takes the zero branch", [(0, 1, big)], flag=2, outcomes=[OK]),
        LoopCase("flag high word", [(0, 1, big)], flag=0x100000001, outcomes=[OK]),
        LoopCase("no rows with the record branch", [], flag=1),
        LoopCase("at the floor", [(1, 0, 9999999)]),
        LoopCase("one above the floor", [(1, 0, 10000000)], outcomes=[OK]),
        LoopCase("one below the floor", [(1, 0, 9999998)]),
        LoopCase("floor by product", [(0, 0, 1)], prices=(9999999,)),
        LoopCase("over the floor by product", [(0, 0, 2)], prices=(5000000,), outcomes=[OK]),
        LoopCase("zero size skips", [(0, 0, 0)]),
        LoopCase("floor with once armed", [(1, 0, 9999999)], once=3),
        LoopCase("floor then large", [(1, 0, 1), (0, 1, big)], outcomes=[OK]),
        LoopCase("large then floor", [(0, 1, big), (1, 0, 1)], outcomes=[OK]),
        LoopCase("once armed on the large path", [(0, 1, big)], once=3, outcomes=[OK]),
        LoopCase("low word at the ceiling", [(0, 0, NOTIONAL_CEILING)], prices=(1,), outcomes=[OK]),
        LoopCase("low word over the ceiling", [(0, 0, NOTIONAL_CEILING + 1)], prices=(1,), outcomes=[OK]),
        LoopCase("low word at the sign bit", [(0, 0, 1 << 63)], prices=(1,), outcomes=[OK]),
        LoopCase("overflow with a tiny low word", [(0, 0, 1 << 62)], prices=(4,), outcomes=[OK]),
        LoopCase("overflow low word one", [(0, 0, (1 << 64) - 1)], prices=(MASK[8],), outcomes=[OK]),
        LoopCase("tag two stops", [(0, 2, big), (0, 1, big)]),
        LoopCase("tag two after a row", [(0, 1, big), (0, 2, big), (0, 1, big)], outcomes=[OK]),
        LoopCase("tag three is a side", [(0, 3, big)], outcomes=[OK]),
        LoopCase("two rows", [(0, 1, big), (1, 0, 10)], prices=(5000000, 5000000), outcomes=[OK, OK]),
        LoopCase("local at the context bound", [(5, 0, 1)]),
        LoopCase("local below the context bound", [(4, 0, 1)], prices=(0, 0, 0, 0, 20000000), books=5, outcomes=[OK]),
        LoopCase("context bound wins over the dex", [(10005, 0, 1)]),
        LoopCase("dex at the collection bound", [(10000, 0, 1)], prices=(20000000,)),
        LoopCase("dex below the collection bound", [(10000, 0, 1)], prices=(20000000,), collections=2, markets=2, outcomes=[OK]),
        LoopCase("dex past the markets", [(10000, 0, 1)], prices=(20000000,), collections=2, markets=1, outcomes=[OK]),
        LoopCase("floor row leaves a far dex alone", [(10000, 0, 1)], prices=(1,)),
        LoopCase("book at the bound", [(2, 0, 1)], books=2, prices=(0, 0, 20000000)),
        LoopCase("book below the bound", [(1, 0, 1)], books=2, prices=(0, 20000000), outcomes=[OK]),
        LoopCase("builder error, code word", [(0, 1, big)], outcomes=[Outcome(error=NO_PRICE)]),
        LoopCase("builder error, zero", [(0, 1, big)], outcomes=[Outcome(error=0)]),
        LoopCase("builder error, one byte string", [(0, 1, big)], outcomes=[Outcome(error=1)]),
        LoopCase("builder error, string", [(0, 1, big)], outcomes=[Outcome(error=64)]),
        LoopCase("builder error, sign bit", [(0, 1, big)], outcomes=[Outcome(error=SIGN[8])]),
        LoopCase("builder error, last positive", [(0, 1, big)], outcomes=[Outcome(error=SIGN[8] - 1)]),
        LoopCase("error then success", [(0, 1, big), (0, 0, big)], outcomes=[Outcome(error=9), OK]),
        LoopCase("fills without capacity", [(0, 1, big)], outcomes=[Outcome(fills=(0, 0x71000, 0))]),
        LoopCase("fills with capacity", [(0, 1, big)], outcomes=[Outcome(fills=(3, 0x71000, 2))]),
        LoopCase("map root, no entries", [(0, 1, big)], outcomes=[Outcome(root=0x72000, height=1, count=0)]),
        LoopCase("map with empty entry", [(0, 1, big)], outcomes=[Outcome(root=0x72000, height=2, count=1, entries=[(0, 0x73000)])]),
        LoopCase("map with entries", [(0, 1, big)],
                 outcomes=[Outcome(root=0x72000, height=0, count=3, entries=[(2, 0x73000), (0, 0x73100), (5, 0x73200)])]),
        LoopCase("builder pushes into the vector", [(0, 1, big)], outcomes=[Outcome(pushed=(4, 0x74000, 1))]),
        LoopCase("error with a pushed vector", [(0, 1, big)], outcomes=[Outcome(error=0, pushed=(1, 0x74000, 1))]),
    ]
    numbers = lcg(0x4C4F)
    for index in range(30):
        rows = []
        for _ in range(next(numbers) % 4 + 1):
            rows.append((next(numbers) % 5, next(numbers) % 2, next(numbers) % 6000000))
        outcomes = [Outcome(error=(None if next(numbers) & 1 else 16), fills=(next(numbers) % 3, 0x71000, 1)) for _ in rows]
        cases.append(LoopCase("random %d" % index, rows, flag=next(numbers) & 1, once=3 * (next(numbers) & 1), outcomes=outcomes))
    return cases


def spec_loop(copy, case):
    events = []
    if case.markets == 0:
        return {"events": events, "stop": ("unwrap", LOCATION_OUTER, ERROR_WORD, UNWRAP_MESSAGE)}
    events.append(("drop", ERROR_WORD))
    events.append(("producer", MARKETS, tuple(range(1, 21)), FRACTION_BITS))
    if case.absent:
        return {"events": events}
    if case.once:
        events.append(("once", 1))
    events.append(("context", MARKETS + 0x60))
    if case.flag & MASK[4] == 1:
        events.append(("record", 0x7B, 0xBB, 0xAA, 0))
    outcomes = iter(case.outcomes)
    for asset, tag, size in case.rows:
        if tag == 2:
            break
        dex, local = asset // 10000, asset % 10000
        if local >= len(case.prices):
            return {"events": events, "stop": ("bounds", local, len(case.prices), LOCATION_CONTEXT)}
        product = size * case.prices[local]
        low = product & MASK[8]
        if not product >> 64 and low <= NOTIONAL_CEILING:
            events.append(("drop", ERROR_WORD))
            if low <= NOTIONAL_FLOOR:
                if case.once:
                    events.append(("once", 1))
                continue
        if dex >= case.collections:
            return {"events": events, "stop": ("unwrap", LOCATION_COLLECTION, ERROR_WORD, UNWRAP_MESSAGE)}
        events.append(("drop", ERROR_WORD))
        if local >= case.books:
            return {"events": events, "stop": ("panic", LOCATION_BOOK)}
        book = BOOKS + dex * 0x10000 + local * BOOK_STRIDE
        out = next(outcomes, OK)
        events.append(("builder", book, USER, tag, size, LARGER, 0xD0, 0x98, (0, 8, 0)))
        if dex >= case.markets:
            return {"events": events, "stop": ("unwrap", LOCATION_OUTER, ERROR_WORD, UNWRAP_MESSAGE)}
        events.append(("drop", ERROR_WORD))
        if out.error is not None:
            if 0 < out.error < SIGN[8]:
                events.append(("free", out.error_pointer, out.error, 0))
        else:
            capacity, pointer, length = out.fills
            events.append(("apply", MARKETS + dex * MARKET_STRIDE, pointer, length,
                           (1,) + tuple(0x30 + index for index in range(32)) if case.flag & MASK[4] == 1 else (1,) + (0,) * 32,
                           0, 0, 0x98))
            if capacity:
                events.append(("free", pointer, capacity * FILL_STRIDE, 0))
            view = (1, 1, out.count, 0, out.root, out.height, 0, out.root, out.height) if out.root else (0, 0, 0)
            events.append(("iterate", view))
            for capacity, pointer in out.entries:
                if capacity:
                    events.append(("free", pointer, capacity * 8, 0))
                events.append(("iterate", view))
        pushed = out.pushed or (0, 8, 0)
        events.append(("finish", pushed, dex, LARGER))
    if case.row_capacity:
        events.append(("free", ROWS, case.row_capacity * ROW_STRIDE, 0))
    events.append(("final", 0x158))
    return {"events": events}


class PositionCase:
    def __init__(self, label, keys=None, sizes=(), fraction=0.5, root=True, length=None):
        self.label, self.keys, self.fraction = label, keys or [], fraction
        self.sizes = list(sizes)[:capacity(self.keys)]
        self.root = root
        self.length = len(self.sizes) if length is None else length


def capacity(keys):
    """Entries a tree of these level widths holds when every node is full."""
    total = 0
    for width in reversed(keys):
        total = width + (width + 1) * total
    return total


def spec_positions(case):
    fraction = case.fraction
    if fraction == fraction and (fraction <= 0.0 or fraction >= 1.0):
        return {"none": True}
    rows = []
    entries = case.sizes[:case.length] if case.root else []
    if case.length > len(case.sizes) and case.root and case.sizes:
        return {"stop": ("panic", LOCATION_POSITION_PARENT)}
    for asset, size in entries:
        value = float(size - (1 << 64) if size & SIGN[8] else size) * fraction
        whole = 0 if value != value else int(value)
        if whole:
            rows.append((asset, 1 if whole > 0 else 0, abs(whole)))
    return {"rows": rows} if rows else {"rows": rows, "vector": (0, 8)}


def signed(value):
    return value & MASK[8]


def position_cases():
    half = [(index * 3, signed(1000 + index * 7)) for index in range(40)]
    cases = [
        PositionCase("empty root", root=False),
        PositionCase("zero length", [3], [(1, 100)], length=0),
        PositionCase("one long", [3], [(7, 100)]),
        PositionCase("one short", [3], [(7, signed(-100))]),
        PositionCase("truncates toward zero", [3], [(7, 101), (8, signed(-101))]),
        PositionCase("drops a size under one", [3], [(7, 1), (8, signed(-1)), (9, 2)]),
        PositionCase("drops a zero size", [3], [(7, 0), (8, 5)]),
        PositionCase("fraction just above zero", [3], [(7, 1 << 62)], fraction=5e-324),
        PositionCase("fraction zero", [3], [(7, 100)], fraction=0.0),
        PositionCase("fraction negative zero", [3], [(7, 100)], fraction=-0.0),
        PositionCase("fraction negative", [3], [(7, 100)], fraction=-0.5),
        PositionCase("fraction one", [3], [(7, 100)], fraction=1.0),
        PositionCase("fraction above one", [3], [(7, 100)], fraction=2.5),
        PositionCase("fraction under one", [3], [(7, 1 << 53)], fraction=1.0 - 2.0 ** -53),
        PositionCase("fraction NaN", [3], [(7, 100)], fraction=float("nan")),
        PositionCase("largest long", [3], [(7, (1 << 63) - 1)], fraction=1.0 - 2.0 ** -53),
        PositionCase("smallest short", [3], [(7, 1 << 63)], fraction=1.0 - 2.0 ** -53),
        PositionCase("two levels", [2, 3], half[:11]),
        PositionCase("two levels, two keys", [2, 3], half[:14]),
        PositionCase("three levels", [1, 2, 3], half[:16]),
        PositionCase("three levels, wider", [2, 1, 2], half[:29]),
        PositionCase("length stops early", [2, 3], half[:11], length=5),
        PositionCase("length past the entries", [3], half[:3], length=4),
    ]
    for height in (3, 6, 7, 8, 9, 10, 15, 16, 17):
        cases.append(PositionCase("chain %d" % height, [1] + [0] * (height - 1) + [2], half[:6]))
        cases.append(PositionCase("chain with keys %d" % height, [0] * height + [2], half[:3]))
    numbers = lcg(0x504F)
    for index in range(16):
        sizes = [(next(numbers) % 100000, signed((next(numbers) >> 8) - (1 << 47))) for _ in range(7)]
        cases.append(PositionCase("random %d" % index, [2, 3], sizes, fraction=(next(numbers) % 999 + 1) / 1000.0))
    return cases


# ---- harness ----

USER = HEAP_BASE + 0x100
OUT = HEAP_BASE + 0x200
VECTOR = HEAP_BASE + 0x300
BOOK = HEAP_BASE + 0x400
LARGER = HEAP_BASE + 0x800
MARKETS = 0x640000000
ROWS = HEAP_BASE + 0x6000
PRICES = HEAP_BASE + 0x7000
COLLECTIONS = HEAP_BASE + 0x9000
BOOKS = 0x650000000
ITERATOR_NODE = HEAP_BASE + 0xB000
ASSET_TABLE = HEAP_BASE + 0xC000
MARKET_ROW = HEAP_BASE + 0xD000
RECORD_BYTES = bytes(0x30 + index for index in range(32))
FRACTION_BITS = to_bits(0.25)
LOOKUP_RESULT = HEAP_BASE + 0xE000
NODES = HEAP_BASE + 0x10000
GROWN = HEAP_BASE + 0x20000
CONTEXT_CAPACITY = 9


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        for slot in (SLOT_PRODUCER, SLOT_ROUND, SLOT_FREE, SLOT_PANIC, SLOT_UNWRAP, SLOT_BOUNDS, SLOT_INDEX, SLOT_ONCE, SLOT_GROW):
            machine.memory.statics[slot] = relative[slot]
        machine.memory.statics[ONCE_STATE] = 0
        machine.slots = {relative[SLOT_FREE]: self.on_free, relative[SLOT_PANIC]: self.on_panic,
                         relative[SLOT_UNWRAP]: self.on_unwrap, relative[SLOT_BOUNDS]: self.on_bounds,
                         relative[SLOT_INDEX]: self.on_index, relative[SLOT_ONCE]: self.on_once,
                         relative[SLOT_PRODUCER]: self.on_producer, relative[SLOT_GROW]: self.on_grow}
        machine.calls = {DROP_ERROR: self.on_drop, CONTEXT: self.on_context, RECORD: self.on_record, APPLY: self.on_apply,
                         ITERATE: self.on_iterate, FINAL_DROP: self.on_final, LOOKUP: self.on_lookup}
        for start in INSERTS:
            machine.calls[start] = self.on_insert
        for start in BUILDERS:
            machine.calls[start] = self.on_builder
        for start in FINISHES:
            machine.calls[start] = self.on_finish
        self.used = HEAP_SIZE
        self.brk = NODES

    def reset(self):
        self.machine.memory.reset(self.used)
        self.events = []
        self.insert = None
        self.brk = NODES

    def carve(self, size):
        at = self.brk
        self.brk += (size + 15) & ~15
        return at

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    # -- builder --

    def build_tree(self, at, tree):
        if not tree.root:
            self.word(at, 0)
            self.word(at + 8, tree.height)
            self.word(at + 0x10, tree.length)
            return
        size = NODE_EDGES + 12 * 8
        addresses = [self.carve(size) for _ in range(tree.height + 1)]
        for level, node in enumerate(addresses):
            self.word(node + NODE_PARENT, addresses[level - 1] if level else 0)
            self.word(node + NODE_PARENT_INDEX, tree.parents[level], 2)
            self.word(node + NODE_LEN, tree.lens[level], 2)
            for index in range(11):
                self.word(node + NODE_KEYS + index * 8, tree.key_at(level, index))
            if level < tree.height:
                self.word(node + NODE_EDGES, addresses[level + 1])
        self.word(at, addresses[0])
        self.word(at + 8, tree.height)
        self.word(at + 0x10, tree.length)

    def install_builder(self, copy, case):
        self.reset()
        fields = FIELD_SETS[BUILDER_ROWS[copy][1]]
        self.machine.memory.put_bytes(USER, bytes(range(1, 21)))
        self.word(BOOK + BOOK_ASSET, case.asset)
        self.build_tree(BOOK + BOOK_FIRST_TREE, case.first)
        self.build_tree(BOOK + BOOK_SECOND_TREE, case.second)
        self.word(LARGER + fields["market_count"], case.markets)
        self.word(LARGER + 0x60, case.date[0], 4)
        self.word(LARGER + 0x64, case.date[1], 4)
        self.word(LARGER + 0x68, case.date[2], 4)
        dex = case.asset // 10000
        # The market list base is chosen so that entry `dex` is this one row in low heap.
        self.word(MARKET_ROW + 8, ASSET_TABLE)
        self.word(MARKET_ROW + 0x10, case.assets)
        self.word(MARKET_ROW + 0x30, case.market_dex)
        self.word(LARGER + fields["markets"], MARKET_ROW - dex * MARKET_STRIDE)
        for index in range(max(case.assets, 16)):
            self.word(ASSET_TABLE + index * ASSET_STRIDE + ASSET_DECIMALS, case.decimals, 1)
        self.word(STACK_TOP - 0x100, VECTOR)

    def run_builder(self, copy, case, start=None):
        self.install_builder(copy, case)
        machine = self.machine
        machine.real = frozenset((BEST, ROUND, TICK))
        result = {}
        try:
            value = machine.run(start or BUILDER_ROWS[copy][0], {RDI: OUT, RSI: BOOK, RDX: USER, RCX: case.side, R8: case.size, R9: LARGER})
        except Panicked as stop:
            result["stop"] = stop.args[0]
        else:
            if value != OUT:
                result["returned"] = value
            if self.insert is None:
                result["out"] = (machine.memory.read(OUT, 8), machine.memory.read(OUT + 8, 8))
            else:
                result["insert"] = self.insert
        words = [row[1] for row in self.events if row[0] == "drop"]
        if words:
            result["drops"] = words
        return result

    def on_insert(self, machine):
        regs = machine.regs
        if regs[RDI] != OUT or regs[RSI] != BOOK or regs[R9] != LARGER:
            raise Halt("insert arguments")
        if machine.memory.read(regs[RSP] + 8, 8) != VECTOR:
            raise Halt("insert vector")
        self.insert = (machine.memory.read(BOOK + BOOK_ASSET, 8), regs[RCX] & MASK[4],
                       machine.memory.bytes_at(regs[RDX], RECORD_SIZE))

    # -- loop --

    def install_loop(self, copy, case):
        self.reset()
        fields = FIELD_SETS[LOOP_ROWS[copy][1]]
        memory = self.machine.memory
        memory.statics[ONCE_STATE] = case.once
        memory.put_bytes(USER, bytes(range(1, 21)))
        self.word(LARGER, case.flag, 4)
        self.word(LARGER + 8, 0xAA)
        self.word(LARGER + 0x28, 0xBB)
        self.word(LARGER + fields["byte"], 0x7B, 1)
        self.word(LARGER + fields["markets"], MARKETS)
        self.word(LARGER + fields["market_count"], case.markets)
        self.word(LARGER + fields["collections"], COLLECTIONS)
        self.word(LARGER + fields["collection_count"], case.collections)
        for dex in range(max(case.collections, 1)):
            self.word(COLLECTIONS + dex * COLLECTION_STRIDE + 8, BOOKS + dex * 0x10000)
            self.word(COLLECTIONS + dex * COLLECTION_STRIDE + 0x10, case.books)
        for index, (asset, tag, size) in enumerate(case.rows):
            self.word(ROWS + index * ROW_STRIDE, asset)
            self.word(ROWS + index * ROW_STRIDE + 8, tag, 1)
            self.word(ROWS + index * ROW_STRIDE + 0x10, size)
        for index, price in enumerate(case.prices):
            self.word(PRICES + index * CONTEXT_STRIDE + CONTEXT_PRICE, price)
        self.case = case
        self.next_outcome = iter(case.outcomes)
        self.remaining = []

    def run_loop(self, copy, case):
        self.install_loop(copy, case)
        machine = self.machine
        machine.real = frozenset()
        machine.xmm[0] = FRACTION_BITS
        result = {}
        try:
            machine.run(LOOP_ROWS[copy][0], {RDI: LARGER, RSI: USER})
        except Panicked as stop:
            result["stop"] = stop.args[0]
        result["events"] = self.events
        return result

    def on_producer(self, machine):
        regs = machine.regs
        self.events.append(("producer", regs[RSI], tuple(machine.memory.bytes_at(regs[RDX], 20)), machine.xmm[0] & MASK[8]))
        case = self.case
        if case.absent:
            self.word(regs[RDI], TAG_NONE)
            return
        self.word(regs[RDI], case.row_capacity)
        self.word(regs[RDI] + 8, ROWS)
        self.word(regs[RDI] + 0x10, len(case.rows))

    def on_context(self, machine):
        regs = machine.regs
        self.events.append(("context", regs[RSI]))
        self.word(regs[RDI], CONTEXT_CAPACITY)
        self.word(regs[RDI] + 8, PRICES)
        self.word(regs[RDI] + 0x10, len(self.case.prices))

    def on_record(self, machine):
        regs = machine.regs
        self.events.append(("record", regs[RSI] & 0xFF, regs[RDX], regs[RCX], regs[R8]))
        machine.memory.put_bytes(regs[RDI], RECORD_BYTES)

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_once(self, machine):
        self.events.append(("once", machine.regs[RSI] & MASK[4]))

    def on_builder(self, machine):
        regs = machine.regs
        memory = machine.memory
        vector = memory.read(regs[RSP] + 8, 8)
        self.events.append(("builder", regs[RSI], regs[RDX], regs[RCX] & MASK[4], regs[R8], regs[R9], regs[RDI] - regs[RSP],
                            vector - regs[RSP], (memory.read(vector, 8), memory.read(vector + 8, 8), memory.read(vector + 16, 8))))
        out = next(self.next_outcome, OK)
        at = regs[RDI]
        if out.error is not None:
            self.word(at, TAG_NONE)
            self.word(at + 8, out.error)
            self.word(at + 0x10, out.error_pointer)
        else:
            self.word(at, out.fills[0])
            self.word(at + 8, out.fills[1])
            self.word(at + 0x10, out.fills[2])
            self.word(at + 0x18, out.root)
            self.word(at + 0x20, out.height)
            self.word(at + 0x28, out.count)
        if out.pushed:
            for index, value in enumerate(out.pushed):
                self.word(vector + index * 8, value)
        self.remaining = list(out.entries)

    def on_apply(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("apply", regs[RDI], regs[RSI], regs[RDX], tuple(memory.bytes_at(regs[RCX], 33)), regs[R8], regs[R9],
                            memory.read(regs[RSP] + 8, 8) - regs[RSP]))

    def on_free(self, machine):
        regs = machine.regs
        self.events.append(("free", regs[RDI], regs[RSI], regs[RDX] & MASK[4]))

    def on_iterate(self, machine):
        regs = machine.regs
        memory = machine.memory
        order = (0, 4, 8, 1, 2, 3, 5, 6, 7) if memory.read(regs[RSI], 8) else (0, 4, 8)
        self.events.append(("iterate", tuple(memory.read(regs[RSI] + index * 8, 8) for index in order)))
        if self.remaining:
            capacity, pointer = self.remaining.pop(0)
            self.word(ITERATOR_NODE + 2 * ROW_STRIDE + 8, capacity)
            self.word(ITERATOR_NODE + 2 * ROW_STRIDE + 0x10, pointer)
            self.word(regs[RDI], ITERATOR_NODE)
            self.word(regs[RDI] + 0x10, 2)
        else:
            self.word(regs[RDI], 0)

    def on_finish(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("finish", (memory.read(regs[RDI], 8), memory.read(regs[RDI] + 8, 8), memory.read(regs[RDI] + 16, 8)),
                            regs[RSI], regs[RDX]))

    def on_final(self, machine):
        self.events.append(("final", machine.regs[RDI] - machine.regs[RSP]))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_index(self, machine):
        raise Panicked(("index", machine.regs[RDI]))

    def on_unwrap(self, machine):
        regs = machine.regs
        raise Panicked(("unwrap", regs[R8], machine.memory.read(regs[RDX], 2), regs[RSI]))

    def on_bounds(self, machine):
        regs = machine.regs
        raise Panicked(("bounds", regs[RDI], regs[RSI], regs[RDX]))

    # -- producer --

    def build_positions(self, case):
        """A B-tree whose level widths come from case.keys, filled in key order."""
        size = POSITION_EDGES + 12 * 8
        entries = iter(case.sizes)

        def make(level, parent, slot):
            node = self.carve(size)
            self.word(node + POSITION_PARENT, parent)
            self.word(node + POSITION_PARENT_INDEX, slot, 2)
            width = case.keys[level]
            filled = 0
            for index in range(width):
                if level + 1 < len(case.keys):
                    self.word(node + POSITION_EDGES + index * 8, make(level + 1, node, index))
                row = next(entries, None)
                if row is None:
                    break
                self.word(node + POSITION_KEYS + index * 8, row[0])
                self.word(node + index * POSITION_STRIDE + POSITION_SIZE, row[1])
                filled += 1
            if filled == width and level + 1 < len(case.keys):
                self.word(node + POSITION_EDGES + width * 8, make(level + 1, node, width))
            self.word(node + POSITION_LEN, filled, 2)
            return node

        return make(0, 0, 0)

    def run_positions(self, case):
        self.reset()
        self.machine.memory.put_bytes(USER, bytes(range(1, 21)))
        self.word(LOOKUP_RESULT + 8, self.build_positions(case) if case.root else 0)
        self.word(LOOKUP_RESULT + 0x10, len(case.keys) - 1 if case.keys else 0)
        self.word(LOOKUP_RESULT + 0x18, case.length)
        self.grown = GROWN
        machine = self.machine
        machine.real = frozenset()
        machine.xmm[0] = to_bits(case.fraction)
        try:
            machine.run(PRODUCER, {RDI: OUT, RSI: LARGER, RDX: USER})
        except Panicked as stop:
            return {"stop": stop.args[0]}
        memory = machine.memory
        capacity = memory.read(OUT, 8)
        if capacity == TAG_NONE:
            return {"none": True}
        pointer, length = memory.read(OUT + 8, 8), memory.read(OUT + 16, 8)
        rows = []
        for index in range(length):
            at = pointer + index * ROW_STRIDE
            rows.append((memory.read(at, 8), memory.read(at + 8, 1), memory.read(at + 0x10, 8)))
        return {"rows": rows} if rows else {"rows": rows, "vector": (capacity, pointer)}

    def run_round(self, value):
        machine = self.machine
        machine.real = frozenset()
        machine.memory.reset(0)
        machine.xmm[0] = to_bits(value)
        machine.run(ROUND, {})
        return machine.xmm[0] & MASK[8]

    def on_lookup(self, machine):
        regs = machine.regs
        if regs[RDI] != LARGER + 0xF8 or regs[RSI] != USER:
            raise Halt("lookup arguments")
        regs[RAX] = LOOKUP_RESULT

    def on_grow(self, machine):
        vector = machine.regs[RDI]
        memory = machine.memory
        capacity, pointer = memory.read(vector, 8), memory.read(vector + 8, 8)
        fresh = self.grown
        self.grown += (max(capacity * 2, 4) + 1) * ROW_STRIDE
        if capacity:
            memory.copy(fresh, pointer, capacity * ROW_STRIDE)
        self.word(vector, max(capacity * 2, 4))
        self.word(vector + 8, fresh)


def compare_builder(harness, copy, case):
    try:
        actual = harness.run_builder(copy, case)
    except (Halt, EvidenceError, IndexError, struct.error) as error:
        return "%s: machine stopped: %s" % (case.label, error)
    expected = spec_builder(copy, case)
    return None if actual == expected else "%s: differs: %r != %r" % (case.label, actual, expected)


def compare_loop(harness, copy, case):
    try:
        actual = harness.run_loop(copy, case)
    except (Halt, EvidenceError, IndexError, struct.error) as error:
        return "%s: machine stopped: %s" % (case.label, error)
    expected = spec_loop(copy, case)
    return None if actual == expected else "%s: differs:\n %r\n %r" % (case.label, actual, expected)


def compare_round(harness, value):
    try:
        actual = harness.run_round(value)
    except (Halt, EvidenceError, IndexError, struct.error) as error:
        return "%r: machine stopped: %s" % (value, error)
    expected = to_bits(spec_round(value))
    return None if actual == expected else "%r: differs: %#x != %#x" % (value, actual, expected)


def compare_positions(harness, case):
    try:
        actual = harness.run_positions(case)
    except (Halt, EvidenceError, IndexError, struct.error) as error:
        return "%s: machine stopped: %s" % (case.label, error)
    expected = spec_positions(case)
    return None if actual == expected else "%s: differs: %r != %r" % (case.label, actual, expected)


# ---- static comparison of the copies ----

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
    """Every `call [rip+disp32]` byte pattern in .text that reads a slot."""
    base, text = image.text_bytes()
    found = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            found.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return found


def operand_text(operand):
    if operand is None:
        return ""
    kind = operand[0]
    if kind == "r":
        return "r%d" % operand[1]
    if kind == "x":
        return "x%d" % operand[1]
    if kind == "i":
        return "%#x" % (operand[1] & MASK[8])
    _, base, index, scale, disp, _ = operand
    parts = []
    if base is not None:
        parts.append("r%d" % base)
    if index is not None:
        parts.append("r%d*%d" % (index, scale))
    parts.append("%#x" % (disp & MASK[8]))
    return "[" + "+".join(parts) + "]"


def row_shape(row, start, end):
    """A row with its branch target made relative when the target stays inside the function."""
    target = row.target
    if target is not None and start <= target < end:
        target = "+%#x" % (target - start)
    elif target is not None:
        target = "%#x" % (target & MASK[8])
    return (row.op, row.width, row.cc, operand_text(row.a), operand_text(row.b), target)


def copy_differences(image, first, second):
    """Rows of two same-sized functions that differ after normalising code distance."""
    begin, end = image.exact_fde(first)
    other, other_end = image.exact_fde(second)
    if end - begin != other_end - other:
        raise EvidenceError("copies differ in size: %#x %#x" % (first, second))
    rows = decode_range(image, begin, end)
    others = decode_range(image, other, other_end)
    if [row.va - begin for row in rows] != [row.va - other for row in others]:
        raise EvidenceError("copies differ in instruction boundaries: %#x %#x" % (first, second))
    found = []
    for row, peer in zip(rows, others):
        left, right = row_shape(row, begin, end), row_shape(peer, other, other_end)
        if left != right:
            found.append({"first": first, "second": second, "offset": row.va - begin, "left": " ".join(map(str, left)),
                          "right": " ".join(map(str, right))})
    return found


def memory_constant(image, row):
    """The f64 named by a `movsd xmm, [absolute]` row."""
    if row.op != "movsd" or row.b[0] != "m" or row.b[1] is not None:
        raise EvidenceError("not an absolute f64 load at %#x" % row.va)
    at = row.b[4]
    return at, struct.unpack_from("<d", image.blob, image.offset(at))[0]


def builder_pins(image):
    """Read each builder's constants and tail fields from its decoded rows."""
    pins = []
    for start, field_set, insert, kind, source, factors in BUILDER_ROWS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        loads = [memory_constant(image, row) for row in rows if row.op == "movsd" and row.a == ("x", 0) and row.b[0] == "m" and row.b[1] is None]
        if len(loads) != 2 or (loads[0][1], loads[1][1]) != factors:
            raise EvidenceError("price factors at %#x: %r" % (start, loads))
        tail = next(index for index, row in enumerate(rows) if row.op == "ret")
        calls = [row.target for row in rows[:tail] if row.op == "call"]
        if calls[-1] != insert:
            raise EvidenceError("insert target at %#x: %#x" % (start, calls[-1]))
        wrote = {}
        for row in rows:
            if row.op == "mov" and row.a[0] == "m" and row.a[1] == RSP and row.b[0] == "i":
                wrote[row.a[4]] = (row.width, row.b[1])
        if wrote[0xF8] != (8, kind) or wrote[0x154] != (1, source):
            raise EvidenceError("record constants at %#x" % start)
        counts = [row.b[4] for row in rows if row.op == "cmp" and row.b[0] == "m"]
        pins.append({"start": start, "field_set": field_set, "factor_zero_at": loads[0][0], "factor_nonzero_at": loads[1][0],
                     "factor_zero_bits": "%#018x" % to_bits(factors[0]), "factor_nonzero_bits": "%#018x" % to_bits(factors[1]),
                     "factor_zero": factors[0], "factor_nonzero": factors[1], "insert": insert, "record_70": kind, "record_cc": source,
                     "market_count_field": counts[0]})
    return pins


# ---- mutation pass ----

MUTATED = (BUILDERS[0], BEST, ROUND, LOOPS[0], PRODUCER)
# Flips that cannot change any defined result, by address, with the reason.
YEAR_ARM = "this arm runs for year 0 or earlier, so the time is before 1970 and clamps to 0 whatever the arm computes"
VECTOR_ARM = "this empty vector is read only by the unwind cleanup; the words are overwritten on the normal path"
RANGE_ARM = "a fraction under 1 keeps the product inside the i64 range, so the saturating cast never acts"
HEIGHT_ARM = "height has nonzero low three bits here, so it is never 8 and 9 splits the same way"
EQUIVALENT = {
    0x4304167: "the sar input is 0 or the sign bit, so a count of 62 clears only bit 0, and a price of 2^63 or more is a multiple of 2048",
    0x4304183: "a key is read through its absolute value, so the midpoint is at most 2^63 and the price stays under 1.2 * 2^63",
    0x430418E: "the rounded price is at least 1 for any midpoint of at least 1, so the raise to 1 never acts",
    0x43041C9: "both uses need a limit past 2^64: buy limits do not exceed the price, sell prices stay under 0.97 * 2^64",
    0x43041F5: "the limit is at least one tick, so the raise to 1 never acts",
    0x430421C: YEAR_ARM,
    0x4304225: YEAR_ARM,
    0x430422C: YEAR_ARM,
    0x4304233: YEAR_ARM,
    0x430423D: YEAR_ARM,
    0x4304268: "the year is not negative here because the arm above lifted it, so this sign bit is always 0",
    0x4A076D5: HEIGHT_ARM,
    0x4A077B5: HEIGHT_ARM,
    0x37053D5: HEIGHT_ARM,
    0x37054B8: HEIGHT_ARM,
    0x565F43E: "at exponent 0x433 the mask is all ones, so the kept bits equal the early return",
    0x4CDC801: VECTOR_ARM,
    0x4CDC80A: VECTOR_ARM,
    0x4CDC813: VECTOR_ARM,
    0x3705332: RANGE_ARM,
    0x370535E: RANGE_ARM,
    0x370553A: RANGE_ARM,
    0x3705555: RANGE_ARM,
    0x370555F: RANGE_ARM,
    0x370559F: "xmm1 is never NaN here, because the magnitude test sends NaN to the zero arm",
}
UNREACHED_GROUPS = (
    (0x4CDCB6E, 0x4CDCB8F, "second market count check: the entry check passed on the same field and nothing writes it"),
    (0x4CDCBD3, 0x4CDCD31, "unwind cleanup"),
    (0x3705667, 0x370566E, "unwind cleanup"),
)


def mutation_targets(rows):
    """Yield (va, offset in instruction, kind) for every conditional and every immediate."""
    for row in rows:
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ 1}


def run_mutants(image, seen):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    builder = builder_cases()
    loops = loop_cases()
    positions = position_cases()
    rounds = round_cases()
    for start in MUTATED:
        if start == LOOPS[0]:
            cases, check = loops, lambda case: compare_loop(harness, 0, case)
        elif start == PRODUCER:
            cases, check = positions, lambda case: compare_positions(harness, case)
        elif start == ROUND:
            cases, check = rounds, lambda value: compare_round(harness, value)
        else:
            cases, check = builder, lambda case: compare_builder(harness, 0, case)
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = check(case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
    return results


RECORD_MAP = (
    (0x00, 8, "constant 1"),
    (0x08, 8, "size argument r8"),
    (0x10, 8, "constant 0"),
    (0x20, 8, "constant 0"),
    (0x30, 8, "constant 0"),
    (0x38, 8, "constant 8, empty vector pointer"),
    (0x40, 16, "zero"),
    (0x70, 8, "constant per builder"),
    (0x80, 8, "limit price from the midpoint"),
    (0x88, 8, "block time in milliseconds, clamped at 0"),
    (0x90, 2, "constant 1"),
    (0xA2, 1, "side byte"),
    (0xA8, 8, "constant 0"),
    (0xB8, 20, "user, 20 bytes"),
    (0xCC, 1, "constant per builder"),
)
LOCATIONS = (LOCATION_OUTER, LOCATION_COLLECTION, LOCATION_BUILDER, LOCATION_CONTEXT, LOCATION_BOOK, LOCATION_LADDER,
             LOCATION_DECIMALS, LOCATION_NO_PARENT, LOCATION_POSITION_PARENT)
WORKED = ((2500000, 0, 0), (2500000, 1, 0), (1, 1, 0), (99999, 0, 0), (99999, 1, 0), (100000, 1, 2))


def worked_examples():
    rows = []
    for mid, side, decimals in WORKED:
        for factors in ((1.03, 0.97), (1.2, 0.8)):
            rows.append({"mid": mid, "side": side, "decimals": decimals, "factors": list(factors),
                         "limit": spec_limit(mid, side, decimals, factors)})
    return rows


def analyse(image, full=True):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    harness = Harness(image)
    outcomes = collections.Counter()
    builders = builder_cases()
    for copy in range(4):
        for case in builders:
            failure = compare_builder(harness, copy, case)
            if failure:
                raise EvidenceError("builder %d: %s" % (copy, failure))
            expected = spec_builder(copy, case)
            outcomes["builder " + ("insert" if "insert" in expected else "no price" if "out" in expected else "panic")] += 1
    loops = loop_cases()
    for copy in range(2):
        for case in loops:
            failure = compare_loop(harness, copy, case)
            if failure:
                raise EvidenceError("loop %d: %s" % (copy, failure))
            outcomes["loop " + ("panic" if "stop" in spec_loop(copy, case) else "returns")] += 1
    positions = position_cases()
    for case in positions:
        failure = compare_positions(harness, case)
        if failure:
            raise EvidenceError("positions: " + failure)
        expected = spec_positions(case)
        outcomes["positions " + ("panic" if "stop" in expected else "none" if "none" in expected else "rows")] += 1
    rounds = round_cases()
    for value in rounds:
        failure = compare_round(harness, value)
        if failure:
            raise EvidenceError("round: " + failure)
    seen = harness.machine.seen
    functions = []
    roles = [(start, "order builder %d" % index) for index, start in enumerate(BUILDERS)]
    roles += [(start, "row loop %d" % index) for index, start in enumerate(LOOPS)]
    roles += [(PRODUCER, "position rows"), (BEST, "best keys of both trees"), (ROUND, "round"), (TICK, "tick, run only")]
    for start, role in roles:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        at = image.offset(begin)
        functions.append({"role": role, "start": begin, "end": end, "size": end - begin, "instructions": len(rows),
                          "executed": sum(1 for row in rows if row.va in seen),
                          "sha256": hashlib.sha256(bytes(image.blob[at:at + end - begin])).hexdigest()})
    differences = []
    for first, second in ((BUILDERS[0], BUILDERS[1]), (BUILDERS[0], BUILDERS[2]), (BUILDERS[0], BUILDERS[3]), (LOOPS[0], LOOPS[1])):
        differences.extend(copy_differences(image, first, second))
    sites = direct_sites(image, BUILDERS + LOOPS)
    calls = []
    for target in BUILDERS + LOOPS:
        for site, opcode in sorted(sites[target]):
            calls.append({"target": target, "site": site, "opcode": opcode, "fde": image.fde(site)[0]})
    mutations = run_mutants(image, seen) if full else []
    locations = {}
    for slot in LOCATIONS:
        path, line, column = image.location(slot, relative)
        locations["%#x" % slot] = "%s:%d:%d" % (path[path.find("l1/"):] if "l1/" in path else path.rsplit("/", 1)[-1], line, column)
    return {"functions": functions, "differences": differences, "calls": calls, "mutations": mutations, "locations": locations,
            "pins": builder_pins(image), "cases": {"builder": len(builders), "loop": len(loops), "positions": len(positions), "round": len(rounds)},
            "outcomes": outcomes, "steps": harness.machine.steps, "slot_sites": slot_sites(image, SLOT_PRODUCER),
            "slot_fdes": [image.fde(site)[0] for site in slot_sites(image, SLOT_PRODUCER)],
            "slot_target": relative[SLOT_PRODUCER], "fraction_limit": struct.unpack_from("<d", image.blob, image.offset(FRACTION_LIMIT_AT))[0]}


def render(evidence):
    files = {}
    rows = ["role\tstart\tend\tsize\tinstructions\texecuted\tsha256"]
    for item in evidence["functions"]:
        rows.append("\t".join((item["role"], "%#x" % item["start"], "%#x" % item["end"], str(item["size"]),
                               str(item["instructions"]), str(item["executed"]), item["sha256"])))
    files["functions.tsv"] = "\n".join(rows) + "\n"
    rows = ["first\tsecond\toffset\tfirst_row\tsecond_row"]
    for item in evidence["differences"]:
        rows.append("\t".join(("%#x" % item["first"], "%#x" % item["second"], "%#x" % item["offset"], item["left"], item["right"])))
    files["copy_differences.tsv"] = "\n".join(rows) + "\n"
    rows = ["target\tcall_site\topcode\tcaller_fde"]
    for item in evidence["calls"]:
        rows.append("\t".join(("%#x" % item["target"], "%#x" % item["site"], "%#x" % item["opcode"], "%#x" % item["fde"])))
    files["callers.tsv"] = "\n".join(rows) + "\n"
    rows = ["offset\tsize\tvalue"]
    for offset, size, rule in RECORD_MAP:
        rows.append("%#x\t%#x\t%s" % (offset, size, rule))
    files["order_record.tsv"] = "\n".join(rows) + "\n"
    rows = ["function\tva\tkind\tresult\tfirst_detecting_case\tnote"]
    for item in evidence["mutations"]:
        note = ""
        if item["result"] == "survived":
            note = EQUIVALENT.get(item["va"], "")
        elif item["result"] == "unreached":
            note = next((reason for low, high, reason in UNREACHED_GROUPS if low <= item["va"] <= high), "")
        rows.append("\t".join(("%#x" % item["function"], "%#x" % item["va"], item["kind"], item["result"], item["by"], note)))
    files["mutations.tsv"] = "\n".join(rows) + "\n"
    summary = {key: 0 for key in ("killed", "survived", "unreached")}
    for item in evidence["mutations"]:
        summary[item["result"]] += 1
    document = {
        "target": {"path": "artifacts/node/94/hl-node", "sha256": SHA256},
        "cases": evidence["cases"],
        "outcomes": dict(sorted(evidence["outcomes"].items())),
        "instructions_stepped": evidence["steps"],
        "mismatches": 0,
        "mutations": summary,
        "locations": evidence["locations"],
        "builders": [{key: ("%#x" % value if key in ("start", "factor_zero_at", "factor_nonzero_at", "insert", "market_count_field") else value)
                      for key, value in item.items()} for item in evidence["pins"]],
        "notional_floor": {"value": NOTIONAL_FLOOR, "ceiling": "%#x" % NOTIONAL_CEILING},
        "no_price_word": "%#x" % NO_PRICE,
        "field_sets": [{key: "%#x" % value for key, value in item.items()} for item in FIELD_SETS],
        "producer": {"slot": "%#x" % SLOT_PRODUCER, "target": "%#x" % evidence["slot_target"],
                     "slot_call_sites": ["%#x" % site for site in evidence["slot_sites"]],
                     "slot_call_fdes": ["%#x" % fde for fde in evidence["slot_fdes"]],
                     "fraction_limit": evidence["fraction_limit"]},
        "strides": {"market": "%#x" % MARKET_STRIDE, "collection": "%#x" % COLLECTION_STRIDE, "book": "%#x" % BOOK_STRIDE,
                    "context": "%#x" % CONTEXT_STRIDE, "row": "%#x" % ROW_STRIDE, "fill": "%#x" % FILL_STRIDE,
                    "asset": "%#x" % ASSET_STRIDE, "position_value": "%#x" % POSITION_STRIDE},
        "worked_examples": worked_examples(),
    }
    files["evidence.json"] = json.dumps(document, indent=2, sort_keys=True) + "\n"
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
