#!/usr/bin/env python3
"""Reconstruct the node #115 mid-price market order builders from ELF bytes.

Six order builders take a book's best bid and ask, form the overflow-free floor midpoint, move it by a
side-dependent factor (1.03/0.97 in four copies, 1.2/0.8 in two), round half away from zero, clamp to
[1, u64::MAX], snap it to the asset's tick (sell side always adds one whole tick), stamp the block time
in milliseconds and hand a fixed order record to the insert path. The original bytes of every builder,
of `round` and of the tick helper run in a small x86-64 evaluator with only the edges stubbed, and an
independently written pure-Python reconstruction predicts every record byte, every no-price result,
every panic and its Location. Every condition and immediate of builder 0, the tick helper and `round`
is then flipped to show the comparison can tell, and deliberately wrong reconstructions must be caught.
This revalidates the merged node #94 reconstruction (RE-006-mid-market-order-94, removed in the #115
migration) on #115 bytes and records where #115 differs. No objdump or readelf output is parsed, and
the binary is never executed. Standard library only.
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

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (start, best-pair reader, insert, record +0x48 kind, record +0xdc byte, factors for side byte zero / nonzero, tick helper, field set)
BUILDER_ROWS = (
    (0x58F4C70, 0x50EAF10, 0x5901DD0, 6, 1, (1.03, 0.97), 0x5A01110, 0),
    (0x58F5060, 0x50EAF10, 0x5909B30, 6, 1, (1.03, 0.97), 0x5A01110, 1),
    (0x58F5450, 0x50EAF10, 0x5901DD0, 1, 4, (1.2, 0.8), 0x5A01110, 0),
    (0x58F5840, 0x50EAF10, 0x5909B30, 1, 4, (1.2, 0.8), 0x5A01110, 1),
    (0x23E3B40, 0x22F6370, 0x23EBEA0, 6, 1, (1.03, 0.97), 0x2891F50, 0),
    (0x23E3F40, 0x22F6370, 0x23EBEA0, 1, 4, (1.2, 0.8), 0x2891F50, 0),
)
BUILDERS = tuple(row[0] for row in BUILDER_ROWS)
TICK = 0x5A01110
TICKS = (0x5A01110, 0x2891F50)
DROP_ERROR = 0x44E0810
SLOT_ROUND = 0x64E1890
SLOT_UNWRAP = 0x64DF6A0
SLOT_BOUNDS_PANIC = 0x64DF830
SLOT_INDEX_PANIC = 0x64DF848
SLOT_ABORT = 0x64DF4C0
LOCATION_BUILDER = 0x648B990
LOCATION_TICK_MARKET = 0x64768A8
LOCATION_TICK_DECIMALS = 0x6478258
FACTOR_AT = {1.03: 0x4592C0, 0.97: 0x459790, 1.2: 0x4592C8, 0.8: 0x459BF0}
ERROR_WORD = 0x156
UNWRAP_MESSAGE = 0x2B
NO_PRICE = 0x800000000000000A
TAG_NONE = 1 << 63
ASSET_FIELD = 0x110
BEST_FIELD = 0xA8
# Two field sets of the outer object: (markets, market count).
FIELD_SETS = ((0x7C8, 0x7D0), (0x1338, 0x1340))
MARKET_STRIDE = 0x510
MARKET_ASSETS = 0x08
MARKET_ASSET_COUNT = 0x10
MARKET_DEX = 0x50
ASSET_STRIDE = 0x20
ASSET_DECIMALS = 0x1D
TIME_FIELD = 0x60
RECORD_SIZE = 0xE0
FAKE_SLOT_BASE = 0x7E0000000

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


class BuilderCase:
    def __init__(self, label, bid, ask, side=0, size=1234, asset=3, decimals=0, markets=1, market_dex=None,
                 assets=8, date=(2024 << 13 | 100 << 4, 3600, 5000000)):
        self.label, self.bid, self.ask = label, bid, ask
        self.side, self.size, self.asset, self.decimals = side, size, asset, decimals
        self.markets = markets
        self.market_dex = asset // 10000 if market_dex is None else market_dex
        self.assets, self.date = assets, date


# ---- reconstruction (written from the claim, independent of the evaluator) ----

def spec_round(value):
    """Half away from zero, written over exact integer parts."""
    size = abs(value)
    if value != value or size >= 2.0 ** 52:
        return value
    whole = math.floor(size)
    return math.copysign(float(whole + 1) if size - whole >= 0.5 else float(whole), value)


def spec_tick(price, decimals, variant=None):
    digits = len(str(price))
    shift = 4 if variant == "tick digits minus four" else 5
    base = 10 ** max(digits - shift, 0)
    cap = 10 ** ((7 if variant == "tick cap seven" else 6) - decimals)
    return min(base, cap)


def spec_millis(date, variant=None):
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
    millis = (days * 86400 + seconds) * 1000 + (0 if variant == "time ignores nanoseconds" else nanos // 1000000)
    if variant == "time not clamped":
        return millis & MASK[8]
    return max(millis, 0)


def spec_price(mid, factor, variant=None):
    """f64 product, rounded, clamped at 0, +inf to 0, saturating u64 cast, then raised to 1."""
    if variant == "round half even":
        scaled = float(round(float(mid) * factor))
    else:
        scaled = spec_round(float(mid) * factor)
    if not scaled > 0.0:
        scaled = 0.0
    if scaled == math.inf:
        price = 0
    elif scaled >= 18446744073709551616.0:
        price = MASK[8]
    else:
        price = int(scaled)
    if variant == "no raise to one":
        return price
    return max(price, 1)


def spec_limit(mid, side, decimals, factors, variant=None):
    """The limit: the factor pair is (zero side byte, nonzero side byte)."""
    selling = (side & (MASK[8] if variant == "whole side word" else 0xFF)) != 0
    if variant == "factors swapped":
        selling = not selling
    factor = factors[1] if selling else factors[0]
    price = spec_price(mid, factor, variant)
    tick = spec_tick(price, decimals, variant)
    quotient = price // tick
    if selling:
        if variant == "sell rounds up only off-tick":
            quotient = -(-price // tick)
        else:
            quotient = MASK[8] if quotient == MASK[8] else quotient + 1
    limit = quotient * tick
    if limit > MASK[8]:
        limit = MASK[8]
    return max(limit, 1)


def spec_mid(bid, ask, variant=None):
    if variant == "wrapping mean":
        return ((bid + ask) & MASK[8]) >> 1
    return (bid & ask) + ((bid ^ ask) >> 1)


def spec_record(copy, case, limit, variant=None):
    record = bytearray([STACK_MARK]) * RECORD_SIZE
    kind, source = BUILDER_ROWS[copy][3], BUILDER_ROWS[copy][4]
    if variant == "kinds swapped":
        kind, source = (1, 4) if kind == 6 else (6, 1)
    struct.pack_into("<QQQ", record, 0, 1, case.size, 0)
    struct.pack_into("<Q", record, 0x20, 0)
    struct.pack_into("<QQQQ", record, 0x30, 0, 8, 0, kind)
    struct.pack_into("<Q", record, 0x58, TAG_NONE)
    struct.pack_into("<QQH", record, 0x90, limit, spec_millis(case.date, variant), 1)
    record[0xB2] = case.side & 0xFF
    struct.pack_into("<Q", record, 0xB8, 0)
    record[0xC8:0xDC] = bytes(range(1, 21))
    record[0xDC] = source
    return bytes(record)


def spec_builder(copy, case, variant=None):
    dex, local = case.asset // 10000, case.asset % 10000
    if dex >= case.markets:
        return {"stop": ("unwrap", LOCATION_BUILDER, ERROR_WORD, UNWRAP_MESSAGE)}
    drops = [ERROR_WORD]
    if case.bid == 0 or case.ask == 0:
        if variant == "zero side still prices" and (case.bid or case.ask):
            pass
        else:
            return {"out": (TAG_NONE, NO_PRICE), "drops": drops}
    mid = spec_mid(case.bid, case.ask, variant)
    factor_pair = BUILDER_ROWS[copy][5]
    price_preview = spec_price(mid, factor_pair[1] if case.side & 0xFF else factor_pair[0], variant)
    del price_preview
    if variant == "decimals checked first" and case.decimals >= 7:
        return {"stop": ("index", LOCATION_TICK_DECIMALS), "drops": drops}
    if dex != case.market_dex or local >= case.assets:
        return {"stop": ("panic", LOCATION_TICK_MARKET), "drops": drops}
    if case.decimals >= 7:
        return {"stop": ("index", LOCATION_TICK_DECIMALS), "drops": drops}
    limit = spec_limit(mid, case.side, case.decimals, factor_pair, variant)
    return {"insert": (case.asset, 0, spec_record(copy, case, limit, variant)), "drops": drops}


NEGATIVES = (
    ("factors swapped", "the side byte picks the other factor"),
    ("whole side word", "all 64 bits of the side argument decide the side"),
    ("sell rounds up only off-tick", "the sell side rounds up to the tick instead of adding a whole tick"),
    ("round half even", "Python round() (half to even) instead of half away from zero"),
    ("decimals checked first", "the decimals panic is checked before the market row checks"),
    ("time ignores nanoseconds", "the millisecond stamp drops the nanosecond word"),
    ("tick digits minus four", "the tick ladder starts one digit early"),
    ("tick cap seven", "the decimals cap is 10^(7-decimals)"),
    ("wrapping mean", "the midpoint is (bid+ask)/2 with 64-bit wrap"),
    ("time not clamped", "times before 1970 are not clamped to 0"),
    ("kinds swapped", "record +0x48/+0xdc constants of the other factor family"),
    ("zero side still prices", "one empty side still yields a price"),
)


def builder_cases():
    cases = []
    plain = 2500000

    def add(label, bid, ask, **options):
        cases.append(BuilderCase(label, bid, ask, **options))

    add("simple buy", plain, plain + 200, side=0)
    add("simple sell", plain, plain + 200, side=1)
    add("side high bits are ignored", plain, plain, side=0x100)
    add("side byte two", plain, plain, side=2)
    add("side byte 0xff", plain, plain, side=0xFF)
    add("side word high only", plain, plain, side=0xFFFFFF00)
    add("bid zero", 0, plain)
    add("ask zero", plain, 0)
    add("both zero", 0, 0)
    add("bid zero sell", 0, plain, side=1)
    add("mid one buy", 1, 1, side=0)
    add("mid one sell", 1, 1, side=1)
    add("mid floors", 1, 2, side=0)
    add("max keys", MASK[8], MASK[8], side=0)
    add("max keys sell", MASK[8], MASK[8], side=1)
    add("max and one", MASK[8], 1, side=1)
    add("sign bit keys", SIGN[8], SIGN[8], side=0)
    add("dex past markets", plain, plain, asset=10000, markets=1)
    add("dex on the last market", plain, plain, asset=10003, markets=2)
    add("dex differs from the market row", plain, plain, asset=10003, markets=2, market_dex=0)
    add("empty book skips the tick checks", 0, plain, asset=10003, markets=2, market_dex=0)
    add("dex past markets with empty book", 0, 0, asset=20000, markets=2)
    add("local on the bound", plain, plain, asset=8, assets=8)
    add("local below the bound", plain, plain, asset=7, assets=8)
    add("decimals six", plain, plain, decimals=6)
    add("decimals seven", plain, plain, decimals=7)
    add("decimals 0xff", plain, plain, decimals=0xFF)
    add("decimals seven on an empty book", 0, plain, decimals=7)
    add("decimals seven and dex mismatch", plain, plain, asset=10003, markets=2, market_dex=0, decimals=7)
    add("decimals seven and local past the bound", plain, plain, asset=9, assets=8, decimals=7)
    add("size word passes through", plain, plain, size=MASK[8])
    add("size zero", plain, plain, size=0)
    add("year one", plain, plain, date=(1 << 13 | 1 << 4, 0, 0))
    add("year zero", plain, plain, date=(0 << 13 | 1 << 4, 0, 0))
    add("year -400", plain, plain, date=(((-400) << 13 | 1 << 4) & MASK[4], 1, 1))
    add("year -1", plain, plain, date=(((-1) << 13 | 300 << 4) & MASK[4], 86399, 999999999))
    add("epoch day", plain, plain, date=(1970 << 13 | 1 << 4, 0, 0))
    add("epoch day one milli", plain, plain, date=(1970 << 13 | 1 << 4, 0, 1000000))
    add("before the epoch clamps", plain, plain, date=(1969 << 13 | 365 << 4, 86399, 999999999))
    add("late year", plain, plain, date=(262142 << 13 | 366 << 4, 86399, 1999999999))
    for year in (1971, 2000, 2001, 2100, 2101, 2200, 2301, 2400, 2401, 2404, 2800, 2801):
        add("year %d" % year, plain, plain, date=(year << 13 | 1 << 4, 0, 0))
    add("flags are ignored", plain, plain, date=(2024 << 13 | 100 << 4 | 7, 3, 4))
    edges = []
    for exponent in range(0, 20):
        edges.extend((10 ** exponent - 1, 10 ** exponent, 10 ** exponent + 1))
    for exponent in range(31, 64):
        edges.extend(((1 << exponent) - 1, 1 << exponent))
    edges.extend((SIGN[8] - 2048, SIGN[8] - 1, SIGN[8], MASK[8] - 2048, MASK[8] - 1, MASK[8]))
    for mid in edges:
        if not 0 < mid <= MASK[8]:
            continue
        for side in (0, 1):
            add("mid %#x side %d" % (mid, side), mid, mid, side=side)
    for mid in (MASK[8], SIGN[8], SIGN[8] - 1, 1 << 62, 15 * 10 ** 18, 10 ** 19, 18 * 10 ** 18):
        for side in (0, 1):
            add("tick one mid %#x side %d" % (mid, side), mid, mid, side=side, decimals=6)
    for exponent in range(4, 20):
        for delta in (-1, 0, 1):
            target = 10 ** exponent + delta
            for side, factor in ((0, 1.03), (1, 0.97), (0, 1.2), (1, 0.8)):
                mid = int(target / factor)
                if not 0 < mid <= MASK[8]:
                    continue
                for nudge in (-1, 0, 1):
                    add("target %#x side %d factor %s nudge %d" % (target, side, factor, nudge), mid + nudge, mid + nudge, side=side)
    for decimals in range(0, 7):
        for mid in (123456, 1234567, 99999999, 123456789012, 2500000):
            for side in (0, 1):
                add("decimals %d mid %d side %d" % (decimals, mid, side), mid, mid, side=side, decimals=decimals)
    numbers = lcg(0x1155)
    for index in range(160):
        shift = next(numbers) % 60
        bid = (next(numbers) << 16 | next(numbers)) >> shift | 1
        ask = (next(numbers) << 16 | next(numbers)) >> shift | 1
        add("random %d" % index, bid & MASK[8], ask & MASK[8], side=next(numbers) & 0x1FF, size=next(numbers),
            decimals=next(numbers) % 7, date=(2020 + next(numbers) % 10 << 13 | (1 + next(numbers) % 360) << 4,
                                              next(numbers) % 86400, next(numbers) % 1000000000))
    return cases


def tick_cases():
    """(label, asset, price, decimals, assets, market_dex) for direct runs of the tick helper."""
    rows = []
    prices = [0, 1]
    for exponent in range(1, 20):
        prices.extend((10 ** exponent - 1, 10 ** exponent, 10 ** exponent + 1))
    prices.extend((MASK[8] - 1, MASK[8], SIGN[8]))
    for decimals in range(0, 7):
        for price in prices:
            rows.append(("price %d decimals %d" % (price, decimals), 3, price, decimals, 8, 0))
    rows.append(("decimals seven", 3, 2500000, 7, 8, 0))
    rows.append(("decimals 0x80", 3, 2500000, 0x80, 8, 0))
    rows.append(("local on the bound", 8, 2500000, 2, 8, 0))
    rows.append(("local past the bound", 9, 2500000, 2, 8, 0))
    rows.append(("dex mismatch", 10003, 2500000, 2, 8, 0))
    rows.append(("dex match", 10003, 2500000, 2, 8, 1))
    rows.append(("dex mismatch and local past the bound", 10009, 2500000, 2, 8, 0))
    rows.append(("dex one local zero", 10000, 2500000, 2, 8, 1))
    rows.append(("dex three local zero", 30000, 2500000, 2, 8, 3))
    rows.append(("dex one local on the bound", 10008, 2500000, 2, 8, 1))
    rows.append(("dex one local below the bound", 10007, 2500000, 2, 8, 1))
    rows.append(("dex three local on the bound", 30005, 2500000, 2, 5, 3))
    rows.append(("dex 1844 local below the bound", 18440004, 2500000, 2, 5, 1844))
    rows.append(("large asset", 4 * 10000 + 7, 2500000, 1, 8, 4))
    return rows


def spec_tick_run(asset, price, decimals, assets, market_dex):
    dex, local = asset // 10000, asset % 10000
    if dex != market_dex or local >= assets:
        return {"stop": ("panic", LOCATION_TICK_MARKET)}
    if decimals >= 7:
        return {"stop": ("index", LOCATION_TICK_DECIMALS)}
    return {"tick": spec_tick(price, decimals)}


def round_cases():
    values = [0.0, -0.0, 0.25, 0.3, -0.3, 0.49999999999999994, -0.49999999999999994, 0.5, -0.5, 0.75, 1.0, 1.5, 2.5, -2.5,
              1.0000000000000002, 1.4999999999999998, 1.9999999999999998, 3.0000000000000004, 1234.5, 1234.4999999999998,
              5e-324, 2.0 ** 51 + 0.5, 2.0 ** 52 - 0.5, 2.0 ** 52 - 1.0, 2.0 ** 52, 2.0 ** 52 + 2.0, 2.0 ** 53, 1e300, -1e300,
              float("inf"), float("-inf"), float("nan")]
    numbers = lcg(0x2B0D)
    for _ in range(80):
        values.append((next(numbers) % 10 ** 9) / 1000.0 + 0.5 * (next(numbers) & 1))
    return values


# ---- harness ----

USER = HEAP_BASE + 0x100
OUT = HEAP_BASE + 0x200
VECTOR = HEAP_BASE + 0x300
BOOK = HEAP_BASE + 0x400
OUTER = HEAP_BASE + 0x1000
MARKET_ROW = HEAP_BASE + 0x4000
ASSET_TABLE = HEAP_BASE + 0x5000


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        self.round_target = relative[SLOT_ROUND]
        machine.memory.statics[SLOT_ROUND] = self.round_target
        hooks = ((SLOT_UNWRAP, self.on_unwrap), (SLOT_BOUNDS_PANIC, self.on_panic),
                 (SLOT_INDEX_PANIC, self.on_index), (SLOT_ABORT, self.on_abort))
        machine.slots = {}
        for index, (slot, hook) in enumerate(hooks):
            if slot not in relative:
                raise EvidenceError("slot without a RELATIVE row: %#x" % slot)
            fake = FAKE_SLOT_BASE + 0x10 * index
            machine.memory.statics[slot] = fake
            machine.slots[fake] = hook
        machine.calls = {DROP_ERROR: self.on_drop}
        for row in BUILDER_ROWS:
            machine.calls[row[1]] = self.on_best
            if row[2]:
                machine.calls[row[2]] = self.on_insert

    def reset(self):
        self.machine.memory.reset(0x6000)
        self.events = []
        self.insert = None

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def install_market(self, assets, market_dex, decimals):
        self.word(MARKET_ROW + MARKET_ASSETS, ASSET_TABLE)
        self.word(MARKET_ROW + MARKET_ASSET_COUNT, assets)
        self.word(MARKET_ROW + MARKET_DEX, market_dex)
        for index in range(max(assets, 16) + 2):
            self.word(ASSET_TABLE + index * ASSET_STRIDE + ASSET_DECIMALS, decimals, 1)

    def install_builder(self, copy, case):
        markets, market_count = FIELD_SETS[BUILDER_ROWS[copy][7]]
        self.reset()
        self.case = case
        self.machine.memory.put_bytes(USER, bytes(range(1, 21)))
        self.word(BOOK + ASSET_FIELD, case.asset)
        self.word(OUTER + market_count, case.markets)
        self.word(OUTER + TIME_FIELD, case.date[0], 4)
        self.word(OUTER + TIME_FIELD + 4, case.date[1], 4)
        self.word(OUTER + TIME_FIELD + 8, case.date[2], 4)
        dex = case.asset // 10000
        # The market base is chosen so that entry `dex` is the one row in the heap.
        self.word(OUTER + markets, (MARKET_ROW - dex * MARKET_STRIDE) & MASK[8])
        self.install_market(case.assets, case.market_dex, case.decimals)
        self.word(STACK_TOP - 0x100, VECTOR)

    def run_builder(self, copy, case):
        self.install_builder(copy, case)
        machine = self.machine
        machine.real = frozenset(TICKS + (self.round_target,))
        result = {}
        try:
            value = machine.run(BUILDER_ROWS[copy][0], {RDI: OUT, RSI: BOOK, RDX: USER, RCX: case.side, R8: case.size, R9: OUTER})
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

    def run_tick(self, asset, price, decimals, assets, market_dex, helper=TICK):
        self.reset()
        self.install_market(assets, market_dex, decimals)
        machine = self.machine
        machine.real = frozenset()
        try:
            value = machine.run(helper, {RDI: MARKET_ROW, RSI: asset, RDX: price})
        except Panicked as stop:
            return {"stop": stop.args[0]}
        return {"tick": value}

    def run_round(self, value):
        machine = self.machine
        machine.real = frozenset()
        machine.memory.reset(0)
        machine.xmm[0] = to_bits(value)
        machine.run(self.round_target, {})
        return machine.xmm[0] & MASK[8]

    def on_best(self, machine):
        regs = machine.regs
        if regs[RSI] != BOOK + BEST_FIELD:
            raise Halt("best-pair argument")
        self.word(regs[RDI], self.case.bid)
        self.word(regs[RDI] + 8, self.case.ask)

    def on_insert(self, machine):
        regs = machine.regs
        if regs[RDI] != OUT or regs[RSI] != BOOK or regs[R9] != OUTER:
            raise Halt("insert arguments")
        if machine.memory.read(regs[RSP] + 8, 8) != VECTOR:
            raise Halt("insert vector")
        self.insert = (machine.memory.read(BOOK + ASSET_FIELD, 8), regs[RCX] & MASK[4],
                       machine.memory.bytes_at(regs[RDX], RECORD_SIZE))

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_index(self, machine):
        raise Panicked(("index", machine.regs[RDI]))

    def on_abort(self, machine):
        raise Panicked(("abort",))

    def on_unwrap(self, machine):
        regs = machine.regs
        raise Panicked(("unwrap", regs[R8], machine.memory.read(regs[RDX], 2), regs[RSI]))


CRASHES = (Halt, EvidenceError, IndexError, struct.error, ValueError, KeyError, OverflowError, ZeroDivisionError)


def compare_builder(harness, copy, case, variant=None):
    try:
        actual = harness.run_builder(copy, case)
    except CRASHES as error:
        return "%s: machine stopped: %s" % (case.label, error)
    expected = spec_builder(copy, case, variant)
    return None if actual == expected else "%s: differs: %r != %r" % (case.label, actual, expected)


def compare_tick(harness, row, helper=TICK):
    label, asset, price, decimals, assets, market_dex = row
    try:
        actual = harness.run_tick(asset, price, decimals, assets, market_dex, helper)
    except CRASHES as error:
        return "%s: machine stopped: %s" % (label, error)
    expected = spec_tick_run(asset, price, decimals, assets, market_dex)
    return None if actual == expected else "%s: differs: %r != %r" % (label, actual, expected)


def compare_round(harness, value):
    try:
        actual = harness.run_round(value)
    except CRASHES as error:
        return "%r: machine stopped: %s" % (value, error)
    expected = to_bits(spec_round(value))
    return None if actual == expected else "%r: differs: %#x != %#x" % (value, actual, expected)


# ---- static pins ----

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


def factor_loads(image):
    """Every movsd/mulsd [rip] in .text whose target holds one of the four factors, grouped by FDE."""
    base, text = image.text_bytes()
    wanted = {}
    for value, at in FACTOR_AT.items():
        if struct.unpack_from("<d", image.blob, image.offset(at))[0] != value:
            raise EvidenceError("factor %r not at %#x" % (value, at))
        wanted[at] = value
    hits = collections.defaultdict(set)
    for prefix in (b"\xf2\x0f\x10", b"\xf2\x0f\x59"):
        at = text.find(prefix)
        while 0 <= at <= len(text) - 8:
            if text[at + 3] & 0xC7 == 0x05:
                target = base + at + 8 + struct.unpack_from("<i", text, at + 4)[0]
                if target in wanted:
                    try:
                        hits[image.fde(base + at)[0]].add(wanted[target])
                    except EvidenceError:
                        pass
            at = text.find(prefix, at + 1)
    return {start: sorted(values) for start, values in hits.items()}


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
    target = row.target
    if target is not None and start <= target < end:
        target = "+%#x" % (target - start)
    elif target is not None:
        target = "%#x" % (target & MASK[8])
    return (row.op, row.width, row.cc, operand_text(row.a), operand_text(row.b), target)


def copy_differences(image, first, second):
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


def builder_pins(image):
    """Read each builder's factors, callees and record constants from its decoded rows."""
    pins = []
    for start, best, insert, kind, source, factors, tick, field_set in BUILDER_ROWS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        loads = [row.b[4] for row in rows if row.op == "movsd" and row.a == ("x", 0) and row.b[0] == "m" and row.b[1] is None]
        values = tuple(struct.unpack_from("<d", image.blob, image.offset(at))[0] for at in loads)
        if values != factors:
            raise EvidenceError("price factors at %#x: %r" % (start, values))
        tail = next(index for index, row in enumerate(rows) if row.op == "ret")
        calls = [row.target for row in rows[:tail] if row.op == "call"]
        if calls[0] != DROP_ERROR or calls[1] != best or calls[2] != tick or calls[3] != insert:
            raise EvidenceError("callees at %#x: %s" % (start, [hex(c) for c in calls]))
        slots = [row.a[4] for row in rows[:tail] if row.op == "calli"]
        if slots != [SLOT_ROUND]:
            raise EvidenceError("slot calls at %#x" % start)
        wrote = {}
        for row in rows:
            if row.op == "mov" and row.a[0] == "m" and row.a[1] == RSP and row.b[0] == "i":
                wrote[row.a[4]] = (row.width, row.b[1])
        if wrote.get(0x78) != (8, kind) or wrote.get(0x10C) != (1, source) or wrote.get(0x110) != (2, ERROR_WORD):
            raise EvidenceError("record constants at %#x" % start)
        pins.append({"start": start, "size": end - start, "best": best, "tick": tick, "insert": calls[3],
                     "factor_zero_at": loads[0], "factor_nonzero_at": loads[1],
                     "factor_zero_bits": "%#018x" % to_bits(factors[0]), "factor_nonzero_bits": "%#018x" % to_bits(factors[1]),
                     "factor_zero": factors[0], "factor_nonzero": factors[1], "record_48": kind, "record_dc": source, "field_set": field_set})
    return pins


# ---- mutation pass ----

MUTATED = (BUILDERS[0], TICK)
YEAR_ARM = "this arm runs for year 0 or earlier, so the time is before 1970 and clamps to 0 whatever the arm computes"
LADDER_ARM = 'every tick rung from 10^6 up meets the cap 10^(6-decimals) <= 10^6 in the min, so a rung moved at or above 10^11 cannot change the tick'
EQUIVALENT = {
    0x58f4de2: 'a cast at or above 2^63 gives 0x8000000000000000, whose shift by 62 clears only bit 0, and every f64 at or above 2^63 is a multiple of 2048',
    0x58f4e09: 'the rounded price is at least 1 for any midpoint of at least 1 (0.8 is the smallest factor), so the raise to 1 never acts',
    0x58f4e4e: 'the saturation word is used only when q+1 or q*tick passes 2^64; a buy keeps q*tick <= price, and a sell price stays under 0.97 * 2^64',
    0x58f4e7a: 'the limit is at least one tick, so the raise to 1 never acts',
    0x58f4ea1: YEAR_ARM,
    0x58f4eaa: YEAR_ARM,
    0x58f4eb1: YEAR_ARM,
    0x58f4eb8: YEAR_ARM,
    0x58f4ec2: YEAR_ARM,
    0x58f4eed: 'the year is not negative here because the arm above lifted it, so this sign bit is always 0',
    0x5a012d4: 'decimals 3 leaves at the earlier exit (6-3 has bits 0 and 1, esi&6 == 2), so a bound of 3 instead of 2 multiplies nothing new',
    0x63efe6e: 'at exponent 0x433 the mask is all ones, so the kept bits equal the early return',
    0x5a01186: LADDER_ARM,
    0x5a0118a: LADDER_ARM,
    0x5a0118f: LADDER_ARM,
    0x5a01195: LADDER_ARM,
    0x5a0119e: LADDER_ARM,
    0x5a011a2: LADDER_ARM,
    0x5a011a7: LADDER_ARM,
    0x5a011ad: LADDER_ARM,
    0x5a011b6: LADDER_ARM,
    0x5a011ba: LADDER_ARM,
    0x5a011bf: LADDER_ARM,
    0x5a011c5: LADDER_ARM,
    0x5a011cb: LADDER_ARM,
    0x5a011d5: LADDER_ARM,
    0x5a011dd: LADDER_ARM,
    0x5a011e3: LADDER_ARM,
    0x5a011f0: LADDER_ARM,
    0x5a011f2: LADDER_ARM,
    0x5a011ff: LADDER_ARM,
    0x5a01201: LADDER_ARM,
    0x5a0120e: LADDER_ARM,
    0x5a01210: LADDER_ARM,
    0x5a0121d: LADDER_ARM,
    0x5a0121f: LADDER_ARM,
    0x5a0122c: LADDER_ARM,
    0x5a01232: LADDER_ARM,
    0x5a0123e: LADDER_ARM,
    0x5a0124a: LADDER_ARM,
    0x5a01256: LADDER_ARM,
}
UNREACHED_GROUPS = ()


def mutation_targets(rows):
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


def run_mutants(image, seen, extra_round=True):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    builder = builder_cases()
    ticks = tick_cases()
    rounds = round_cases()
    plan = [(BUILDERS[0], builder, lambda case: compare_builder(harness, 0, case)),
            (TICK, ticks, lambda row: compare_tick(harness, row))]
    if extra_round:
        plan.append((harness.round_target, rounds, lambda value: compare_round(harness, value)))
    for start, cases, check in plan:
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
    (0x40, 8, "constant 0"),
    (0x48, 8, "constant per builder: 6 (1.03/0.97) or 1 (1.2/0.8)"),
    (0x58, 8, "constant 0x8000000000000000"),
    (0x90, 8, "limit price from the midpoint"),
    (0x98, 8, "block time in milliseconds, clamped at 0"),
    (0xA0, 2, "constant 1"),
    (0xB2, 1, "side byte"),
    (0xB8, 8, "constant 0"),
    (0xC8, 20, "user, 20 bytes"),
    (0xDC, 1, "constant per builder: 1 (1.03/0.97) or 4 (1.2/0.8)"),
)
LOCATIONS = (LOCATION_BUILDER, LOCATION_TICK_MARKET, LOCATION_TICK_DECIMALS)
WORKED = ((2500000, 0, 0), (2500000, 1, 0), (1, 1, 0), (99999, 0, 0), (99999, 1, 0), (100000, 1, 2),
          (MASK[8], 0, 0), (MASK[8], 1, 6))


def worked_examples():
    rows = []
    for mid, side, decimals in WORKED:
        for factors in ((1.03, 0.97), (1.2, 0.8)):
            rows.append({"mid": mid, "side": side, "decimals": decimals, "factors": list(factors),
                         "limit": spec_limit(mid, side, decimals, factors)})
    return rows


def outcome_name(result):
    if "insert" in result:
        return "insert"
    if "out" in result:
        return "no price"
    return "panic " + result["stop"][0]


def analyse(image, full=True):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    pins = builder_pins(image)
    harness = Harness(image)
    outcomes = collections.Counter()
    builders = builder_cases()
    case_rows = []
    actual_by = {}
    for copy in range(len(BUILDER_ROWS)):
        for index, case in enumerate(builders):
            failure = compare_builder(harness, copy, case)
            if failure:
                raise EvidenceError("builder %d: %s" % (copy, failure))
            expected = spec_builder(copy, case)
            actual_by[(copy, index)] = expected
            outcomes["builder " + outcome_name(expected)] += 1
            limit = ""
            if "insert" in expected:
                limit = str(struct.unpack_from("<Q", expected["insert"][2], 0x90)[0])
            case_rows.append((copy, case, outcome_name(expected), limit))
    ticks = tick_cases()
    tick_rows = []
    for helper in TICKS:
        for row in ticks:
            failure = compare_tick(harness, row, helper)
            if failure:
                raise EvidenceError("tick %#x: %s" % (helper, failure))
            expected = spec_tick_run(*row[1:])
            tick_rows.append((helper, row, expected))
            outcomes["tick " + ("panic" if "stop" in expected else "value")] += 1
    rounds = round_cases()
    for value in rounds:
        failure = compare_round(harness, value)
        if failure:
            raise EvidenceError("round: " + failure)
    seen = set(harness.machine.seen)
    negatives = []
    for name, meaning in NEGATIVES:
        caught = 0
        first = ""
        for copy in range(len(BUILDER_ROWS)):
            for index, case in enumerate(builders):
                if spec_builder(copy, case, name) != actual_by[(copy, index)]:
                    caught += 1
                    if not first:
                        first = "%d %s" % (copy, case.label)
        negatives.append({"name": name, "meaning": meaning, "caught": caught, "first": first})
        if not caught:
            raise EvidenceError("negative control not caught: " + name)
    functions = []
    roles = [(start, "order builder %d" % index) for index, start in enumerate(BUILDERS)]
    roles += [(TICKS[0], "tick helper 0"), (TICKS[1], "tick helper 1"), (harness.round_target, "round")]
    for start, role in roles:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        at = image.offset(begin)
        functions.append({"role": role, "start": begin, "end": end, "size": end - begin, "instructions": len(rows),
                          "executed": sum(1 for row in rows if row.va in seen),
                          "sha256": hashlib.sha256(bytes(image.blob[at:at + end - begin])).hexdigest()})
    differences = []
    for first, second in ((BUILDERS[0], BUILDERS[1]), (BUILDERS[0], BUILDERS[2]), (BUILDERS[0], BUILDERS[3]),
                          (BUILDERS[4], BUILDERS[5])):
        differences.extend(copy_differences(image, first, second))
    sites = direct_sites(image, BUILDERS + TICKS)
    calls = []
    for target in BUILDERS + TICKS:
        for site, opcode in sorted(sites[target]):
            calls.append({"target": target, "site": site, "opcode": opcode, "fde": image.fde(site)[0]})
    loads = factor_loads(image)
    mutations = run_mutants(image, seen) if full else []
    locations = {}
    for slot in LOCATIONS:
        path, line, column = image.location(slot, relative)
        locations["%#x" % slot] = "%s:%d:%d" % (path[path.find("l1/"):] if "l1/" in path else path.rsplit("/", 1)[-1], line, column)
    return {"functions": functions, "differences": differences, "calls": calls, "mutations": mutations, "locations": locations,
            "pins": pins, "cases": {"builder": len(builders), "builder_runs": len(builders) * len(BUILDER_ROWS),
                                    "tick": len(ticks) * len(TICKS), "round": len(rounds)},
            "outcomes": outcomes, "steps": harness.machine.steps, "case_rows": case_rows, "tick_rows": tick_rows,
            "negatives": negatives, "factor_loads": loads, "round_target": harness.round_target,
            "slot_targets": {"%#x" % slot: relative[slot] for slot in (SLOT_ROUND, SLOT_UNWRAP, SLOT_BOUNDS_PANIC, SLOT_INDEX_PANIC, SLOT_ABORT)}}


def date_text(date):
    return "%#x/%d/%d" % date


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
    rows = ["fde_start\tfactors_loaded"]
    for start, values in sorted(evidence["factor_loads"].items()):
        rows.append("%#x\t%s" % (start, ",".join(repr(v) for v in values)))
    files["factor_loads.tsv"] = "\n".join(rows) + "\n"
    rows = ["offset\tsize\tvalue"]
    for offset, size, rule in RECORD_MAP:
        rows.append("%#x\t%#x\t%s" % (offset, size, rule))
    files["order_record.tsv"] = "\n".join(rows) + "\n"
    rows = ["copy\tbuilder\tlabel\tbid\task\tside\tasset\tdecimals\tmarkets\tmarket_dex\tassets\tdate\toutcome\tlimit"]
    for copy, case, outcome, limit in evidence["case_rows"]:
        rows.append("\t".join((str(copy), "%#x" % BUILDERS[copy], case.label, "%#x" % case.bid, "%#x" % case.ask,
                               "%#x" % case.side, str(case.asset), str(case.decimals), str(case.markets), str(case.market_dex),
                               str(case.assets), date_text(case.date), outcome, limit)))
    files["builder_cases.tsv"] = "\n".join(rows) + "\n"
    rows = ["helper\tlabel\tasset\tprice\tdecimals\tassets\tmarket_dex\tresult"]
    for helper, row, expected in evidence["tick_rows"]:
        result = str(expected["tick"]) if "tick" in expected else "%s %#x" % expected["stop"]
        rows.append("\t".join(("%#x" % helper, row[0], str(row[1]), str(row[2]), str(row[3]), str(row[4]), str(row[5]), result)))
    files["tick_cases.tsv"] = "\n".join(rows) + "\n"
    rows = ["name\tmeaning\tcases_caught\tfirst_caught"]
    for item in evidence["negatives"]:
        rows.append("\t".join((item["name"], item["meaning"], str(item["caught"]), item["first"])))
    files["negative_controls.tsv"] = "\n".join(rows) + "\n"
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
        "target": {"path": "artifacts/node/115/hl-node", "sha256": SHA256},
        "cases": evidence["cases"],
        "outcomes": dict(sorted(evidence["outcomes"].items())),
        "instructions_stepped": evidence["steps"],
        "mismatches": 0,
        "mutations": summary,
        "negative_controls": {item["name"]: item["caught"] for item in evidence["negatives"]},
        "locations": evidence["locations"],
        "builders": [{key: ("%#x" % value if key in ("start", "size", "best", "tick", "insert", "factor_zero_at", "factor_nonzero_at") else value)
                      for key, value in item.items()} for item in evidence["pins"]],
        "round": "%#x" % evidence["round_target"],
        "slots": {key: "%#x" % value for key, value in sorted(evidence["slot_targets"].items())},
        "no_price_word": "%#x" % NO_PRICE,
        "error_word": "%#x" % ERROR_WORD,
        "layout": {"book_asset": "%#x" % ASSET_FIELD, "book_best_pair": "%#x" % BEST_FIELD, "field_sets": [["%#x" % a, "%#x" % b] for a, b in FIELD_SETS], "market_stride": "%#x" % MARKET_STRIDE,
                   "market_assets": "%#x" % MARKET_ASSETS, "market_asset_count": "%#x" % MARKET_ASSET_COUNT,
                   "market_dex": "%#x" % MARKET_DEX, "asset_stride": "%#x" % ASSET_STRIDE,
                   "asset_decimals": "%#x" % ASSET_DECIMALS, "time": "%#x" % TIME_FIELD},
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
    parser.add_argument("--quick", action="store_true", help="skip the mutation pass (development only)")
    options = parser.parse_args(argv)
    files = render(analyse(load_image(), full=not options.quick))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
