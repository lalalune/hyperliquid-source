#!/usr/bin/env python3
"""Rebuild the node #115 TWAP slice step (order slice size, limit price, reschedule) and prove it on the bytes.

Four slice bodies (two perp copies 0x5a305e0 / 0x5a33760, two spot copies 0x5a31640 / 0x5a32be0) turn one
due TWAP record into either a 0x70-byte order slice or a hand-off to the advance function. The real
bytes of each body, plus the `round` (0x63efe40) and `floor` (0x63effe0) helpers they call, run in a
Python x86-64 evaluator with only the edges stubbed (the two lookup helpers, book top, tick lookup, spot
mid, fused multiply-add, recorder, call-once, panics, the advance callee). A separately written
specification predicts every stub call and every byte of the result. Conditions are then flipped on the
bytes to show that the comparison can fail. No disassembler or ELF dump text is parsed and the binary is
never executed. Standard library only.
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

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

PERP, SPOT = "perp", "spot"
# slice body, advance callee, family
COPIES = (
    dict(slice=0x5A305E0, advance=0x5A145D0, family=PERP, markets=0x7C8, count=0x7D0),
    dict(slice=0x5A33760, advance=0x5A13910, family=PERP, markets=0x1338, count=0x1340),
    dict(slice=0x5A31640, advance=0x5A13F70, family=SPOT),
    dict(slice=0x5A32BE0, advance=0x5A14C30, family=SPOT),
)
PERP_TICK = 0x5A01110
SPOT_TICK = 0x5A01310
SPOT_MID = 0x3C11290
LOOKUP_USER = 0x57F4AC0
LOOKUP_ORDER = 0x57F36B0
BOOK_TOP = 0x46DF820
DROP_ERROR = 0x44E0810
ROUND = 0x63EFE40
FLOOR = 0x63EFFE0
FMA = 0x63F0210
RECORDER = 0x4524E40
CALL_ONCE = 0x5C87D50
PANIC_UNWRAP = 0x1680C30
PANIC_INDEX = 0x1680CBF
ONCE_STATE = 0x64F01D8
ONCE_VALUE = 0x64F01C0
ONCE_VTABLE = 0x63FE250
ONCE_LOCATION = 0x63FE278
LOCATION_MARKET = 0x648B990
LOCATION_BOOKS = 0x647DC08
LOCATION_SZ = 0x64B7FC8
UNWRAP_SIZE = 0x2B
ERROR_WORD = 0x156
DIVISOR = 10000
MARKET_STRIDE = 0x510
BOOK_STRIDE = 0x120
BOOK_TOP_FIELD = 0xA8
MARKETS_FIELD = 0x7C8
COUNT_FIELD = 0x7D0
SPOT_MID_FIELD = 0x80
SPOT_TICK_FIELD = 0x90
BUCKET_SECONDS = 60.0
THRESHOLDS = {PERP: dict(whole=30000000, floor=12000000), SPOT: dict(whole=3000000000, floor=1200000000)}
JITTER_MODULUS = 40
CATCH_UP = 3
SIG_FIGS = 5
SLICE_SIZE = 0x70
USER_STRIDE = 0x38
ORDER_STRIDE = 0x70
BTREE_TAG = 0x8000000000000000

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
STEP_LIMIT = 300000
MUTANT_STEP_LIMIT = 6000


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
STEP_LIMIT = 300000
MUTANT_STEP_LIMIT = 8000
FAKE_MEMCMP = 0x7E000000



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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd"}
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


# ---- specification ----


def lcg(variant):
    """A small fixed generator so the sampled cases are the same on every run."""
    state = (variant * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 16


def user_id(number):
    return bytes((number * 37 + index * 11 + 5) & 0xFF for index in range(20))


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


def pack_date(year, ordinal, flags=0):
    return ((year << 13) | (ordinal << 4) | flags) & MASK[4]


def time_key(moment):
    return signed32(moment[0]), moment[1] & MASK[4], moment[2] & MASK[4]


def time_bytes(moment):
    return struct.pack("<III", *(value & MASK[4] for value in moment))


def days_from_ce(date):
    """Days from the Unix epoch for chrono's packed date: year above bit 13, ordinal in bits 4..12."""
    packed = signed32(date)
    year = packed >> 13
    ordinal = (packed >> 4) & 0x1FF
    shift = 0
    last = year - 1
    if last < 0:
        cycles = (-last) // 400 + 1
        last += cycles * 400
        shift = -cycles * 146097
    return ordinal + shift + last * 365 + last // 4 - last // 100 + last // 400 - 719163


def unix_millis(moment):
    return days_from_ce(moment[0]) * 86400 * 1000 + moment[1] * 1000 + moment[2] // 1000000


def saturate(value):
    """f64 to u64: NaN and infinities give 0, negatives 0, values above the top u64::MAX."""
    if value != value or value in (math.inf, -math.inf) or value <= 0.0:
        return 0
    return MASK[8] if value >= 18446744073709551616.0 else int(value)


def duration_steps(duration):
    """2 * (duration / 60) + 1, saturating; only a negative or NaN duration trips the assertion."""
    if duration != duration or duration < 0.0:
        return None
    buckets = saturate(duration / BUCKET_SECONDS)
    return MASK[8] if buckets >= 1 << 63 else 2 * buckets + 1


def round_half_away(value):
    whole = float(math.floor(abs(value))) if abs(value) < 4503599627370496.0 else abs(value)
    if abs(value) - whole >= 0.5:
        whole += 1.0
    return math.copysign(whole, value)


def fused(left, right, extra):
    exact = fractions.Fraction(left) * fractions.Fraction(right) + fractions.Fraction(extra)
    return float(exact) if exact else 0.0


def five_figures(size):
    unit = 1
    while size >= unit * 10 ** SIG_FIGS:
        unit *= 10
    return size // unit * unit



# ---- node #115 specification ----

def duration_steps(duration):
    """2 * saturate(duration / 60) + 1, saturating. No assertion: negative, NaN and infinite durations count as 0."""
    buckets = saturate(duration / BUCKET_SECONDS)
    return MASK[8] if buckets >= 1 << 63 else 2 * buckets + 1


def ceil_div(left, right):
    return (left + right - 1) // right


class Order:
    """One 0x60-byte TWAP value in node #115 layout. Unnamed fields stay a ramp, so a wrong field read shows."""

    def __init__(self, asset=20003, total=1000000, duration=3600.0, side=0, reduce_only=0, randomize=0, executed=0, counter=7,
                 owner=None, raw_duration=None):
        self.asset, self.total, self.duration, self.side = asset, total, duration, side
        self.reduce_only, self.randomize, self.executed, self.counter = reduce_only, randomize, executed, counter
        self.owner = owner
        self.raw_duration = raw_duration

    def float_duration(self):
        return self.duration if self.raw_duration is None else to_float(self.raw_duration)

    def body(self, user):
        out = bytearray((index * 13 + 0x31) & 0xFF for index in range(0x68))
        bits = self.raw_duration if self.raw_duration is not None else to_bits(self.duration)
        struct.pack_into("<QQQ", out, 0, self.asset, self.total, bits)
        out[0x20], out[0x21], out[0x22] = self.reduce_only, self.randomize, self.side
        struct.pack_into("<Q", out, 0x30, self.executed)
        struct.pack_into("<Q", out, 0x40, self.counter)
        out[0x54:0x68] = self.owner or user_id(user)
        return bytes(out)


class SliceCase:
    def __init__(self, label, order=None, oid=5, user=1, now=None, flag=0, once=0, top=(1000000, 1000200), mid=1000100, tick=100,
                 markets=3, books=5, users=(5, 2, 1, 0), orders=(5, 2, 1, 0), lookup="found", **fields):
        """users / orders: (capacity, head, length, logical index). lookup: found, absent, beyond (index past length)."""
        self.label, self.order = label, order or Order(**fields)
        self.oid, self.user = oid, user
        self.now = now or (pack_date(2025, 100), 3600, 123456789)
        self.flag, self.once, self.top, self.mid, self.tick = flag, once, top, mid, tick
        self.markets, self.books = markets, books
        self.users, self.orders, self.lookup = users, orders, lookup


H = HEAP_BASE
RESULT, HOLDER, CAPTURE, ROW_AT, NOW_AT, FLAG_AT = H + 0x100, H + 0x200, H + 0x240, H + 0x300, H + 0x340, H + 0x360
COLLECTION, OUTER, TRACKER, VECTOR = H + 0x380, H + 0x400, H + 0xC00, H + 0x30000
MARKETS, BOOKS, USERS, ORDERS = H + 0x10000, H + 0x14000, H + 0x20000, H + 0x24000
USED = 0x28000


def advance_call(case):
    return ("advance", TRACKER, case.order.owner or user_id(case.user), case.oid, OUTER, VECTOR)


def lookup_events(case):
    events = [("find user", TRACKER + 0x18, user_id(case.user))]
    if case.lookup in ("found", "absent2") and case.users[3] < case.users[2]:
        events.append(("find order", USERS + phys(case.users) * USER_STRIDE + 0x18, case.oid))
    return events


def phys(ring):
    capacity, head, length, index = ring
    at = index + head
    return at - capacity if at >= capacity else at


def spec_slice(copy, case, variant=""):
    """Expected events and result of one slice call."""
    row = COPIES[copy]
    order = case.order
    events = []
    if case.lookup == "absent" or case.users[3] >= case.users[2]:
        return {"events": [("find user", TRACKER + 0x18, user_id(case.user))], "tag": 2}
    events = lookup_events(case)
    if case.lookup == "absent2" or case.orders[3] >= case.orders[2]:
        return {"events": events, "tag": 2}
    steps = duration_steps(order.float_duration())
    if variant == "assert_negative" and not order.float_duration() >= 0.0:
        return {"events": events, "stop": ("assert", 0, 0, 0)}
    once = ("once", ONCE_STATE, 1, ONCE_VTABLE, ONCE_LOCATION, ONCE_VALUE)
    if case.flag:
        return {"events": events + ([once] if case.once else []) + [advance_call(case)], "tag": 2}
    asset = order.asset
    dex, local = asset // DIVISOR, asset % DIVISOR
    if row["family"] == PERP:
        if dex >= case.markets:
            return {"events": events, "stop": ("unwrap", LOCATION_MARKET, ERROR_WORD, UNWRAP_SIZE)}
        events.append(("drop", ERROR_WORD))
        if local >= case.books:
            return {"events": events, "stop": ("index", local, case.books, LOCATION_BOOKS)}
        events.append(("top", BOOKS + local * BOOK_STRIDE + BOOK_TOP_FIELD))
        first, second = case.top
        mid = (first & second) + ((first ^ second) >> 1)
        if variant == "mid_sum":
            mid = ((first + second) & MASK[8]) // 2
        if not first or not second:
            return {"events": events + [advance_call(case)], "tag": 2}
    else:
        events.append(("mid", OUTER + SPOT_MID_FIELD, asset, COLLECTION))
        mid = case.mid
        if not mid:
            return {"events": events + [advance_call(case)], "tag": 2}
    factor = 0.97 if order.side else 1.03
    if variant == "factor_swap":
        factor = 1.03 if order.side else 0.97
    priced = max(round_half_away(factor * float(mid)), 0.0)
    if variant == "trunc_price":
        priced = float(int(factor * float(mid)))
    limit = max(saturate(priced), 1)
    if row["family"] == PERP:
        events.append(("tick", MARKETS + dex * MARKET_STRIDE, asset, limit))
    else:
        events.append(("tick", OUTER + SPOT_TICK_FIELD, asset, limit))
    units = limit // case.tick
    if order.side and variant != "no_up_tick":
        units = min(units + 1, MASK[8])
    price = units * case.tick
    price = max(MASK[8] if price > MASK[8] else price, 1)
    total, executed, counter = order.total, order.executed, order.counter
    ratio = float(total) / float(steps)
    if counter == steps:
        target = total
    else:
        if order.randomize and variant != "jitter_off":
            jitter = max(unix_millis(case.now), 0) % JITTER_MODULUS / 100.0 + -0.2
            value = fused(ratio, float(counter), jitter * ratio)
        else:
            value = float(counter) * ratio
        target = saturate(math.floor(value) if value == value and abs(value) != math.inf else value)
    if target < executed:
        return {"events": events + [advance_call(case)], "tag": 2}
    want = target - executed
    remaining = total - executed
    if remaining < 0:
        events.append(("recorder", LOCATION_SZ))
        remaining = 0
    size = remaining
    limits = THRESHOLDS[row["family"]]
    if (price * remaining >= limits["whole"]) if variant == "ge_threshold" else (price * remaining > limits["whole"]):
        floor = ceil_div(limits["floor"], price) if price <= limits["floor"] else 1
        if variant in ("floor_zero", "size_order_94"):
            floor = limits["floor"] // price if price <= limits["floor"] else 0
        cap = saturate(ratio)
        cap = MASK[8] if cap * CATCH_UP >= MASK[8] else cap * CATCH_UP + (0 if variant == "cap_no_plus" else 1)
        size = max(min(cap, want), floor)
        if variant == "size_order_94":
            size = min(cap, max(want, floor))
        left = total - executed
        if left < 0:
            events.append(("recorder", LOCATION_SZ))
            left = 0
        if variant != "left_not_min":
            size = min(size, left)
        if counter < steps or variant == "round_always":
            size = five_figures(size)
    if not size:
        return {"events": events + [advance_call(case)], "tag": 2}
    fields = {0: struct.pack("<Q", 1), 8: struct.pack("<Q", size), 0x10: b"\x03", 0x19: b"\x02", 0x20: struct.pack("<Q", price),
              0x28: struct.pack("<Q", asset), 0x30: bytes((order.side, order.reduce_only, 0)), 0x48: struct.pack("<Q", asset),
              0x50: struct.pack("<Q", case.oid), 0x58: order.owner or user_id(case.user)}
    return {"events": events, "tag": 1, "fields": fields}


def expected_bytes(fields):
    out = bytearray([STACK_MARK]) * SLICE_SIZE
    for offset, value in fields.items():
        out[offset:offset + len(value)] = value
    return bytes(out)


# ---- harness ----

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.machine.step_limit = STEP_LIMIT if not patches else MUTANT_STEP_LIMIT
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        slots = {}
        for row in COPIES:
            start, end = image.exact_fde(row["slice"])
            for insn in decode_range(image, start, end):
                if insn.op == "calli" and insn.a[0] == "m" and insn.a[1] is None:
                    slots[insn.a[4]] = relative[insn.a[4]]
        for slot, target in slots.items():
            machine.memory.statics[slot] = target
        machine.slots = {FMA: self.on_fma, RECORDER: self.on_recorder, CALL_ONCE: self.on_once, PANIC_UNWRAP: self.on_unwrap,
                         PANIC_INDEX: self.on_index, SPOT_MID: self.on_mid}
        machine.calls = {LOOKUP_USER: self.on_find_user, LOOKUP_ORDER: self.on_find_order, BOOK_TOP: self.on_top,
                         DROP_ERROR: self.on_drop, PERP_TICK: self.on_tick, SPOT_TICK: self.on_tick}
        for row in COPIES:
            machine.calls[row["advance"]] = self.on_advance
        self.events = []

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def ring(self, at, capacity, buffer, head, length):
        self.word(at, capacity)
        self.word(at + 8, buffer)
        self.word(at + 0x10, head)
        self.word(at + 0x18, length)

    def run_slice(self, copy, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        memory.statics[ONCE_STATE] = case.once
        machine.real = frozenset((ROUND, FLOOR))
        self.events = []
        self.case = case
        row = COPIES[copy]
        # users: a ring of 0x38 entries whose +0x18 holds the order ring
        capacity, head, length, index = case.users
        self.ring(TRACKER + 0x18, capacity, USERS, head, length)
        for slot in range(capacity):
            memory.put_bytes(USERS + slot * USER_STRIDE, bytes((slot * 29 + at + 3) & 0xFF for at in range(USER_STRIDE)))
        ocap, ohead, olen, oindex = case.orders
        entry = USERS + phys(case.users) * USER_STRIDE
        self.ring(entry + 0x18, ocap, ORDERS, ohead, olen)
        for slot in range(ocap):
            memory.put_bytes(ORDERS + slot * ORDER_STRIDE, bytes((slot * 17 + at * 5 + 1) & 0xFF for at in range(ORDER_STRIDE)))
        if case.lookup == "found" and oindex < olen:
            memory.put_bytes(ORDERS + phys(case.orders) * ORDER_STRIDE + 8, case.order.body(case.user))
        memory.put_bytes(NOW_AT, struct.pack("<III", *(value & MASK[4] for value in case.now)))
        self.word(FLAG_AT, case.flag, 1)
        self.word(COLLECTION + 8, BOOKS)
        self.word(COLLECTION + 0x10, case.books)
        for decoy in (0x7C8, 0x1338):
            self.word(OUTER + decoy, 0xBAD0000 + decoy)
            self.word(OUTER + decoy + 8, 0x99)
        if row["family"] == PERP:
            self.word(OUTER + row["markets"], MARKETS)
            self.word(OUTER + row["count"], case.markets)
        for at, value in enumerate((TRACKER, NOW_AT, FLAG_AT, COLLECTION, OUTER, VECTOR)):
            self.word(CAPTURE + at * 8, value)
        self.word(HOLDER, CAPTURE)
        memory.put_bytes(ROW_AT, user_id(case.user))
        self.word(ROW_AT + 0x18, case.oid)
        try:
            machine.run(row["slice"], {RDI: RESULT, RSI: HOLDER, RDX: ROW_AT})
        except Panicked as stop:
            return {"events": self.events, "stop": stop.args[0]}
        out = {"events": self.events, "tag": memory.read(RESULT, 8)}
        if out["tag"] == 1:
            out["bytes"] = memory.bytes_at(RESULT, SLICE_SIZE)
        return out

    # -- stubs --

    def found(self, machine, ring_index, absent):
        machine.keep_rdx = True
        machine.regs[RAX] = 1 if absent else 0
        machine.regs[RDX] = ring_index

    def on_find_user(self, machine):
        regs = machine.regs
        self.events.append(("find user", regs[RDI], machine.memory.bytes_at(regs[RSI], 20)))
        self.found(machine, self.case.users[3], self.case.lookup == "absent")

    def on_find_order(self, machine):
        regs = machine.regs
        self.events.append(("find order", regs[RDI], machine.memory.read(regs[RSI], 8)))
        self.found(machine, self.case.orders[3], self.case.lookup == "absent2")

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_top(self, machine):
        self.events.append(("top", machine.regs[RSI]))
        machine.memory.write(machine.regs[RDI], 8, self.case.top[0])
        machine.memory.write(machine.regs[RDI] + 8, 8, self.case.top[1])

    def on_mid(self, machine):
        self.events.append(("mid", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = self.case.mid

    def on_tick(self, machine):
        self.events.append(("tick", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = self.case.tick

    def on_fma(self, machine):
        left, right, extra = to_float(machine.xmm[0] & MASK[8]), to_float(machine.xmm[1] & MASK[8]), to_float(machine.xmm[2] & MASK[8])
        machine.xmm[0] = to_bits(fused(left, right, extra))
        machine.keep_float = True

    def on_recorder(self, machine):
        self.events.append(("recorder", machine.regs[RSI]))

    def on_advance(self, machine):
        regs = machine.regs
        self.events.append(("advance", regs[RDI], machine.memory.bytes_at(regs[RSI], 20), regs[RDX], regs[RCX], regs[R8]))

    def on_once(self, machine):
        regs = machine.regs
        reference = machine.memory.read(machine.memory.read(regs[RDX], 8), 8)
        self.events.append(("once", regs[RDI], regs[RSI] & 0xFF, regs[RCX], regs[R8], reference))

    def on_unwrap(self, machine):
        regs = machine.regs
        raise Panicked(("unwrap", regs[R8], machine.memory.read(regs[RDX], 2), regs[RSI]))

    def on_index(self, machine):
        regs = machine.regs
        raise Panicked(("index", regs[RDI], regs[RSI], regs[RDX]))


# ---- cases ----

def nan_bits():
    return 0x7FF8000000000000


DURATIONS = (3600.0, 60.0, 59.9, 120.0, 0.0, -0.0, -1.0, float("nan"), float("inf"), 5e-324, 86400.0, 1e18, 1e300, 604800.0, 30.0, 1e6)
TOTALS = (1, 7, 99999, 100000, 1000000, 123456789, 10 ** 12, 10 ** 15, 1 << 63, MASK[8] - 1, MASK[8], 500000, 31)
TOPS = ((1000000, 1000200), (0, 5), (7, 0), (1, 1), (MASK[8], MASK[8]), (1 << 63, 3), (999, 1001), (50, 51), (2, 3), (12345, 54321))
MIDS = (1, 999, 1000100, 10 ** 9, 1 << 63, MASK[8], 0, 25, 4000000)
TICKS = (1, 10, 100, 1000, 3, 7, 100000, 1 << 40)
NOWS = ((pack_date(2025, 100), 3600, 123456789), (pack_date(2000, 1), 0, 0), (pack_date(2024, 366), 86399, 999999999),
        (pack_date(2030, 200), 40000, 777777777), (pack_date(1999, 365), 1, 1000000), (pack_date(2026, 311), 12345, 987654321))
ASSETS = (20003, 10000, 0, 4, 20002, 20001, 30001, 10004, 3, 9999, 40001, 20004, 10002, 30000)


def pick(source, pool):
    return pool[next(source) % len(pool)]


def make_case(copy, source, number):
    duration = pick(source, DURATIONS)
    steps = duration_steps(duration)
    total = pick(source, TOTALS)
    executed = pick(source, (0, 1, total // 3, total // 2, max(total - 1, 0), total, min(total + 5, MASK[8]), 12345, MASK[8]))
    counter = pick(source, (0, 1, 2, steps - 1 if steps else 0, steps, min(steps + 1, MASK[8]), 7, 59, MASK[8], 100))
    kind = next(source) % 40
    lookup = "found"
    if kind == 0:
        lookup = "absent"
    elif kind == 1:
        lookup = "absent2"
    capacity = 1 + next(source) % 9
    ocapacity = 1 + next(source) % 9
    length = 1 + next(source) % capacity
    olength = 1 + next(source) % ocapacity
    users = (capacity, next(source) % capacity, length, next(source) % length if kind != 2 else length + next(source) % 3)
    orders = (ocapacity, next(source) % ocapacity, olength, next(source) % olength if kind != 3 else olength + next(source) % 3)
    asset = pick(source, ASSETS)
    family = COPIES[copy]["family"]
    markets = 3 if kind % 7 else 2 + next(source) % 3
    books = 5 if kind % 5 else next(source) % 12
    top = pick(source, TOPS)
    mid = pick(source, MIDS)
    flag = 1 if kind in (4, 5, 6) else 0
    order = Order(asset=asset, total=total, duration=duration, side=next(source) & 1, reduce_only=next(source) & 1,
                  randomize=1 if next(source) % 3 == 0 else 0, executed=executed, counter=counter)
    return SliceCase("%s-%d" % (family, number), order=order, oid=1 + next(source) % 1000, user=1 + next(source) % 50, now=pick(source, NOWS),
                     flag=flag, once=next(source) & 1, top=top, mid=mid, tick=pick(source, TICKS), markets=markets, books=books,
                     users=users, orders=orders, lookup=lookup)


def edge_cases(copy):
    """Fixed cases on the exact thresholds, on saturating clamps and on negative jitter."""
    family = COPIES[copy]["family"]
    whole = THRESHOLDS[family]["whole"]
    number = 0
    for mid, tick, price in ((97, 100, 100), (10, 10, 10), (971, 1000, 1000), (1, 1, 1)):
        for delta in (-1, 0, 1):
            for counter in (60, 121):
                remaining = whole // price + delta
                top = (mid, mid)
                yield SliceCase("%s-edge-%d" % (family, number), order=Order(asset=20003, total=remaining, duration=3600.0, counter=counter),
                                top=top, mid=mid, tick=tick)
                number += 1
    for counter in (MASK[8] - 1, MASK[8], 1 << 63, (1 << 63) + 1000, 5, 0):
        for randomize in (0, 1):
            for total in (MASK[8], 1 << 63):
                yield SliceCase("%s-edge-%d" % (family, number), order=Order(asset=20003, total=total, duration=1e300, counter=counter,
                                                                              randomize=randomize), top=(1000, 1000), mid=1000, tick=1)
                number += 1
    for now in NOWS:
        for counter in (0, 1, 2):
            yield SliceCase("%s-edge-%d" % (family, number), order=Order(asset=20003, total=10 ** 12, duration=3600.0, counter=counter,
                                                                          randomize=1), now=now)
            number += 1
    for side in (0, 1):
        for mid in (MASK[8], 1 << 63, (1 << 62) + 3):
            yield SliceCase("%s-edge-%d" % (family, number), order=Order(asset=20003, side=side), top=(mid, mid), mid=mid, tick=3)
            number += 1


def cases_for(copy, count):
    yield from edge_cases(copy)
    source = lcg(copy + 1)
    for number in range(count):
        yield make_case(copy, source, number)


# ---- comparison ----

def outcome_of(actual):
    if "stop" in actual:
        return "panic"
    if actual["tag"] == 1:
        return "order"
    return "reschedule" if any(event[0] == "advance" for event in actual["events"]) else "none"


def matches(actual, expected):
    if actual["events"] != expected["events"]:
        return False
    if ("stop" in actual) != ("stop" in expected):
        return False
    if "stop" in expected:
        return actual["stop"] == expected["stop"]
    if actual["tag"] != expected["tag"]:
        return False
    return expected["tag"] != 1 or actual["bytes"] == expected_bytes(expected["fields"])


def check(harness, copy, case, spec=None):
    expected = (spec or spec_slice)(copy, case)
    try:
        actual = harness.run_slice(copy, case)
    except (Halt, Panicked, EvidenceError, ZeroDivisionError):
        return False, expected, None
    return matches(actual, expected), expected, actual


def analyse(image, per_copy, rows_every, mutants=True):
    harness = Harness(image)
    counts = {}
    outcomes = {}
    mismatches = []
    rows = []
    seen = [set() for _ in COPIES]
    for copy in range(len(COPIES)):
        for number, case in enumerate(cases_for(copy, per_copy)):
            before = len(harness.machine.seen)
            ok, expected, actual = check(harness, copy, case)
            counts[copy] = counts.get(copy, 0) + 1
            if not ok:
                mismatches.append((copy, number, case.label))
                continue
            kind = outcome_of(actual)
            outcomes[(copy, kind)] = outcomes.get((copy, kind), 0) + 1
            if number % rows_every == 0:
                size = struct.unpack_from("<Q", actual["bytes"], 8)[0] if kind == "order" else 0
                price = struct.unpack_from("<Q", actual["bytes"], 0x20)[0] if kind == "order" else 0
                rows.append((copy, number, kind, size, price, len(actual["events"])))
    return harness, counts, outcomes, mismatches, rows


# ---- mutation, variants, evidence ----

VARIANTS = ("assert_negative", "mid_sum", "factor_swap", "trunc_price", "no_up_tick", "jitter_off", "ge_threshold", "floor_zero",
            "cap_no_plus", "size_order_94", "left_not_min", "round_always")
VARIANT_NOTE = {
    "assert_negative": "node #94 rule: a negative or NaN duration trips an assertion",
    "mid_sum": "mid as (a + b) // 2 instead of the carry-free average",
    "factor_swap": "1.03 for side 1 and 0.97 for side 0",
    "trunc_price": "truncate instead of round half away",
    "no_up_tick": "no extra tick for side 1",
    "jitter_off": "ignore the jitter switch",
    "ge_threshold": "whole-remainder test with >= instead of >",
    "floor_zero": "node #94 rule: minimum size is floor(unit / price), 0 above the unit",
    "cap_no_plus": "cap is 3 * even without the +1",
    "size_order_94": "node #94 order: min(cap, max(want, floor)) instead of max(min(cap, want), floor)",
    "left_not_min": "skip the final min with the unexecuted total",
    "round_always": "five-figure rounding even on the last step",
}


def jcc_patch(image, row):
    at = image.offset(row.va)
    first = image.blob[at]
    if 0x70 <= first <= 0x7F:
        return row.va, first ^ 1
    if first == 0x0F and 0x80 <= image.blob[at + 1] <= 0x8F:
        return row.va + 1, image.blob[at + 1] ^ 1
    return None


def detects(image, copy, patches, probe):
    harness = Harness(image, patches)
    for case in probe:
        try:
            ok, _, _ = check(harness, copy, case)
        except Exception:  # a crashed mutant is a detected mutant
            return True
        if not ok:
            return True
    return False


def run_mutants(image, seen, probe, probe2, limit):
    rows = []
    for copy in (0, 2):
        start, end = image.exact_fde(COPIES[copy]["slice"])
        sites = []
        for row in decode_range(image, start, end):
            if row.op == "jcc" and row.va in seen:
                patch = jcc_patch(image, row)
                if patch:
                    sites.append((row.va, patch))
        step = max(1, len(sites) // limit)
        for va, (at, byte) in sites[::step]:
            patches = {at: byte}
            caught = detects(image, copy, patches, probe[copy])
            stage = 1
            if not caught:
                caught = detects(image, copy, patches, probe2[copy])
                stage = 2
            rows.append((copy, va, at, byte, "detected" if caught else "survived", stage))
    return rows


def copy_rows(image, copy):
    start, end = image.exact_fde(COPIES[copy]["slice"])
    return start, end, decode_range(image, start, end)


def shape(row, start):
    target = row.target
    if row.op in ("jcc", "jmp") and target is not None:
        target = target - start
    return (row.op, row.a, row.b, row.width, row.cc, target if row.op != "call" else None)


def copy_differences(image):
    out = []
    for first, second in ((0, 1), (2, 3)):
        sa, ea, ra = copy_rows(image, first)
        sb, eb, rb = copy_rows(image, second)
        if len(ra) != len(rb):
            out.append((first, second, -1, 0, 0, "instruction count", len(ra), len(rb)))
        for index, (x, y) in enumerate(zip(ra, rb)):
            if shape(x, sa) != shape(y, sb):
                out.append((first, second, index, x.va, y.va, x.op, shape(x, sa)[1:], shape(y, sb)[1:]))
            elif x.op == "call" and x.target != y.target:
                out.append((first, second, index, x.va, y.va, "call target", hex(x.target), hex(y.target)))
    return out


def table(rows):
    return "".join("\t".join(str(cell) for cell in row) + "\n" for row in rows)


def tsv_cell(value):
    return str(value).replace("\t", " ").replace("\n", " ")


def build(image, per_copy, rows_every, mutant_limit):
    harness, counts, outcomes, mismatches, rows = analyse(image, per_copy, rows_every)
    seen = harness.machine.seen
    coverage = []
    for copy in range(len(COPIES)):
        start, end, decoded = copy_rows(image, copy)
        stepped = sum(1 for row in decoded if row.va in seen)
        coverage.append((copy, hex(start), hex(end), end - start, len(decoded), stepped))
    probe = {copy: list(cases_for(copy, 300)) for copy in range(4)}
    probe2 = {copy: list(cases_for(copy, 1200)) for copy in range(4)}
    mutants = run_mutants(image, seen, probe, probe2, mutant_limit)
    variants = []
    for variant in VARIANTS:
        first = None
        wrong = 0
        tried = 0
        for copy in range(4):
            for number, case in enumerate(cases_for(copy, 800)):
                ok, _, _ = check(harness, copy, case, lambda c, k, v=variant: spec_slice(c, k, v))
                tried += 1
                if not ok:
                    wrong += 1
                    if first is None:
                        first = case.label
        variants.append((variant, VARIANT_NOTE[variant], first or "-", wrong, tried))
    return harness, counts, outcomes, mismatches, rows, coverage, mutants, variants


def corrupt_controls(image):
    """Three structural negatives: wrong digest, address outside every FDE, address that is not an FDE start."""
    results = []
    for label, action in (("wrong digest", lambda: load_image(BINARY, "0" * 64)),
                          ("outside every FDE", lambda: image.fde(0x10)),
                          ("not an FDE start", lambda: image.exact_fde(COPIES[0]["slice"] + 1))):
        try:
            action()
            results.append((label, False))
        except EvidenceError:
            results.append((label, True))
    return results


def render(image, per_copy, rows_every, mutant_limit):
    harness, counts, outcomes, mismatches, rows, coverage, mutants, variants = build(image, per_copy, rows_every, mutant_limit)
    if mismatches:
        raise EvidenceError("%d mismatches, first %r" % (len(mismatches), mismatches[0]))
    controls = corrupt_controls(image)
    detected_mutants = sum(1 for row in mutants if row[4] == "detected")
    survivors = len(mutants) - detected_mutants
    detected_variants = sum(1 for row in variants if row[3] > 0)
    negative = len(mutants) - survivors + len(variants) + len(controls)
    detected = detected_mutants + detected_variants + sum(1 for _, ok in controls if ok)
    total = sum(counts.values())
    files = {}
    files["cases.tsv"] = "copy\tcase\toutcome\tsize\tprice\tstub events\n" + table(
        (COPIES[c]["slice"] and hex(COPIES[c]["slice"]), n, k, s, p, e) for c, n, k, s, p, e in rows)
    files["outcomes.tsv"] = "copy\toutcome\tcases\n" + table(
        (hex(COPIES[c]["slice"]), k, outcomes[(c, k)]) for c, k in sorted(outcomes))
    files["copies.tsv"] = "copy\tstart\tend\tbytes\tinstructions\tstepped\tfamily\tadvance callee\tmarkets field\tcount field\n" + table(
        (hex(COPIES[c]["slice"]),) + coverage[c][1:] + (COPIES[c]["family"], hex(COPIES[c]["advance"]),
                                                       hex(COPIES[c].get("markets", 0)), hex(COPIES[c].get("count", 0)))
        for c in range(len(COPIES)))
    files["copy_differences.tsv"] = "first\tsecond\tindex\tva first\tva second\twhat\tfirst\tsecond\n" + table(
        tuple(tsv_cell(cell) for cell in row) for row in copy_differences(image))
    files["mutants.tsv"] = "copy\tjcc va\tpatched byte va\tnew byte\tresult\tstage\n" + table(
        (hex(COPIES[c]["slice"]), hex(v), hex(a), hex(b), r, s) for c, v, a, b, r, s in mutants)
    files["variants.tsv"] = "variant\tmeaning\tfirst case where the bytes disagree\tdisagreeing cases\tcases tried\n" + table(variants)
    files["controls.tsv"] = "control\tdetected\n" + table(controls)
    summary = dict(binary_sha256=SHA256, cases=total, mismatches=len(mismatches), per_copy=per_copy,
                   coverage=[dict(copy=c[1], bytes=c[3], instructions=c[4], stepped=c[5]) for c in coverage],
                   mutants=len(mutants), mutants_detected=detected_mutants, survivors=survivors,
                   variants=len(variants), variants_detected=detected_variants, controls=len(controls))
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    measure = dict(cases=total, negative_controls=negative, negative_detected=detected, mutants_tried=len(mutants),
                   mutants_survived=survivors)
    files["measure.json"] = json.dumps(measure, indent=1, sort_keys=True) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (folder / name).write_text(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=2800, help="cases per slice copy")
    parser.add_argument("--sample", type=int, default=3, help="keep every Nth case in cases.tsv")
    parser.add_argument("--mutants", type=int, default=70, help="jcc flips per representative copy")
    args = parser.parse_args(argv)
    image = load_image()
    write_outputs(args.out, render(image, args.cases, args.sample, args.mutants))
    return 0


if __name__ == "__main__":
    sys.exit(main())
