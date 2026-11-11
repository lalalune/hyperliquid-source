#!/usr/bin/env python3
"""Rebuild the node #115 TWAP advance step (reschedule 30 s on, or hand the finished order on) and prove it on the bytes.

Four advance bodies (perp 0x5a145d0 / 0x5a13910, spot 0x5a13f70 / 0x5a14c30) look the user up in the tracker, look the order
up in the user's order ring, move the due moment on by 30 s (catching up past the clock in whole 30 s steps), count the step,
and then either push a heap entry for the next step or hand the finished order to a finish callee. The real bytes of each
body plus the entry helper (0x4dc5ad0 / 0x4dc2040) and the entry resolver (0x4da6d70 / 0x4da7360) run in a Python x86-64
evaluator with only the edges stubbed (the ring lookups, the ring insert for a missing user, four chrono calls, ceil, the heap
push and the finish callee). A separately written specification predicts every stub call, the order record and the user
ring afterwards. Conditions are then flipped on the bytes to show that the comparison can fail. No disassembler or ELF dump
text is parsed and the binary is never executed. Standard library only.
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
        if two == 0x13 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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

H = HEAP_BASE
RESULT, HOLDER, CAPTURE, ROW_AT, NOW_AT, FLAG_AT = H + 0x100, H + 0x200, H + 0x240, H + 0x300, H + 0x340, H + 0x360
COLLECTION, OUTER, TRACKER, VECTOR = H + 0x380, H + 0x400, H + 0xC00, H + 0x30000
MARKETS, BOOKS, USERS, ORDERS = H + 0x10000, H + 0x14000, H + 0x20000, H + 0x24000
USED = 0x28000


def phys(ring):
    capacity, head, length, index = ring
    at = index + head
    return at - capacity if at >= capacity else at


# ---- node #115 advance step ----

# advance body, tracker entry helper, entry resolver, finish callee, family
ADVANCE = (
    dict(advance=0x5A145D0, entry=0x4DC5AD0, resolve=0x4DA6D70, finish=0x5A17DD0, family=PERP),
    dict(advance=0x5A13910, entry=0x4DC5AD0, resolve=0x4DA6D70, finish=0x5A18190, family=PERP),
    dict(advance=0x5A13F70, entry=0x4DC2040, resolve=0x4DA7360, finish=0x5A18550, family=SPOT),
    dict(advance=0x5A14C30, entry=0x4DC2040, resolve=0x4DA7360, finish=0x5A18840, family=SPOT),
)
PROMOTE = {PERP: 0x515A060, SPOT: 0x51581B0}
INSERT_USER = 0x57ECF00
INSERT_USER_SPOT = 0x57EA4B0
BOUNDARY = {0x515A060: "ring to tree promotion", 0x524ED60: "drop of a replaced container", 0x57DD230: "ring drop of two slices",
            0x5B99360: "tree to ring conversion", 0x51ECAB0: "tree entry insert", 0x51581B0: "spot ring promotion",
            0x57DE6D0: "spot ring drop", 0x5B7E600: "spot tree conversion"}
SLOT_TIME_ADD, SLOT_DATE_ADD, SLOT_TIME_SUB, SLOT_SECS, SLOT_CEIL = 0x64E0F78, 0x64E0AA0, 0x64E0FC0, 0x64E0F70, 0x64E7858
DEFAULT_MOMENT = 0x4679D0
FLOAT_AT = dict(nanos_divisor=0x458D50, zero_test=0x459010, step=0x458CD8, bucket=0x459718)
STEP_SECONDS = 30
NANOS = 1000000000
USER_AT, ENTRY_AT = H + 0x500, H + 0x540
FINISH_TAG = 0x8000000000000002
DAY_UNIT = 86400
# the two range tests on the carried seconds, as immediates read from the compare chain
CARRY_ADD_1, CARRY_LIMIT_1 = 0xFFDF3B645A1CAC08, 0xFFBE76C8B4395811
CARRY_ADD_2, CARRY_LIMIT_2 = 0xFFFF574000000000, 0xFFFEAE7FFFFEAE81
BYTE_PINS = (
    (0x5A1470C, b"\x49\xbf" + struct.pack("<Q", CARRY_ADD_1), "carry range test 1, add"),
    (0x5A14716, b"\x49\xbe" + struct.pack("<Q", CARRY_LIMIT_1), "carry range test 1, limit"),
    (0x5A14760, b"\x48\xb9" + struct.pack("<Q", CARRY_ADD_2), "carry range test 2, add"),
    (0x5A1476D, b"\x48\xba" + struct.pack("<Q", CARRY_LIMIT_2), "carry range test 2, limit"),
)


def mc_time_add(secs, nanos, dsecs, dnanos):
    """Contract of the chrono time add: (secs, nanos, whole seconds carried out of the day)."""
    total_nanos = nanos + dnanos
    total = secs + dsecs + total_nanos // NANOS
    kept = total % DAY_UNIT
    return kept, total_nanos % NANOS, (total - kept) & MASK[8]


def mc_date_add(date, days):
    """Contract of the chrono date add: packed ordinal arithmetic only."""
    return (date + (days << 4)) & MASK[4]


def mc_time_sub(now, moment):
    """now - moment as (secs, nanos) with 0 <= nanos < 1e9; the day count uses the packed ordinal."""
    span = ((signed32(now[0]) - signed32(moment[0])) >> 4) * DAY_UNIT + (now[1] - moment[1])
    total = span * NANOS + (now[2] - moment[2])
    return total // NANOS, total % NANOS


def sdiv_trunc(value, divisor):
    sign = -1 if value < 0 else 1
    return sign * (abs(value) // divisor)


class AdvOrder(Order):
    """Order record with the due moment at body +0x48."""

    def __init__(self, due=None, **fields):
        super().__init__(**fields)
        self.due = due or (pack_date(2025, 100), 3570, 123456789)

    def body(self, user):
        out = bytearray(super().body(user))
        out[0x48:0x54] = time_bytes(self.due)
        return bytes(out)


class AdvCase:
    """users / orders: (capacity, head, length, logical index). lookup: found, user_missing, absent2, beyond."""

    def __init__(self, label, order=None, oid=5, user=1, now=None, users=(5, 2, 1, 0), orders=(5, 2, 1, 0), lookup="found",
                 carry=None, date_none=False, behind=None, **fields):
        self.label, self.order = label, order or AdvOrder(**fields)
        self.oid, self.user = oid, user
        self.now = now or (pack_date(2025, 100), 3600, 123456789)
        self.users, self.orders, self.lookup = users, orders, lookup
        self.carry, self.date_none, self.behind = carry, date_none, behind


def floats(image):
    return {name: to_float(struct.unpack_from("<Q", image.blob, image.offset(va))[0]) for name, va in FLOAT_AT.items()}


def f64(value):
    return to_bits(value)


def spec_advance(case, constants, default, variant=""):
    """Everything the advance body must do for one case: stub calls in order, plus the order record and user ring afterwards."""
    order = case.order
    key = user_id(case.user)
    events = [("find user", TRACKER + 0x18, key)]
    if case.lookup == "user_missing" and case.users[2] > 0x3F:
        return dict(events=events, stop=("boundary", PROMOTE[case.family]))
    if case.lookup == "user_missing":
        if variant != "no_user_insert":
            events.append(("insert user", TRACKER + 0x18, case.users[3], key, struct.pack("<QQQQ", 0, 8, 0, 0)))
        events.append(("find order", 0, 0, case.oid))
        return dict(events=events, inserted=variant != "no_user_insert")
    events.append(("find order", case.orders[0], case.orders[2], case.oid))
    if case.lookup == "absent2" or (case.lookup == "beyond" and case.orders[3] >= case.orders[2]):
        return dict(events=events)
    due = order.due
    step = 31 if variant == "step_31" else STEP_SECONDS
    secs, nanos, carry = mc_time_add(due[1], due[2], step, 0)
    if case.carry is not None:
        carry = case.carry
    events.append(("time add", due[1], due[2], step, 0))
    moment = None

    def resolve(carry, date, secs, nanos):
        in_range = not ((carry + CARRY_ADD_1) & MASK[8] < CARRY_LIMIT_1 or (carry + CARRY_ADD_2) & MASK[8] < CARRY_LIMIT_2)
        if variant == "mask_carry_check":
            in_range = True
        if not in_range:
            return default
        days = sdiv_trunc(carry - (1 << 64) if carry & SIGN[8] else carry, DAY_UNIT)
        events.append(("date add", date & MASK[4], days & MASK[4]))
        if case.date_none:
            if variant == "panic_on_date_fail":
                return None
            return default
        return (mc_date_add(date, days), secs, nanos)

    moment = resolve(carry, due[0], secs, nanos)
    if moment is None:
        return dict(events=events, stop=("expect",))
    behind_key = (signed32(moment[0]), moment[1] & MASK[4], moment[2] & MASK[4])
    now_key = time_key(case.now)
    late = behind_key < now_key or (variant == "skip_equal_catchup" and behind_key <= now_key)
    if variant == "unsigned_date_cmp":
        late = (moment[0] & MASK[4], moment[1], moment[2]) < (case.now[0] & MASK[4], case.now[1] & MASK[4], case.now[2] & MASK[4])
    if late:
        events.append(("time sub", time_bytes(case.now), time_bytes(moment)))
        span = case.behind if case.behind is not None else mc_time_sub(case.now, moment)
        whole, part = span
        if whole < 0 and part > 0:
            whole, part = whole + 1, part - NANOS
        behind = float(whole) + float(part) / constants["nanos_divisor"]
        behind = behind if behind > 0.0 else 0.0
        quotient = 0.0 if behind == constants["zero_test"] else behind / constants["step"]
        events.append(("ceil", f64(quotient)))
        if variant == "floor_catchup":
            rounded = float(math.floor(quotient))
        else:
            rounded = float(math.ceil(quotient)) if quotient == quotient and abs(quotient) != math.inf else quotient
        exponent_ok = (f64(quotient) >> 52) < 0x7FF
        seconds_f = rounded * constants["step"] if exponent_ok else 0.0
        events.append(("secs to duration", f64(seconds_f)))
        whole_secs, whole_nanos = int(seconds_f), 0
        total = min(whole_secs * NANOS + whole_nanos, (1 << 63) - 1)
        dsecs, dnanos = total // NANOS, total % NANOS
        events.append(("time add", moment[1], moment[2], dsecs, dnanos))
        nsecs, nnanos, ncarry = mc_time_add(moment[1], moment[2], dsecs, dnanos)
        moment = resolve(ncarry, moment[0], nsecs, nnanos)
        if moment is None:
            return dict(events=events, stop=("expect",))
    counter = order.counter + 1
    if counter > MASK[8] and variant != "counter_wrap":
        counter = MASK[8]
    counter &= MASK[8]
    if variant == "counter_wrap" and counter == 0:
        pass
    done = order.executed >= order.total
    if variant == "finish_exec_gt":
        done = order.executed > order.total
    if not done:
        steps = duration_steps(order.float_duration())
        if variant == "steps_no_plus_one":
            steps = steps - 1 if steps < MASK[8] and steps else steps
        done = counter >= steps if variant == "finish_ge" else counter > steps
    state = dict(due=time_bytes(moment), counter=counter)
    if done:
        events.append(("finish", TRACKER, key, case.oid, FINISH_TAG, VECTOR))
    else:
        entry = (struct.pack("<Q", case.oid) + key + time_bytes(moment)) if variant == "entry_order" else (
            struct.pack("<Q", case.oid) + time_bytes(moment) + key)
        events.append(("push", TRACKER, entry))
    return dict(events=events, state=state)


# ---- harness ----

class AdvanceHarness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.machine.step_limit = STEP_LIMIT if not patches else MUTANT_STEP_LIMIT
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        slots = {}
        for row in ADVANCE:
            start, end = image.exact_fde(row["advance"])
            for insn in decode_range(image, start, end):
                if insn.op == "calli" and insn.a[0] == "m" and insn.a[1] is None:
                    slots[insn.a[4]] = relative[insn.a[4]]
        self.slot_set = frozenset(slots)
        for slot, target in slots.items():
            machine.memory.statics[slot] = target
        handlers = {SLOT_TIME_ADD: self.on_time_add, SLOT_DATE_ADD: self.on_date_add, SLOT_TIME_SUB: self.on_time_sub,
                    SLOT_SECS: self.on_secs, SLOT_CEIL: self.on_ceil}
        machine.slots = {slots[slot]: handlers[slot] for slot in slots if slot in handlers}
        machine.real = frozenset(va for row in ADVANCE for va in (row["entry"], row["resolve"]))
        machine.calls = {LOOKUP_USER: self.on_find_user, LOOKUP_ORDER: self.on_find_order, INSERT_USER: self.on_insert_user, INSERT_USER_SPOT: self.on_insert_user,
                         0x4ECB990: self.on_push}
        for va in BOUNDARY:
            machine.calls[va] = (lambda machine, va=va: self.on_boundary(machine, va))
        for row in ADVANCE:
            machine.calls[row["finish"]] = self.on_finish
        self.events = []
        self.default = tuple(struct.unpack("<III", image.blob[image.offset(DEFAULT_MOMENT):image.offset(DEFAULT_MOMENT) + 12]))

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def ring(self, at, capacity, buffer, head, length):
        for index, value in enumerate((capacity, buffer, head, length)):
            self.word(at + index * 8, value)

    def read_ring(self, at, stride, count_cap):
        memory = self.machine.memory
        capacity, buffer, head, length = (memory.read(at + index * 8, 8) for index in range(4))
        return [memory.bytes_at(buffer + ((head + logical) % capacity) * stride, stride) for logical in range(length)]

    def run_advance(self, index, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        self.events = []
        self.case = case
        row = ADVANCE[index]
        capacity, head, length, position = case.users
        self.ring(TRACKER + 0x18, capacity, USERS, head, length)
        for slot in range(capacity):
            memory.put_bytes(USERS + slot * USER_STRIDE, bytes((slot * 29 + at + 3) & 0xFF for at in range(USER_STRIDE)))
        ocap, ohead, olen, oindex = case.orders
        entry = USERS + phys(case.users) * USER_STRIDE
        if case.lookup != "user_missing":
            self.ring(entry + 0x18, ocap, ORDERS, ohead, olen)
        for slot in range(ocap):
            memory.put_bytes(ORDERS + slot * ORDER_STRIDE, bytes((slot * 17 + at * 5 + 1) & 0xFF for at in range(ORDER_STRIDE)))
        self.target = ORDERS + phys(case.orders) * ORDER_STRIDE
        if case.lookup in ("found", "beyond") and oindex < olen:
            memory.put_bytes(self.target + 8, case.order.body(case.user))
        memory.put_bytes(OUTER + 0x60, time_bytes(case.now))
        memory.put_bytes(USER_AT, user_id(case.user))
        self.word(TRACKER, 64)
        self.word(TRACKER + 8, VECTOR)
        self.word(TRACKER + 0x10, 0)
        out = {}
        try:
            machine.run(row["advance"], {RDI: TRACKER, RSI: USER_AT, RDX: case.oid, RCX: OUTER, R8: VECTOR})
        except Panicked as stop:
            out["stop"] = stop.args[0]
        out["events"] = self.events
        if memory.read(TRACKER + 0x18, 8) == 0:  # the promotion path has already moved the ring out
            out["users"] = None
        else:
            out["users"] = [(raw[:20], raw[0x18:0x38]) for raw in self.read_ring(TRACKER + 0x18, USER_STRIDE, 0)]
        if case.lookup in ("found", "beyond") and case.orders[3] < case.orders[2]:
            body = memory.bytes_at(self.target + 8, 0x68)
            out["state"] = dict(due=body[0x48:0x54], counter=struct.unpack_from("<Q", body, 0x40)[0])
        return out

    # -- stubs --

    def found(self, machine, position, absent):
        machine.keep_rdx = True
        machine.regs[RAX] = 1 if absent else 0
        machine.regs[RDX] = position

    def on_find_user(self, machine):
        regs = machine.regs
        self.events.append(("find user", regs[RDI], machine.memory.bytes_at(regs[RSI], 20)))
        self.found(machine, self.case.users[3], self.case.lookup == "user_missing")

    def on_find_order(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("find order", memory.read(regs[RDI], 8), memory.read(regs[RDI] + 0x18, 8), memory.read(regs[RSI], 8)))
        self.found(machine, self.case.orders[3], self.case.lookup == "absent2")

    def on_insert_user(self, machine):
        regs = machine.regs
        memory = machine.memory
        ring, position, record = regs[RDI], regs[RSI], regs[RDX]
        capacity, buffer, head, length = (memory.read(ring + index * 8, 8) for index in range(4))
        self.events.append(("insert user", ring, position, memory.bytes_at(record, 20), memory.bytes_at(record + 0x18, 32)))
        rows = [memory.bytes_at(buffer + ((head + logical) % capacity) * USER_STRIDE, USER_STRIDE) for logical in range(length)]
        rows.insert(position, memory.bytes_at(record, USER_STRIDE))
        for logical, raw in enumerate(rows):
            memory.put_bytes(buffer + ((head + logical) % capacity) * USER_STRIDE, raw)
        memory.write(ring + 0x18, 8, length + 1)

    def on_push(self, machine):
        regs = machine.regs
        self.events.append(("push", regs[RDI], machine.memory.bytes_at(regs[RSI], 0x28)))

    def on_finish(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("finish", regs[RDI], machine.memory.bytes_at(regs[RSI], 20), regs[RDX], memory.read(regs[RCX], 8), regs[R9]))

    def on_boundary(self, machine, va):
        raise Panicked(("boundary", va))

    def on_time_add(self, machine):
        regs = machine.regs
        memory = machine.memory
        secs, nanos = memory.read(regs[RSI], 4), memory.read(regs[RSI] + 4, 4)
        dsecs, dnanos = regs[RDX], regs[RCX] & MASK[4]
        self.events.append(("time add", secs, nanos, dsecs, dnanos))
        kept, kept_nanos, carry = mc_time_add(secs, nanos, dsecs, dnanos)
        if self.case.carry is not None and not any(event[0] == "ceil" for event in self.events):
            carry = self.case.carry
        memory.write(regs[RDI], 4, kept)
        memory.write(regs[RDI] + 4, 4, kept_nanos)
        memory.write(regs[RDI] + 8, 8, carry)

    def on_date_add(self, machine):
        regs = machine.regs
        days = signed32(regs[RSI])
        self.events.append(("date add", regs[RDI] & MASK[4], regs[RSI] & MASK[4]))
        regs[RAX] = 0 if self.case.date_none else mc_date_add(regs[RDI], days)

    def on_time_sub(self, machine):
        regs = machine.regs
        memory = machine.memory
        now, moment = memory.bytes_at(regs[RDI], 12), memory.bytes_at(regs[RSI], 12)
        self.events.append(("time sub", now, moment))
        span = self.case.behind or mc_time_sub(struct.unpack("<III", now), struct.unpack("<III", moment))
        machine.regs[RAX] = span[0] & MASK[8]
        machine.regs[RDX] = span[1] & MASK[8]
        machine.keep_rdx = True

    def on_secs(self, machine):
        bits = machine.xmm[0] & MASK[8]
        self.events.append(("secs to duration", bits))
        value = to_float(bits)
        if not 0.0 <= value < 18446744073709551616.0:
            raise Panicked(("duration", bits))
        machine.regs[RAX] = int(value)
        machine.regs[RDX] = 0
        machine.keep_rdx = True

    def on_ceil(self, machine):
        bits = machine.xmm[0] & MASK[8]
        self.events.append(("ceil", bits))
        value = to_float(bits)
        machine.xmm[0] = to_bits(float(math.ceil(value)) if value == value and abs(value) != math.inf else value)
        machine.keep_float = True


# ---- cases ----

CONSTANT_CACHE = {}


def moment_pool():
    return ((pack_date(2025, 100), 3570, 123456789), (pack_date(2025, 100), 3599, 123456789), (pack_date(2025, 100), 86399, 999999999),
            (pack_date(2025, 100), 0, 0), (pack_date(2024, 366), 86370, 5), (pack_date(2025, 99), 3570, 1), (pack_date(2025, 101), 3570, 1),
            (pack_date(2000, 1), 10, 10), (pack_date(-5, 100), 3570, 1), (pack_date(2025, 100), 3570, 0x80000000))


NOWS = ((pack_date(2025, 100), 3600, 123456789), (pack_date(2025, 100), 3570, 123456789), (pack_date(2025, 100), 0, 0),
        (pack_date(2025, 101), 5, 7), (pack_date(2025, 99), 86399, 1), (pack_date(2026, 1), 0, 0), (pack_date(-5, 100), 3600, 1),
        (pack_date(2025, 100), 3600, 0x80000000))
CARRIES = (None, 0, 86400, (-86400) & MASK[8], (-86399) & MASK[8], (1 << 31) * 86400 - 1, (1 << 31) * 86400,
           (-(1 << 31) * 86400 - 86399) & MASK[8], (-(1 << 31) * 86400 - 86400) & MASK[8], 1 << 63, MASK[8], 86400 * 400)
BEHINDS = (None, (0, 0), (0, 1), (29, 999999999), (30, 0), (30, 1), (59, 0), (60, 0), (3600, 5), (-1, 500000000), (-2, 0), (1 << 40, 7),
           (1 << 62, 0), (86400 * 365, 123))
DURATIONS_ADV = (3600.0, 60.0, 59.9, 120.0, 0.0, -0.0, -1.0, float("nan"), float("inf"), 5e-324, 1e18, 1e300, 30.0, 7200.0)
TOTALS_ADV = (1, 7, 100000, 1000000, 1 << 63, MASK[8])
COUNTERS = (0, 1, 7, 60, 119, 120, 121, 122, 500, (1 << 63) - 1, 1 << 63, MASK[8] - 1, MASK[8])
EXECUTED = (0, 1, 999999, 1000000, 1000001, 5 << 60, MASK[8])
RINGS = ((5, 2, 1, 0), (5, 4, 3, 2), (5, 3, 3, 1), (4, 3, 4, 3), (8, 7, 5, 4), (1, 0, 1, 0), (6, 5, 2, 0), (3, 2, 2, 1), (7, 0, 6, 5))
FREE_RINGS = ((5, 2, 1, 0), (5, 4, 3, 3), (5, 3, 3, 1), (8, 7, 5, 5), (6, 5, 2, 0), (3, 2, 2, 2), (7, 0, 6, 4), (9, 8, 5, 0))


def named_cases():
    rows = []

    def add(label, **options):
        rows.append(AdvCase(label, **options))

    add("reschedule before the end")
    add("user missing, front", lookup="user_missing", users=(5, 2, 1, 0))
    add("user missing, back", lookup="user_missing", users=(5, 4, 3, 3))
    add("user missing, middle wrapped", lookup="user_missing", users=(5, 4, 3, 1))
    add("user missing, empty ring", lookup="user_missing", users=(3, 0, 0, 0))
    add("order missing", lookup="absent2")
    add("order index past the length", lookup="beyond", orders=(5, 2, 1, 1))
    add("order index at the last slot", lookup="beyond", orders=(5, 2, 3, 2))
    add("executed reaches total", executed=1000000)
    add("executed passes total", executed=1000001)
    add("executed one short", executed=999999, counter=121)
    add("counter becomes the last step", counter=119)
    add("counter becomes one past the steps", counter=120)
    add("counter saturates", counter=MASK[8])
    add("counter at 2^63", counter=1 << 63, duration=1e300)
    add("duration infinite", counter=0, duration=float("inf"))
    add("duration negative", duration=-1.0, counter=1)
    add("duration NaN", duration=float("nan"), counter=1)
    add("zero total", total=0)
    add("midnight carry", due=(pack_date(2025, 100), 86399, 9), now=(pack_date(2025, 100), 0, 0))
    add("carry top of the range", carry=(1 << 31) * 86400 - 1)
    add("carry just over the range", carry=(1 << 31) * 86400)
    add("carry bottom of the range", carry=(-(1 << 31) * 86400 - 86399) & MASK[8])
    add("carry just under the range", carry=(-(1 << 31) * 86400 - 86400) & MASK[8])
    add("date add fails", date_none=True)
    add("date add fails after catch-up", date_none=True, due=(pack_date(2025, 100), 100, 5))
    add("next equals now", due=(pack_date(2025, 100), 3570, 123456789), now=(pack_date(2025, 100), 3600, 123456789))
    add("next one nano behind", due=(pack_date(2025, 100), 3570, 123456788), now=(pack_date(2025, 100), 3600, 123456789))
    add("next one nano ahead", due=(pack_date(2025, 100), 3570, 123456790), now=(pack_date(2025, 100), 3600, 123456789))
    add("behind exactly a multiple", due=(pack_date(2025, 100), 3510, 123456789), now=(pack_date(2025, 100), 3600, 123456789))
    add("behind just past a multiple", due=(pack_date(2025, 100), 3510, 123456788), now=(pack_date(2025, 100), 3600, 123456789))
    add("behind a day", due=(pack_date(2025, 99), 3570, 123456789))
    add("large user ring, user found", users=(0x50, 3, 0x41, 7))
    add("large user ring, user missing: promotion boundary", lookup="user_missing", users=(0x50, 3, 0x41, 7))
    add("user ring of 63, user missing", lookup="user_missing", users=(0x50, 3, 0x3F, 7))
    add("user ring of 64, user missing: promotion boundary", lookup="user_missing", users=(0x50, 3, 0x40, 7))
    add("high nanos in now", due=(pack_date(2025, 100), 3570, 1), now=(pack_date(2025, 100), 3600, 0x80000000))
    return rows


def random_case(source, number):
    pick = lambda pool: pool[next(source) % len(pool)]
    lookup = ("found", "found", "found", "found", "user_missing", "absent2", "beyond")[next(source) % 7]
    users = pick(FREE_RINGS) if lookup == "user_missing" else pick(RINGS)
    orders = pick(RINGS)
    due = pick(moment_pool())
    options = dict(oid=1 + next(source) % 50, user=1 + next(source) % 9, now=pick(NOWS), users=users, orders=orders, lookup=lookup,
                   carry=pick(CARRIES) if next(source) % 6 == 0 else None, date_none=next(source) % 11 == 0,
                   behind=pick(BEHINDS) if next(source) % 9 == 0 else None)
    return AdvCase("random %d" % number, due=due, total=pick(TOTALS_ADV), executed=pick(EXECUTED), counter=pick(COUNTERS),
                   duration=pick(DURATIONS_ADV), **options)


def cases_for(index, count):
    family = ADVANCE[index]["family"]
    for case in named_cases():
        case.family = family
        yield case
    source = lcg(31 + index)
    for number in range(count):
        case = random_case(source, number)
        case.family = family
        yield case


# ---- comparison ----

def case_spec(harness, case, variant=""):
    CONSTANT_CACHE.setdefault("floats", floats(harness.image))
    return spec_advance(case, CONSTANT_CACHE["floats"], harness.default, variant)


def expected_users(case, expected):
    """Normalised user ring after the run, built only from the case; None once the ring was handed to the promotion."""
    if case.lookup == "user_missing" and case.users[2] > 0x3F:
        return None
    rows = [(bytes((slot * 29 + at + 3) & 0xFF for at in range(USER_STRIDE))) for slot in range(case.users[0])]
    capacity, head, length, _ = case.users
    logical = [rows[(head + index) % capacity] for index in range(length)]
    if case.lookup != "user_missing":
        raw = bytearray(logical[case.users[3]])
        raw[0x18:0x38] = struct.pack("<QQQQ", case.orders[0], ORDERS, case.orders[1], case.orders[2])
        logical[case.users[3]] = bytes(raw)
    pairs = [(raw[:20], raw[0x18:0x38]) for raw in logical]
    if expected.get("inserted"):
        pairs.insert(case.users[3], (user_id(case.user), struct.pack("<QQQQ", 0, 8, 0, 0)))
    return pairs


def expected_state(case, expected):
    if "state" in expected:
        return expected["state"]
    if case.lookup in ("found", "beyond") and case.orders[3] < case.orders[2]:
        body = case.order.body(case.user)
        return dict(due=body[0x48:0x54], counter=struct.unpack_from("<Q", body, 0x40)[0])
    return None


def matches(actual, expected, case):
    if actual["events"] != expected["events"]:
        return False
    if ("stop" in actual) != ("stop" in expected):
        return False
    if actual["users"] != expected_users(case, expected):
        return False
    if "stop" in expected:
        return True
    return actual.get("state") == expected_state(case, expected)


def check(harness, index, case, variant=""):
    expected = case_spec(harness, case, variant)
    try:
        actual = harness.run_advance(index, case)
    except (Halt, Panicked, EvidenceError, ZeroDivisionError):
        return False, expected, None
    return matches(actual, expected, case), expected, actual


def outcome_of(expected):
    if "stop" in expected:
        return "stop"
    names = [event[0] for event in expected["events"]]
    if "finish" in names:
        return "finish"
    if "push" in names:
        return "reschedule"
    return "user inserted" if expected.get("inserted") else "none"


def analyse(image, per_copy, rows_every):
    harness = AdvanceHarness(image)
    counts, outcomes, mismatches, rows = {}, {}, [], []
    for index in range(len(ADVANCE)):
        for number, case in enumerate(cases_for(index, per_copy)):
            ok, expected, actual = check(harness, index, case)
            counts[index] = counts.get(index, 0) + 1
            if not ok:
                mismatches.append((index, number, case.label))
                continue
            kind = outcome_of(expected)
            outcomes[(index, kind)] = outcomes.get((index, kind), 0) + 1
            if number % rows_every == 0:
                state = expected.get("state") or {}
                rows.append((index, number, kind, case.label, state["counter"] if state else "-", state["due"].hex() if state else "-",
                             len(expected["events"])))
    return harness, counts, outcomes, mismatches, rows


# ---- mutation, variants, evidence ----

VARIANTS = ("no_user_insert", "step_31", "mask_carry_check", "panic_on_date_fail", "skip_equal_catchup", "unsigned_date_cmp",
            "floor_catchup", "counter_wrap", "finish_exec_gt", "steps_no_plus_one", "finish_ge", "entry_order")
VARIANT_NOTE = {
    "no_user_insert": "a missing user is not added to the tracker ring (the entry resolver only looks)",
    "step_31": "the reschedule step is 31 s",
    "mask_carry_check": "no range test on the carried seconds before the date add",
    "panic_on_date_fail": "node #94 rule: a failed date add panics instead of using the stored default moment",
    "skip_equal_catchup": "catch up when the next moment equals now",
    "unsigned_date_cmp": "compare the packed date unsigned",
    "floor_catchup": "round the catch-up quotient down",
    "counter_wrap": "the step counter wraps instead of saturating",
    "finish_exec_gt": "finish when executed is above the total, not at it",
    "steps_no_plus_one": "step count is 2 * buckets, without the +1",
    "finish_ge": "finish when the counter reaches the step count",
    "entry_order": "heap entry laid out as oid, user, moment",
}


def jcc_patch(image, row):
    at = image.offset(row.va)
    first = image.blob[at]
    if 0x70 <= first <= 0x7F:
        return row.va, first ^ 1
    if first == 0x0F and 0x80 <= image.blob[at + 1] <= 0x8F:
        return row.va + 1, image.blob[at + 1] ^ 1
    return None


def detects(image, index, patches, probe):
    harness = AdvanceHarness(image, patches)
    for case in probe:
        try:
            ok, _, _ = check(harness, index, case)
        except Exception:  # a crashed mutant is a detected mutant
            return True
        if not ok:
            return True
    return False


def function_rows(image, va):
    start, end = image.exact_fde(va)
    return start, end, decode_range(image, start, end)


def run_mutants(image, seen, probe, probe2, limit):
    rows = []
    for index in (0, 2):
        row = ADVANCE[index]
        sites = []
        for name in ("advance", "entry", "resolve"):
            for insn in function_rows(image, row[name])[2]:
                if insn.op == "jcc" and insn.va in seen:
                    patch = jcc_patch(image, insn)
                    if patch:
                        sites.append((name, insn.va, patch))
        step = max(1, len(sites) // limit)
        for name, va, (at, byte) in sites[::step]:
            patches = {at: byte}
            caught = detects(image, index, patches, probe[index])
            stage = 1
            if not caught:
                caught = detects(image, index, patches, probe2[index])
                stage = 2
            rows.append((index, name, va, at, byte, "detected" if caught else "survived", stage))
    return rows


def pin_controls(image):
    """Each pinned immediate must match the image; a one-byte corruption of the copy must be refused."""
    rows = []
    for va, expected, what in BYTE_PINS:
        at = image.offset(va)
        genuine = bytes(image.blob[at:at + len(expected)]) == expected
        broken = bytearray(expected)
        broken[-1] ^= 1
        refused = bytes(image.blob[at:at + len(expected)]) != bytes(broken)
        rows.append((hex(va), what, genuine, refused))
    return rows


def corrupt_controls(image):
    results = []
    for label, action in (("wrong digest", lambda: load_image(BINARY, "0" * 64)),
                          ("outside every FDE", lambda: image.fde(0x10)),
                          ("not an FDE start", lambda: image.exact_fde(ADVANCE[0]["advance"] + 1)),
                          ("entry helper address inside another body", lambda: image.exact_fde(ADVANCE[2]["entry"] + 4))):
        try:
            action()
            results.append((label, False))
        except EvidenceError:
            results.append((label, True))
    return results


def shape(row, start):
    target = row.target
    if row.op in ("jcc", "jmp") and target is not None:
        target = target - start
    return (row.op, row.a, row.b, row.width, row.cc, target if row.op != "call" else None)


def copy_differences(image):
    out = []
    for first, second in ((0, 1), (2, 3), (0, 2)):
        sa, ea, ra = function_rows(image, ADVANCE[first]["advance"])
        sb, eb, rb = function_rows(image, ADVANCE[second]["advance"])
        if len(ra) != len(rb):
            out.append((first, second, -1, 0, 0, "instruction count", len(ra), len(rb)))
        for index, (x, y) in enumerate(zip(ra, rb)):
            if shape(x, sa) != shape(y, sb):
                out.append((first, second, index, hex(x.va), hex(y.va), x.op, "-", "-"))
            elif x.op == "call" and x.target != y.target:
                out.append((first, second, index, hex(x.va), hex(y.va), "call target", hex(x.target), hex(y.target)))
    return out


def table(rows):
    return "".join("\t".join(str(cell) for cell in row) + "\n" for row in rows)


STUB_ROLES = (
    (LOOKUP_USER, "direct", "user ring search: rax 1 when absent, rdx the logical position"),
    (LOOKUP_ORDER, "direct", "order ring search: rax 1 when absent, rdx the logical position"),
    (INSERT_USER, "direct", "perp ring insert of a new user record at a logical position"),
    (INSERT_USER_SPOT, "direct", "spot ring insert of a new user record at a logical position"),
    (0x4ECB990, "direct", "heap push of the 0x28 byte entry (oid, moment, user)"),
    (SLOT_TIME_ADD, "slot", "chrono time plus seconds and nanos: out secs, nanos, carried whole seconds"),
    (SLOT_DATE_ADD, "slot", "chrono date plus days: packed date or 0"),
    (SLOT_TIME_SUB, "slot", "chrono difference of two moments: rax secs, edx nanos"),
    (SLOT_SECS, "slot", "f64 seconds to a duration: rax secs, edx nanos"),
    (SLOT_CEIL, "slot", "libm ceil of xmm0"),
) + tuple((row["finish"], "direct", "finish callee, tag word 0x8000000000000002") for row in ADVANCE) + tuple(
    (va, "boundary", what) for va, what in sorted(BOUNDARY.items()))


def build(image, per_copy, rows_every, mutant_limit):
    harness, counts, outcomes, mismatches, rows = analyse(image, per_copy, rows_every)
    seen = harness.machine.seen
    coverage = []
    for index, row in enumerate(ADVANCE):
        for name in ("advance", "entry", "resolve"):
            start, end, decoded = function_rows(image, row[name])
            coverage.append((index, name, hex(start), hex(end), end - start, len(decoded), sum(1 for item in decoded if item.va in seen)))
    probe = {index: list(cases_for(index, 200)) for index in range(4)}
    probe2 = {index: list(cases_for(index, 1200)) for index in range(4)}
    mutants = run_mutants(image, seen, probe, probe2, mutant_limit)
    variants = []
    for variant in VARIANTS:
        first, wrong, tried = None, 0, 0
        for index in range(4):
            for number, case in enumerate(cases_for(index, 600)):
                ok, _, _ = check(harness, index, case, variant)
                tried += 1
                if not ok:
                    wrong += 1
                    if first is None:
                        first = case.label
        variants.append((variant, VARIANT_NOTE[variant], first or "-", wrong, tried))
    return harness, counts, outcomes, mismatches, rows, coverage, mutants, variants


def render(image, per_copy, rows_every, mutant_limit):
    harness, counts, outcomes, mismatches, rows, coverage, mutants, variants = build(image, per_copy, rows_every, mutant_limit)
    if mismatches:
        raise EvidenceError("%d mismatches, first %r" % (len(mismatches), mismatches[0]))
    controls = corrupt_controls(image)
    pins = pin_controls(image)
    detected_mutants = sum(1 for row in mutants if row[5] == "detected")
    survivors = len(mutants) - detected_mutants
    detected_variants = sum(1 for row in variants if row[3] > 0)
    pin_ok = sum(1 for row in pins if row[2] and row[3])
    negative = detected_mutants + len(variants) + len(controls) + len(pins)
    detected = detected_mutants + detected_variants + sum(1 for _, ok in controls if ok) + pin_ok
    total = sum(counts.values())
    files = {}
    files["cases.tsv"] = "copy\tcase\toutcome\tlabel\tcounter after\tdue after\tstub events\n" + table(
        (hex(ADVANCE[c]["advance"]), n, k, label, counter, due, e) for c, n, k, label, counter, due, e in rows)
    files["outcomes.tsv"] = "copy\toutcome\tcases\n" + table((hex(ADVANCE[c]["advance"]), k, outcomes[(c, k)]) for c, k in sorted(outcomes))
    files["copies.tsv"] = "copy\tfunction\tstart\tend\tbytes\tinstructions\tstepped\n" + table(
        (hex(ADVANCE[c[0]]["advance"]), c[1]) + c[2:] for c in coverage)
    files["callees.tsv"] = "copy\tfamily\tentry helper\tentry resolver\tfinish callee\n" + table(
        (hex(r["advance"]), r["family"], hex(r["entry"]), hex(r["resolve"]), hex(r["finish"])) for r in ADVANCE)
    files["stubs.tsv"] = "address\tkind\trole\n" + table((hex(va), kind, what) for va, kind, what in STUB_ROLES)
    constants = floats(image)
    files["constants.tsv"] = "constant\taddress\tvalue\n" + table(
        (name, hex(FLOAT_AT[name]), repr(constants[name])) for name in sorted(FLOAT_AT)) + table(
        (what, hex(va), expected.hex()) for va, expected, what in BYTE_PINS) + table(
        (name, "default moment", str(harness.default)) for name in ("date add failure",))
    files["copy_differences.tsv"] = "first\tsecond\tindex\tva first\tva second\twhat\tfirst\tsecond\n" + table(copy_differences(image))
    files["mutants.tsv"] = "copy\tfunction\tjcc va\tpatched byte va\tnew byte\tresult\tstage\n" + table(
        (hex(ADVANCE[c]["advance"]), n, hex(v), hex(a), hex(b), r, s) for c, n, v, a, b, r, s in mutants)
    files["variants.tsv"] = "variant\tmeaning\tfirst case where the bytes disagree\tdisagreeing cases\tcases tried\n" + table(variants)
    files["controls.tsv"] = "control\tdetected\n" + table(controls) + table(
        ("pin %s %s" % (va, what), genuine and refused) for va, what, genuine, refused in pins)
    summary = dict(binary_sha256=SHA256, cases=total, mismatches=len(mismatches), per_copy=per_copy,
                   coverage=[dict(copy=c[0], function=c[1], bytes=c[4], instructions=c[5], stepped=c[6]) for c in coverage],
                   mutants=len(mutants), mutants_detected=detected_mutants, survivors=survivors,
                   variants=len(variants), variants_detected=detected_variants, controls=len(controls), pins=len(pins))
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    measure = dict(cases=total, negative_controls=negative, negative_detected=detected, mutants_tried=len(mutants), mutants_survived=survivors)
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
    parser.add_argument("--cases", type=int, default=3000, help="random cases per advance copy")
    parser.add_argument("--sample", type=int, default=3, help="keep every Nth case in cases.tsv")
    parser.add_argument("--mutants", type=int, default=60, help="jcc flips per representative copy")
    args = parser.parse_args(argv)
    image = load_image()
    write_outputs(args.out, render(image, args.cases, args.sample, args.mutants))
    return 0


if __name__ == "__main__":
    sys.exit(main())
