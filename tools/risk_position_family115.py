"""Reconstruct three node #115 clearinghouse position routines (fold 0x3bebd70, check 0x447e810, margin test 0x469b990) with their real callees.

The fold sums, over every position of one account (ring buffer or B-tree), a saturating figure built from a margin-row product, an unsigned division and
a stored balance; the check turns one position into an emit request after an f64 range gate, an asset-mode test, a per-account map lookup and a clipped
f64 ratio; the margin test combines two opaque helper results with four checked products and two thresholds. The real bytes of these three bodies, of
the map lookup 0x4716be0, of the B-tree iterator step 0x37c5ba0 and of the ring and B-tree searches 0x455cb20 / 0x35be560 run in a small x86-64
evaluator with the remaining callees as recording stubs; a separately written rule list predicts every result, panic, fault and recorded call, and every
reached conditional, immediate and field offset of the seven bodies is edited. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/risk_position_family115.py --out <dir>
"""


import argparse
import bisect
import collections
import fractions
import hashlib
import itertools
import json
import math
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

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
HEAP_SIZE = 0x20000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000


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
        self.relative_map = None
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
        if rela["size"] % 24:
            raise EvidenceError("truncated RELA section")
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/z_vendor/"):
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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
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
    if byte == 0xCC:
        return finish("int3")
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
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
        if byte == 0xFF and kind == 6:
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
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
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
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
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrdi", rm, ("r", reg), width, target=value)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
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
        row.data = bytes(read(va, row.size))
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
        self.xmm_result = None

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
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
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
            self.put(row.a, width, self.signed_product(self.get(row.b, width), row.target, width))
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
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.signed_product(self.get(row.a, width), self.get(row.b, width), width))
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "rol":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width] if count else value)
        elif op == "ror":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) if count else value)
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

    def signed_product(self, left, right, width):
        """Two and three operand IMUL: the flags report a product that does not fit the signed operand width."""
        bits = 8 * width
        left, right = left & MASK[width], right & MASK[width]
        left = left - (1 << bits) if left >> (bits - 1) & 1 else left
        right = right - (1 << bits) if right >> (bits - 1) & 1 else right
        product = left * right
        self.cf = self.of = not -(1 << (bits - 1)) <= product < (1 << (bits - 1))
        return product & MASK[width]

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
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
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
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right





# ---------------------------------------------------------------------------------------------------------------------------------
# Subjects of this packet. Three clearinghouse position routines that the previous position-ratio packet left out ("every other copy of
# the routine at 0x447e810, 0x3bebd70 and 0x469b990 (different code, not claimed here)"), run together with the callees they reach:
#   0x3bebd70  fold of all positions of one account (ring buffer or B-tree) into one saturating figure
#   0x447e810  single position check for one asset key: range gate on an f64 fraction, asset mode, per-account lookup, ratio, emit request
#   0x469b990  margin test for a hypothetical position change: two opaque helpers, four checked products, two threshold comparisons
#   0x4716be0  the per-account map lookup used by the last two (20-byte key, 0x98-byte entries)
#   0x37c5ba0  B-tree in-order iterator step used by the fold; 0x455cb20 / 0x35be560 ring and tree searches used by the check
# ---------------------------------------------------------------------------------------------------------------------------------

TOTAL = 0x3BEBD70
CHECK = 0x447E810
OKAY = 0x469B990
MAPGET = 0x4716BE0
ITER = 0x37C5BA0
RING = 0x455CB20
TREE = 0x35BE560
HASH = 0x4717440      # SipHash-1-3 of the 20-byte key
WRITE = 0x45927A0     # SipHasher write of the key bytes (called by HASH)
PROBE = 0x3EE6740     # hashbrown probe with the inlined 20-byte key comparison
TARGETS = (TOTAL, CHECK, OKAY, MAPGET, HASH, WRITE, PROBE, ITER, RING, TREE)
NAMES = {TOTAL: "position_fold", CHECK: "position_check", OKAY: "margin_test", MAPGET: "account_map_get", HASH: "siphash13_key", WRITE: "siphash13_write",
         PROBE: "hashbrown_probe", ITER: "btree_iter_next", RING: "ring_search", TREE: "tree_search"}
FAMILY_OF = {TOTAL: ("fold",), ITER: ("fold",), CHECK: ("check",), RING: ("check",), TREE: ("check",), OKAY: ("test",), MAPGET: ("map", "check", "test"),
             HASH: ("hash", "map"), WRITE: ("hash", "map"), PROBE: ("map", "check", "test")}

NEXTSTEP = 0x448BC30  # large evaluation helper of the margin test (direct call, recorded stub)
DROP = 0x46EC470      # drop of a small error value (direct call, recorded stub)
SLOTS = {0x64E4EA8: "sat", 0x64DF620: "index", 0x64DF830: "panic", 0x64DF6A0: "fmt", 0x64DF9F0: "once", 0x64E6D20: "route", 0x64E7B28: "emit",
         0x64E7B48: "big"}
DIRECT = {NEXTSTEP: "next", DROP: "drop"}
MARK_BASE = 0x7700000000
ONCE = 0x64FDAF8
DEFAULT = 0x64FDA80
LOW = 0x459490      # f64 0.5
ONE = 0x4592B0      # f64 1.0
BOUND = 0x459360    # f64 2^63
TOPF = 0x458E50     # f64 2^63 - 1024

MIN64 = -(1 << 63)
MAX64 = (1 << 63) - 1
TOP = MASK[8]
M32 = MASK[4]
SEARCH_KEY_LIMIT = 10000

# heap map (offsets from HEAP_BASE)
OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x70
KEYS = HEAP_BASE + 0x300         # two 20-byte keys at +0 and +0x14 (margin test), query key (position check) at +0x40
QKEY = HEAP_BASE + 0x340
CTX = HEAP_BASE + 0x380
V10, V18, V20, V28 = (HEAP_BASE + 0x3C0 + 8 * index for index in range(4))
TABLE1 = HEAP_BASE + 0x3E0       # fold: {+8 rows, +0x10 count}
CONT1 = HEAP_BASE + 0x400        # fold: container header, accumulator word at +0x48
STATE = HEAP_BASE + 0x1000
META = HEAP_BASE + 0x1400
ROWS = HEAP_BASE + 0x2000
ENTRIES = HEAP_BASE + 0x4000     # map entries, 0x98 bytes each
HTAB = HEAP_BASE + 0x10000       # hash table: bucket words below HTAB + 0x400, control bytes from there
BUFS = HEAP_BASE + 0x5000        # ring buffers, 0x800 bytes per entry
TREEMEM = HEAP_BASE + 0x7000
USED = 0x12000
ARG_SLOT = STACK_TOP - 0x100
OUT_INIT = bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE))
ENTRY_SIZE = 0x98


class Sites:
    """Location records, message strings and static addresses named by the subjects, read from the lea / mov operands of the bytes."""

    def __init__(self, image):
        self.image = image
        r = lambda va: rip_target(image, va)
        self.fold_sat_sum, self.fold_sat_sub, self.fold_sat_add = r(0x3BEBFB2), r(0x3BEBFFA), r(0x3BEC061)
        self.fold_fmt = (r(0x3BEC07D), 0x2B, r(0x3BEC084), r(0x3BEC08B))
        self.fold_size, self.fold_index = r(0x3BEC0D5), r(0x3BEC0E2)
        self.check_key, self.check_size, self.check_sat, self.check_index = r(0x447EB11), r(0x447EB64), r(0x447EB85), r(0x447EBDB)
        self.check_fmt = (r(0x447EBAC), 0x2B, r(0x447EBB3), r(0x447EBBA))
        self.once_args = (r(0x447EB34), 1, r(0x447EB3B), r(0x447EB42))
        self.default = r(0x447E8D7)
        self.test_sat_diff, self.test_sat_mul, self.test_size = r(0x469BBCE), r(0x469BC37), r(0x469BBE6)
        self.test_fmt_a = (r(0x469BC55), 0x2B, r(0x469BC5C), r(0x469BC63))
        self.test_fmt_b = (r(0x469BC7A), 0x2B, r(0x469BC81), r(0x469BC88))
        self.map_index, self.probe_index = r(0x4716CA3), r(0x3EE685F)
        self.consts = {name: struct.unpack_from("<d", image.blob, image.offset(at))[0] for name, at in (("low", LOW), ("one", ONE), ("bound", BOUND), ("top", TOPF))}

    def text(self, at, count):
        offset = self.image.offset(at)
        return bytes(self.image.blob[offset:offset + count]).decode("ascii", "replace")


def rel(value):
    """Normalise a pointer for the logs: heap addresses become offsets, stack addresses a tag."""
    if HEAP_BASE <= value < HEAP_BASE + HEAP_SIZE:
        return ("h", value - HEAP_BASE)
    if STACK_TOP - STACK_SIZE <= value < STACK_TOP:
        return "stack"
    return value


def signed(value):
    value &= TOP
    return value - (1 << 64) if value >> 63 else value


def sat(value):
    return max(MIN64, min(MAX64, value))


def rip_target(image, va):
    return decode_range(image, va, va + 7)[0].b[4]


def rec(tag=0, c=0, v=1, b=1, d=7, div=1, pad=None):
    return dict(tag=tag & M32, div=div & M32, c=c, v=v, b=b, d=d & TOP, pad=pad if pad is not None else bytes((0x40 + 5 * index) & 0xFF for index in range(24)))


def rec_bytes(item):
    return struct.pack("<II", item["tag"], item["div"]) + struct.pack("<qq", item["c"], item["v"]) + item["pad"][:24] + struct.pack("<qQ", item["b"], item["d"] & TOP)


def key20(seed):
    return bytes((0x31 * seed + 7 * index + 1) & 0xFF for index in range(20))


class Container:
    """One position container: a ring buffer of (key, record) or a B-tree, plus the accumulator word at +0x48."""

    def __init__(self, mode, recs, cap=None, head=0, acc=0, height=None):
        self.mode, self.recs, self.cap, self.head, self.acc, self.height = mode, recs, cap, head, acc, height


def tree_capacity(height):
    return 12 ** (height + 1) - 1


def tree_minimum(height):
    return 1 if height == 0 else 1 + 2 * tree_minimum(height - 1)


def put_tree(memory, entries, base, forced=None):
    """B-tree nodes laid out as the target reads them: values at +0, parent at +0x2c0, keys at +0x2c8, parent index +0x320, length +0x322, edges +0x328.
    Height 0 for up to 11 keys, else the smallest height that holds the keys unless a larger one is forced. Returns (root, height)."""
    count = len(entries)
    if count == 0:
        return 0, 0
    height = 0
    while count > tree_capacity(height):
        height += 1
    if forced is not None and forced > height and count >= tree_minimum(forced):
        height = forced
    allocated = [0]

    def node(items, internal, parent, parent_index):
        at = base + 0x400 * allocated[0]
        allocated[0] += 1
        memory.put_bytes(at, bytes((0x90 + index) & 0xFF for index in range(0x388 if internal else 0x328)))
        for slot, (key, item) in enumerate(items):
            memory.put_bytes(at + slot * 64, rec_bytes(item))
            memory.write(at + 0x2C8 + slot * 8, 8, key)
        memory.put_bytes(at + 0x2C8, bytes(0x58))
        for slot, (key, item) in enumerate(items):
            memory.write(at + 0x2C8 + slot * 8, 8, key)
        memory.write(at + 0x2C0, 8, parent)
        memory.write(at + 0x320, 2, parent_index)
        memory.write(at + 0x322, 2, len(items))
        return at

    def build(items, level, parent, parent_index):
        if level == 0:
            return node(items, False, parent, parent_index)
        children = min(12, max(2, -(-(len(items) + 1) // (tree_capacity(level - 1) + 1))))
        share = len(items) - (children - 1)
        sizes = [share // children + (1 if slot < share % children else 0) for slot in range(children)]
        at = node([], True, parent, parent_index)
        picked, edges, cursor = [], [], 0
        for slot, size in enumerate(sizes):
            edges.append(build(items[cursor:cursor + size], level - 1, at, slot))
            cursor += size
            if slot < children - 1:
                picked.append(items[cursor])
                cursor += 1
        for slot, (key, item) in enumerate(picked):
            memory.put_bytes(at + slot * 64, rec_bytes(item))
            memory.write(at + 0x2C8 + slot * 8, 8, key)
        memory.write(at + 0x322, 2, len(picked))
        for slot, child in enumerate(edges):
            memory.write(at + 0x328 + slot * 8, 8, child)
        return at

    root = build(list(entries), height, 0, 0)
    return root, height


def put_container(memory, at, container, buf, tree):
    """Write the container header (and its storage) at `at`; ring storage at `buf`, tree nodes from `tree`."""
    memory.put_bytes(at, bytes((0x20 + index) & 0xFF for index in range(0x80)))
    if container.mode == "ring":
        memory.write(at, 8, container.cap)
        memory.write(at + 8, 8, buf)
        memory.write(at + 0x10, 8, container.head)
        memory.write(at + 0x18, 8, len(container.recs))
        for slot, (key, item) in enumerate(container.recs):
            spot = buf + (container.head + slot) % container.cap * 72
            memory.write(spot, 8, key)
            memory.put_bytes(spot + 8, rec_bytes(item))
    else:
        root, height = put_tree(memory, container.recs, tree, container.height)
        memory.write(at, 8, MIN64 & TOP)
        memory.write(at + 8, 8, root)
        memory.write(at + 0x10, 8, height)
        memory.write(at + 0x18, 8, len(container.recs))
    memory.write(at + 0x48, 8, container.acc & TOP)


class World:
    """The evaluator with every opaque call recorded; one instance runs every case of every subject."""

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        machine.real = frozenset((MAPGET, HASH, WRITE, PROBE, ITER, RING, TREE))
        self.machine = machine
        self.sites = Sites(image)
        for slot, name in SLOTS.items():
            machine.memory.statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = getattr(self, "on_" + name)
        for target, name in DIRECT.items():
            machine.calls[target] = getattr(self, "on_" + name)
        self.case = None
        self.log = []

    # ---- recorded callees
    def on_sat(self, machine):
        self.log.append(("sat", machine.regs[RDI], machine.regs[RSI]))

    def on_index(self, machine):
        raise Panicked(("index", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_fmt(self, machine):
        regs = machine.regs
        raise Panicked(("fmt", (regs[RDI], regs[RSI], regs[RCX], regs[R8])))

    def on_once(self, machine):
        regs, memory = machine.regs, machine.memory
        chain = memory.read(memory.read(regs[RDX], 8), 8)
        self.log.append(("once", regs[RDI], regs[RSI] & M32, regs[RCX], regs[R8], chain))
        memory.statics[ONCE] = 0

    def on_route(self, machine):
        regs, memory = machine.regs, machine.memory
        self.log.append(("route", rel(regs[RSI]), regs[RDX] & TOP, regs[RCX], rel(regs[R9]), rel(memory.read(regs[RSP], 8))))
        memory.write(regs[RDI], 8, self.case.route[0] & TOP)
        memory.write(regs[RDI] + 8, 8, self.case.route[1] & TOP)

    def on_big(self, machine):
        regs = machine.regs
        self.log.append(("big", rel(regs[RSI]), regs[RDX], rel(regs[RCX])))

    def on_emit(self, machine):
        regs = machine.regs
        self.log.append(("emit", rel(regs[RSI]), rel(regs[RDX]), regs[RCX]))
        machine.memory.put_bytes(regs[RDI], self.case.emit[:OUT_SIZE])

    def on_next(self, machine):
        regs, memory = machine.regs, machine.memory
        self.log.append(("next", rel(regs[RSI]), regs[RDX], regs[RCX], regs[R8], regs[R9], memory.read(regs[RSP] + 8, 8)))
        tag, second, third, extra = self.case.step
        memory.write(regs[RDI], 4, tag)
        memory.write(regs[RDI] + 8, 8, second & TOP)
        memory.write(regs[RDI] + 0x10, 8, third & TOP)
        memory.write(regs[RDI] + 0x40, 8, extra & TOP)

    def on_drop(self, machine):
        self.log.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def reset(self, case):
        machine = self.machine
        machine.memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        machine.memory.statics[ONCE] = case.once if hasattr(case, "once") else 0
        self.case, self.log = case, []
        machine.memory.put_bytes(OUT, OUT_INIT)
        return machine.memory

    def execute(self, entry, args, before):
        """Run one entry; return ('ret', value) or the panic / fault outcome; the heap outside the declared result must be unchanged."""
        machine = self.machine
        try:
            value = machine.run(entry, args)
        except Panicked as stop:
            return stop.args[0] + (tuple(self.log),)
        except Halt as stop:
            if str(stop).startswith("division by zero"):
                return ("fault", "divide", tuple(self.log))
            raise
        return ("ret", value, tuple(self.log))


def siphash13(k0, k1, data):
    """Standard SipHash-1-3 (one compression round, three finalisation rounds), written independently of the bytes."""
    state = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]

    def rounds(count):
        v0, v1, v2, v3 = state
        for _ in range(count):
            v0 = (v0 + v1) & TOP
            v1 = ((v1 << 13) | (v1 >> 51)) & TOP
            v1 ^= v0
            v0 = ((v0 << 32) | (v0 >> 32)) & TOP
            v2 = (v2 + v3) & TOP
            v3 = ((v3 << 16) | (v3 >> 48)) & TOP
            v3 ^= v2
            v0 = (v0 + v3) & TOP
            v3 = ((v3 << 21) | (v3 >> 43)) & TOP
            v3 ^= v0
            v2 = (v2 + v1) & TOP
            v1 = ((v1 << 17) | (v1 >> 47)) & TOP
            v1 ^= v2
            v2 = ((v2 << 32) | (v2 >> 32)) & TOP
        state[:] = [v0, v1, v2, v3]

    length = len(data)
    for at in range(0, length - length % 8, 8):
        word = int.from_bytes(data[at:at + 8], "little")
        state[3] ^= word
        rounds(1)
        state[0] ^= word
    last = (length & 0xFF) << 56 | int.from_bytes(data[length - length % 8:], "little")
    state[3] ^= last
    rounds(1)
    state[0] ^= last
    state[2] ^= 0xFF
    rounds(3)
    return state[0] ^ state[1] ^ state[2] ^ state[3]


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


def draw_signed(stream, big=False):
    word = next(stream)
    kind = word >> 40 & 7
    value = next(stream)
    if kind == 0:
        return 0
    if kind == 1:
        return (value % 2000) - 1000
    if kind == 2:
        return signed(value) >> (value >> 8 & 31 | 24)
    if kind == 3:
        return (value % 10 ** 12) * (1 if word & 1 else -1)
    if kind == 4:
        return [MAX64, MIN64, MAX64 - 1, MIN64 + 1][word >> 8 & 3] if big else (value % 100)
    if kind == 5:
        return value % 30
    return signed(value) >> (value >> 8 & 63)


def draw_key(stream):
    word = next(stream)
    kind = word >> 40 & 7
    value = next(stream)
    if kind <= 3:
        return value % 60
    if kind == 4:
        return 10000 * (value % 4) + value % 25
    if kind == 5:
        return value % 10000
    if kind == 6:
        return value
    return TOP - value % 4


def draw_tag(stream):
    word = next(stream)
    return [0, 1, 1, 1, 2, 3, 0xFFFFFFFF, 0x100000001][word >> 20 & 7]


def draw_div(stream):
    word = next(stream)
    kind = word >> 24 & 7
    value = next(stream)
    if kind == 0:
        return 0 if word & 0x3000000000 == 0 else 1
    if kind <= 2:
        return 1 + value % 50
    if kind <= 4:
        return 1 + value % 100000
    if kind == 5:
        return 1 + value % M32
    return 1 + (value >> 20) % 9


def draw_records(stream, count, mode, big=True):
    keys = set()
    while len(keys) < count:
        keys.add(draw_key(stream))
    keys = sorted(keys)
    out = []
    for key in keys:
        word = next(stream)
        size = draw_signed(stream)
        if size == 0 and word & 3:
            size = 1 + word >> 8 & 255
        out.append((key, rec(tag=draw_tag(stream), c=draw_signed(stream, big), v=size, b=abs(draw_signed(stream)), d=next(stream), div=draw_div(stream),
                             pad=next(stream).to_bytes(8, "little") * 3)))
    return out


def draw_rows(stream, count, plain=False):
    rows = []
    for _ in range(count):
        word = next(stream)
        rows.append(abs(draw_signed(stream)) if word >> 4 & 7 else draw_signed(stream, True) & TOP)
    return rows


def digest_of(outcome):
    kind = outcome[0]
    body = outcome[1] if kind == "ret" else outcome[1:-1]
    text = body.hex() if isinstance(body, bytes) else repr(body)
    return kind, hashlib.sha256(text.encode()).hexdigest()[:16], len(outcome[-1])


# ---------------------------------------------------------------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------------------------------------------------------------

class FoldCase:
    family = "fold"
    once = 0

    def __init__(self, name, container, rows):
        self.name, self.container, self.rows = name, container, rows


class CheckCase:
    buckets, filler, tombs, shape, collide = None, 0, 0, 1, 0
    family = "check"

    def __init__(self, name, arg, key, dex, meta, rows, map=(), qkey=None, once=0, emit=None, probe_bad=0, k0=0x0123456789ABCDEF, k1=0x0FEDCBA987654321):
        self.name, self.arg, self.key, self.dex, self.meta, self.rows = name, arg, key, dex, meta, rows
        self.map, self.qkey, self.once, self.probe_bad, self.k0, self.k1 = list(map), qkey if qkey is not None else key20(1), once, probe_bad, k0, k1
        self.emit = emit if emit is not None else bytes((0x11 * index + 5) & 0xFF for index in range(OUT_SIZE))


class TestCase:
    buckets, filler, tombs, shape, collide = None, 0, 0, 1, 0
    family = "test"

    def __init__(self, name, side, keys, map, once, route, p10, p18, p20, p28, step, k0=0x1111222233334444, k1=0x5555666677778888, probe_bad=0):
        self.name, self.side, self.keys, self.map, self.once, self.route = name, side, keys, list(map), once, route
        self.p10, self.p18, self.p20, self.p28, self.step = p10, p18, p20, p28, step
        self.k0, self.k1, self.probe_bad = k0, k1, probe_bad


class HashCase:
    family = "hash"
    once = 0

    def __init__(self, name, k0, k1, key):
        self.name, self.k0, self.k1, self.key = name, k0, k1, key


class MapCase:
    buckets, filler, tombs, shape, collide = None, 0, 0, 1, 0
    family = "map"
    once = 0

    def __init__(self, name, map, qkey, probe_bad=0, k0=0x0A0B0C0D0E0F1011, k1=0x1213141516171819):
        self.name, self.map, self.qkey, self.probe_bad, self.k0, self.k1 = name, list(map), qkey, probe_bad, k0, k1


def f64(value):
    return to_bits(value)


def put_state(memory, case, meta=(), rows=()):
    memory.put_bytes(STATE, bytes((0x70 + index) & 0xFF for index in range(0x200)))
    memory.write(STATE + 8, 8, META)
    memory.write(STATE + 0x10, 8, len(meta))
    memory.write(STATE + 0x50, 8, getattr(case, "dex", 0))
    memory.write(STATE + 0x68, 8, ENTRIES)
    memory.write(STATE + 0x70, 8, len(case.map) if hasattr(case, "map") else 0)
    memory.write(STATE + 0x78, 8, 0x1111)
    memory.write(STATE + 0x98, 8, getattr(case, "k0", 0))
    memory.write(STATE + 0xA0, 8, getattr(case, "k1", 0))
    memory.write(STATE + 0x150, 8, ROWS)
    memory.write(STATE + 0x158, 8, len(rows))
    for slot, mode in enumerate(meta):
        memory.put_bytes(META + slot * 32, bytes((0x30 + slot + index) & 0xFF for index in range(32)))
        memory.write(META + slot * 32 + 0x1C, 1, mode)
    put_rows(memory, rows)


def put_rows(memory, rows):
    for slot, value in enumerate(rows):
        memory.put_bytes(ROWS + slot * 96, bytes((0x55 + slot + index) & 0xFF for index in range(96)))
        memory.write(ROWS + slot * 96 + 0x20, 8, value & TOP)


def put_map(memory, case):
    for index, (key, container) in enumerate(case.map):
        at = ENTRIES + index * ENTRY_SIZE
        put_container(memory, at, container, BUFS + index * 0x800, TREEMEM + index * 0x2800)
        memory.put_bytes(at + 0x80, key + bytes(ENTRY_SIZE - 0x80 - len(key)))
    put_table(memory, case)


def query_key(case):
    return case.keys[1 if case.side & M32 else 0] if case.family == "test" else case.qkey


def put_table(memory, case):
    """The hashbrown table of the account map: one control byte per bucket (7 hash bits, 0xff empty, 0x80 deleted), 16 mirrored bytes, and below the
    control bytes one index word per bucket. Entries are placed in the table's own probe order (SipHash-1-3 of the key under the map keys)."""
    count = len(case.map)
    ctrl_at = HTAB + 0x400
    memory.write(STATE + 0x78, 8, ctrl_at)
    if count < 2:
        memory.write(STATE + 0x80, 8, 3)
        return
    need = count + case.filler + case.tombs + 1
    buckets = case.buckets or 4
    while buckets < need:
        buckets *= 2
    mask = buckets - 1
    ctrl = bytearray(b"\xff") * (buckets + 16)
    cells = {}

    def set_ctrl(slot, value):
        ctrl[slot] = value
        ctrl[((slot - 16) & mask) + 16] = value

    def find(h):
        pos, stride = h & mask, 0
        while True:
            hits = [i for i in range(16) if ctrl[pos + i] & 0x80]
            if hits:
                slot = (pos + hits[0]) & mask
                if not ctrl[slot] & 0x80:
                    slot = next(i for i in range(16) if ctrl[i] & 0x80)
                return slot
            stride += 16
            pos = (pos + stride) & mask

    stream = lcg(case.shape)
    key = query_key(case)
    wanted = siphash13(case.k0, case.k1, key) >> 57
    other = next(i for i, (name, _) in enumerate(case.map) if name != key)
    for number in range(case.filler):
        h = next(stream)
        if number < case.collide:
            h = wanted << 57 | h & ((1 << 57) - 1)
        slot = find(h)
        set_ctrl(slot, h >> 57)
        cells[slot] = other
    for index, (name, _) in enumerate(case.map):
        h = siphash13(case.k0, case.k1, name)
        slot = find(h)
        set_ctrl(slot, h >> 57)
        cells[slot] = count + case.probe_bad - 1 if name == key and case.probe_bad else index
    for _ in range(case.tombs):
        slot = next(stream) % buckets
        if ctrl[slot] == 0xFF:
            set_ctrl(slot, 0x80)
    memory.put_bytes(ctrl_at, bytes(ctrl))
    for slot, value in cells.items():
        memory.write(ctrl_at - 8 * (slot + 1), 8, value)
    memory.write(STATE + 0x80, 8, mask)
    memory.write(STATE + 0x88, 8, buckets - count - case.filler)
    memory.write(STATE + 0x90, 8, count + case.filler)


def lookup_spec(case, sites, log):
    """The map lookup as a rule list: ('h', offset) of the entry, 0, or an index-panic outcome."""
    count = len(case.map)
    key = query_key(case)
    if count == 0:
        return 0, None
    if count == 1:
        return (("h", ENTRIES - HEAP_BASE), None) if case.map[0][0] == key else (0, None)
    for index, item in enumerate(case.map):
        if item[0] == key:
            if case.probe_bad:
                return None, ("index", count + case.probe_bad - 1, count, sites.probe_index, tuple(log))
            return ("h", ENTRIES + index * ENTRY_SIZE - HEAP_BASE), None
    return 0, None


def entry_index(found):
    return None if found == 0 else (found[1] - (ENTRIES - HEAP_BASE)) // ENTRY_SIZE


# ---------------------------------------------------------------------------------------------------------------------------------
# Rule lists
# ---------------------------------------------------------------------------------------------------------------------------------

def spec_fold(case, sites, m=frozenset()):
    log = []
    acc = case.container.acc if "acc_zero_start" not in m else 0
    nrows = len(case.rows)
    recs = list(case.container.recs)
    if "reverse_order" in m:
        recs.reverse()
    for key, item in recs:
        index = key % (9999 if "index_mod_9999" in m else SEARCH_KEY_LIMIT)
        if index >= nrows:
            return ("index", index, nrows, sites.fold_index, tuple(log))
        x = signed(case.rows[index])
        if x < 0:
            return ("panic", sites.fold_size, tuple(log))
        product = x * item["v"]
        if not MIN64 <= product <= MAX64:
            return ("panic", sites.fold_size, tuple(log))
        magnitude = abs(product)
        if item["div"] == 0:
            return ("fault", "divide", tuple(log))
        divisor = item["div"] + (1 if "divisor_plus_one" in m else 0)
        low = magnitude & M32 if "div_32bit_only" in m else magnitude
        quotient = low // divisor
        tag = item["tag"]
        stored = tag == 1 if "tag_low_bit" not in m else tag & 1 == 1
        if "tag_ignored" in m:
            stored = False
        if not stored:
            total = acc + product
            if not MIN64 <= total <= MAX64:
                log.append(("sat", 0, sites.fold_sat_sum))
                total = sat(total) if "no_sat_sum" not in m else signed(total)
            if quotient >> 63:
                return ("fmt", sites.fold_fmt, tuple(log))
            if "sub_first" in m:
                total = acc - quotient + product
            else:
                total = total - quotient
            if not MIN64 <= total <= MAX64:
                log.append(("sat", 0, sites.fold_sat_sub))
                total = sat(total) if "no_sat_sub" not in m else signed(total)
            acc = total
        else:
            extra = product + item["c"]
            if not MIN64 <= extra <= MAX64:
                log.append(("sat", 0, sites.fold_sat_add))
                extra = sat(extra)
            if quotient >> 63:
                return ("fmt", sites.fold_fmt, tuple(log))
            if "no_threshold" not in m:
                if ("threshold_gt" in m and extra > quotient) or ("threshold_gt" not in m and "unsigned_compare" not in m and extra >= quotient) \
                        or ("unsigned_compare" in m and extra & TOP >= quotient):
                    continue
            total = acc + extra
            if not MIN64 <= total <= MAX64:
                log.append(("sat", 0, sites.fold_sat_sum))
                total = sat(total)
            total = total - quotient
            if not MIN64 <= total <= MAX64:
                log.append(("sat", 0, sites.fold_sat_sub))
                total = sat(total)
            acc = total
    if "ret_abs" in m:
        value = abs(acc) if acc != MIN64 else MAX64
    elif "ret_negative_ok" in m:
        value = (-acc) & TOP if acc != MIN64 else MAX64
    elif "ret_min_wraps" in m:
        value = max(-acc, 0) & TOP
    else:
        value = MAX64 if acc == MIN64 else max(-acc, 0)
    return ("ret", value, tuple(log))


def spec_check(case, sites, m=frozenset()):
    log = []
    out = bytearray(OUT_INIT)
    value = to_float(case.arg)
    consts = sites.consts

    def code(number):
        out[0:2] = number.to_bytes(2, "little")
        return ("ret", bytes(out), tuple(log))

    low_bad = consts["low"] > value
    high_bad = value > consts["one"]
    if "range_inclusive" in m:
        low_bad, high_bad = consts["low"] >= value, value >= consts["one"]
    if "nan_rejected" in m:
        low_bad = low_bad or value != value
    if low_bad or high_bad:
        return code(0x46)
    dex, index = divmod(case.key, SEARCH_KEY_LIMIT)
    if dex != case.dex or index >= len(case.meta):
        return ("panic", sites.check_key, tuple(log))
    mode = case.meta[index]
    if (mode == 0) if "mode_nonzero" in m else (mode != 2):
        return code(0x14E)
    found, bad = lookup_spec(case, sites, log)
    if bad is not None:
        return bad
    if case.once:
        log.append(("once", ONCE, 1) + sites.once_args[2:] + (DEFAULT,))
    container = None
    if found != 0:
        container = case.map[entry_index(found)][1]
    items = dict(container.recs) if container is not None else {}
    item = items.get(case.key)
    if item is None:
        return code(0x1A2)
    nrows = len(case.rows)
    if index >= nrows:
        return ("index", index, nrows, sites.check_index, tuple(log))
    x = signed(case.rows[index])
    if x < 0:
        return ("panic", sites.check_size, tuple(log))
    product = x * item["v"]
    if not MIN64 <= product <= MAX64:
        return ("panic", sites.check_size, tuple(log))
    if not item["tag"] & 1:
        return code(0x1A2)
    total = product + item["c"]
    if not MIN64 <= total <= MAX64:
        log.append(("sat", 0, sites.check_sat))
        total = sat(total) if "no_add_sat" not in m else signed(total)
    magnitude = abs(product)
    if magnitude >> 63:
        return ("fmt", sites.check_fmt, tuple(log))
    scaled = float(magnitude) * (consts["one"] / value) if "ratio_inverted" not in m else float(magnitude) * (value / consts["one"])
    if scaled != scaled or scaled in (math.inf, -math.inf):
        clipped = 0.0
    else:
        clipped = scaled if scaled <= consts["bound"] else consts["bound"]
    cast = MAX64 if clipped > consts["top"] else int(clipped) if "cast_rounds" not in m else int(clipped + 0.5)
    if "cast_wraps" in m and clipped >= consts["bound"]:
        cast = MIN64
    difference = cast - total
    if not MIN64 <= difference <= MAX64:
        return code(0xC4)
    if (difference < 0) if "diff_nonneg" in m else (difference <= 0):
        return code(0x1A2)
    log.append(("emit", ("h", STATE - HEAP_BASE), ("h", QKEY - HEAP_BASE), case.key))
    if int.from_bytes(case.emit[0:2], "little") == 0x1A2 and "emit_copied_always" not in m:
        return code(0x1A2)
    out[:] = case.emit[:OUT_SIZE]
    return ("ret", bytes(out), tuple(log))


def spec_test(case, sites, m=frozenset()):
    log = []
    side = case.side & M32
    found, bad = lookup_spec(case, sites, log)
    if bad is not None:
        return bad
    if case.once:
        log.append(("once", ONCE, 1) + sites.once_args[2:] + (DEFAULT,))
    container_acc = 0 if found == 0 else case.map[entry_index(found)][1].acc
    where = DEFAULT if found == 0 else found
    log.append(("route", where, 0, 1, ("h", STATE + 0x148 - HEAP_BASE), ("h", STATE - HEAP_BASE)))
    a, b = signed(case.route[0]), signed(case.route[1])
    if b < 0:
        return ("fmt", sites.test_fmt_a, tuple(log))
    acc = container_acc
    gap = a - b
    if not MIN64 <= gap <= MAX64:
        log.append(("sat", 0, sites.test_sat_diff))
        gap = sat(gap)
    spare = acc - max(gap, 0)
    if not MIN64 <= spare <= MAX64:
        log.append(("drop", 0xC4))
        return ("ret", 2, tuple(log))
    log.append(("big", where, case.p10 & TOP, ("h", STATE - HEAP_BASE)))
    if signed(case.p18) < 0:
        return ("fmt", sites.test_fmt_b, tuple(log))
    delta = signed(case.p18)
    flip = (side & 0xFF) != 0
    if "flip_on_word" in m:
        flip = side != 0
    if flip:
        delta = -delta
    log.append(("next", "stack", case.p20 & TOP, delta & TOP, acc & TOP, spare & TOP, case.p28 & TOP))
    tag, second, third, extra = case.step
    if tag & M32 == 2:
        return ("ret", 2, tuple(log))
    rest = a - acc
    if not MIN64 <= rest <= MAX64:
        log.append(("drop", 0xC4))
        return ("ret", 2, tuple(log))
    rest += signed(extra) if "rest_without_extra" not in m else 0
    if not MIN64 <= rest <= MAX64:
        log.append(("drop", 0xC3))
        return ("ret", 2, tuple(log))
    tag &= M32
    unit = signed(case.p28)
    if tag == 0 or "move_always" in m:
        if unit < 0:
            return ("ret", 2, tuple(log))
        move = unit * delta
        if not MIN64 <= move <= MAX64:
            return ("ret", 2, tuple(log))
    else:
        move = 0
    rest += move
    if not MIN64 <= rest <= MAX64:
        log.append(("drop", 0xC3))
        return ("ret", 2, tuple(log))
    if unit < 0:
        return ("panic", sites.test_size, tuple(log))
    other = unit * signed(third)
    if not MIN64 <= other <= MAX64:
        return ("panic", sites.test_size, tuple(log))
    if tag == 1 or "second_always" in m:
        other += signed(second)
        if not MIN64 <= other <= MAX64:
            log.append(("sat", 0, sites.test_sat_mul))
            other = sat(other)
    floor = -100 if "floor_zero" not in m else 0
    keep = int(rest >= floor)
    keep_other = int(other >= floor)
    if "tag_xor_dropped" in m:
        return ("ret", keep & keep_other, tuple(log))
    return ("ret", (((tag & 0xFF) ^ 1) | keep_other) & keep & 0xFF, tuple(log))


def spec_hash(case, sites, m=frozenset()):
    return ("ret", siphash13(case.k0, case.k1, case.key), ())


def spec_map(case, sites, m=frozenset()):
    log = []
    found, bad = lookup_spec(case, sites, log)
    if bad is not None:
        return bad
    return ("ret", found, tuple(log))


SPECS = {"fold": spec_fold, "check": spec_check, "test": spec_test, "map": spec_map, "hash": spec_hash}


# ---------------------------------------------------------------------------------------------------------------------------------
# Running a case on the bytes
# ---------------------------------------------------------------------------------------------------------------------------------

def run_case(world, case):
    memory = world.reset(case)
    machine = world.machine
    if case.family == "fold":
        put_state(memory, case, rows=case.rows)
        memory.write(TABLE1 + 8, 8, ROWS)
        memory.write(TABLE1 + 0x10, 8, len(case.rows))
        put_container(memory, CONT1, case.container, BUFS, TREEMEM)
        entry, args = TOTAL, {RDI: CONT1, RSI: TABLE1}
    elif case.family == "check":
        put_state(memory, case, case.meta, case.rows)
        put_map(memory, case)
        memory.put_bytes(QKEY, case.qkey)
        machine.xmm[0] = case.arg
        entry, args = CHECK, {RDI: OUT, RSI: STATE, RDX: QKEY, RCX: case.key}
    elif case.family == "test":
        put_state(memory, case)
        put_map(memory, case)
        memory.put_bytes(KEYS, case.keys[0] + case.keys[1])
        for slot, value in enumerate((KEYS, STATE, V10, V18, V20, V28)):
            memory.write(CTX + 8 * slot, 8, value)
        for at, value in ((V10, case.p10), (V18, case.p18), (V20, case.p20), (V28, case.p28)):
            memory.write(at, 8, value & TOP)
        entry, args = OKAY, {RDI: CTX, RSI: case.side}
    elif case.family == "hash":
        memory.put_bytes(QKEY, case.key)
        entry, args = HASH, {RDI: case.k0, RSI: case.k1, RDX: QKEY}
    else:
        put_state(memory, case)
        put_map(memory, case)
        memory.put_bytes(QKEY, case.qkey)
        entry, args = MAPGET, {RDI: STATE + 0x60, RSI: QKEY}
    before = bytes(memory.heap[:USED])
    result = world.execute(entry, args, before)
    if result[0] != "ret":
        return before, result
    after = bytes(memory.heap[:USED])
    value = result[1]
    skips = []
    if case.family == "check":
        if value != OUT:
            raise Halt("result pointer")
        value = after[OUT - HEAP_BASE:OUT - HEAP_BASE + OUT_SIZE]
        skips.append((OUT - HEAP_BASE, OUT - HEAP_BASE + OUT_SIZE))
    elif case.family == "map":
        value = rel(value)
    elif case.family == "test":
        value &= 0xFF
    left, right = bytearray(before), bytearray(after)
    for start, end in skips:
        left[start:end] = bytes(end - start)
        right[start:end] = bytes(end - start)
    if left != right:
        raise Halt("state changed outside the result")
    return before, ("ret", value, result[2])


# ---------------------------------------------------------------------------------------------------------------------------------
# Case generators
# ---------------------------------------------------------------------------------------------------------------------------------

def ring(recs, cap=None, head=0, acc=0):
    return Container("ring", recs, cap if cap is not None else len(recs) + 1, head, acc)


def tree(recs, acc=0):
    return Container("tree", recs, None, 0, acc)


def seq(count, fn):
    return [(index + 1, fn(index)) for index in range(count)]


def fold_named():
    out = []

    def add(name, recs, rows, mode="ring", cap=None, head=0, acc=0, height=None):
        container = ring(recs, cap, head, acc) if mode == "ring" else Container("tree", recs, None, 0, acc, height)
        out.append(FoldCase(name, container, rows))

    plain = rec(tag=0, c=0, v=5, div=2)
    add("empty ring", [], [10] * 4)
    add("empty tree", [], [10] * 4, "tree")
    add("empty min accumulator", [], [10], acc=MIN64)
    add("empty positive accumulator", [], [10], acc=77)
    add("empty negative accumulator", [], [10], acc=-77)
    add("plain one ring", [(1, plain)], [0, 100], cap=3, head=2)
    add("plain one tree", [(1, plain)], [0, 100], "tree")
    add("tag one skipped", [(1, rec(tag=1, c=1000, v=5, div=2))], [0, 100])
    add("tag one applied", [(1, rec(tag=1, c=0, v=5, div=1000))], [0, 100])
    add("tag one equal skips", [(1, rec(tag=1, c=-499, v=5, div=500))], [0, 100])
    add("tag one one below applies", [(1, rec(tag=1, c=-500, v=5, div=500))], [0, 100])
    add("tag one one above skips", [(1, rec(tag=1, c=-498, v=5, div=500))], [0, 100])
    add("tag one negative threshold", [(1, rec(tag=1, c=-600, v=5, div=1))], [0, 100])
    add("tag one equal with a saturating accumulator", [(1, rec(tag=1, c=-499, v=5, div=500))], [0, 100], acc=MAX64)
    add("tag one equal with a saturating accumulator low", [(1, rec(tag=1, c=-499, v=5, div=500))], [0, 100], acc=MIN64)
    add("exact multiple of 10000", [(10000, rec(tag=0, v=5, div=2))], [100])
    add("second exact multiple", [(20000, rec(tag=0, v=5, div=2))], [100])
    add("largest exact multiple", [(TOP - TOP % 10000, rec(tag=0, v=5, div=2))], [100])
    add("largest key", [(TOP, rec(tag=0, v=5, div=2))], [100])
    add("largest key below a multiple", [(TOP - TOP % 10000 - 1, rec(tag=0, v=5, div=2))], [100])
    add("tag three is not stored", [(1, rec(tag=3, c=0, v=5, div=1))], [0, 100])
    add("tag high word", [(1, rec(tag=0x100000001, c=0, v=5, div=1))], [0, 100])
    add("tag all ones", [(1, rec(tag=0xFFFFFFFF, c=0, v=5, div=1))], [0, 100])
    add("divide by zero", [(1, rec(tag=0, v=5, div=0))], [0, 100])
    add("divide by zero after good", [(1, plain), (2, rec(tag=0, v=5, div=0))], [0, 100, 100])
    add("wide dividend", [(1, rec(tag=0, v=1 << 40, div=3))], [0, 7])
    add("wide dividend max divisor", [(1, rec(tag=0, v=1 << 40, div=M32))], [0, 7])
    add("narrow dividend max divisor", [(1, rec(tag=0, v=3, div=M32))], [0, 7])
    add("dividend exactly 2^32", [(1, rec(tag=0, v=1 << 32, div=7))], [0, 1])
    add("dividend 2^32 minus one", [(1, rec(tag=0, v=(1 << 32) - 1, div=7))], [0, 1])
    add("quotient too big", [(1, rec(tag=0, v=MIN64, div=1))], [0, 1])
    add("quotient too big tag one", [(1, rec(tag=1, v=MIN64, div=1, c=0))], [0, 1])
    add("most negative product halved", [(1, rec(tag=0, v=MIN64, div=2))], [0, 1])
    add("negative row", [(1, plain)], [0, MIN64 & TOP])
    add("product overflow", [(1, rec(tag=0, v=MAX64, div=1))], [0, 2])
    add("index panic", [(5, plain)], [1, 2])
    add("index at count", [(2, plain)], [1, 2])
    add("key modulo 10000", [(10001, plain), (20001, plain)], [0, 5])
    add("sum saturates high", [(1, rec(tag=0, v=MAX64, div=1, c=0)), (2, rec(tag=0, v=MAX64, div=1))], [0, 1, 1], acc=MAX64)
    add("sum saturates low", [(1, rec(tag=0, v=-5, div=1))], [0, MAX64], acc=MIN64 + 1)
    add("difference saturates low", [(1, rec(tag=0, v=0, div=1)), (2, rec(tag=0, v=0, div=1))], [0, 0, 0], acc=MIN64 + 3)
    add("difference saturates high", [(1, rec(tag=0, v=-5, div=1))], [0, 1], acc=MAX64 - 1)
    add("tag one add saturates", [(1, rec(tag=1, v=MAX64, c=MAX64, div=1))], [0, 1])
    add("tag one add saturates low", [(1, rec(tag=1, v=-(1 << 62) - 5, c=MIN64, div=1))], [0, 1])
    add("tag one sum saturates", [(1, rec(tag=1, v=1 << 60, c=0, div=1 << 20))], [0, 1], acc=MAX64)
    add("tag one subtract saturates", [(1, rec(tag=1, v=1 << 60, c=0, div=1 << 30))], [0, 1], acc=MIN64 + 3)
    add("wrapped ring", seq(4, lambda i: rec(tag=i & 1, v=i + 2, c=i, div=i + 1)), [0] + [30] * 6, cap=4, head=3)
    add("ring head beyond capacity", seq(4, lambda i: rec(tag=i & 1, v=i + 2, c=i, div=i + 1)), [0] + [30] * 6, cap=5, head=7)
    add("ring split exactly", seq(3, lambda i: rec(tag=0, v=i + 2, div=i + 1)), [0] + [30] * 6, cap=6, head=3)
    add("ring full", seq(5, lambda i: rec(tag=0, v=i + 2, div=i + 1)), [0] + [30] * 6, cap=5, head=0)
    add("tree two levels", seq(30, lambda i: rec(tag=i % 3, v=i + 2, c=i * 7, div=i + 1)), [0] + [30] * 31, "tree")
    add("tree eleven keys", seq(11, lambda i: rec(tag=i % 2, v=i + 2, c=i * 9, div=i + 1)), [0] + [30] * 12, "tree")
    add("tree twelve keys", seq(12, lambda i: rec(tag=i % 2, v=i + 2, c=i * 9, div=i + 1)), [0] + [30] * 13, "tree")
    add("tree height two", seq(60, lambda i: rec(tag=i % 2, v=i + 2, c=i * 9, div=i + 1)), [0] + [30] * 61, "tree", height=2)
    add("tree height two minimum", seq(7, lambda i: rec(tag=i % 2, v=i + 2, c=i * 9, div=i + 1)), [0] + [30] * 8, "tree", height=2)
    add("tree 200 keys", seq(200, lambda i: rec(tag=i % 3, v=i + 2, c=i * 9, div=i + 1)), [0] + [30] * 201, "tree")
    add("tree fifty keys", seq(50, lambda i: rec(tag=i % 2, v=i + 2, c=i * 9, div=i + 1)), [0] + [30] * 51, "tree")
    add("tree last key panics", seq(30, lambda i: rec(tag=0, v=i + 2, div=i + 1)), [0] + [30] * 29, "tree")
    add("ring first key panics", [(40, plain)] + [(50, plain)], [0] * 3)
    return out


def fold_vector(stream, index):
    mode = "ring" if next(stream) >> 30 & 3 else "tree"
    count = (next(stream) >> 30) % (14 if mode == "ring" else 40)
    recs = draw_records(stream, count, mode)
    nrows = 1 + (next(stream) >> 30) % 70
    rows = draw_rows(stream, nrows)
    word = next(stream)
    acc = [0, draw_signed(stream, True), MAX64, MIN64, 12345, -5][word >> 20 & 7 if word >> 20 & 7 < 6 else 0]
    if word & 1 == 0:
        # make most positions addressable so the loop is exercised past its first item
        recs = [(key % 40 + 1 + 10000 * (key >> 20 & 1), item) for key, item in recs]
        recs = sorted({key: item for key, item in recs}.items())
        rows = [abs(signed(value)) % (1 << 24) for value in rows] + [abs(signed(next(stream))) % (1 << 24) for _ in range(45)]
        recs = [(key, dict(item, v=signed(item["v"]) >> 36 if abs(item["v"]) > (1 << 40) else item["v"])) for key, item in recs]
    if word & 0x1C == 0x1C:
        recs = [(key, dict(item, div=item["div"] or 1)) for key, item in recs]
    cap = len(recs) + (next(stream) >> 30) % 6 + (1 if recs else 0)
    head = (next(stream) >> 30) % max(cap, 1) + (cap if word >> 8 & 3 == 0 else 0)
    container = Container(mode, recs, cap if mode == "ring" else None, head if mode == "ring" else 0, acc)
    return FoldCase("f%d" % index, container, rows)


def check_named():
    out = []
    base_meta = [2, 0, 2, 2, 2, 3, 2, 2]
    here = key20(1)
    other = key20(2)

    def add(name, **kw):
        fields = dict(arg=f64(0.75), key=3, dex=0, meta=base_meta, rows=[0, 0, 0, 100], map=[(here, ring([(3, rec(tag=1, c=0, v=5, div=1))], 4, 2))], qkey=here, once=0)
        fields.update(kw)
        out.append(CheckCase(name, fields["arg"], fields["key"], fields["dex"], fields["meta"], fields["rows"], fields["map"], fields["qkey"], fields["once"],
                             emit=fields.get("emit"), probe_bad=fields.get("probe_bad", 0)))

    add("emitted request")
    add("emitted request tree", map=[(here, tree([(3, rec(tag=1, c=0, v=5))]))])
    add("emitted at lower bound", arg=f64(0.5))
    add("emitted at upper bound", arg=f64(1.0))
    add("below lower bound", arg=f64(0.4999999999999999))
    add("above upper bound", arg=f64(1.0000000000000002))
    add("nan passes the gate", arg=0x7FF8000000000000)
    add("negative nan passes the gate", arg=0xFFF8000000000001)
    add("infinity above", arg=f64(math.inf))
    add("negative infinity", arg=f64(-math.inf))
    add("negative zero", arg=f64(-0.0))
    add("wrong dex", key=10003, dex=0)
    add("dex matches", key=10003, dex=1, rows=[0, 0, 0, 100], meta=[2] * 4, map=[(here, ring([(10003, rec(tag=1, c=0, v=5))], 2, 0))])
    add("asset beyond count", key=9, meta=[2] * 8, rows=[0] * 10)
    add("asset at count", key=8, meta=[2] * 8, rows=[0] * 10)
    add("mode zero", key=1, meta=[2, 0, 2, 2])
    add("mode one", key=3, meta=[2, 2, 2, 1])
    add("mode three", key=3, meta=[2, 2, 2, 3])
    add("mode 0x102", key=3, meta=[2, 2, 2, 2])
    add("map empty uses default", map=[])
    add("map one miss", map=[(other, ring([(3, rec(tag=1))], 4, 0))])
    add("map two hit second", map=[(other, ring([(3, rec(tag=0))], 4, 0)), (here, ring([(3, rec(tag=1, c=0, v=5))], 4, 2))])
    add("map two miss", map=[(other, ring([(3, rec(tag=0))], 4, 0)), (key20(3), ring([(3, rec(tag=1))], 4, 2))])
    add("map three hit third", map=[(other, ring([], 1, 0)), (key20(3), tree([])), (here, ring([(3, rec(tag=1, c=0, v=5))], 4, 2))])
    add("probe returns index at count", map=[(other, ring([], 1, 0)), (here, ring([(3, rec(tag=1))], 4, 2))], probe_bad=1)
    add("probe returns index past count", map=[(other, ring([], 1, 0)), (here, ring([(3, rec(tag=1))], 4, 2))], probe_bad=3)
    add("once word set", once=3)
    add("once word set and miss", once=3, map=[])
    add("key absent from account", key=2, rows=[0, 0, 100], map=[(here, ring([(3, rec(tag=1))], 4, 2))])
    add("row index beyond rows", rows=[0, 0, 0])
    add("negative row word", rows=[0, 0, 0, MIN64 & TOP])
    add("row word 2^63 minus one", rows=[0, 0, 0, MAX64], map=[(here, ring([(3, rec(tag=1, c=0, v=1))], 4, 2))])
    add("product overflow", rows=[0, 0, 0, 2], map=[(here, ring([(3, rec(tag=1, v=MAX64))], 4, 2))])
    add("tag low bit clear", map=[(here, ring([(3, rec(tag=2, c=0, v=5))], 4, 2))])
    add("tag high bits ignored", map=[(here, ring([(3, rec(tag=0xFFFFFFFE, c=0, v=5))], 4, 2))])
    add("tag low bit with high bits", map=[(here, ring([(3, rec(tag=0x80000001, c=0, v=5))], 4, 2))])
    add("sum saturates high", rows=[0, 0, 0, 1], map=[(here, ring([(3, rec(tag=1, c=MAX64, v=7))], 4, 2))])
    add("sum saturates high wrapped to the low half", rows=[0, 0, 0, 1], arg=f64(0.5), map=[(here, ring([(3, rec(tag=1, c=1, v=MAX64))], 4, 2))])
    add("sum saturates high wrapped to the upper half", rows=[0, 0, 0, 1], arg=f64(0.5), map=[(here, ring([(3, rec(tag=1, c=MAX64, v=MAX64))], 4, 2))])
    add("sum saturates high wrapped near zero", rows=[0, 0, 0, 1], arg=f64(0.5), map=[(here, ring([(3, rec(tag=1, c=(1 << 62) + 5, v=MAX64 - 7))], 4, 2))])
    add("sum saturates low", rows=[0, 0, 0, 1], map=[(here, ring([(3, rec(tag=1, c=MIN64, v=-7))], 4, 2))])
    add("most negative product", rows=[0, 0, 0, 1], map=[(here, ring([(3, rec(tag=1, c=0, v=MIN64))], 4, 2))])
    add("difference positive", rows=[0, 0, 0, 100], map=[(here, ring([(3, rec(tag=1, c=-1000, v=5))], 4, 2))])
    add("difference zero", rows=[0, 0, 0, 1], arg=f64(1.0), map=[(here, ring([(3, rec(tag=1, c=0, v=8))], 4, 2))])
    add("difference negative", rows=[0, 0, 0, 100], map=[(here, ring([(3, rec(tag=1, c=1000, v=5))], 4, 2))])
    add("difference overflow high", rows=[0, 0, 0, 1], arg=f64(0.5), map=[(here, ring([(3, rec(tag=1, c=MIN64, v=(1 << 62)))], 4, 2))])
    add("difference cannot overflow low", rows=[0, 0, 0, 1], arg=f64(1.0), map=[(here, ring([(3, rec(tag=1, c=MAX64, v=0))], 4, 2))])
    add("scaled value above 2^63", rows=[0, 0, 0, 1], arg=f64(0.5), map=[(here, ring([(3, rec(tag=1, c=-5, v=MAX64))], 4, 2))])
    add("scaled value at 2^63", rows=[0, 0, 0, 1], arg=f64(1.0), map=[(here, ring([(3, rec(tag=1, c=-5, v=MAX64))], 4, 2))])
    add("scaled value between 2^62 and 2^63", rows=[0, 0, 0, 1], arg=f64(1.0), map=[(here, ring([(3, rec(tag=1, c=-5, v=5 * 10 ** 18))], 4, 2))])
    add("fraction rounding boundary", rows=[0, 0, 0, 1], arg=f64(0.6), map=[(here, ring([(3, rec(tag=1, c=0, v=1))], 4, 2))])
    add("fraction rounding boundary one below", rows=[0, 0, 0, 1], arg=f64(0.6), map=[(here, ring([(3, rec(tag=1, c=-1, v=1))], 4, 2))])
    add("tree key above every key", map=[(here, tree(seq(30, lambda i: rec(tag=1, c=-9, v=4))))], key=35, meta=[2] * 40, rows=[0] * 36)
    add("tree key above every key small", map=[(here, tree(seq(5, lambda i: rec(tag=1, c=-9, v=4))))], key=9, meta=[2] * 40, rows=[0] * 10)
    add("scaled value just below", rows=[0, 0, 0, 1], arg=f64(0.5), map=[(here, ring([(3, rec(tag=1, c=-5, v=(1 << 62) - 1000))], 4, 2))])
    add("nan fraction yields zero", arg=0x7FF8000000000000, map=[(here, ring([(3, rec(tag=1, c=-5, v=5))], 4, 2))])
    add("nan fraction negative sum", arg=0x7FF8000000000000, rows=[0, 0, 0, 1], map=[(here, ring([(3, rec(tag=1, c=-50, v=5))], 4, 2))])
    add("emit reports no change", emit=b"\xa2\x01" + bytes(range(2, OUT_SIZE)), map=[(here, ring([(3, rec(tag=1, c=-1000, v=5))], 4, 2))])
    add("emit tag one a one", emit=b"\xa1\x01" + bytes(range(2, OUT_SIZE)), map=[(here, ring([(3, rec(tag=1, c=-1000, v=5))], 4, 2))])
    add("emit tag low byte only", emit=b"\xa2\x02" + bytes(range(2, OUT_SIZE)), map=[(here, ring([(3, rec(tag=1, c=-1000, v=5))], 4, 2))])
    add("wrapped ring hit", map=[(here, ring([(1, rec(tag=0)), (2, rec(tag=0)), (3, rec(tag=1, c=-9, v=4)), (4, rec(tag=0))], 4, 3))], rows=[0, 0, 0, 90])
    add("tree two levels", map=[(here, tree(seq(30, lambda i: rec(tag=1, c=-9, v=4))))], key=17, meta=[2] * 20, rows=[0] * 17 + [80])
    add("tree absent", map=[(here, tree(seq(30, lambda i: rec(tag=1, c=-9, v=4))))], key=0, meta=[2] * 20, rows=[80])
    add("key at modulus", key=10000, dex=1, meta=[2], rows=[80], map=[(here, ring([(10000, rec(tag=1, c=-9, v=4))], 2, 0))])
    return out


def shape_table(case, stream):
    word = next(stream)
    case.buckets = 4 << (word >> 20 & 3)
    case.filler = word >> 24 & 7 if word & 3 else 0
    case.tombs = word >> 28 & 3
    case.shape = next(stream) | 1
    case.collide = case.filler // 2 if word >> 32 & 1 else 0


def key_pool(stream, count):
    return [key20(next(stream) % 11) for _ in range(count)]


def make_map(stream, n, qkey, want, items):
    """n map entries; the query key is entry `want` if it is a valid index. `items` are the (key, record) lists to give out."""
    entries = []
    pool = [key20(100 + slot) for slot in range(n)]
    for slot in range(n):
        key = qkey if slot == want else pool[slot]
        recs = items[slot % len(items)]
        word = next(stream)
        mode = "ring" if word >> 20 & 3 else "tree"
        cap = len(recs) + (word >> 28) % 5 + (1 if recs else 0)
        head = (word >> 36) % max(cap, 1)
        entries.append((key, Container(mode, recs, cap if mode == "ring" else None, head if mode == "ring" else 0, draw_signed(stream, True))))
    return entries


def check_vector(stream, index):
    stage = next(stream) >> 30 & 15
    nasset = 1 + (next(stream) >> 30) % 8
    asset = (next(stream) >> 30) % nasset
    dex = (next(stream) >> 30) % 3
    key = dex * 10000 + asset
    state_dex = dex
    if stage == 1:
        state_dex = dex + 1 + (next(stream) >> 30) % 2 if next(stream) & 1 else dex
        if state_dex == dex:
            key = dex * 10000 + nasset + (next(stream) >> 30) % 3
    meta = [2] * nasset
    word = next(stream)
    for slot in range(nasset):
        if (word >> slot) & 3 == 0 and slot != asset:
            meta[slot] = [0, 1, 3, 0xFF][word >> 20 & 3]
    if stage == 2:
        meta[asset] = [0, 1, 3, 0xFF, 0x20][next(stream) >> 30 & 3]
    if stage == 0:
        arg = [0.4, 0.49999, 1.0001, 3.0, math.inf, -math.inf, 0.0, -0.5, math.nan][next(stream) >> 30 % 9 if False else (next(stream) >> 30) % 9]
        arg = f64(arg)
    else:
        pick = next(stream) >> 30 & 7
        arg = f64([0.5, 1.0, 0.75, 0.5 + (next(stream) >> 11) / (1 << 54), 0.9999, 0.51, 0.6, 0.99][pick]) if pick != 6 else 0x7FF8000000000000 if next(stream) & 1 else f64(0.6)
    recs = draw_records(stream, (next(stream) >> 30) % 5, "ring")
    me = (key, rec(tag=draw_tag(stream) if stage != 8 else 1, c=draw_signed(stream, True) if stage != 9 else -abs(draw_signed(stream)), v=draw_signed(stream),
                   div=1, d=next(stream)))
    if stage == 10:
        me[1]["v"] = MAX64 - (next(stream) >> 40 & 3)
    if stage == 11:
        me[1]["v"] = [MIN64, MIN64 + 1, 1 << 62][next(stream) >> 30 % 3 if False else (next(stream) >> 30) % 3]
    if stage != 3:
        recs = sorted({k: v for k, v in recs + [me]}.items())
    else:
        recs = [(k, v) for k, v in recs if k != key]
    n = (next(stream) >> 30) % 4
    want = (next(stream) >> 30) % n if n and stage != 4 else -1
    qkey = key20(500 + (next(stream) >> 30) % 5)
    items = [recs, draw_records(stream, (next(stream) >> 30) % 4, "ring"), recs]
    entries = make_map(stream, n, qkey, want, items)
    nrows = 1 + (next(stream) >> 30) % 12
    if stage == 5:
        nrows = asset
    rows = [abs(signed(next(stream))) % 5000 for _ in range(nrows)]
    word = next(stream)
    if asset < nrows:
        rows[asset] = [0, 1, 7, 100, 1 << 40, MAX64, (MIN64 & TOP) if stage == 6 else 3, 12345][word >> 20 & 7]
    emit = bytes(next(stream) >> 24 & 0xFF for _ in range(OUT_SIZE))
    if (next(stream) >> 20) & 3 == 0:
        emit = b"\xa2\x01" + emit[2:]
    once = (3 if next(stream) & 1 else 0)
    probe_bad = 1 + (next(stream) >> 30) % 2 if stage == 12 else 0
    case = CheckCase("c%d" % index, arg, key, state_dex, meta, rows, entries, qkey, once, emit, probe_bad, k0=next(stream), k1=next(stream))
    shape_table(case, stream)
    return case


def test_named():
    out = []
    here, there = key20(1), key20(2)
    entry = ring([], 1, 0, 1000)

    def add(name, **kw):
        fields = dict(side=0, keys=(here, there), map=[(here, ring([], 1, 0, 1000))], once=0, route=(2000, 100), p10=7, p18=5, p20=9, p28=3, step=(1, 10, 20, 30))
        fields.update(kw)
        out.append(TestCase(name, fields["side"], fields["keys"], fields["map"], fields["once"], fields["route"], fields["p10"], fields["p18"], fields["p20"], fields["p28"],
                            fields["step"], probe_bad=fields.get("probe_bad", 0)))

    add("tag one passes")
    add("tag zero passes", step=(0, 10, 20, 30))
    add("tag two returns two", step=(2, 10, 20, 30))
    add("tag three", step=(3, 10, 20, 30))
    add("tag 256", step=(256, 10, 20, 30))
    add("tag 258 is not two", step=(258, 10, 20, 30))
    add("tag high word", step=(0x100000001, 10, 20, 30))
    add("side one uses second key", side=1, map=[(there, ring([], 1, 0, -50))])
    add("side word 256 uses second key unflipped", side=256, map=[(there, ring([], 1, 0, -50))])
    add("side 0xffffffff", side=M32, map=[(there, ring([], 1, 0, -50))])
    add("side one flips the figure", side=1, p18=50, step=(0, 0, 0, 0), p28=1)
    add("side zero does not flip", side=0, p18=50, step=(0, 0, 0, 0), p28=1)
    add("map empty uses default", map=[])
    add("map two found", map=[(there, ring([], 1, 0, 7)), (here, ring([], 1, 0, 1000))])
    add("map two missing", map=[(there, ring([], 1, 0, 7)), (key20(3), ring([], 1, 0, 1000))])
    add("map three side one", side=1, map=[(here, ring([], 1, 0, 1)), (key20(3), ring([], 1, 0, 1)), (there, ring([], 1, 0, 1000))])
    add("probe index at count", map=[(there, ring([], 1, 0, 7)), (here, ring([], 1, 0, 1000))], probe_bad=1)
    add("once word set", once=3)
    add("negative second route word", route=(500, -1))
    add("route difference saturates high", route=(MAX64, -0) if False else (MAX64, 0))
    add("route difference saturates low", route=(MIN64, 5))
    add("route difference exactly min", route=(MIN64 + 5, 5))
    add("route difference negative", route=(5, 500))
    add("spare overflow", route=(1, 0), map=[(here, ring([], 1, 0, MIN64))])
    add("spare overflow with gap", route=(500, 100), map=[(here, ring([], 1, 0, MIN64 + 100))])
    add("spare no overflow at edge", route=(500, 100), map=[(here, ring([], 1, 0, MIN64 + 400))])
    add("negative figure", p18=-1)
    add("zero figure", p18=0)
    add("remainder overflow", step=(1, 10, 20, 30), route=(MIN64, 0), map=[(here, ring([], 1, 0, 1))])
    add("extra overflow", step=(1, 10, 20, MAX64), route=(MAX64, 0))
    add("extra overflow low", step=(1, 10, 20, MIN64), route=(MIN64 + 1, 0), map=[(here, ring([], 1, 0, 0))])
    add("tag zero negative unit", step=(0, 10, 20, 30), p28=-4)
    add("tag zero move overflow", step=(0, 10, 20, 30), p28=MAX64, p18=2)
    add("tag zero move added", step=(0, 10, 20, 30), p28=1000, p18=3)
    add("tag zero move overflow into remainder", step=(0, 10, 20, 0), p28=3, p18=3, route=(MAX64, 0), map=[(here, ring([], 1, 0, 0))])
    add("tag one negative unit panics", step=(1, 10, 20, 30), p28=-4)
    add("tag one product overflow panics", step=(1, 10, 20, 30), p28=MAX64)
    add("tag one multiplier overflow panics", step=(1, 10, MAX64, 30), p28=2)
    add("tag one sum saturates", step=(1, MAX64, 1, 30), p28=2)
    add("tag one sum saturates low", step=(1, MIN64, 1, 30), p28=2)
    add("tag three skips the sum", step=(3, MAX64, 1, 30), p28=2)
    add("remainder at floor", step=(1, 10, 20, -100), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    add("remainder below floor", step=(1, 10, 20, -101), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    add("other at floor", step=(1, -100, 0, 0), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    add("other below floor", step=(1, -101, 0, 0), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    add("tag zero ignores other", step=(0, -101, 0, 0), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    add("tag three ignores other", step=(3, -101, 0, 0), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    add("tag 257 low byte one", step=(257, -101, 0, 0), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    add("both below floor tag zero", step=(0, 0, 0, -101), route=(0, 0), map=[(here, ring([], 1, 0, 0))], p28=0)
    return out


def test_vector(stream, index):
    word = next(stream)
    side = [0, 1, 2, 256, M32, 0x80000000][word >> 20 & 7 if word >> 20 & 7 < 6 else 0]
    n = (next(stream) >> 30) % 4
    keys = (key20(900), key20(901))
    qkey = keys[1] if side else keys[0]
    want = (next(stream) >> 30) % n if n and (next(stream) & 3) else -1
    entries = make_map(stream, n, qkey, want, [[], []])
    route = (draw_signed(stream, True), abs(draw_signed(stream, True)) if next(stream) & 7 else draw_signed(stream, True))
    tag = [0, 1, 2, 3, 256, 257, 0x100000001, M32][next(stream) >> 24 & 7]
    step = (tag, draw_signed(stream, True), draw_signed(stream, True), draw_signed(stream, True))
    p18 = abs(draw_signed(stream, True)) if next(stream) & 15 else draw_signed(stream, True)
    p28 = draw_signed(stream, True) if next(stream) & 3 else abs(draw_signed(stream)) % 1000
    if next(stream) & 3 == 0:
        route = ((next(stream) >> 40) % 1000, (next(stream) >> 40) % 300)
        step = (tag, (next(stream) >> 40) % 400 - 200, (next(stream) >> 40) % 6, (next(stream) >> 40) % 400 - 200)
        p28 = (next(stream) >> 40) % 6
        p18 = (next(stream) >> 40) % 30
    case = TestCase("t%d" % index, side, keys, entries, 3 if next(stream) & 1 else 0, route, next(stream), p18, next(stream), p28, step,
                    k0=next(stream), k1=next(stream), probe_bad=1 + (next(stream) >> 30) % 2 if (next(stream) & 31) == 0 else 0)
    shape_table(case, stream)
    return case


def map_cases():
    out = []
    keys = [key20(40 + slot) for slot in range(5)]
    for count in range(0, 5):
        entries = [(keys[slot], ring([], 1, 0, slot)) for slot in range(count)]
        for probe in list(keys[:count]) + [key20(77)]:
            out.append(MapCase("m%d-%s" % (count, probe[:1].hex()), entries, probe))
        if count >= 2:
            for bad in (1, 2, 5):
                out.append(MapCase("bad%d-%d" % (count, bad), entries, keys[0], probe_bad=bad))
            for buckets, filler, tombs in ((4, 0, 0), (8, 3, 0), (16, 8, 2), (32, 20, 4), (64, 40, 6), (16, 0, 5), (128, 100, 8)):
                for probe in (keys[0], keys[count - 1], key20(77)):
                    case = MapCase("shape%d-%d-%d-%d-%s" % (count, buckets, filler, tombs, probe[:1].hex()), entries, probe)
                    case.buckets, case.filler, case.tombs, case.shape, case.collide = buckets, filler, tombs, 7 + buckets, filler // 2
                    out.append(case)
    # near-equal keys: one byte of the 20 differs (the 16 + 4 byte compare of the single-entry path)
    for position in range(20):
        mutated = bytearray(keys[0])
        mutated[position] ^= 0x40
        out.append(MapCase("single-diff-%d" % position, [(keys[0], ring([], 1, 0, 0))], bytes(mutated)))
    return out


def map_vector(stream, index):
    n = (next(stream) >> 30) % 7
    pool = []
    while len(pool) < n:
        key = key20(200 + (next(stream) >> 30) % 40)
        if key not in pool:
            pool.append(key)
    entries = [(pool[slot], ring([], 1, 0, slot)) for slot in range(n)]
    q = pool[(next(stream) >> 30) % n] if n and next(stream) & 3 else key20(300 + (next(stream) >> 30) % 9)
    case = MapCase("mv%d" % index, entries, q, probe_bad=(1 + (next(stream) >> 30) % 3) if (next(stream) & 15) == 0 else 0, k0=next(stream), k1=next(stream))
    shape_table(case, stream)
    case.filler = case.filler * 2
    case.collide = case.filler // 2 if next(stream) & 1 else 0
    return case


def hash_named():
    out = []
    keys = [bytes(20), b"\xff" * 20, bytes(range(20)), bytes(range(20, 0, -1)), b"\x80" + bytes(19), bytes(19) + b"\x01", key20(1), key20(2)]
    pairs = [(0, 0), (TOP, TOP), (0x0706050403020100, 0x0F0E0D0C0B0A0908), (1, 0), (0, 1), (0x736F6D6570736575, 0x646F72616E646F6D), (1 << 63, 1 << 63)]
    for index, key in enumerate(keys):
        for pair, (k0, k1) in enumerate(pairs):
            out.append(HashCase("h%d-%d" % (index, pair), k0, k1, key))
    return out


def hash_vector(stream, index):
    key = b"".join(next(stream).to_bytes(8, "little") for _ in range(3))[:20]
    return HashCase("hv%d" % index, next(stream), next(stream), key)


# ---------------------------------------------------------------------------------------------------------------------------------
# Streams, controls and evidence
# ---------------------------------------------------------------------------------------------------------------------------------

VECTORS = {"fold": (fold_vector, 3300), "check": (check_vector, 3300), "test": (test_vector, 3300), "map": (map_vector, 1500), "hash": (hash_vector, 800)}
NAMED = {"fold": fold_named, "check": check_named, "test": test_named, "map": map_cases, "hash": hash_named}

VARIANTS = {
    "fold": ("tag_low_bit", "tag_ignored", "no_threshold", "threshold_gt", "unsigned_compare", "no_sat_sum", "no_sat_sub", "sub_first", "div_32bit_only", "divisor_plus_one",
             "ret_abs", "ret_negative_ok", "ret_min_wraps", "acc_zero_start", "reverse_order", "index_mod_9999"),
    "check": ("range_inclusive", "nan_rejected", "mode_nonzero", "no_add_sat", "ratio_inverted", "cast_rounds", "cast_wraps", "diff_nonneg", "emit_copied_always"),
    "test": ("flip_on_word", "floor_zero", "tag_xor_dropped", "rest_without_extra", "move_always", "second_always"),
    "map": (),
    "hash": (),
}


def vector_stream(family, count=None, seed=0x1234ABCD):
    make, default = VECTORS[family]
    stream = lcg(seed)
    for index in range(default if count is None else count):
        yield make(stream, index)


def check_stream(world, cases, sites, rows=None, keep_every=0, variant=frozenset(), tally=None):
    """Run each case on the bytes, compare at once with the rule list, keep only counts and sampled rows."""
    count = 0
    for case in cases:
        before, got = run_case(world, case)
        want = SPECS[case.family](case, sites, variant)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.name, got, want))
        if tally is not None:
            key = (case.family, got[0])
            tally[key] = tally.get(key, 0) + 1
        if rows is not None and (keep_every == 0 or count % keep_every == 0):
            rows.append((case.family, case.name) + digest_of(got))
        count += 1
    return count


def first_failure(world, cases, sites, variant=frozenset()):
    for case in cases:
        try:
            before, got = run_case(world, case)
            if got != SPECS[case.family](case, sites, variant):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError):
            return case
    return None


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def mutation_samples():
    samples = {}
    for family in ("hash", "fold", "check", "test", "map"):
        samples[family] = list(NAMED[family]()) + list(vector_stream(family, 260, seed=0x78))
    return samples


DEAD_STORE = "store of a field the forward walk never reads again or that already holds that value"
REDUNDANT_GUARD = "guard whose flipped constant leaves the loop count of the following halving loop unchanged"
UNUSED_INSERTION = "the insertion point of a missing key is never read: the subject returns on a miss"
UNUSED_HEIGHT = "the height word of the tree search result is never read by the subject"
FLOOR_ONLY = "the saturated figure is only compared with -100, and every value the flipped constant can produce is on the same side"
LENGTH_20 = "constant that depends on the key length; bit 0 of 20 is zero, so the flipped value gives the same tail of 4 bytes"
EXPECTED_SURVIVORS = {
    (0x3BEBE21, "immediate"): DEAD_STORE,
    (0x3BEBFCC, "displacement"): "lea whose result is dead: the cursor is null on the only path that reaches it",
    (0x447EA0F, "immediate"): "low byte of the absolute-value mask: clearing bit 0 cannot change whether a double is above the largest finite one",
    (0x447EA20, "immediate"): "low byte of the largest finite double: the lowered limit differs only for exactly DBL_MAX, which the scaled figure (at most 2^64) never reaches",
    (0x469BC23, "immediate"): FLOOR_ONLY,
    (0x469BC27, "immediate"): FLOOR_ONLY,
    (0x459289B, "immediate"): LENGTH_20,
    (0x459289F, "immediate"): LENGTH_20,
    (0x459291C, "immediate"): LENGTH_20,
    (0x4592923, "immediate"): LENGTH_20,
    (0x3EE675F, "immediate"): "pshuflw broadcast selector: after punpcklbw all four low words are equal, so any word selector gives the same vector",
    (0x37C5BE7, "displacement"): DEAD_STORE,
    (0x37C5D86, "displacement"): DEAD_STORE,
    (0x37C5C25, "immediate"): "unroll-by-eight threshold: only heights of eight or more reach the unrolled loop",
    (0x37C5D08, "immediate"): "unroll-by-eight threshold: only heights of eight or more reach the unrolled loop",
    (0x37C5C83, "displacement"): "reads the length word two bytes past a leaf node, where any nonzero neighbour takes the same branch",
    (0x455CB75, "immediate"): REDUNDANT_GUARD,
    (0x455CBAC, "condition"): UNUSED_INSERTION,
    (0x455CBAE, "immediate"): UNUSED_INSERTION,
    (0x455CBE9, "immediate"): REDUNDANT_GUARD,
    (0x455CC1F, "immediate"): UNUSED_INSERTION,
    (0x35BE5DF, "displacement"): UNUSED_HEIGHT,
}


def run_mutants(image, table, seen, samples, sites):
    results = []
    for target in TARGETS:
        cases = []
        for family in FAMILY_OF[target]:
            cases += samples[family]
        cases = sorted(cases, key=lambda case: case.family != FAMILY_OF[target][-1] and 0)
        for va, kind, patch in edits_for(image, table[target], seen):
            world = World(image, patch)
            world.machine.step_limit = MUTANT_STEP_LIMIT
            failure = first_failure(world, cases, sites)
            results.append((va, kind, "killed" if failure is not None else "survived", NAMES[target], failure.name if failure is not None else EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    unexplained = [row for row in results if row[4] == "UNEXPLAINED"]
    if unexplained:
        raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return results


def structural_controls(image, world, sample, sites):
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    rows.append(("one flipped file byte changes the SHA-256", "detected" if hashlib.sha256(bytes(blob)).hexdigest() != SHA256 else "MISSED"))
    for label, va in (("address inside the fold", TOTAL + 1), ("address before the check", CHECK - 1), ("address inside the margin test", OKAY + 8),
                      ("address in .rodata", LOW), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    wrong = Sites(image)
    wrong.fold_sat_sum, wrong.fold_sat_sub = wrong.fold_sat_sub, wrong.fold_sat_sum
    fold = [case for case in sample if case.family == "fold"]
    rows.append(("fold saturation sites swapped", "detected" if first_failure(world, fold, wrong) is not None else "MISSED"))
    wrong = Sites(image)
    wrong.consts = dict(wrong.consts, low=0.25)
    check = [case for case in sample if case.family == "check"]
    rows.append(("lower fraction bound of another value", "detected" if first_failure(world, check, wrong) is not None else "MISSED"))
    wrong = Sites(image)
    wrong.consts = dict(wrong.consts, bound=wrong.consts["bound"] / 2)
    rows.append(("clip constant halved", "detected" if first_failure(world, check, wrong) is not None else "MISSED"))
    wrong = Sites(image)
    wrong.check_key = wrong.check_size
    rows.append(("dex mismatch panic mapped to the size site", "detected" if first_failure(world, check, wrong) is not None else "MISSED"))
    wrong = Sites(image)
    wrong.test_fmt_a, wrong.test_fmt_b = wrong.test_fmt_b, wrong.test_fmt_a
    test = [case for case in sample if case.family == "test"]
    rows.append(("margin test message sites swapped", "detected" if first_failure(world, test, wrong) is not None else "MISSED"))
    wrong = Sites(image)
    wrong.probe_index = wrong.map_index
    maps = [case for case in sample if case.family in ("map", "check")]
    rows.append(("probe index panic mapped to the map index site", "detected" if first_failure(world, maps, wrong) is not None else "MISSED"))
    probe = next(case for case in sample if case.family == "test" and case.name == "tag one passes")
    before, got = run_case(world, probe)
    mangled = TestCase(probe.name, probe.side, probe.keys, probe.map, probe.once, (probe.route[0] + 1, probe.route[1]), probe.p10, probe.p18, probe.p20, probe.p28, probe.step)
    rows.append(("an altered route result changes the logged helper request", "detected" if spec_test(mangled, sites) != got else "MISSED"))
    return rows


def decoded_table(image):
    return {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}


def call_rows(table, relative):
    rows = []
    for target in TARGETS:
        for row in table[target]:
            if row.op == "call":
                kind = "real" if row.target in TARGETS else "stub"
                rows.append((NAMES[target], "%#x" % row.va, "direct", "%#x" % row.target, kind, "%#x" % row.target))
            elif row.op == "calli":
                rows.append((NAMES[target], "%#x" % row.va, "slot", "%#x" % row.a[4], "stub", "%#x" % relative[row.a[4]] if row.a[4] in relative else "-"))
    return rows


def location_rows(image, sites):
    relative = image.relative()
    rows = []
    for name in ("fold_sat_sum", "fold_sat_sub", "fold_sat_add", "fold_size", "fold_index", "check_key", "check_size", "check_sat", "check_index",
                 "test_sat_diff", "test_sat_mul", "test_size", "map_index", "probe_index"):
        slot = getattr(sites, name)
        path, line, column = image.location(slot, relative)
        rows.append((name, "%#x" % slot, path, line, column))
    for name in ("fold_fmt", "check_fmt", "test_fmt_a", "test_fmt_b"):
        text, length = getattr(sites, name)[0], getattr(sites, name)[1]
        rows.append((name, "%#x" % text, "message %r" % sites.text(text, length), length, "-"))
    for name, slot in (("once_state_word", ONCE), ("default_container", sites.default)):
        rows.append((name, "%#x" % slot, "static in .data", "-", "-"))
    return rows


def constant_rows(image, sites, table):
    rows = []
    for name, value in sorted(sites.consts.items()):
        rows.append(("f64", name, repr(value), "%#x" % {"low": LOW, "one": ONE, "bound": BOUND, "top": TOPF}[name]))
    for target in TARGETS:
        for row in table[target]:
            if row.imm_at is not None and row.imm_size == 8 and row.op == "mov":
                rows.append((NAMES[target], "movabs", "%#x" % int.from_bytes(row.data[row.imm_at:row.imm_at + 8], "little"), "%#x" % row.va))
    return rows


def analyse(image, mutate=True):
    sites = Sites(image)
    world = World(image)
    tally, evidence = {}, {}
    totals = {}
    for family in ("fold", "check", "test", "map", "hash"):
        named_rows, vector_rows = [], []
        named = check_stream(world, NAMED[family](), sites, named_rows, tally=tally)
        vectors = check_stream(world, vector_stream(family), sites, vector_rows, keep_every=8, tally=tally)
        evidence[family] = (named_rows, vector_rows)
        totals[family] = (named, vectors)
    seen = set(world.machine.seen)
    table = decoded_table(image)
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    samples = mutation_samples()
    variants = []
    for family, names in VARIANTS.items():
        pool = samples[family]
        for name in names:
            failure = first_failure(world, pool, sites, frozenset((name,)))
            variants.append((family, name, "detected" if failure is not None else "MISSED", failure.name if failure else "-"))
    structural = structural_controls(image, world, [case for family in samples for case in samples[family]], sites)
    result = dict(table=table, evidence=evidence, totals=totals, unreached=unreached, variants=variants, structural=structural, tally=tally, sites=sites,
                  calls=call_rows(table, image.relative()), locations=location_rows(image, sites), constants=constant_rows(image, sites, table))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, samples, sites)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"

    table = result["table"]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[t], "%#x" % row.va, row.size, row.data.hex(), row.op) for t in TARGETS for row in table[t]])
    tsv("call-sites.tsv", ("caller", "address", "form", "callee_or_slot", "run_as", "resolves_to"), result["calls"])
    tsv("locations.tsv", ("site", "address", "path_or_message", "line", "column"), result["locations"])
    tsv("constants.tsv", ("function", "name", "value", "address"), result["constants"])
    tsv("model-variants.tsv", ("family", "switch", "outcome", "first_case"), result["variants"])
    tsv("structural-controls.tsv", ("control", "outcome"), result["structural"])
    for family in ("fold", "check", "test", "map", "hash"):
        named_rows, vector_rows = result["evidence"][family]
        head = ("family", "case", "form", "result_digest", "recorded_calls")
        tsv("named-%s.tsv" % family, head, named_rows)
        tsv("vector-%s.tsv" % family, head, vector_rows)
    mutations = result.get("mutations", [])
    if mutations:
        tsv("mutations.tsv", ("address", "kind", "outcome", "function", "first_case"), [("%#x" % va, kind, outcome, name, case) for va, kind, outcome, name, case in mutations])
    killed = sum(1 for row in mutations if row[2] == "killed")
    variants_detected = sum(1 for row in result["variants"] if row[2] == "detected")
    structural_detected = sum(1 for row in result["structural"] if row[1] == "detected")
    total_cases = sum(named + vectors for named, vectors in result["totals"].values())
    controls = len(result["variants"]) + len(result["structural"]) + killed
    detected = variants_detected + structural_detected + killed
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "functions": {NAMES[t]: {"address": "%#x" % t, "bytes": sum(row.size for row in table[t]), "instructions": len(table[t]),
                                 "unreached_rows": ["%#x" % va for va in result["unreached"][t]]} for t in TARGETS},
        "cases": {family: {"named": named, "vectors": vectors} for family, (named, vectors) in sorted(result["totals"].items())},
        "outcome_kinds": {"%s:%s" % key: value for key, value in sorted(result["tally"].items())},
        "model_variants": len(result["variants"]), "structural_controls": len(result["structural"]),
    }
    if mutations:
        summary["mutations"] = {"total": len(mutations), "killed": killed, "survived": sum(1 for r in mutations if r[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": total_cases, "negative_controls": controls, "negative_detected": detected}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
