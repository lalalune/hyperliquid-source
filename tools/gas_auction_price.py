#!/usr/bin/env python3
"""Pin the node #94 gas auction price curve, restart rule and payment gates from ELF bytes.

GasAuction prices fall from start_gas_wei to min_gas over one bucket; 0x325ccb0 computes that price,
0x33742d0 restarts an auction on a bucket roll, 0x2702060 and its copies roll the buckets, and the gates
0x2744020, 0x4d5c4f0, 0x46ce080 and 0x46ce200 test the price against a user limit and balance. The real
bytes run through small evaluators, a separately written specification predicts every run, both float
tails are split over all 2^64 bit patterns, and every reached conditional row is mutated. No objdump or
readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/gas_auction_price.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
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

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

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
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
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


PRICE = 0x325CCB0
RESTART = 0x33742D0
ROLLS = (0x2702060, 0x4CEE310, 0x4CEE5E0)
GATES = (0x2744020, 0x4D5C4F0)
SHORT_GATES = (0x46CE080, 0x46CE200)
INFO = 0x2A25590
TARGETS = (PRICE, RESTART) + ROLLS + GATES + SHORT_GATES + (INFO,)
NAMES = {PRICE: "price", RESTART: "restart", ROLLS[0]: "roll_a", ROLLS[1]: "roll_b", ROLLS[2]: "roll_c", GATES[0]: "gate_a", GATES[1]: "gate_b",
         SHORT_GATES[0]: "short_gate_a", SHORT_GATES[1]: "short_gate_b", INFO: "info_row"}
# The restart closure goes on to timing and logging; only its state rows are held here.
WINDOWS = {RESTART: ((0x33742D0, 0x337433D), (0x3374730, 0x3374744))}
SIBLING_ROLLS = (0x3BB0400, 0x3C1A9E0)

SLOT_PRICE = 0x57739B8
SLOT_TIME = 0x576E888
SLOT_SECONDS = 0x576E8C0
SLOT_ROUND = 0x576F6D8
SLOT_HOLDER = 0x5773170
SLOT_PANIC = 0x576E470
PANIC_LOCATION = 0x56F21F0
TIME_HELPER = 0x13C8E10
SECONDS_HELPER = 0x1447130
ROUND_HELPER = 0x565F410
CLOCK = 0x4EE3800
GOSSIP_ROLL = 0x3BB0400
DROP = 0x2A29660
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_COMPLETED = 0x176
TAG_NOT_STARTED = 0x177
TAG_OVER_MAX = 0x178
TAG_NO_BALANCE = 0x179
TAG_DISABLED = 0x17A
TAG_SUB = 0xBF
STATUS_TABLE = 0x59A8D0
ARM_NAMES = (TAG_COMPLETED, TAG_NOT_STARTED, TAG_OVER_MAX, TAG_NO_BALANCE, TAG_DISABLED, TAG_SUB)

SECONDS_PATH = 0x5B9765
SECONDS_PATH_SIZE = 0x2B
SECONDS_LINE_WORD = 0x5400000001
RESTART_NAME = 0x584604
RESTART_NAME_SIZE = 0x13
RESTART_LIMITS = 0x205E70
POW10 = 0x584B08

F_END = 0x08
F_MILLIS = 0x10
F_BUCKET = 0x18
F_RATIO = 0x20
F_START = 0x28
F_TOKEN = 0x30
F_FLOOR = 0x38
AUCTION_SIZE = 0x40
# Two state layouts: the visit order of the four auctions, then the gossip slot words.
LAYOUT_FIRST = dict(order=(0x32E8, 0x32A8, 0x3328, 0x90), borrow=0x3610, pointer=0x3618, length=0x3620)
LAYOUT_SECOND = dict(order=(0x3D68, 0x3D28, 0x3DA8, 0x90), borrow=0x4090, pointer=0x4098, length=0x40A0)
LAYOUTS = {ROLLS[0]: LAYOUT_FIRST, ROLLS[1]: LAYOUT_FIRST, ROLLS[2]: LAYOUT_SECOND}
SLOT_STRIDE = 0x50
OPTION_NONE = 2

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
AUCTION = HEAP_BASE + 0x1000
NOW = HEAP_BASE + 0x1100
ARGS = HEAP_BASE + 0x1800
REFS = HEAP_BASE + 0x1900
PARAMS = HEAP_BASE + 0x1A00
ADDRESS = HEAP_BASE + 0x1B00
CTX = HEAP_BASE + 0x2000
HOLDER = HEAP_BASE + 0x2400
NODES = HEAP_BASE + 0x3000
NODE_STRIDE = 0x200
TOKENS = HEAP_BASE + 0x6000
TOKEN_STRIDE = 0xE8
FIELD_WEI = 0x49
TOKENS_PTR = 0x180
TOKENS_LEN = 0x188
STATE = HEAP_BASE + 0x8000
USED = 0x10000
FILL = 0xCC
CAPACITY = 11
TWO64 = 18446744073709551616.0
USER = bytes(range(0x31, 0x45))


class Stopped(Exception):
    pass


def fdiv(left, right):
    if right == 0:
        if left != left or left == 0:
            return math.nan
        return math.copysign(math.inf, left) * math.copysign(1.0, right)
    return left / right


def spec_round(value):
    if value != value or value in (math.inf, -math.inf):
        return value
    whole = float(math.trunc(value))
    if abs(value - whole) >= 0.5:
        whole += math.copysign(1.0, value)
    return math.copysign(whole, value)


def saturate(value):
    """Both float tails: not finite gives 0, then floor at 0 and ceiling at u64::MAX."""
    if value != value or value in (math.inf, -math.inf) or value <= 0:
        return 0
    return MASK[8] if value >= TWO64 else int(value)


def days_from_date(packed):
    year = (packed - (1 << 32) if packed & SIGN[4] else packed) >> 13
    ordinal = packed >> 4 & 0x1FF
    extra = 0
    if year <= 0:
        cycles = (1 - year) // 400 + 1
        year += 400 * cycles
        extra = -146097 * cycles
    before = year - 1
    return ordinal + extra + 365 * before + before // 4 - before // 100 + before // 400 - 719163


def millis_of(time):
    date, seconds, nanos = time
    return max(0, (days_from_date(date) * 86400 + seconds) * 1000 + nanos // 1000000)


def later(left, right):
    def key(value):
        date = value[0] - (1 << 32) if value[0] & SIGN[4] else value[0]
        return date, value[1], value[2]
    return key(left) > key(right)


class Auction:
    def __init__(self, tag=0, end=0, millis=60000, bucket=3, ratio=2, start=1000, token=7, floor=100):
        self.tag, self.end, self.millis, self.bucket, self.ratio = tag, end, millis, bucket, ratio
        self.start, self.token, self.floor = start, token, floor

    def data(self):
        return struct.pack("<8Q", self.tag, self.end, self.millis, self.bucket, self.ratio, self.start, self.token, self.floor)

    def copy(self, **fields):
        fresh = Auction(self.tag, self.end, self.millis, self.bucket, self.ratio, self.start, self.token, self.floor)
        for name, value in fields.items():
            setattr(fresh, name, value)
        return fresh


T_START = (2026 << 13 | 200 << 4 | 3, 1000, 5000000)
T_NOW = (2026 << 13 | 200 << 4 | 3, 1060, 5000000)


class Case:
    def __init__(self, name, kind, **fields):
        self.name = name
        self.kind = kind
        self.auction = Auction()
        self.time = T_START
        self.now = T_NOW
        self.seconds = 15.0
        self.round_bits = None
        self.__dict__.update(fields)


def price_of(case):
    """Return (tag, price, events) for one price run."""
    auction = case.auction
    if auction.tag & 0xFF:
        return TAG_COMPLETED, None, ()
    events = [("time",)]
    if later(case.time, case.now):
        return TAG_NOT_STARTED, None, tuple(events)
    events.append(("seconds",))
    scaled = case.seconds * 1000.0
    events.append(("round", to_bits(scaled)))
    rounded = to_float(case.round_bits) if case.round_bits is not None else spec_round(scaled)
    elapsed = saturate(rounded)
    if auction.start < auction.floor:
        return TAG_SUB, None, tuple(events)
    span = auction.start - auction.floor
    factor = 1.0 - fdiv(float(elapsed), float(auction.millis))
    factor = factor if factor > 0.0 else 0.0
    product = factor * float(span)
    price = saturate(product) + auction.floor
    if price > MASK[8]:
        price = auction.floor
    return TAG_OK, price, tuple(events)


def blank():
    return bytearray([FILL]) * OUT_SIZE


def spec_price(case):
    tag, price, events = price_of(case)
    out = blank()
    struct.pack_into("<H", out, 0, tag)
    if price is not None:
        struct.pack_into("<Q", out, 8, price)
    return "price", bytes(out), events, case.auction.data()


def spec_restart(case):
    words = list(struct.unpack("<8Q", case.auction.data()))
    if case.flag != 1:
        return "restart", False, 0, case.auction.data(), case.flag
    if words[0] & MASK[4] == 1:
        product = words[1] * words[F_RATIO // 8]
        if product <= MASK[8]:
            words[F_START // 8] = product
    else:
        words[F_START // 8] = words[F_FLOOR // 8]
    words[0] = 0
    return "restart", True, 2, struct.pack("<8Q", *words), None


def spec_roll(case):
    now = millis_of(case.now)
    events = []
    states = {}
    order = LAYOUTS[case.kind]["order"]
    for offset, auction in zip(order, case.auctions):
        fresh = auction.copy()
        if auction.tag & MASK[4] != OPTION_NONE:
            bucket = now // auction.millis
            rolled = bucket > auction.bucket
            if rolled:
                fresh.bucket = bucket
            base = STATE + offset
            events.append(("restart", RESTART_NAME, RESTART_NAME_SIZE, int(rolled), base + F_START, base, base + F_RATIO, base + F_FLOOR))
        states[offset] = fresh.data()
    if case.borrow != 1 << 63:
        first = STATE + 0x7000
        events.append(("gossip", first, first + case.slots * SLOT_STRIDE, 0, STATE + 0x90, case.now))
    return "roll", tuple(events), tuple(states[offset] for offset in order)


def balance_of(case, token):
    return (0, 0, 0) if case.shape == "none" else case.balances.get(token, (0, 0, 0))


def charge(out, tag, price=None, token=None, flag=None):
    struct.pack_into("<H", out, 0, tag)
    if price is not None:
        struct.pack_into("<QQ", out, 8, price, token)
    if flag is not None:
        out[0x18] = flag


def refuse(kind, out, tag, price, token):
    """A refusal keeps different words per copy: both, the token only, or the tag alone."""
    struct.pack_into("<H", out, 0, tag)
    if kind == GATES[0]:
        struct.pack_into("<Q", out, 8, price)
    if kind in GATES:
        struct.pack_into("<Q", out, 0x10, token)


def propagate(short, tag):
    if short:
        out = bytearray([STACK_MARK]) * OUT_SIZE
    else:
        out = bytearray(0x14) + bytearray([STACK_MARK]) * (OUT_SIZE - 0x14)
    struct.pack_into("<H", out, 0, tag)
    return out


def spec_gate(case):
    auction = case.auction
    short = case.kind in SHORT_GATES
    out = blank()
    if not short:
        if case.user == bytes(20):
            charge(out, TAG_OK, flag=OPTION_NONE)
            return "gate", bytes(out), ()
        if case.absent:
            charge(out, TAG_DISABLED)
            return "gate", bytes(out), ()
        if case.exempt:
            charge(out, TAG_OK, flag=OPTION_NONE)
            return "gate", bytes(out), ()
    keep = 0 if short else case.keep
    events = ()
    if keep and auction.tag & 0xFF:
        price = auction.end
    else:
        tag, price, events = price_of(case)
        if tag != TAG_OK:
            return "gate", bytes(propagate(short, tag)), events
        if not keep and case.max_some & (MASK[1] if short else MASK[8]) and price > case.maximum:
            refuse(case.kind, out, TAG_OVER_MAX, price, auction.token)
            return "gate", bytes(out), events
    total, hold, _ = balance_of(case, auction.token)
    needed = hold + price
    if needed > MASK[8] or needed > total:
        refuse(case.kind, out, TAG_NO_BALANCE, price, auction.token)
        return "gate", bytes(out), events
    charge(out, TAG_OK, price, auction.token, keep)
    return "gate", bytes(out), events


def spec_info(case):
    auction = case.auction
    if auction.token >= len(case.wei):
        return "panic", PANIC_LOCATION, (("time",),)
    tag, price, events = price_of(case)
    events = (("time",),) + events
    power = case.pow10[case.wei[auction.token]]
    current = float(price) / power if tag == TAG_OK else None
    final = float(auction.end) / power if auction.tag else None
    seconds = max(0, days_from_date(case.time[0]) * 86400 + case.time[1])
    return "info", current, final, seconds, auction.millis // 1000, float(auction.start) / power, events + (("drop", tag),) * (tag != TAG_OK)


def spec_run(case):
    if case.kind == PRICE:
        return spec_price(case)
    if case.kind == RESTART:
        return spec_restart(case)
    if case.kind in ROLLS:
        return spec_roll(case)
    if case.kind == INFO:
        return spec_info(case)
    return spec_gate(case)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((PRICE,))
        machine.memory.statics[SLOT_PRICE] = PRICE
        machine.calls = {CLOCK: self.on_clock, RESTART: self.on_restart, GOSSIP_ROLL: self.on_gossip, DROP: self.on_drop}
        table = {SLOT_TIME: self.on_time, SLOT_SECONDS: self.on_seconds, SLOT_ROUND: self.on_round, SLOT_HOLDER: self.on_holder, SLOT_PANIC: self.on_panic}
        for slot, hook in table.items():
            marker = MARK_BASE + slot
            machine.memory.statics[slot] = marker
            machine.slots[marker] = hook
        self.events = []
        self.case = None
        self.clock = 0
        self.stop_at = 2

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def read(self, addr, size=8):
        return self.machine.memory.read(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def triple(self, at):
        return struct.unpack("<III", self.machine.memory.bytes_at(at, 12))

    def put_triple(self, at, value):
        self.machine.memory.put_bytes(at, struct.pack("<III", *value))

    def on_time(self, machine):
        self.expect(machine.regs[RSI] == AUCTION + F_MILLIS, "time words")
        self.events.append(("time",))
        self.put_triple(machine.regs[RDI], self.case.time)

    def on_seconds(self, machine):
        regs = machine.regs
        self.expect(self.triple(regs[RDI]) == self.case.now, "now")
        self.expect(self.triple(regs[RSI]) == self.case.time, "start")
        self.expect(self.read(regs[RSI] + 0x10) == SECONDS_LINE_WORD, "location word")
        self.expect(self.read(regs[RSI] + 0x18) == SECONDS_PATH, "location path")
        self.expect(self.read(regs[RSI] + 0x20) == SECONDS_PATH_SIZE, "location size")
        self.events.append(("seconds",))
        machine.xmm_result = to_bits(self.case.seconds)

    def on_round(self, machine):
        bits = machine.xmm[0] & MASK[8]
        self.events.append(("round", bits))
        machine.xmm_result = self.case.round_bits if self.case.round_bits is not None else to_bits(spec_round(to_float(bits)))

    def on_holder(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == CTX + 0x80, "holder map")
        self.expect(self.machine.memory.bytes_at(regs[RSI], 20) == self.case.user, "holder key")
        regs[RAX] = HOLDER

    def on_panic(self, machine):
        raise Panicked(machine.regs[RDI])

    def on_clock(self, machine):
        self.expect(machine.regs[RDI] == 1, "clock argument")
        self.clock += 1
        if self.clock == self.stop_at:
            raise Stopped()
        machine.regs[RAX] = 0x1234

    def on_restart(self, machine):
        regs = machine.regs
        args, refs = regs[RDI], regs[RSI]
        self.events.append(("restart", self.read(args), self.read(args + 8), self.read(args + 0x20, 1), self.read(refs), self.read(refs + 8),
                            self.read(refs + 0x10), self.read(refs + 0x18)))
        self.expect(self.read(args + 0x10) == struct.unpack_from("<Q", self.image.blob, RESTART_LIMITS)[0], "first limit")
        self.expect(self.read(args + 0x18) == struct.unpack_from("<Q", self.image.blob, RESTART_LIMITS + 8)[0], "second limit")

    def on_gossip(self, machine):
        regs = machine.regs
        args = regs[RSI]
        self.events.append(("gossip", self.read(args), self.read(args + 8), self.read(args + 0x10), self.read(args + 0x18), self.triple(self.read(args + 0x20))))
        self.word(regs[RDI], 0)
        self.word(regs[RDI] + 0x10, 0)

    def on_drop(self, machine):
        self.events.append(("drop", self.read(machine.regs[RDI], 2)))

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(OUT, bytes(blank()))
        memory.put_bytes(AUCTION - 0x40, bytes([FILL]) * 0xC0)
        memory.put_bytes(AUCTION, case.auction.data())
        self.put_triple(NOW, case.now)
        self.word(NOW + 12, 0xCCCCCCCC, 4)
        self.events = []
        self.case = case
        self.clock = 0

    def run_price(self, case):
        self.fresh(case)
        self.machine.run(PRICE, {RDI: OUT, RSI: AUCTION, RDX: NOW})
        memory = self.machine.memory
        return "price", memory.bytes_at(OUT, OUT_SIZE), tuple(self.events), memory.bytes_at(AUCTION, AUCTION_SIZE)

    def run_restart(self, case):
        self.fresh(case)
        memory = self.machine.memory
        memory.put_bytes(ARGS, bytes([FILL]) * 0x30)
        memory.write(ARGS + 0x20, 1, case.flag)
        for index, value in enumerate((AUCTION + F_START, AUCTION, AUCTION + F_RATIO, AUCTION + F_FLOOR)):
            self.word(REFS + 8 * index, value)
        try:
            value = self.machine.run(RESTART, {RDI: ARGS, RSI: REFS}) & 0xFF
            done = False
        except Stopped:
            value = None
            done = True
        return "restart", done, self.clock, memory.bytes_at(AUCTION, AUCTION_SIZE), value

    def run_roll(self, case):
        self.fresh(case)
        memory = self.machine.memory
        layout = LAYOUTS[case.kind]
        for offset in layout["order"]:
            memory.put_bytes(STATE + offset - 0x10, bytes([FILL]) * 0x60)
        for offset, auction in zip(layout["order"], case.auctions):
            memory.put_bytes(STATE + offset, auction.data())
        self.word(STATE + layout["borrow"], case.borrow)
        self.word(STATE + layout["pointer"], STATE + 0x7000)
        self.word(STATE + layout["length"], case.slots)
        self.machine.run(case.kind, {RDI: STATE, RSI: NOW})
        return "roll", tuple(self.events), tuple(memory.bytes_at(STATE + offset, AUCTION_SIZE) for offset in layout["order"])

    def node(self, index, keys, values, children, stale):
        base = NODES + index * NODE_STRIDE
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * 0x1D0)
        for at in range(CAPACITY):
            key = keys[at] if at < len(keys) else stale
            self.word(base + 8 + 8 * at, key)
            total, hold, third = values[at] if at < len(values) else (MASK[8], MASK[8], MASK[8])
            self.word(base + 0x60 + 0x18 * at, total)
            self.word(base + 0x68 + 0x18 * at, hold)
            self.word(base + 0x70 + 0x18 * at, third)
        self.word(base + 0x16A, len(keys), 2)
        for at, child in enumerate(children):
            self.word(base + 0x170 + 8 * at, NODES + child * NODE_STRIDE)
        return base

    def tree(self, case):
        items = sorted(case.balances.items())
        self.word(HOLDER + 0x10, 0)
        self.word(HOLDER + 0x18, 0)
        if case.shape == "none":
            return
        keys = [key for key, _ in items]
        values = [value for _, value in items]
        stale = case.auction.token
        if case.shape == "leaf":
            root = self.node(0, keys, values, (), stale)
            height = 0
        else:
            half = len(keys) // 2
            self.node(1, keys[:half], values[:half], (), stale)
            self.node(2, keys[half + 1:], values[half + 1:], (), stale)
            root = self.node(0, keys[half:half + 1], values[half:half + 1], (1, 2), stale)
            height = 1
        self.word(HOLDER + 0x10, root)
        self.word(HOLDER + 0x18, height)

    def run_gate(self, case):
        self.fresh(case)
        memory = self.machine.memory
        memory.put_bytes(CTX, bytes([FILL]) * 0x100)
        self.put_triple(CTX + 0x60, case.now)
        self.tree(case)
        if case.kind in SHORT_GATES:
            memory.put_bytes(ADDRESS, case.user + bytes([FILL]) * 4)
            self.machine.run(case.kind, {RDI: OUT, RSI: AUCTION, RDX: ADDRESS, RCX: case.max_some | 0xABCD00, R8: case.maximum, R9: CTX})
        else:
            memory.put_bytes(PARAMS, bytes([FILL]) * 0x40)
            self.word(PARAMS, case.max_some)
            self.word(PARAMS + 8, case.maximum)
            self.word(PARAMS + 0x10, 0 if case.absent else AUCTION)
            memory.put_bytes(PARAMS + 0x18, case.user)
            memory.write(PARAMS + 0x2C, 1, case.keep)
            memory.write(PARAMS + 0x2D, 1, case.exempt)
            self.machine.run(case.kind, {RDI: OUT, RSI: CTX, RDX: PARAMS})
        return "gate", memory.bytes_at(OUT, OUT_SIZE), tuple(self.events)

    def run_info(self, case):
        self.fresh(case)
        memory = self.machine.memory
        memory.put_bytes(CTX, bytes([FILL]) * 0x200)
        self.word(CTX + TOKENS_PTR, TOKENS)
        self.word(CTX + TOKENS_LEN, len(case.wei))
        memory.put_bytes(TOKENS, bytes([FILL]) * (TOKEN_STRIDE * 8))
        for index, wei in enumerate(case.wei):
            memory.write(TOKENS + index * TOKEN_STRIDE + FIELD_WEI, 1, wei)
        try:
            self.machine.run(INFO, {RDI: OUT, RSI: AUCTION, RDX: CTX, RCX: NOW})
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)
        words = struct.unpack_from("<7Q", memory.bytes_at(OUT, 0x38))
        return ("info", to_float(words[1]) if words[0] == 1 else None, to_float(words[3]) if words[2] == 1 else None, words[4], words[5], to_float(words[6]), tuple(self.events))

    def run(self, case):
        if case.kind == PRICE:
            return self.run_price(case)
        if case.kind == RESTART:
            return self.run_restart(case)
        if case.kind in ROLLS:
            return self.run_roll(case)
        if case.kind == INFO:
            return self.run_info(case)
        return self.run_gate(case)

    def window(self, start, stop, setup, result):
        """Run a row range with poisoned registers; return its decision record and result."""
        machine = self.machine
        machine.regs = [POISON] * 16
        machine.xmm = [POISON | POISON << 64] * 16
        setup(machine)
        pc = start
        trace = []
        for _ in range(100):
            if pc == stop:
                return tuple(trace), result(machine)
            row = machine.cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                machine.cache[pc] = row
            if row.op in ("jcc", "cmov"):
                trace.append((row.va, machine.condition(row.cc)))
            pc = machine.step(row)
            if row.op == "ucomisd":
                trace.append((row.va, machine.cf, machine.zf, machine.pf))
            elif row.op == "cvttsd2si":
                trace.append((row.va, machine.regs[row.a[1]] == 1 << 63))
        raise Halt("window did not end")

    def elapsed_stage(self, bits):
        self.machine.memory.reset(USED)
        self.machine.memory.put_bytes(AUCTION, Auction(start=5, floor=1).data())

        def setup(machine):
            machine.xmm[0] = bits | POISON << 64
            machine.regs[R15] = AUCTION
            machine.regs[R14] = AUCTION + F_MILLIS
            machine.regs[RBX] = OUT
        return self.window(STAGE_ONE[0], STAGE_ONE[1], setup, lambda machine: machine.regs[RSI])

    def product_stage(self, bits):
        def setup(machine):
            machine.xmm[1] = bits | POISON << 64
            machine.xmm[0] = 0
            machine.regs[RAX] = 0
        return self.window(STAGE_TWO[0], STAGE_TWO[1], setup, lambda machine: machine.regs[RCX])


STAGE_ONE = (0x325CD8B, 0x325CE31)
STAGE_TWO = (0x325CEC2, 0x325CF26)
FLOAT_SEEDS = ((0, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000), (0x7FF0000000000001, (1 << 63) - 1),
               (1 << 63, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))
INTERIOR_POINTS = 8


def interior(lo, hi):
    return [lo + (hi - lo) * index // (INTERIOR_POINTS + 1) for index in range(1, INTERIOR_POINTS + 1)]


def merge_pieces(found):
    found.sort(key=lambda row: row[0])
    merged = []
    for lo, hi, trace in found:
        if merged and merged[-1][2] == trace and merged[-1][1] + 1 == lo:
            merged[-1] = (merged[-1][0], hi, trace)
        else:
            merged.append((lo, hi, trace))
    return merged


def split(run, seed):
    """Halve a range until both ends share one decision record."""
    stack = [seed]
    found = []
    runs = 0
    while stack:
        lo, hi = stack.pop()
        first = run(lo)
        last = run(hi) if hi != lo else first
        runs += 2
        if first == last:
            found.append((lo, hi, first))
            continue
        middle = (lo + hi) // 2
        stack.append((middle + 1, hi))
        stack.append((lo, middle))
    return merge_pieces(found), runs


def refine(stage, label):
    rows = []
    runs = 0
    for seed in FLOAT_SEEDS:
        pieces, count = split(lambda bits: stage(bits)[0], seed)
        runs += count
        for lo, hi, trace in pieces:
            for bits in [lo, hi] + (interior(lo, hi) if hi > lo else []):
                got = stage(bits)
                if got[0] != trace:
                    raise EvidenceError("interior point left its piece: %#x" % bits)
                if got[1] != saturate(to_float(bits)):
                    raise EvidenceError("%s mismatch at %#x: %#x" % (label, bits, got[1]))
            rows.append((label, "%#x" % lo, "%#x" % hi, stage(lo)[1], stage(hi)[1], len(trace)))
    return rows, runs


def division_bound():
    """x // 1000 as ((x >> 3) * m) >> 68: exact for all u64 when 0 <= m*125 - 2^68 and the excess stays small."""
    multiplier = 0x20C49BA5E353F7CF
    excess = multiplier * 125 - (1 << 68)
    return multiplier, excess, 0 <= excess and excess << 61 < 1 << 68


A = Auction()
PAST = (2026 << 13 | 199 << 4 | 3, 1060, 5000000)
EARLIER_SECOND = (T_NOW[0], 1059, T_NOW[2])
LATER_SECOND = (T_NOW[0], 1061, T_NOW[2])
LATER_NANO = (T_NOW[0], 1060, 5000001)
EARLIER_NANO = (T_NOW[0], 1060, 4999999)
NEXT_DAY = (2026 << 13 | 201 << 4 | 3, 0, 0)
NEGATIVE_YEAR = ((-3 & 0x7FFFF) << 13 | 200 << 4 | 3 | 0xFFFFFFFF00000000 & 0, 0, 0)
NEGATIVE_NOW = ((-3 << 13 | 201 << 4 | 3) & MASK[4], 0, 0)
NEGATIVE_START = ((-3 << 13 | 200 << 4 | 3) & MASK[4], 0, 0)
NEGATIVE_LATER = ((-2 << 13 | 200 << 4 | 3) & MASK[4], 0, 0)


def price_cases():
    def case(name, **fields):
        return Case(name, PRICE, **fields)
    return [
        case("zero_elapsed", seconds=0.0),
        case("quarter", seconds=15.0),
        case("half", seconds=30.0),
        case("last_milli", seconds=59.999),
        case("exact_end", seconds=60.0),
        case("past_end", seconds=61.0),
        case("far_past_end", seconds=1e9),
        case("half_milli_rounds_up", seconds=0.0005),
        case("just_under_half_milli", seconds=0.00049),
        case("completed", auction=A.copy(tag=1, end=55)),
        case("completed_low_byte", auction=A.copy(tag=0x101, end=55)),
        case("high_byte_only_is_open", auction=A.copy(tag=0x100)),
        case("same_time", time=T_NOW, seconds=0.0),
        case("not_started_day", time=NEXT_DAY),
        case("started_day_before", time=PAST),
        case("not_started_second", time=LATER_SECOND),
        case("started_second", time=EARLIER_SECOND),
        case("not_started_nano", time=LATER_NANO),
        case("started_nano", time=EARLIER_NANO),
        case("negative_date_before", time=NEGATIVE_START, now=NEGATIVE_NOW),
        case("negative_date_after", time=NEGATIVE_NOW, now=NEGATIVE_START),
        case("negative_against_positive", time=NEGATIVE_START),
        case("positive_against_negative", now=NEGATIVE_START),
        case("second_wins_over_nano", time=(T_NOW[0], 1059, 999999999)),
        case("second_loses_over_nano", time=(T_NOW[0], 1061, 0)),
        case("start_below_floor", auction=A.copy(start=99, floor=100)),
        case("start_equals_floor", auction=A.copy(start=100, floor=100)),
        case("zero_duration_zero_elapsed", auction=A.copy(millis=0), seconds=0.0),
        case("zero_duration_elapsed", auction=A.copy(millis=0), seconds=1.0),
        case("nan_seconds", round_bits=to_bits(math.nan)),
        case("infinite_seconds", round_bits=to_bits(math.inf)),
        case("negative_infinite_seconds", round_bits=to_bits(-math.inf)),
        case("negative_seconds", round_bits=to_bits(-5.0)),
        case("huge_seconds", round_bits=to_bits(1e300)),
        case("largest_finite_rounded", round_bits=0x7FEFFFFFFFFFFFFF),
        case("two64_rounded", round_bits=to_bits(TWO64)),
        case("below_two64_rounded", round_bits=to_bits(18446744073709549568.0)),
        case("two63_rounded", round_bits=to_bits(9223372036854775808.0)),
        case("above_two63_rounded", round_bits=to_bits(9223372036854777856.0), auction=A.copy(millis=MASK[8])),
        case("big_millis", auction=A.copy(millis=1 << 63), round_bits=to_bits(float(1 << 62))),
        case("span_rounds_up", seconds=0.0, auction=A.copy(start=(1 << 53) + 3, floor=0)),
        case("span_tie_down", seconds=0.0, auction=A.copy(start=(1 << 53) + 1, floor=0)),
        case("max_span_overflow_gives_floor", seconds=0.0, auction=A.copy(start=MASK[8], floor=1)),
        case("max_span_zero_floor", seconds=0.0, auction=A.copy(start=MASK[8], floor=0)),
        case("two64_product_floor_2048", seconds=0.0, auction=A.copy(start=MASK[8], floor=2048)),
        case("high_floor", seconds=15.0, auction=A.copy(start=MASK[8], floor=MASK[8] - 1000)),
        case("big_span_half", seconds=30.0, auction=A.copy(start=1 << 63, floor=1 << 40)),
        case("word_bits_above_32", seconds=15.0, auction=A.copy(start=(5 << 32) + 77, floor=3 << 32, millis=(1 << 33) + 1)),
    ]


def restart_cases():
    def case(name, flag=1, **fields):
        return Case(name, RESTART, flag=flag, **fields)
    return [
        case("no_roll", flag=0, auction=A.copy(tag=1, end=9)),
        case("no_sale_gives_floor", auction=A.copy(tag=0, start=5000, floor=321)),
        case("sale_doubles", auction=A.copy(tag=1, end=9, ratio=2)),
        case("sale_ratio_zero", auction=A.copy(tag=1, end=9, ratio=0)),
        case("sale_ratio_three", auction=A.copy(tag=1, end=1 << 40, ratio=3)),
        case("sale_below_floor_stays_below", auction=A.copy(tag=1, end=2, ratio=3, floor=1000)),
        case("product_fits_exactly", auction=A.copy(tag=1, end=(1 << 63), ratio=1)),
        case("product_top", auction=A.copy(tag=1, end=MASK[8], ratio=1)),
        case("product_overflows_by_one", auction=A.copy(tag=1, end=1 << 63, ratio=2)),
        case("product_overflows_big", auction=A.copy(tag=1, end=MASK[8], ratio=MASK[8])),
        case("tag_high_word_ignored", auction=A.copy(tag=(5 << 32) | 1, end=9, ratio=2)),
        case("tag_word_is_two", auction=A.copy(tag=2, end=9, start=5, floor=6)),
        case("tag_low_byte_one_only", auction=A.copy(tag=0x101, end=9, start=5, floor=6)),
    ]


def roll_auctions(lasts=(0, 0, 0, 0), millis=(60000, 60000, 60000, 60000), tags=(0, 0, 0, 0)):
    return [A.copy(bucket=last, millis=size, tag=tag) for last, size, tag in zip(lasts, millis, tags)]


def bucket_of(now, size):
    return millis_of(now) // size


def roll_cases(kind):
    base = bucket_of(T_NOW, 60000)

    def case(name, auctions, now=T_NOW, borrow=0, slots=2):
        return Case("%s" % name, kind, auctions=auctions, now=now, borrow=borrow, slots=slots)
    big = 1 << 40
    return [
        case("all_roll", roll_auctions()),
        case("none_roll", roll_auctions((base, base, base, base))),
        case("equal_minus_one", roll_auctions((base - 1, base, base + 1, 0))),
        case("each_differs", roll_auctions((1, 2, 3, base + 7))),
        case("second_size", roll_auctions(millis=(1000, 3600000, 86400000, 7))),
        case("sizes_above_32_bits", roll_auctions(millis=(big, big + 1, 1 << 33, 1 << 62))),
        case("first_disabled", roll_auctions(tags=(2, 0, 0, 0))),
        case("second_disabled", roll_auctions(tags=(0, 2, 0, 0))),
        case("third_disabled", roll_auctions(tags=(0, 0, 2, 0))),
        case("fourth_disabled", roll_auctions(tags=(0, 0, 0, 2))),
        case("all_disabled", roll_auctions(tags=(2, 2, 2, 2))),
        case("sold_tag_rolls", roll_auctions(tags=(1, 1, 0, 1))),
        case("tag_high_word", roll_auctions(tags=((1 << 32) | 2, 0, 0, 0))),
        case("borrowed", roll_auctions(), borrow=1 << 63),
        case("borrow_other_value", roll_auctions(), borrow=1),
        case("no_slots", roll_auctions(), slots=0),
        case("many_slots", roll_auctions(), slots=7),
        case("leap_year_date", roll_auctions(), now=(2024 << 13 | 366 << 4 | 2, 86399, 999999999)),
        case("low_nibble_ignored", roll_auctions(), now=(2023 << 13 | 59 << 4 | 15, 1, 1000000)),
        case("year_one", roll_auctions(), now=(1 << 13 | 1 << 4, 5, 0)),
        case("old_year", roll_auctions(), now=(1600 << 13 | 60 << 4 | 2, 5, 7)),
        case("epoch_day", roll_auctions(), now=(1970 << 13 | 1 << 4 | 2, 0, 0)),
        case("epoch_nano_floor", roll_auctions(millis=(1, 1, 1, 1)), now=(1970 << 13 | 1 << 4 | 2, 0, 999999)),
        case("epoch_first_milli", roll_auctions(millis=(1, 1, 1, 1)), now=(1970 << 13 | 1 << 4 | 2, 0, 1000000)),
        case("before_epoch_clamps", roll_auctions(millis=(1, 1, 1, 1), lasts=(0, 0, 0, 0)), now=(1969 << 13 | 365 << 4 | 2, 86399, 0)),
        case("zero_year_date", roll_auctions(millis=(1, 1, 1, 1)), now=(0 << 13 | 1 << 4 | 2, 0, 0)),
        case("century_year", roll_auctions(), now=(2101 << 13 | 1 << 4 | 2, 0, 0)),
        case("largest_date_year", roll_auctions(millis=(1, 1000, 1 << 32, (1 << 32) + 1)), now=(262000 << 13 | 365 << 4 | 2, 86399, 999999999)),
        case("below_33_bits", roll_auctions(millis=(1000, 1000, 1000, 1000)), now=(1970 << 13 | 51 << 4 | 2, 0, 0)),
        case("far_future", roll_auctions(millis=(1, 1000, 1 << 32, (1 << 32) + 1)), now=(9999 << 13 | 365 << 4 | 2, 86399, 999999999)),
    ]


def balances():
    return {3: (10, 1, 8), 7: (1000, 100, 9), 9: (50, 0, 2), 12: (MASK[8], MASK[8] - 5, 3), 15: (0, 0, 0)}


def gate_cases(kind):
    short = kind in SHORT_GATES

    def case(name, **fields):
        data = dict(user=USER, keep=0, exempt=0, absent=False, max_some=0, maximum=0, balances=balances(), shape="leaf", seconds=15.0)
        data.update(fields)
        return Case(name, kind, **data)
    rows = [
        case("plain"),
        case("internal_left", shape="internal", auction=A.copy(token=3, floor=1, start=5)),
        case("internal_middle", shape="internal", auction=A.copy(token=9, floor=1, start=5)),
        case("internal_right", shape="internal", auction=A.copy(token=15, floor=0, start=0)),
        case("internal_right_b", shape="internal", auction=A.copy(token=12, floor=5, start=5)),
        case("internal_miss", shape="internal", auction=A.copy(token=8, floor=1, start=5)),
        case("internal_miss_low", shape="internal", auction=A.copy(token=1, floor=1, start=5)),
        case("internal_miss_high", shape="internal", auction=A.copy(token=99, floor=0, start=0)),
        case("empty_map_zero_price", shape="none", auction=A.copy(floor=0, start=0)),
        case("empty_map_one", shape="none", auction=A.copy(floor=1, start=1)),
        case("leaf_miss_zero_price", auction=A.copy(token=8, floor=0, start=0)),
        case("leaf_miss_one", auction=A.copy(token=8, floor=1, start=1)),
        case("leaf_past_end_miss", auction=A.copy(token=99, floor=0, start=0)),
        case("exact_balance", auction=A.copy(floor=900, start=900)),
        case("one_short", auction=A.copy(floor=901, start=901)),
        case("hold_overflow", auction=A.copy(token=12, floor=6, start=6)),
        case("hold_exact_top", auction=A.copy(token=12, floor=5, start=5)),
        case("error_completed", auction=A.copy(tag=1, end=5)),
        case("error_not_started", time=NEXT_DAY),
        case("error_sub", auction=A.copy(start=1, floor=2)),
        case("max_over", max_some=1, maximum=100),
        case("max_equal", max_some=1, maximum=775),
        case("max_above", max_some=1, maximum=776),
        case("max_one_below", max_some=1, maximum=774),
        case("max_absent", max_some=0, maximum=1),
        case("zero_user_passes_to_price", user=bytes(19) + b"\x01"),
        case("first_byte_user", user=b"\x01" + bytes(19)),
        case("middle_byte_user", user=bytes(10) + b"\x01" + bytes(9)),
    ]
    if short:
        rows += [
            case("short_error_second", auction=A.copy(start=3, floor=9)),
            case("short_flag_high_bits", max_some=0x100, maximum=1),
            case("short_max_low_bit", max_some=0x101, maximum=1),
        ]
    else:
        rows += [
            case("zero_user_free", user=bytes(20)),
            case("zero_user_before_disabled", user=bytes(20), absent=True),
            case("disabled", absent=True),
            case("disabled_before_exempt", absent=True, exempt=1),
            case("exempt", exempt=1),
            case("exempt_skips_price", exempt=1, auction=A.copy(tag=1, end=5)),
            case("keep_open", keep=1),
            case("keep_open_ignores_max", keep=1, max_some=1, maximum=1),
            case("keep_completed_uses_end", keep=1, auction=A.copy(tag=1, end=37)),
            case("keep_completed_low_byte", keep=1, auction=A.copy(tag=0x101, end=37)),
            case("keep_completed_ignores_max", keep=1, auction=A.copy(tag=1, end=37), max_some=1, maximum=1),
            case("keep_completed_no_time", keep=1, auction=A.copy(tag=1, end=37), time=NEXT_DAY),
            case("keep_completed_short", keep=1, auction=A.copy(tag=1, end=901)),
            case("keep_not_started", keep=1, time=NEXT_DAY),
            case("keep_sub_error", keep=1, auction=A.copy(start=1, floor=2)),
            case("keep_other_byte", keep=3),
            case("max_word_high_bits", max_some=1 << 40, maximum=1),
            case("user_last_extra_byte", user=bytes(16) + b"\x01" + bytes(3)),
        ]
    return rows


def info_cases():
    pow10 = None

    def case(name, **fields):
        data = dict(wei=(2, 8, 18, 6, 0), auction=A.copy(token=1), seconds=15.0, pow10=pow10)
        data.update(fields)
        return Case(name, INFO, **data)
    return [
        case("open"),
        case("first_token", auction=A.copy(token=0)),
        case("last_token", auction=A.copy(token=4)),
        case("eighteen_decimals", auction=A.copy(token=2, start=1 << 62, floor=1 << 60)),
        case("completed", auction=A.copy(token=1, tag=1, end=12345)),
        case("completed_tag_high_byte", auction=A.copy(token=1, tag=0x100, end=12345)),
        case("not_started", time=NEXT_DAY, auction=A.copy(token=1)),
        case("sub_error", auction=A.copy(token=1, start=3, floor=7)),
        case("token_at_length", auction=A.copy(token=5)),
        case("token_far", auction=A.copy(token=1 << 40)),
        case("before_epoch_seconds", time=(1969 << 13 | 365 << 4 | 2, 86399, 0), auction=A.copy(token=1)),
        case("epoch_seconds", time=(1970 << 13 | 1 << 4 | 2, 1, 7), auction=A.copy(token=1)),
        case("negative_year_seconds", time=NEGATIVE_START, auction=A.copy(token=1)),
        case("century_seconds", time=(2101 << 13 | 1 << 4 | 2, 0, 0), auction=A.copy(token=1)),
        case("leap_seconds", time=(2024 << 13 | 366 << 4 | 2, 86399, 0), auction=A.copy(token=1)),
        case("duration_999", auction=A.copy(token=1, millis=999)),
        case("duration_1000", auction=A.copy(token=1, millis=1000)),
        case("duration_1999", auction=A.copy(token=1, millis=1999)),
        case("duration_top", auction=A.copy(token=1, millis=MASK[8])),
        case("duration_top_multiple", auction=A.copy(token=1, millis=MASK[8] - MASK[8] % 1000)),
        case("duration_below_multiple", auction=A.copy(token=1, millis=MASK[8] - MASK[8] % 1000 - 1)),
        case("big_prices", auction=A.copy(token=3, start=MASK[8], floor=MASK[8] - 7, tag=1, end=MASK[8])),
    ]


def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state


def vector_cases(count):
    """Words of every width and shape; shifted draws reach the edges where a double loses bits."""
    stream = lcg(94)

    def draw():
        value = next(stream)
        return value >> (next(stream) % 64)
    rows = []
    for index in range(count):
        low, high = sorted((draw(), draw()))
        auction = Auction(millis=draw() | 1, start=high, floor=low)
        kind = next(stream) % 4
        if kind == 0:
            rows.append(Case("vector_%d" % index, PRICE, auction=auction, round_bits=to_bits(float(draw()))))
        elif kind == 1:
            elapsed = auction.millis // (1 + next(stream) % 16)
            rows.append(Case("vector_%d" % index, PRICE, auction=auction, round_bits=to_bits(float(elapsed))))
        elif kind == 2:
            rows.append(Case("vector_%d" % index, PRICE, auction=auction.copy(start=low + (draw() >> 11)), round_bits=to_bits(float(draw() >> 12))))
        else:
            rows.append(Case("vector_%d" % index, RESTART, flag=1, auction=Auction(tag=next(stream) % 2, end=draw(), ratio=draw(), start=draw(), floor=draw())))
    return rows


def all_cases(image):
    powers = struct.unpack_from("<40d", image.blob, image.offset(POW10))
    rows = []
    for case in info_cases():
        case.pow10 = powers
        rows.append(case)
    lists = {PRICE: price_cases(), RESTART: restart_cases(), INFO: rows}
    for kind in ROLLS:
        lists[kind] = roll_cases(kind)
    for kind in GATES + SHORT_GATES:
        lists[kind] = gate_cases(kind)
    return lists


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("case %s of %#x: %r != %r" % (case.name, case.kind, got, want))
        outcomes.append(got)
    return outcomes


def direct_to(image, target):
    start, text = image.text_bytes()
    packed = re.compile(b"\xe8")
    hits = []
    for match in packed.finditer(text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def calls_through(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


def slot_rows(image):
    relative = image.relative()
    named = ((SLOT_PRICE, "price", PRICE), (SLOT_TIME, "bucket start time", TIME_HELPER), (SLOT_SECONDS, "seconds between", SECONDS_HELPER), (SLOT_ROUND, "round", ROUND_HELPER))
    rows = []
    for slot, role, target in named:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target))
    return rows


def site_rows(image):
    rows = []
    for name, target in (("price", PRICE), ("restart", RESTART), ("roll_a", ROLLS[0]), ("roll_b", ROLLS[1]), ("roll_c", ROLLS[2]), ("gate_a", GATES[0]), ("gate_b", GATES[1]),
                         ("short_gate_a", SHORT_GATES[0]), ("short_gate_b", SHORT_GATES[1]), ("info_row", INFO), ("gossip_roll", GOSSIP_ROLL)):
        sites = direct_to(image, target)
        if target == PRICE:
            sites += calls_through(image, SLOT_PRICE)
        if target == INFO:
            sites += calls_through(image, 0x57738A0)
        rows.append(("%#x" % target, name, len(sites), " ".join("%#x" % site for site in sorted(sites))))
    return rows


def constant_rows(image):
    names = ((0x20AF40, "1000.0"), (0x20A510, "2^64"), (0x20A218, "2^64-2048"), (0x20A7F0, "2^63"), (0x20A4B0, "infinity"), (0x20A528, "1.01"), (0x20A730, "1.0"))
    rows = []
    for at, name in names:
        data = bytes(image.blob[image.offset(at):image.offset(at) + 8])
        rows.append(("%#x" % at, name, data.hex(), repr(struct.unpack("<d", data)[0])))
    for index in range(20):
        at = POW10 + 8 * index
        data = bytes(image.blob[image.offset(at):image.offset(at) + 8])
        if struct.unpack("<d", data)[0] != 10.0 ** index:
            raise EvidenceError("table row %d" % index)
        rows.append(("%#x" % at, "10^%d" % index, data.hex(), repr(10.0 ** index)))
    return rows


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in ARM_NAMES:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        at = data.find(b"\x48\x8d\x35")
        if at < 0 or data[at + 7] != 0xBA:
            raise EvidenceError("status arm %#x has another shape" % tag)
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
    return rows


FIELD_LIST = b"bucket_guardstart_gas_weiend_gas_weitokeninitial_gas_to_last_auction_gas_ratiomin_gas"
SERIALIZER = 0x230BC10
# key, key length, bytes that name the field, field offset
FIELD_BYTES = (("bucket_guard", bytes.fromhex("488d7b10"), F_MILLIS), ("start_gas_wei", bytes.fromhex("488d4b28"), F_START), ("end_gas_wei", bytes.fromhex("4889d9"), 0),
               ("token", bytes.fromhex("488d4b30"), F_TOKEN), ("initial_gas_to_last_auction_gas_ratio", bytes.fromhex("488d4b20"), F_RATIO), ("min_gas", bytes.fromhex("4883c338"), F_FLOOR))


def field_rows(image):
    start, end = image.exact_fde(SERIALIZER)
    data = bytes(image.blob[image.offset(start):image.offset(end - 1) + 1])
    keys = []
    for match in re.finditer(b"\x48\x8d\x35", data):
        at = match.start()
        target = start + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        width = data[at + 7:at + 18].find(b"\xba")
        if width < 0:
            continue
        size = struct.unpack_from("<I", data, at + 7 + width + 1)[0]
        keys.append((at, bytes(image.blob[image.offset(target):image.offset(target) + size]).decode("ascii")))
    if len(keys) != len(FIELD_BYTES):
        raise EvidenceError("serializer has %d keys" % len(keys))
    rows = []
    previous = 0
    for (at, key), (name, pattern, field) in zip(keys, FIELD_BYTES):
        if key != name:
            raise EvidenceError("key %s where %s was expected" % (key, name))
        # The field row sits between the previous key and the call after this key.
        window = data[previous:at + 40]
        if pattern not in window:
            raise EvidenceError("no field row for %s" % key)
        rows.append((key, "%#x" % (start + at), "%#x" % field, "%#x" % (start + previous + window.index(pattern)), pattern.hex()))
        previous = at + 7
    if image.blob.find(FIELD_LIST) < 0:
        raise EvidenceError("field list missing")
    return rows


AUCTION_KEYS = ((b"register_token_gas_auction", 0x37530BE, bytes.fromhex("488d8b88170000"), 0x1B20), (b"perp_deploy_gas_auction", 0x37530EC, bytes.fromhex("488d8bc8170000"), 0x1B20),
                (b"spot_pair_deploy_gas_auction", 0x375311A, bytes.fromhex("488d8b08180000"), 0x1B20),
                (b"register_token_gas_auction", 0x4D8668E, bytes.fromhex("488d8b283d0000"), 0), (b"perp_deploy_gas_auction", 0x4D866BC, bytes.fromhex("488d8b683d0000"), 0),
                (b"spot_pair_deploy_gas_auction", 0x4D866EA, bytes.fromhex("488d8ba83d0000"), 0))


def auction_rows(image):
    rows = []
    for key, lea, pattern, base in AUCTION_KEYS:
        at = image.offset(lea)
        data = bytes(image.blob[at - 7:at + 7])
        target = lea + 7 + struct.unpack_from("<i", data, 10)[0]
        if data[:7] != pattern or bytes(image.blob[image.offset(target):image.offset(target) + len(key)]) != key:
            raise EvidenceError("auction key row %#x" % lea)
        inner = struct.unpack_from("<i", data, 3)[0]
        if inner + base not in LAYOUT_FIRST["order"] + LAYOUT_SECOND["order"]:
            raise EvidenceError("auction offset %#x" % inner)
        rows.append((key.decode("ascii"), "%#x" % lea, "%#x" % inner, "%#x" % (inner + base)))
    return rows


def roll_rows(image):
    """Each roll copy names the same four offsets and the same gossip words; the sibling loops share the rows."""
    rows = []
    for kind in ROLLS:
        start, end = image.exact_fde(kind)
        data = bytes(image.blob[image.offset(start):image.offset(end - 1) + 1])
        leas = tuple(struct.unpack_from("<i", data, m.start() + 3)[0] for m in re.finditer(b"\x48\x8d\x87", data))
        layout = LAYOUTS[kind]
        if sorted(leas[:4]) != sorted(layout["order"]):
            raise EvidenceError("roll copy %#x has offsets %r" % (kind, leas))
        for word in (layout["borrow"], layout["pointer"], layout["length"]):
            if struct.pack("<i", word) not in data:
                raise EvidenceError("roll copy %#x lacks %#x" % (kind, word))
        rows.append(("%#x" % kind, "%#x" % start, "%#x" % end, " ".join("%#x" % value for value in leas[:4]), sum(1 for site in direct_to(image, RESTART) if start <= site < end)))
    for kind, store in ((SIBLING_ROLLS[0], bytes.fromhex("49894718")), (SIBLING_ROLLS[1], bytes.fromhex("49894718"))):
        start, end = image.exact_fde(kind)
        data = bytes(image.blob[image.offset(start):image.offset(end - 1) + 1])
        if data.count(store) != 1 or not any(start <= site < end for site in direct_to(image, RESTART)):
            raise EvidenceError("sibling roll %#x has another shape" % kind)
        rows.append(("%#x" % kind, "%#x" % start, "%#x" % end, "stride %#x" % SLOT_STRIDE, 1))
    return rows


def edge_rows(harness):
    rows = []
    named = (("start_exceeded_at_zero_elapsed", A.copy(start=(1 << 53) + 3, floor=0), 0.0), ("no_excess_on_tie", A.copy(start=(1 << 53) + 1, floor=0), 0.0),
             ("sum_overflow_gives_floor", A.copy(start=MASK[8], floor=1), 0.0), ("sum_overflow_near_top", A.copy(start=MASK[8], floor=2048), 0.0),
             ("sum_fits_with_zero_floor", A.copy(start=MASK[8], floor=0), 0.0), ("decay_reaches_floor", A.copy(start=1000, floor=100), 60.0),
             ("one_milli_left", A.copy(start=1000, floor=100), 59.999), ("no_room_small_spans_truncate", A.copy(start=101, floor=100), 30.0))
    for name, auction, seconds in named:
        case = Case(name, PRICE, auction=auction, seconds=seconds)
        got = harness.run(case)
        if got != spec_run(case):
            raise EvidenceError("edge row %s" % name)
        rows.append((name, auction.start, auction.floor, auction.millis, seconds, struct.unpack_from("<Q", got[1], 8)[0]))
    return rows


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


def first_failure(harness, cases):
    for case in cases:
        try:
            if harness.run(case) != spec_run(case):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError):
            return case
    return None


YEAR_ZERO = "year 0 or earlier only: such a date is before 1970, so the clamp at 0 hides this term"
SIGN_FIX = "sign fix of a division by 100: the year term is never negative here"
TOP_BIT = "the sar of a 64-bit conversion picks a mask; an input of 2^63 or more has its low ten bits clear, so bit 0 of the mask never matters"
LOOP_END = "the last visit: the loop ends on the bpl test, so this index is not read"
EXPECTED_SURVIVORS = {
    (0x325CD90, "immediate"): "bit 0 of the absolute value mask: no bit pattern moves across the finite bound by losing bit 0, except the largest finite value, which stays below the bound",
    (0x325CDB8, "condition"): "both arms give the same value: the clamp pair leaves 0..2^64 unchanged, and a negative value left alone still converts to 0",
    (0x325CDC6, "condition"): "both arms give the same value: the clamp pair leaves 0..2^64 unchanged, and a value above 2^64 left alone still converts to u64::MAX",
    (0x325CDF5, "immediate"): TOP_BIT, (0x325CEEA, "immediate"): TOP_BIT,
    (0x325CE26, "immediate"): "u64::MAX and u64::MAX - 1 both convert to 2^64 in the next rows, and the word has no other reader",
    (0x2702210, "immediate"): LOOP_END, (0x4CEE4C0, "immediate"): LOOP_END, (0x4CEE7A0, "immediate"): LOOP_END,
    (0x270211B, "immediate"): SIGN_FIX, (0x4CEE3CB, "immediate"): SIGN_FIX, (0x4CEE699, "immediate"): SIGN_FIX, (0x2A25741, "immediate"): SIGN_FIX,
}
for _base in (0x27020B1, 0x4CEE361, 0x4CEE632):
    for _step in (0, 8, 15, 21, 27):
        EXPECTED_SURVIVORS[(_base + _step, "immediate")] = YEAR_ZERO
for _at in (0x2A255F1, 0x2A255F8, 0x2A255FF, 0x2A25605, 0x2A2560D):
    EXPECTED_SURVIVORS[(_at, "immediate")] = YEAR_ZERO


def run_mutants(image, table, seen, lists):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    for target in TARGETS:
        if first_failure(control, lists[target]) is not None:
            raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, lists[target]) is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def rows_of(image, target):
    if target in WINDOWS:
        return [row for low, high in WINDOWS[target] for row in decode_range(image, low, high)]
    return decode_range(image, *image.exact_fde(target))


def analyse(image, mutate=True, vectors=1200):
    harness = Harness(image)
    lists = all_cases(image)
    outcomes = {target: check_cases(harness, lists[target]) for target in TARGETS}
    extra = vector_cases(vectors)
    check_cases(harness, extra)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    one, runs_one = refine(harness.elapsed_stage, "elapsed")
    two, runs_two = refine(harness.product_stage, "product")
    result = dict(table=table, lists=lists, outcomes=outcomes, vector_count=vectors, unreached=unreached, pieces=one + two, stage_runs=(runs_one, runs_two),
                  slots=slot_rows(image), sites=site_rows(image), constants=constant_rows(image), statuses=status_rows(image), fields=field_rows(image), auctions=auction_rows(image),
                  rolls=roll_rows(image), edges=edge_rows(harness), bound=division_bound())
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, lists)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(outcome):
    kind = outcome[0]
    if kind == "price":
        return kind, outcome[1][:0x10].hex(), ",".join(event[0] for event in outcome[2]), ""
    if kind == "restart":
        return kind, "finished" if outcome[1] else "returned", str(outcome[2]), outcome[3].hex()
    if kind == "roll":
        return kind, ",".join(event[0] + (":%d" % event[3] if event[0] == "restart" else "") for event in outcome[1]), "", ""
    if kind == "gate":
        return kind, outcome[1][:0x19].hex(), ",".join(event[0] for event in outcome[2]), ""
    if kind == "panic":
        return kind, "%#x" % outcome[1], "", ""
    return kind, repr(outcome[1:6]), ",".join(event[0] for event in outcome[6]), ""


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("slots.tsv", ("slot", "role", "relative_target"), result["slots"])
    tsv("call-sites.tsv", ("function", "name", "sites", "addresses"), result["sites"])
    tsv("constants.tsv", ("address", "name", "bytes", "value"), result["constants"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("fields.tsv", ("key", "key_lea", "field", "field_row", "pattern"), result["fields"])
    tsv("state-auctions.tsv", ("key", "key_lea", "inner_offset", "state_offset"), result["auctions"])
    tsv("roll-copies.tsv", ("function", "fde_start", "fde_end", "offsets", "restart_calls"), result["rolls"])
    tsv("edges.tsv", ("name", "start", "floor", "millis", "seconds", "price"), result["edges"])
    tsv("stage-pieces.tsv", ("stage", "low_bits", "high_bits", "result_low", "result_high", "decisions"), result["pieces"])
    tsv("outcomes.tsv", ("function", "case", "kind", "output", "events", "state"),
        [("%#x" % target, case.name) + describe(outcome) for target in TARGETS for case, outcome in zip(result["lists"][target], result["outcomes"][target])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    multiplier, excess, exact = result["bound"]
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": sum(len(rows) for rows in result["lists"].values()), "vector_cases": result["vector_count"],
        "stage_pieces": {"elapsed": sum(1 for row in result["pieces"] if row[0] == "elapsed"), "product": sum(1 for row in result["pieces"] if row[0] == "product")},
        "stage_runs": {"elapsed": result["stage_runs"][0], "product": result["stage_runs"][1]},
        "divide_by_1000": {"multiplier": "%#x" % multiplier, "excess": excess, "exact_for_all_u64": exact},
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
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
