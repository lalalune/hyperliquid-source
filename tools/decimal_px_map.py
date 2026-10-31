#!/usr/bin/env python3
"""Pin the node #94 raw price to Decimal map builder 0x3bb7280 and the exactness of its f64 route.

0x3bb7280 walks a dex's book rows, packs asset id dex*10000+i, reads szDecimals from the meta row, divides
the raw price as f64 by 10^(6-sz) and converts the quotient to a 16-byte Decimal with the excess bit
rule. The real bytes run under recording stubs with the real conversion callee, a separately written
rule list predicts every run, every reached row of the builder is mutated, and an error bound table
shows which quotient ranges can lose exactness. No objdump or readelf output is parsed and the binary is
never executed. Standard library only.

    python3 tools/decimal_px_map.py --out <dir>
"""

import argparse
import bisect
import fractions
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
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
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


TARGET = 0x3BB7280
CONVERT = 0x4EAC740
PRICE = 0x32781C0
DROP = 0x3762510
INSERT = 0x3395550
DRAIN = 0x33BA470
SLOT_MAP = 0x5774BE0
SLOT_INDEX = 0x576E470
SLOT_ADD = 0x576E118
SLOT_SLICE = 0x576E150
SLOT_MUL = 0x576E1B0
PANIC_SLOTS = (SLOT_INDEX, SLOT_ADD, SLOT_SLICE, SLOT_MUL)
LOC_INDEX = 0x56F21C0
LOC_PDI = 0x5714708
LOC_DECIMALS = 0x56F3350
DIVISORS = 0x584B08
ZERO_WORDS = 0x207DA4
SITES = (0x27449AA, 0x4D5D41C, 0x4D5DCDC)
STATUS_TABLE = 0x59A8D0
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_BAD = 0xAC
SCALE_BASE = 6
SZ_LIMIT = 7
ASSETS_PER_DEX = 10000
ROW_STRIDE = 0x30
ROW_SZ = 0x2A
BOOK_STRIDE = 0xD8
M_TABLE = 0x08
M_LEN = 0x10
M_DEX = 0x30
B_ROWS = 0x08
B_LEN = 0x10

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
META = HEAP_BASE + 0x300
BOOKS = HEAP_BASE + 0x400
TABLE = HEAP_BASE + 0x500
TABLE_ROWS = 40
COMPARED = 0x1000
USED = 0x2000
FILL = 0xCC
FAR_TABLE = 0x7A00000000
BOOK_ROWS = 0x7900000000
MAP_ROOT = 0x7B00000000
MAP_STEP = 0x100
HEIGHT_CYCLE = 5
TOP = MASK[8]
HEIGHT_UNSET = int.from_bytes(bytes([STACK_MARK]) * 8, "little")
THRESHOLD = fractions.Fraction(4444, 10000)
MANTISSA_LIMIT = 1 << 52


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


def convert(bits):
    """rust_decimal style f64 to Decimal with excess bits removed: (negative, mantissa, scale), None if it does not fit."""
    negative = bits >> 63
    biased = bits >> 52 & 0x7FF
    fraction = bits & (MANTISSA_LIMIT - 1)
    if biased == 0:
        power, mantissa = -1074, fraction
    else:
        power, mantissa = biased - 1075, fraction | MANTISSA_LIMIT
    ten = power
    if power > 0:
        for _ in range(power):
            if mantissa >> 95:
                mantissa //= 5
            else:
                ten -= 1
                mantissa <<= 1
    else:
        for _ in range(-power):
            if mantissa & 1 == 0:
                ten += 1
                mantissa >>= 1
            elif (mantissa * 5) >> 96:
                ten += 1
                mantissa >>= 1
            else:
                mantissa *= 5
    if ten > 0:
        for _ in range(ten):
            mantissa *= 10
            if mantissa >> 96:
                return None
        ten = 0
    while ten < -28:
        quotient, remainder = divmod(mantissa, 10)
        ten += 1
        if quotient == 0:
            mantissa, ten = 0, 0
            break
        mantissa = quotient + (remainder >= 5)
    while ten < 0 and mantissa >= MANTISSA_LIMIT:
        quotient, remainder = divmod(mantissa, 10)
        mantissa = quotient + (remainder >= 5)
        ten += 1
    while ten < 0 and mantissa % 10 == 0:
        mantissa //= 10
        ten += 1
    return negative, mantissa, -ten


def decimal_bytes(result):
    negative, mantissa, scale = result
    return struct.pack("<IIII", negative << 31 | scale << 16, mantissa >> 64, mantissa & MASK[4], mantissa >> 32 & MASK[4])


def quotient_bits(x, sz, divisors=None):
    divisor = (divisors or {}).get(SCALE_BASE - sz, 10.0 ** (SCALE_BASE - sz))
    return to_bits(fdiv(float(x), divisor))


def display(result):
    negative, mantissa, scale = result
    text = str(mantissa).rjust(scale + 1, "0")
    if scale:
        text = text[:-scale] + "." + text[-scale:]
    return ("-" if negative else "") + text


class Case:
    """rows is a list of (raw price, szDecimals); table_len and dex shape the meta struct."""

    def __init__(self, name, rows, dex=0, table_len=None, divisors=None, far=False):
        self.name, self.rows, self.dex = name, rows, dex
        self.table_len = len(rows) if table_len is None else table_len
        self.divisors, self.far = divisors or {}, far


def blank():
    return bytes([FILL]) * OUT_SIZE


def spec_run(case):
    """Events and the Out block from the rule list, without looking at the code."""
    events, out = [], bytearray(blank())

    def finish_ok(count):
        out[0:2] = struct.pack("<H", TAG_OK)
        root = MAP_ROOT + MAP_STEP * (count - 1) if count else 0
        height = (count - 1) % HEIGHT_CYCLE if count else HEIGHT_UNSET
        out[8:0x20] = struct.pack("<QQQ", root, height, count)
        return "done", tuple(events), bytes(out)

    def finish_bad(count):
        out[0:2] = struct.pack("<H", TAG_BAD)
        root = MAP_ROOT + MAP_STEP * (count - 1) if count else 0
        height = (count - 1) % HEIGHT_CYCLE if count else HEIGHT_UNSET
        events.append(("drain", root, height, count))
        return "done", tuple(events), bytes(out)

    def panic(slot, location):
        events.append(("panic", slot, location))
        return "panic", tuple(events), bytes(out)

    if not case.rows:
        return finish_ok(0)
    base = case.dex * ASSETS_PER_DEX
    if base > TOP:
        return panic(SLOT_MUL, LOC_PDI)
    count = 0
    for local, (x, sz) in enumerate(case.rows):
        asset = base + local
        if asset > TOP:
            return panic(SLOT_ADD, LOC_PDI)
        events.append(("price", local))
        if local >= ASSETS_PER_DEX or local >= case.table_len:
            return panic(SLOT_INDEX, LOC_INDEX)
        if sz >= SZ_LIMIT:
            return panic(SLOT_SLICE, LOC_DECIMALS)
        bits = quotient_bits(x, sz, case.divisors)
        if bits & (TOP >> 1) >= 0x7FF0000000000000:
            return finish_bad(count)
        if bits & (TOP >> 1) == 0:
            value = decimal_bytes((bits >> 63, 0, 0))
        else:
            result = convert(bits)
            if result is None:
                return finish_bad(count)
            value = decimal_bytes(result)
        events.append(("drop", TAG_BAD))
        events.append(("insert", asset, value))
        count += 1
    return finish_ok(count)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((CONVERT,))
        machine.calls = {PRICE: self.on_price, DROP: self.on_drop, INSERT: self.on_insert, DRAIN: self.on_drain}
        statics = machine.memory.statics
        for slot in PANIC_SLOTS:
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = self.panic_hook(slot)
        self.events = []
        self.case = None
        self.count = 0
        self.prices = 0
        self.drain = None
        self.far_keys = []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def panic_hook(self, slot):
        def hook(machine):
            self.events.append(("panic", slot, machine.regs[RDI]))
            raise Panicked("panic")
        return hook

    def read(self, addr):
        return self.machine.memory.read(addr, 8)

    def word(self, addr, value):
        self.machine.memory.write(addr, 8, value & MASK[8])

    def frame(self):
        return self.machine.regs[RSP] + 8

    def on_price(self, machine):
        local = self.prices
        self.prices += 1
        self.expect(machine.regs[RDI] == BOOK_ROWS + BOOK_STRIDE * local, "book row pointer")
        self.events.append(("price", local))
        machine.regs[RAX] = self.case.rows[local][0]

    def on_drop(self, machine):
        frame = self.frame()
        self.expect(machine.regs[RDI] == frame + 0x50, "drop pointer")
        self.events.append(("drop", machine.memory.read(frame + 0x50, 2)))

    def on_insert(self, machine):
        frame = self.frame()
        regs = machine.regs
        self.expect(regs[RDI] == frame + 0x114 and regs[RSI] == frame and regs[RCX] == frame + 0xB0, "insert pointers")
        self.expect(self.read(frame) == (MAP_ROOT + MAP_STEP * (self.count - 1) if self.count else 0), "map root before insert")
        self.expect(self.read(frame + 0x10) == self.count, "map length before insert")
        self.events.append(("insert", regs[RDX], machine.memory.bytes_at(frame + 0xB0, 16)))
        self.word(frame, MAP_ROOT + MAP_STEP * self.count)
        self.word(frame + 8, self.count % HEIGHT_CYCLE)
        self.word(frame + 0x10, self.count + 1)
        self.count += 1

    def on_drain(self, machine):
        frame = self.frame()
        regs = machine.regs
        self.expect(regs[RDI] == frame + 0x28 and regs[RSI] == frame + 0x50, "drain pointers")
        if self.drain is None:
            words = [self.read(frame + 0x50 + 8 * index) for index in range(9)]
            root = self.read(frame)
            height = self.read(frame + 8)
            flag = int(root != 0)
            want = [flag, 0, root, height, flag, 0, root, height, self.read(frame + 0x10) if flag else 0]
            if flag:
                self.expect(words == want, "iterator words")
            else:
                self.expect(words[0] == 0 and words[4] == 0 and words[8] == 0, "empty iterator words")
            self.events.append(("drain", root, height, words[8]))
            self.drain = words[8]
        self.word(frame + 0x28, 1 if self.drain else 0)
        self.drain = max(self.drain - 1, 0)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        statics = memory.statics
        for key in self.far_keys:
            statics.pop(key, None)
        self.far_keys = []
        for key in range(SCALE_BASE + 1):
            statics.pop(DIVISORS + 8 * key, None)
        for key, value in case.divisors.items():
            statics[DIVISORS + 8 * key] = to_bits(value)
        base = FAR_TABLE if case.far else TABLE
        self.word(META + M_TABLE, base)
        self.word(META + M_LEN, case.table_len)
        self.word(META + M_DEX, case.dex)
        self.word(BOOKS + B_ROWS, BOOK_ROWS)
        self.word(BOOKS + B_LEN, len(case.rows))
        if case.far:
            for local, row in enumerate(case.rows):
                key = FAR_TABLE + ROW_STRIDE * local + ROW_SZ
                statics[key] = row[1]
                self.far_keys.append(key)
        else:
            if len(case.rows) > TABLE_ROWS:
                raise EvidenceError("table too small")
            for local, row in enumerate(case.rows):
                memory.write(TABLE + ROW_STRIDE * local + ROW_SZ, 1, row[1])
        self.case = case
        self.events = []
        self.count = 0
        self.prices = 0
        self.drain = None
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        status = "done"
        try:
            result = self.machine.run(TARGET, {RDI: OUT, RSI: META, RDX: BOOKS})
            self.expect(result == OUT, "result pointer")
        except Panicked:
            status = "panic"
        after = memory.bytes_at(HEAP_BASE, COMPARED)
        at = OUT - HEAP_BASE
        if after[:at] != self.before[:at] or after[at + OUT_SIZE:] != self.before[at + OUT_SIZE:]:
            raise Halt("write outside the Out block")
        return status, tuple(self.events), after[at:at + OUT_SIZE]


GRID = (0, 1, 2, 9, 10, 99, 100, 999, 1000, 12345, 99999, 100000, 1000000, 1234567, 10000000, 4096029, 419430423, 40960254, 409602504, 4096000004, (1 << 52) - 1, 1 << 52, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 53) + 2,
        10 ** 15, 10 ** 16 + 1, 10 ** 18, 10 ** 19, 1 << 63, TOP - 1023, TOP - 1024, TOP - 1, TOP)


def structure_cases():
    bound = TOP // ASSETS_PER_DEX
    fault = dict(table_len=None)
    rows = [("empty", [], dict()), ("empty_top_dex", [], dict(dex=1 << 62)), ("one_dex0", [(1000000, 0)], dict()),
            ("one_dex1", [(1000000, 0)], dict(dex=1)), ("three_mixed", [(123456, 3), (7, 6), (5000000, 0)], dict(dex=7)),
            ("sz_each", [(123456789, sz) for sz in range(SZ_LIMIT)], dict(dex=2)), ("sz_7", [(1, 0), (1, 7)], dict(dex=3)),
            ("sz_8", [(1, 8)], dict()), ("sz_255", [(1, 255)], dict()), ("sz_128", [(1, 128)], dict()), ("longer_than_table", [(5, 1), (6, 1), (7, 1)], dict(table_len=2)),
            ("table_empty", [(5, 1)], dict(table_len=0)), ("dex_bound", [(5, 1), (6, 1)], dict(dex=bound)), ("dex_bound_plus", [(5, 1)], dict(dex=bound + 1)),
            ("dex_top", [(5, 1)], dict(dex=TOP)), ("dex_two_pow_32", [(5, 1), (6, 2)], dict(dex=1 << 32)), ("zero_first", [(0, 0), (0, 6), (1, 6)], dict()),
            ("zero_scale_six", [(0, 0)], dict(dex=4)), ("forty_rows", [(index * 1000 + 1, index % 7) for index in range(TABLE_ROWS)], dict(dex=9))]
    cases = [Case(name, data, **fields) for name, data, fields in rows]
    del fault
    return cases


def fault_cases():
    """Divisor table words replaced in the fixture only: rows the real table cannot reach."""
    rows = [("fault_inf_first", [(5, 6)], {0: 0.0}), ("fault_inf_after_rows", [(5, 1), (6, 1), (5, 6)], {0: 0.0}), ("fault_nan", [(0, 6)], {0: 0.0}),
            ("fault_negative", [(5, 6)], {0: -1.0}), ("fault_negative_zero", [(0, 6)], {0: -1.0}), ("fault_too_large", [(5, 1), (TOP, 6)], {0: 1e-30}),
            ("fault_too_large_first", [(TOP, 6)], {0: 1e-30}), ("fault_subnormal", [(1, 6), (3, 6)], {0: 1e308}), ("fault_tiny", [(1, 6)], {0: 2.0 ** 1000}), ("fault_small_fraction", [(3, 6)], {0: 1e30}),
            ("fault_huge_divide", [(TOP, 6), (1 << 62, 6)], {0: 1e-9})]
    return [Case(name, data, divisors=divisors) for name, data, divisors in rows]


def grid_cases():
    cases = []
    for sz in range(SZ_LIMIT):
        for start in range(0, len(GRID), 6):
            chunk = GRID[start:start + 6]
            cases.append(Case("grid_sz%d_%d" % (sz, start), [(x, sz) for x in chunk], dex=sz))
    return cases


def heavy_cases():
    bound = TOP // ASSETS_PER_DEX
    room = TOP - bound * ASSETS_PER_DEX
    return [Case("index_10001_rows", [(0, 0)] * (ASSETS_PER_DEX + 1), dex=3, table_len=ASSETS_PER_DEX + 5, far=True),
            Case("asset_id_wrap", [(0, 0)] * (room + 2), dex=bound, table_len=room + 5, far=True)]


def named_cases():
    return structure_cases() + fault_cases() + grid_cases()


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state


def vector_cases(count):
    stream = lcg(0x3BB7280)
    cases = []
    for index in range(count):
        rows = []
        for _ in range(4):
            shift = next(stream) % 64
            x = next(stream) >> shift
            rows.append((x, next(stream) % SZ_LIMIT))
        cases.append(Case("vector_%d" % index, rows, dex=next(stream) % 200))
    return cases


def exact_value(x, k):
    result = convert(quotient_bits(x, SCALE_BASE - k))
    return fractions.Fraction(result[1], 10 ** result[2]) == fractions.Fraction(x, 10 ** k)


def error_rows():
    """Half an ulp of the quotient, in units of the last kept digit, for every binade and kept scale of the domain."""
    rows = []
    low, high = fractions.Fraction(1, 10 ** 6), fractions.Fraction(1 << 64)
    for power in range(-20, 64):
        one, two = fractions.Fraction(2) ** power, fractions.Fraction(2) ** (power + 1)
        for scale in range(0, 29):
            first = max(one, low, fractions.Fraction(MANTISSA_LIMIT, 10 ** (scale + 1)))
            last = min(two, high, fractions.Fraction(MANTISSA_LIMIT, 10 ** scale))
            if first >= last:
                continue
            bound = fractions.Fraction(2) ** (power - 53) * 10 ** scale
            rows.append((power, scale, first, last, bound))
    return rows


def windows_of(rows):
    return [row for row in rows if row[4] >= THRESHOLD]


def inside(windows, value):
    return any(row[2] <= value < row[3] for row in windows)


def error_exceeds(x, k, scale):
    power = 10 ** k
    top, bottom = (x / power).as_integer_ratio()
    return 9 * abs(top * power - x * bottom) * 10 ** scale >= 4 * bottom * power


def first_inexact(windows, k):
    """Walk x upward through every window; every x outside is exact by the bound table."""
    power = 10 ** k
    tried = 0
    for row in windows:
        start = math.ceil(row[2] * power)
        end = min(math.ceil(row[3] * power), 10 ** 15)
        if end - start > SCAN_ROWS:
            end = start + SCAN_ROWS
        for x in range(start, end):
            if x % power == 0:
                continue
            tried += 1
            if error_exceeds(x, k, row[1]) and not exact_value(x, k):
                return x, row[0], tried
    return None, None, tried


SCAN_ROWS = 3500000


def significant_scan(windows, digits):
    """All x with at most `digits` significant digits, below 10^15, whose quotient lies in a window."""
    bad, tried = [], 0
    low, high = 10 ** (digits - 1), 10 ** digits
    for k in range(1, SCALE_BASE + 1):
        power = 10 ** k
        for row in windows:
            for shift in range(0, 15):
                unit = 10 ** shift
                first = max(low, math.ceil(row[2] * power / unit))
                last = min(high, math.ceil(row[3] * power / unit))
                for d in range(first, last):
                    x = d * unit
                    if x >= 10 ** 15 or x % power == 0:
                        continue
                    tried += 1
                    if error_exceeds(x, k, row[1]) and not exact_value(x, k):
                        bad.append((x, k))
    return tried, bad


def sample_rule(windows, count):
    """Below 10^15 and outside the windows every sampled quotient is exact; inexact samples all lie inside."""
    stream = lcg(0x10000)
    outside = in_window = wrong = 0
    for _ in range(count):
        digits = next(stream) % 15 + 1
        x = next(stream) % 10 ** digits
        k = next(stream) % (SCALE_BASE + 1)
        if x == 0:
            continue
        ok = exact_value(x, k)
        if inside(windows, fractions.Fraction(x / 10 ** k)):
            in_window += 1
        else:
            outside += 1
            wrong += not ok
    return dict(sampled_outside=outside, sampled_inside=in_window, sampled_outside_inexact=wrong)


def exactness(harness):
    table = error_rows()
    windows = windows_of(table)
    firsts = []
    for k in range(1, SCALE_BASE + 1):
        x, power, tried = first_inexact(windows, k)
        firsts.append((k, x, power, tried))
    witnesses = []
    for k, x, power, tried in firsts:
        if x is None:
            continue
        sz = SCALE_BASE - k
        case = Case("first_inexact_k%d" % k, [(x, sz)])
        got = harness.run(case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("real bytes differ on the first inexact value k=%d" % k)
        result = convert(quotient_bits(x, sz))
        text = str(x).rjust(k + 1, "0")
        witnesses.append((k, x, text[:-k] + "." + text[-k:], display(result), "%#018x" % quotient_bits(x, sz)))
    scans = {digits: significant_scan(windows, digits) for digits in (5, 6)}
    return dict(table=table, windows=windows, firsts=firsts, witnesses=witnesses, scans=scans, sample=sample_rule(windows, 12000))


def display_cases():
    rows = []
    for x, k in ((1, 6), (123456, 3), (1000000, 6), (10 ** 15 + 1, 0), ((1 << 53) + 1, 0), (TOP, 0), (TOP, 6), (10 ** 16 + 1, 2), (1 << 63, 3), (333333333333333, 6), (4503599627370495, 3)):
        result = convert(quotient_bits(x, SCALE_BASE - k))
        rows.append((x, k, "%#018x" % quotient_bits(x, SCALE_BASE - k), display(result), result[1], result[2]))
    return rows


def direct_to(image, target):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def slot_sites(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


def site_rows(image):
    if image.relative().get(SLOT_MAP) != TARGET:
        raise EvidenceError("map slot")
    sites = slot_sites(image, SLOT_MAP)
    if tuple(sites) != SITES:
        raise EvidenceError("map sites %r" % sites)
    if direct_to(image, TARGET):
        raise EvidenceError("direct call to the map builder")
    if direct_to(image, PRICE) != [0x3BB7331]:
        raise EvidenceError("price helper has other callers")
    return [("%#x" % site, "%#x" % SLOT_MAP, "%#x" % TARGET) for site in sites]


def divisor_rows(image):
    rows = []
    at = image.offset(DIVISORS)
    for k in range(SCALE_BASE + 1):
        word = struct.unpack_from("<Q", image.blob, at + 8 * k)[0]
        if to_float(word) != 10.0 ** k:
            raise EvidenceError("divisor %d" % k)
        rows.append((k, SCALE_BASE - k, "%#x" % (DIVISORS + 8 * k), "%#018x" % word, "%d" % to_float(word)))
    return rows


def location_rows(image):
    rows = []
    relative = image.relative()
    for slot in (LOC_INDEX, LOC_PDI, LOC_DECIMALS):
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % slot, path, line, column))
    return rows


def constant_rows(image):
    zero = bytes(image.blob[image.offset(ZERO_WORDS):image.offset(ZERO_WORDS) + 12])
    if zero != bytes(12):
        raise EvidenceError("zero words")
    base = image.offset(STATUS_TABLE)
    arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * TAG_BAD)[0]
    data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
    at = data.find(b"\x48\x8d\x35")
    text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    size = struct.unpack_from("<I", data, at + 8)[0]
    return [("%#x" % ZERO_WORDS, zero.hex(), "twelve zero bytes behind the flags word of a zero Decimal"),
            ("%#x" % TAG_BAD, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii"))]


def bound_rows(image):
    """Quotient range of the real table: why the non-finite, subnormal and None rows are out of reach."""
    words = [to_float(struct.unpack_from("<Q", image.blob, image.offset(DIVISORS) + 8 * k)[0]) for k in range(SCALE_BASE + 1)]
    small = min(1.0 / word for word in words)
    large = max(float(TOP) / word for word in words)
    return dict(smallest_nonzero_quotient=small.hex(), largest_quotient=large.hex(), largest_binary_exponent=math.frexp(large)[1] - 53)


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case)
        if got != want:
            events = [(index, one, two) for index, (one, two) in enumerate(zip(got[1], want[1])) if one != two][:3]
            raise EvidenceError("case %s: %s %s events %r lengths %d %d out %s %s" % (case.name, got[0], want[0], events, len(got[1]), len(want[1]), got[2][:0x20].hex(), want[2][:0x20].hex()))
        outcomes.append(got)
    return outcomes


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
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error):
            return case
    return None


SUBNORMAL = "every subnormal quotient is far below the Decimal unit 1e-28, so the conversion gives 0 whatever this row feeds it, and a zero quotient gives the same bytes"
EXPECTED_SURVIVORS = {
    (0x3BB73C8, "immediate"): "clears bit 0 of the absolute value: only a NaN with fraction 1 would change side, and a divide cannot produce one",
    (0x3BB73D5, "immediate"): "moves the bound to infinity+1: infinity then enters the converter, which refuses it, giving the same status and no row",
    (0x3BB73F2, "immediate"): "clears bit 0 of the fraction for the zero test: fraction 1 is 2^-1074, below any u64 over a finite divisor",
    (0x3BB7433, "condition"): SUBNORMAL, (0x3BB7439, "immediate"): SUBNORMAL, (0x3BB7445, "immediate"): SUBNORMAL, (0x3BB744D, "immediate"): SUBNORMAL,
}
CASE_STEP_LIMIT = 150000


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = CASE_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for va, kind, patch in edits_for(image, table, seen):
        harness = Harness(image, patch)
        harness.machine.step_limit = CASE_STEP_LIMIT
        failed = first_failure(harness, cases)
        if failed is not None:
            results.append((va, kind, "killed", "whole run"))
        else:
            results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def mutant_cases():
    return structure_cases() + fault_cases() + grid_cases()[:7]


def analyse(image, mutate=True, vectors=300):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    harness.machine.step_limit = 3000000
    heavy = heavy_cases()
    outcomes += check_cases(harness, heavy)
    harness.machine.step_limit = STEP_LIMIT
    cases = cases + heavy
    check_cases(harness, vector_cases(vectors))
    exact = exactness(harness)
    seen = set(harness.machine.seen)
    table = decode_range(image, *image.exact_fde(TARGET))
    unreached = [row.va for row in table if row.va not in seen and row.op not in ("int3", "nop")]
    convert_rows = decode_range(image, *image.exact_fde(CONVERT))
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, exact=exact, sites=site_rows(image), divisors=divisor_rows(image), locations=location_rows(image), constants=constant_rows(image),
                  bounds=bound_rows(image), displays=display_cases(), convert_rows=len(convert_rows), convert_reached=sum(1 for row in convert_rows if row.va in seen))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, mutant_cases())
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(outcome):
    text = "%#x" % struct.unpack_from("<H", outcome[2], 0)[0] if outcome[0] == "done" else "panic"
    counts = {}
    for event in outcome[1]:
        counts[event[0]] = counts.get(event[0], 0) + 1
    return text, ",".join("%s=%d" % item for item in sorted(counts.items())), hashlib.sha256(repr(outcome).encode()).hexdigest()[:16]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    exact = result["exact"]
    tsv("function-rows.tsv", ("address", "size", "bytes", "operation"), [("%#x" % row.va, row.size, row.data.hex(), row.op) for row in result["table"]])
    tsv("call-sites.tsv", ("site", "slot", "relative_target"), result["sites"])
    tsv("divisors.tsv", ("k", "sz_decimals", "address", "bits", "value"), result["divisors"])
    tsv("locations.tsv", ("record", "path", "line", "column"), result["locations"])
    tsv("constants.tsv", ("address_or_tag", "value", "meaning"), result["constants"])
    tsv("outcomes.tsv", ("case", "status", "events", "digest"), [(case.name,) + describe(outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    tsv("sample-values.tsv", ("raw", "k", "quotient_bits", "decimal", "mantissa", "scale"), result["displays"])
    tsv("error-bound.tsv", ("binade_power", "kept_scale", "low", "high", "half_ulp_in_last_digit", "window"),
        [(row[0], row[1], "%.6f" % float(row[2]), "%.6f" % float(row[3]), "%.6f" % float(row[4]), int(row[4] >= THRESHOLD)) for row in exact["table"]])
    tsv("first-inexact.tsv", ("k", "raw", "binade_power", "x_tried"), [(k, "none below the scan cap" if x is None else x, "" if power is None else power, tried) for k, x, power, tried in exact["firsts"]])
    tsv("inexact-witnesses.tsv", ("k", "raw", "exact_text", "decimal", "quotient_bits"), exact["witnesses"])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "target": {"address": "%#x" % TARGET, "bytes": sum(row.size for row in result["table"]), "instructions": len(result["table"]), "unreached_rows": ["%#x" % va for va in result["unreached"]]},
        "convert_callee": {"rows": result["convert_rows"], "rows_reached": result["convert_reached"]},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"], "quotient_range": result["bounds"], "scan_cap_per_window": SCAN_ROWS,
        "windows": [{"binade_power": row[0], "kept_scale": row[1], "half_ulp": "%.6f" % float(row[4])} for row in exact["windows"]],
        "significant_scan": {str(digits): {"tried": value[0], "inexact": len(value[1])} for digits, value in exact["scans"].items()}, "rule_sample": exact["sample"],
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
