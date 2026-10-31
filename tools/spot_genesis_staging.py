#!/usr/bin/env python3
"""Pin node #94 spot UserGenesis staging: the genesis caps, the blacklist gate and the three row writers.

The real bytes run on real B-tree nodes, including the tree helpers they call. A separately written rule list predicts
the result word, the stored maps and every other heap byte, and every reached conditional row, immediate and field
offset is mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/spot_genesis_staging.py --out <dir>
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
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 3000000
MUTANT_STEP_LIMIT = 200000


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
            return finish("cvtsi2sd", ("x", reg), rm, width)
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
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
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

CAP_GATE = 0x371F250
BLACK_GATE = 0x371FDA0
STORE_USERS = 0x371F030
STORE_TOKENS = 0x3721160
BLACK_SET = 0x37215B0
NAMES = {CAP_GATE: "genesis_cap_gate", BLACK_GATE: "blacklist_gate", STORE_USERS: "store_user_balances", STORE_TOKENS: "store_existing_token_balances", BLACK_SET: "apply_blacklist_rows"}
TARGETS = tuple(sorted(NAMES))
SLOTS = {CAP_GATE: 0x5774C98, BLACK_GATE: 0x5774CA0, STORE_USERS: 0x5774CB0, STORE_TOKENS: 0x5774CB8, BLACK_SET: 0x5774CC0}
KEEP_ADDRESS = b"\xff" * 20
KEEP_AT = 0x599044
COLLECT_USERS = 0x3BB3E40
COLLECT_TOKENS = 0x3BB25F0
SET_INSERT = 0x339B590
SET_REMOVE = 0x33ACFE0
TOKEN_INSERT = 0x3398240
DROP_TOKENS = 0x33F4320
DROP_NEXT = 0x33B1E80
HELPERS = (COLLECT_USERS, COLLECT_TOKENS, SET_INSERT, SET_REMOVE, TOKEN_INSERT, DROP_TOKENS, DROP_NEXT)
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_ZERO = 0x576DFF0
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_SORT = 0x5774F60
SLOT_CMP = 0x576E488
SLOT_ONCE = 0x576E8B8
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128)
ONCE_WORD = 0x577AB98
RESUME = 0x5660110
MARK_BASE = 0x7700000000
OK = 0x186
TAG_TEXT = 0xDF
TAG_TOKEN = 0xEA
TEXTS = {"too_many_blacklist": (0x59919A, 0x26), "blacklist_with_balances": (0x59913D, 0x5D), "balance_for_blacklisted": (0x5991C0, 0xA2), "genesis_limit": (0x3F009D, 0x3B)}
TEXT_TABLE = 0x59A8D0
SERDE = (b"struct TokenGenesis with 3 elements", b"user_balancesexisting_token_balancesblacklist_users")
OUT = HEAP_BASE + 0x100
S = HEAP_BASE + 0x1000
VEC_AT = HEAP_BASE + 0x200
ROWS = HEAP_BASE + 0x2000
ROWS_B = HEAP_BASE + 0x1800
NODES = HEAP_BASE + 0xC0000
NODE_END = HEAP_BASE + 0xFF000
FILL_END = NODES - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
TOP = MASK[8]
ROOT_AT = S + 0x370
COUNT_AT = S + 0x198
USER_ROW = 0x30


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, len_at, edge_at, index_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.len_at, self.edge_at, self.index_at = key_at, key_size, val_at, val_size, len_at, edge_at, index_at


L_TOP = Layout(8, 8, 0x60, 0x48, 0x37A, 0x380, 0x378)
L_USERS = Layout(0x60, 0x14, 8, 8, 0x13E, 0x140, 0x13C)
L_TOKENS = Layout(8, 8, 0x60, 8, 0xBA, 0xC0, 0xB8)
L_BLACK = Layout(8, 0x14, 0, 0, 0xE6, 0xE8, 0xE4)


def address(number):
    return number.to_bytes(20, "big")


class Case:
    FIELDS = dict(token=7, users=(), tokens=(), black=None, state=None, count=64, model=False, seed_users=0, seed_tokens=0, once=0, keep_seeded=False, n=None, m=None)

    def __init__(self, name, entry, **fields):
        self.name = name
        self.entry = entry
        for key, value in self.FIELDS.items():
            setattr(self, key, fields.pop(key, value))
        if fields:
            raise EvidenceError("unknown case field %s" % sorted(fields))
        self.state = {token: (dict(rec[0]), dict(rec[1]), sorted(set(rec[2]))) for token, rec in (self.state or {}).items()}
        if (self.seed_users or self.seed_tokens or self.keep_seeded) and self.token not in self.state:
            self.state[self.token] = ({}, {}, [])
        self.n = len(self.users) if self.n is None else self.n
        self.m = len(self.tokens) if self.m is None else self.m


def spec_cap(case, out):
    def verdict(flag):
        out[:3] = OK.to_bytes(2, "little") + bytes([flag])
        return "ok %d" % flag
    if case.n > 10000 or case.m > 2:
        return verdict(0)
    rec = case.state.get(case.token, ({}, {}, []))
    users = set(rec[0]) | {bytes((1, i // 256 + 1, i % 256)) for i in range(case.seed_users)}
    if case.keep_seeded:
        users.add(KEEP_ADDRESS)
    users |= {address(user) if isinstance(user, int) else user for user, _ in case.users}
    users.discard(KEEP_ADDRESS)
    if len(users) > 10000:
        return verdict(0)
    tokens = set(rec[1]) | {1 << 60 | i for i in range(case.seed_tokens)}
    for token, _ in case.tokens:
        if token >= case.count:
            out[:2] = TAG_TOKEN.to_bytes(2, "little")
            return "refused token"
        tokens.add(token)
    return verdict(int(len(tokens) <= 2))


def spec_black(case, out):
    def text(name):
        at, size = TEXTS[name]
        out[:2] = TAG_TEXT.to_bytes(2, "little")
        out[8:24] = struct.pack("<QQ", at, size)
        return "refused " + name
    def ok():
        out[:2] = OK.to_bytes(2, "little")
        return "ok"
    if case.black is not None:
        if len(case.black) > 1000:
            return text("too_many_blacklist")
        if case.n or case.m:
            return text("blacklist_with_balances")
        return ok()
    rec = case.state.get(case.token, ({}, {}, []))
    held = set(rec[2])
    if any(address(user) in held for user, _ in case.users):
        return text("balance_for_blacklisted")
    return ok()


def record(state, token):
    return state.setdefault(token, ({}, {}, set()))


def spec_state(case):
    state = {token: (dict(rec[0]), dict(rec[1]), set(rec[2])) for token, rec in case.state.items()}
    events = []
    if case.entry == STORE_USERS:
        for user, wei in case.users:
            rec = record(state, case.token)
            key = address(user)
            if key in rec[0] and rec[0][key] != wei and case.once:
                events.append("once")
            rec[0][key] = wei
    elif case.entry == STORE_TOKENS:
        for token, wei in case.tokens:
            rec = record(state, case.token)
            if token in rec[1] and rec[1][token] != wei and case.once:
                events.append("once")
            rec[1][token] = wei
    elif case.entry == BLACK_SET:
        rec = record(state, case.token)
        for user, flag in case.black:
            key = address(user)
            if flag:
                rec[0].pop(key, None)
                rec[2].add(key)
            else:
                rec[2].discard(key)
    return state, events


def flat(state):
    return tuple(sorted((token, tuple(sorted(rec[0].items())), tuple(sorted(rec[1].items())), tuple(sorted(rec[2]))) for token, rec in state.items()))


def spec_run(case, before):
    out = bytearray(before[OUT - HEAP_BASE:OUT - HEAP_BASE + 24])
    if case.entry == CAP_GATE:
        label = spec_cap(case, out)
    elif case.entry == BLACK_GATE:
        label = spec_black(case, out)
    else:
        label = "stored"
    state, events = spec_state(case)
    return ("run", bytes(out), flat(state), tuple(events), None, label)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        self.model_calls = {COLLECT_USERS: self.on_collect_users, COLLECT_TOKENS: self.on_collect_tokens, SET_INSERT: self.on_set_insert, SET_REMOVE: self.on_set_remove, TOKEN_INSERT: self.on_token_insert, DROP_TOKENS: self.on_drop, DROP_NEXT: self.on_drop_next}
        hooks = {SLOT_FREE: self.on_free, SLOT_ALLOC: self.on_alloc, SLOT_COPY: self.on_copy, SLOT_MOVE: self.on_copy, SLOT_CMP: self.on_cmp, SLOT_ONCE: self.on_once}
        for slot in PANIC_SLOTS:
            hooks[slot] = self.on_panic
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        statics[ONCE_WORD] = 0
        statics[SLOT_SORT] = image.relative()[SLOT_SORT]
        self.case = None
        self.events = []
        self.live = {}
        self.node_cur = NODES
        self.sets = {}
        self.real_set = None

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        raise Panicked("panic path")

    def on_once(self, machine):
        self.expect(machine.regs[RDI] == ONCE_WORD and machine.regs[RSI] == 1, "once word and flag")
        self.events.append("once")

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        at = self.node_cur
        self.node_cur += (size + 15) & ~15
        self.expect(self.node_cur <= NODE_END, "allocator room")
        self.live[at] = size
        machine.regs[RAX] = at
        if self.case.entry == BLACK_GATE and self.case.users and size in (L_BLACK.edge_at, L_BLACK.edge_at + 0x60):
            for slot in range(11):
                machine.memory.put_bytes(at + L_BLACK.key_at + L_BLACK.key_size * slot, self.stale(L_BLACK))

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.pop(at, None) == size, "free of a live block with its size")

    def on_copy(self, machine):
        dst, src, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        machine.memory.put_bytes(dst, machine.memory.bytes_at(src, size))
        machine.regs[RAX] = dst

    def on_cmp(self, machine):
        left = machine.memory.bytes_at(machine.regs[RDI], machine.regs[RDX])
        right = machine.memory.bytes_at(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if left == right else (1 if left > right else TOP)

    def collected(self, machine, base, keys):
        memory = machine.memory
        target = machine.regs[RDI]
        at = self.rec_at(base)
        root, height, size = (memory.read(at + 8 * i, 8) for i in range(3))
        flag = int(root != 0)
        words = [flag, 0, root, height, flag, 0, root, height, size if root else 0]
        self.expect([memory.read(machine.regs[RSI] + 8 * i, 8) for i in range(9)] == words, "iterator words")
        memory.write(target, 8, 0x4000)
        memory.write(target + 8, 8, 0)
        memory.write(target + 16, 8, len(keys))
        self.sets[target] = set(keys)

    def rec_at(self, base):
        memory = self.machine.memory
        return self.walk_top(self.case.token) + base

    def walk_top(self, token):
        memory = self.machine.memory
        node = memory.read(ROOT_AT, 8)
        height = memory.read(ROOT_AT + 8, 8)
        while True:
            size = memory.read(node + L_TOP.len_at, 2)
            keys = [memory.read(node + 8 + 8 * slot, 8) for slot in range(size)]
            if token in keys:
                return node + 0x60 + 0x48 * keys.index(token)
            node = memory.read(node + L_TOP.edge_at + 8 * sum(key < token for key in keys), 8)
            height -= 1

    def rec_of(self):
        return self.case.state.get(self.case.token, ({}, {}, []))

    def on_collect_users(self, machine):
        case = self.case
        keys = set(self.rec_of()[0]) | {bytes((1, i // 256 + 1, i % 256)) for i in range(case.seed_users)}
        if case.keep_seeded:
            keys.add(KEEP_ADDRESS)
        self.collected(machine, 0, keys)

    def on_collect_tokens(self, machine):
        case = self.case
        self.collected(machine, 0x18, set(self.rec_of()[1]) | {1 << 60 | i for i in range(case.seed_tokens)})

    def update(self, machine, key, add):
        target = machine.regs[RDI]
        self.sets.setdefault(target, set())
        if add:
            self.sets[target].add(key)
        else:
            self.sets[target].discard(key)
        machine.memory.write(target + 16, 8, len(self.sets[target]))

    def on_set_insert(self, machine):
        self.update(machine, machine.memory.bytes_at(machine.regs[RSI], 20), True)

    def on_set_remove(self, machine):
        self.expect(machine.memory.bytes_at(machine.regs[RSI], 20) == bytes(self.image.blob[self.image.offset(KEEP_AT):self.image.offset(KEEP_AT) + 20]), "removed key")
        self.update(machine, machine.memory.bytes_at(machine.regs[RSI], 20), False)

    def on_token_insert(self, machine):
        self.update(machine, machine.regs[RSI], True)

    def on_drop(self, machine):
        self.expect(STACK_TOP - STACK_SIZE <= machine.regs[RDI] < STACK_TOP, "dropped set")

    def on_drop_next(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def node(self, layout, items, children=()):
        at = self.node_cur
        size = layout.edge_at + (0x60 if children else 0)
        self.node_cur += (size + 15) & ~15
        self.live[at] = size
        memory = self.machine.memory
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at, 8, 0)
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(len(items), 11):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, self.stale(layout))
        for slot, (key, value) in enumerate(items):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, key)
            if layout.val_size:
                memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        for slot, child in enumerate(children):
            memory.write(at + layout.edge_at + 8 * slot, 8, child)
            memory.write(child, 8, at)
            memory.write(child + layout.index_at, 2, slot)
        return at

    def stale(self, layout):
        """Unused key slots hold the key the case looks for, so a wrong length word finds it."""
        case = self.case
        if layout is L_TOP:
            return struct.pack("<Q", case.token)
        if layout is L_BLACK and case.users:
            return address(case.users[-1][0])
        return bytes(layout.key_size)

    def tree(self, layout, items):
        """Sorted items into a tree: one leaf up to 11 items, else leaves of 5 below one root."""
        items = sorted(items)
        if not items:
            return 0, 0xFEED, 0
        if len(items) <= 11:
            return self.node(layout, items), 0, len(items)
        parts, seps, at = [], [], 0
        while len(items) - at > 11:
            parts.append(items[at:at + 5])
            seps.append(items[at + 5])
            at += 6
        parts.append(items[at:])
        return self.node(layout, seps, [self.node(layout, part) for part in parts]), 1, len(items)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(0x100000)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.events = []
        self.live = {}
        self.sets = {}
        self.node_cur = NODES
        memory.statics[ONCE_WORD] = case.once
        memory.write(COUNT_AT, 8, case.count)
        tops = []
        for token, rec in sorted(case.state.items()):
            users = self.tree(L_USERS, [(key, struct.pack("<Q", wei)) for key, wei in rec[0].items()])
            tokens = self.tree(L_TOKENS, [(struct.pack("<Q", key), struct.pack("<Q", wei)) for key, wei in rec[1].items()])
            black = self.tree(L_BLACK, [(key, b"") for key in rec[2]])
            data = b"".join(struct.pack("<QQQ", *part) for part in (users, tokens, black))
            tops.append((struct.pack("<Q", token), data))
        root, height, count = self.tree(L_TOP, tops)
        memory.write(ROOT_AT, 8, root)
        memory.write(ROOT_AT + 8, 8, height)
        memory.write(ROOT_AT + 16, 8, count)
        self.fill_rows(case)
        self.fixture = dict(self.live)
        return bytes(memory.heap[:FILL_END])

    def fill_rows(self, case):
        memory = self.machine.memory
        if case.entry in (CAP_GATE, BLACK_GATE):
            for index, (user, _) in enumerate(case.users):
                memory.put_bytes(ROWS + USER_ROW * index, address(user))
            held = case.state.get(case.token, ({}, {}, []))[2]
            for index, key in enumerate(held):
                memory.put_bytes(ROWS + USER_ROW * (len(case.users) + index), key)
            for index, (token, wei) in enumerate(case.tokens):
                memory.write(ROWS_B + 0x20 * index, 8, token)
        elif case.entry == STORE_USERS:
            for index, (user, wei) in enumerate(case.users):
                memory.put_bytes(ROWS + 0x20 * index, address(user))
                memory.write(ROWS + 0x20 * index + 0x18, 8, wei)
        elif case.entry == STORE_TOKENS:
            for index, (token, wei) in enumerate(case.tokens):
                memory.write(ROWS + 0x10 * index, 8, token)
                memory.write(ROWS + 0x10 * index + 8, 8, wei)
        if case.black is not None:
            memory.write(VEC_AT, 8, len(case.black))
            memory.write(VEC_AT + 8, 8, ROWS_B)
            memory.write(VEC_AT + 16, 8, len(case.black))
            if case.entry == BLACK_SET:
                for index, (user, flag) in enumerate(case.black):
                    memory.put_bytes(ROWS_B + 21 * index, address(user) + bytes((flag,)))

    def walk(self, layout, root, height, want):
        memory = self.machine.memory
        items = []

        def visit(node, level):
            size = memory.read(node + layout.len_at, 2)
            self.expect(size <= 11, "node length")
            for slot in range(size + 1):
                if level:
                    child = memory.read(node + layout.edge_at + 8 * slot, 8)
                    self.expect(memory.read(child, 8) == node, "child parent link")
                    self.expect(memory.read(child + layout.index_at, 2) == slot, "child index")
                    visit(child, level - 1)
                if slot < size:
                    key = memory.bytes_at(node + layout.key_at + layout.key_size * slot, layout.key_size)
                    value = memory.bytes_at(node + layout.val_at + layout.val_size * slot, layout.val_size) if layout.val_size else b""
                    items.append((key, value))
        if root:
            visit(root, height)
        self.expect(len(items) == want, "stored length")
        self.expect([key for key, _ in items] == sorted(key for key, _ in items), "key order")
        return items

    def state_now(self):
        memory = self.machine.memory
        state = {}
        tops = self.walk(L_TOP, memory.read(ROOT_AT, 8), memory.read(ROOT_AT + 8, 8), memory.read(ROOT_AT + 16, 8))
        for key, data in tops:
            words = struct.unpack("<9Q", data)
            users = self.walk(L_USERS, *words[0:2], words[2])
            tokens = self.walk(L_TOKENS, *words[3:5], words[5])
            black = self.walk(L_BLACK, *words[6:8], words[8])
            state[struct.unpack("<Q", key)[0]] = ({k: struct.unpack("<Q", v)[0] for k, v in users}, {struct.unpack("<Q", k)[0]: struct.unpack("<Q", v)[0] for k, v in tokens}, {k for k, _ in black})
        return state

    def run(self, case):
        before = self.fresh(case)
        fixture = self.fixture
        machine = self.machine
        memory = machine.memory
        entry = case.entry
        machine.calls = dict(self.model_calls) if case.model else {RESUME: self.on_panic}
        machine.real = frozenset((entry,)) if case.model else RealCode.ALL
        try:
            if entry == CAP_GATE:
                memory.write(STACK_TOP - 0x100, 8, case.m)
                machine.run(entry, {RDI: OUT, RSI: S, RDX: case.token, RCX: ROWS, R8: case.n, R9: ROWS_B})
            elif entry == BLACK_GATE:
                memory.write(STACK_TOP - 0x100, 8, case.m)
                memory.write(STACK_TOP - 0xF8, 8, 0 if case.black is None else VEC_AT)
                machine.run(entry, {RDI: OUT, RSI: S, RDX: case.token, RCX: ROWS, R8: case.n})
            elif entry == STORE_USERS:
                machine.run(entry, {RDI: S, RSI: case.token, RDX: ROWS, RCX: len(case.users)})
            elif entry == STORE_TOKENS:
                machine.run(entry, {RDI: S, RSI: case.token, RDX: ROWS, RCX: len(case.tokens)})
            else:
                machine.run(entry, {RDI: S, RSI: case.token, RDX: VEC_AT})
        except Panicked as panic:
            return before, ("panic", str(panic), None, tuple(self.events), None, None)
        if entry in (CAP_GATE, BLACK_GATE):
            self.expect(self.live == fixture or case.model, "gates free what they allocate")
        now = bytes(memory.heap[:FILL_END])
        out = now[OUT - HEAP_BASE:OUT - HEAP_BASE + 24]
        low, high = ROOT_AT - HEAP_BASE, ROOT_AT - HEAP_BASE + 24
        self.expect(now[:OUT - HEAP_BASE] == before[:OUT - HEAP_BASE] and now[OUT - HEAP_BASE + 24:low] == before[OUT - HEAP_BASE + 24:low] and now[high:] == before[high:], "writes outside the result and the map head")
        return before, ("run", out, flat(self.state_now()), tuple(self.events), None, None)


class RealCode:
    ALL = frozenset()


def collect_real(image):
    """Every function reachable from the targets by direct calls; indirect calls stay hooked."""
    seen = set(TARGETS) | {image.relative()[SLOT_SORT]}
    todo = list(seen)
    while todo:
        for row in decode_range(image, *image.exact_fde(todo.pop())):
            if row.op == "call" and row.target not in seen and row.target != RESUME and row.target < 0x5660000:
                seen.add(row.target)
                todo.append(row.target)
    return frozenset(seen)


def same(got, want):
    return got[:4] == want[:4]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


U = [0x1000 + 16 * i for i in range(80)]
ONES = (1 << 160) - 1


def users(*indices, wei=5):
    return tuple((U[i], wei + i) for i in indices)


def rec(user_rows=(), token_rows=(), black=()):
    return ({address(u): w for u, w in user_rows}, dict(token_rows), [address(u) for u in black])


def cap_cases():
    C = CAP_GATE
    out = [
        Case("empty action, no record", C),
        Case("one user, no record", C, users=users(1)),
        Case("ten users, no record", C, users=users(*range(10))),
        Case("twelve users, no record", C, users=users(*range(12))),
        Case("token row in range", C, tokens=((3, 1),)),
        Case("two token rows", C, tokens=((3, 1), (4, 1))),
        Case("same token twice counts once", C, tokens=((3, 1), (3, 2))),
        Case("token at the last index", C, tokens=((63, 1),)),
        Case("token one past the count", C, tokens=((64, 1),)),
        Case("second token row out of range", C, tokens=((3, 1), (64, 1))),
        Case("record with users, new user", C, users=users(9), state={7: rec(users(1, 2))}),
        Case("record with users, same user", C, users=users(1), state={7: rec(users(1, 2))}),
        Case("record for another token only", C, users=users(1), state={8: rec(users(1, 2), ((1, 1), (2, 1), (3, 1)))}),
        Case("two stored tokens, same again", C, tokens=((1, 1),), state={7: rec((), ((1, 9), (2, 9)))}),
        Case("two stored tokens, a third", C, tokens=((3, 1),), state={7: rec((), ((1, 9), (2, 9)))}),
        Case("one stored token, two new", C, tokens=((3, 1), (4, 1)), state={7: rec((), ((1, 9),))}),
        Case("one stored token, one new", C, tokens=((3, 1),), state={7: rec((), ((1, 9),))}),
        Case("three stored tokens, no new", C, state={7: rec((), ((1, 9), (2, 9), (3, 9)))}),
        Case("three stored tokens, bad new", C, tokens=((64, 1),), state={7: rec((), ((1, 9), (2, 9), (3, 9)))}),
        Case("all-ones user alone", C, users=((ONES, 1),)),
        Case("all-ones user beside others", C, users=((ONES, 1),) + users(1)),
        Case("stored users deep tree", C, users=users(40), state={7: rec(users(*range(30)))}),
        Case("list count above limit", C, n=10001, m=0),
        Case("list count well above limit", C, n=1 << 40, m=0),
        Case("token rows above limit", C, m=3, tokens=((1, 1), (2, 1), (3, 1))),
        Case("token rows far above limit", C, m=1 << 40, n=0),
        Case("both above limit", C, n=10001, m=3, tokens=((64, 1), (1, 1), (1, 1))),
        Case("bad token row beyond the row limit", C, tokens=((64, 1), (64, 1), (64, 1))),
        Case("token count zero", C, tokens=((0, 1),), count=0),
        Case("token zero at count one", C, tokens=((0, 1),), count=1),
        Case("deep outer map, stored token", C, token=30, users=users(1), state={t: rec() for t in range(0, 60, 2)}),
        Case("deep outer map, no record", C, token=31, users=users(1), state={t: rec() for t in range(0, 60, 2)}),
        Case("deep outer map, three stored tokens", C, token=30, state={t: rec((), ((1, 1), (2, 1), (3, 1))) if t == 30 else rec() for t in range(0, 60, 2)}),
    ]
    M = dict(model=True)
    out += [
        Case("exactly at limit, one new", C, users=users(1), seed_users=9999, **M),
        Case("one above limit by one new", C, users=users(1), seed_users=10000, **M),
        Case("at limit, repeat of stored", C, users=((U[2], 1),), seed_users=9999, state={7: rec(users(2))}, **M),
        Case("at limit, all-ones row does not count", C, users=((ONES, 1),), seed_users=10000, **M),
        Case("seeded all-ones does not count", C, keep_seeded=True, seed_users=10000, **M),
        Case("seeded all-ones with one more", C, keep_seeded=True, users=users(1), seed_users=10000, **M),
        Case("over limit hides a bad token", C, users=users(1), seed_users=10000, tokens=((64, 1),), **M),
        Case("at limit with token rows", C, users=users(1), seed_users=9999, tokens=((1, 1), (2, 1)), **M),
        Case("seeded tokens two, new one", C, tokens=((1, 1),), seed_tokens=2, **M),
        Case("seeded tokens one, new one", C, tokens=((1, 1),), seed_tokens=1, **M),
        Case("seeded tokens three", C, seed_tokens=3, **M),
        Case("model empty", C, **M),
        Case("list of 10000 rows", C, users=tuple((0x100000 + i, 1) for i in range(10000)), **M),
        Case("stored users reach the collector", C, users=users(9), state={7: rec(users(1, 2, 3), ((1, 1),))}, **M),
        Case("stored tokens reach the collector", C, tokens=((5, 1),), state={7: rec((), ((1, 1), (2, 1)))}, **M),
        Case("model list count above limit", C, n=10001, m=0, **M),
    ]
    return out


def black_cases():
    C = BLACK_GATE
    held = {7: rec(users(1), (), (0x1000 + 16 * 2, 0x1000 + 16 * 5))}
    deep = {7: rec((), (), [U[i] for i in range(30)])}
    return [
        Case("no list, no rows, no record", C),
        Case("no list, rows, no record", C, users=users(2)),
        Case("no list, record without blacklist", C, users=users(2), state={7: rec(users(1))}),
        Case("no list, other token holds the user", C, users=users(2), state={8: held[7]}),
        Case("no list, first row held", C, users=users(2, 3), state=held),
        Case("no list, last row held", C, users=users(3, 4, 5), state=held),
        Case("no list, not held", C, users=users(3, 4), state=held),
        Case("no list, key below the first", C, users=((1, 1),), state=held),
        Case("no list, key above the last", C, users=users(70), state=held),
        Case("no list, deep tree first", C, users=users(0), state=deep),
        Case("no list, deep tree separator", C, users=users(5), state=deep),
        Case("no list, deep tree last", C, users=users(29), state=deep),
        Case("no list, deep tree miss", C, users=((U[29] + 1, 1),), state=deep),
        Case("no list, token rows only", C, tokens=((1, 1),), state=held),
        Case("no list, no rows, record held", C, state=held),
        Case("list empty", C, black=()),
        Case("list one", C, black=((U[1], 1),)),
        Case("list at 1000", C, black=((U[1], 1),) * 1000),
        Case("list at 1001", C, black=((U[1], 1),) * 1001),
        Case("list at 1001 with rows", C, black=((U[1], 1),) * 1001, users=users(1)),
        Case("list with user rows", C, black=((U[1], 1),), users=users(1)),
        Case("list with token rows", C, black=((U[1], 1),), tokens=((1, 1),)),
        Case("empty list with user rows", C, black=(), users=users(1)),
        Case("empty list with token rows", C, black=(), tokens=((1, 1),)),
        Case("list skips the held scan", C, black=(), state=held),
        Case("high bits of the user count", C, black=(), n=1 << 40),
        Case("high bits of the token count", C, black=(), m=1 << 40),
        Case("empty list with record", C, black=((U[9], 0),), state=held),
        Case("deep outer map, stored token", C, token=30, users=users(2), state={t: rec((), (), (U[2],)) for t in range(0, 60, 2)}),
        Case("deep outer map, no record", C, token=31, users=users(2), state={t: rec((), (), (U[2],)) for t in range(0, 60, 2)}),
    ]


def store_cases():
    A, B = STORE_USERS, STORE_TOKENS
    out = [
        Case("no rows, no record", A),
        Case("one row, new record", A, users=users(1)),
        Case("one row, record for other token", A, users=users(1), state={8: rec(users(2))}),
        Case("record exists, new user", A, users=users(2), state={7: rec(users(1))}),
        Case("record exists, smaller token present", A, users=users(2), state={6: rec(users(5)), 7: rec(users(1)), 9: rec()}),
        Case("repeat in the rows keeps the last", A, users=((U[1], 5), (U[1], 9))),
        Case("overwrite with another amount", A, users=((U[1], 9),), state={7: rec(((U[1], 5),))}),
        Case("overwrite with the same amount", A, users=((U[1], 5),), state={7: rec(((U[1], 5),))}),
        Case("overwrite with another amount, once word set", A, once=1, users=((U[1], 9),), state={7: rec(((U[1], 5),))}),
        Case("overwrite with the same amount, once word set", A, once=1, users=((U[1], 5),), state={7: rec(((U[1], 5),))}),
        Case("new user, once word set", A, once=1, users=users(1)),
        Case("zero amount kept", A, users=((U[1], 0),)),
        Case("maximum amount kept", A, users=((U[1], TOP),)),
        Case("twelve rows split a leaf", A, users=users(*range(12))),
        Case("twenty rows in reverse", A, users=users(*range(19, -1, -1))),
        Case("deep user tree", A, users=users(50, 3), state={7: rec(users(*range(0, 40)))}),
        Case("deep token map, new token", A, token=70, users=users(1), state={t: rec() for t in range(0, 60, 2)}),
        Case("deep token map, stored token", A, token=30, users=users(1), state={t: rec() for t in range(0, 60, 2)}),
        Case("full leaf of the token map", A, token=5, users=users(1), state={t: rec() for t in range(10, 21)}),
        Case("no token rows, no record", B),
        Case("one token row, new record", B, tokens=((3, 8),)),
        Case("token row, record exists", B, tokens=((3, 8),), state={7: rec((), ((1, 2),))}),
        Case("token repeat keeps the last", B, tokens=((3, 8), (3, 9))),
        Case("token overwrite", B, tokens=((3, 8),), state={7: rec((), ((3, 2),))}),
        Case("token overwrite same", B, tokens=((3, 2),), state={7: rec((), ((3, 2),))}),
        Case("token overwrite, once word set", B, once=1, tokens=((3, 8),), state={7: rec((), ((3, 2),))}),
        Case("token overwrite same, once word set", B, once=1, tokens=((3, 2),), state={7: rec((), ((3, 2),))}),
        Case("deep token rows", B, tokens=tuple((i, i + 1) for i in range(25))),
        Case("deep outer map", B, token=70, tokens=((1, 1),), state={t: rec() for t in range(0, 60, 2)}),
        Case("smaller key in record", B, token=9, tokens=((1, 1),), state={3: rec(), 9: rec((), ((5, 5),)), 12: rec()}),
    ]
    return out


def black_set_cases():
    C = BLACK_SET
    many = {7: rec(users(*range(20)), ((1, 1),), [U[i] for i in range(30, 50)])}
    return [
        Case("empty list, no record", C, black=()),
        Case("empty list, record", C, black=(), state={7: rec(users(1))}),
        Case("add, no record", C, black=((U[1], 1),)),
        Case("add, record without the user", C, black=((U[1], 1),), state={7: rec(users(2))}),
        Case("add drops the balance row", C, black=((U[1], 1),), state={7: rec(users(1, 2))}),
        Case("add last balance row", C, black=((U[1], 1),), state={7: rec(users(1))}),
        Case("add twice", C, black=((U[1], 1), (U[1], 1)), state={7: rec(users(1))}),
        Case("remove, no record", C, black=((U[1], 0),)),
        Case("remove held", C, black=((U[1], 0),), state={7: rec((), (), (U[1], U[2]))}),
        Case("remove keeps the balance row", C, black=((U[1], 0),), state={7: rec(users(1), (), (U[1],))}),
        Case("add then remove", C, black=((U[1], 1), (U[1], 0)), state={7: rec(users(1))}),
        Case("remove then add", C, black=((U[1], 0), (U[1], 1)), state={7: rec(users(1), (), (U[1],))}),
        Case("flag two counts as add", C, black=((U[1], 2),), state={7: rec(users(1))}),
        Case("flag 255 counts as add", C, black=((U[1], 255),)),
        Case("add in deep trees", C, black=((U[5], 1), (U[70], 1)), state=many),
        Case("remove in deep trees", C, black=((U[35], 0), (U[71], 0)), state=many),
        Case("existing token rows stay", C, black=((U[1], 1),), state={7: rec(users(1), ((3, 4),))}),
        Case("other token untouched", C, black=((U[1], 1),), state={7: rec(), 8: rec(users(1))}),
        Case("twelve adds", C, black=tuple((U[i], 1) for i in range(12))),
        Case("deep outer map", C, token=70, black=((U[1], 1),), state={t: rec() for t in range(0, 60, 2)}),
    ]


def named_cases():
    return cap_cases() + black_cases() + store_cases() + black_set_cases()


def vector_cases(count):
    source = lcg(0x5EED15)
    pick = lambda limit: next(source) % limit
    out = []
    for index in range(count):
        state = {}
        for token in range(pick(4)):
            key = 5 + pick(6)
            state[key] = rec(users(*{pick(16) for _ in range(pick(14))}), tuple((pick(5), 1 + pick(9)) for _ in range(pick(4))), [U[pick(16)] for _ in range(pick(6))])
        token = 5 + pick(6)
        kind = pick(5)
        rows = tuple((U[pick(16)], pick(4)) for _ in range(pick(7)))
        toks = tuple((pick(8) if pick(4) else 64 + pick(3), pick(4)) for _ in range(pick(4)))
        name = "vector %d" % index
        if kind == 0:
            case = Case(name, CAP_GATE, token=token, users=rows, tokens=toks, state=state)
        elif kind == 1:
            black = None if pick(2) else tuple((U[pick(16)], pick(2)) for _ in range(pick(4)))
            case = Case(name, BLACK_GATE, token=token, users=rows, tokens=toks, black=black, state=state)
        elif kind == 2:
            case = Case(name, STORE_USERS, token=token, users=rows, state=state)
        elif kind == 3:
            case = Case(name, STORE_TOKENS, token=token, tokens=toks, state=state)
        else:
            case = Case(name, BLACK_SET, token=token, black=tuple((U[pick(16)], pick(3)) for _ in range(pick(9))), state=state)
        out.append(case)
    return out


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before)
        if not same(got, want):
            raise EvidenceError("case disagrees with the rule list: %s" % case.name + diff_text(got, want))
        outcomes.append((got, want[5]))
    return outcomes


def diff_text(got, want):
    return " got %r want %r" % (got[:4], want[:4])


def text_at(image, arm):
    start = image.offset(arm)
    data = bytes(image.blob[start:start + 40])
    at = data.find(b"\x48\x8d\x35")
    if at < 0 or data[at + 7] != 0xBA:
        return ""
    target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    size = struct.unpack_from("<I", data, at + 8)[0]
    return bytes(image.blob[image.offset(target):image.offset(target) + size]).decode()


def arm_of(image, table, index):
    return table + struct.unpack_from("<i", image.blob, image.offset(table) + 4 * index)[0]


def text_rows(image):
    rows = []
    for name, (at, size) in sorted(TEXTS.items()):
        rows.append((name, "%#x" % at, size, bytes(image.blob[image.offset(at):image.offset(at) + size]).decode()))
    rows.append(("tag_0xea", "-", 0, text_at(image, arm_of(image, TEXT_TABLE, TAG_TOKEN))))
    return rows


def serde_rows(image):
    blob = bytes(image.blob)
    rows = []
    for text in SERDE:
        at = blob.find(text)
        if at < 0:
            raise EvidenceError("no serde text")
        rows.append(("%#x" % at, text.decode()))
    return rows


def constant_rows(image):
    data = bytes(image.blob[image.offset(KEEP_AT):image.offset(KEEP_AT) + 20])
    if data != KEEP_ADDRESS:
        raise EvidenceError("kept address bytes")
    return [("%#x" % KEEP_AT, data.hex())]


def slot_rows(image):
    relative = image.relative()
    text = image.text_bytes()
    base = image.exact_fde(CAP_GATE)[0] - bytes(image.blob).find(bytes(image.blob[image.offset(CAP_GATE):image.offset(CAP_GATE) + 64])) + image.offset(CAP_GATE) - image.offset(CAP_GATE)
    rows = []
    start = image.offset(CAP_GATE)
    delta = CAP_GATE - start
    blob = bytes(image.blob)
    for target in TARGETS:
        slot = SLOTS[target]
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        holders = sorted(at for at, value in relative.items() if value == target)
        sites = []
        pos = blob.find(b"\xff\x15", 0x1000000)
        while pos >= 0 and pos < 0x5700000:
            va = pos + delta
            if va + 6 + struct.unpack_from("<i", blob, pos + 2)[0] == slot:
                sites.append(va)
            pos = blob.find(b"\xff\x15", pos + 2)
        rows.append(("%#x" % target, NAMES[target], "%#x" % slot, " ".join("%#x" % at for at in holders), len(sites), " ".join("%#x" % at for at in sites)))
    return rows


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


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
            before, got = harness.run(case)
            if not same(got, spec_run(case, before)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


BACK_CURSOR = "same: back cursor word of a drop iterator; the drop walks forward only and never reads it"
DEAD_WORD = "same: no later row reads this word on the path without a record"
ZERO_ROOT = "same: both edges reach a test of the zero root and leave together"
HANDLE_HEIGHT = "same: height word of a vacant entry handle; the insert always starts at a leaf and never reads it"
EXPECTED_SURVIVORS = {}
for _rows, _kind, _text in (
        ((0x371F571, 0x371F615, 0x372002A, 0x372008A, 0x37200A6), "immediate", BACK_CURSOR),
        ((0x371FED9, 0x371FEE1), "immediate", DEAD_WORD),
        ((0x371FEEF,), "condition", ZERO_ROOT),
        ((0x3721349, 0x3721674), "immediate", HANDLE_HEIGHT)):
    for _row in _rows:
        EXPECTED_SURVIVORS[_row, _kind] = _text


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    groups = collections.defaultdict(list)
    for case in cases:
        groups[case.entry].append(case)
    extra = vector_cases(200)
    for target in TARGETS:
        chosen = groups[target] + [case for case in extra if case.entry == target]
        reach = collections.defaultdict(list)
        for case in chosen:
            control.machine.seen = set()
            control.run(case)
            for va in control.machine.seen:
                reach[va].append(case)
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, reach[va])
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results



def analyse(image, mutate=True, vectors=300):
    RealCode.ALL = collect_real(image) | {CAP_GATE}
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, texts=text_rows(image), serde=serde_rows(image), constants=constant_rows(image), slots=slot_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    got, label = outcome
    return "%#x" % case.entry, case.name, label, hashlib.sha256(repr((got[0], got[1], got[2], got[3])).encode()).hexdigest()[:16], len(got[3])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("texts.tsv", ("name", "address", "size", "text"), result["texts"])
    tsv("serde.tsv", ("file_offset", "text"), result["serde"])
    tsv("constants.tsv", ("address", "bytes"), result["constants"])
    tsv("slots.tsv", ("function", "name", "slot", "relative_slots", "ff15_sites", "sites"), result["slots"])
    tsv("outcomes.tsv", ("entry", "case", "result", "digest", "events"), [describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
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

