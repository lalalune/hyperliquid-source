#!/usr/bin/env python3
"""Pin node #94 read precompile gas: one length cap and one gas rule across twelve precompiles.

Each function is found from its 20 byte address constant. The real rows from the entry to the input decoder call
run under a recording memcmp with real B-tree fixtures, a separate rule list predicts every outcome, and every
reached conditional row, immediate and field offset is mutated. The final gas form is read from rows and bytes.
No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/read_precompile_gas.py --out <dir>
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


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


SLOT_MEMCMP = 0x576E488
MARK_BASE = 0x7700000000
MARK_MEMCMP = MARK_BASE + 1

TOP = MASK[8]
LENGTH_CAP = 2000
GAS_BASE = 1000
GAS_PER_BYTE = 33
DOC_BASE = 2000
DOC_PER_BYTE = 65
ADDRESS_LOW = 0x800
ADDRESS_HIGH = 0x813
# Named here by number only: their functions are subjects or caller rows of other packets, so this packet reads no bytes of them.
OUT_OF_SCOPE = (0x802, 0x803, 0x806, 0x807, 0x808, 0x80A, 0x80E, 0x80F)
EXPECTED_ADDRESSES = 20
LABEL_AT = 0x58251C
LABEL = b"utils::abi_decode_raw"

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x28
CTX = HEAP_BASE + 0x300
SET_ROOT = HEAP_BASE + 0x600
INPUT = HEAP_BASE + 0x780
INPUT_DATA = HEAP_BASE + 0x7A0
SET_NODES = HEAP_BASE + 0x900
SET_NODE_STRIDE = 0x100
USED = 0x1000
SET_KEY_AT = 8
SET_LEN = 0xE6
SET_EDGE_AT = 0xE8


class Reached(Exception):
    """The run got past every gate and called the input decoder."""

    def __init__(self, target, regs):
        Exception.__init__(self)
        self.target, self.regs = target, regs


class Case:
    __slots__ = ("name", "keys", "set_shape", "n", "gas")

    def __init__(self, name, keys=(), set_shape="absent", n=32, gas=10 ** 6):
        self.name, self.keys, self.set_shape, self.n, self.gas = name, keys, set_shape, n, gas


def rip_lea_sites(image):
    """(site, target) for every rip relative 64 bit lea in .text, read as bytes."""
    va, text = image.text_bytes()
    for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text):
        at = match.start()
        if at + 7 <= len(text):
            yield va + at, va + at + 7 + struct.unpack_from("<i", text, at + 3)[0]


def address_constants(image):
    """Rodata offsets of the 20 byte constants 0x800 to 0x813."""
    section = image.named[".rodata"]
    data = bytes(image.blob[section["offset"]:section["offset"] + section["size"]])
    found = {}
    for match in re.finditer(rb"\x00{18}\x08[\x00-\x13]", data):
        found[section["address"] + match.start()] = int.from_bytes(match[0], "big")
    return found


def family(image):
    """Map each precompile number to the FDE that loads its constant."""
    constants = address_constants(image)
    numbers = sorted(set(constants.values()))
    if len(numbers) != EXPECTED_ADDRESSES or numbers[0] != ADDRESS_LOW or numbers[-1] != ADDRESS_HIGH:
        raise EvidenceError("address constants moved")
    owners = {}
    for site, target in rip_lea_sites(image):
        if target in constants:
            owners.setdefault(constants[target], []).append((site, target))
    if sorted(owners) != numbers:
        raise EvidenceError("a precompile has no loader")
    rows = []
    for number in numbers:
        if len(owners[number]) != 1:
            raise EvidenceError("two loaders for %#x" % number)
        site, target = owners[number][0]
        if number not in OUT_OF_SCOPE:
            start, end = image.fde(site)
            rows.append(dict(number=number, start=start, end=end, lea=site, const=target))
    return numbers, rows


def rows_to(image, start, stop):
    """Decode rows from a function start up to an address."""
    rows = []
    reader = Machine(image).read_code
    pc = start
    while pc < stop:
        row = decode(reader, pc)
        rows.append(row)
        pc = row.next
    return rows


def imm_of(row):
    for operand in (row.a, row.b):
        if operand and operand[0] == "i":
            return operand[1]
    return None


def reg_of(operand):
    return operand[1] if operand and operand[0] == "r" else None


def writes(row, reg):
    return row.a is not None and row.a[0] == "r" and row.a[1] == reg and row.op not in ("cmp", "test", "push")


def gate_shape(image, entry):
    """Find the cap, base and decoder rows of one function by walking from its entry."""
    rows = rows_to(image, entry["start"], min(entry["end"], entry["start"] + 0x280))
    cap = next(row for row in rows if row.op == "cmp" and imm_of(row) == LENGTH_CAP)
    length = reg_of(cap.a)
    after = [row for row in rows if row.va > cap.va]
    shift = next(row for row in after if row.op == "shl" and imm_of(row) == 5)
    base = next(row for row in after if row.op == "add" and imm_of(row) == GAS_BASE)
    decoder = next(row for row in after if row.op == "call" and row.va > base.va)
    entry.update(cap=cap.va, shift=shift.va, base=base.va, base_reg=reg_of(base.a), length_reg=length, shift_reg=reg_of(shift.a), decoder=decoder.target, decoder_site=decoder.va)
    return rows


def slot_stores(data):
    """Map each rsp displacement to the source registers of 64 bit stores there, from both displacement forms."""
    stores = {}
    for match in re.finditer(rb"([\x48\x4c])\x89([\x44\x4c\x54\x5c\x64\x6c\x74\x7c])\x24(.)", data, re.S):
        stores.setdefault(match[3][0], []).append(match[2][0] >> 3 & 7 | (8 if match[1][0] & 4 else 0))
    for match in re.finditer(rb"([\x48\x4c])\x89([\x84\x8c\x94\x9c\xa4\xac\xb4\xbc])\x24(....)", data, re.S):
        stores.setdefault(struct.unpack("<I", match[3])[0], []).append(match[2][0] >> 3 & 7 | (8 if match[1][0] & 4 else 0))
    return stores


def only_store_slots(data, register):
    """Stack slots whose single store in the function comes from this register."""
    return {slot for slot, sources in slot_stores(data).items() if sources == [register]}


def clean_path(image, entry, start, stop, registers, restores=()):
    """Walk every path from start to stop; refuse when a row on such a path leaves a register changed."""
    reader = Machine(image).read_code
    stack = [(start, False)]
    visited = set()
    reached = False
    while stack:
        pc, dirty = stack.pop()
        if (pc, dirty) in visited:
            continue
        visited.add((pc, dirty))
        if pc == stop:
            if dirty:
                raise EvidenceError("register changed before %#x in %#x" % (stop, entry["number"]))
            reached = True
            continue
        if not entry["start"] <= pc < entry["end"]:
            continue
        try:
            row = decode(reader, pc)
        except (Halt, EvidenceError, IndexError, KeyError):
            continue
        if row.op in ("ret", "int3", "jmpi"):
            continue
        after = dirty or any(writes(row, register) for register in registers)
        if row.op == "mov" and row.b and row.b[0] == "m" and row.b[1] == RSP and row.b[4] in restores and reg_of(row.a) in registers:
            after = False
        if row.op == "jmp":
            stack.append((row.target, after))
        elif row.op == "jcc":
            stack.append((row.target, after))
            stack.append((row.next, after))
        else:
            stack.append((row.next, after))
    if not reached:
        raise EvidenceError("no path to %#x in %#x" % (stop, entry["number"]))


def runtime_sum(image, entry, site):
    """Check `mov $33,edx; mov len,rax; mul; jo; add rax,Y; mov $-1,rax; cmovae; cmovae; cmp; jbe`, with Y the base gate sum."""
    rows = rows_to(image, site, site + 56)
    names = [row.op for row in rows]
    if names[0] != "mov" or names[2] != "mul":
        raise EvidenceError("no multiply at %#x" % site)
    at = 3 + (names[3] == "mov")
    jump, add, top, one, two, compare, branch = rows[at:at + 7]
    if (jump.op, jump.cc) != ("jcc", 0) or add.op != "add" or reg_of(add.b) != RAX or imm_of(top) != TOP & -1 and imm_of(top) != -1:
        raise EvidenceError("unknown runtime gas shape at %#x" % site)
    if (one.op, two.op, compare.op, branch.op) != ("cmov", "cmov", "cmp", "jcc") or reg_of(compare.a) != RAX or compare.b[0] != "m":
        raise EvidenceError("unknown runtime gas tail at %#x" % site)
    if {one.cc, two.cc, branch.cc} != {3, 6} or one.cc != 3 or two.cc != 3 or branch.cc != 6:
        raise EvidenceError("unknown runtime gas conditions at %#x" % site)
    target = reg_of(add.a)
    base = entry["base_reg"]
    next_row = decode(Machine(image).read_code, entry["decoder_site"]).next
    data = bytes(image.blob[image.offset(entry["start"]):image.offset(entry["end"])])
    if target == base:
        # Stores before the decoder call belong to the gate, so only later stores can feed a reload on these paths.
        slots = only_store_slots(data[entry["decoder_site"] - entry["start"]:], base)
        clean_path(image, entry, next_row, rows[0].va, (base,), slots)
        return "base gate register"
    prefix = 0x48 | (4 if base >= 8 else 0) | (1 if target >= 8 else 0)
    copy = bytes((prefix, 0x89, 0xC0 | (base & 7) << 3 | (target & 7)))
    sites = [entry["start"] + match.start() for match in re.finditer(re.escape(copy), data) if entry["start"] + match.start() > entry["decoder_site"]]
    for found in sites:
        try:
            clean_path(image, entry, next_row, found, (base,))
            clean_path(image, entry, found + 3, rows[0].va, (target,))
        except EvidenceError:
            continue
        return "copy of the base gate register at %#x" % found
    return stack_source(entry, data, site, base, target)


def stack_source(entry, data, site, base, target):
    """Accept a reload of one stack slot when the base gate register is the only value ever stored there."""
    start = entry["start"]
    load = bytes((0x48 | (4 if target >= 8 else 0), 0x8B, 0x84 | (target & 7) << 3, 0x24))
    near = [match.start() for match in re.finditer(re.escape(load) + rb"(....)", data, re.S) if 0 < site - (start + match.start()) < 0x100]
    slots = {struct.unpack_from("<I", data, at + 4)[0] for at in near}
    if len(slots) != 1:
        raise EvidenceError("sum register has no base gate source in %#x" % entry["number"])
    slot = slots.pop()
    tail = re.escape(bytes((0x24,)) + struct.pack("<I", slot))
    stores = [match for match in re.finditer(rb"[\x48\x49\x4c\x4d]\x89[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]" + tail, data)]
    want = bytes((0x48 | (4 if base >= 8 else 0), 0x89, 0x84 | (base & 7) << 3))
    if len(stores) != 1 or stores[0][0][:3] != want:
        raise EvidenceError("stack slot of the sum has other stores in %#x" % entry["number"])
    return "stack slot +%#x stored once from the base gate register at %#x" % (slot, start + stores[0].start())


def final_shape(image, entry):
    """Read the final gas form: `add imm,N` after `add S,N`, or `mov $33,edx; mul`."""
    data = bytes(image.blob[image.offset(entry["start"]):image.offset(entry["end"])])
    base = entry["start"]
    runtime = [base + match.start() for match in re.finditer(rb"\xba\x21\x00\x00\x00", data)]
    length, shift = entry["length_reg"], entry["shift_reg"]
    prefix = 0x48 | (4 if shift >= 8 else 0) | (1 if length >= 8 else 0)
    pair = bytes((prefix, 0x01, 0xC0 | (shift & 7) << 3 | (length & 7)))
    folds = [base + match.start() for match in re.finditer(re.escape(pair), data) if base + match.start() > entry["decoder_site"]]
    fixed = []
    for match in re.finditer(bytes((0x49 if length >= 8 else 0x48, 0x81, 0xC0 | (length & 7))) + rb"(....)", data, re.S):
        site = base + match.start()
        value = struct.unpack("<I", match[1])[0]
        if site > entry["decoder_site"] and value < 1 << 20:
            fixed.append((site, value))
    if runtime and not fixed:
        if len(runtime) != 1:
            raise EvidenceError("two output multiplies in %#x" % entry["number"])
        entry.update(form="runtime", final=runtime[0], final_value=GAS_PER_BYTE, output=None, sum_reg=runtime_sum(image, entry, runtime[0]))
        return
    if len(fixed) != 1 or len(folds) != 1 or runtime:
        raise EvidenceError("unknown fixed gas shape in %#x: %s %s %s" % (entry["number"], fixed, folds, runtime))
    site, value = fixed[0]
    # Calls keep these callee-saved registers by the ABI, so only rows in this function can change them.
    next_row = decode(Machine(image).read_code, entry["decoder_site"]).next
    clean_path(image, entry, next_row, folds[0], (length, shift))
    clean_path(image, entry, folds[0] + 3, site, (length,))
    size = (value - GAS_BASE) // GAS_PER_BYTE
    if (value - GAS_BASE) % GAS_PER_BYTE or size % 32:
        raise EvidenceError("constant is not 1000 + 33 words in %#x" % entry["number"])
    if struct.pack("<BI", 0xBF, size) not in data:
        raise EvidenceError("no allocation of the output size in %#x" % entry["number"])
    entry.update(form="fixed", final=site, final_value=value, output=size, fold=folds[0])


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.memory.statics[SLOT_MEMCMP] = MARK_MEMCMP
        machine.slots[MARK_MEMCMP] = self.on_memcmp
        self.entry = None

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_memcmp(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 20, "memcmp length")
        self.expect(regs[RDI] == self.entry["const"], "memcmp left side")
        left = machine.memory.bytes_at(regs[RDI], 20)
        right = machine.memory.bytes_at(regs[RSI], 20)
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def on_decoder(self, machine):
        regs = machine.regs
        for pointer, size in ((RCX, R8), (RDX, RCX)):
            if regs[pointer] == LABEL_AT:
                self.expect(regs[size] == len(LABEL), "decoder label length")
                self.expect(machine.memory.bytes_at(LABEL_AT, len(LABEL)) == LABEL, "decoder label text")
        raise Reached(self.entry["decoder"], list(regs))

    def set_node(self, at, keys, children=(), stale=None):
        memory = self.machine.memory
        memory.write(at + SET_LEN, 2, len(keys))
        for slot in range(11):
            key = keys[slot] if slot < len(keys) else (stale if stale is not None else 0xFFFFFF00 + slot)
            memory.put_bytes(at + SET_KEY_AT + 20 * slot, key.to_bytes(20, "big"))
        for slot, child in enumerate(children):
            memory.write(at + SET_EDGE_AT + 8 * slot, 8, child)

    def set_state(self, case, number):
        memory = self.machine.memory
        if case.set_shape == "absent":
            memory.write(SET_ROOT, 8, 0)
            memory.write(SET_ROOT + 8, 8, 0xFEED)
            return
        keys = sorted(number + offset for offset in case.keys)
        if case.set_shape == "leaf":
            self.set_node(SET_NODES, keys, stale=number)
            memory.write(SET_ROOT, 8, SET_NODES)
            memory.write(SET_ROOT + 8, 8, 0)
            return
        left, right = SET_NODES + SET_NODE_STRIDE, SET_NODES + 2 * SET_NODE_STRIDE
        if case.set_shape == "deep left":
            self.set_node(left, keys, stale=number)
            self.set_node(right, [number + 8], stale=number)
            self.set_node(SET_NODES, [number + 5], (left, right))
        else:
            self.set_node(left, [number - 3, number - 2], stale=number)
            self.set_node(right, keys, stale=number)
            self.set_node(SET_NODES, [number - 1], (left, right))
        memory.write(SET_ROOT, 8, SET_NODES)
        memory.write(SET_ROOT + 8, 8, 1)

    def run(self, entry, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000)))
        memory.write(CTX + 0x38, 8, SET_ROOT)
        memory.write(INPUT + 8, 8, INPUT_DATA)
        memory.write(INPUT + 0x10, 8, case.n)
        self.set_state(case, entry["number"])
        self.entry = entry
        machine.calls = {entry["decoder"]: self.on_decoder}
        before = bytes(memory.heap[:USED])
        try:
            value = machine.run(entry["start"], {RDI: OUT, RSI: CTX, RDX: INPUT, RCX: case.gas})
        except Reached as stop:
            after = bytes(memory.heap[:USED])
            return before, ("reached", after, stop.target, input_arguments(stop.regs, case.n))
        if value != OUT:
            raise Halt("result pointer")
        return before, ("returned", bytes(memory.heap[:USED]), None, None)


def input_arguments(regs, n):
    """Which argument registers hold the input pointer and its length when the decoder is called."""
    if regs[RDI] == INPUT_DATA and regs[RSI] == n:
        return "rdi,rsi"
    if regs[RSI] == INPUT_DATA and regs[RDX] == n:
        return "rsi,rdx"
    return "other"


def gas_in(n):
    return GAS_BASE + GAS_PER_BYTE * n


def spec_run(entry, case, before):
    hit = case.set_shape != "absent" and 0 in case.keys
    if hit or case.n > LENGTH_CAP or gas_in(case.n) > case.gas:
        state = bytearray(before)
        state[OUT - HEAP_BASE:OUT - HEAP_BASE + 24] = bytes(16) + struct.pack("<Q", 1 << 63)
        return ("returned", bytes(state), None, None)
    return ("reached", before, entry["decoder"], None)


def same(got, want):
    return got[:3] == want[:3] and (got[0] != "reached" or got[3] in ("rdi,rsi", "rsi,rdx"))


def named_cases():
    out = []
    add = out.append
    for shape in ("leaf", "deep", "deep left"):
        add(Case("blocked " + shape, keys=(0, 1), set_shape=shape))
        add(Case("other keys " + shape, keys=(1, 2), set_shape=shape))
        add(Case("lower key " + shape, keys=(-1,), set_shape=shape))
    add(Case("blocked last", keys=(-2, -1, 0), set_shape="leaf"))
    add(Case("blocked middle", keys=(-1, 0, 1), set_shape="leaf"))
    add(Case("empty node", keys=(), set_shape="leaf"))
    add(Case("full node above", keys=tuple(1 + index for index in range(11)), set_shape="leaf"))
    add(Case("full node below", keys=tuple(index - 11 for index in range(11)), set_shape="leaf"))
    for n in (0, 1, 32, 1999, 2000, 2001, 2002, 4000, 1 << 20, 1 << 59, 1 << 63, TOP):
        add(Case("length %d" % n, n=n, gas=TOP))
    for n in (0, 4, 32, 2000):
        base = gas_in(n)
        for gas in (0, base - 1, base, base + 1):
            add(Case("gas %d %d" % (n, gas), n=n, gas=gas))
    return out


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state


def vector_cases(count):
    stream = lcg(0x800)
    cases = []
    for index in range(count):
        n = next(stream) % 2100
        gas = gas_in(n) + next(stream) % 3 - 1
        cases.append(Case("vector %d" % index, n=n, gas=gas))
    return cases


def check_all(harness, entries, cases):
    outcomes = []
    for entry in entries:
        counts = collections.Counter()
        forms = set()
        for case in cases:
            before, got = harness.run(entry, case)
            want = spec_run(entry, case, before)
            if not same(got, want):
                raise EvidenceError("case disagrees with the rule list: %#x %s %r" % (entry["number"], case.name, got[0]))
            counts[got[0]] += 1
            if got[3]:
                forms.add(got[3])
        outcomes.append((entry, counts, sorted(forms)))
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


def first_failure(harness, entry, cases):
    for case in cases:
        try:
            before, got = harness.run(entry, case)
            if not same(got, spec_run(entry, case, before)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error):
            return case
    return None


EXPECTED_SURVIVORS = {}


def run_mutants(image, entries, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    for entry in entries:
        if first_failure(control, entry, cases) is not None:
            raise EvidenceError("an unedited image fails under the mutant step limit")
    for entry in entries:
        rows = [row for row in rows_to(image, entry["start"], entry["decoder_site"])]
        for va, kind, patch in edits_for(image, rows, seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(harness, entry, cases)
            if hit is not None:
                results.append((entry["number"], va, kind, "killed", hit.name))
            else:
                results.append((entry["number"], va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=60):
    numbers, entries = family(image)
    for entry in entries:
        gate_shape(image, entry)
        final_shape(image, entry)
    harness = Harness(image)
    cases = named_cases() + vector_cases(vectors)
    outcomes = check_all(harness, entries, cases)
    result = dict(numbers=numbers, entries=entries, cases=cases, outcomes=outcomes, vector_count=vectors)
    if mutate:
        result["mutations"] = run_mutants(image, entries, set(harness.machine.seen), cases)
        unexplained = [row for row in result["mutations"] if row[4] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[1]), row[2]) for row in unexplained])
    return result


def cost(n, output):
    return GAS_BASE + GAS_PER_BYTE * (n + output)


def doc_cost(n, output):
    return DOC_BASE + DOC_PER_BYTE * (n + output)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("address-scope.tsv", ("precompile", "scope"), [("%#x" % number, "out, rows in other packets" if number in OUT_OF_SCOPE else "in") for number in result["numbers"]])
    tsv("family.tsv", ("precompile", "function", "function_end", "lea_site", "cap_site", "base_site", "decoder", "decoder_site", "final_form", "final_site", "final_value", "output_bytes", "cost_32_byte_input", "docs_formula", "sum_source"),
        [("%#x" % e["number"], "%#x" % e["start"], "%#x" % e["end"], "%#x" % e["lea"], "%#x" % e["cap"], "%#x" % e["base"], "%#x" % e["decoder"], "%#x" % e["decoder_site"], e["form"], "%#x" % e["final"], e["final_value"],
          e["output"] if e["output"] is not None else "runtime", cost(32, e["output"]) if e["output"] is not None else "runtime", doc_cost(32, e["output"]) if e["output"] is not None else "runtime", e.get("sum_reg", "33n from the gate registers")) for e in result["entries"]])
    tsv("gate-outcomes.tsv", ("precompile", "returned_starved", "reached_decoder", "decoder_arguments"), [("%#x" % entry["number"], counts["returned"], counts["reached"], ",".join(forms).replace(",", " ", 1)) for entry, counts, forms in result["outcomes"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("precompile", "address", "kind", "outcome", "detail"), [("%#x" % number, "%#x" % va, k, o, d) for number, va, k, o, d in result["mutations"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "address_values": len(result["numbers"]), "in_scope": len(result["entries"]), "out_of_scope": len(OUT_OF_SCOPE), "cases_per_function": len(result["cases"]),
               "vector_cases_per_function": result["vector_count"], "fixed_form": sum(1 for e in result["entries"] if e["form"] == "fixed"), "runtime_form": sum(1 for e in result["entries"] if e["form"] == "runtime")}
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"), "survived": sum(1 for r in rows if r[3] == "survived")}
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
