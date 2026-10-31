#!/usr/bin/env python3
"""Pin node #94 HyperEVM user read precompiles: what each word of 0x800, 0x813, 0x801, 0x804, 0x805, 0x809, 0x810 and 0x811 holds.

Each function ends a read with a fixed or dynamic list of 32-byte words. The real bytes run under recording stubs
with real B-tree and hash table fixtures, a separately written rule list predicts the heap, events and output of
every run, and every reached conditional row, immediate and field offset is mutated. No objdump or readelf output
is parsed and the binary is never executed. Standard library only.

    python3 tools/user_read_precompiles.py --out <dir>
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


READERS = {0x800: 0x3305000, 0x813: 0x3305EC0, 0x801: 0x3248A20, 0x805: 0x324C530, 0x809: 0x324ABA0, 0x810: 0x324BA00, 0x811: 0x324A610, 0x804: 0x32480A0}
NAMES = {0x3305000: "position_0x800", 0x3305EC0: "position_0x813", 0x3248A20: "spot_balance_0x801", 0x324C530: "delegator_summary_0x805", 0x324ABA0: "block_word_0x809",
         0x324BA00: "user_exists_0x810", 0x324A610: "bole_user_0x811", 0x32480A0: "delegations_0x804", 0x3C18310: "bole_user_values", 0x35935B0: "bole_row_lookup",
         0x3992540: "delegator_summary", 0x3BE3530: "delegation_rows", 0x3BD0820: "delegation_words"}
VALUES = 0x3C18310
ROW_LOOKUP = 0x35935B0
SUMMARY = 0x3992540
COLLECT = 0x3BE3530
WORDS_OF = 0x3BD0820
TARGETS = tuple(sorted(NAMES))
OWNER = {VALUES: (0x811,), ROW_LOOKUP: (0x811,), SUMMARY: (0x805,), COLLECT: (0x804,), WORDS_OF: (0x804,)}

D_ADDRESS_U16 = 0x37E6A00
D_ADDRESS_U32 = 0x37E6480
D_ADDRESS_U64 = 0x37E6B80
D_ADDRESS = 0x37E6060
D_NONE = 0x37E6230
POSITION = 0x32696F0
HASH = 0x399C7A0
FORMAT = 0x37F3190
DROP = 0x3C1ADA0
WRAP = 0x3C02770
BYTES_FROM_VEC = 0x1511380
SLOT_DIV = 0x576E1A8
SLOT_MEMCMP = 0x576E488
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_ALLOC_FAIL2 = 0x576E020
SLOT_BYTES = 0x576E240
SLOT_WRAP = 0x5775510
SLOT_SPOT_USER = 0x5773170
SLOT_BOLE_USER = 0x5773E58
SLOT_SUMMARY = 0x5774F18
SLOT_STAKE_SUM = 0x5774900
SLOT_VT_EVEN = 0x576E140
SLOT_VT_ODD = 0x576E148
SLOT_DROP_EVEN = 0x5770228
SLOT_DROP_ODD = 0x5770220
SHARED_VTABLE = 0x5670A08
HOOK_SLOTS = (SLOT_DIV, SLOT_MEMCMP, SLOT_ALLOC, SLOT_FREE, SLOT_ALLOC_FAIL, SLOT_ALLOC_FAIL2, SLOT_BYTES, SLOT_SPOT_USER, SLOT_BOLE_USER, SLOT_STAKE_SUM, SLOT_DROP_EVEN, SLOT_DROP_ODD)
MARK_BASE = 0x7700000000
MARK_SHARED_DROP = MARK_BASE + 2
MARK_BYTES_DROP = MARK_BASE + 3
VT_EVEN = 0x7711000000
VT_ODD = 0x7722000000
LABEL_AT = 0x58251C
LABEL_LEN = 0x15
TAG_TOKEN = 0xEA
TAG_BOLE = 0xE1

E14 = 10 ** 14
TOP = MASK[8]
GUARD = E14 << 64
LENGTH_CAP = 2000
GAS_BASE = 1000
GAS_PER_BYTE = 33
WORD_COUNT = {0x800: 5, 0x813: 5, 0x801: 3, 0x805: 4, 0x809: 1, 0x810: 1, 0x811: 4}
SUM_READERS = (0x800, 0x813, 0x801, 0x805, 0x809, 0x810)

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x28
ROW_BUFFER = HEAP_BASE + 0x240
VALUE_ARGS = HEAP_BASE + 0x270
TOKEN_BUFFER = HEAP_BASE + 0x290
CTX = HEAP_BASE + 0x300
META = HEAP_BASE + 0x400
PX_STATE = HEAP_BASE + 0x460
BLOCK_STATE = HEAP_BASE + 0x4A0
SET_ROOT = HEAP_BASE + 0x600
INPUT = HEAP_BASE + 0x780
INPUT_DATA = HEAP_BASE + 0x7A0
VTABLE = HEAP_BASE + 0x7C0
USER_REC = HEAP_BASE + 0x800
SET_NODES = HEAP_BASE + 0x900
SET_NODE_STRIDE = 0x100
ALLOC_LOW = HEAP_BASE + 0x1000
ALLOC_HIGH = HEAP_BASE + 0x5000
EXISTS = HEAP_BASE + 0x5000
STAKING = HEAP_BASE + 0x5100
BOLE = HEAP_BASE + 0x5400
NODES = HEAP_BASE + 0x5800
USED = 0x12000
DATA_WORD = 0x0123456789ABCDEF
FORMATTED = (0xE500000000000000, 0xE600000000000000, 0xE700000000000000)
SET_KEY_AT = 8
SET_LEN = 0xE6
SET_EDGE_AT = 0xE8
USER = 0x1234567890ABCDEF0011223344556677889900AA
STALE_KEY = int("AB" * 20, 16)


class Layout:
    def __init__(self, size, val_at, val_size, key_at, len_at, edge_at, parent_idx=None):
        self.size, self.val_at, self.val_size, self.key_at, self.len_at, self.edge_at, self.parent_idx = size, val_at, val_size, key_at, len_at, edge_at, parent_idx


L_RESERVE = Layout(0x860, 0, 0xB0, 0x798, 0x7F2, 0x7F8)
L_BALANCE = Layout(0x1E0, 0x60, 0x18, 8, 0x16A, 0x170)
L_ROW = Layout(0x230, 0, 0x20, 0x168, 0x1C2, 0x1C8)
L_PENDING = Layout(0x200, 0, 0x10, 0xB8, 0x196, 0x198)
L_USER_STATE = Layout(0x258, 8, 0x18, 0x110, 0x1EE, 0x1F0, 0x1EC)


class Case:
    DEFAULTS = dict(entry=0x324A610, keys=(), set_shape="absent", n=36, gas=10 ** 6, ok=True, tok=5, count=10, oom=None, odd=False, user=USER, reserve=(("shape", "leaf"), ("ia", E14), ("ib", E14)),
                    row=(0, 0, 0, 0), row_shape="leaf", faults=None, out_len=None, pos=None, pos_err=None, perp=7, bal=(0, 0, 0), bal_shape="leaf", word=0, exists=None, sum_word=0, u=None, u_shape="leaf",
                    p=None, p_shape="leaf", rows=(), height=0, d_shape="leaf", d_outer="leaf")

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, fields.pop(key, value))
        if fields:
            raise EvidenceError("unknown case fields: %s" % sorted(fields))
        self.reserve = dict(self.reserve)
        self.faults = self.faults or {}
        self.number = ADDRESSES.get(self.entry, self.entry)


class Bump:
    """Allocator shared by the harness and the rule list, so a run's addresses are predictable."""

    def __init__(self, case):
        self.case, self.cur, self.count = case, ALLOC_LOW, 0

    def take(self, size):
        self.count += 1
        if self.case.oom == self.count:
            return 0
        at = self.cur + (1 if self.case.odd and self.count == 1 else 0)
        self.cur += (size + 0x2F) & ~0xF
        if self.cur > ALLOC_HIGH:
            raise Halt("alloc area full")
        return at


class Div:
    def __init__(self, faults):
        self.faults, self.log = faults, []

    def __call__(self, num, den):
        index = len(self.log)
        self.log.append((num, den))
        return self.faults.get(index, num // den)


def be_word(value):
    return b"\0" * 24 + struct.pack(">Q", value)


def signed_word(value):
    return (b"\xff" if value >> 63 else b"\0") * 24 + struct.pack(">Q", value)


def gas_in(n):
    return GAS_BASE + GAS_PER_BYTE * n


def total_gas(n, out_len):
    wide = out_len * GAS_PER_BYTE
    if wide > TOP:
        return TOP
    value = gas_in(n) + wide
    return TOP if value > TOP else value


def wrap32(value):
    value &= MASK[4]
    return value - (1 << 32) if value >> 31 else value


def lock_millis(date, secs, frac):
    """Year, ordinal and flags in one signed word, then seconds and nanoseconds, to Unix milliseconds floored at 0."""
    date = wrap32(date)
    year = date >> 13
    y, shift = year - 1, 0
    if year <= 0:
        k = (1 - year) // 400 + 1
        y += 400 * k
        shift = -146097 * k
    days = ((date >> 4) & 0x1FF) + shift + (wrap32(y * 1461) >> 2) - y // 100 + (y // 100 >> 2) - 719163
    ms = (days * 86400 + (secs & MASK[4])) * 1000 + (frac & MASK[4]) // 10 ** 6
    ms = ms & TOP
    return 0 if ms == 0 or ms >> 63 else ms


def user_values(case, div):
    """Two (flag, stored word, scaled word) lanes from one user row and the reserve indices."""
    b0, b1, s0, s1 = case.row
    lanes = []
    for stored, base, index in ((b0, b1, case.reserve["ia"]), (s0, s1, case.reserve["ib"])):
        product = base * index
        if product >= GUARD:
            lanes.append((0, stored, None))
        else:
            q = div(product, E14)
            lanes.append((int(base != 0 or q == 0), stored, q))
    return lanes


def output_of(case):
    entry = case.number
    if entry in (0x800, 0x813):
        w0, w1, w2, lev, flag = case.pos
        return signed_word(w0) + be_word(w1) + signed_word(w2) + b"\0" * 28 + struct.pack(">I", lev) + b"\0" * 31 + bytes((flag,))
    if entry == 0x801:
        words = case.bal if case.bal_shape in ("leaf", "deep") else (0, 0, 0)
        return b"".join(be_word(w) for w in words)
    if entry == 0x805:
        p, n = case.p if case.p is not None and case.p_shape in TREE_HIT else (0, 0)
        u = case.u[0] if case.u is not None and case.u_shape in TREE_HIT else 0
        return b"".join(be_word(w) for w in (case.sum_word, max(u - p, 0), p, n))
    if entry == 0x809:
        return be_word(case.word)
    if entry == 0x810:
        return be_word(1 if case.exists in EXISTS_HIT else 0)
    raise EvidenceError("no fixed output for %#x" % entry)


TREE_HIT = ("leaf", "deep", "deep left")
EXISTS_HIT = ("first", "after twin", "second group", "third group", "wrapped", "tail twin hit")


def delegation_rows(case):
    return sorted(case.rows) if case.d_shape == "leaf" else []


def spec_run(case, before):
    state = bytearray(before)
    events = []
    div = Div(case.faults)
    bump = Bump(case)
    entry = case.number

    def poke(addr, data):
        at = addr - HEAP_BASE
        if addr >= ALLOC_HIGH:
            at -= ALLOC_HIGH - ALLOC_LOW
        state[at:at + len(data)] = data

    def result(stamp, output=None):
        return ("run", bytes(state), div.log, tuple(events), output, stamp)

    def starved():
        poke(OUT, bytes(16) + struct.pack("<Q", 1 << 63))
        return result("starved")

    def refused(tag, payload):
        events.extend((("format", tag, payload), ("drop", tag)))
        poke(OUT, bytes(16) + struct.pack("<QQQ", *FORMATTED))
        return result("refused %#x %#x" % (tag, payload))

    def alloc(align, size):
        events.append(("alloc", size))
        at = bump.take(size)
        if not at:
            raise _Oom((align, size))
        return at

    try:
        if entry == VALUES:
            if case.reserve["shape"] in ("leaf", "deep"):
                lanes = user_values(case, div)
            else:
                lanes = [(0, case.row[0], None), (0, case.row[2], None)]
            data = b"".join(struct.pack("<QQQ", flag, stored, q or 0) for flag, stored, q in lanes)
            poke(OUT, data)
            return result("flags %d %d" % (lanes[0][0], lanes[1][0]))
        if (entry in case.keys and case.set_shape != "absent") or case.n > LENGTH_CAP or gas_in(case.n) > case.gas:
            return starved()
        if not case.ok:
            at = alloc(1, 13)
            poke(OUT, bytes(16) + struct.pack("<QQQ", 13, at, 13))
            return result("invalid input", b"Invalid input")
        if entry == 0x811:
            if case.tok >= case.count:
                return refused(TAG_TOKEN, case.tok)
            if case.reserve["shape"] not in ("leaf", "deep"):
                return refused(TAG_BOLE, 0)
            if case.row_shape not in ("leaf", "deep"):
                return refused(TAG_BOLE, 0)
            lanes = user_values(case, div)
            words = []
            for flag, stored, q in lanes:
                words.extend((stored, q) if flag & 1 else (0, 0))
            data = b"".join(be_word(w) for w in words)
            one = alloc(1, 0x80)
            two = alloc(8, 0x20)
            events.extend((("free", two, 0x20), ("bytes", 0x80)))
            out_len = 0x80 if case.out_len is None else case.out_len
            total = total_gas(case.n, out_len)
            shown = data[:min(out_len, 0x80)]
            if total > case.gas:
                events.append(("free_bytes", one, out_len))
                poke(OUT, bytes(16) + struct.pack("<Q", 1 << 63))
                return result("starved after output")
            poke(OUT, struct.pack("<QQQQQ", VTABLE, one, out_len, DATA_WORD, total))
            return result("ok", shown)
        if entry == 0x804:
            rows = delegation_rows(case)
            count = len(rows)
            table = alloc(8, 0x28 * count) if count else None
            words = alloc(1, 0x60 * count) if count else None
            size = (3 * count + 2) * 32
            buffer = alloc(1, (3 * count + 3) * 32)
            stack = alloc(8, 0x20)
            events.append(("free", stack, 0x20))
            if count:
                events.append(("free", words, 0x60 * count))
            shared = alloc(8, 0x18)
            data = be_word(0x20) + be_word(count)
            for key, amount, date, secs, frac in rows:
                data += b"\0" * 12 + key.to_bytes(20, "big") + be_word(amount) + be_word(lock_millis(date, secs, frac))
            total = total_gas(case.n, size)
            if total > case.gas:
                events.append(("free_shared", buffer, size))
                poke(OUT, bytes(16) + struct.pack("<Q", 1 << 63))
                stamp = result("starved after output")
                if count:
                    events.append(("free", table, 0x28 * count))
                return result("starved after output")
            poke(OUT, struct.pack("<QQQQQ", SHARED_VTABLE, buffer, size, shared, total))
            if count:
                events.append(("free", table, 0x28 * count))
            return result("ok %d rows" % count, data + struct.pack("<QQQ", buffer, (3 * count + 3) * 32, 1))
        if entry in (0x800, 0x813) and case.pos_err is not None:
            poke(OUT, bytes(16) + struct.pack("<QQQ", *case.pos_err))
            return result("position error")
        if entry == 0x801 and case.tok >= case.count:
            return refused(TAG_TOKEN, case.tok)
        data = output_of(case)
        size = len(data)
        one = alloc(1, size)
        two = alloc(8, 0x20)
        events.append(("free", two, 0x20))
        total = total_gas(case.n, size)
        data_word = one if one & 1 else one | 1
        if total > case.gas:
            events.append(("drop_odd" if one & 1 else "drop_even", data_word, one, size))
            poke(OUT, bytes(16) + struct.pack("<Q", 1 << 63))
            return result("starved after output")
        poke(OUT, struct.pack("<QQQQQ", VT_ODD if one & 1 else VT_EVEN, one, size, data_word, total))
        return result("ok", data)
    except _Oom as oom:
        return ("panic", oom.args[0], div.log, tuple(events), None, "panic")


class _Oom(Exception):
    pass


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        statics = memory.statics
        machine.calls = {D_ADDRESS_U16: self.on_decode_u16, D_ADDRESS_U32: self.on_decode_u32, D_ADDRESS_U64: self.on_decode_u64, D_ADDRESS: self.on_decode_address, D_NONE: self.on_decode_none,
                         POSITION: self.on_position, HASH: self.on_hash, FORMAT: self.on_format, DROP: self.on_drop}
        hooks = {SLOT_DIV: self.on_div, SLOT_MEMCMP: self.on_memcmp, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_ALLOC_FAIL: self.on_alloc_fail, SLOT_ALLOC_FAIL2: self.on_alloc_fail,
                 SLOT_BYTES: self.on_bytes, SLOT_SPOT_USER: self.on_spot_user, SLOT_BOLE_USER: self.on_bole_user, SLOT_STAKE_SUM: self.on_stake_sum, SLOT_DROP_EVEN: self.on_drop_even, SLOT_DROP_ODD: self.on_drop_odd}
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        machine.slots[MARK_SHARED_DROP] = self.on_drop_shared
        machine.slots[MARK_BYTES_DROP] = self.on_drop_bytes
        statics[SLOT_WRAP] = WRAP
        statics[SLOT_SUMMARY] = SUMMARY
        statics[SLOT_VT_EVEN] = VT_EVEN
        statics[SLOT_VT_ODD] = VT_ODD
        statics[SHARED_VTABLE + 0x20] = MARK_SHARED_DROP
        machine.real = frozenset((WRAP, SUMMARY, VALUES, ROW_LOOKUP, COLLECT, WORDS_OF))
        self.constants = CONSTANTS.setdefault(id(image), {entry: find_constant(image, entry) for entry in READERS.values()})
        self.case = None
        self.log = []
        self.events = []
        self.bump = None
        self.node_cur = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def user_at(self, address):
        self.expect(self.machine.memory.bytes_at(address, 20) == self.case.user.to_bytes(20, "big"), "user bytes")

    def on_alloc_fail(self, machine):
        raise Panicked("%d %d" % (machine.regs[RDI], machine.regs[RSI]))

    def on_div(self, machine):
        regs = machine.regs
        num, den = regs[RDI] | regs[RSI] << 64, regs[RDX] | regs[RCX] << 64
        index = len(self.log)
        self.log.append((num, den))
        q = self.case.faults[index] if index in self.case.faults else num // den
        regs[RAX], regs[RDX] = q & TOP, q >> 64
        machine.keep_rdx = True

    def on_memcmp(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 20, "memcmp length")
        if regs[RDI] < HEAP_BASE:
            self.expect(regs[RDI] == self.constants[self.case.entry][0], "memcmp constant")
        left = machine.memory.bytes_at(regs[RDI], 20)
        right = machine.memory.bytes_at(regs[RSI], 20)
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def decode_common(self, regs, data, length):
        self.expect(data == INPUT_DATA, "decode pointer")
        self.expect(length == self.case.n, "decode length")

    def on_decode_u16(self, machine):
        regs, memory = machine.regs, machine.memory
        self.decode_common(regs, regs[RSI], regs[RDX])
        memory.write(regs[RDI], 1, int(self.case.ok))
        if self.case.ok:
            memory.put_bytes(regs[RDI] + 2, self.case.user.to_bytes(20, "big"))
            memory.write(regs[RDI] + 0x16, 2, self.case.perp)

    def on_decode_u32(self, machine):
        regs, memory = machine.regs, machine.memory
        self.decode_common(regs, regs[RSI], regs[RDX])
        memory.write(regs[RDI], 1, int(self.case.ok))
        if self.case.ok:
            memory.put_bytes(regs[RDI] + 4, self.case.user.to_bytes(20, "big"))
            memory.write(regs[RDI] + 0x18, 4, self.case.perp)

    def on_decode_u64(self, machine):
        regs, memory = machine.regs, machine.memory
        self.decode_common(regs, regs[RSI], regs[RDX])
        memory.write(regs[RDI], 1, int(self.case.ok))
        if self.case.ok:
            memory.write(regs[RDI] + 8, 8, self.case.tok)
            memory.put_bytes(regs[RDI] + 0x10, self.case.user.to_bytes(20, "big"))

    def on_decode_address(self, machine):
        regs, memory = machine.regs, machine.memory
        self.decode_common(regs, regs[RSI], regs[RDX])
        self.expect(regs[RCX] == LABEL_AT and regs[R8] == LABEL_LEN, "decoder label")
        memory.write(regs[RDI], 1, int(self.case.ok))
        if self.case.ok:
            memory.put_bytes(regs[RDI] + 1, self.case.user.to_bytes(20, "big"))

    def on_decode_none(self, machine):
        regs = machine.regs
        self.decode_common(regs, regs[RDI], regs[RSI])
        self.expect(regs[RDX] == LABEL_AT and regs[RCX] & MASK[4] == LABEL_LEN, "decoder label")
        regs[RAX] = 1 if self.case.ok else 0x100

    def on_position(self, machine):
        regs, memory = machine.regs, machine.memory
        case = self.case
        self.expect(regs[RSI] == 0x4141 and regs[RDX] == 0x4242, "position state words")
        self.user_at(regs[RCX])
        self.expect(regs[R8] == case.perp, "position index")
        if case.pos_err is not None:
            for index, value in enumerate(case.pos_err):
                memory.write(regs[RDI] + 8 * index, 8, value)
            memory.write(regs[RDI] + 0x1C, 1, 2)
            return
        w0, w1, w2, lev, flag = case.pos
        for index, value in enumerate((w0, w1, w2)):
            memory.write(regs[RDI] + 8 * index, 8, value)
        memory.write(regs[RDI] + 0x18, 4, lev)
        memory.write(regs[RDI] + 0x1C, 1, flag)

    def on_hash(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == EXISTS + 0x20, "hash state")
        self.user_at(regs[RSI])
        regs[RAX] = EXIST_HASH

    def on_format(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDX] & MASK[4] == 0, "format flag")
        tag = memory.read(regs[RSI], 2)
        payload = memory.read(regs[RSI] + 8, 8) if tag == TAG_TOKEN else memory.read(regs[RSI] + 2, 1)
        self.events.append(("format", tag, payload))
        for index, value in enumerate(FORMATTED):
            memory.write(regs[RDI] + 8 * index, 8, value)
        regs[RAX] = regs[RDI]

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_alloc(self, machine):
        regs = machine.regs
        self.events.append(("alloc", regs[RDI]))
        regs[RAX] = self.bump.take(regs[RDI])

    def on_free(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] & MASK[4] == 0, "free flags")
        self.events.append(("free", regs[RDI], regs[RSI]))

    def on_bytes(self, machine):
        regs, memory = machine.regs, machine.memory
        cap, ptr, size = (memory.read(regs[RSI] + 8 * index, 8) for index in range(3))
        self.expect(cap == 0x80 and size == 0x80, "vector words")
        self.events.append(("bytes", size))
        out_len = 0x80 if self.case.out_len is None else self.case.out_len
        for index, value in enumerate((VTABLE, ptr, out_len, DATA_WORD)):
            memory.write(regs[RDI] + 8 * index, 8, value)

    def on_drop_bytes(self, machine):
        regs = machine.regs
        self.expect(machine.memory.read(regs[RDI], 8) == DATA_WORD, "bytes drop data")
        self.events.append(("free_bytes", regs[RSI], regs[RDX]))

    def on_drop_even(self, machine):
        regs = machine.regs
        self.events.append(("drop_even", machine.memory.read(regs[RDI], 8), regs[RSI], regs[RDX]))

    def on_drop_odd(self, machine):
        regs = machine.regs
        self.events.append(("drop_odd", machine.memory.read(regs[RDI], 8), regs[RSI], regs[RDX]))

    def on_drop_shared(self, machine):
        regs = machine.regs
        self.expect(machine.memory.read(machine.memory.read(regs[RDI], 8) + 16, 8) == 1, "shared count")
        self.events.append(("free_shared", regs[RSI], regs[RDX]))

    def on_spot_user(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == META, "spot state")
        self.user_at(regs[RSI])
        regs[RAX] = USER_REC

    def on_bole_user(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == BOLE, "bole state")
        self.user_at(regs[RSI])
        regs[RAX] = USER_REC

    def on_stake_sum(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STAKING + 0x168, "delegations map")
        self.user_at(regs[RSI])
        regs[RAX] = self.case.sum_word

    def alloc_node(self, layout):
        at = self.node_cur
        self.node_cur += layout.size
        memory = self.machine.memory
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF for index in range(layout.size)))
        return at

    def u64_node(self, layout, items, children=(), stale=None):
        at = self.alloc_node(layout)
        memory = self.machine.memory
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            key = stale if stale is not None and slot >= len(items) else 0x5A5A0000 + slot
            memory.write(at + layout.key_at + 8 * slot, 8, key)
        for slot, (key, value) in enumerate(items):
            memory.write(at + layout.key_at + 8 * slot, 8, key)
            for index, word in enumerate(value):
                memory.write(at + layout.val_at + layout.val_size * slot + 8 * index, 8, word)
        for slot, child in enumerate(children):
            memory.write(at + layout.edge_at + 8 * slot, 8, child)
        return at

    def u64_tree(self, layout, shape, key, value, decoy, head):
        """Write root and height at `head`. Unused key slots hold the searched key, so a length bound error finds it."""
        memory = self.machine.memory
        if shape == "empty":
            memory.write(head, 8, 0)
            memory.write(head + 8, 8, 0xFEED)
            return
        if shape == "deep":
            left = self.u64_node(layout, [(key - 2 & TOP, decoy), (key - 1 & TOP, decoy)], stale=key)
            right = self.u64_node(layout, [(key, value), (key + 2, decoy)], stale=key + 1)
            root = self.u64_node(layout, [(key - 1 & TOP, decoy)], (left, right))
            memory.write(head, 8, root)
            memory.write(head + 8, 8, 1)
            return
        if shape == "leaf":
            lows = [(key - 3 + index & TOP, decoy) for index in range(3)] if key >= 3 else []
            root = self.u64_node(layout, lows + [(key, value), (key + 1, decoy)], stale=key)
        elif shape == "miss":
            root = self.u64_node(layout, [(key - 1 & TOP, decoy), (key + 1, decoy)], stale=key)
        else:
            root = self.u64_node(layout, [(key - 1 & TOP, decoy)], stale=key)
        memory.write(head, 8, root)
        memory.write(head + 8, 8, 0)

    def addr_node(self, layout, items, children=(), stale=None):
        at = self.alloc_node(layout)
        memory = self.machine.memory
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            key = stale if stale is not None and slot >= len(items) else 0xFFFFFF00 + slot
            memory.put_bytes(at + layout.key_at + 20 * slot, key.to_bytes(20, "big"))
        for slot, (key, value) in enumerate(items):
            memory.put_bytes(at + layout.key_at + 20 * slot, key.to_bytes(20, "big"))
            memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        for slot, child in enumerate(children):
            memory.write(at + layout.edge_at + 8 * slot, 8, child)
            if layout.parent_idx is not None:
                memory.write(child, 8, at)
                memory.write(child + layout.parent_idx, 2, slot)
        return at

    def addr_tree(self, layout, shape, key, value, decoy, head):
        memory = self.machine.memory
        if shape == "empty":
            memory.write(head, 8, 0)
            memory.write(head + 8, 8, 0xFEED)
            return
        if shape == "deep":
            left = self.addr_node(layout, [(key - 2, decoy), (key - 1, decoy)], stale=key)
            right = self.addr_node(layout, [(key, value), (key + 2, decoy)], stale=key + 1)
            root = self.addr_node(layout, [(key - 1, decoy)], (left, right))
            memory.write(head, 8, root)
            memory.write(head + 8, 8, 1)
            return
        if shape == "deep left":
            left = self.addr_node(layout, [(key - 1, decoy), (key, value)], stale=key + 1)
            right = self.addr_node(layout, [(key + 2, decoy)], stale=key)
            root = self.addr_node(layout, [(key + 1, decoy)], (left, right))
            memory.write(head, 8, root)
            memory.write(head + 8, 8, 1)
            return
        if shape == "leaf":
            root = self.addr_node(layout, [(key - 3 + index, decoy) for index in range(3)] + [(key, value), (key + 1, decoy)], stale=key)
        elif shape == "miss":
            root = self.addr_node(layout, [(key - 1, decoy), (key + 1, decoy)], stale=key)
        else:
            root = self.addr_node(layout, [(key - 1, decoy)], stale=key)
        memory.write(head, 8, root)
        memory.write(head + 8, 8, 0)

    def set_node(self, at, keys, children=(), stale=None):
        memory = self.machine.memory
        memory.write(at + SET_LEN, 2, len(keys))
        for slot in range(11):
            key = keys[slot] if slot < len(keys) else (stale if stale is not None else 0xFFFFFF00 + slot)
            memory.put_bytes(at + SET_KEY_AT + 20 * slot, key.to_bytes(20, "big"))
        for slot, child in enumerate(children):
            memory.write(at + SET_EDGE_AT + 8 * slot, 8, child)

    def set_state(self, case, address):
        memory = self.machine.memory
        if case.set_shape == "absent":
            memory.write(SET_ROOT, 8, 0)
            memory.write(SET_ROOT + 8, 8, 0xFEED)
            return
        keys = sorted(case.keys)
        if case.set_shape == "leaf":
            self.set_node(SET_NODES, keys, stale=address)
            memory.write(SET_ROOT, 8, SET_NODES)
            memory.write(SET_ROOT + 8, 8, 0)
            return
        left, right = SET_NODES + SET_NODE_STRIDE, SET_NODES + 2 * SET_NODE_STRIDE
        if case.set_shape == "deep left":
            self.set_node(left, keys, stale=address)
            self.set_node(right, [address + 8], stale=address)
            self.set_node(SET_NODES, [address + 5], (left, right))
        else:
            self.set_node(left, [address - 3, address - 2], stale=address)
            self.set_node(right, keys, stale=address)
            self.set_node(SET_NODES, [address - 1], (left, right))
        memory.write(SET_ROOT, 8, SET_NODES)
        memory.write(SET_ROOT + 8, 8, 1)

    def exists_state(self, case):
        memory = self.machine.memory
        memory.write(EXISTS + 0x18, 8, 0 if case.exists == "empty" else 3)
        memory.write(EXISTS + 0x20, 8, 0x4343)
        ctrl = NODES + 0x2000
        memory.write(EXISTS, 8, ctrl)
        memory.write(EXISTS + 8, 8, EXIST_MASK)
        table = bytearray(b"\x80" * (EXIST_MASK + 1))
        pos = EXIST_HASH & EXIST_MASK
        h2 = EXIST_HASH >> 57
        near = bytes(case.user.to_bytes(20, "big"))

        def put(slot, key):
            slot &= EXIST_MASK
            table[slot] = h2
            memory.put_bytes(ctrl - 0x58 * (slot + 1), key)

        twin = near[:3] + bytes((near[3] ^ 1,)) + near[4:]
        tail = near[:18] + bytes((near[18] ^ 1,)) + near[19:]
        kind = case.exists
        if kind == "first":
            put(pos, near)
        elif kind == "after twin":
            put(pos + 1, twin)
            put(pos + 3, near)
        elif kind == "second group":
            put(pos + 16, near)
        elif kind == "third group":
            put(pos + 48, near)
        elif kind == "wrapped":
            pos2 = (EXIST_MASK + 1 - pos) & EXIST_MASK
            put(pos + pos2 + 2, near)
        elif kind == "tail twin hit":
            put(pos, tail)
            put(pos + 8, near)
        elif kind == "twin only":
            put(pos, twin)
            table[(pos + 5) & EXIST_MASK] = 0xFF
        elif kind == "tail twin":
            put(pos, tail)
            table[(pos + 5) & EXIST_MASK] = 0xFF
        elif kind == "miss":
            table[(pos + 2) & EXIST_MASK] = 0xFF
        elif kind == "miss later":
            put(pos + 20, near)
            table[(pos + 2) & EXIST_MASK] = 0xFF
        if kind in ("first", "after twin", "wrapped", "tail twin hit", "second group", "third group"):
            # A far empty byte stops a walk that went past the right group.
            table[(pos + 61) & EXIST_MASK] = 0xFF
        memory.put_bytes(ctrl, bytes(table) + bytes(table[:16]))

    def delegation_tree(self, rows, height):
        layout = L_USER_STATE
        memory = self.machine.memory

        def value(row):
            _, amount, date, secs, frac = row
            return struct.pack("<QIII", amount, date & MASK[4], secs, frac) + b"\xCC" * 4

        def chain(h, part):
            if h == 0:
                return self.addr_node(layout, [(row[0], value(row)) for row in part], stale=STALE_KEY)
            return self.addr_node(layout, [], (chain(h - 1, part),), stale=STALE_KEY)

        if height == 0:
            root = chain(0, rows)
        else:
            mid = len(rows) // 2
            root = self.addr_node(layout, [(rows[mid][0], value(rows[mid]))], (chain(height - 1, rows[:mid]), chain(height - 1, rows[mid + 1:])), stale=STALE_KEY)
        memory.write(root, 8, 0)
        return root

    def delegations_state(self, case):
        memory = self.machine.memory
        rows = delegation_rows(case)
        root = self.delegation_tree(rows, case.height) if rows else 0
        value = struct.pack("<QQQ", root, case.height, len(rows))
        decoy = struct.pack("<QQQ", 0x77, 9, 99)
        if case.d_shape == "leaf" and not rows:
            value = struct.pack("<QQQ", 0, 0x55, 0x66)
        self.addr_tree(L_USER_STATE, case.d_shape if case.d_shape != "leaf" else case.d_outer, case.user, value, decoy, STAKING + 0x168)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000)))
        self.case, self.log, self.events, self.bump, self.node_cur = case, [], [], Bump(case), NODES
        entry = case.number
        reserve = case.reserve
        rec_decoy = (0x11,) * 11 + (reserve["ia"] ^ 0x33,) + (0x11,) * 3 + (reserve["ib"] ^ 0x11,)
        rec = (0x22,) * 11 + (reserve["ia"],) + (0x22,) * 3 + (reserve["ib"],)
        if entry == VALUES:
            memory.write(BOLE + 0xD0, 8, 0)
            self.u64_tree(L_RESERVE, reserve["shape"], case.tok, rec, rec_decoy, BOLE + 0xD0)
            for index, word in enumerate(case.row):
                memory.write(ROW_BUFFER + 8 * index, 8, word)
            memory.write(VALUE_ARGS, 8, BOLE)
            memory.write(VALUE_ARGS + 8, 8, TOKEN_BUFFER)
            memory.write(TOKEN_BUFFER, 8, case.tok)
        else:
            memory.write(CTX + 8, 8, PX_STATE)
            memory.write(CTX + 0x10, 8, META)
            memory.write(CTX + 0x20, 8, STAKING)
            memory.write(CTX + 0x30, 8, BLOCK_STATE)
            memory.write(CTX + 0x38, 8, SET_ROOT)
            memory.write(CTX + 0x40, 8, EXISTS)
            memory.write(CTX + 0x48, 8, BOLE)
            memory.write(META + 0x198, 8, case.count)
            memory.write(PX_STATE + 8, 8, 0x4141)
            memory.write(PX_STATE + 0x10, 8, 0x4242)
            memory.write(BLOCK_STATE + 0x28, 8, case.word)
            memory.write(INPUT + 8, 8, INPUT_DATA)
            memory.write(INPUT + 0x10, 8, case.n)
            memory.write(VTABLE + 0x20, 8, MARK_BYTES_DROP)
            self.set_state(case, entry)
            if entry == 0x811:
                self.u64_tree(L_RESERVE, reserve["shape"], case.tok, rec, rec_decoy, BOLE + 0xD0)
                self.u64_tree(L_ROW, case.row_shape, case.tok, case.row, tuple(word ^ 0x5555 for word in case.row), USER_REC + 0x18)
            elif entry == 0x801:
                self.u64_tree(L_BALANCE, case.bal_shape, case.tok, case.bal, tuple(word ^ 0x5555 for word in case.bal), USER_REC + 0x10)
            elif entry == 0x805:
                self.addr_tree(L_USER_STATE, case.u_shape, case.user, struct.pack("<QQQ", *(case.u or (0, 0, 0))), struct.pack("<QQQ", 0x1999, 0x2999, 0x3999), STAKING + 0x1F8)
                self.addr_tree(L_PENDING, case.p_shape, case.user, struct.pack("<QQ", *(case.p or (0, 0))), struct.pack("<QQ", 0x4999, 0x5999), STAKING + 0x228)
            elif entry == 0x810:
                self.exists_state(case)
            elif entry == 0x804:
                self.delegations_state(case)
        return self.snapshot()

    def snapshot(self):
        heap = self.machine.memory.heap
        return bytes(heap[:ALLOC_LOW - HEAP_BASE]) + bytes(heap[ALLOC_HIGH - HEAP_BASE:USED])

    def capture(self, case):
        """What a caller sees: error text or output bytes, and for 0x804 the shared block."""
        memory = self.machine.memory
        if case.entry == VALUES:
            return None
        head = [memory.read(OUT + 8 * index, 8) for index in range(5)]
        if head[0] == 0 and head[1] == 0:
            if head[2] == 13:
                return memory.bytes_at(head[3], 13)
            return None
        data = memory.bytes_at(head[1], min(head[2], 0x4000))[:0x80] if case.number == 0x811 else memory.bytes_at(head[1], head[2])
        if case.number == 0x804:
            data += memory.bytes_at(head[3], 0x18)
        return data

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        try:
            if case.entry == VALUES:
                value = machine.run(VALUES, {RDI: OUT, RSI: ROW_BUFFER, RDX: VALUE_ARGS})
                memory = machine.memory
                # A lane with no scaled word leaves caller register garbage, which no reader sees.
                for flag_at, q_at in ((OUT, OUT + 0x10), (OUT + 0x18, OUT + 0x28)):
                    if memory.read(flag_at, 8) == 0 and (case.reserve["shape"] not in ("leaf", "deep") or memory.read(q_at, 8) in (POISON, 0)):
                        memory.write(q_at, 8, 0)
                    elif memory.read(flag_at, 8) == 0:
                        memory.write(q_at, 8, 0)
            else:
                value = machine.run(case.entry, {RDI: OUT, RSI: CTX, RDX: INPUT, RCX: case.gas})
            if value != OUT:
                raise Halt("result pointer")
        except Panicked as panic:
            text = str(panic).split()
            return before, ("panic", (int(text[0]), int(text[1])), self.log, tuple(self.events), None, "panic")
        return before, ("run", self.snapshot(), self.log, tuple(self.events), self.capture(case), None)


EXIST_HASH = (0x5B << 57) | 0x1234567000 | 58
EXIST_MASK = 63


def find_constant(image, entry):
    """The 20-byte address constant: the first rip-relative lea in the function that lands on `00*18 08 xx`."""
    start, end = image.exact_fde(entry)
    data = bytes(image.blob[image.offset(start):image.offset(start) + 0x90])
    for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", data):
        at = match.start()
        target = start + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        try:
            text = bytes(image.blob[image.offset(target):image.offset(target) + 20])
        except EvidenceError:
            continue
        if text[:18] == bytes(18) and text[18] == 8:
            return target, int.from_bytes(text, "big")
    raise EvidenceError("no address constant in %#x" % entry)


ADDRESSES = {entry: address for address, entry in READERS.items()}
CONSTANTS = {}


def same(got, want):
    return got[:5] == want[:5]


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


def gate_cases(address, **base):
    entry = READERS[address]
    size = {0x800: 0xA0, 0x813: 0xA0, 0x801: 0x60, 0x805: 0x80, 0x809: 0x20, 0x810: 0x20, 0x811: 0x80}.get(address)
    tag = "%#x " % address
    cases = [Case(tag + "n 2000", entry=entry, n=2000, gas=10 ** 7, **base), Case(tag + "n 2001", entry=entry, n=2001, gas=10 ** 7, **base),
             Case(tag + "n 0", entry=entry, n=0, gas=10 ** 7, **base), Case(tag + "gas gate exact", entry=entry, n=4, gas=gas_in(4), **base),
             Case(tag + "gas gate short", entry=entry, n=4, gas=gas_in(4) - 1, **base), Case(tag + "bad input", entry=entry, ok=False, **base), Case(tag + "bad input oom", entry=entry, ok=False, oom=1, **base),
             Case(tag + "own address leaf", entry=entry, keys=(address,), set_shape="leaf", **base), Case(tag + "own address deep left", entry=entry, keys=(address,), set_shape="deep left", **base),
             Case(tag + "own address deep right", entry=entry, keys=(address,), set_shape="deep right", **base), Case(tag + "other address", entry=entry, keys=(address + 1,), set_shape="leaf", **base),
             Case(tag + "other below", entry=entry, keys=(address - 1,), set_shape="leaf", **base), Case(tag + "other deep left", entry=entry, keys=(address + 1,), set_shape="deep left", **base),
             Case(tag + "other deep right", entry=entry, keys=(address - 1, ), set_shape="deep right", **base),
             Case(tag + "own address third", entry=entry, keys=(address - 2, address - 1, address), set_shape="leaf", **base)]
    if size is not None:
        total = total_gas(36, size)
        cases += [Case(tag + "exact total", entry=entry, gas=total, **base), Case(tag + "one short of total", entry=entry, gas=total - 1, **base),
                  Case(tag + "exact total odd", entry=entry, gas=total, odd=True, **base), Case(tag + "short total odd", entry=entry, gas=total - 1, odd=True, **base),
                  Case(tag + "oom one", entry=entry, oom=1, **base), Case(tag + "oom two", entry=entry, oom=2, **base)]
    return cases


def position_cases(address):
    pos = (0x1122334455667788, 0x0102030405060708, 0x0A0B0C0D0E0F1011, 0xC0D0E0F, 1)
    neg = ((-5) & TOP, 0x8000000000000001, (-7) & TOP, 0xFFFFFFFE, 0)
    entry = READERS[address]
    tag = "%#x " % address
    return gate_cases(address, pos=pos) + [
        Case(tag + "negative size", entry=entry, pos=neg), Case(tag + "mixed sign one", entry=entry, pos=(5, 7, (-1) & TOP, 1, 1)), Case(tag + "mixed sign two", entry=entry, pos=((-1) & TOP, 7, 1 << 62, 1, 0)),
        Case(tag + "other byte", entry=entry, pos=(1, 2, 3, 4, 0x7F)), Case(tag + "error", entry=entry, pos=pos, pos_err=(0x31, 0x32, 0x33)), Case(tag + "top index", entry=entry, pos=pos, perp=0xFFFF), Case(tag + "other index", entry=entry, pos=pos, perp=0x1234)]


def balance_cases():
    entry = READERS[0x801]
    bal = (0x1111222233334444, 0x5555666677778888, 0x99990000AAAABBBB)
    return gate_cases(0x801, bal=bal) + [
        Case("0x801 deep", entry=entry, bal=bal, bal_shape="deep"), Case("0x801 miss", entry=entry, bal=bal, bal_shape="miss"), Case("0x801 miss below", entry=entry, bal=bal, bal_shape="below"), Case("0x801 empty", entry=entry, bal=bal, bal_shape="empty"),
        Case("0x801 token 0", entry=entry, bal=bal, tok=0), Case("0x801 token count-1", entry=entry, bal=bal, tok=9), Case("0x801 token count", entry=entry, bal=bal, tok=10), Case("0x801 token count+1", entry=entry, bal=bal, tok=11),
        Case("0x801 top word", entry=entry, bal=(TOP, TOP, TOP), tok=2), Case("0x801 big token", entry=entry, bal=bal, tok=1 << 40, count=(1 << 40) + 1)]


def summary_cases():
    entry = READERS[0x805]
    good = dict(sum_word=0x1020304050607080, u=(1000, 7, 7), p=(300, 4))
    cases = gate_cases(0x805, **good)
    for u_shape in ("leaf", "deep", "deep left", "miss", "below", "empty"):
        for p_shape in ("leaf", "deep", "deep left", "miss", "below", "empty"):
            cases.append(Case("0x805 U %s P %s" % (u_shape, p_shape), entry=entry, u_shape=u_shape, p_shape=p_shape, **good))
    cases += [Case("0x805 pending equals U", entry=entry, sum_word=1, u=(300, 0, 0), p=(300, 1)), Case("0x805 pending above U", entry=entry, sum_word=2, u=(300, 0, 0), p=(301, 1)),
              Case("0x805 pending one below U", entry=entry, sum_word=3, u=(301, 0, 0), p=(300, 1)), Case("0x805 pending top", entry=entry, sum_word=TOP, u=(TOP, 5, 5), p=(TOP - 1, TOP)), Case("0x805 U zero P zero", entry=entry, u=(0, 1, 1), p=(0, 0))]
    return cases


def exists_cases():
    entry = READERS[0x810]
    cases = gate_cases(0x810, exists="first")
    for kind in ("empty",) + EXISTS_HIT + ("twin only", "tail twin", "miss", "miss later"):
        cases.append(Case("0x810 " + kind, entry=entry, exists=kind))
    cases.append(Case("0x810 oom two absent", entry=entry, exists="empty", oom=2))
    return cases


def day(y, m, d):
    """Date word for a year in the plain Gregorian range: year<<13 | ordinal<<4 | flags 0."""
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    return y << 13 | (sum((31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[:m - 1]) + d) << 4


def delegation_cases():
    entry = READERS[0x804]
    rows = [(0xA0 + index * 16, 10 ** 8 * (index + 1) + 3, day(2026, 1 + index % 12, 1 + index), 3600 * index + 11, 123456789 + index * 1000000) for index in range(5)]
    cases = gate_cases(0x804, rows=tuple(rows[:2]))
    size = (3 * 2 + 2) * 32
    total = total_gas(36, size)
    empty_total = total_gas(36, 2 * 32)
    cases += [Case("0x804 exact total", entry=entry, rows=tuple(rows[:2]), gas=total), Case("0x804 short total", entry=entry, rows=tuple(rows[:2]), gas=total - 1), Case("0x804 no rows exact", entry=entry, gas=empty_total), Case("0x804 no rows short", entry=entry, gas=empty_total - 1)]
    for index in range(1, 5):
        cases.append(Case("0x804 oom %d" % index, entry=entry, rows=tuple(rows[:2]), oom=index))
    cases.append(Case("0x804 oom 5", entry=entry, rows=tuple(rows[:2]), oom=5))
    cases.append(Case("0x804 no rows oom 1", entry=entry, oom=1))
    cases.append(Case("0x804 no rows oom 2", entry=entry, oom=2))
    cases.append(Case("0x804 no rows oom 3", entry=entry, oom=3))
    for shape in ("miss", "below", "empty"):
        cases.append(Case("0x804 user " + shape, entry=entry, rows=tuple(rows[:2]), d_shape=shape))
    cases.append(Case("0x804 user with no inner root", entry=entry))
    cases.append(Case("0x804 user deep", entry=entry, rows=tuple(rows[:2]), d_outer="deep"))
    cases.append(Case("0x804 user deep left", entry=entry, rows=tuple(rows[:2]), d_outer="deep left"))
    for count in (1, 3, 5):
        cases.append(Case("0x804 leaf %d rows" % count, entry=entry, rows=tuple(rows[:count])))
    many = [(0x1000 + index, index + 1, day(2030, 3, 1), index, index) for index in range(11)]
    cases.append(Case("0x804 full leaf", entry=entry, rows=tuple(many)))
    for height in (1, 2, 3, 7, 8, 9, 15, 16, 17):
        cases.append(Case("0x804 height %d" % height, entry=entry, rows=tuple(rows), height=height))
    times = ((1970, 1, 1, 0, 0), (1970, 1, 1, 0, 999999), (1970, 1, 1, 0, 1000000), (1969, 12, 31, 86399, 999999999), (1970, 1, 1, 1, 0), (2000, 3, 1, 0, 0), (2024, 2, 29, 86399, 1999999999), (2100, 3, 1, 0, 0), (2101, 1, 1, 0, 0),
             (2400, 12, 31, 5, 7), (1600, 1, 1, 0, 0), (9999, 12, 31, 86399, 999999999), (1, 1, 1, 0, 0), (2026, 10, 31, 50400, 5000000))
    for index, (y, m, d, secs, frac) in enumerate(times):
        cases.append(Case("0x804 time %d-%d-%d" % (y, m, d), entry=entry, rows=((0xB0, 7, day(y, m, d), secs, frac),)))
    for year in (0, -1, -400, -401, -262000):
        cases.append(Case("0x804 year %d" % year, entry=entry, rows=((0xB0, 7, year << 13 | 45 << 4, 3, 4),)))
    return cases


def bole_cases():
    entry = READERS[0x811]
    reserve = (("shape", "leaf"), ("ia", E14 + 3), ("ib", E14 + 7))
    row = (11, 3 * 10 ** 9, 13, 5 * 10 ** 9)
    good = dict(reserve=reserve, row=row)
    cases = gate_cases(0x811, **good)
    total = total_gas(36, 0x80)
    cases += [Case("0x811 row deep", entry=entry, row_shape="deep", **good), Case("0x811 row miss", entry=entry, row_shape="miss", **good), Case("0x811 row miss below", entry=entry, row_shape="below", **good), Case("0x811 row empty", entry=entry, row_shape="empty", **good),
              Case("0x811 token count", entry=entry, tok=10, **good), Case("0x811 token count-1", entry=entry, tok=9, **good), Case("0x811 big token", entry=entry, tok=1 << 40, count=(1 << 40) + 1, **good),
              Case("0x811 reserve deep", entry=entry, row=row, reserve=(("shape", "deep"), ("ia", E14 + 3), ("ib", E14 + 7))), Case("0x811 reserve miss", entry=entry, row=row, reserve=(("shape", "miss"), ("ia", E14), ("ib", E14))),
              Case("0x811 reserve below", entry=entry, row=row, reserve=(("shape", "below"), ("ia", E14), ("ib", E14))), Case("0x811 reserve empty", entry=entry, row=row, reserve=(("shape", "empty"), ("ia", E14), ("ib", E14))),
              Case("0x811 saturating gas", entry=entry, out_len=1 << 59, gas=TOP, **good), Case("0x811 saturating sum", entry=entry, out_len=(1 << 64) // 33, gas=TOP - 1, **good), Case("0x811 wide output", entry=entry, out_len=1 << 62, gas=TOP, **good), Case("0x811 short output", entry=entry, out_len=0x60, gas=total - 1, **good)]
    low = (1 << 64) // E14
    edge = E14 << 64
    for name, base, index in (("floor down", 3, E14 // 2 - 1), ("floor exact", 5, E14), ("floor above", 10 ** 6, E14 + 3), ("zero base", 0, E14 + 5), ("zero index", 7, 0), ("guard exact", 1 << 63, 2 * E14), ("guard below", (1 << 63) - 1, 2 * E14), ("guard one under", 1 << 62, 4 * E14 - 1), ("top base", TOP, E14), ("top both", TOP, TOP), ("quotient top", TOP, E14 + 0)):
        reserve_one = (("shape", "leaf"), ("ia", index), ("ib", E14 + 1))
        reserve_two = (("shape", "leaf"), ("ia", E14 + 1), ("ib", index))
        cases.append(Case("0x811 borrow " + name, entry=entry, reserve=reserve_one, row=(21, base, 23, 29)))
        cases.append(Case("0x811 supply " + name, entry=entry, reserve=reserve_two, row=(21, 29, 23, base)))
    factors = factor_guard()
    cases.append(Case("0x811 borrow product guard-1", entry=entry, reserve=(("shape", "leaf"), ("ia", factors[1]), ("ib", E14)), row=(1, factors[0], 2, 3)))
    cases.append(Case("0x811 supply product guard-1", entry=entry, reserve=(("shape", "leaf"), ("ia", E14), ("ib", factors[1])), row=(1, 3, 2, factors[0])))
    cases.append(Case("0x811 zero base false quotient", entry=entry, reserve=reserve, row=(1, 0, 2, 5), faults={0: 9}))
    cases.append(Case("0x811 zero supply false quotient", entry=entry, reserve=reserve, row=(1, 5, 2, 0), faults={1: 9}))
    for name, shape in (("hit", "leaf"), ("deep", "deep"), ("miss", "miss"), ("below", "below"), ("empty", "empty")):
        one = (("shape", shape), ("ia", E14 + 3), ("ib", E14 + 7))
        cases.append(Case("values " + name, entry=VALUES, reserve=one, row=row))
        cases.append(Case("values %s over" % name, entry=VALUES, reserve=(("shape", shape), ("ia", TOP), ("ib", E14)), row=(1, TOP, 2, 3)))
    cases.append(Case("values second over", entry=VALUES, reserve=(("shape", "leaf"), ("ia", E14), ("ib", TOP)), row=(1, 3, 2, TOP)))
    return cases


def factor_guard():
    """Two words whose product has the largest high word the guard admits."""
    base = (1 << 63) + 1
    index = (GUARD - 1) // base
    if not (base * index >> 64 == E14 - 1 and base <= TOP and index <= TOP):
        raise EvidenceError("guard factors moved")
    return base, index


def named_cases():
    return (position_cases(0x800) + position_cases(0x813) + balance_cases() + summary_cases() + gate_cases(0x809, word=0xFEDCBA9876543210) + exists_cases() + delegation_cases() + bole_cases())


def vector_cases(count):
    stream = lcg(0x311406)
    cases = []
    draw = lambda: next(stream)
    for index in range(count):
        kind = index % 8
        n = draw() % 2100
        gas = gas_in(n) + draw() % 8000
        if kind in (0, 1):
            address = 0x800 if kind == 0 else 0x813
            cases.append(Case("vector %d" % index, entry=READERS[address], n=n, gas=gas, perp=draw() & 0xFFFF, pos=(draw(), draw(), draw(), draw() & MASK[4], draw() & 1)))
        elif kind == 2:
            cases.append(Case("vector %d" % index, entry=READERS[0x801], n=n, gas=gas, tok=draw() % 12, bal=(draw(), draw(), draw()), bal_shape=("leaf", "deep", "miss", "empty")[draw() % 4]))
        elif kind == 3:
            cases.append(Case("vector %d" % index, entry=READERS[0x805], n=n, gas=gas, sum_word=draw(), u=(draw() >> (draw() % 8), 1, 2), p=(draw() >> (draw() % 8), draw()), u_shape=("leaf", "deep", "miss")[draw() % 3], p_shape=("leaf", "deep", "miss")[draw() % 3]))
        elif kind == 4:
            cases.append(Case("vector %d" % index, entry=READERS[0x809], n=n, gas=gas, word=draw()))
        elif kind == 5:
            cases.append(Case("vector %d" % index, entry=READERS[0x810], n=n, gas=gas, user=draw() << 60 | draw() | 1 << 150, exists=(("first",) + EXISTS_HIT + ("miss", "twin only"))[draw() % 8]))
        elif kind == 6:
            count_rows = draw() % 6
            rows = tuple(sorted((0x1000 + 16 * row + draw() % 8, draw() >> 8, day(1971 + draw() % 300, 1 + draw() % 12, 1 + draw() % 28), draw() % 86400, draw() % 2000000000) for row in range(count_rows)))
            cases.append(Case("vector %d" % index, entry=READERS[0x804], n=n, gas=gas + 100000, rows=rows, height=draw() % 3 if count_rows else 0))
        else:
            cases.append(Case("vector %d" % index, entry=READERS[0x811], n=n, gas=gas + 100000, tok=draw() % 9, row=(draw(), draw() >> (draw() % 40), draw(), draw() >> (draw() % 40)), reserve=(("shape", "leaf"), ("ia", E14 + draw() % E14), ("ib", E14 + draw() % E14))))
    return cases


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
    if got[0] != want[0]:
        return " form %r %r" % (got[:2] if got[0] == "panic" else got[0], want[:2] if want[0] == "panic" else want[0])
    if got[1] != want[1]:
        if isinstance(got[1], bytes):
            at = next(index for index in range(len(got[1])) if got[1][index] != want[1][index])
            return " heap +%#x got %s want %s" % (at, got[1][at:at + 16].hex(), want[1][at:at + 16].hex())
        return " value %r %r" % (got[1], want[1])
    if got[2] != want[2]:
        return " divides %r %r" % (got[2], want[2])
    if got[3] != want[3]:
        return " events %r %r" % (got[3], want[3])
    return " output %r %r" % (got[4], want[4])


def constant_rows(image):
    rows = []
    for address, entry in sorted(READERS.items()):
        at, value = find_constant(image, entry)
        if value != address:
            raise EvidenceError("address constant moved for %#x" % address)
        rows.append(("%#x" % address, "%#x" % entry, "%#x" % at, bytes(image.blob[image.offset(at):image.offset(at) + 20]).hex()))
    return rows


def label_rows(image):
    start = image.offset(LABEL_AT)
    text = bytes(image.blob[start:start + LABEL_LEN])
    if text != b"utils::abi_decode_raw":
        raise EvidenceError("decoder label moved")
    return [("%#x" % LABEL_AT, LABEL_LEN, text.decode())]


KEY_RUNS = (b"totalSuppliedtotalBorrowedbasisvalue", b"delegatedundelegatedtotalPendingWithdrawalnPendingWithdrawals")


def key_rows(image):
    rows = []
    for run in KEY_RUNS:
        at = image.blob.find(run)
        if at < 0:
            raise EvidenceError("key text missing")
        if image.blob.find(run, at + 1) >= 0:
            raise EvidenceError("key text not unique")
        rows.append(("%#x" % at, run.decode()))
    return rows


def holder_rows(image):
    """RELATIVE slots holding each function, and direct rel32 calls or jumps at it, read from the bytes."""
    relative = image.relative()
    wanted = set(TARGETS)
    slots = collections.defaultdict(list)
    for slot, value in relative.items():
        if value in wanted:
            slots[value].append(slot)
    va, text = image.text_bytes()
    direct = collections.defaultdict(list)
    for match in re.finditer(rb"[\xe8\xe9]", text):
        if match.start() + 5 > len(text):
            break
        target = va + match.start() + 5 + struct.unpack_from("<i", text, match.start() + 1)[0]
        if target in wanted:
            direct[target].append(va + match.start())
    indirect = collections.defaultdict(list)
    held = {slot: target for target, items in slots.items() for slot in items}
    for match in re.finditer(rb"\xff\x15", text):
        if match.start() + 6 > len(text):
            break
        slot = va + match.start() + 6 + struct.unpack_from("<i", text, match.start() + 2)[0]
        if slot in held:
            indirect[held[slot]].append(va + match.start())
    rows = []
    for target in TARGETS:
        rows.append(("%#x" % target, NAMES[target], " ".join("%#x" % s for s in sorted(slots[target])), " ".join("%#x" % s for s in sorted(direct[target])), " ".join("%#x" % s for s in sorted(indirect[target]))))
    return rows


def word_table(data):
    return [data[index:index + 32] for index in range(0, len(data), 32)]


def probe(harness, case):
    _, got = harness.run(case)
    if got[0] != "run" or got[4] is None:
        raise EvidenceError("probe did not finish: %s" % case.name)
    return word_table(got[4])


def output_rows(harness):
    """One probe per function with distinct source values, so word order comes from a run and not from the rule list."""
    rows = []

    def add(address, words, names):
        if len(words) != len(names):
            raise EvidenceError("word count moved for %#x" % address)
        for index, (word, name) in enumerate(zip(words, names)):
            rows.append(("%#x" % address, index, word.hex(), name))

    pos = (0xFFFFFFFFFFFFFFF0, 0x0102030405060708, 0xFFFFFFFFFFFFFFE0, 0xC0D0E0F, 1)
    names = ("out +0x00, i64 sign extended to 256 bits", "out +0x08, u64 zero extended", "out +0x10, i64 sign extended to 256 bits", "out +0x18, u32", "out +0x1c, one byte, 2 means error words")
    add(0x800, probe(harness, Case("p", entry=READERS[0x800], pos=pos)), names)
    add(0x813, probe(harness, Case("p", entry=READERS[0x813], pos=pos)), names)
    add(0x801, probe(harness, Case("p", entry=READERS[0x801], bal=(0x1111, 0x2222, 0x3333))), ("balance row +0x00", "balance row +0x08", "balance row +0x10"))
    add(0x805, probe(harness, Case("p", entry=READERS[0x805], sum_word=0x4444, u=(0x9000, 1, 2), p=(0x1000, 3))),
        ("delegated sum 0x3c0f050", "user_states row +0 less pending, 0 below", "pending total, S+0x228 value +0", "pending count, S+0x228 value +8"))
    add(0x809, probe(harness, Case("p", entry=READERS[0x809], word=0x55AA)), ("[[ctx+0x30]+0x28]",))
    add(0x810, probe(harness, Case("p", entry=READERS[0x810], exists="first")), ("1 when the hash set at ctx+0x40 holds the user",))
    row = ((0xB, 3 * 10 ** 9, 0xD, 5 * 10 ** 9))
    add(0x811, probe(harness, Case("p", reserve=(("shape", "leaf"), ("ia", E14 + 3), ("ib", E14 + 7)), row=row)),
        ("row +0x00", "floor(row +0x08 * reserve +0x58 / 1e14)", "row +0x10", "floor(row +0x18 * reserve +0x78 / 1e14)"))
    two = ((0xA0, 0x1234, day(2026, 10, 31), 7, 8000000), (0xB0, 0x5678, day(1960, 1, 1), 1, 2))
    add(0x804, probe(harness, Case("p", entry=READERS[0x804], rows=two))[:-1], ("offset 0x20", "row count", "row 0 key, 12 zero bytes then 20 address bytes", "row 0 amount, value +0", "row 0 lock time as Unix ms, floored at 0",
                                                                            "row 1 key", "row 1 amount", "row 1 lock time, before 1970 gives 0"))
    return rows


def rounding_rows(harness):
    """The user word against the two reserve totals of the same index: floor here, ceil for borrowed there."""
    rows = []
    for base, index in ((1, E14 + 1), (3, E14 // 2), (10 ** 6, E14 + 3), (5, E14), (7, E14 - 1)):
        for name, reserve, row, slot in (("borrow word", (("shape", "leaf"), ("ia", index), ("ib", E14)), (0, base, 0, 0), 1), ("supply word", (("shape", "leaf"), ("ia", E14), ("ib", index)), (0, 0, 0, base), 3)):
            words = probe(harness, Case("p", reserve=reserve, row=row))
            value = int.from_bytes(words[slot], "big")
            rows.append((name, base, index, value, base * index // E14, -(-(base * index) // E14)))
    return rows


def lane_rows():
    rows = []
    for name, value in (("largest high word admitted", E14 - 1), ("first refused product", GUARD), ("largest quotient", (GUARD - 1) // E14), ("u64 max", TOP)):
        rows.append((name, "%#x" % value))
    return rows


def gas_rows():
    rows = []
    for address, size in (("0x800", 0xA0), ("0x813", 0xA0), ("0x801", 0x60), ("0x805", 0x80), ("0x809", 0x20), ("0x810", 0x20), ("0x811", 0x80)):
        rows.append((address, size, total_gas(36, size)))
    for count in (0, 1, 5):
        size = (3 * count + 2) * 32
        rows.append(("0x804 %d rows" % count, size, total_gas(36, size)))
    return rows


def lock_rows(harness):
    rows = []
    for y, m, d, secs, frac in ((1970, 1, 1, 0, 0), (1970, 1, 1, 0, 1000000), (1969, 12, 31, 86399, 999999999), (2026, 10, 31, 50400, 5000000), (2024, 2, 29, 86399, 1999999999), (1, 1, 1, 0, 0)):
        words = probe(harness, Case("p", entry=READERS[0x804], rows=((0xB0, 7, day(y, m, d), secs, frac),)))
        rows.append(("%04d-%02d-%02d" % (y, m, d), secs, frac, int.from_bytes(words[4], "big")))
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


DEAD_OUTPUT_HEAD = "first word of a two-word block that is freed right after with no reader"
TEXT_OVERLAP = "low byte of the text word stored at +5; the next store at +0 overwrites bytes 5 to 7, so the edit cannot reach the text"
DANGLING = "the dangling pointer of an empty list; no row is read through it"
ITERATOR_BACK = "a word of the back half of the map iterator or the empty list length; the walk reads only the front half and ends by count"
HUGE_LIST = "a size bound that needs more than 2^58 rows; the fixture list cannot reach it"
OFFSET_STACK = "the ABI offset stack: its one value is read for word 0 before this row, and after it the stack is only freed, whose size does not depend on it"
ZERO_HEAD = "copies the first 16 bytes of a word that are zero in every row, and the edited offset lands on zero bytes too"
SHIFT_OF_ZERO = "shift of an index that is 0 here"
ALWAYS_LARGE = "gas so far is at least 1000, so the add carries and the cmov gives u64::MAX for -1 or -2"
TWIN_CMOV = "the row is doubled, so the other copy of the cmov still applies"
ALL_BYTES_SAME = "shuffle of a value whose bytes are all equal"
SAME_WORD = "+0x48 of the iterator is the row capacity, which equals the length at +0x40"
NEVER_NEGATIVE = "fixes up a negative quotient; y is never negative after the 400 year shift"
EIGHT_LOOP = "the compare is reached only with a count that is not a multiple of 8, so 8 and 9 behave the same"
OLD_YEARS = "the branch for year <= 0 only makes dates before 1970, which the floor at 0 hides"
LOW_WORD = "the compare of the low word can carry only for a product of exactly 1e14*2^64-1, and the tool has no factors of that number"
EXPECTED_SURVIVORS = {}
for _rows, _kind, _text in (
        ((0x3248D0F, 0x324A9C3, 0x324AD23, 0x324BCC2, 0x324C6FD, 0x330524A, 0x3306109), "immediate", DEAD_OUTPUT_HEAD),
        ((0x324830B, 0x3248C28, 0x324A83B, 0x324ADDB, 0x324BC5E, 0x324C7F1, 0x33051B9, 0x3306078), "immediate", TEXT_OVERLAP),
        ((0x324822A, 0x32483E4, 0x32488D7, 0x3BD097B), "immediate", DANGLING),
        ((0x324837C, 0x32483FE), "immediate", ITERATOR_BACK),
        ((0x32483A0, 0x3248483, 0x324849A), "immediate", HUGE_LIST),
        ((0x32484AB,), "displacement", HUGE_LIST),
        ((0x324852A, 0x3248596, 0x324859A, 0x3248717), "immediate", OFFSET_STACK),
        ((0x3248586, 0x3248708, 0x3248715), "condition", OFFSET_STACK),
        ((0x324859E, 0x32485A9), "displacement", OFFSET_STACK),
        ((0x3248665, 0x32486CA), "displacement", ZERO_HEAD),
        ((0x324855D,), "immediate", SHIFT_OF_ZERO),
        ((0x3248833, 0x324AB24), "immediate", ALWAYS_LARGE),
        ((0x324883A, 0x324883E), "condition", TWIN_CMOV),
        ((0x324BBB3, 0x3305270, 0x3305275, 0x33052B0, 0x33052B5, 0x330612F, 0x3306134, 0x330616F, 0x3306174), "immediate", ALL_BYTES_SAME),
        ((0x3BE353B,), "displacement", SAME_WORD),
        ((0x3BE3599,), "immediate", NEVER_NEGATIVE),
        ((0x3BE3685, 0x3BE3768), "immediate", EIGHT_LOOP),
        ((0x3BE3805, 0x3BE380E, 0x3BE3815, 0x3BE381C, 0x3BE3826), "immediate", OLD_YEARS),
        ((0x3C183DF, 0x3C184B0), "immediate", LOW_WORD)):
    for _row in _rows:
        EXPECTED_SURVIVORS[_row, _kind] = _text


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    extra = vector_cases(80)
    plain = cases + extra
    for target in TARGETS:
        numbers = OWNER.get(target, (ADDRESSES.get(target),)) + ((VALUES,) if target == VALUES else ())
        chosen = [case for case in plain if case.number in numbers]
        chosen.sort(key=lambda case: len(case.rows) * 3 + case.height)
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(harness, chosen)
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=320):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), labels=label_rows(image), keys=key_rows(image), holders=holder_rows(image),
                  output=output_rows(harness), rounding=rounding_rows(harness), lanes=lane_rows(), gas=gas_rows(), locks=lock_rows(harness))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    got, stamp = outcome
    return "%#x" % case.number, case.name, stamp, hashlib.sha256(repr((got[0], got[1], got[2], got[3], got[4])).encode()).hexdigest()[:16], len(got[2]), len(got[3])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("address-constants.tsv", ("precompile", "function", "constant_at", "bytes"), result["constants"])
    tsv("decoder-label.tsv", ("address", "length", "text"), result["labels"])
    tsv("key-text.tsv", ("file_offset", "text"), result["keys"])
    tsv("holders.tsv", ("function", "name", "relative_slots", "direct_sites", "slot_call_sites"), result["holders"])
    tsv("output-map.tsv", ("precompile", "word", "probe_bytes", "source"), result["output"])
    tsv("rounding-samples.tsv", ("word", "base", "index", "precompile", "floor", "ceil"), result["rounding"])
    tsv("product-guard.tsv", ("name", "value"), result["lanes"])
    tsv("gas-table.tsv", ("precompile", "output_bytes", "total_for_36_byte_input"), result["gas"])
    tsv("lock-time-samples.tsv", ("date", "seconds", "nanoseconds", "word"), result["locks"])
    tsv("outcomes.tsv", ("precompile", "case", "result", "digest", "divides", "events"), [describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
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
